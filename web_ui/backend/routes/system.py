#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

System information and health routes.
"""

from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, HTTPException
from ..system_info import (
    get_system_info,
    detect_system,
    get_system_detector,
    get_live_stats,
)


def _get_project_version() -> str:
    """Get version from pyproject.toml"""
    try:
        # Find pyproject.toml (go up from web_ui/backend/routes/system.py)
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent.parent
        pyproject_path = project_root / "pyproject.toml"
        
        if pyproject_path.exists():
            with open(pyproject_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("version"):
                        # Parse: version = "4.0.0-beta.2"
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            return parts[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "unknown"


PROJECT_VERSION = _get_project_version()


def register(app: FastAPI, scanner_service):
    """Register system routes"""

    @app.get("/api/health")
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "active_scans": len(scanner_service.get_active_scans()),
        }

    @app.get("/api/version")
    async def get_version():
        """Get BRS-XSS version from pyproject.toml"""
        return {
            "version": PROJECT_VERSION,
            "name": "BRS-XSS",
            "github": "https://github.com/EPTLLC/brs-xss",
        }

    @app.get("/api/system/info")
    async def get_system_info_endpoint():
        """Get system hardware info and performance modes"""
        return get_system_info()

    @app.post("/api/system/detect")
    async def detect_system_endpoint():
        """Force re-detection of system hardware"""
        return detect_system(force=True)

    @app.post("/api/system/mode")
    async def set_performance_mode(mode: str):
        """set preferred performance mode"""
        detector = get_system_detector()

        valid_modes = ["light", "standard", "turbo", "maximum"]
        if mode not in valid_modes:
            raise HTTPException(
                status_code=400, detail=f"Invalid mode. Must be one of: {valid_modes}"
            )

        if detector.save_mode_preference(mode):
            return {"status": "saved", "mode": mode}
        raise HTTPException(status_code=500, detail="Failed to save preference")

    @app.get("/api/system/stats")
    async def get_system_stats():
        """
        Get live system statistics (CPU, RAM, Load, parallelism info).
        Lightweight endpoint for polling.
        """
        stats = get_live_stats()

        detector = get_system_detector()
        info = detector.get_system_info()
        saved_mode = info.get("saved_mode", "standard")
        stats["performance_mode"] = saved_mode

        # Get active scans info
        active_scans = scanner_service.get_active_scans()
        stats["active_scans"] = len(active_scans)

        # Get parallelism info from performance mode
        mode_config = info.get("modes", {}).get(saved_mode, {})
        stats["max_parallel"] = mode_config.get("max_concurrent", 10)
        stats["cpu_cores"] = info.get("system", {}).get("cpu_cores", 1)

        # Get current scan progress if any active
        total_targets = 0
        scanned_targets = 0
        try:
            if active_scans:
                for scan_id in active_scans:
                    scan_data = scanner_service.storage.get_scan(scan_id)
                    if scan_data and isinstance(scan_data, dict):
                        scanned_targets += scan_data.get("urls_scanned", 0) or 0
        except Exception:
            pass  # Don't fail stats endpoint on scan data errors

        stats["targets_total"] = total_targets
        stats["targets_scanned"] = scanned_targets

        return stats

    @app.post("/api/system/restart")
    async def restart_backend():
        """
        Restart backend server.
        Returns immediately, then server restarts via subprocess.
        Note: This requires the backend to be run with a process manager
        (systemd, supervisor, etc.) for automatic restart, OR it will
        attempt to start a new process before exiting.
        """
        import os
        import sys
        import subprocess
        import threading
        import time
        from pathlib import Path

        def delayed_restart():
            """Restart after short delay to allow response to be sent"""
            time.sleep(1.5)  # Give time for response to be sent

            # Get current Python executable
            python_exe = sys.executable

            # Find project root (go up from web_ui/backend/routes/system.py)
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent.parent.parent  # Go up 4 levels

            # Determine command - check how we're currently running
            # The backend can be run as: python3 -m web_ui.backend.app
            # or via uvicorn: uvicorn web_ui.backend.app:app --host 0.0.0.0 --port 8000

            # Check if uvicorn is available
            try:
                import importlib.util

                if importlib.util.find_spec("uvicorn"):
                    # Use uvicorn for restart (more reliable)
                    cmd = [
                        python_exe,
                        "-m",
                        "uvicorn",
                        "web_ui.backend.app:app",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8000",
                    ]
                else:
                    raise ImportError("uvicorn not found")
            except ImportError:
                # Fallback: Direct module execution (app.py has __main__ handler)
                cmd = [python_exe, "-m", "web_ui.backend.app"]

            # Start new process in background
            try:
                # Change to project root directory
                os.chdir(str(project_root))

                # set PYTHONPATH
                env = os.environ.copy()
                if "PYTHONPATH" not in env:
                    env["PYTHONPATH"] = str(project_root)
                else:
                    env["PYTHONPATH"] = f"{project_root}:{env['PYTHONPATH']}"

                # Start new process (detached, redirect output)
                log_file = open("/tmp/brs_backend.log", "a")
                subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    env=env,
                    cwd=str(project_root),
                    start_new_session=True,  # Detach from parent
                    preexec_fn=os.setsid if hasattr(os, "setsid") else None,
                )
                log_file.close()

                time.sleep(1.0)  # Give new process time to start
            except Exception as e:
                print(f"Failed to restart backend: {e}", file=sys.stderr)
                # Don't exit if restart failed - let process manager handle it
                return

            # Now exit current process gracefully
            # Use SIGTERM to allow cleanup, or _exit(0) for immediate
            try:
                os._exit(0)  # Immediate exit
            except Exception:
                import signal

                os.kill(os.getpid(), signal.SIGTERM)

        # Start restart in background thread (non-daemon so it completes)
        restart_thread = threading.Thread(target=delayed_restart, daemon=False)
        restart_thread.start()

        return {"status": "restarting", "message": "Backend will restart in a moment"}
