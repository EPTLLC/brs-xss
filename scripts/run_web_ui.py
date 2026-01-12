#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 08 Jan 2026 17:25:59 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class FrontendCommandSpec:
    """Represents how to invoke the Vite dev server."""

    command: list[str]
    direct_args: bool
    runner: str


class ManagedProcess:
    """Wrapper around subprocess.Popen with prefixed output."""

    def __init__(self, name: str, command: Sequence[str], cwd: Path):
        self.name = name
        self.command = list(command)
        self.cwd = cwd
        self._proc: subprocess.Popen | None = None
        self._stream_thread: threading.Thread | None = None

    def start(self):
        cmd_display = " ".join(shlex.quote(part) for part in self.command)
        print(f"[runner] Starting {self.name}: {cmd_display}")
        self._proc = subprocess.Popen(
            self.command,
            cwd=str(self.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._stream_thread = threading.Thread(target=self._stream_output, daemon=True)
        self._stream_thread.start()

    def _stream_output(self):
        assert self._proc is not None
        if not self._proc.stdout:
            return
        prefix = f"[{self.name}] "
        for line in self._proc.stdout:
            print(f"{prefix}{line}", end="")

    def poll(self) -> int | None:
        return None if self._proc is None else self._proc.poll()

    def stop(self, grace_seconds: float = 5.0):
        if not self._proc:
            return
        if self._proc.poll() is not None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        finally:
            if self._stream_thread:
                self._stream_thread.join(timeout=1.0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run BRS-XSS Web UI (backend + frontend) with a single command."
    )
    parser.add_argument(
        "--backend-host",
        default="0.0.0.0",
        help="Host for FastAPI backend (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--backend-port",
        type=int,
        default=8000,
        help="Port for FastAPI backend (default: 8000)",
    )
    parser.add_argument(
        "--frontend-host",
        default="0.0.0.0",
        help="Host for Vite dev server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--frontend-port",
        type=int,
        default=5173,
        help="Port for Vite dev server (default: 5173)",
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Skip automatic frontend dependency installation",
    )
    parser.add_argument(
        "--no-backend-reload",
        action="store_true",
        help="Disable uvicorn auto-reload (enabled by default for development).",
    )
    return parser.parse_args()


def ensure_python_dependencies():
    missing = []
    for module in ("uvicorn", "fastapi"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        joined = ", ".join(missing)
        raise SystemExit(
            f"Missing Python dependencies: {joined}. Install project requirements before running this script."
        )


def ensure_frontend_dependencies(frontend_dir: Path, skip_install: bool):
    node_modules = frontend_dir / "node_modules"
    if node_modules.exists():
        return
    if skip_install:
        print(
            "[runner] node_modules not found and --skip-install was set. Skipping install."
        )
        return
    installer = resolve_frontend_installer()
    print(f"[runner] Installing frontend dependencies via: {' '.join(installer)}")
    try:
        subprocess.run(installer, cwd=str(frontend_dir), check=True)
    except FileNotFoundError as exc:
        raise SystemExit(
            "Dependency installation failed: package manager not found."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"Dependency installation failed (exit code {exc.returncode})."
        ) from exc


def _collect_pids(stdout: str) -> set[int]:
    pids: set[int] = set()
    for token in stdout.strip().split():
        if token.isdigit():
            pids.add(int(token))
    return pids


def _find_pids_on_port(port: int) -> set[int]:
    """Return PIDs listening on TCP port using lsof/fuser if available."""
    commands = []
    if shutil.which("lsof"):
        commands.append(["lsof", "-ti", f"tcp:{port}"])
    if shutil.which("fuser"):
        commands.append(["fuser", f"{port}/tcp"])

    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            pids = _collect_pids(result.stdout)
            if pids:
                return pids
        except subprocess.CalledProcessError:
            continue
    return set()


def ensure_port_available(port: int, label: str):
    """
    Ensure TCP port is free. If occupied, attempt to terminate owners.
    """
    pids = _find_pids_on_port(port)
    if not pids:
        return

    print(f"[runner] Port {port} ({label}) is in use by {sorted(pids)}. Releasing...")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError:
            print(f"[runner] Permission denied terminating PID {pid} on port {port}.")

    for _ in range(10):
        if not _find_pids_on_port(port):
            print(f"[runner] Freed port {port} ({label}).")
            return
        time.sleep(0.3)

    remaining = _find_pids_on_port(port)
    if remaining:
        for pid in remaining:
            try:
                print(f"[runner] Force killing PID {pid} on port {port}.")
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except PermissionError:
                print(
                    f"[runner] Permission denied force killing PID {pid} on port {port}."
                )
        time.sleep(0.5)

    if _find_pids_on_port(port):
        raise SystemExit(f"Failed to free port {port} ({label}).")
    print(f"[runner] Freed port {port} ({label}).")


def _require_bun() -> None:
    if not shutil.which("bun"):
        raise SystemExit(
            "Bun is required for the Web UI. Install Bun (https://bun.sh) and ensure it is in PATH."
        )


def resolve_frontend_installer() -> list[str]:
    """Always install dependencies via Bun."""
    _require_bun()
    return ["bun", "install"]


def resolve_frontend_command() -> FrontendCommandSpec:
    """Always run dev server via Bun."""
    _require_bun()
    if shutil.which("bunx"):
        return FrontendCommandSpec(["bunx", "--bun", "vite"], True, "bunx")
    # bunx not present -> use `bun x`
    return FrontendCommandSpec(["bun", "x", "vite"], True, "bun")


def build_frontend_command(
    spec: FrontendCommandSpec, args: argparse.Namespace
) -> list[str]:
    vite_args = ["--host", args.frontend_host, "--port", str(args.frontend_port)]
    command = list(spec.command)
    if spec.direct_args:
        command.extend(vite_args)
    else:
        command.append("--")
        command.extend(vite_args)
    return command


def build_backend_command(args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "web_ui.backend.app:app",
        "--host",
        args.backend_host,
        "--port",
        str(args.backend_port),
    ]
    if not args.no_backend_reload:
        command.extend(["--reload"])
    return command


def run_processes(processes: list[ManagedProcess]) -> int:
    for process in processes:
        process.start()
    exit_code = 0
    try:
        while True:
            time.sleep(0.5)
            for process in processes:
                code = process.poll()
                if code is None:
                    continue
                if code == 0:
                    print(
                        f"[runner] {process.name} exited with code 0. Shutting down remaining processes."
                    )
                else:
                    print(
                        f"[runner] {process.name} exited with code {code}. Stopping everything."
                    )
                exit_code = code
                return exit_code
    except KeyboardInterrupt:
        print("\n[runner] CTRL+C received. Stopping services...")
        return 0
    finally:
        for process in processes:
            process.stop()


def main():
    args = parse_args()
    root_dir = Path(__file__).resolve().parents[1]
    frontend_dir = root_dir / "web_ui" / "frontend"

    ensure_python_dependencies()
    frontend_spec = resolve_frontend_command()
    ensure_frontend_dependencies(frontend_dir, args.skip_install)
    ensure_port_available(args.backend_port, "backend")
    ensure_port_available(args.frontend_port, "frontend")

    backend_command = build_backend_command(args)
    frontend_command = build_frontend_command(frontend_spec, args)

    print(f"[runner] Using frontend runner: {frontend_spec.runner}")
    print("[runner] Backend URL: http://%s:%d" % (args.backend_host, args.backend_port))
    print(
        "[runner] Frontend URL: http://%s:%d" % (args.frontend_host, args.frontend_port)
    )

    processes = [
        ManagedProcess("backend", backend_command, root_dir),  # Run from project root
        ManagedProcess("frontend", frontend_command, frontend_dir),
    ]
    exit_code = run_processes(processes)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
