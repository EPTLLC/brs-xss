#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 26 Dec 2025 UTC
Status: Created
Telegram: https://t.me/EasyProTech

System information detection and performance mode calculation.
Dynamically calculates optimal scanner settings based on hardware.
"""

import os
import json
import time
import platform
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess


@dataclass
class SystemProfile:
    """System hardware profile"""

    cpu_model: str
    cpu_cores: int
    cpu_threads: int
    ram_total_gb: float
    ram_available_gb: float
    cpu_frequency_mhz: float
    gpu_model: str
    gpu_count: int
    network_speed_mbps: int
    os_name: str
    os_version: str
    detected_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PerformanceMode:
    """Performance mode configuration"""

    name: str
    label: str
    description: str
    threads: int
    max_concurrent: int
    requests_per_second: int
    request_delay_ms: int
    dom_workers: int
    playwright_browsers: int
    http_pool_size: int
    recommended: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SystemDetector:
    """Detects system hardware and calculates performance modes"""

    CONFIG_DIR = Path.home() / ".brs-xss"
    PROFILE_FILE = CONFIG_DIR / "system_profile.json"

    def __init__(self):
        self._profile: Optional[SystemProfile] = None
        self._modes: Optional[Dict[str, PerformanceMode]] = None

    def detect_system(self, force: bool = False) -> SystemProfile:
        """
        Detect system hardware.

        Args:
            force: Force re-detection even if cached

        Returns:
            SystemProfile with hardware info
        """
        # Check cache first
        if not force and self._profile:
            return self._profile

        # Try to load from file
        if not force and self.PROFILE_FILE.exists():
            try:
                with open(self.PROFILE_FILE, "r") as f:
                    data = json.load(f)
                    data.setdefault("cpu_frequency_mhz", 0.0)
                    data.setdefault("gpu_model", "None")
                    data.setdefault("gpu_count", 0)
                    data.setdefault("network_speed_mbps", 1000)
                    self._profile = SystemProfile(**data)
                    return self._profile
            except Exception:
                pass

        # Detect fresh
        self._profile = self._detect_hardware()

        # Save to file
        self._save_profile()

        return self._profile

    def _detect_hardware(self) -> SystemProfile:
        """Perform actual hardware detection"""

        # CPU info
        cpu_model = "Unknown CPU"
        cpu_cores = os.cpu_count() or 1
        cpu_threads = cpu_cores
        cpu_freq_mhz = 0.0

        try:
            # Try to get CPU model from /proc/cpuinfo (Linux)
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if "model name" in line:
                            cpu_model = line.split(":")[1].strip()
                            break

                # Count threads (processors)
                with open("/proc/cpuinfo", "r") as f:
                    cpu_threads = sum(1 for line in f if line.startswith("processor"))
            # cpu frequency from psutil if available
            try:
                import psutil

                freq = psutil.cpu_freq()
                if freq:
                    cpu_freq_mhz = freq.max or freq.current or 0.0
            except ImportError:
                pass
        except Exception:
            pass

        # RAM info
        ram_total_gb = 0.0
        ram_available_gb = 0.0

        try:
            # Try psutil first
            import psutil

            mem = psutil.virtual_memory()
            ram_total_gb = round(mem.total / (1024**3), 1)
            ram_available_gb = round(mem.available / (1024**3), 1)
        except ImportError:
            # Fallback to /proc/meminfo (Linux)
            try:
                if os.path.exists("/proc/meminfo"):
                    with open("/proc/meminfo", "r") as f:
                        for line in f:
                            if "MemTotal" in line:
                                kb = int(line.split()[1])
                                ram_total_gb = round(kb / (1024**2), 1)
                            elif "MemAvailable" in line:
                                kb = int(line.split()[1])
                                ram_available_gb = round(kb / (1024**2), 1)
            except Exception:
                ram_total_gb = 4.0  # Default fallback
                ram_available_gb = 2.0
        gpu_model, gpu_count = self._detect_gpu()
        net_speed = self._detect_network_speed()

        return SystemProfile(
            cpu_model=cpu_model,
            cpu_cores=cpu_cores,
            cpu_threads=cpu_threads,
            ram_total_gb=ram_total_gb,
            ram_available_gb=ram_available_gb,
            cpu_frequency_mhz=cpu_freq_mhz,
            gpu_model=gpu_model,
            gpu_count=gpu_count,
            network_speed_mbps=net_speed,
            os_name=platform.system(),
            os_version=platform.release(),
            detected_at=datetime.utcnow().isoformat(),
        )

    def _save_profile(self):
        """Save profile to disk"""
        try:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.PROFILE_FILE, "w") as f:
                json.dump(self._profile.to_dict(), f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save system profile: {e}")

    def _detect_gpu(self) -> (str, int):
        """Detect GPU model/count (NVIDIA preferred)."""
        gpu_model = "None"
        gpu_count = 0
        try:
            result = subprocess.run(
                ["nvidia-smi", "-L"], capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                lines = [
                    line.strip() for line in result.stdout.splitlines() if line.strip()
                ]
                gpu_count = len(lines)
                if gpu_count > 0:
                    gpu_model = lines[0]
        except Exception:
            # fallback: check /dev/dri
            try:
                dri = Path("/dev/dri")
                if dri.exists():
                    cards = list(dri.glob("card*"))
                    gpu_count = len(cards)
                    if gpu_count > 0:
                        gpu_model = "Generic GPU (/dev/dri)"
            except Exception:
                pass
        return gpu_model, gpu_count

    def _detect_network_speed(self) -> int:
        """Attempt to detect NIC speed (Mbps)."""
        speed = 1000  # default assume 1Gbps
        try:
            import psutil

            stats = psutil.net_if_stats()
            max_speed = 0
            for iface, data in stats.items():
                if data.speed > max_speed:
                    max_speed = data.speed
            if max_speed > 0:
                speed = max_speed
        except ImportError:
            pass
        return speed

    def get_performance_modes(
        self, profile: Optional[SystemProfile] = None
    ) -> Dict[str, PerformanceMode]:
        """
        Calculate performance modes based on system hardware.

        All values are dynamically calculated from actual hardware.
        """
        if profile is None:
            profile = self.detect_system()

        # Base calculations from hardware
        cores = profile.cpu_threads
        ram_gb = profile.ram_available_gb

        # Calculate base capacity
        # Threads: limited by CPU cores
        # RPS: limited by both CPU and RAM (network buffers need RAM)
        max_threads = max(1, cores)
        # Consider CPU freq (GHz) and GPU count for boosting concurrency
        freq_factor = 1.0 + (profile.cpu_frequency_mhz or 0) / 5000.0
        gpu_factor = 1.0 + (0.2 * profile.gpu_count)
        net_factor = (
            1.0
            if profile.network_speed_mbps >= 1000
            else profile.network_speed_mbps / 1000.0
        )
        capacity_multiplier = freq_factor * gpu_factor * net_factor
        max_rps = int(min(cores * 25, ram_gb * 12) * capacity_multiplier)
        dom_workers_base = max(2, cores // 4)
        playwright_browsers_base = max(2, cores // 12)
        http_pool_base = max(32, cores * 4)

        # Calculate modes as percentages of capacity
        def mode(key: str, share: float, desc: str, recommended=False):
            threads = max(1, int(max_threads * share))
            return PerformanceMode(
                name=key,
                label=desc.split()[0],
                description=desc,
                threads=threads,
                max_concurrent=max(1, threads),
                requests_per_second=max(5, int(max_rps * share)),
                request_delay_ms=(
                    0
                    if share >= 0.5
                    else max(5, int(1000 / max(5, int(max_rps * share))))
                ),
                dom_workers=max(1, int(dom_workers_base * share)),
                playwright_browsers=max(1, int(playwright_browsers_base * share)),
                http_pool_size=max(16, int(http_pool_base * share)),
                recommended=recommended,
            )

        modes = {
            "light": mode("light", 0.15, "Light minimal load"),
            "standard": mode(
                "standard", 0.35, "Standard balanced", recommended=(cores <= 8)
            ),
            "turbo": mode(
                "turbo", 0.6, "Turbo high performance", recommended=(8 < cores <= 24)
            ),
            "maximum": mode(
                "maximum", 0.95, "Maximum full power", recommended=(cores > 24)
            ),
        }

        self._modes = modes
        return modes

    def get_mode_by_name(self, name: str) -> Optional[PerformanceMode]:
        """Get specific performance mode by name"""
        if self._modes is None:
            self.get_performance_modes()
        return self._modes.get(name)

    def get_recommended_mode(self) -> PerformanceMode:
        """Get the recommended mode for this system"""
        modes = self.get_performance_modes()
        for mode in modes.values():
            if mode.recommended:
                return mode
        return modes["standard"]

    def get_system_info(self) -> Dict[str, Any]:
        """
        Get complete system info for API response.

        Returns dict with:
        - system: hardware profile
        - modes: available performance modes
        - recommended: name of recommended mode
        - saved_mode: currently saved preference (if any)
        """
        profile = self.detect_system()
        modes = self.get_performance_modes(profile)

        # Get saved preference
        saved_mode = self._get_saved_mode()

        # Find recommended
        recommended = "standard"
        for name, mode in modes.items():
            if mode.recommended:
                recommended = name
                break

        return {
            "system": profile.to_dict(),
            "modes": {name: mode.to_dict() for name, mode in modes.items()},
            "recommended": recommended,
            "saved_mode": saved_mode or recommended,
        }

    def _get_saved_mode(self) -> Optional[str]:
        """Get saved mode preference"""
        prefs_file = self.CONFIG_DIR / "preferences.json"
        try:
            if prefs_file.exists():
                with open(prefs_file, "r") as f:
                    data = json.load(f)
                    return data.get("performance_mode")
        except Exception:
            pass
        return None

    def save_mode_preference(self, mode_name: str) -> bool:
        """Save mode preference to disk"""
        try:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            prefs_file = self.CONFIG_DIR / "preferences.json"

            # Load existing prefs
            prefs = {}
            if prefs_file.exists():
                with open(prefs_file, "r") as f:
                    prefs = json.load(f)

            # Update mode
            prefs["performance_mode"] = mode_name
            prefs["updated_at"] = datetime.utcnow().isoformat()

            # Save
            with open(prefs_file, "w") as f:
                json.dump(prefs, f, indent=2)

            return True
        except Exception as e:
            print(f"Warning: Could not save mode preference: {e}")
            return False


# Singleton instance
_detector: Optional[SystemDetector] = None


def get_system_detector() -> SystemDetector:
    """Get singleton SystemDetector instance"""
    global _detector
    if _detector is None:
        _detector = SystemDetector()
    return _detector


def get_system_info() -> Dict[str, Any]:
    """Convenience function to get system info"""
    return get_system_detector().get_system_info()


def detect_system(force: bool = False) -> Dict[str, Any]:
    """Convenience function to detect/re-detect system"""
    detector = get_system_detector()
    detector.detect_system(force=force)
    return detector.get_system_info()


def get_live_stats() -> Dict[str, Any]:
    """
    Get live system statistics (CPU, RAM, Load, Network).
    Lightweight - reads from /proc, no significant overhead.
    """
    stats = {
        "cpu_percent": 0.0,
        "ram_used_gb": 0.0,
        "ram_total_gb": 0.0,
        "ram_percent": 0.0,
        "load_1m": 0.0,
        "load_5m": 0.0,
        "load_15m": 0.0,
        "net_sent_mbps": 0.0,
        "net_recv_mbps": 0.0,
    }

    # Try psutil first for RAM, load, and network (most accurate)
    try:
        import psutil

        mem = psutil.virtual_memory()
        stats["ram_total_gb"] = round(mem.total / (1024**3), 1)
        stats["ram_used_gb"] = round(mem.used / (1024**3), 1)
        stats["ram_percent"] = mem.percent
        load = psutil.getloadavg()
        stats["load_1m"] = round(load[0], 2)
        stats["load_5m"] = round(load[1], 2)
        stats["load_15m"] = round(load[2], 2)

        # Network: get bytes sent/recv, compare with cached values
        net_io = psutil.net_io_counters()
        current_time = time.time()

        # Use module-level cache for network delta calculation
        global _net_cache
        if "_net_cache" not in globals():
            _net_cache = {
                "time": current_time,
                "sent": net_io.bytes_sent,
                "recv": net_io.bytes_recv,
            }

        time_delta = current_time - _net_cache["time"]
        if time_delta > 0.5:  # At least 0.5s between measurements
            bytes_sent_delta = net_io.bytes_sent - _net_cache["sent"]
            bytes_recv_delta = net_io.bytes_recv - _net_cache["recv"]

            # Convert to Mbps (megabits per second)
            stats["net_sent_mbps"] = round(
                (bytes_sent_delta * 8) / (time_delta * 1_000_000), 2
            )
            stats["net_recv_mbps"] = round(
                (bytes_recv_delta * 8) / (time_delta * 1_000_000), 2
            )

            # Update cache
            _net_cache = {
                "time": current_time,
                "sent": net_io.bytes_sent,
                "recv": net_io.bytes_recv,
            }

        # CPU: use interval=0.1 for blocking but accurate reading
        stats["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        return stats
    except ImportError:
        pass

    # Fallback to /proc (Linux only)
    try:
        # Load average
        if os.path.exists("/proc/loadavg"):
            with open("/proc/loadavg", "r") as f:
                parts = f.read().split()
                stats["load_1m"] = float(parts[0])
                stats["load_5m"] = float(parts[1])
                stats["load_15m"] = float(parts[2])

        # Memory
        if os.path.exists("/proc/meminfo"):
            meminfo = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = int(parts[1].strip().split()[0])  # KB
                        meminfo[key] = val

            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", 0)
            used = total - available

            stats["ram_total_gb"] = round(total / (1024**2), 1)
            stats["ram_used_gb"] = round(used / (1024**2), 1)
            if total > 0:
                stats["ram_percent"] = round((used / total) * 100, 1)

        # CPU - simple estimation from /proc/stat
        # This is approximate, psutil is more accurate
        if os.path.exists("/proc/stat"):
            with open("/proc/stat", "r") as f:
                line = f.readline()
                parts = line.split()
                if parts[0] == "cpu":
                    # user, nice, system, idle, iowait, irq, softirq
                    user = int(parts[1])
                    nice = int(parts[2])
                    system = int(parts[3])
                    idle = int(parts[4])
                    total = user + nice + system + idle
                    if total > 0:
                        active = user + nice + system
                        stats["cpu_percent"] = round((active / total) * 100, 1)
    except Exception:
        pass

    return stats
