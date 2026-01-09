#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0-beta.1
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 09 Jan 2026 UTC
Status: Beta - v4.0.0-beta.1
Telegram: https://t.me/EasyProTech

SINGLE SOURCE OF TRUTH for version information.
All other modules should import from here.
Version is read from pyproject.toml at runtime.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


def _get_version_from_pyproject() -> Optional[str]:
    """Extract version from pyproject.toml"""
    try:
        import toml

        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "r", encoding="utf-8") as f:
                data = toml.load(f)
                return data.get("project", {}).get("version")
    except ImportError:
        # toml not available, try manual parsing
        try:
            pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith("version"):
                            # Parse: version = "4.0.0"
                            parts = line.split("=", 1)
                            if len(parts) == 2:
                                return parts[1].strip().strip('"').strip("'")
        except Exception:
            pass
    except Exception:
        pass
    return None


# Get the actual version from pyproject.toml
PROJECT_VERSION = _get_version_from_pyproject() or "4.0.0-beta.1"

# Knowledge Base version - updated dynamically from API
_kb_version_info: Dict[str, str] = {
    "version": "unknown",
    "build": "unknown",
    "revision": "stable",
}


def get_version() -> str:
    """Get current version from package metadata"""
    return PROJECT_VERSION


def get_version_string() -> str:
    """Get formatted version string for display"""
    return f"BRS-XSS v{PROJECT_VERSION}"


def get_user_agent() -> str:
    """Get User-Agent string for HTTP requests"""
    return f"BRS-XSS/{PROJECT_VERSION}"


def get_build_info() -> Dict[str, str]:
    """Get build information"""
    return {
        "version": PROJECT_VERSION,
        "build_date": datetime.now().strftime("%d %b %Y %H:%M:%S UTC"),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "kb_version": _kb_version_info["version"],
        "kb_build": _kb_version_info["build"],
        "kb_revision": _kb_version_info["revision"],
    }


def update_knowledge_base_version(kb_info: Dict[str, Any]) -> None:
    """
    Update Knowledge Base version from external source (API response).

    Args:
        kb_info: Dictionary with 'version', 'build', 'revision' keys
    """
    global _kb_version_info
    if kb_info:
        _kb_version_info["version"] = kb_info.get(
            "version", _kb_version_info["version"]
        )
        _kb_version_info["build"] = kb_info.get("build", _kb_version_info["build"])
        _kb_version_info["revision"] = kb_info.get(
            "revision", _kb_version_info["revision"]
        )


def get_kb_version() -> str:
    """Get current KB version"""
    return _kb_version_info["version"]


# Export for easy imports
VERSION = PROJECT_VERSION
VERSION_STRING = get_version_string()
USER_AGENT = get_user_agent()
BUILD_INFO = get_build_info()
