#!/usr/bin/env python3
"""
Project: BRS-XSS Version Management
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 26 Oct 2025 13:43:19 UTC
Status: Modified
Telegram: https://t.me/EasyProTech

SINGLE SOURCE OF TRUTH for version information.
All other modules should import from here.
"""

import toml
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Try to get version from pyproject.toml first
def _get_version_from_pyproject() -> Optional[str]:
    """Extract version from pyproject.toml"""
    try:
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
                return data.get('project', {}).get('version')
    except Exception:
        pass
    return None

# Fallback to hardcoded version if pyproject.toml fails
def _get_version_from_init() -> str:
    """Fallback to hardcoded version"""
    return "2.1.0"

# Get the actual version
PROJECT_VERSION = _get_version_from_pyproject() or _get_version_from_init()

# Knowledge Base version - will be updated automatically
KB_VERSION = "1.0.0"
KB_BUILD = "2025.10.26"
KB_REVISION = "stable"

# Auto-generated metadata
BUILD_DATE = datetime.now().strftime("%d %b %Y %H:%M:%S UTC")
BUILD_TIMESTAMP = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

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
        "build_date": BUILD_DATE,
        "timestamp": BUILD_TIMESTAMP,
        "kb_version": KB_VERSION,
        "kb_build": KB_BUILD,
        "kb_revision": KB_REVISION
    }

def update_knowledge_base_version(kb_info: Dict[str, Any]):
    """Update Knowledge Base version from external source"""
    global KB_VERSION, KB_BUILD, KB_REVISION

    if kb_info:
        KB_VERSION = kb_info.get('version', KB_VERSION)
        KB_BUILD = kb_info.get('build', KB_BUILD)
        KB_REVISION = kb_info.get('revision', KB_REVISION)

# Export for easy imports
VERSION = PROJECT_VERSION
VERSION_STRING = get_version_string()
USER_AGENT = get_user_agent()
BUILD_INFO = get_build_info()