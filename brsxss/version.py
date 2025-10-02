#!/usr/bin/env python3
"""
BRS-XSS Version Management
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 05 Sep 2025 15:30:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

SINGLE SOURCE OF TRUTH for version information.
All other modules should import from here.
"""

from . import __version__

def get_version() -> str:
    """Get current version from package metadata"""
    return __version__

def get_version_string() -> str:
    """Get formatted version string for display"""
    return f"BRS-XSS v{__version__}"

def get_user_agent() -> str:
    """Get User-Agent string for HTTP requests"""
    return f"BRS-XSS v{__version__}"

# Export for easy imports
VERSION = __version__
VERSION_STRING = get_version_string()
USER_AGENT = get_user_agent()
