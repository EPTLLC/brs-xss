#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 12 Jan 2026 UTC
Status: Created - Storage package init
Telegram: https://t.me/EasyProTech

Storage package combining all storage modules via mixins.
"""

from typing import Optional

from .base import BaseStorage
from .scans import ScansMixin
from .vulnerabilities import VulnerabilitiesMixin
from .users import UsersMixin
from .strategies import StrategiesMixin
from .domains import DomainsMixin


class ScanStorage(
    BaseStorage,
    ScansMixin,
    VulnerabilitiesMixin,
    UsersMixin,
    StrategiesMixin,
    DomainsMixin,
):
    """
    Main storage class combining all storage functionality.
    
    Uses mixin pattern to split ~3500 lines into manageable modules:
    - base.py: Database initialization, migrations, cleanup
    - scans.py: Scan CRUD operations
    - vulnerabilities.py: Vulnerability operations, dashboard stats
    - users.py: User management, authentication, settings
    - strategies.py: Strategy trees, A/B testing
    - domains.py: Domain profiles, payloads, workflows
    """
    pass


# Global storage instance
_storage_instance: Optional[ScanStorage] = None


def get_storage() -> ScanStorage:
    """Get global storage instance"""
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = ScanStorage()
    return _storage_instance


# Re-export for backwards compatibility
__all__ = [
    "ScanStorage",
    "get_storage",
    "BaseStorage",
    "ScansMixin",
    "VulnerabilitiesMixin",
    "UsersMixin",
    "StrategiesMixin",
    "DomainsMixin",
]
