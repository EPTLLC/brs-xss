#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Authentication module - simple user management.
"""

from .models import User, UserCreate, UserUpdate, AuthConfig
from .password import hash_password, verify_password
from .jwt_handler import create_token, verify_token, get_current_user_id

__all__ = [
    "User",
    "UserCreate",
    "UserUpdate",
    "AuthConfig",
    "hash_password",
    "verify_password",
    "create_token",
    "verify_token",
    "get_current_user_id",
]
