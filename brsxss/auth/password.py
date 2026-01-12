#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Password hashing utilities using bcrypt.
"""

import hashlib
import secrets


def hash_password(password: str) -> str:
    """
    Hash password using SHA-256 with salt.
    Simple but secure - no external dependencies.
    """
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${hashed}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        salt, stored_hash = hashed.split("$", 1)
        computed = hashlib.sha256((salt + password).encode()).hexdigest()
        return secrets.compare_digest(computed, stored_hash)
    except (ValueError, AttributeError):
        return False
