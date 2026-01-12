#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: Created
Telegram: https://t.me/EasyProTech

JWT token handling - simple implementation without external JWT library.
Uses HMAC-SHA256 for signing.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Optional


# Secret key - generated on first run, stored in env or file
_SECRET_KEY: Optional[str] = None
TOKEN_EXPIRY_HOURS = 24


def _get_secret_key() -> str:
    """Get or generate secret key"""
    global _SECRET_KEY

    if _SECRET_KEY:
        return _SECRET_KEY

    # Try environment variable first
    _SECRET_KEY = os.environ.get("BRS_JWT_SECRET")
    if _SECRET_KEY:
        return _SECRET_KEY

    # Try to read from file
    secret_file = os.path.expanduser("~/.config/brs-xss/.jwt_secret")
    if os.path.exists(secret_file):
        with open(secret_file, "r") as f:
            _SECRET_KEY = f.read().strip()
            return _SECRET_KEY

    # Generate new secret
    import secrets

    _SECRET_KEY = secrets.token_hex(32)

    # Save to file
    os.makedirs(os.path.dirname(secret_file), exist_ok=True)
    with open(secret_file, "w") as f:
        f.write(_SECRET_KEY)
    os.chmod(secret_file, 0o600)

    return _SECRET_KEY


def _b64_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(data: str) -> bytes:
    """URL-safe base64 decode with padding restoration"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def create_token(user_id: str, username: str, is_admin: bool = False) -> str:
    """Create JWT token"""
    header = {"alg": "HS256", "typ": "JWT"}

    payload = {
        "sub": user_id,
        "username": username,
        "is_admin": is_admin,
        "iat": int(time.time()),
        "exp": int(time.time()) + (TOKEN_EXPIRY_HOURS * 3600),
    }

    header_b64 = _b64_encode(json.dumps(header).encode())
    payload_b64 = _b64_encode(json.dumps(payload).encode())

    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        _get_secret_key().encode(), message.encode(), hashlib.sha256
    ).digest()
    signature_b64 = _b64_encode(signature)

    return f"{message}.{signature_b64}"


def verify_token(token: str) -> Optional[dict]:
    """
    Verify JWT token and return payload if valid.
    Returns None if invalid or expired.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts

        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            _get_secret_key().encode(), message.encode(), hashlib.sha256
        ).digest()

        actual_sig = _b64_decode(signature_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        # Decode payload
        payload = json.loads(_b64_decode(payload_b64))

        # Check expiration
        if payload.get("exp", 0) < time.time():
            return None

        return payload

    except Exception:
        return None


def get_current_user_id(token: str) -> Optional[str]:
    """Extract user ID from token"""
    payload = verify_token(token)
    return payload.get("sub") if payload else None
