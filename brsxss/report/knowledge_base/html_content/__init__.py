#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

Knowledge Base: HTML Content Context - Guide
Refactored to comply with 300-line file limit
"""

from .description import TITLE, DESCRIPTION, METADATA
from .attack_vectors import ATTACK_VECTOR
from .remediation import REMEDIATION

DETAILS = {
    "title": TITLE,
    **METADATA,
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION
}

