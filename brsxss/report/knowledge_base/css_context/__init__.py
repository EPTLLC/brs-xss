#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

Knowledge Base: CSS Context - Guide
Refactored to comply with 300-line file limit
"""

from .description import TITLE, DESCRIPTION
from .attack_vectors_legacy import LEGACY_ATTACKS
from .attack_vectors_modern import MODERN_ATTACKS
from .remediation import REMEDIATION

ATTACK_VECTOR = LEGACY_ATTACKS + "\n\n" + MODERN_ATTACKS

DETAILS = {
    "title": TITLE,
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION
}

