#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAFFingerprinter minimal
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:53:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.waf.waf_fingerprinter import WAFFingerprinter
from brsxss.waf.signature_database import SignatureDatabase
from brsxss.waf.waf_signature import WAFSignature
from brsxss.waf.waf_types import WAFType


def test_waf_fingerprinter_with_minimal_signature():
    db = SignatureDatabase(signatures_path=None)
    # Add a minimal fake signature for a dummy header
    sig = WAFSignature(
        waf_type=WAFType.CLOUDFLARE,
        name="CF-Min",
        header_patterns=[r"x-test-waf:"],
        required_headers=["x-test-waf"],
        content_patterns=[],
        error_page_patterns=[],
        status_codes=[403],
        confidence_weight=1.0,
    )
    db.add_signature(sig)

    fp = WAFFingerprinter(signatures_db=db)
    headers = {"X-Test-WAF": "on"}
    res1 = fp.fingerprint_response(headers, "", 403)
    assert res1 and res1[0].waf_type == WAFType.CLOUDFLARE

    # Cached path
    res2 = fp.fingerprint_response(headers, "", 403)
    assert res2 == res1
