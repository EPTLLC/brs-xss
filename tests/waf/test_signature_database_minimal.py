#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - SignatureDatabase minimal
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 03:46:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
from brsxss.waf.signature_database import SignatureDatabase
from brsxss.waf.waf_types import WAFType
from brsxss.waf.waf_signature import WAFSignature


def test_signature_database_defaults_and_add(tmp_path):
    db_path = tmp_path / "sigs.json"
    db = SignatureDatabase(str(db_path))
    # Defaults present
    assert db.get_signatures_for_waf(WAFType.CLOUDFLARE)
    # Add a custom sig and save
    sig = WAFSignature(
        waf_type=WAFType.CLOUDFLARE,
        name="CF-Extra",
        header_patterns=["x-custom:"],
        required_headers=["x-custom"],
        content_patterns=["cf-extra"],
        error_page_patterns=["<title>cf extra</title>"],
        status_codes=[403],
        confidence_weight=0.5,
    )
    db.add_signature(sig)
    db.save_signatures()
    assert db_path.exists()

    # Reload and check merge
    db2 = SignatureDatabase(str(db_path))
    cfs = [s.name for s in db2.get_signatures_for_waf(WAFType.CLOUDFLARE)]
    assert "CF-Extra" in cfs and db2.get_all_signatures()
