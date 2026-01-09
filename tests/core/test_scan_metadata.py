#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ScanMetadata coordinator
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:27:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path

from brsxss.core.scan_metadata import ScanMetadata


def test_scan_metadata_end_to_end(tmp_path: Path):
    sm = ScanMetadata()
    sm.set_target_info("https://t")
    sm.set_scan_config(timeout=1, max_concurrent=2)
    sm.record_request(0.1, 200, True)
    sm.record_request(0.2, 404, False)
    sm.record_parameter_test("q", "html")
    sm.record_payload_test("basic")
    sm.record_vulnerability("high", "html_content")
    sm.record_waf_detection("cf")
    sm.record_bypass_technique("unicode")
    sm.finalize_scan()
    path = sm.save_metadata(str(tmp_path))
    assert Path(path).exists()
    summary = sm.get_summary_report()
    ci = sm.export_for_ci()
    md = sm.get_metadata_dict()
    assert "Scan ID:" in summary and ci["status"] == "completed" and md["scan_id"]
