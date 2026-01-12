#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - System End-to-End
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:01:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import json
from urllib.parse import urlparse, parse_qs

import pytest

from brsxss.detect.xss.reflected.scanner import XSSScanner
from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics


@pytest.mark.asyncio
async def test_system_e2e_scan_and_report(tmp_path, monkeypatch):
    # Mock HTTP client that reflects the parameter value in the response body
    class MResp:
        def __init__(self, status_code=200, text="<html><body>OK</body></html>"):
            self.status_code = status_code
            self.text = text
            self.headers = {"content-type": "text/html"}

    class MClient:
        async def get(self, url):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            # reflect first param value if present
            value = next(iter(qs.values()), ["test"])[0]
            return MResp(200, f"<html><body>Search: {value}</body></html>")

        async def post(self, url, data=None):
            v = next(iter((data or {}).values()), "test")
            return MResp(200, f"<html><body>Posted: {v}</body></html>")

        async def close(self):
            return None

    # Build real scanner with mocked client
    # Disable DOM XSS to avoid launching headless browser in tests
    scanner = XSSScanner(http_client=MClient(), enable_dom_xss=False)

    # Limit payloads to a single known payload to speed up
    payload_value = "<system-xss>"

    class P:
        payload = payload_value

    monkeypatch.setattr(
        scanner.payload_generator,
        "generate_payloads",
        lambda ctx, wafs, max_payloads=None: [P()],
    )

    vulns = await scanner.scan_url(
        "http://test.local/search", method="GET", parameters={"q": "probe"}
    )
    assert isinstance(vulns, list)
    assert len(vulns) >= 1

    # Convert to VulnerabilityData for reporting
    items = []
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "low")
        if hasattr(sev, "value"):
            sev = sev.value
        items.append(
            VulnerabilityData(
                id=f"xss_{i}",
                title=f"XSS in parameter {v.get('parameter','')}",
                description=f"Detected reflection in {v.get('parameter','')}",
                severity=sev,
                confidence=0.8,
                url=v.get("url", "http://test.local"),
                parameter=v.get("parameter", "q"),
                payload=v.get("payload", payload_value),
                context="html_content",
                # v4.0.0-beta.2: Add evidence to make findings confirmed
                evidence_response="Payload reflected in response body",
            )
        )

    stats = ScanStatistics(
        total_urls_tested=1,
        total_parameters_tested=1,
        total_payloads_tested=len(items),
        total_requests_sent=len(items),
        vulnerabilities_found=len(items),
    )

    cfg = ReportConfig(
        output_dir=str(tmp_path), formats=[ReportFormat.HTML, ReportFormat.JSON]
    )
    gen = ReportGenerator(cfg)
    out = gen.generate_report(items, stats, {"url": "http://test.local"})
    assert ReportFormat.HTML in out and ReportFormat.JSON in out

    html_file = tmp_path / (out[ReportFormat.HTML].split("/")[-1])
    html_content = (tmp_path / html_file.name).read_text(encoding="utf-8")
    # Ensure KB-enriched sections are present (Attack Vector/Remediation)
    assert "Attack Vector" in html_content and "Remediation" in html_content

    json_file = tmp_path / (out[ReportFormat.JSON].split("/")[-1])
    data = json.loads((tmp_path / json_file.name).read_text(encoding="utf-8"))
    assert data["summary"]["total_vulnerabilities"] == len(items)
