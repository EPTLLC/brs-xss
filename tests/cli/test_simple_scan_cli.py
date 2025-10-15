#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI simple_scan smoke
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:47:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import json
import types
import asyncio
from pathlib import Path

import pytest

from cli.commands.simple_scan import simple_scan


@pytest.mark.asyncio
async def test_simple_scan_smoke_generates_report(tmp_path, monkeypatch):
    # Mock HTTPClient
    class MResp:
        status_code = 200
        text = "<html><body>Search results: test</body></html>"
        headers = {}

    class MClient:
        async def get(self, url):
            return MResp()
        async def post(self, url, data=None):
            return MResp()
        async def close(self):
            return None

    monkeypatch.setattr("brsxss.core.http_client.HTTPClient", lambda timeout=15, verify_ssl=True: MClient())

    # Mock scanner to avoid heavy work
    async def fake_scan_url(self, url, method, params):
        return [{
            'severity': 'low',
            'url': url,
            'http_method': method,
            'parameter': list(params.keys())[0] if params else 'q',
            'payload': '<x>',
        }]

    monkeypatch.setattr("brsxss.core.scanner.XSSScanner.scan_url", fake_scan_url)

    # Execute scan for a synthetic target with query param
    out_file = tmp_path / "out.json"
    await simple_scan(target="example.com/search?q=test", threads=1, timeout=5, output=str(out_file), deep=False, verbose=False, ml_mode=False, blind_xss_webhook=None, no_ssl_verify=True, safe_mode=True, pool_cap=1000, max_payloads=10)

    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["scan_info"]["vulnerabilities_found"] >= 1
    assert data["vulnerabilities"][0]["url"].startswith("http")


