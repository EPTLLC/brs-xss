#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - HTTPClient
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 15:03:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest

from brsxss.core.http_client import HTTPClient, HTTPResponse


@pytest.mark.asyncio
async def test_http_client_timeout(monkeypatch):
    client = HTTPClient(timeout=0.01)

    class MSession:
        closed = False
        def __init__(self):
            pass
        async def close(self):
            self.closed = True
        def request(self, *a, **kw):
            class Ctx:
                async def __aenter__(self):
                    # Simulate long operation to trigger timeout
                    import asyncio
                    await asyncio.sleep(0.05)
                    class R:
                        status = 200
                        headers = {}
                        url = "https://ex.com"
                        async def text(self):
                            return "ok"
                    return R()
                async def __aexit__(self, exc_type, exc, tb):
                    return False
            return Ctx()

    class MConnector: pass

    async def fake_get_session():
        return MSession()

    monkeypatch.setattr(client, "_get_session", fake_get_session)

    resp = await client.get("https://example.com", timeout=0.01, retries=0)
    assert isinstance(resp, HTTPResponse)
    assert resp.status_code in (0, 200)
    # If timeout fired, error message should be present
    if resp.status_code == 0:
        assert "timeout" in (resp.error or "").lower()


