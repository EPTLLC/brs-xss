#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - HTTPClient timeouts, retries, headers
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:12:30 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import asyncio

import pytest

from brsxss.detect.xss.reflected.http_client import HTTPClient, HTTPResponse


class DummyResp:
    def __init__(self, status=200, text="OK", headers=None, url="https://example.org/"):
        self.status = status
        self._text = text
        self.headers = headers or {"X": "Y"}
        self.url = url

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class DummySession:
    def __init__(self, behavior):
        self.behavior = behavior
        self.closed = False

    def request(self, method, url, **kwargs):
        return self.behavior(method, url, **kwargs)

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_headers_and_success(monkeypatch):
    client = HTTPClient(timeout=1)

    async def get_session():
        def behavior(method, url, **kwargs):
            assert kwargs["headers"]["User-Agent"].startswith("BRS-XSS")
            return DummyResp(200, "OK", {"Server": "x"}, url)

        return DummySession(behavior)

    monkeypatch.setattr(client, "_get_session", get_session)
    r = await client.get("https://example.org/")
    assert isinstance(r, HTTPResponse)
    assert r.status_code == 200 and r.text == "OK" and r.headers["Server"] == "x"


@pytest.mark.asyncio
async def test_timeout_and_retries(monkeypatch):
    client = HTTPClient(timeout=0.01)
    attempts = {"n": 0}

    async def get_session():
        def behavior(method, url, **kwargs):
            attempts["n"] += 1
            raise asyncio.TimeoutError()

        return DummySession(behavior)

    monkeypatch.setattr(client, "_get_session", get_session)
    r = await client.get("https://example.org/", retries=2)
    assert r.status_code == 0 and "timeout" in (r.error or "").lower()
    assert attempts["n"] >= 3


@pytest.mark.asyncio
async def test_client_error_and_close(monkeypatch):
    import aiohttp

    client = HTTPClient(timeout=0.01)
    attempts = {"n": 0}

    class CloseableDummy(DummySession):
        async def close(self):
            self.closed = True

    async def get_session():
        def behavior(method, url, **kwargs):
            attempts["n"] += 1
            raise aiohttp.ClientError("boom")

        return CloseableDummy(behavior)

    monkeypatch.setattr(client, "_get_session", get_session)
    r = await client.post("https://example.org/", data={"a": 1}, retries=1)
    assert r.status_code == 0 and "client error" in (r.error or "").lower()
    assert attempts["n"] >= 2
    # After error, ensure close works and session is inactive
    await client.close()
    stats = client.get_stats()
    assert stats["session_active"] is False and stats["error_count"] >= 1


def test_sync_wrappers(monkeypatch):
    client = HTTPClient(timeout=1)

    async def get_session():
        def behavior(method, url, **kwargs):
            return DummyResp(200, "OK")

        return DummySession(behavior)

    monkeypatch.setattr(client, "_get_session", get_session)
    r1 = client.get_sync("https://example.org/")
    r2 = client.post_sync("https://example.org/", data="x")
    assert r1.status_code == 200 and r2.status_code == 200
