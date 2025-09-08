import asyncio
from types import SimpleNamespace

import pytest

from brsxss.core.http_client import HTTPClient, HTTPResponse


class DummyResp:
    def __init__(self, status=200, text="OK", url="http://ex/", headers=None):
        self.status = status
        self._text = text
        self.url = url
        self.headers = headers or {"X": "y"}

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class DummySession:
    def __init__(self, resp: DummyResp = None, raise_exc: Exception = None):
        self._resp = resp or DummyResp()
        self._raise = raise_exc
        self.closed = False

    def request(self, *args, **kwargs):
        if self._raise:
            async def _raise_cm():
                raise self._raise
            class R:
                async def __aenter__(self_inner):
                    await _raise_cm()
                async def __aexit__(self_inner, exc_type, exc, tb):
                    return False
            return R()
        return self._resp

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_http_client_success(monkeypatch):
    client = HTTPClient(timeout=1)

    async def fake_get_session():
        return DummySession(resp=DummyResp(status=201, text="YO"))

    monkeypatch.setattr(client, "_get_session", fake_get_session)

    resp: HTTPResponse = await client.get("http://x")
    assert resp.status_code == 201
    assert resp.text == "YO"
    assert resp.headers["X"] == "y"
    await client.close()


@pytest.mark.asyncio
async def test_http_client_retries_and_error(monkeypatch):
    client = HTTPClient(timeout=1)

    class Boom(Exception):
        pass

    # First two attempts raise, last one also raises to hit error path
    attempts = {"n": 0}

    async def fake_get_session():
        attempts["n"] += 1
        return DummySession(raise_exc=Boom("fail"))

    monkeypatch.setattr(client, "_get_session", fake_get_session)

    resp: HTTPResponse = await client.get("http://x", retries=2)
    assert resp.status_code == 0
    assert "Client error" in (resp.error or "") or "Unexpected" in (resp.error or "")
    assert client.get_stats()["error_count"] >= 1
    await client.close()
