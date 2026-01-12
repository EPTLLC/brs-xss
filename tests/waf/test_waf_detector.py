#!/usr/bin/env python3

"""
Project: BRS-XSS Tests for WAFDetector
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:00:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from brsxss.detect.xss.reflected.http_client import HTTPClient
from brsxss.detect.waf.detector import WAFDetector
from brsxss.detect.waf.models import WAFBrand


@pytest.mark.asyncio
async def test_detects_waf_by_header():
    """
    Test that WAFDetector can identify a WAF from response headers.
    """
    # Arrange
    mock_response = MagicMock()
    mock_response.headers = {"Server": "cloudflare"}
    mock_response.text = "<html></html>"

    mock_http_client = MagicMock(spec=HTTPClient)
    mock_http_client.get = AsyncMock(return_value=mock_response)

    detector = WAFDetector(http_client=mock_http_client)

    # Act
    detected_wafs = await detector.detect_waf("http://test.com")

    # Assert
    assert len(detected_wafs) == 1
    assert detected_wafs[0].brand == WAFBrand.CLOUDFLARE


@pytest.mark.asyncio
async def test_detects_waf_by_content(aresponses):
    """
    Test that WAFDetector can identify a WAF from response body content.
    """
    # Arrange
    mock_response = MagicMock()
    mock_response.headers = {}
    mock_response.text = "<html><body>Request blocked by Imperva</body></html>"

    mock_http_client = MagicMock(spec=HTTPClient)
    mock_http_client.get = AsyncMock(return_value=mock_response)

    detector = WAFDetector(http_client=mock_http_client)

    # Act
    detected_wafs = await detector.detect_waf("http://test.com")

    # Assert
    assert len(detected_wafs) > 0  # Imperva might trigger multiple signatures
    assert any(waf.brand == WAFBrand.IMPERVA for waf in detected_wafs)


@pytest.mark.asyncio
async def test_returns_empty_when_no_waf_detected(aresponses):
    """
    Test that WAFDetector returns an empty list when no WAF is found.
    """
    # Arrange
    mock_response = MagicMock()
    mock_response.headers = {"Server": "nginx"}
    mock_response.text = "<html><body>Welcome</body></html>"

    mock_http_client = MagicMock(spec=HTTPClient)
    mock_http_client.get = AsyncMock(return_value=mock_response)

    detector = WAFDetector(http_client=mock_http_client)

    # Act
    detected_wafs = await detector.detect_waf("http://test.com")

    # Assert
    assert len(detected_wafs) == 0
