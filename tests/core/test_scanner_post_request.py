#!/usr/bin/env python3

"""
Project: BRS-XSS Tests
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:45:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from brsxss.core.scanner import XSSScanner
from brsxss.core.http_client import HTTPClient


@pytest.mark.asyncio
@patch("brsxss.core.scanner.HeadlessDOMDetector")
async def test_scanner_uses_post_for_post_method(mock_headless_detector_class):
    """
    Verify that XSSScanner uses the HTTP POST method when instructed to.
    """
    # 1. Arrange: set up the mocks

    # Mock headless DOM detector to prevent real browser navigation
    mock_headless_detector = MagicMock()
    mock_headless_detector.detect = AsyncMock(return_value=[])
    mock_headless_detector.close = AsyncMock()
    mock_headless_detector_class.return_value = mock_headless_detector

    # Mock the HTTPClient
    mock_http_client = MagicMock(spec=HTTPClient)
    mock_http_client.post = AsyncMock()
    mock_http_client.get = AsyncMock()
    mock_http_client.close = AsyncMock()

    # Mock the response from the initial context analysis POST request
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<html></html>"
    mock_http_client.post.return_value = mock_response

    # Instantiate the scanner, injecting our mocked HTTP client
    scanner = XSSScanner(http_client=mock_http_client)

    # Mock dependencies of the scanner to isolate the test
    # We mock detect_waf to prevent it from making GET requests
    scanner.waf_detector.detect_waf = AsyncMock(return_value=[])
    scanner.context_analyzer.analyze_context = MagicMock()
    scanner.payload_generator.generate_payloads = MagicMock(
        return_value=[]
    )  # No payloads to speed up test

    # 2. Act: Call the method under test
    await scanner.scan_url(
        url="http://test.com/search", method="POST", parameters={"query": "test"}
    )

    # 3. Assert: Verify the behavior

    # Check that http_client.post was called (at least once, may be called
    # multiple times for filter detection and context analysis)
    assert mock_http_client.post.call_count >= 1, "POST should be called at least once"

    # Check that http_client.get was NOT called
    mock_http_client.get.assert_not_called()

    await scanner.close()
