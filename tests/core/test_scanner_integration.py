#!/usr/bin/env python3

"""
Project: BRS-XSS Integration Tests
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 15:50:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from brsxss.core.scanner import XSSScanner
from brsxss.core.http_client import HTTPClient

# A payload that is likely to be found as an exact reflection
TEST_PAYLOAD = "<brsxss-test-payload>"

@pytest.mark.asyncio
async def test_scanner_finds_xss_in_post_request():
    """
    Integration test: Ensure the scanner can find a vulnerability
    in a POST request from end-to-end.
    """
    # 1. Arrange
    
    # Mock HTTP response for the POST request containing the payload
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = f"<html><body>Search results: {TEST_PAYLOAD}</body></html>"
    mock_response.headers = {}  # Add empty headers dict to avoid mock coroutine issues
    
    # Mock the HTTPClient
    mock_http_client = MagicMock(spec=HTTPClient)
    # The scanner will make multiple POST calls: one for context, then for each payload.
    # We configure the mock to return our vulnerable response for all of them.
    mock_http_client.post = AsyncMock(return_value=mock_response)
    # Also mock GET for WAF detection to avoid coroutine warnings
    mock_http_client.get = AsyncMock(return_value=mock_response)
    
    # Instantiate the real scanner, injecting our mock client
    scanner = XSSScanner(http_client=mock_http_client)
    
    # We only need to mock the payload generator to return our specific test payload
    # All other components (ReflectionDetector, ContextAnalyzer, etc.) will be real.
    mock_payload_obj = MagicMock()
    mock_payload_obj.payload = TEST_PAYLOAD
    scanner.payload_generator.generate_payloads = MagicMock(return_value=[mock_payload_obj])
    
    # 2. Act
    vulnerabilities = await scanner.scan_url(
        url="http://test.com/search",
        method="POST",
        parameters={"query": "test"}
    )
    
    # 3. Assert
    assert vulnerabilities is not None
    assert len(vulnerabilities) == 1
    
    vuln = vulnerabilities[0]
    assert vuln['vulnerable'] is True
    assert vuln['parameter'] == 'query'
    assert vuln['payload'] == TEST_PAYLOAD
    assert vuln['context'] == 'html_content'

    await scanner.close()
