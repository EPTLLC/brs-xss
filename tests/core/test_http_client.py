#!/usr/bin/env python3

"""
Project: BRS-XSS Tests for HTTPClient
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 16:10:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from aresponses.main import ResponsesMockServer

from brsxss.core.http_client import HTTPClient

@pytest.mark.asyncio
async def test_http_client_get_success(aresponses: ResponsesMockServer):
    """
    Test a successful GET request with the HTTPClient.
    """
    # Arrange
    host = "test-server.com"
    path = "/test-path"
    aresponses.add(host, path, "get", aresponses.Response(status=200, text="Success"))
    
    client = HTTPClient()
    
    # Act
    response = await client.get(f"http://{host}{path}")
    
    # Assert
    assert response.status_code == 200
    assert response.text == "Success"
    
    await client.close()

@pytest.mark.asyncio
async def test_http_client_post_success(aresponses: ResponsesMockServer):
    """
    Test a successful POST request with the HTTPClient.
    """
    # Arrange
    host = "test-server.com"
    path = "/submit"
    aresponses.add(host, path, "post", aresponses.Response(status=200, text="Posted"))
    
    client = HTTPClient()
    
    # Act
    response = await client.post(f"http://{host}{path}", data={"key": "value"})
    
    # Assert
    assert response.status_code == 200
    assert response.text == "Posted"
    
    await client.close()

@pytest.mark.asyncio
async def test_http_client_handles_404_error(aresponses: ResponsesMockServer):
    """
    Test that the client correctly handles a 404 Not Found error.
    """
    # Arrange
    host = "test-server.com"
    path = "/not-found"
    aresponses.add(host, path, "get", aresponses.Response(status=404, text="Not Found"))
    
    client = HTTPClient()
    
    # Act
    response = await client.get(f"http://{host}{path}")
    
    # Assert
    assert response.status_code == 404
    assert response.text == "Not Found"
    
    await client.close()
