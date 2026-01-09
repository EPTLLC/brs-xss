#!/usr/bin/env python3

"""
Project: BRS-XSS Tests
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:30:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from unittest.mock import MagicMock, AsyncMock

from cli.commands.simple_scan import _discover_parameters, _build_scan_targets

# Mock HTML content with a POST form
FAKE_HTML_POST_FORM = """
<html>
<body>
    <form action="/search.php" method="post">
        <input type="text" name="query" value="test">
        <input type="submit" name="submit">
    </form>
</body>
</html>
"""


@pytest.mark.asyncio
async def test_discover_parameters_finds_post_form():
    """
    Ensure that _discover_parameters correctly identifies a POST form
    and extracts its action, method, and parameters.
    """
    # Mock the HTTP client to avoid real network calls
    mock_http_client = MagicMock()

    # Mock the crawler's response
    # We need to simulate the crawler finding a page with our fake HTML
    crawl_result = MagicMock()
    crawl_result.status_code = 200
    crawl_result.content = FAKE_HTML_POST_FORM
    crawl_result.url = "http://test.com"

    mock_crawler_instance = MagicMock()
    mock_crawler_instance.crawl = AsyncMock(return_value=[crawl_result])

    # We need to mock the CrawlerEngine class to return our mock instance
    # This is a bit complex due to how it's imported within the function
    from brsxss.crawler import engine

    original_crawler_engine = engine.CrawlerEngine
    engine.CrawlerEngine = MagicMock(return_value=mock_crawler_instance)

    # --- Call the function we want to test ---
    discovered_params = await _discover_parameters(
        url="http://test.com", deep_scan=True, http_client=mock_http_client
    )

    # --- Assertions ---
    assert discovered_params is not None
    assert len(discovered_params) > 0

    # Check if we found the POST form correctly
    post_form_entry = None
    for entry in discovered_params:
        if entry.method == "POST":
            post_form_entry = entry
            break

    assert post_form_entry is not None
    assert post_form_entry.url == "http://test.com/search.php"
    assert post_form_entry.method == "POST"
    assert "query" in post_form_entry.params
    assert post_form_entry.params["query"] == "test"

    # Restore the original class to avoid side effects in other tests
    engine.CrawlerEngine = original_crawler_engine


def test_build_scan_targets_with_domain():
    """
    Test that _build_scan_targets correctly creates URLs for a simple domain.
    """
    targets = _build_scan_targets("example.com")
    assert "http://example.com/" in targets
    assert "https://example.com/" in targets
    assert len(targets) > 10  # Should generate a list of common paths


def test_build_scan_targets_with_full_url():
    """
    Test that _build_scan_targets uses the provided URL directly.
    """
    url = "http://example.com/search?q=test"
    targets = _build_scan_targets(url)
    assert targets == [url]
