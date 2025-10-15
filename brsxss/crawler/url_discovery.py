#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import re
from urllib.parse import urljoin
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

from ..utils.logger import Logger
logger = Logger("crawler.url_discovery")


class URLType(Enum):
    """Types of discovered URLs"""
    LINK = "link"               # Regular link
    FORM_ACTION = "form_action" # Form action
    AJAX_ENDPOINT = "ajax"      # AJAX endpoint
    API_ENDPOINT = "api"        # API endpoint
    RESOURCE = "resource"       # Resource (CSS, JS, img)
    REDIRECT = "redirect"       # Redirect


@dataclass
class DiscoveredURL:
    """Discovered URL"""
    url: str
    url_type: URLType
    source_context: str = ""    # Source context
    method: str = "GET"
    parameters: Dict[str, str] = field(default_factory=dict)
    
    # Additional data
    depth: int = 0
    discovered_at: str = ""
    parent_url: str = ""
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


class URLDiscovery:
    """
    URL discovery engine.
    
    Functions:
    - Link extraction from HTML
    - Form action discovery
    - AJAX endpoint detection
    - API endpoint discovery
    - JavaScript analysis for URLs
    """
    
    def __init__(self):
        """Initialize URL discovery"""
        self.use_beautifulsoup = BS4_AVAILABLE
        
        if not self.use_beautifulsoup:
            logger.warning("BeautifulSoup unavailable, using regex fallback")
    
    def discover_urls(self, html_content: str, base_url: str, depth: int = 0) -> List[DiscoveredURL]:
        """
        Main URL discovery method.
        
        Args:
            html_content: HTML content
            base_url: Base URL
            depth: Current depth
            
        Returns:
            List of discovered URLs
        """
        discovered = []
        
        # Extract links
        links = self._extract_links(html_content, base_url, depth)
        discovered.extend(links)
        
        # Extract form actions
        form_actions = self._extract_form_actions(html_content, base_url, depth)
        discovered.extend(form_actions)
        
        # Extract AJAX endpoints
        ajax_endpoints = self._extract_ajax_endpoints(html_content, base_url, depth)
        discovered.extend(ajax_endpoints)
        
        # Extract API endpoints
        api_endpoints = self._extract_api_endpoints(html_content, base_url, depth)
        discovered.extend(api_endpoints)
        
        # Extract resources
        resources = self._extract_resources(html_content, base_url, depth)
        discovered.extend(resources)
        
        # Deduplicate
        unique_urls = self._deduplicate_urls(discovered)
        
        logger.debug(f"Discovered {len(unique_urls)} unique URLs at depth {depth}")
        
        return unique_urls
    
    def _extract_links(self, html_content: str, base_url: str, depth: int) -> List[DiscoveredURL]:
        """Extract regular links from HTML"""
        links = []
        
        if self.use_beautifulsoup:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Extract <a> tags
                for link_tag in soup.find_all('a', href=True):
                    href = str(link_tag.get("href", ""))
                    if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                        absolute_url = urljoin(base_url, href)
                        
                        discovered_url = DiscoveredURL(
                            url=absolute_url,
                            url_type=URLType.LINK,
                            source_context=f"<a> tag: {link_tag.get_text()[:50]}",
                            depth=depth,
                            discovered_at=base_url
                        )
                        links.append(discovered_url)
            
            except Exception as e:
                logger.error(f"Error extracting links with BeautifulSoup: {e}")
                return self._extract_links_with_regex(html_content, base_url, depth)
        
        else:
            return self._extract_links_with_regex(html_content, base_url, depth)
        
        return links
    
    def _extract_links_with_regex(self, html_content: str, base_url: str, depth: int) -> List[DiscoveredURL]:
        """Extract links with regex fallback"""
        links = []
        
        # Pattern for <a> tags
        link_pattern = r'<a[^>]*href\s*=\s*["\']([^"\']*)["\'][^>]*>(.*?)</a>'
        
        for match in re.finditer(link_pattern, html_content, re.IGNORECASE | re.DOTALL):
            href = match.group(1)
            text = match.group(2)
            
            if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                absolute_url = urljoin(base_url, href)
                
                discovered_url = DiscoveredURL(
                    url=absolute_url,
                    url_type=URLType.LINK,
                    source_context=f"<a> tag: {text[:50]}",
                    depth=depth,
                    parent_url=base_url
                )
                links.append(discovered_url)
        
        return links
    
    def _extract_form_actions(self, html_content: str, base_url: str, depth: int) -> List[DiscoveredURL]:
        """Extract form actions"""
        actions = []
        
        if self.use_beautifulsoup:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                for form_tag in soup.find_all('form'):
                    action = str(form_tag.get("action", ""))
                    method = str(form_tag.get("method", "GET")).upper()
                    
                    if action:
                        absolute_url = urljoin(base_url, action)
                        
                        discovered_url = DiscoveredURL(
                            url=absolute_url,
                            url_type=URLType.FORM_ACTION,
                            source_context="<form> action",
                            method=method,
                            depth=depth,
                            parent_url=base_url
                        )
                        actions.append(discovered_url)
            
            except Exception as e:
                logger.error(f"Error extracting form actions: {e}")
        
        return actions
    
    def _extract_ajax_endpoints(self, html_content: str, base_url: str, depth: int) -> List[DiscoveredURL]:
        """Extract AJAX endpoints from JavaScript"""
        endpoints = []
        
        # Common AJAX patterns
        ajax_patterns = [
            r'\.ajax\s*\(\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\s*\(\s*["\'](?:GET|POST)["\'],\s*["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in ajax_patterns:
            for match in re.finditer(pattern, html_content, re.IGNORECASE):
                endpoint = match.group(1)
                if endpoint and not endpoint.startswith('#'):
                    absolute_url = urljoin(base_url, endpoint)
                    
                    discovered_url = DiscoveredURL(
                        url=absolute_url,
                        url_type=URLType.AJAX_ENDPOINT,
                        source_context="JavaScript AJAX",
                        depth=depth,
                        parent_url=base_url
                    )
                    endpoints.append(discovered_url)
        
        return endpoints
    
    def _extract_api_endpoints(self, html_content: str, base_url: str, depth: int) -> List[DiscoveredURL]:
        """Extract API endpoints"""
        endpoints = []
        
        # API patterns
        api_patterns = [
            r'["\']([^"\']*\/api\/[^"\']*)["\']',
            r'["\']([^"\']*\/v\d+\/[^"\']*)["\']',
            r'["\']([^"\']*\.json)["\']',
            r'["\']([^"\']*\/rest\/[^"\']*)["\']'
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, html_content, re.IGNORECASE):
                endpoint = match.group(1)
                if self._is_valid_url_part(endpoint):
                    absolute_url = urljoin(base_url, endpoint)
                    
                    discovered_url = DiscoveredURL(
                        url=absolute_url,
                        url_type=URLType.API_ENDPOINT,
                        source_context="API endpoint pattern",
                        depth=depth,
                        parent_url=base_url
                    )
                    endpoints.append(discovered_url)
        
        return endpoints
    
    def _extract_resources(self, html_content: str, base_url: str, depth: int) -> List[DiscoveredURL]:
        """Extract resource URLs (CSS, JS, images)"""
        resources = []
        
        # Resource patterns
        resource_patterns = [
            (r'<link[^>]*href\s*=\s*["\']([^"\']*)["\']', 'CSS'),
            (r'<script[^>]*src\s*=\s*["\']([^"\']*)["\']', 'JavaScript'),
            (r'<img[^>]*src\s*=\s*["\']([^"\']*)["\']', 'Image'),
            (r'<iframe[^>]*src\s*=\s*["\']([^"\']*)["\']', 'IFrame')
        ]
        
        for pattern, resource_type in resource_patterns:
            for match in re.finditer(pattern, html_content, re.IGNORECASE):
                src = match.group(1)
                if src and not src.startswith(('data:', 'javascript:')):
                    absolute_url = urljoin(base_url, src)
                    
                    discovered_url = DiscoveredURL(
                        url=absolute_url,
                        url_type=URLType.RESOURCE,
                        source_context=f"{resource_type} resource",
                        depth=depth,
                        parent_url=base_url
                    )
                    resources.append(discovered_url)
        
        return resources
    
    def _is_valid_url_part(self, url_part: str) -> bool:
        """Check if URL part is valid"""
        if not url_part or len(url_part) < 2:
            return False
        
        # Skip common false positives
        invalid_patterns = [
            r'^[\d\s]*$',  # Only numbers and spaces
            r'^\w{1,3}$',  # Very short strings
            r'^[^a-zA-Z]*$'  # No letters
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, url_part):
                return False
        
        return True
    
    def _deduplicate_urls(self, discovered_urls: List[DiscoveredURL]) -> List[DiscoveredURL]:
        """Remove duplicate URLs"""
        seen_urls = set()
        unique_urls = []
        
        for discovered_url in discovered_urls:
            # Normalize URL for comparison
            normalized_url = discovered_url.url.lower().rstrip('/')
            
            if normalized_url not in seen_urls:
                seen_urls.add(normalized_url)
                unique_urls.append(discovered_url)
        
        return unique_urls
    
    def get_discovery_stats(self) -> Dict[str, Any]:
        """Discovery statistics"""
        return {
            'parser_used': 'BeautifulSoup' if self.use_beautifulsoup else 'Regex',
            'beautifulsoup_available': BS4_AVAILABLE,
            'supported_url_types': [url_type.value for url_type in URLType]
        }