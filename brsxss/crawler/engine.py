#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import asyncio
import time
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field

from .scope import ScopeManager
from .form_parser import FormExtractor
from .url_discovery import URLDiscovery
from ..core.http_client import HTTPClient
from ..utils.logger import Logger
logger = Logger("crawler.engine")


@dataclass
class CrawlConfig:
    """Crawler configuration"""
    # Main settings
    max_depth: int = 3                    # Maximum depth
    max_urls: int = 1000                  # Maximum number of URLs
    max_concurrent: int = 10              # Maximum parallel requests
    request_delay: float = 0.1            # Delay between requests
    timeout: int = 10                     # Request timeout
    
    # Content filters  
    follow_redirects: bool = True         # Follow redirects
    extract_forms: bool = True            # Extract forms
    extract_links: bool = True            # Extract links
    extract_ajax: bool = True             # Search AJAX endpoints
    
    # User-Agent and headers
    user_agent: str = "BRS-XSS Crawler v1.0"
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # Error handling
    retry_failed: bool = True             # Retry failed requests
    max_retries: int = 3                  # Maximum retries
    skip_non_html: bool = True            # Skip non-HTML content


@dataclass
class CrawlResult:
    """Crawl result"""
    url: str
    status_code: int
    content: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    response_time: float = 0.0
    depth: int = 0
    
    # Extracted data
    discovered_urls: List[Any] = field(default_factory=list)
    extracted_forms: List[Any] = field(default_factory=list)
    
    # Error info
    error: Optional[str] = None
    retry_count: int = 0


class CrawlerEngine:
    """
    Asynchronous web crawler engine.
    
    Functions:
    - Asynchronous crawling with configurable concurrency
    - Smart scope management
    - Form and link extraction
    - AJAX endpoint discovery
    - Configurable depth and URL limits
    """
    
    def __init__(self, config: Optional[CrawlConfig] = None, http_client: Optional[HTTPClient] = None):
        """Initialize crawler"""
        self.config = config or CrawlConfig()
        self.http_client = http_client or HTTPClient()
        self._owns_http_client = http_client is None  # Track if we created the client
        self.form_extractor = FormExtractor()
        self.url_discovery = URLDiscovery()
        
        # State
        self.crawled_urls: Set[str] = set()
        self.crawl_queue: asyncio.Queue = asyncio.Queue()
        self.results: List[CrawlResult] = []
        self.scope_manager: Optional[ScopeManager] = None
        
        # Statistics
        self.start_time = 0.0
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
    
    async def crawl(self, start_url: str) -> List[CrawlResult]:
        """
        Start crawling from URL.
        
        Args:
            start_url: Starting URL
            
        Returns:
            List of crawl results
        """
        logger.info(f"Starting crawl from: {start_url}")
        self.start_time = time.time()
        
        # Initialize scope manager
        self.scope_manager = ScopeManager(start_url)
        
        # Add starting URL to queue
        await self.crawl_queue.put((start_url, 0))
        self.crawled_urls.add(start_url)
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        
        # Start crawler workers
        tasks = []
        for _ in range(self.config.max_concurrent):
            task = asyncio.create_task(self._crawler_worker(semaphore))
            tasks.append(task)
        
        # Wait for queue to be empty
        await self.crawl_queue.join()
        
        # Cancel workers
        for task in tasks:
            task.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*tasks, return_exceptions=True)
        
        duration = time.time() - self.start_time
        logger.success(f"Crawl completed in {duration:.2f}s. Processed {len(self.results)} URLs")
        
        return self.results
    
    async def _crawler_worker(self, semaphore: asyncio.Semaphore):
        """Crawler worker coroutine"""
        while True:
            try:
                # Get URL from queue with longer timeout
                url, depth = await asyncio.wait_for(
                    self.crawl_queue.get(), timeout=30.0
                )
                
                try:
                    async with semaphore:
                        await self._crawl_url(url, depth)
                finally:
                    self.crawl_queue.task_done()
                
                # Delay between requests
                if self.config.request_delay > 0:
                    await asyncio.sleep(self.config.request_delay)
                
            except asyncio.TimeoutError:
                # No more URLs in queue
                break
            except Exception as e:
                logger.error(f"Worker error: {e}")
                # Still mark task as done even on error
                try:
                    self.crawl_queue.task_done()
                except Exception:
                    pass
                continue
    
    async def _crawl_url(self, url: str, depth: int):
        """Crawl single URL"""
        if len(self.results) >= self.config.max_urls:
            return
        
        if depth > self.config.max_depth:
            return
        
        logger.debug(f"Crawling: {url} (depth: {depth})")
        
        try:
            # Make request
            start_time = time.time()
            response = await self.http_client.get(
                url,
                timeout=self.config.timeout,
                headers=self._get_request_headers()
            )
            response_time = time.time() - start_time
            
            self.total_requests += 1
            
            # Check content type (case-insensitive)
            content_type = response.headers.get('content-type', '') or response.headers.get('Content-Type', '')
            content_type = content_type.lower()
            if self.config.skip_non_html and 'html' not in content_type:
                logger.debug(f"Skipping non-HTML content: {url} (content-type: {content_type})")
                return
            
            # Create result
            result = CrawlResult(
                url=url,
                status_code=response.status_code,
                content=response.text,
                headers=dict(response.headers),
                response_time=response_time,
                depth=depth
            )
            
            # Extract data if successful
            if 200 <= response.status_code < 300:
                self.successful_requests += 1
                await self._extract_data(result, depth)
            else:
                self.failed_requests += 1
                result.error = f"HTTP {response.status_code}"
            
            self.results.append(result)
            
        except Exception as e:
            self.failed_requests += 1
            error_result = CrawlResult(
                url=url,
                status_code=0,
                depth=depth,
                error=str(e)
            )
            self.results.append(error_result)
            logger.error(f"Error crawling {url}: {e}")
    
    async def _extract_data(self, result: CrawlResult, depth: int):
        """Extract data from crawl result"""
        
        # Extract URLs
        if self.config.extract_links:
            discovered_urls = self.url_discovery.discover_urls(
                result.content, result.url, depth
            )
            result.discovered_urls = discovered_urls
            
            # Add new URLs to queue
            await self._add_urls_to_queue(discovered_urls, depth + 1)
        
        # Extract forms
        if self.config.extract_forms:
            forms = self.form_extractor.extract_forms(result.content, result.url)
            result.extracted_forms = forms
    
    async def _add_urls_to_queue(self, discovered_urls: List[Any], depth: int):
        """Add discovered URLs to crawl queue"""
        for discovered_url in discovered_urls:
            url = discovered_url.url
            
            # Check if already crawled
            if url in self.crawled_urls:
                continue
            
            # Check scope
            if self.scope_manager and not self.scope_manager.is_in_scope(url):
                continue
            
            # Add to queue
            self.crawled_urls.add(url)
            await self.crawl_queue.put((url, depth))
            
            # Check URL limit
            if len(self.crawled_urls) >= self.config.max_urls:
                break
    
    def _get_request_headers(self) -> Dict[str, str]:
        """Get request headers"""
        headers = {
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Add custom headers
        headers.update(self.config.custom_headers)
        
        return headers
    
    def get_crawl_stats(self) -> Dict[str, Any]:
        """Get crawl statistics"""
        duration = time.time() - self.start_time if self.start_time else 0
        
        stats = {
            'duration': duration,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'success_rate': self.successful_requests / max(1, self.total_requests),
            'urls_discovered': len(self.crawled_urls),
            'results_count': len(self.results),
            'average_response_time': self._calculate_average_response_time()
        }
        
        if self.scope_manager:
            stats.update(self.scope_manager.get_scope_stats())
        
        return stats
    
    def _calculate_average_response_time(self) -> float:
        """Calculate average response time"""
        if not self.results:
            return 0.0
        
        total_time = sum(result.response_time for result in self.results if result.response_time > 0)
        count = len([r for r in self.results if r.response_time > 0])
        
        return total_time / max(1, count)
    
    async def close(self):
        """Close crawler and cleanup resources"""
        if self._owns_http_client and self.http_client:
            await self.http_client.close()