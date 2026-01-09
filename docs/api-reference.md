# BRS-XSS API Reference

**Project:** BRS-XSS (XSS Detection Suite)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Developer:** Brabus  
**Version:** 3.0.0  
**Date:** Thu 26 Dec 2025 UTC  
**Telegram:** https://t.me/EasyProTech

## Table of Contents

- [Web UI REST API](#web-ui-rest-api)
- [Core Module](#core-module)
- [WAF Module](#waf-module)
- [DOM Module](#dom-module)
- [Crawler Module](#crawler-module)
- [Report Module](#report-module)
- [Utils Module](#utils-module)

---

## Web UI REST API

BRS-XSS includes a FastAPI-based REST API for the Web UI.

### System Endpoints

#### GET /api/system/info

Get hardware profile and performance modes.

**Response:**
```json
{
  "system": {
    "cpu_model": "AMD EPYC 9274F 24-Core Processor",
    "cpu_cores": 48,
    "cpu_threads": 48,
    "ram_total_gb": 251.4,
    "ram_available_gb": 244.1,
    "os_name": "Linux",
    "os_version": "6.8.0-87-generic",
    "detected_at": "2025-12-26T00:49:08.565826"
  },
  "modes": {
    "light": {
      "name": "light",
      "label": "Light",
      "description": "Minimal resource usage, background scanning",
      "threads": 4,
      "max_concurrent": 4,
      "requests_per_second": 72,
      "request_delay_ms": 50,
      "recommended": false
    },
    "standard": {...},
    "turbo": {...},
    "maximum": {..., "recommended": true}
  },
  "recommended": "maximum",
  "saved_mode": "maximum"
}
```

#### POST /api/system/detect

Force hardware re-detection.

**Response:**
Same as GET /api/system/info with fresh detection.

#### POST /api/system/mode?mode={mode_name}

Set preferred performance mode.

**Parameters:**
- `mode`: One of `light`, `standard`, `turbo`, `maximum`

**Response:**
```json
{
  "status": "saved",
  "mode": "turbo"
}
```

### Scan Endpoints

#### POST /api/scans

Start a new scan.

**Request:**
```json
{
  "target_url": "https://example.com/search?q=test",
  "mode": "standard",
  "follow_redirects": true,
  "custom_headers": {"X-Custom": "value"}
}
```

**Response:**
```json
{
  "scan_id": "abc123def456",
  "status": "started"
}
```

#### GET /api/scans

List scans.

**Query Parameters:**
- `limit`: Max results (default: 20, max: 100)
- `status`: Filter by status (running, completed, failed, cancelled)

**Response:**
```json
[
  {
    "id": "abc123def456",
    "url": "https://example.com/search?q=test",
    "mode": "standard",
    "status": "completed",
    "started_at": "2025-12-26T00:50:00Z",
    "completed_at": "2025-12-26T00:52:00Z",
    "vulnerability_count": 3,
    "critical_count": 1,
    "high_count": 2
  }
]
```

#### GET /api/scans/{scan_id}

Get scan details.

**Response:**
```json
{
  "id": "abc123def456",
  "url": "https://example.com/search?q=test",
  "mode": "standard",
  "status": "completed",
  "started_at": "2025-12-26T00:50:00Z",
  "completed_at": "2025-12-26T00:52:00Z",
  "urls_scanned": 15,
  "parameters_tested": 8,
  "payloads_sent": 1200,
  "duration_seconds": 120,
  "waf_detected": {
    "name": "Cloudflare",
    "type": "cloud",
    "confidence": 0.95,
    "bypass_available": true
  },
  "vulnerabilities": [
    {
      "severity": "critical",
      "context": "html_attribute",
      "parameter": "q",
      "payload": "\" onmouseover=alert(1) \"",
      "proof_url": "https://...",
      "confidence": 0.98
    }
  ]
}
```

#### DELETE /api/scans/{scan_id}

Delete a scan.

**Response:**
```json
{"status": "deleted"}
```

#### POST /api/scans/{scan_id}/cancel

Cancel a running scan.

**Response:**
```json
{"status": "cancelling"}
```

### Knowledge Base Endpoints

#### GET /api/kb/stats

Get BRS-KB statistics with full attribution.

**Response:**
```json
{
  "name": "BRS-KB",
  "full_name": "BRS XSS Knowledge Base",
  "version": "4.0.0",
  "build": "stable",
  "revision": "20251226",
  "author": "Brabus",
  "company": "EasyProTech LLC",
  "website": "https://www.easypro.tech",
  "license": "MIT",
  "repo_url": "https://github.com/EPTLLC/BRS-KB",
  "telegram": "https://t.me/EasyProTech",
  "total_payloads": "<dynamic from API>",
  "contexts": "<dynamic from API>",
  "waf_bypass_count": "<dynamic from API>",
  "available_contexts": ["html_content", "html_attribute", "..."],
  "mode": "remote",
  "api_url": "https://brs-kb.easypro.tech/api/v1"
}
```

#### GET /api/kb/payloads

Query payloads with filtering.

**Query Parameters:**
- `category`: Filter by category (waf_bypass, websocket, graphql, etc.)
- `limit`: Max results (default: 50, max: 500)
- `offset`: Pagination offset

### WebSocket

#### WS /ws

Real-time scan progress.

**Connect:** `ws://host:port/ws`

**Messages Sent:**
```json
{"type": "ping"}
```

**Messages Received:**
```json
{"type": "pong"}

{"type": "progress", "data": {
  "scan_id": "abc123",
  "status": "running",
  "progress_percent": 45,
  "current_phase": "scanning",
  "current_url": "https://example.com/page",
  "elapsed_seconds": 30
}}

{"type": "vulnerability", "scan_id": "abc123", "data": {
  "severity": "high",
  "context": "html_attribute",
  "parameter": "q",
  "payload": "...",
  "proof_url": "..."
}}
```

### Other Endpoints

#### GET /api/dashboard

Get dashboard statistics.

#### GET /api/settings

Get application settings.

#### PUT /api/settings

Update application settings.

#### GET /api/health

Health check endpoint.

---

## Core Module

### XSSScanner

Main XSS vulnerability scanner.

```python
from brsxss.core import XSSScanner

scanner = XSSScanner(
    config=None,                    # ConfigManager instance
    timeout=10,                     # Request timeout (seconds)
    max_concurrent=10,              # Max concurrent requests
    verify_ssl=True,                # SSL verification
    enable_dom_xss=True,            # Enable DOM XSS detection
    blind_xss_webhook=None,         # Blind XSS webhook URL
    progress_callback=None,         # Progress callback function
    max_payloads=None,              # Max payloads per parameter
    http_client=None                # Optional HTTPClient instance
)
```

**Methods:**

#### scan_url()

Scan a specific entry point for XSS vulnerabilities.

```python
async def scan_url(
    url: str,                       # Target URL
    method: str = "GET",            # HTTP method (GET/POST)
    parameters: Optional[Dict[str, str]] = None  # Parameters to test
) -> List[Dict[str, Any]]
```

**Example:**
```python
import asyncio
from brsxss.core import XSSScanner

async def main():
    scanner = XSSScanner(timeout=15, max_concurrent=20)
    
    results = await scanner.scan_url(
        url="https://target.com/search",
        method="GET",
        parameters={"q": "test"}
    )
    
    for vuln in results:
        print(f"Found XSS: {vuln['url']}")
        print(f"Payload: {vuln['payload']}")
        print(f"Severity: {vuln['severity']}")
    
    await scanner.close()

asyncio.run(main())
```

#### close()

Close scanner and cleanup resources.

```python
async def close() -> None
```

---

### ConfigManager

Configuration management system.

```python
from brsxss.core import ConfigManager

config = ConfigManager(config_file="config.yaml")
```

**Methods:**

#### get()

Get configuration value.

```python
def get(key: str, default: Any = None) -> Any
```

**Example:**
```python
config = ConfigManager()
timeout = config.get("scanner.timeout", 15)
rate_limit = config.get("scanner.rate_limit", 8.0)
```

#### set()

Set configuration value.

```python
def set(key: str, value: Any) -> None
```

#### save()

Save configuration to file.

```python
def save(file_path: Optional[str] = None) -> None
```

---

### HTTPClient

Async HTTP client with retry logic.

```python
from brsxss.core import HTTPClient

client = HTTPClient(
    timeout=10,
    verify_ssl=True,
    max_retries=3,
    backoff_factor=2.0
)
```

**Methods:**

#### get()

Send GET request.

```python
async def get(
    url: str,
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None
) -> HTTPResponse
```

#### post()

Send POST request.

```python
async def post(
    url: str,
    data: Optional[Dict[str, str]] = None,
    json: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None
) -> HTTPResponse
```

**Example:**
```python
async def test_request():
    client = HTTPClient(timeout=15)
    
    response = await client.get(
        "https://example.com/api",
        params={"key": "value"},
        headers={"User-Agent": "BRS-XSS/4.0.0-beta.1"}
    )
    
    print(f"Status: {response.status_code}")
    print(f"Body: {response.text}")
    
    await client.close()
```

---

### PayloadGenerator

Context-aware payload generation.

```python
from brsxss.core import PayloadGenerator

generator = PayloadGenerator(
    config=None,                    # GenerationConfig instance
    blind_xss_webhook=None          # Blind XSS webhook
)
```

**Methods:**

#### generate_payloads()

Generate context-specific payloads.

```python
def generate_payloads(
    context_info: Dict[str, Any],
    detected_wafs: Optional[List[DetectedWAF]] = None,
    max_payloads: Optional[int] = None
) -> List[GeneratedPayload]
```

**Example:**
```python
from brsxss.core import PayloadGenerator

generator = PayloadGenerator()

context_info = {
    "context_type": "html_content",
    "tag_name": "div",
    "filters_detected": []
}

payloads = generator.generate_payloads(
    context_info=context_info,
    max_payloads=100
)

for payload in payloads:
    print(f"Payload: {payload.payload}")
    print(f"Effectiveness: {payload.effectiveness_score}")
    print(f"Context: {payload.context}")
```

---

## WAF Module

### WAFDetector

WAF detection system.

```python
from brsxss.waf import WAFDetector

detector = WAFDetector(http_client=None)
```

**Methods:**

#### detect_waf()

Detect WAF on target URL.

```python
async def detect_waf(url: str) -> List[WAFInfo]
```

**Example:**
```python
from brsxss.waf import WAFDetector

async def detect():
    detector = WAFDetector()
    
    wafs = await detector.detect_waf("https://example.com")
    
    for waf in wafs:
        print(f"WAF: {waf.name}")
        print(f"Type: {waf.waf_type}")
        print(f"Confidence: {waf.confidence}")
    
    await detector.close()
```

---

### EvasionEngine

WAF evasion engine.

```python
from brsxss.waf import EvasionEngine

engine = EvasionEngine()
```

**Methods:**

#### generate_evasions()

Generate WAF evasion payloads.

```python
def generate_evasions(
    payload: str,
    detected_wafs: List[WAFInfo],
    max_variations: int = 50
) -> List[EvasionResult]
```

**Example:**
```python
from brsxss.waf import EvasionEngine, WAFInfo, WAFType

engine = EvasionEngine()

waf = WAFInfo(
    waf_type=WAFType.CLOUDFLARE,
    name="Cloudflare",
    confidence=0.95,
    detection_method="header"
)

evasions = engine.generate_evasions(
    "<script>alert(1)</script>",
    [waf],
    max_variations=20
)

for evasion in evasions:
    print(f"Technique: {evasion.technique}")
    print(f"Payload: {evasion.mutated_payload}")
    print(f"Success Probability: {evasion.success_probability}")
```

---

## DOM Module

### DOMAnalyzer

DOM-based XSS analyzer.

```python
from brsxss.dom import DOMAnalyzer

analyzer = DOMAnalyzer(
    headless=True,
    timeout=30
)
```

**Methods:**

#### analyze_page()

Analyze page for DOM XSS vulnerabilities.

```python
async def analyze_page(url: str) -> List[DOMVulnerability]
```

**Example:**
```python
from brsxss.dom import DOMAnalyzer

async def analyze():
    analyzer = DOMAnalyzer()
    await analyzer.start()
    
    vulns = await analyzer.analyze_page("https://example.com")
    
    for vuln in vulns:
        print(f"Source: {vuln.source}")
        print(f"Sink: {vuln.sink}")
        print(f"Severity: {vuln.severity}")
    
    await analyzer.close()
```

---

## Crawler Module

### CrawlerEngine

Web crawler for discovering entry points.

```python
from brsxss.crawler import CrawlerEngine

crawler = CrawlerEngine(
    max_depth=3,
    max_pages=100,
    respect_robots=True
)
```

**Methods:**

#### crawl()

Crawl website and discover entry points.

```python
async def crawl(start_url: str) -> List[EntryPoint]
```

**Example:**
```python
from brsxss.crawler import CrawlerEngine

async def crawl():
    crawler = CrawlerEngine(max_depth=2)
    
    entry_points = await crawler.crawl("https://example.com")
    
    for ep in entry_points:
        print(f"URL: {ep.url}")
        print(f"Method: {ep.method}")
        print(f"Parameters: {ep.parameters}")
```

---

## Report Module

### ReportGenerator

Multi-format report generation.

```python
from brsxss.report import ReportGenerator, ReportFormat

generator = ReportGenerator()
```

**Methods:**

#### generate_report()

Generate vulnerability report.

```python
def generate_report(
    vulnerabilities: List[Dict[str, Any]],
    format: ReportFormat = ReportFormat.JSON,
    output_file: Optional[str] = None
) -> str
```

**Example:**
```python
from brsxss.report import ReportGenerator, ReportFormat

generator = ReportGenerator()

vulnerabilities = [
    {
        "url": "https://example.com/search",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "severity": "high",
        "confidence": 0.95
    }
]

# Generate SARIF report
sarif = generator.generate_report(
    vulnerabilities,
    format=ReportFormat.SARIF,
    output_file="results.sarif"
)

# Generate HTML report
html = generator.generate_report(
    vulnerabilities,
    format=ReportFormat.HTML,
    output_file="results.html"
)
```

---

## Utils Module

### Logger

Logging utility.

```python
from brsxss.utils import Logger

logger = Logger("module.name")
```

**Methods:**

```python
logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")
logger.success("Success message")
```

### URLValidator

URL validation utility.

```python
from brsxss.utils import URLValidator

validator = URLValidator()
```

**Methods:**

#### validate()

Validate URL format and accessibility.

```python
def validate(url: str) -> bool
```

**Example:**
```python
from brsxss.utils import URLValidator

validator = URLValidator()

if validator.validate("https://example.com"):
    print("Valid URL")
else:
    print("Invalid URL")
```

---

## Complete Example

```python
import asyncio
from brsxss.core import XSSScanner, ConfigManager
from brsxss.crawler import CrawlerEngine
from brsxss.report import ReportGenerator, ReportFormat

async def comprehensive_scan():
    # Initialize components
    config = ConfigManager()
    config.set("scanner.timeout", 20)
    config.set("scanner.max_concurrent", 30)
    
    scanner = XSSScanner(config=config, timeout=20, max_concurrent=30)
    crawler = CrawlerEngine(max_depth=2)
    reporter = ReportGenerator()
    
    # Crawl target
    print("Crawling target...")
    entry_points = await crawler.crawl("https://target.com")
    print(f"Found {len(entry_points)} entry points")
    
    # Scan each entry point
    all_vulnerabilities = []
    for ep in entry_points:
        print(f"Scanning {ep.url}...")
        vulns = await scanner.scan_url(
            url=ep.url,
            method=ep.method,
            parameters=ep.parameters
        )
        all_vulnerabilities.extend(vulns)
    
    print(f"Found {len(all_vulnerabilities)} vulnerabilities")
    
    # Generate reports
    sarif_report = reporter.generate_report(
        all_vulnerabilities,
        format=ReportFormat.SARIF,
        output_file="scan_results.sarif"
    )
    
    html_report = reporter.generate_report(
        all_vulnerabilities,
        format=ReportFormat.HTML,
        output_file="scan_results.html"
    )
    
    # Cleanup
    await scanner.close()
    await crawler.close()
    
    print("Scan complete!")
    print(f"SARIF report: scan_results.sarif")
    print(f"HTML report: scan_results.html")

if __name__ == "__main__":
    asyncio.run(comprehensive_scan())
```

---

## Type Definitions

### Common Types

```python
from typing import Dict, List, Any, Optional, Tuple

# Vulnerability result
VulnerabilityResult = Dict[str, Any]  # {url, parameter, payload, severity, confidence, ...}

# Entry point
EntryPoint = Dict[str, Any]  # {url, method, parameters}

# HTTP response
HTTPResponse = namedtuple('HTTPResponse', ['status_code', 'headers', 'text', 'content'])

# WAF info
WAFInfo = dataclass with fields: waf_type, name, confidence, detection_method, ...

```

---

## Error Handling

```python
from brsxss.core import XSSScanner
from brsxss.utils.exceptions import (
    ScannerError,
    NetworkError,
    ValidationError,
    ConfigurationError
)

async def safe_scan():
    scanner = XSSScanner()
    
    try:
        results = await scanner.scan_url("https://example.com")
    except NetworkError as e:
        print(f"Network error: {e}")
    except ValidationError as e:
        print(f"Validation error: {e}")
    except ScannerError as e:
        print(f"Scanner error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        await scanner.close()
```

---

## Support

For API questions and support:

- **Documentation**: https://github.com/EPTLLC/brs-xss/wiki
- **Issues**: https://github.com/EPTLLC/brs-xss/issues
- **Telegram**: https://t.me/EasyProTech
- **Email**: support@easypro.tech

---

**BRS-XSS** | **EasyProTech LLC** | **https://t.me/EasyProTech**

