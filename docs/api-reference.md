# BRS-XSS API Reference

**Project:** BRS-XSS (XSS Detection Suite)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Developer:** Brabus  
**Version:** 4.0.0-beta.2  
**Date:** Sun 12 Jan 2026 UTC  
**Telegram:** https://t.me/EasyProTech

## Table of Contents

- [Web UI REST API](#web-ui-rest-api)
- [Strategy API (NEW)](#strategy-api-new)
- [A/B Testing API (NEW)](#ab-testing-api-new)
- [Core Module](#core-module)
- [WAF Module](#waf-module)
- [DOM Module](#dom-module)
- [Crawler Module](#crawler-module)
- [Report Module](#report-module)

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
    "os_version": "6.8.0-87-generic"
  },
  "modes": {
    "light": {"name": "light", "threads": 4, "requests_per_second": 72},
    "standard": {"threads": 12},
    "turbo": {"threads": 24},
    "maximum": {"threads": 43, "recommended": true}
  },
  "recommended": "maximum",
  "saved_mode": "maximum"
}
```

#### POST /api/system/detect

Force hardware re-detection.

#### POST /api/system/mode?mode={mode_name}

Set preferred performance mode (light, standard, turbo, maximum).

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

List scans with optional `limit` and `status` filters.

#### GET /api/scans/{scan_id}

Get scan details with vulnerabilities.

#### DELETE /api/scans/{scan_id}

Delete a scan.

#### POST /api/scans/{scan_id}/cancel

Cancel a running scan.

### Knowledge Base Endpoints

#### GET /api/kb/stats

Get BRS-KB statistics with full attribution.

#### GET /api/kb/payloads

Query payloads with filtering by category, limit, offset.

### WebSocket

#### WS /ws

Real-time scan progress.

**Connect:** `ws://host:port/ws`

**Messages Received:**
```json
{"type": "progress", "data": {
  "scan_id": "abc123",
  "status": "running",
  "progress_percent": 45,
  "current_phase": "scanning"
}}

{"type": "vulnerability", "scan_id": "abc123", "data": {
  "severity": "high",
  "context": "html_attribute",
  "parameter": "q",
  "payload": "..."
}}
```

---

## Strategy API (NEW)

Strategy management endpoints for PTT (Pentesting Task Tree).

### GET /api/strategy/tree

Get the default strategy tree.

**Response:**
```json
{
  "id": "default",
  "name": "Default PTT Strategy",
  "version": "1.0",
  "root": {...},
  "is_default": true
}
```

### GET /api/strategy/trees

List all strategy trees (custom + default).

**Query Parameters:**
- `user_id`: Filter by user (optional)

### POST /api/strategy/trees

Create a new custom strategy tree.

**Request:**
```json
{
  "name": "My WAF Bypass Strategy",
  "description": "Optimized for Cloudflare bypass",
  "version": "1.0",
  "tags": ["waf", "cloudflare"],
  "tree_data": {
    "root": {...}
  }
}
```

### GET /api/strategy/trees/{tree_id}

Get a specific strategy tree.

### PUT /api/strategy/trees/{tree_id}

Update a custom strategy tree.

**Request:**
```json
{
  "name": "Updated Name",
  "description": "New description",
  "tree_data": {...}
}
```

### DELETE /api/strategy/trees/{tree_id}

Delete a custom strategy tree (default strategies cannot be deleted).

### POST /api/strategy/trees/{tree_id}/clone

Clone an existing strategy tree.

**Query Parameters:**
- `new_name`: Name for the cloned strategy

### POST /api/strategy/trees/{tree_id}/activate

Set a strategy tree as active for new scans.

### GET /api/strategy/trees/active/current

Get currently active strategy tree.

### GET /api/strategy/trees/{tree_id}/export

Export strategy as JSON file.

**Response:** JSON file download

### POST /api/strategy/trees/import

Import strategy from JSON file.

**Request:** Multipart form with file upload

### POST /api/strategy/trees/import/json

Import strategy from JSON body.

**Request:**
```json
{
  "format": "brs-xss-strategy",
  "version": "1.0",
  "strategy": {
    "name": "Imported Strategy",
    "tree_data": {...}
  }
}
```

### POST /api/strategy/simulate

Simulate strategy execution.

**Query Parameters:**
- `context_type`: html, javascript, attribute, url, css
- `waf_detected`: true/false
- `waf_name`: WAF name if detected
- `max_actions`: Maximum actions to simulate (default: 10)

**Response:**
```json
{
  "actions": [
    {
      "step": 1,
      "action_type": "test_payload",
      "payload": "<script>alert(1)</script>",
      "encoding": "none",
      "context": "html",
      "node_id": "node_123"
    }
  ],
  "statistics": {
    "total_actions": 10,
    "success_count": 0,
    "failed_count": 10
  }
}
```

### GET /api/strategy/scan/{scan_id}

Get strategy execution path for a completed scan.

**Response:**
```json
{
  "id": "path_123",
  "scan_id": "scan_456",
  "strategy_tree_id": "default",
  "initial_context": "html",
  "waf_detected": true,
  "waf_name": "Cloudflare",
  "actions": [...],
  "visited_nodes": ["node1", "node2"],
  "node_statuses": {"node1": "success", "node2": "failed"},
  "pivots": [{"reason": "waf_detected", "from": "node1", "to": "node3"}],
  "statistics": {...}
}
```

### GET /api/strategy/scan/{scan_id}/exists

Check if strategy path exists for a scan.

### GET /api/strategy/scan/{scan_id}/summary

Get summary of strategy execution for a scan.

### GET /api/strategy/node-types

Get available node types.

### GET /api/strategy/rule-types

Get available rule types.

### GET /api/strategy/contexts

Get available injection contexts.

### GET /api/strategy/encodings

Get available encoding strategies.

---

## A/B Testing API (NEW)

Endpoints for comparing strategy effectiveness.

### GET /api/strategy/ab-tests

List all A/B tests.

**Query Parameters:**
- `user_id`: Filter by user (optional)
- `status`: Filter by status (pending, running, completed, cancelled)

### POST /api/strategy/ab-tests

Create a new A/B test.

**Request:**
```json
{
  "name": "WAF Bypass Comparison",
  "description": "Compare default vs custom WAF strategy",
  "strategy_a_id": "default",
  "strategy_b_id": "custom_123",
  "target_scans": 10
}
```

**Response:**
```json
{
  "id": "test_456",
  "name": "WAF Bypass Comparison",
  "status": "pending",
  "strategy_a_id": "default",
  "strategy_b_id": "custom_123",
  "target_scans": 10,
  "completed_scans_a": 0,
  "completed_scans_b": 0
}
```

### GET /api/strategy/ab-tests/{test_id}

Get A/B test details.

### POST /api/strategy/ab-tests/{test_id}/start

Start an A/B test.

### POST /api/strategy/ab-tests/{test_id}/cancel

Cancel a running A/B test.

### DELETE /api/strategy/ab-tests/{test_id}

Delete an A/B test.

### GET /api/strategy/ab-tests/running/current

Get currently running A/B test.

### GET /api/strategy/ab-tests/{test_id}/comparison

Get detailed comparison of A/B test results.

**Response:**
```json
{
  "test_id": "test_456",
  "status": "completed",
  "strategy_a": {
    "id": "default",
    "name": "Default PTT Strategy",
    "scans_completed": 10,
    "total_vulns": 15,
    "avg_vulns_per_scan": 1.5,
    "success_rate": 80.0,
    "avg_duration": 45.2
  },
  "strategy_b": {
    "id": "custom_123",
    "name": "WAF Bypass Strategy",
    "scans_completed": 10,
    "total_vulns": 22,
    "avg_vulns_per_scan": 2.2,
    "success_rate": 90.0,
    "avg_duration": 52.1
  },
  "winner": "strategy_b",
  "progress": {
    "target": 10,
    "completed_a": 10,
    "completed_b": 10,
    "percent_complete": 100.0
  }
}
```

---

## Core Module

### XSSScanner

Main XSS vulnerability scanner.

```python
from brsxss.detect.xss.reflected.scanner import XSSScanner

scanner = XSSScanner(
    config=None,
    timeout=10,
    max_concurrent=10,
    verify_ssl=True,
    enable_dom_xss=True,
    max_payloads=None
)
```

**Methods:**

#### scan_url()

Scan a specific entry point for XSS vulnerabilities.

```python
async def scan_url(
    url: str,
    method: str = "GET",
    parameters: dict[str, str] | None = None
) -> list[dict[str, Any]]
```

#### close()

Close scanner and cleanup resources.

---

## WAF Module

### WAFDetector

```python
from brsxss.detect.waf.detector import WAFDetector

detector = WAFDetector(http_client=None)
wafs = await detector.detect_waf("https://example.com")
```

### EvasionEngine

```python
from brsxss.detect.waf.evasion_engine import EvasionEngine

engine = EvasionEngine()
evasions = engine.generate_evasions(payload, detected_wafs, max_variations=50)
```

---

## DOM Module

### DOMAnalyzer

```python
from brsxss.detect.xss.dom.headless_detector import HeadlessDOMDetector

detector = HeadlessDOMDetector(headless=True, timeout=30)
await detector.start()
vulns = await detector.analyze_page("https://example.com")
await detector.close()
```

---

## Crawler Module

### CrawlerEngine

```python
from brsxss.detect.crawler.engine import CrawlerEngine

crawler = CrawlerEngine(max_depth=3, max_pages=100)
entry_points = await crawler.crawl("https://example.com")
```

---

## Report Module

### ReportGenerator

```python
from brsxss.report import ReportGenerator, ReportFormat

generator = ReportGenerator()

# Generate SARIF report
sarif = generator.generate_report(
    vulnerabilities,
    format=ReportFormat.SARIF,
    output_file="results.sarif"
)

# Generate PDF report
from brsxss.report.pdf_report import PDFReportGenerator

pdf_gen = PDFReportGenerator()
pdf_path = pdf_gen.generate(scan_data, vulnerabilities)
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
