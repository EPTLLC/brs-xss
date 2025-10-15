# BRS-XSS API Reference

**Project:** BRS-XSS (XSS Detection Suite)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Developer:** Brabus  
**Version:** 2.0.0  
**Date:** Wed 15 Oct 2025 02:30:00 MSK  
**Telegram:** https://t.me/EasyProTech

## Table of Contents

- [Core Module](#core-module)
- [ML Module](#ml-module)
- [WAF Module](#waf-module)
- [DOM Module](#dom-module)
- [Crawler Module](#crawler-module)
- [Report Module](#report-module)
- [Utils Module](#utils-module)

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
        headers={"User-Agent": "BRS-XSS v2.0.0"}
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

### MLIntegration

Machine learning integration layer.

```python
from brsxss.core import MLIntegration

ml = MLIntegration(
    enable_ml=True,
    models_dir="brsxss/ml/models"
)
```

**Methods:**

#### enhance_context_detection()

Enhance context detection with ML predictions.

```python
def enhance_context_detection(
    html_content: str,
    marker_position: int,
    heuristic_context: str,
    heuristic_confidence: float
) -> Dict[str, Any]
```

**Example:**
```python
ml = MLIntegration(enable_ml=True)

enhanced = ml.enhance_context_detection(
    html_content="<div>USER_INPUT</div>",
    marker_position=5,
    heuristic_context="html_content",
    heuristic_confidence=0.7
)

print(f"Context: {enhanced['context']}")
print(f"Confidence: {enhanced['confidence']}")
print(f"ML Enhanced: {enhanced['ml_enhanced']}")
```

#### score_payload_effectiveness()

Score payload effectiveness using ML.

```python
def score_payload_effectiveness(
    payload: str,
    context: str,
    base_score: float = 0.5
) -> Dict[str, Any]
```

#### get_statistics()

Get ML integration statistics.

```python
def get_statistics() -> Dict[str, Any]
```

---

## ML Module

### MLPredictor

Main ML prediction system.

```python
from brsxss.ml import MLPredictor

predictor = MLPredictor(
    models_dir="brsxss/ml/models",
    enable_cache=True
)
```

**Methods:**

#### predict_context()

Predict injection context using ML.

```python
def predict_context(
    html_content: str,
    marker_position: int
) -> PredictionResult
```

#### predict_payload_effectiveness()

Predict payload effectiveness.

```python
def predict_payload_effectiveness(
    payload: str
) -> PredictionResult
```

#### predict_vulnerability_severity()

Predict vulnerability severity.

```python
def predict_vulnerability_severity(
    vulnerability_data: Dict[str, Any]
) -> PredictionResult
```

**Example:**
```python
from brsxss.ml import MLPredictor

predictor = MLPredictor()

# Predict context
context_result = predictor.predict_context(
    "<script>USER_INPUT</script>",
    8
)
print(f"Context: {context_result.prediction}")
print(f"Confidence: {context_result.confidence}")

# Predict payload effectiveness
payload_result = predictor.predict_payload_effectiveness(
    "<script>alert(1)</script>"
)
print(f"Effectiveness: {payload_result.prediction}")
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
from brsxss.core import XSSScanner, ConfigManager, MLIntegration
from brsxss.crawler import CrawlerEngine
from brsxss.report import ReportGenerator, ReportFormat

async def comprehensive_scan():
    # Initialize components
    config = ConfigManager()
    config.set("scanner.timeout", 20)
    config.set("scanner.max_concurrent", 30)
    
    ml = MLIntegration(enable_ml=True)
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

# Prediction result
PredictionResult = dataclass with fields: prediction, confidence, confidence_level, ...
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

**BRS-XSS v2.0.0** | **EasyProTech LLC** | **https://t.me/EasyProTech**

