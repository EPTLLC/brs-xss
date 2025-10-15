# BRS-XSS Examples

**Project:** BRS-XSS (XSS Detection Suite)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Developer:** Brabus  
**Telegram:** https://t.me/EasyProTech

## Overview

This directory contains practical examples demonstrating various features and usage patterns of BRS-XSS.

## Examples

### 01. Basic Scan (`01_basic_scan.py`)

Learn how to perform a basic XSS scan on a single URL with GET parameters.

**Features demonstrated:**
- Scanner initialization
- Basic GET parameter scanning
- Result processing and display

**Run:**
```bash
python3 examples/01_basic_scan.py
```

---

### 02. POST Form Scan (`02_post_form_scan.py`)

Scan HTML forms using POST method to detect XSS in form submissions.

**Features demonstrated:**
- POST method scanning
- Form field testing
- Exploitability scoring

**Run:**
```bash
python3 examples/02_post_form_scan.py
```

---

### 03. WAF Bypass (`03_waf_bypass.py`)

Detect WAFs and automatically generate bypass payloads.

**Features demonstrated:**
- WAF detection
- Bypass payload generation
- Success probability ranking
- WAF-aware scanning

**Run:**
```bash
python3 examples/03_waf_bypass.py
```

---

### 04. ML-Enhanced Scan (`04_ml_enhanced_scan.py`)

Use Machine Learning for improved detection accuracy.

**Features demonstrated:**
- ML integration
- Context prediction enhancement
- Payload effectiveness scoring
- Vulnerability severity assessment
- ML statistics reporting

**Run:**
```bash
python3 examples/04_ml_enhanced_scan.py
```

---

### 05. Full Website Scan (`05_full_website_scan.py`)

Perform a comprehensive scan of an entire website.

**Features demonstrated:**
- Website crawling
- Entry point discovery
- Bulk scanning
- Multi-format report generation (SARIF, HTML, JSON)
- Scan statistics

**Run:**
```bash
python3 examples/05_full_website_scan.py
```

---

## Requirements

All examples require BRS-XSS to be installed:

```bash
# Install from source
pip install -e .

# Or install from PyPI
pip install brs-xss
```

## Usage Notes

### Target URLs

Examples use `https://example.com` as placeholder. Replace with actual test targets:

```python
# Replace this
target_url = "https://example.com/search"

# With your test target
target_url = "https://yourtestsite.local/search"
```

### Authorization

**IMPORTANT:** Only scan systems you own or have explicit written permission to test.

### Rate Limiting

For production scans, adjust concurrency and rate limits:

```python
scanner = XSSScanner(
    timeout=20,
    max_concurrent=10,  # Adjust based on target capacity
    verify_ssl=True
)
```

### Safe Mode

Enable safe mode for production environments:

```python
# In config file
scanner:
  safe_mode: true
  max_depth: 2
  respect_robots: true
```

## Advanced Examples

### Custom Configuration

```python
from brsxss.core import ConfigManager, XSSScanner

config = ConfigManager()
config.set("scanner.timeout", 30)
config.set("scanner.max_concurrent", 50)
config.set("payloads.max_generation", 2000)

scanner = XSSScanner(config=config)
```

### Progress Tracking

```python
def progress_callback(current, total):
    percent = (current / total) * 100
    print(f"Progress: {percent:.1f}% ({current}/{total})")

scanner = XSSScanner(progress_callback=progress_callback)
```

### Custom Reports

```python
from brsxss.report import ReportGenerator

reporter = ReportGenerator()

# Add custom fields
vulnerabilities = [
    {
        "url": "...",
        "parameter": "...",
        "severity": "high",
        "custom_field": "custom_value"
    }
]

reporter.generate_report(vulnerabilities, format=ReportFormat.JSON)
```

## Testing Examples

Run examples against test targets:

```bash
# DVWA (Damn Vulnerable Web Application)
docker run -d -p 80:80 vulnerables/web-dvwa

# WebGoat
docker run -d -p 8080:8080 webgoat/goat

# Then run examples
python3 examples/01_basic_scan.py
```

## CI/CD Integration

Use examples as templates for CI/CD pipelines:

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install brs-xss
    python3 examples/05_full_website_scan.py
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: scan_results.sarif
```

## Troubleshooting

### Import Errors

```bash
# Ensure BRS-XSS is installed
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="/path/to/brs-xss:$PYTHONPATH"
```

### SSL Errors

```python
# Disable SSL verification (not recommended for production)
scanner = XSSScanner(verify_ssl=False)
```

### Timeout Issues

```python
# Increase timeout for slow targets
scanner = XSSScanner(timeout=60)
```

## Contributing

To add new examples:

1. Create new file: `examples/06_your_example.py`
2. Follow existing format and style
3. Add documentation to this README
4. Test thoroughly
5. Submit pull request

## Support

For questions about examples:

- **Documentation**: https://github.com/EPTLLC/brs-xss/wiki
- **Issues**: https://github.com/EPTLLC/brs-xss/issues
- **Telegram**: https://t.me/EasyProTech

---

**BRS-XSS v2.0.0** | **EasyProTech LLC**

