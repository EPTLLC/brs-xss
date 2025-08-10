```
██████╗ ██████╗ ███████╗      ██╗  ██╗███████╗███████╗
██╔══██╗██╔══██╗██╔════╝      ╚██╗██╔╝██╔════╝██╔════╝
██████╔╝██████╔╝███████╗█████╗ ╚███╔╝ ███████╗███████╗
██╔══██╗██╔══██╗╚════██║╚════╝ ██╔██╗ ╚════██║╚════██║
██████╔╝██║  ██║███████║      ██╔╝ ██╗███████║███████║
╚═════╝ ╚═╝  ╚═╝╚══════╝      ╚═╝  ╚═╝╚══════╝╚══════╝
```

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-GPLv3%20%2F%20Commercial-red)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen)
![GitHub stars](https://img.shields.io/github/stars/EPTLLC/brs-xss?style=social)
![GitHub forks](https://img.shields.io/github/forks/EPTLLC/brs-xss?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/EPTLLC/brs-xss?style=social)

# BRS-XSS

**Professional XSS Scanner with Advanced Detection Capabilities**

**Company:** EasyProTech LLC (www.easypro.tech)  
**Developer:** Brabus  
**Created:** Thu 07 Aug 2025 01:04:15 MSK  
**Version:** 1.0.2  
**Updated:** Mon 11 Aug 2025 01:40:52 MSK  
**Telegram:** https://t.me/EasyProTech

## Overview

BRS-XSS is a command-line Cross-Site Scripting (XSS) vulnerability scanner designed for security professionals and penetration testers. Built with modular Python architecture and comprehensive detection capabilities.

**BRS-XSS is part of the [Brabus Recon Suite (BRS)](https://github.com/EPTLLC/brs), a modular toolkit for professional network analysis and security auditing.**

### Key Features

- **🎯 Context-Aware Scanning** - Intelligent payload generation based on injection context (HTML, JavaScript, CSS)
- **🛡️ WAF Detection & Bypass** - Advanced evasion techniques for popular WAF solutions
- **🧠 Intelligent Classification** - Advanced heuristic analysis with ML-ready framework
- **📊 Professional Reporting** - Multiple output formats (HTML, JSON; optional SARIF/JUnit)
- **🌐 Multi-Language Support** - English (default) and Russian interfaces
- **⚡ High Performance** - Asynchronous scanning with configurable threading
- **🕷️ Web Crawling** - Form extraction and URL discovery capabilities
- **🔍 DOM XSS Analysis** - Client-side JavaScript vulnerability detection

### 🛠️ Technology Stack

- **Core:** Python 3.8+, AsyncIO, aiohttp
- **CLI:** Typer with rich terminal output
- **Analysis:** Intelligent heuristic algorithms with ML-ready architecture
- **Reporting:** Jinja2 templates, multiple export formats
- **Crawling:** BeautifulSoup with regex fallback
- **I18N:** Babel for internationalization

### 🏗️ Architecture

- **Modular Design** - Independent, testable components following SRP
- **CLI-First** - Terminal-focused interface
- **Asynchronous** - Non-blocking HTTP operations
- **Extensible** - Plugin-ready architecture

## Quick Start

### Installation

```bash
# Install (editable)
pip install -e .

# First run (install browsers for DOM analysis)
playwright install
```

### Docker

```bash
# Build image (includes Playwright browsers)
docker build -t brs-xss:latest .

# Run scan
docker run --rm brs-xss:latest scan example.com
```

### Basic Usage

```bash
# Serious scan (maximal discovery + testing by default)
brs-xss scan example.com

# Scan with options
brs-xss scan example.com --threads 20 --timeout 15

# Show version
brs-xss version

# Show configuration
brs-xss config --show
```

### Advanced Options

```bash
# Deep scan with custom settings
brs-xss scan target.com \
  --threads 25 \
  --timeout 20 \
  --output /path/to/report.json \
  --verbose

# Scan with SSL bypass
brs-xss scan internal.company.com --no-ssl-verify

# Blind XSS testing
brs-xss scan target.com --blind-xss https://webhook.site/unique-id
```

### 🎯 Live Example

**Testing against XSS Game (Educational Purpose):**
```bash
# Scan vulnerable target
python3 main.py scan "xss-game.appspot.com/level1/frame?query=test" --verbose

# Expected Output:
# ✅ 5 vulnerabilities found
# - alert(document.cookie)
# - eval("alert(1)")  
# - setTimeout("alert(1)",0)
# - Function("alert(1)")()
# Report saved: results/json/scan_report_*.json
```

## Project Structure

```
brs-xss/
├── brsxss/                    # Main package
│   ├── core/                  # Core scanning engine
│   ├── payloads/              # Payload collections
│   ├── dom/                   # DOM XSS analysis (Playwright)
│   ├── waf/                   # WAF detection & bypass
│   ├── ml/                    # Machine learning
│   ├── report/                # Report generation
│   ├── utils/                 # Utilities
│   └── i18n/                  # Internationalization
├── cli/                       # Command-line interface
│   ├── main.py                # CLI entry point
│   └── commands/              # CLI commands
├── config/                    # Configuration
├── requirements/              # Dependencies
├── results/                   # Scan results (auto-created)
│   ├── html/                  # Professional HTML reports
│   └── json/                  # Simple & professional JSON reports
├── README.md
├── CHANGELOG.md
├── LICENSE
├── DISCLAIMER.md
├── ETHICS.md
├── LEGAL.md
├── KEY_VERIFICATION.md
├── setup.py
└── main.py                    # Application entry point
```

## Supported Languages

| Code | Language | Status |
|------|----------|--------|
| `en` | English | ✅ Complete |
| `ru` | Russian | ✅ Complete |

*Additional languages can be added by extending the i18n system.*

## Core Capabilities

### Context Analysis
- **HTML Context Detection** - Tag, attribute, and text content analysis
- **JavaScript Context** - Script tag and event handler detection  
- **CSS Context** - Style tag and inline style analysis
- **Filter Detection** - Input sanitization analysis

### WAF Detection & Bypass
- **Supported WAFs:** Cloudflare, AWS WAF, Incapsula, ModSecurity, Akamai, Barracuda, F5 BIG-IP
- **Evasion Techniques:** Encoding, obfuscation, payload fragmentation, case variation
- **Adaptive Strategies** - WAF-specific bypass methods

### Machine Learning
- **Context Classification** - ML-enhanced context detection
- **Payload Effectiveness** - Predictive payload scoring
- **Vulnerability Assessment** - Risk-based classification

### Reporting Formats
- **HTML** - Interactive reports with detailed analysis (default)
- **JSON** - Machine-readable structured data (default)
- **SARIF** - Static Analysis Results Interchange Format (optional)
- **JUnit (XML)** - CI-friendly XML (optional)

## Results Structure

All scan results are automatically saved to the `results/` directory:

```
results/
├── json/     # Machine-readable JSON data (simple scan report)
├── brsxss_report_<timestamp>.html  # Professional HTML reports
├── brsxss_report_<timestamp>.json  # Professional JSON reports
└── README.md
```

### 📋 Example Results

**JSON Report Sample:**
```json
{
  "scan_info": {
    "timestamp": "2025-08-07T01:21:13.000000",
    "scanner": "BRS-XSS Simple Scanner v1.0.0",
    "targets_scanned": 2,
    "vulnerabilities_found": 5
  },
  "vulnerabilities": [
    {
      "url": "http://xss-game.appspot.com/level1/frame?query=test",
      "parameter": "query",
      "payload": "alert(document.cookie)",
      "vulnerable": true,
      "reflection_type": "exact",
      "context": "javascript",
      "severity": "medium",
      "score": 6.96,
      "confidence": 0.569,
      "exploitation_confidence": 0.85,
      "context_analysis": {
        "context_type": "javascript",
        "risk_level": "high",
        "payload_recommendations": [
          "Use eval() for dynamic code execution",
          "Try constructor.constructor() for code execution"
        ]
      }
    }
  ]
}
```

**HTML Reports:** Interactive reports with vulnerability details available in `results/html/`

**SARIF Integration:** Compatible with GitHub Security tab and other security tools.

## Configuration

Configuration is managed through `config/default.yaml`:

```yaml
scanner:
  max_depth: 3
  timeout: 10
  threads: 10
  
payloads:
  max_generation: 1000
  contexts: ["html", "attribute", "script", "comment"]
  
ml:
  enable_prediction: true
  confidence_threshold: 0.8
  
reporting:
  formats: ["html", "json", "sarif", "xml", "csv"]
  output_dir: "./results/"
```

## Current Status

### ✅ Implemented Features
- [x] Core XSS scanning engine
- [x] Context-aware payload generation
- [x] WAF detection and bypass techniques
- [x] ML-based vulnerability classification
- [x] Web crawling and form extraction
- [x] DOM XSS analysis capabilities
- [x] Multi-format reporting
- [x] Internationalization (EN/RU)
- [x] CLI interface with rich output
- [x] Configuration management

### 🚧 Known Limitations
- No GUI interface (CLI only)
- No REST API server
- Limited to 2 languages currently (EN/RU)
- Analysis uses intelligent heuristics (no pre-trained ML models included)
- DOM dynamic analysis requires `playwright install` to provision browsers
- WAF bypass techniques not thoroughly tested on production configurations

## BRS Suite Integration

BRS-XSS is a specialized module within the [Brabus Recon Suite (BRS)](https://github.com/EPTLLC/brs) ecosystem:

### Related BRS Modules:
- **[BRS Core](https://github.com/EPTLLC/brs)** - Network reconnaissance and vulnerability scanning
- **BRS-XSS** - Cross-Site Scripting vulnerability detection (this module)
- **BRS-SQL** - SQL injection testing framework *(planned)*
- **BRS-Web** - Web application security scanner *(planned)*

### BRS Features:
- **Modular Architecture** - Independent, interoperable security tools
- **Professional Interface** - Business-appropriate, emoji-free design
- **Comprehensive Results** - Timestamped, structured reporting
- **GPG-Signed Releases** - Cryptographically verified authenticity

**Learn more:** [BRS Documentation](https://github.com/EPTLLC/brs)

## Contributing

Community contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Follow the modular architecture
4. Ensure all comments and code are in English
5. Submit a pull request

## Support Policy

**NO SUPPORT PROVIDED**: This project is released as-is without support, consultation, or assistance.

**Community Contributions**: Development contributions are welcome but not obligated.

## Legal Framework

**COMPREHENSIVE LEGAL PROTECTION:**

### License Structure
- **[LICENSE](LICENSE)** - Dual GPLv3/Commercial licensing terms
- **[LEGAL.md](LEGAL.md)** - Complete legal terms and compliance requirements
- **[DISCLAIMER.md](DISCLAIMER.md)** - Liability disclaimers and warranties

### Security & Ethics
- **[ETHICS.md](ETHICS.md)** - Responsible use guidelines and ethical principles  
- **[KEY_VERIFICATION.md](KEY_VERIFICATION.md)** - GPG signature verification procedures

### Quick Reference
**GPLv3 License:** Educational, research, and open-source projects  
**Commercial License:** Commercial entities - Contact https://t.me/EasyProTech  

**⚖️ CRITICAL:** Read all legal documents before use. Unauthorized use is illegal and will be prosecuted.

---

**BRS-XSS v1.0.2** | **[Brabus Recon Suite](https://github.com/EPTLLC/brs)** | **EasyProTech LLC** | **Developer: Brabus** | **https://t.me/EasyProTech**

*Professional XSS Detection for Authorized Security Testing*

**⚠️ Disclaimer:** This tool is intended for authorized security testing only. Users are responsible for compliance with applicable laws and regulations.

## Technical Specifications

### WAF Detection & Testing
**Detected WAFs:** Cloudflare, AWS WAF, Incapsula, ModSecurity, Akamai, Barracuda, F5 BIG-IP, Fortinet, Sucuri
**Testing Status:** Pattern-based detection only. Bypass techniques require validation on live WAF configurations.
**Recommended Testing:** Controlled environments with known WAF setups for verification.

### Machine Learning Implementation
**Current Status:** Heuristic-based analysis with ML framework prepared
**Implementation:**
- Context: Rule-based detection using 25+ HTML/JS features
- Payload: Heuristic scoring of 30+ payload characteristics  
- Vulnerability: Risk scoring based on context + reflection accuracy

**ML Framework:** scikit-learn compatible architecture ready for model training
**Models:** No pre-trained models included - uses intelligent fallback algorithms
**Accuracy:** Context detection ~70-80%, Payload effectiveness ~60-75% (heuristic-based)

### DOM XSS Analysis
**Current Capability:** Headless browser execution (Playwright) + source/sink detection
**Sources Detected:** 25+ (location.*, document.*, localStorage, postMessage, etc.)
**Sinks Detected:** 20+ (innerHTML, eval, document.write, setTimeout, etc.)
**Limitations:** Requires `playwright install` to provision browsers

**Dynamic Analysis Features:**
- JavaScript execution monitoring (console, pageerror, dialog)
- Real-time sink detection during execution
- Screenshot capture for PoC

### Security & Logging
**Payload Sanitization:** Automatic truncation and character filtering for logs
**Sensitive Data Handling:** No credentials or tokens logged by default
**Safe Logging Mode:** Available via PayloadValidator.sanitize_payload_for_logging()
**Log Levels:** DEBUG, INFO, WARNING, ERROR, CRITICAL, SUCCESS with color coding

### Performance Metrics
- **Python Version:** 3.8+
- **Dependencies:** See `requirements/base.txt`
- **File Count:** 100+ Python modules across 8 main packages
- **Lines of Code:** ~15,000 (estimated)
- **Architecture:** Modular, following Single Responsibility Principle
- **Performance:** Asynchronous HTTP with configurable concurrency (1-50 threads)
- **Memory Usage:** Optimized for large-scale scans with result caching