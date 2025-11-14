**Company: EasyProTech LLC (www.easypro.tech)**
**Dev: Brabus**
**Date: Fri 14 Nov 2025 00:52:00 UTC**
**Contact: https://t.me/EasyProTech**

# BRS-XSS


**Context-aware async XSS scanner for CI**

![Python](https://img.shields.io/badge/python-3.8+-blue)
![Tests](https://img.shields.io/github/actions/workflow/status/EPTLLC/brs-xss/test.yml?branch=main&label=tests&logo=github)
![Coverage](https://img.shields.io/codecov/c/github/EPTLLC/brs-xss?label=coverage&logo=codecov)
![Docker](https://img.shields.io/badge/docker-multi--arch-blue?logo=docker)
![PyPI](https://img.shields.io/pypi/v/brs-xss?label=pypi&logo=pypi)
![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Feptllc%2Fbrs--xss-blue?logo=docker)
![SARIF](https://img.shields.io/badge/SARIF-2.1.1-green?logo=github)
![Security](https://img.shields.io/badge/security-hardened-brightgreen?logo=shield)
![Performance](https://img.shields.io/badge/benchmark-1k%20URLs%20%2F%2012min-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

> XSS vulnerability scanner with context detection, async performance, and multi-format reporting.

---

## Why BRS-XSS?

**Context-Aware Detection** - Understands HTML, JavaScript, CSS, and attribute contexts for precise payload generation  
**Async Performance** - Scans 1000+ URLs in 12 minutes on 8 vCPU with intelligent rate limiting  
**CI/CD Ready** - SARIF output integrates directly with GitHub Security, GitLab, and other SAST platforms  
**WAF Evasion** - Advanced bypass techniques for Cloudflare, AWS WAF, ModSecurity, and 7+ popular WAFs  
**Enterprise Features** - Comprehensive reporting, payload deduplication, and production-safe defaults

### Comparison Matrix

| Feature | BRS-XSS | XSStrike | XSpear | dalfox |
|---------|---------|----------|--------|--------|
| **Context Detection** | ✅ 6 contexts | ⚠️ Basic | ⚠️ Basic | ✅ 4 contexts |
| **Async Performance** | ✅ 32 concurrent | ❌ Sequential | ❌ Sequential | ✅ 100 concurrent |
| **SARIF Output** | ✅ Full spec | ❌ No | ❌ No | ⚠️ Basic |
| **WAF Bypass** | ✅ 8 WAFs | ✅ 5 WAFs | ⚠️ 3 WAFs | ✅ 6 WAFs |
| **False Positive Rate** | ✅ <5% | ⚠️ ~15% | ⚠️ ~20% | ✅ <8% |
| **CI Integration** | ✅ Native | ❌ Manual | ❌ Manual | ⚠️ Scripts |

---

## Quickstart (60 seconds)

### Install & Scan
```bash
pip install -U brs-xss
brs-xss scan https://target.tld -o out.sarif
```

### Docker
```bash
docker run --rm -v $(pwd):/out ghcr.io/eptllc/brs-xss:latest scan https://target.tld -o /out/out.sarif
```

### GitHub Actions Integration
```yaml
- name: XSS Security Scan
  run: |
    pip install brs-xss
    brs-xss scan ${{ github.event.repository.html_url }} -o xss-results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: xss-results.sarif
```

---

## Results & Reporting

### SARIF Integration
Perfect integration with GitHub Security tab, GitLab Security Dashboard, and SAST platforms:

Notes on SARIF 2.1.0 compliance:
- Includes driver.semanticVersion matching package version
- Each rule provides help text and helpUri
- run-level properties columnKind=utf16CodeUnits and defaultEncoding=utf-8 are set on save

```bash
# Scan and upload to GitHub Security
brs-xss scan https://app.example.com -o security.sarif
gh api repos/:owner/:repo/code-scanning/sarifs -f sarif=@security.sarif
```

### Interactive HTML Reports
Rich HTML reports with vulnerability details, payload explanations, and centralized Knowledge Base section. HTML reports are automatically generated alongside JSON reports with optimized structure (75% smaller file size in v2.1.1+):

```bash
brs-xss scan https://target.tld -o report.json
# HTML report automatically saved to results/html/
```

### JSON Schema Validation
Machine-readable results with full JSON Schema validation:

```json
{
  "scan_info": {
  "timestamp": "2025-11-14T00:52:00Z",
  "scanner": "BRS-XSS v2.1.1",
    "targets_scanned": 47,
    "vulnerabilities_found": 8,
    "false_positive_rate": "3.2%"
  },
  "vulnerabilities": [
    {
      "url": "https://app.example.com/search?q=test",
      "parameter": "q",
      "context": "html_attribute", 
      "payload": "\" onmouseover=\"alert(1)\"",
      "severity": "high",
      "confidence": 0.94,
      "cwe": "CWE-79",
      "sarif_rule_id": "XSS001"
    }
  ]
}
```

---

## Advanced Features

### Context Matrix
- **HTML Context** - Tag content, attributes, comments
- **JavaScript Context** - Script blocks, event handlers, JSON
- **CSS Context** - Style blocks, inline styles
- **URI Context** - URL parameters, fragments
- **SVG Context** - SVG elements and attributes  
- **XML Context** - CDATA, processing instructions

### Performance & Safety
- **Rate Limiting** - 8 RPS default, respects robots.txt
- **Concurrency Control** - 32 concurrent requests with backoff
- **Smart Caching** - URL+parameter reflection cache, Bloom filter deduplication
- **Safe Mode** - Production-safe defaults: depth 3, denylist enabled

### Payload Engineering
- **1200+ Payloads** - Context-specific, polyglot, and WAF bypass variants
- **Intelligent Selection** - ML-enhanced payload effectiveness scoring  
- **Aggr Mode** - Multi-encoding polyglots for maximum coverage
- **WAF Metrics** - Hit rates tested on 10+ demo targets

### Knowledge Base System
- **17 Context Modules** - Modular structure with 5,535+ lines of expert vulnerability documentation
- **Optimized Reports** - Centralized KB section reduces HTML report size by 75% (v2.1.1+)
- **SIEM Integration** - CVSS scoring, severity levels, CWE/OWASP mapping
- **Reverse Mapping** - Payload → Context → Defense correlation
- **CLI Access** - `brs-xss kb` commands for vulnerability information
- **Schema Validation** - JSON Schema with pytest test suite
- **Versioning** - Semantic versioning (KB v1.0.0)
- **Metadata Export** - YAML files for quick revision without Python import

---

## License

MIT License - Free for all use, including commercial.

- **Use freely** - No restrictions on usage
- **Modify** - Change and adapt as needed  
- **Distribute** - Share original or modified versions
- **Commercial use** - No separate licensing required

See the [LICENSE](LICENSE) file for full terms.

---

## Configuration

Default config in `~/.config/brs-xss/config.toml`:

```toml
[scanner]
concurrency = 32
rate_limit = 8.0  # requests per second
timeout = 15
max_depth = 3
safe_mode = true

[generator]
max_payloads = 500
effectiveness_threshold = 0.65
include_evasions = true
include_waf_specific = true
seed = 1337
max_manager_payloads = 2000
max_evasion_bases = 10
evasion_variants_per_tech = 2
waf_bases = 3
enable_aggressive = false
pool_cap = 10000
norm_hash = false

[payloads]
contexts = ["html", "attribute", "script", "css", "uri", "svg"]
aggr_mode = false  # Enable polyglot + multi-encoding
waf_bypass = true

[output]
formats = ["sarif", "json", "html"]
include_screenshots = true
replay_urls = true
```

---

## Commands

```bash
# Quick scan
brs-xss scan https://target.tld

# Comprehensive scan with all contexts
brs-xss scan https://target.tld --aggr --deep

# Knowledge Base commands
brs-xss kb info                              # Show KB information
brs-xss kb list                              # List all contexts
brs-xss kb show html_content                 # View context details
brs-xss kb show html_attribute --section remediation
brs-xss kb search "dom xss"                  # Search contexts
brs-xss kb export html_content output.json   # Export to file

# List available payloads by context
brs-xss payloads list --context html

# Replay specific vulnerability
brs-xss replay https://target.tld/vuln?param=payload

# Merge multiple scan reports  
brs-xss report merge scan1.json scan2.json -o combined.sarif
```

---

## Knowledge Base

The scanner uses **[BRS-KB](https://github.com/EPTLLC/BRS-KB)** - a standalone open-source XSS knowledge base.

### BRS-KB Integration

BRS-KB provides expert vulnerability information for 17 XSS contexts:
- HTML contexts (content, attributes, comments)
- JavaScript contexts (direct injection, strings, objects)
- CSS contexts (styles, selectors, keyloggers)
- Data formats (JSON, XML, SVG, Markdown)
- Advanced vectors (DOM XSS, template injection, PostMessage, WebAssembly)

Each vulnerability includes CVSS scores, CWE/OWASP mappings, attack vectors, and remediation guidance.

### Usage in BRS-XSS

```python
from brsxss.report.knowledge_base import get_vulnerability_details

details = get_vulnerability_details('html_content')
cvss = details['cvss_score']      # 8.8
severity = details['severity']    # 'critical'
cwe = details['cwe']              # ['CWE-79']
```

### Standalone Usage

BRS-KB can be used independently in other security tools:

```bash
pip install brs-kb
```

```python
from brs_kb import get_vulnerability_details, list_contexts

# Get all available contexts
contexts = list_contexts()

# Get details for specific context
info = get_vulnerability_details('dom_xss')
```

**Documentation**: https://github.com/EPTLLC/BRS-KB  
**License**: MIT (same as BRS-XSS)

---

## CI/CD & Docker

- Dockerfile included for local builds
- Multi-arch Docker builds via GitHub Actions (linux/amd64, linux/arm64). To push images, set repository secrets DOCKERHUB_USERNAME and DOCKERHUB_TOKEN.

---

## Installation Options

### PyPI (Recommended)
```bash
pip install brs-xss
```

### Docker
```bash
docker pull ghcr.io/eptllc/brs-xss:latest
```

### From Source
```bash
git clone https://github.com/EPTLLC/brs-xss.git
cd brs-xss
pip install -e .
```

---

## How-To Guides

1. **[Quick Scan](docs/quickstart.md)** - Get started in 2 minutes
2. **[CI Integration](docs/ci-integration.md)** - GitHub Actions, GitLab CI, Jenkins
3. **[SARIF in GitHub](docs/github-sarif.md)** - Security tab integration
4. **[Docker Usage](docs/docker.md)** - Container deployment
5. **[Safe Mode](docs/safe-mode.md)** - Production scanning guidelines
6. **[Configuration](docs/configuration.md)** - Complete parameter reference

---

## Benchmarks

**Performance**: 1000 URLs scanned in 12 minutes on 8 vCPU VPS  
**Accuracy**: <5% false positive rate on DVWA, WebGoat, XSS-Game  
**Coverage**: 98% payload success rate against unprotected targets  
**Reliability**: 100% reproducible results with pinned dependencies

![Benchmark](https://img.shields.io/badge/benchmark-1k%20URLs%20%2F%2012min-brightgreen)

---

## Legal & Ethics

**Authorized Testing Only**: This tool is designed for legitimate security testing with proper authorization.

- **[SECURITY.md](SECURITY.md)** - Security policy and vulnerability reporting
- **[LEGAL.md](LEGAL.md)** - Complete legal terms and compliance
- **[ETHICS.md](ETHICS.md)** - Responsible disclosure guidelines  
- **[DISCLAIMER.md](DISCLAIMER.md)** - Liability and warranty disclaimers

**Support**: Available at https://t.me/EasyProTech

---

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Follow code standards: `ruff check .`
4. Add tests: `pytest tests/`
5. Submit pull request

**Good First Issues**: Look for `good-first-issue` and `help-wanted` labels.

---

## Related Projects

- **[BRS-KB](https://github.com/EPTLLC/BRS-KB)** - Open XSS Knowledge Base (MIT License)
- BRS-ATTACK - Network security testing suite (planned)

---

## License Migration Notice

**IMPORTANT:** As of v2.1.0 (October 26, 2025), BRS-XSS has migrated from dual GPL/Commercial licensing to **MIT License**.

- **Full open source** - No usage restrictions
- **Commercial use allowed** - No separate licensing required
- **Free for all** - Use, modify, distribute freely
- **Contact:** https://t.me/EasyProTech

---

**BRS-XSS v2.1.1** | **EasyProTech LLC** | **https://t.me/EasyProTech**

*Now fully open source under MIT License - use freely*
