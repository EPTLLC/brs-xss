# BRS-XSS v1.0.5.1 Release Notes

**Context-aware async XSS scanner for CI**

## Highlights

- **GitHub Security Integration**: Direct SARIF 2.1.0 upload to GitHub Security tab
- **Enterprise Documentation**: 6 comprehensive guides for CI/CD integration  
- **Production Readiness**: Docker multi-arch builds and performance benchmarks

## Installation

```bash
# PyPI (recommended)
pip install -U brs-xss

# Docker
docker pull ghcr.io/eptllc/brs-xss:1.0.5.1

# From source
git clone https://github.com/EPTLLC/brs-xss.git
cd brs-xss
pip install -e .
```

## Quick Start

```bash
# Basic scan with safe mode (default)
brs-xss scan https://target.tld -o report.sarif

# CI/CD integration
brs-xss scan $CI_PROJECT_URL --safe-mode --timeout 30
```

## What's New in v1.0.5.1

### Core Improvements
- **SARIF 2.1.0 Compliance (stabilized)**: Fixed reporter structure, added `driver.semanticVersion`, rule help/helpUri, CWE mapping, and run-level properties
- **Reliability**: New SARIF structure tests to prevent regressions

### Security & Safety
- **Safe Mode by Default**: Production-safe scanning with robots.txt compliance
- **Payload Protection**: Length limits, sanitized logging, secure defaults
- **Blind XSS Control**: Disabled in safe mode for production safety
- **Pool Size Control**: Hard caps to prevent memory issues

### Developer Experience
- **Documentation**: README updated with SARIF compliance notes
- **Docker Multi-Arch**: GHCR workflow for linux/amd64 and linux/arm64
- **CI**: Multi-arch build workflow cleaned and validated
- **Test Coverage**: 70+ tests passing; coverage ≥80%

### Configuration
- **TOML Support**: User-friendly configuration in ~/.config/brs-xss/config.toml
- **Configurable Weights**: Custom effectiveness scores for payload sources
- **Performance Tuning**: 15+ parameters for optimization

## Performance Benchmarks

- **Speed**: 5000+ payloads generated per second
- **Memory**: Optimized pool management with configurable caps
- **Determinism**: 100% reproducible results with seed-based generation
- **Filtering**: Smart deduplication with LRU cache normalization

## GitHub Security Integration

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

## Configuration Reference

See [Configuration Guide](docs/configuration.md) for complete parameter reference.

### Production Defaults
```toml
[generator]
max_payloads = 500
effectiveness_threshold = 0.65
safe_mode = true
pool_cap = 10000
payload_max_len = 4096

[generator.weights]
context_specific = 0.92
context_matrix = 0.90
comprehensive = 0.70
evasion = 0.75
```

## Breaking Changes

None - this is a backward-compatible release.

## Migration Guide

No migration required from v1.0.3. All existing configurations remain valid.

## Known Issues

- DOM XSS analysis requires `playwright install` for browser provisioning
- WAF bypass techniques need validation on production configurations

## Next Steps

- Context Matrix integration into core scanning engine
- WAF bypass test-suite with real-world validation
- ML-scoring pipeline for enhanced accuracy

## Support

**NO SUPPORT PROVIDED**: Released as-is under dual GPLv3/Commercial license.

**Community**: Contributions welcome via GitHub issues and pull requests.

**Commercial**: Enterprise licensing available at https://t.me/EasyProTech

---

**BRS-XSS v1.0.4** | **EasyProTech LLC** | **https://t.me/EasyProTech**

*Production-ready XSS scanner for authorized security testing*
