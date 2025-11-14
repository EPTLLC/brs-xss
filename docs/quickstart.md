# Quick Scan Guide

**Get started with BRS-XSS in 2 minutes**

## Installation

```bash
pip install -U brs-xss==2.1.1
```

## Basic Scan

```bash
# Scan a single URL
brs-xss scan https://example.com

# Scan with specific parameters
brs-xss scan "https://example.com/search?q=test" --fast

# Scan with custom output
brs-xss scan https://example.com -o results.sarif --format sarif
```

## Quick Options

| Flag | Description | Example |
|------|-------------|---------|
| `--fast` | Quick scan mode | `brs-xss scan url --fast` |
| `--deep` | Deep scan with DOM analysis | `brs-xss scan url --deep` |
| `--aggr` | Aggressive payload mode | `brs-xss scan url --aggr` |
| `--timeout N` | Request timeout | `brs-xss scan url --timeout 30` |
| `--threads N` | Concurrent threads | `brs-xss scan url --threads 20` |

## Output Formats

```bash
# SARIF for CI/CD
brs-xss scan url -o report.sarif --format sarif

# JSON for automation
brs-xss scan url -o report.json --format json

# HTML for manual review
brs-xss scan url -o report.html --format html
```

## Next Steps

- [CI Integration](ci-integration.md) - Automate scans in CI/CD
- [SARIF in GitHub](github-sarif.md) - Security tab integration
- [Safe Mode](safe-mode.md) - Production scanning guidelines
