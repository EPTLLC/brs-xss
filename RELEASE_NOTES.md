# BRS-XSS v4.0.0 Release Notes

- **Date**: 2025-12-28
- **Tag**: `v4.0.0`
- **Build**: 2025.12.28

## Major Release - Remote API Architecture + Classification Engine

**Complete re-architecture with BRS-KB remote API and intelligent classification engine.**

This is a MAJOR release with significant architectural changes:
- BRS-XSS now connects to the centralized BRS-KB API for payloads, contexts, and WAF bypasses
- New Classification Engine for accurate vulnerability typing, confidence scoring, and context detection

### What's New

#### Classification Engine (NEW)

Intelligent XSS classification system that replaces hardcoded labels with dynamic analysis:

| Component | Purpose |
|-----------|---------|
| **XSS Type Classifier** | Determines Reflected/DOM/Stored/Mutation based on payload and context |
| **Context Parser** | Hierarchical context: `html > img > onerror` instead of just `html` |
| **Payload Classifier** | Consistent PAYLOAD CLASS for every finding |
| **Confidence Calculator** | Factor-based scoring with DOM/trigger boosts |

**Key Improvements:**
- `<img src=x onerror=alert(1)>` now correctly classified as "DOM XSS (Event Handler)"
- Auto-execute handlers (onerror, onload) get 90%+ confidence
- External script loads get 95%+ confidence
- Severity synchronized with confidence (no more MEDIUM with 99% confidence)
- Every finding includes `payload_class`, `trigger`, and `is_deterministic` fields

See [Classification Engine Documentation](docs/classification-engine.md) for details.

#### Remote API as Primary Source
- BRS-KB API (`https://brs-kb.easypro.tech/api/v1`) is now the default payload source
- No local installation required - works out of the box
- Real-time access to latest payloads and bypass techniques
- Free tier with no rate limits

#### Dynamic Statistics
All statistics fetched in real-time from API:
- Total payloads count
- Available injection contexts
- WAF bypass techniques

Check live stats: [brs-kb.easypro.tech/api/v1/stats](https://brs-kb.easypro.tech/api/v1/stats)

#### New KBAdapter Architecture
- `RemoteKBClient`: HTTP client for API communication
- `LocalKBClient`: Fallback for offline/airgapped environments  
- `auto` mode: Try remote first, fallback to local if unavailable
- ETag caching for optimized performance

#### Enterprise Configuration
```bash
# Set API key for production
export BRSXSS_KB_API_KEY="your-api-key"

# Override mode
export BRSXSS_KB_MODE="remote"  # or "local" or "auto"
```

### Breaking Changes

- **Default mode changed**: Now `remote` instead of `local`
- **brs_kb library**: No longer required by default (optional for offline mode)
- **Config structure**: New `kb:` section in config files
- **Vulnerability output**: New fields added (`vulnerability_type`, `payload_class`, `classification`)

### New Files

| File | Purpose |
|------|---------|
| `brsxss/core/xss_type_classifier.py` | XSS type classification |
| `brsxss/core/context_parser.py` | Hierarchical context detection |
| `brsxss/core/payload_classifier.py` | PAYLOAD CLASS generation |
| `docs/classification-engine.md` | Classification engine documentation |

### Migration Guide

#### From v2.x to v4.0.0

1. **Update the package**:
   ```bash
   pip install -U brs-xss
   ```

2. **No configuration needed** for basic usage - remote API works automatically

3. **For offline environments**, set mode to local:
   ```bash
   pip install git+https://github.com/EPTLLC/BRS-KB.git
   export BRSXSS_KB_MODE="local"
   ```

4. **For enterprise/production**, set your API key:
   ```bash
   export BRSXSS_KB_API_KEY="your-production-key"
   ```

### Configuration

New `kb:` section in `config/default.yaml`:

```yaml
kb:
  mode: "remote"  # remote | local | auto
  api:
    url: "https://brs-kb.easypro.tech/api/v1"
    timeout: 30
    max_retries: 3
  local:
    path: "/var/BRS/BRS-KB"
    fallback_enabled: true
  cache:
    enabled: true
    ttl: 3600
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BRSXSS_KB_API_KEY` | API key for production | Free tier key |
| `BRSXSS_KB_API_URL` | Custom API URL | https://brs-kb.easypro.tech/api/v1 |
| `BRSXSS_KB_MODE` | KB mode | remote |
| `BRSXSS_KB_LOCAL_PATH` | Local BRS-KB path | /var/BRS/BRS-KB |

### Installation

```bash
# PyPI (recommended)
pip install brs-xss

# Install Playwright for DOM analysis
playwright install chromium

# Docker
docker pull ghcr.io/eptllc/brs-xss:4.0.0
docker pull ghcr.io/eptllc/brs-xss:latest

# From source
git clone https://github.com/EPTLLC/BRS-XSS.git
cd BRS-XSS
pip install -e .
```

### Quick Start

```bash
# Basic scan (uses remote API automatically)
brs-xss scan https://target.com

# Deep scan with HTML report
brs-xss scan https://target.com --deep --output report.json

# Check KB connection
brs-xss kb info
```

### Links

- **Website**: https://brs-xss.easypro.tech
- **GitHub**: https://github.com/EPTLLC/BRS-XSS
- **BRS-KB API**: https://brs-kb.easypro.tech
- **API Docs**: https://brs-kb.easypro.tech/docs.html
- **Telegram**: https://t.me/EasyProTech

---

**BRS-XSS v4.0.0** | **EasyProTech LLC** | **https://www.easypro.tech**

*Powered by BRS-KB - XSS Knowledge Base API*
