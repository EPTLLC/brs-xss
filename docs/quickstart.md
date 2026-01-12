# Quick Start Guide

**Ship the Web UI and CLI in minutes (BRS-XSS v4.0.0-beta.2)**

## Requirements

- Python 3.10+
- Bun >= 1.3 (frontend toolchain: `bun install`, `bunx --bun vite`)
- Playwright browsers (for DOM XSS detection): `playwright install chromium`
- System libraries for PDF generation (WeasyPrint)

### System Dependencies

**macOS** (Homebrew):
```bash
brew install pango libffi
```

**Ubuntu/Debian**:
```bash
sudo apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```

## Web UI (recommended)

```bash
git clone https://github.com/EPTLLC/brs-xss.git
cd brs-xss

# Install Python dependencies (editable mode keeps CLI in sync)
pip install -e .

# Launch backend + frontend together
python3 scripts/run_web_ui.py
```

What happens:
- backend listens on `http://0.0.0.0:8000`
- frontend runs on `http://localhost:5173` (open in the browser)
- the launcher auto-installs frontend deps via Bun if needed, frees occupied ports and stops both services on Ctrl+C

Useful flags:

```bash
# Custom ports / hosts
python3 scripts/run_web_ui.py --backend-host 127.0.0.1 --backend-port 8210 --frontend-port 5190

# Skip bun install when node_modules is pre-populated
python3 scripts/run_web_ui.py --skip-install

# Disable uvicorn autoreload (production-like)
python3 scripts/run_web_ui.py --no-backend-reload
```

## Web UI tour

1. **Dashboard** – system profile, KB stats, recent scans, live metrics.  
2. **New Scan** – specify target URL, select performance mode (Light/Standard/Turbo/Maximum), configure redirects, headers, crawl depth.  
3. **Scan Details** – real-time log feed, phase counters, live WAF detection, confirmed/potential findings.  
4. **Settings → Performance Mode** – hardware auto-detection (CPU/RAM/GPU/network) with adaptive threads/RPS/DOM workers.  
5. **Settings → Proxy Management** – manage up to 10 saved proxies, run `/api/proxy/test`, apply to crawler + scanner instantly.

## CLI quick start

Install from PyPI if you only need the CLI:

```bash
pip install -U brs-xss
playwright install chromium
```

### Basic scans

```bash
# Default scan (console output)
brs-xss scan https://example.com/search?q=test

# Save JSON report
brs-xss scan https://example.com --output results.json

# Verbose output
brs-xss scan https://example.com --verbose
```

### Deep scan with crawling

```bash
# Enable deep discovery (crawl forms)
brs-xss scan https://example.com --deep

# With custom thread count
brs-xss scan https://example.com --deep --threads 20
```

### Throttling and limits

```bash
# Limit payloads per entry point
brs-xss scan https://example.com --max-payloads 200

# Custom timeout
brs-xss scan https://example.com --timeout 30

# Safe mode (default: true)
brs-xss scan https://example.com --safe-mode
```

### CLI Options Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--threads` | Max concurrent requests | 10 |
| `--timeout` | Request timeout (seconds) | 15 |
| `--output` | Path to save JSON report | - |
| `--deep` | Enable deep discovery | false |
| `--verbose` | Verbose output | false |
| `--safe-mode` | Restrict dangerous payloads | true |
| `--pool-cap` | Max payload pool size | 10000 |
| `--max-payloads` | Max payloads per entry point | 500 |

## Next steps

- [Web UI Guide](web-ui.md) – pages, API endpoints, proxy workflow  
- [Configuration](configuration.md) – YAML/TOML layers, environment overrides  
- [CI Integration](ci-integration.md) – GitHub Actions / GitLab examples  
- [Safe Mode](safe-mode.md) – production throttling checklist
