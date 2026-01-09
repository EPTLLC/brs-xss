# Web UI Guide

**Complete guide to BRS-XSS Web Interface**

## Overview

BRS-XSS includes a modern web interface built with:
- **Backend**: FastAPI (Python)
- **Frontend**: React 18 + TypeScript + Tailwind CSS (Vite via Bun)
- **Real-time**: WebSocket for live progress
- **Storage**: SQLite for scan persistence

The Web UI is an operational control plane over the BRS-XSS engine, not a separate scanner.

## Installation

### Requirements

- Python 3.8+
- Bun ≥ 1.3 (`bun install`, `bunx --bun vite`)
- Playwright browsers (`playwright install chromium`)
- Optional: local BRS-KB package for offline payloads

### Launch

```bash
git clone https://github.com/EPTLLC/brs-xss.git
cd brs-xss
pip install -e .
python3 scripts/run_web_ui.py
```

The launcher auto-installs frontend dependencies via Bun, frees backend/frontend ports, and runs uvicorn + `bunx --bun vite` together. Logs are prefixed with `[backend]` / `[frontend]`. Stop with Ctrl+C.

### Advanced operation

- **Custom ports**: `python3 scripts/run_web_ui.py --backend-port 8200 --frontend-port 5180`
- **Skip install**: `python3 scripts/run_web_ui.py --skip-install` (when `node_modules/` is already provisioned)
- **Production-style**: `python3 scripts/run_web_ui.py --no-backend-reload` behind a supervisor/reverse proxy
- **TLS / auth**: terminate TLS and enforce auth in the reverse proxy; backend serves APIs only on HTTP.
- **Security**: the backend exposes unauthenticated APIs by default—never publish it directly on the internet without an authentication layer.

## Pages

### Dashboard

Main overview page showing:

**System Profile Card**
- CPU model and thread count
- Available/total RAM
- Current performance mode
- "Detect System" button

**Knowledge Base Card**
- BRS-KB version
- Total payloads count
- Available contexts

**Statistics Grid**
- Total scans
- Vulnerabilities found
- Average scan duration
- Most common context

**Recent Scans Table**
- Last 5 scans with status
- Click to view details
- Quick delete option

### New Scan

Start a new scan with options:

**Target URL**
- Full URL, including query/body parameters (e.g., `https://example.com/search?q=test`)

**Performance profile**
- Select **Light / Standard / Turbo / Maximum** (mirrors Settings → Performance Mode).  
- Each profile pre-populates threads, concurrency, DOM workers, Playwright instances, HTTP pool size based on detected hardware.

**Options**
- Follow redirects
- Custom HTTP headers
- Override crawl depth / max URLs
- Toggle safe mode, rate limiting, proxy usage

### Scan Details

Real-time scan monitoring:

**Progress Terminal**
- Live log output (terminal style)
- Phase indicators (init, crawl, scan, complete)
- Vulnerability notifications

**Status Cards**
- Progress percentage
- URLs scanned
- Payloads sent
- Elapsed time

**WAF Detection**
- Detected WAF name
- Confidence level
- Bypass availability

**Vulnerabilities Table**
- Severity badge (Critical, High, Medium, Low)
- Context type
- Parameter name
- Payload (copyable)
- Proof URL

### Scan History

List all scans with filtering:

**Filters**
- Status (all, running, completed, failed)
- Mode (all modes)
- Search by URL

**Features**
- Multi-select for bulk delete
- Copy domain button
- Rescan button with mode selection
- Sort by date, status, vulnerabilities

### Settings

Configure scanner behavior:

**Performance Mode** (Priority)
- Hardware detection display
- Mode selector (Light, Standard, Turbo, Maximum)
- Threads and RPS shown per mode
- Recommended mode indicator

**Scanner Defaults**
- Default scan mode
- Max crawl depth
- Request timeout
- Max concurrent scans

**Blind XSS**
- Callback server URL
- Enable/disable toggle

**Telegram Notifications**
- Enable/disable toggle
- Bot token
- Chat ID

**UI Preferences**
- Theme (Dark Cyber / Light)
- Results per page

#### Proxy Management

- Configure outbound proxy (HTTP/HTTPS/SOCKS4/SOCKS5) directly from the Settings page.
- Saved proxies (up to 10) can be selected, renamed, or deleted without retyping credentials.
- The **Test Proxy** button calls `/api/proxy/test`, returning IP, country, and latency to verify the route before scanning.
- When a proxy is enabled, the backend applies it to crawler, scanner, reconnaissance, and all HTTP clients automatically.

API example:
```bash
# Apply proxy
curl -X POST "http://localhost:8000/api/proxy" \
  -d "proxy_string=127.0.0.1:8899" \
  -d "protocol=http" \
  -d "enabled=true"

# Verify via backend test harness
curl -X POST "http://localhost:8000/api/proxy/test"
```

Logs in `scripts/run_web_ui.py` are prefixed with `[backend]` and will emit `Proxy applied: protocol://host:port` when settings take effect.

## API Reference

All endpoints are served on the local backend (`localhost:8000`) by default. Expose them outside the host only through an authenticated proxy.

### System Endpoints

**GET /api/system/info**
```json
{
  "system": {
    "cpu_model": "AMD EPYC 9274F",
    "cpu_cores": 48,
    "cpu_threads": 48,
    "ram_total_gb": 251.4,
    "ram_available_gb": 244.1,
    "os_name": "Linux",
    "os_version": "6.8.0-87-generic"
  },
  "modes": {
    "light": {"threads": 4, "requests_per_second": 72, ...},
    "standard": {"threads": 12, ...},
    "turbo": {"threads": 24, ...},
    "maximum": {"threads": 43, ..., "recommended": true}
  },
  "recommended": "maximum",
  "saved_mode": "maximum"
}
```

**POST /api/system/detect**
Force re-detection of hardware.

**POST /api/system/mode?mode=turbo**
Set preferred performance mode.

### Scan Endpoints

**POST /api/scans**
```json
{
  "target_url": "https://example.com/search?q=test",
  "mode": "standard",
  "follow_redirects": true,
  "custom_headers": {}
}
```

**GET /api/scans**
List scans with optional `limit` and `status` filters.

**GET /api/scans/{scan_id}**
Full scan details with vulnerabilities.

**DELETE /api/scans/{scan_id}**
Delete scan and results.

**POST /api/scans/{scan_id}/cancel**
Cancel running scan.

### WebSocket

**Connect**: `ws://host:port/ws`

**Messages Received**:
```json
{"type": "progress", "data": {
  "scan_id": "abc123",
  "status": "running",
  "progress_percent": 45,
  "current_phase": "scanning",
  "current_url": "https://..."
}}

{"type": "vulnerability", "scan_id": "abc123", "data": {
  "severity": "high",
  "context": "html_attribute",
  "parameter": "q",
  "payload": "...",
  "proof_url": "..."
}}
```

## Performance Modes

The backend computes mode profiles dynamically using `web_ui.backend.system_info`:

```
Light     → minimal background load (threads ≈ CPU_threads / 6)
Standard  → balanced profile (auto-recommended for ≤16 threads)
Turbo     → high-performance profile (auto-recommended for 16–32 threads)
Maximum   → ~90% of available capacity (auto-recommended for >32 threads)
```

Each profile defines:
- worker `threads` and HTTP concurrency
- `requests_per_second` / `request_delay_ms`
- DOM detector workers and number of Playwright browser instances
- HTTP connection pool (`http_pool_size`)

The detector also accounts for:
- CPU frequency (boosts concurrency on faster CPUs)
- GPU availability (enables multi-browser DOM scanning with hardware acceleration)
- RAM headroom
- NIC speed (caps RPS on slow links)

Use **Settings → Performance Mode → Detect System** to refresh hardware data after VM migrations or scaling events. Cached profile lives in `~/.brs-xss/system_profile.json`; selected mode persists in `~/.brs-xss/preferences.json`.

## Storage

Scans stored in SQLite database:
- Location: `brsxss_ui.db`
- Includes: scan metadata, vulnerabilities, progress

System profile cached:
- Location: `~/.brs-xss/system_profile.json`
- Re-detect with "Detect System" button

Mode preference saved:
- Location: `~/.brs-xss/preferences.json`
- Persists across restarts

## Troubleshooting

**“Frontend cannot reach backend”**
- Confirm `python3 scripts/run_web_ui.py` is still running (two prefixes in logs).
- If you changed ports, ensure the frontend `vite.config.ts` proxy points to the same backend host/port.
- Re-run the launcher with `--backend-port` / `--frontend-port` if another process grabbed the default ports.

**“WebSocket disconnected”**
- The frontend reconnects automatically; check terminal output for `[backend]` errors.
- Verify no reverse proxy is stripping `Upgrade: websocket`.

**“No system info displayed”**
- Press **Detect System** — the call hits `/api/system/detect`.
- Inspect `[backend]` logs for `Could not get performance settings`.
- Ensure `psutil` is installed; hardware detection relies on it.

**“Scan stuck at 0%”**
- Confirm the target is reachable from the backend host (`curl` using the same proxy if configured).
- Review `[backend]` log for crawler errors, proxy failures, or Playwright exceptions (`playwright install chromium` might be missing).

