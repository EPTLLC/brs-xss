# Web UI Guide

**Complete guide to BRS-XSS Web Interface**

**Version**: 4.0.0-beta.2

## Overview

BRS-XSS includes a modern web interface built with:
- **Backend**: FastAPI (Python)
- **Frontend**: React 18 + TypeScript + Tailwind CSS (Vite via Bun)
- **Real-time**: WebSocket for live progress
- **Storage**: SQLite for scan persistence

The Web UI is an operational control plane over the BRS-XSS engine, not a separate scanner.

## Installation

### Requirements

- Python 3.10+
- Bun >= 1.3
- Playwright browsers (`playwright install chromium`)
- Optional: local BRS-KB package for offline payloads

### Launch

```bash
git clone https://github.com/EPTLLC/brs-xss.git
cd brs-xss
pip install -e .
python3 scripts/run_web_ui.py
```

The launcher auto-installs frontend dependencies via Bun, frees backend/frontend ports, and runs uvicorn + vite together.

### Advanced operation

- **Custom ports**: `python3 scripts/run_web_ui.py --backend-port 8200 --frontend-port 5180`
- **Skip install**: `python3 scripts/run_web_ui.py --skip-install`
- **Production-style**: `python3 scripts/run_web_ui.py --no-backend-reload`

## Pages

### Dashboard

Main overview page showing:
- System Profile Card (CPU, RAM, performance mode)
- Knowledge Base Card (BRS-KB stats)
- Statistics Grid (scans, vulnerabilities, duration)
- Recent Scans Table

### New Scan

Start a new scan with options:
- Target URL with parameters
- Performance profile (Light/Standard/Turbo/Maximum)
- Custom headers, crawl depth, safe mode
- Custom payloads (one per line)

### Scan Details

Real-time scan monitoring:
- Progress Terminal with live logs
- Status Cards (progress, URLs, payloads, time)
- WAF Detection info
- Vulnerabilities Table with severity badges

### Scan History

List all scans with filtering by status, mode, and URL search.

### Strategy (NEW in v4.0.0-beta.2)

PTT (Pentesting Task Tree) management page:

#### Default Tree Tab
- Interactive tree visualization
- Node types: Root, Context, Payload, Encoding, WAF Bypass, Mutation, Condition
- Click nodes to see details

#### Simulation Tab
- Test strategy without running scans
- Select context (HTML, JS, Attribute, URL, CSS)
- Toggle WAF simulation
- View planned actions

#### My Strategies Tab
- Create, edit, clone, delete custom strategies
- Activate strategy for new scans
- Export/import strategies as JSON

#### A/B Tests Tab
- Create tests comparing two strategies
- Set target scan count
- View results: vulnerabilities, success rate, duration
- Automatic winner detection

#### Scan Path Viewer
- Search by scan ID
- View execution timeline
- See pivot points and statistics

### Settings

Configure scanner behavior:
- Performance Mode selection
- Scanner defaults (mode, depth, timeout)
- Blind XSS callback URL
- Telegram notifications
- Proxy management (HTTP/HTTPS/SOCKS)

## Storage Architecture (v4.0.0-beta.2)

The storage layer is now modular:

```
web_ui/backend/storage/
├── __init__.py      # ScanStorage class composition
├── base.py          # Base class, DB initialization
├── scans.py         # Scan CRUD operations
├── vulnerabilities.py # Vulnerability management
├── users.py         # User, auth, settings
├── strategies.py    # Strategy trees, A/B tests
└── domains.py       # Domain profiles
```

Database: `brsxss_ui.db` (SQLite)

## Performance Modes

- **Light**: minimal load, threads = CPU/6
- **Standard**: balanced, recommended for <=16 threads
- **Turbo**: high-performance, for 16-32 threads
- **Maximum**: ~90% capacity, for >32 threads

## Troubleshooting

**Frontend cannot reach backend**: Check if launcher is running, verify ports.

**WebSocket disconnected**: Check backend logs, verify no proxy stripping Upgrade header.

**Scan stuck at 0%**: Verify target reachable, check for Playwright errors.

**Strategy page not loading**: Verify brsxss.strategy module installed, check /api/strategy/tree.
