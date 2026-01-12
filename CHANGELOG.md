# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0-beta.2] - 2026-01-12

### Major Release - Architecture Refactoring, Strategy Management, A/B Testing

**BRS-XSS v4.0.0-beta.2** — Complete codebase restructuring, PTT strategy management, A/B testing, modular storage.

#### Added - Architecture Refactoring

- **detect/ Module**: All detection logic in one place
  - `detect/xss/reflected/` - 66 files for HTTP-based XSS detection
  - `detect/xss/dom/` - 18 files for browser-based DOM XSS
  - `detect/waf/` - 21 files for WAF detection and bypass
  - `detect/crawler/` - 9 files for URL/form discovery
  - `detect/recon/` - 9 files for target reconnaissance
  - `detect/payloads/` - 4 files for payload management

- **count/ Module**: Single source of truth for vulnerability counting
  - `count_findings()` - THE function for counting vulnerabilities
  - `SeverityCounts` - standardized counts structure
  - `prepare_report_data()` - unified report data preparation
  - Ensures UI, Telegram, PDF, API all show IDENTICAL numbers

- **report/ Module**: All report generation
  - Moved `pdf_report.py` from `integrations/` to `report/`
  - HTML, JSON, SARIF, JUnit, PDF all in one place

- **storage/ Module**: Modular database layer
  - `storage/base.py` - Base class and DB initialization
  - `storage/scans.py` - Scan CRUD operations
  - `storage/vulnerabilities.py` - Vulnerability management
  - `storage/users.py` - User and auth management
  - `storage/strategies.py` - Strategy trees and A/B tests
  - `storage/domains.py` - Domain profiles

#### Added - PTT Strategy Management (Web UI)

- **Strategy Tree Visualization**: Interactive tree view of PTT (Pentesting Task Tree)
- **Strategy Editor**: Full CRUD for custom strategy trees
- **Strategy Simulation**: Test strategy execution without running scans
- **Strategy Path Recording**: Track actual execution path during scans
- **Export/Import**: JSON format for strategy sharing
- **Strategy Cloning**: Clone and modify existing strategies

#### Added - A/B Testing

- **A/B Test Management**: Compare effectiveness of different strategies
- **Test Configuration**: Select two strategies, set target scan count
- **Results Comparison**: Vulnerabilities found, success rate, duration
- **Winner Detection**: Automatic winner determination based on results

#### Added - Custom Payloads Support

- CLI: `--custom-payloads /path/to/file.txt` option
- Web UI: Custom payloads textarea in Advanced Options
- Auto-load from `~/.config/brs-xss/custom_payloads.txt`
- `brsxss/detect/xss/reflected/custom_payloads.py` module

#### Added - Other

- **Version Bump Script**: `scripts/bump_version.py` for automated version updates
- **WAF Evasion Enhancements**: Akamai bypass, Sucuri bypass techniques

#### Changed - Codebase Restructure

- `brsxss/core/` -> `brsxss/detect/xss/reflected/`
- `brsxss/dom/` -> `brsxss/detect/xss/dom/`
- `brsxss/waf/` -> `brsxss/detect/waf/`
- `brsxss/crawler/` -> `brsxss/detect/crawler/`
- `brsxss/reconnaissance/` -> `brsxss/detect/recon/`
- `brsxss/payloads/` -> `brsxss/detect/payloads/`
- `brsxss/integrations/pdf_report.py` -> `brsxss/report/pdf_report.py`
- `web_ui/backend/storage.py` -> `web_ui/backend/storage/` (modular)
- Updated all imports across entire codebase (127+ files)

#### Changed - Python & Dependencies

- **Python Version**: Minimum Python 3.10 (dropped 3.8, 3.9 support)
- Modern type hints (`list[str]` instead of `List[str]`)
- CI tests on Python 3.10, 3.11, 3.12 only
- Added `aiohttp-socks` for proxy support
- Added `python-multipart` for file uploads
- FastAPI lifespan handlers (removed deprecated `on_event`)
- Pydantic v2 `model_config` (removed deprecated `class Config`)

#### Changed - Scanning

- **Parallel Scanning**: Full parallelization at all levels
  - Target-level: Multiple URLs scanned in parallel
  - Payload-level: Payloads tested in parallel within each parameter
  - DOM-level: Browser-based tests run in parallel
- **Rate Limiting**: HTTPClient respects `request_delay_ms` from performance modes
- **Type System**: Full mypy compliance (0 errors in 171 files)

#### Fixed

- All mypy type errors (33 errors fixed)
- All ruff linting errors
- WAF bypass test assertions
- Scanner progress not updating in UI
- "Zombie" active scans after backend restart
- Dependencies not installed with `pip install -e .`
- Missing `weasyprint` in `pyproject.toml`
- `run_web_ui.py` backend not starting (working directory fix)
- Orphaned vulnerabilities after scan deletion
- Telegram settings not loading
- CRITICAL: `_new_page` recursion bug in HeadlessDOMDetector
- Performance Modes not affecting scan speed
- PDF Report Generation Error (weasyprint/pydyf version)
- Fragment XSS Detection URL encoding issue
- DOM Worker Overload (semaphore fix)
- Choppy Progress Bar
- JS String Breakout Payloads (tail neutralization)
- Event Handler Context Detection
- CRITICAL: Report Counts Mismatch (UI vs Telegram/PDF)
- DOM XSS Payloads tail neutralization
- Fragment External Script Detection

#### Removed

- Old directories: `core/`, `dom/`, `waf/`, `crawler/`, `reconnaissance/`, `payloads/`
- Old `reporting/` module (replaced by `count/`)
- Monolithic `storage.py` (replaced by `storage/` package)

#### UI/UX Improvements

- **Live Duration**: Scan duration updates in real-time
- **Rescan Modal**: Performance Mode selection
- **Strategy Page**: New page for PTT visualization and management
- **Action Icons Hover Effect**: Icons appear on row hover
- **Telegram Button**: Always visible for completed scans

#### Report Engine Improvements

- **Finding Deduplication**: Group identical findings by pattern
- **Heuristic Finding Classification**: Separate severity for potential findings
- **Injection Type Classification**: TAG, ATTRIBUTE, CONTENT, JAVASCRIPT, CSS, URL

#### Benchmark Results

- **Google XSS Game: 6/6 levels passed (100%)**
- **IBM Altoro Mutual: 1/1 PASS**
- **alf.nu/alert1: 1/1 PASS**
- **Google Firing Range: 7/7 PASS**
- **Total: 15/15 completed targets (100% detection rate)**

---

## [4.0.0-beta.1] - 2026-01-08

### Beta Release - Full Web UI, Parallel Architecture

**BRS-XSS v4.0.0-beta.1** — Complete rewrite with Web UI, parallel scanning, and enterprise features.

#### Added - Web UI (NEW)
- **Full React Frontend** (`web_ui/frontend/`):
  - Dashboard with real-time scan monitoring
  - New Scan page with performance mode selection
  - Scan History with filtering and search
  - Scan Details with vulnerability breakdown
  - Settings page (Proxy, Telegram, Performance)
  - Target Intelligence panel (WAF, technologies, headers)
  - WebSocket real-time updates

- **FastAPI Backend** (`web_ui/backend/`):
  - RESTful API for all scanner operations
  - SQLite storage for scan history
  - WebSocket manager for live updates
  - System info detection (CPU, RAM, network)
  - Performance mode auto-detection

- **Performance Modes**:
  - Light: 4 threads, 100 RPS (weak hardware)
  - Standard: 16 threads, 400 RPS (recommended)
  - Turbo: 28 threads, 700 RPS (powerful hardware)
  - Maximum: 45 threads, 1140 RPS (server-grade)

#### Added - Integrations
- **Telegram Notifications**:
  - Scan start/complete notifications
  - PDF report auto-generation and sending
  - Channel and discussion group support
  - Configurable notification levels

- **PDF Reports** (`brsxss/report/pdf_report.py`):
  - Professional vulnerability reports
  - Executive summary with statistics
  - Detailed findings with evidence
  - Remediation recommendations

#### Added - Reconnaissance
- **Target Profiler** (`brsxss/detect/recon/`):
  - Technology detection (frameworks, CMS, libraries)
  - WAF fingerprinting with bypass recommendations
  - Security headers analysis
  - DNS and SSL information

#### Changed
- **Scanner Architecture**: Async-first design with aiohttp
- **Crawler Integration**: Full site crawling with form discovery
- **Documentation**: Updated for Web UI and new features

---

## [4.0.0] - 2025-12-28

### Major Release - Remote API Architecture + Classification Engine

**BRS-XSS v4.0.0** — Complete re-architecture with BRS-KB remote API and intelligent classification engine.

#### Added - Remote API Integration
- **BRS-KB API**: Primary payload source (`https://brs-kb.easypro.tech/api/v1`)
- **KBAdapter**: Unified adapter supporting remote API, local library, and auto modes
- **ETag Caching**: HTTP caching for optimized API performance
- **Dynamic Statistics**: Real-time payload/context/WAF bypass counts from API
- **Environment Variables**: Enterprise-grade configuration via env vars
- **Fallback Mode**: Automatic fallback to local library if API unavailable

#### Added - Classification Engine (NEW)
- **XSS Type Classifier**: Dynamic XSS type detection (Reflected, DOM-based, Stored, Mutation, Blind)
- **Context Parser**: Hierarchical context detection (`html > img > onerror`)
- **Payload Classifier**: Consistent PAYLOAD CLASS generation for all findings
- **Payload Analyzer**: Runtime metadata computation
- **Confidence Calculator**: Factor-based calculation with DOM/trigger boosts

#### Changed - Scoring System
- Confidence levels: DEFINITE (95%+), VERY_HIGH (85%+), HIGH (70%+), MEDIUM, LOW
- Severity synchronized with confidence
- Auto-execute handlers = 90%+ confidence

#### Changed - Configuration
- Default Mode: Remote API (previously local library)
- Configuration: New `kb:` section in `config/default.yaml`
- Version Management: Single source of truth in `brsxss/version.py`

---

## [2.1.1] - 2025-11-14

### Code Quality & Performance

- **Knowledge Base Refactoring**: Modular structure for KB modules
- **HTML Report Optimization**: 75% reduction in report file sizes
- All tests passing, backward compatible

---

## [2.1.0] - 2025-10-26

### MIT License Migration

- **License Change**: GPL/Commercial → MIT License
- **Full Open Source**: No restrictions on usage
- **Contact**: Telegram only (https://t.me/EasyProTech)

---

## [1.0.0] - 2025-12-27

### Initial Release

- Context-Aware Payloads (HTML, JavaScript, CSS, URI, SVG, XML)
- WAF Evasion (Cloudflare, Akamai, AWS WAF, Imperva, ModSecurity)
- DOM Analysis via Playwright
- Multi-Format Reports (SARIF, JSON, HTML)

---

**License**: MIT  
**Author**: EasyProTech LLC (https://www.easypro.tech)

[4.0.0-beta.2]: https://github.com/EPTLLC/brs-xss/releases/tag/v4.0.0-beta.2
[4.0.0-beta.1]: https://github.com/EPTLLC/brs-xss/releases/tag/v4.0.0-beta.1
[4.0.0]: https://github.com/EPTLLC/brs-xss/releases/tag/v4.0.0
[2.1.1]: https://github.com/EPTLLC/brs-xss/releases/tag/v2.1.1
[2.1.0]: https://github.com/EPTLLC/brs-xss/releases/tag/v2.1.0
[1.0.0]: https://github.com/EPTLLC/brs-xss/releases/tag/v1.0.0
