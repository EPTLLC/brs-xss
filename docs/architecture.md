# BRS-XSS Architecture

**Version**: 4.0.0-beta.2

## Module Structure

```
brsxss/
├── detect/             # ALL detection logic
│   ├── xss/
│   │   ├── reflected/  # HTTP-based reflected XSS (66 files)
│   │   │   ├── scanner.py           # Main XSSScanner
│   │   │   ├── http_client.py       # HTTP requests
│   │   │   ├── context_analyzer.py  # Context detection
│   │   │   ├── payload_generator.py # Payload generation
│   │   │   ├── custom_payloads.py   # Custom payload loading
│   │   │   └── ...
│   │   ├── dom/        # Browser-based DOM XSS (18 files)
│   │   │   ├── headless_detector.py # Playwright-based detection
│   │   │   ├── dom_analyzer.py      # DOM analysis
│   │   │   └── ...
│   │   └── stored/     # Stored XSS (future)
│   ├── waf/            # WAF detection (21 files)
│   │   ├── detector.py
│   │   ├── evasion_engine.py
│   │   └── ...
│   ├── crawler/        # URL/form discovery (9 files)
│   │   ├── engine.py
│   │   ├── form_extractor.py
│   │   └── ...
│   ├── recon/          # Target reconnaissance (9 files)
│   │   ├── target_profiler.py
│   │   ├── technology_detector.py
│   │   └── ...
│   └── payloads/       # Payload management (4 files)
│       ├── kb_adapter.py
│       ├── payload_manager.py
│       └── ...
│
├── count/              # SINGLE SOURCE OF TRUTH for counting
│   ├── __init__.py     # Main exports: count_findings, SeverityCounts
│   ├── types.py        # Data types: SeverityCounts, ReportData
│   ├── counter.py      # THE counting function
│   └── processor.py    # Report data preparation
│
├── report/             # Report generation
│   ├── report_generator.py  # Main generator (HTML, JSON, SARIF, JUnit)
│   ├── pdf_report.py        # PDF reports
│   ├── templates.py
│   └── ...
│
├── strategy/           # PTT Strategy Engine
│   ├── __init__.py     # Main exports
│   ├── tree.py         # StrategyTree, StrategyNode
│   ├── engine.py       # StrategyEngine
│   ├── rules.py        # Switching rules
│   └── tracker.py      # ScanStrategyTracker
│
├── integrations/       # External integrations
│   ├── telegram_bot.py
│   └── telegram_service.py
│
├── i18n/               # Localization
├── utils/              # Utilities (logger, validators)
└── version.py          # Version info
```

## Web UI Backend Structure

```
web_ui/backend/
├── main.py             # FastAPI application entry point
├── scanner_service.py  # Scanner orchestration
├── system_info.py      # Hardware detection
├── websocket_manager.py # WebSocket handling
│
├── storage/            # MODULAR DATABASE LAYER (v4.0.0-beta.2)
│   ├── __init__.py     # ScanStorage class composition
│   ├── base.py         # Base class, DB init, migrations
│   ├── scans.py        # Scan CRUD operations
│   ├── vulnerabilities.py # Vulnerability management
│   ├── users.py        # User, auth, settings
│   ├── strategies.py   # Strategy trees, A/B tests, scan paths
│   └── domains.py      # Domain profiles
│
└── routes/             # API routes
    ├── scans.py        # /api/scans
    ├── strategy.py     # /api/strategy (NEW)
    ├── settings.py     # /api/settings
    ├── system.py       # /api/system
    ├── kb.py           # /api/kb
    ├── dashboard.py    # /api/dashboard
    ├── proxy.py        # /api/proxy
    ├── telegram.py     # /api/telegram
    └── ...
```

## Import Paths

```python
# Detection
from brsxss.detect import XSSScanner, HeadlessDOMDetector, WAFDetector
from brsxss.detect.xss.reflected.scanner import XSSScanner
from brsxss.detect.xss.dom.headless_detector import HeadlessDOMDetector
from brsxss.detect.waf.detector import WAFDetector
from brsxss.detect.crawler.engine import CrawlerEngine
from brsxss.detect.recon.target_profiler import TargetProfiler
from brsxss.detect.payloads.kb_adapter import KBAdapter

# Counting
from brsxss.count import count_findings, prepare_report_data

# Reports
from brsxss.report import ReportGenerator, PDFReportGenerator

# Strategy
from brsxss.strategy import StrategyEngine, StrategyTree, create_default_strategy

# Integrations
from brsxss.integrations import TelegramBot

# Web UI Storage
from backend.storage import ScanStorage, get_storage
```

## Critical Architecture Rules

### 1. Counting - Single Source of Truth

**ALL vulnerability counting MUST go through `brsxss/count/`**

```python
from brsxss.count import count_findings

counts = count_findings(vulnerabilities)
print(counts.critical)  # Number of critical
print(counts.high)      # Number of high
print(counts.total)     # Total (critical+high+medium+low)
```

This ensures:
- UI shows same numbers as Telegram
- Telegram shows same numbers as PDF
- PDF shows same numbers as API
- **NO EXCEPTIONS**

### 2. Detection - Modular Structure

All detection code lives in `detect/`:
- `detect/xss/reflected/` - HTTP-based reflected XSS
- `detect/xss/dom/` - Browser-based DOM XSS
- `detect/waf/` - WAF detection and bypass
- `detect/crawler/` - URL and form discovery
- `detect/recon/` - Target profiling
- `detect/payloads/` - Payload management

### 3. Reports - Consistent Output

All report generators receive data from `count/`:

```python
from brsxss.count import prepare_report_data

report_data = prepare_report_data(vulnerabilities)
# report_data.counts - SeverityCounts
# report_data.findings - Normalized findings
```

### 4. Storage - Modular Design (v4.0.0-beta.2)

Database operations are split by domain:

```python
from backend.storage import get_storage

storage = get_storage()

# Scans
storage.create_scan(...)
storage.get_scan(scan_id)
storage.update_scan_status(...)

# Strategies
storage.create_strategy_tree(...)
storage.get_strategy_trees()
storage.create_ab_test(...)

# Users
storage.get_user(user_id)
storage.update_user_settings(...)
```

Each mixin handles its own domain:
- `ScanStorageMixin` - scan lifecycle
- `VulnerabilityStorageMixin` - vulnerability CRUD
- `UserStorageMixin` - users, auth, settings
- `StrategyStorageMixin` - PTT trees, A/B tests
- `DomainStorageMixin` - domain profiles

### 5. Strategy Engine

PTT (Pentesting Task Tree) management:

```python
from brsxss.strategy import StrategyEngine, ScanStrategyTracker

# Initialize engine
engine = StrategyEngine()
engine.initialize(url, parameter, context_type, waf_detected)

# Generate actions
for action in engine.generate_actions():
    # Execute action
    result = await execute_payload(action.payload)
    engine.record_result(action, success=result.success)

# Track execution path
tracker = ScanStrategyTracker(scan_id, strategy_tree_id, context, waf_info)
tracker.record_action(action)
tracker.record_pivot("waf_detected", "Cloudflare")
```

## Data Flow

```
Scanner finds vulnerability
        │
        ▼
┌───────────────────┐
│   count/          │  ← SINGLE counting point
│   count_findings()│
└─────────┬─────────┘
          │
    ┌─────┴─────┬─────────┬─────────┐
    ▼           ▼         ▼         ▼
┌───────┐  ┌────────┐ ┌───────┐ ┌───────┐
│  UI   │  │Telegram│ │  PDF  │ │  API  │
└───────┘  └────────┘ └───────┘ └───────┘

ALL show IDENTICAL numbers
```

## Strategy Flow

```
Scan Start
    │
    ▼
┌───────────────────┐
│ StrategyEngine    │  ← Select strategy tree
│ initialize()      │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ generate_actions()│  ← Yield payloads based on tree
└─────────┬─────────┘
          │
    ┌─────┴─────┐
    ▼           ▼
┌───────┐  ┌───────┐
│Success│  │Failure│
└───┬───┘  └───┬───┘
    │          │
    ▼          ▼
┌───────────────────┐
│ record_result()   │  ← Update tree state
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ ScanStrategyTracker│ ← Record execution path
│ save to DB        │
└───────────────────┘
```

## Why This Matters

Before this architecture, counting happened in multiple places:
- `storage.py` counted when reading from DB
- `telegram_service.py` counted differently
- `pdf_report.py` used yet another method
- Result: UI showed 1 vuln, Telegram showed 0

Now there's ONE function that counts. Everyone uses it.
Numbers are always consistent.

## File Size Limit

Each file should be max 200-250 lines (with rare exceptions up to 450-500).
This ensures:
- Improved readability
- Maintainability
- Single Responsibility Principle
- Easy testing
- Team scalability
- Instant IDE navigation

## Database Schema (v4.0.0-beta.2)

### Core Tables
- `scans` - Scan metadata and status
- `vulnerabilities` - Found vulnerabilities
- `settings` - Application settings
- `users` - User accounts
- `user_settings` - Per-user preferences

### Strategy Tables (NEW)
- `strategy_trees` - Custom PTT trees
- `strategy_ab_tests` - A/B test configurations
- `scan_strategy_paths` - Execution path recordings

### Domain Tables
- `domain_profiles` - Per-domain intelligence
- `target_profiles` - Cached target info
