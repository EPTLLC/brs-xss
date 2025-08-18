#!/usr/bin/env python3

Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 22:26:02 MSK
Status: Created
Telegram: https://t.me/EasyProTech

# Changelog

All notable changes to this project will be documented in this file.

## [1.0.3] - 2025-08-18
### Added
- **Comprehensive Payload Integration**: PayloadGenerator now uses PayloadManager to access ALL 901+ payloads from payloads folder
- **Real-time Progress Tracking**: Added progress callback system showing "Testing payload X/Y" with percentage and time estimates
- **Enhanced User Feedback**: Dual progress bars - one for URLs, one for detailed payload testing progress

### Fixed
- **Syntax Errors**: Resolved F821 undefined name errors (Dict import, MLTrainer reference, keyword scope)
- **Python 3.8 Compatibility**: Fixed playwright version requirement (>=1.40.0) and license format for older setuptools
- **GitHub Actions**: Updated workflows to use requirements/base.txt and proper package installation
- **Progress Bar**: Fixed progress display that was stuck at 0% - now shows real scanning progress

### Changed
- **Payload Limit**: Increased GenerationConfig.max_payloads from 50 to 2000 for comprehensive testing
- **Progress Display**: Enhanced CLI to show both URL scanning and payload testing progress simultaneously

### Technical
- Added progress_callback parameter to XSSScanner for real-time progress updates
- Integrated PayloadManager into PayloadGenerator for full payload coverage
- Fixed workflow files to properly install dependencies and run tests

## [1.0.2] - 2025-08-10
### Added
- Dockerfile with Playwright browsers; run scanner fully via Docker.
- Heuristic exploitation likelihood (0–1), likelihood levels (low/med/high) and reasons in results.
- Tests: paths/atomic_write/sanitize and log sanitizer.
- BeautifulSoup support for crawler (beautifulsoup4 dependency).

### Changed
- CLI help: threads → “Concurrency (parallel requests)”.
- README: Quick Start via pip entry point, Playwright install step, WAF detection marked beta, Docker usage section, removed excessive emojis.

### Fixed
- HTML report shows detection score, exploitation likelihood, confidence; policy (thresholds) appended.

## [1.0.1] - 2025-08-10
### Added
- Professional multi-format reports (HTML + JSON) via `ReportGenerator` integrated into serious scan flow.
- Headless DOM XSS detection now captures `dialog` (alert/confirm/prompt) events.

### Changed
- CLI streamlined: single serious scanning command `scan` with deep and ML enabled by default.
- Context analysis no longer requires HTTP 200; proceeds with any response containing content.
- Vulnerability threshold reads from `scanner.min_vulnerability_score` in config.
- Unified file headers and official Telegram link `https://t.me/EasyProTech` across the codebase.
- README updated to reflect serious scan usage and DOM dynamic analysis (Playwright).

### Fixed
- Duplicate `close()` implementations in `XSSScanner` removed; consolidated cleanup.
- Safe serialization for report generation when inputs are dataclasses/enums.

### Notes
- SARIF/JUnit templates available; can be enabled via formats in report config in future.

## [1.0.0] - 2025-08-06
- Initial release.


