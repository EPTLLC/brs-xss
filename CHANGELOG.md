#!/usr/bin/env python3

Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 22:26:02 MSK
Status: Created
Telegram: https://t.me/EasyProTech

# Changelog

All notable changes to this project will be documented in this file.

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


