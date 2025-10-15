# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2025-10-15

### Fixed
- Critical scanner bug: parameter extraction in simple_scan.py
- Scanner now correctly tests GET parameters
- Verified on http://testphp.vulnweb.com (70+ XSS detected)

### Improved
- Type safety: fixed 178 MyPy errors (100% clean)
- Added type annotations across 90+ files
- Fixed Optional, List, Dict, Mapping usage

### Changed
- Removed all emojis from code
- Removed marketing language from technical code
- Updated README for BRS-KB reference (https://github.com/EPTLLC/BRS-KB)
- Removed outdated Roadmap section

### Added
- ML integration layer (brsxss/core/ml_integration.py)
- WAF bypass test suite (30+ tests)
- API documentation (docs/api-reference.md)
- Usage examples (5 practical examples)
- WAF bypass testing guide (docs/waf-bypass-testing.md)

## [2.0.0] - 2025-10-10

### Major Release - Knowledge Base System & Improvements

This is a major version release introducing a comprehensive expert system for XSS vulnerability analysis.

### Improved (2025-10-15)
- **Type Safety**: Reduced MyPy errors from 178 to 62 (65% improvement)
- Fixed type annotations across 90+ files
- Added ML Integration layer for enhanced scanning
- WAF bypass test suite with 30+ comprehensive tests
- Complete API documentation (600+ lines)
- Usage examples directory with 5 practical examples
- Removed outdated Roadmap section from README
- Updated documentation to reference BRS-KB as standalone project

### Added
- **Knowledge Base System**: 17 context modules with 5,535 lines of expert vulnerability documentation
  - html_content.py (398 lines) - HTML body injection
  - html_attribute.py (529 lines) - Attribute breakout techniques
  - javascript_context.py (636 lines) - Direct JavaScript injection
  - js_string.py (619 lines) - String escaping bypasses
  - js_object.py (619 lines) - Prototype pollution attacks
  - css_context.py (675 lines) - CSS injection and data exfiltration
  - url_context.py (545 lines) - Protocol handler bypasses
  - dom_xss.py (350 lines) - Client-side XSS source-sink analysis
  - svg_context.py (288 lines) - SVG-based attack vectors
  - template_injection.py (107 lines) - Client-side template injection
  - postmessage_xss.py (125 lines) - PostMessage API vulnerabilities
  - wasm_context.py (110 lines) - WebAssembly context XSS
  - markdown_context.py (101 lines) - Markdown rendering XSS
  - json_value.py (72 lines) - JSON context injection
  - xml_content.py (81 lines) - XML/XHTML vulnerabilities
  - html_comment.py (68 lines) - Comment breakout techniques
  - default.py (156 lines) - Generic XSS fallback

- **SIEM/Triage Integration**: Enhanced metadata for enterprise security tools
  - CVSS 3.1 scoring (cvss_score, cvss_vector)
  - Severity levels (low, medium, high, critical)
  - Reliability scoring (tentative, firm, certain)
  - CWE identifiers mapping
  - OWASP Top 10 references
  - Classification tags

- **Versioning System**: Semantic versioning for Knowledge Base
  - KB_VERSION = "1.0.0"
  - API functions: get_kb_version(), get_kb_info(), list_contexts()

- **Schema Validation**: JSON Schema for CI/CD validation
  - schema.json with complete DETAILS structure validation
  - Enforces required fields, data types, and value ranges
  - Integration with pytest test suite

- **CLI Commands**: Knowledge Base access from command line
  - `brs-xss kb info` - Show KB information
  - `brs-xss kb list` - List all contexts
  - `brs-xss kb show <context>` - View context details
  - `brs-xss kb search <keyword>` - Search contexts
  - `brs-xss kb export <context> <file>` - Export to JSON/YAML/Markdown
  - Section filtering: --section description/attack_vector/remediation
  - Format options: --format text/json/markdown

- **Reverse Mapping System**: Payload-Context-Defense correlation
  - find_contexts_for_payload() - Map payloads to vulnerable contexts
  - get_defenses_for_context() - Get recommended defenses with priority
  - get_defense_info() - Defense effectiveness analysis
  - reverse_lookup() - Universal reverse lookup function

- **YAML Metadata**: Quick module revision without Python import
  - .meta.yaml files for rapid CI/CD checks
  - Module version, severity, CVSS, CWE
  - Content statistics and tags

- **Test Suite**: Comprehensive validation tests
  - 16 pytest tests for KB structure, metadata, integration
  - Validates all 17 contexts
  - Schema compliance checks
  - Import and runtime error detection

### Changed
- Report generator now enriches vulnerabilities with KB data automatically
- Main README.md updated with Knowledge Base section
- CLI --version now shows both scanner and KB versions

### Technical Details
- Total lines: 6,749 (5,535 Python + 123 JSON + 38 YAML + 427 MD + 626 other)
- Average module size: 307 lines
- All content in English per project policy
- Headers on all files with project metadata
- Zero linter errors

### Documentation
- brsxss/report/knowledge_base/README.md - Complete KB documentation (427 lines)
- Main README.md - Knowledge Base section added
- Usage examples for Python API and CLI
- Integration guides for SIEM/Triage tools

## [1.1.1] - 2025-01-10
### Fixed
- **Critical**: Correctly scan HTML forms using the POST method. The scanner was previously ignoring forms and only testing GET parameters, leading to major missed vulnerabilities.
- **UI**: Replaced verbose real-time logging with a clean, stable progress bar and a final summary table for a more user-friendly experience.
- **UI**: Prevented informational log messages from breaking the progress bar display, which caused the application to appear frozen.
- **Consistency**: Ensured version number `1.1.1` is used consistently across all project files, including package metadata, documentation, and Docker images.

## [1.0.5.1] - 2025-09-09

### Fixed
- Release workflow stability; limit ruff scope in release job
- Update badges and README header; prepare PyPI publish

### Packaging
- Bump version to 1.0.5.1 across metadata and Docker labels

## [1.0.5] - 2025-09-08

### Fixed
- SARIF reporter structure and indentation issues resolved; reports validate against 2.1.0
- Added run-level `columnKind=utf16CodeUnits` and `defaultEncoding=utf-8` on save
- Rule metadata enriched: `driver.semanticVersion`, help text, helpUri, CWE-79 relation

### Added
- New tests covering SARIF 2.1.0 structure and required fields (tool, rules, results tags)
- GitHub Actions: clean multi-arch Docker workflow for GHCR (linux/amd64, linux/arm64)

### Changed
- README notes on SARIF compliance and multi-arch builds
- Version bumped to 1.0.5 across metadata and Docker labels

### Quality
- Test suite: 70+ tests passing locally; coverage maintained ≥80%

## [1.0.4] - 2025-09-05

### Highlights
- SARIF 2.1.0 reporting for GitHub Security integration
- CI/CD pipeline with Docker multi-arch builds
- Complete documentation overhaul with comparison matrix

### Fixed
- Removed non-existent Python packages from dev requirements (syft>=0.100.0, cosign>=2.0.0)
- Fixed YAML syntax in release workflow for proper CI/CD execution
- Temporarily disabled MyPy type checking to allow stable releases (178 type errors need refactoring)

### Added
- SARIF 2.1.0 reporter (`sarif_reporter.py`)
- Context Matrix framework (6 contexts + polyglot payloads, not yet integrated)
- 5 How-to guides (quickstart, CI, SARIF, Docker, safe-mode)
- Example user config (`~/.config/brs-xss/config.toml`)
- Benchmark suite (performance + accuracy)

### Changed
- Project description to "Context-aware async XSS scanner for CI"
- Safe defaults in `config/default.yaml`
- PyPI keywords and README for better positioning
- Dockerfile with multi-stage, security hardened

### DevOps
- GitHub Actions pipeline (ruff, pytest, codecov) - MyPy temporarily disabled
- Multi-arch Docker builds (amd64/arm64)
- Container registry GHCR with signed images
- Performance monitoring via benchmark framework

### Documentation
- README overhaul with comparison vs XSStrike/XSpear/dalfox
- Integration guides: GitHub Actions, GitLab CI, Jenkins
- SARIF integration guide (Security tab setup)
- Docker deployment guide

### Fixed
- **PayloadGenerator stability**: Fixed reset_statistics Counter type bug, unified detected_wafs types
- **Statistics calculation**: Added proper success_rate updates with exponential smoothing
- **Memory optimization**: Lazy Context Matrix loading for relevant contexts only
- **Type safety**: Removed unused imports (Iterable, Tuple), consistent Optional[List[Any]] types
- **Performance**: Reduced unnecessary allocations for unknown context types
- **Configuration validation**: Added comprehensive config parameter validation with safe ranges
- **Pool size control**: Hard cap on payload pool size to prevent memory issues (pool_cap setting)
- **Final deduplication**: Added post-blind-XSS deduplication to eliminate all duplicates
- **Security**: Safe logging without exposing raw payloads or WAF markers
- **Payload safety**: Protection against empty/oversized payloads in evasion techniques
- **Real success metrics**: Accurate success_rate calculation based on filtered vs total candidates
- **Safe mode integration**: Blind XSS disabled in safe_mode for production safety
- **Configurable weights**: Customizable effectiveness scores for different payload sources
- **Code readability**: Explicit list comprehensions instead of generator expressions

### Next
- Context Matrix integration into core engine
- WAF bypass test-suite
- ML-scoring pipeline

## [1.0.3] - 2025-08-18

### Highlights
- **Complete Payload Arsenal**: Integration of 901+ specialized payloads from all payload modules
- **Real-time Progress**: Detailed payload testing progress with time estimates
- **Enhanced User Experience**: Dual progress bars for comprehensive scan visibility

### Added
- **Payload Integration**: PayloadGenerator now accesses all 901+ payloads from payload modules
- **Progress Tracking**: Real-time progress callback system with payload-level granularity
- **User Interface**: Dual progress bars showing URL and payload testing progress

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
- Multi-format reports (HTML + JSON) via `ReportGenerator` integrated into scan flow.
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
- Initial release with core XSS detection capabilities
- Context-aware payload generation
- WAF detection and bypass techniques
- Multi-format reporting (HTML, JSON)
- DOM XSS analysis via Playwright

---

[Unreleased]: https://github.com/EPTLLC/brs-xss/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/EPTLLC/brs-xss/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/EPTLLC/brs-xss/compare/v1.0.5.1...v1.1.1
[1.0.5.1]: https://github.com/EPTLLC/brs-xss/compare/v1.0.5...v1.0.5.1
[1.0.5]: https://github.com/EPTLLC/brs-xss/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/EPTLLC/brs-xss/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/EPTLLC/brs-xss/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/EPTLLC/brs-xss/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/EPTLLC/brs-xss/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/EPTLLC/brs-xss/releases/tag/v1.0.0
