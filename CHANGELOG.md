# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **XSS Type Classifier** (`brsxss/core/xss_type_classifier.py`):
  - Dynamic XSS type detection: Reflected, DOM-based, Stored, Mutation, Blind
  - Subtypes: DOM_EVENT_HANDLER, DOM_INNERHTML, DOM_DOCUMENT_WRITE, DOM_EVAL
  - `InjectionSource` enum: URL_PARAMETER, URL_FRAGMENT, DOM_API, STORAGE, POSTMESSAGE
  - `TriggerType` enum: EVENT_HANDLER, SCRIPT_TAG, SCRIPT_SRC, JAVASCRIPT_URI
  - Confidence modifiers and minimum severity recommendations

- **Context Parser** (`brsxss/core/context_parser.py`):
  - Hierarchical context detection: `html > img > onerror` instead of just `html`
  - `ContextPath` with base type, hierarchy, subcontext, attribute type
  - HTML parser for accurate payload location detection
  - Risk level assessment and JavaScript execution capability detection

- **Payload Classifier** (`brsxss/core/payload_classifier.py`):
  - Consistent PAYLOAD CLASS generation for all findings
  - `InjectionType` enum: SCRIPT_INLINE, SCRIPT_EXTERNAL, HTML_ATTRIBUTE, EVENT_HANDLER
  - `TriggerMechanism` enum: AUTO_IMMEDIATE, ERROR_TRIGGERED, LOAD_TRIGGERED, USER_CLICK
  - Deterministic vs user-interaction flags
  - Human-readable trigger descriptions

- **Payload Analyzer** (`brsxss/core/payload_analyzer.py`) [Phase 7]:
  - Runtime metadata computation (KB stores WHAT works, Scanner computes HOW)
  - `ExecutionType` enum: ERROR_TRIGGERED, LOAD_TRIGGERED, AUTO_IMMEDIATE, USER_CLICK
  - `InjectionClass` enum: SCRIPT_INLINE, SCRIPT_EXTERNAL, HTML_ATTRIBUTE, SVG_INJECTION
  - `XSSTypeHint` enum: DOM_EVENT_HANDLER, DOM_INNERHTML, LIKELY_REFLECTED
  - `AnalyzedPayload` dataclass with computed fields:
    - `trigger_element`, `trigger_attribute`, `trigger_vector`
    - `execution`, `is_deterministic`, `requires_interaction`
    - `confidence_boost`, `severity_minimum`
    - `contains_external_resource`, `external_url`
  - Obfuscation level detection (unicode/hex escapes, encoding functions)

#### Changed - Scoring System
- **Confidence Calculator**: Complete refactoring with factor-based calculation
  - Factors: reflection, context, payload, detection, dom_confirmation, trigger_determinism
  - `ConfidenceLevel` enum: DEFINITE (95%+), VERY_HIGH (85%+), HIGH (70%+), MEDIUM, LOW
  - Minimum confidence enforcements: DOM confirmed = 90%+, external script = 95%+
  - Auto-execute handlers (onerror, onload) = 90%+ confidence

- **Scoring Engine**: Severity synchronized with confidence
  - 95%+ confidence + DOM confirmed = minimum HIGH severity
  - 85%+ confidence = minimum MEDIUM severity
  - External script load = minimum HIGH severity
  - Auto-execute event handlers = minimum HIGH severity
  - No more MEDIUM severity with 99% confidence

- **Scanner Integration**: All new classifiers integrated
  - Dynamic `vulnerability_type` instead of hardcoded "Reflected XSS"
  - `payload_class`, `trigger`, `trigger_mechanism` in every finding
  - `is_deterministic`, `requires_interaction` flags
  - `classification` block with full details including `payload_analysis`
  - Hierarchical context: `html > img > onerror` instead of just `html`
  - **CRITICAL FIX**: `parameter=unknown` now correctly classified as DOM-based (not Reflected)
  - `dom_confirmed=True` takes priority for DOM-based classification

- **Classification Rules Matrix** (`brsxss/core/classification_rules.py`) [Phase 8]:
  - Truth table for (mode × source × type × confidence) combinations
  - Quick mode uses "Potential DOM XSS" / "heuristic" terminology
  - Standard mode uses confirmed terminology
  - Deterministic pattern overrides: `<script>` = 95%+, `onerror=` = 90%+
  - Prevents Reflected XSS label when parameter unknown
  - Auto-infers source from parameter (param known → url_parameter)

- **Unified Finding Normalizer** (`brsxss/core/finding_normalizer.py`) [Phase 9]:
  - SINGLE normalization point for ALL findings before report
  - Fixes DOM fragment findings bypassing classification pipeline
  - `normalize_finding()`: Applies all classification rules
  - `prepare_findings_for_report()`: Entry point for PDF/JSON/SARIF
  - Dev assertions: Catches Reflected XSS + unknown param violations
  - Context hierarchy: Auto-builds `html > img > onerror` from payload

#### Changed - Reports
- **Scan ID vs Authorization Reference**: Now separate in PDF reports
  - `authorization_ref` parameter in `generate_scan_report()`
  - Default format: `AUTH-{scan_id[:8].upper()}`

#### Changed - Configuration
- **Default Mode**: Remote API (previously local library)
- **Configuration**: New `kb:` section in `config/default.yaml`
- **Version Management**: Single source of truth in `brsxss/version.py`
- **Web UI**: Dynamic KB stats display (payloads, contexts, WAF bypasses)

#### Technical Details
- `RemoteKBClient`: HTTP client using `http.client` for proper header handling
- `LocalKBClient`: Wrapper for local `brs_kb` library
- Auto-detection of KB availability with graceful degradation
- No hardcoded values - all stats fetched dynamically

#### Configuration
```yaml
kb:
  mode: "remote"  # remote | local | auto
  api:
    url: "https://brs-kb.easypro.tech/api/v1"
    timeout: 30
```

Environment variables:
- `BRSXSS_KB_API_KEY` - API key for production
- `BRSXSS_KB_MODE` - Override mode (remote/local/auto)

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

[4.0.0]: https://github.com/EPTLLC/brs-xss/releases/tag/v4.0.0
[2.1.1]: https://github.com/EPTLLC/brs-xss/releases/tag/v2.1.1
[2.1.0]: https://github.com/EPTLLC/brs-xss/releases/tag/v2.1.0
[1.0.0]: https://github.com/EPTLLC/brs-xss/releases/tag/v1.0.0
