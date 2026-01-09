# Classification Engine

**BRS-XSS v4.0.0-beta.1 - Intelligent XSS Classification System**

## Overview

The Classification Engine is a set of modules that provide accurate, context-aware classification of XSS vulnerabilities. It replaces hardcoded classifications with dynamic analysis based on payload characteristics, injection context, and execution confirmation.

## Components

### 1. XSS Type Classifier

**File**: `brsxss/core/xss_type_classifier.py`

Determines the XSS vulnerability type based on payload analysis, source detection, and DOM confirmation.

#### XSS Types

| Type | Description |
|------|-------------|
| `REFLECTED` | Payload reflected from URL/form parameters |
| `DOM_BASED` | Payload executed via DOM manipulation |
| `STORED` | Payload persisted in storage/database |
| `MUTATION` | Payload mutated by browser parsing |
| `BLIND` | Payload triggers external callback |
| `SELF` | Requires victim to inject payload themselves |

#### Subtypes (DOM-based)

| Subtype | Description |
|---------|-------------|
| `DOM_EVENT_HANDLER` | Triggered via event handler (onerror, onload) |
| `DOM_INNERHTML` | Injected via innerHTML sink |
| `DOM_DOCUMENT_WRITE` | Injected via document.write() |
| `DOM_EVAL` | Executed via eval() family |
| `DOM_LOCATION` | Manipulated via location object |

#### Usage

```python
from brsxss.core.xss_type_classifier import get_xss_classifier, InjectionSource

classifier = get_xss_classifier()

result = classifier.classify(
    payload='<img src=x onerror=alert(1)>',
    parameter='q',
    source=InjectionSource.URL_PARAMETER,
    dom_confirmed=True,
    reflection_context='html'
)

print(result.xss_type.value)        # "DOM XSS (Event Handler)"
print(result.trigger_type.value)    # "auto_execute"
print(result.severity_minimum)      # "high"
print(result.confidence_modifier)   # +0.20
```

#### Classification Result

| Field | Type | Description |
|-------|------|-------------|
| `xss_type` | XSSType | Vulnerability classification |
| `trigger_type` | TriggerType | How payload executes |
| `source` | InjectionSource | Where input originated |
| `payload_class` | str | Human-readable class |
| `trigger_description` | str | Trigger explanation |
| `confidence_modifier` | float | Adjustment for confidence (-0.2 to +0.2) |
| `severity_minimum` | str | Minimum recommended severity |
| `details` | dict | Additional classification details |

---

### 2. Context Parser

**File**: `brsxss/core/context_parser.py`

Provides hierarchical context detection instead of coarse labels like "html" or "javascript".

#### Context Path Examples

| Old Context | New Context Path |
|-------------|------------------|
| `html` | `html > body > div > img > onerror` |
| `javascript` | `javascript > script > inline > statement` |
| `html_attribute` | `html > a > href > javascript_uri` |

#### Usage

```python
from brsxss.core.context_parser import get_context_parser

parser = get_context_parser()

result = parser.parse(
    content='<div><img src=x onerror="alert(1)"></div>',
    payload='alert(1)',
    content_type='text/html'
)

print(result.primary_context.to_string())  # "html > div > img > onerror"
print(result.risk_level)                   # "high"
print(result.can_execute_js)               # True
```

#### Context Analysis Result

| Field | Type | Description |
|-------|------|-------------|
| `primary_context` | ContextPath | Most relevant context |
| `secondary_contexts` | List[ContextPath] | Alternative contexts |
| `risk_level` | str | low/medium/high/critical |
| `can_execute_js` | bool | JavaScript execution possible |
| `requires_breakout` | bool | Quote/tag breakout needed |
| `breakout_needed` | str | Description of breakout |
| `suggestions` | List[str] | Exploitation hints |

#### Context Types

**Base Types**: HTML, JAVASCRIPT, CSS, URL, SVG, XML, JSON, TEMPLATE

**HTML Sub-Contexts**:
- `TAG_CONTENT` - Between tags: `<div>HERE</div>`
- `TAG_NAME` - Tag position: `<HERE ...>`
- `ATTRIBUTE_VALUE` - Attribute value: `<tag attr="HERE">`
- `COMMENT` - HTML comment: `<!-- HERE -->`

**JavaScript Sub-Contexts**:
- `STRING_SINGLE` - Single quoted: `'HERE'`
- `STRING_DOUBLE` - Double quoted: `"HERE"`
- `EXPRESSION` - Expression: `var x = HERE`
- `STATEMENT` - Statement: `HERE;`

**Attribute Types**:
- `EVENT_HANDLER` - onclick, onerror, etc.
- `SRC` - Script/image source
- `HREF` - Link target
- `SRCDOC` - iframe content

---

### 3. Payload Classifier

**File**: `brsxss/core/payload_classifier.py`

Generates consistent PAYLOAD CLASS information for all findings.

#### Usage

```python
from brsxss.core.payload_classifier import get_payload_classifier

classifier = get_payload_classifier()

result = classifier.classify('<img src=x onerror=alert(1)>')

print(result.to_payload_class_string())
# "HTML Attribute Injection | Trigger: img.onerror"

print(result.injection_type.value)   # "HTML Attribute Injection"
print(result.trigger.value)          # "error_triggered"
print(result.vector)                 # "img.onerror"
print(result.is_deterministic)       # True
print(result.requires_interaction)   # False
```

#### Injection Types

| Type | Description | Example |
|------|-------------|---------|
| `SCRIPT_INLINE` | Inline script tag | `<script>alert(1)</script>` |
| `SCRIPT_EXTERNAL` | External script | `<script src=...>` |
| `HTML_ATTRIBUTE` | Attribute injection | `<img onerror=...>` |
| `EVENT_HANDLER` | Event handler only | `onclick=alert(1)` |
| `JAVASCRIPT_URI` | JavaScript URI | `href="javascript:..."` |
| `DATA_URI` | Data URI | `src="data:text/html,..."` |
| `SVG_INJECTION` | SVG-based XSS | `<svg onload=...>` |
| `DOM_MANIPULATION` | DOM sink | `innerHTML=...` |
| `EVAL_BASED` | Eval family | `eval(...)` |

#### Trigger Mechanisms

| Mechanism | Description | Deterministic |
|-----------|-------------|---------------|
| `AUTO_IMMEDIATE` | Executes on page load | Yes |
| `ERROR_TRIGGERED` | Triggers on error | Yes |
| `LOAD_TRIGGERED` | Triggers on load | Yes |
| `EXTERNAL_LOAD` | Loads external resource | Yes |
| `USER_CLICK` | Requires click | No |
| `USER_HOVER` | Requires mouse hover | No |
| `USER_FOCUS` | Requires focus | No |

---

### 4. Payload Analyzer (NEW in v4.0.0)

**File**: `brsxss/core/payload_analyzer.py`

Runtime payload analysis - computes metadata that KB cannot store.

#### Architecture

```
BRS-KB (Static Knowledge)          BRS-XSS PayloadAnalyzer (Runtime)
─────────────────────────          ─────────────────────────────────
payload: "<img onerror=...>"   →   trigger_element: "img"
contexts: ["html_attribute"]       trigger_attribute: "onerror"
severity: "high"                   execution: "error_triggered"
tags: ["onerror", "event"]         is_deterministic: true
                                   xss_type_hint: "DOM XSS (Event Handler)"
                                   confidence_boost: +0.25
                                   severity_minimum: "high"
```

#### Usage

```python
from brsxss.core.payload_analyzer import get_payload_analyzer, analyze_payload

analyzer = get_payload_analyzer()

# Or use convenience function
result = analyze_payload('<img src=x onerror=alert(1)>')

print(result.trigger_vector)        # "img.onerror"
print(result.execution.value)       # "error_triggered"
print(result.is_deterministic)      # True
print(result.confidence_boost)      # +0.25
print(result.severity_minimum)      # "high"
print(result.payload_class_string)  # "Html Attribute | via img.onerror | (Auto-Execute)"
```

#### AnalyzedPayload Fields

| Field | Type | Description |
|-------|------|-------------|
| `trigger_element` | str | HTML element (img, svg, script) |
| `trigger_attribute` | str | Event handler (onerror, onload) |
| `trigger_vector` | str | Combined: "img.onerror" |
| `execution` | ExecutionType | How payload executes |
| `is_deterministic` | bool | Will definitely execute |
| `requires_interaction` | bool | Needs user action |
| `auto_executes` | bool | Executes automatically |
| `injection_class` | InjectionClass | Injection classification |
| `xss_type_hint` | XSSTypeHint | Suggested XSS type |
| `confidence_boost` | float | Adjustment for confidence |
| `severity_minimum` | str | Minimum recommended severity |
| `contains_external_resource` | bool | Loads external content |
| `external_url` | str | External URL if any |

#### Execution Types

| Type | Description | Deterministic |
|------|-------------|---------------|
| `ERROR_TRIGGERED` | onerror handler | Yes |
| `LOAD_TRIGGERED` | onload handler | Yes |
| `AUTO_IMMEDIATE` | Script tag | Yes |
| `EXTERNAL_LOAD` | script src | Yes |
| `USER_CLICK` | onclick, etc. | No |
| `USER_HOVER` | onmouseover | No |
| `USER_FOCUS` | onfocus | No |

#### Confidence Boost Values

| Condition | Boost |
|-----------|-------|
| Deterministic trigger | +0.15 |
| Auto-execute handler | +0.10 |
| External script | +0.10 |
| Inline script | +0.05 |
| Requires interaction | -0.10 |

---

### 5. Confidence Calculator

**File**: `brsxss/core/confidence_calculator.py`

Factor-based confidence calculation with payload-aware adjustments.

#### Confidence Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| `reflection` | 0.25 | Reflection quality (exact/encoded/filtered) |
| `context` | 0.20 | Context detection certainty |
| `payload` | 0.15 | Payload pattern recognition |
| `detection` | 0.15 | Detection method count |
| `dom_confirmation` | 0.15 | DOM execution confirmed |
| `trigger_determinism` | 0.10 | Trigger reliability |

#### Minimum Confidence Enforcements

| Condition | Minimum Confidence |
|-----------|-------------------|
| DOM execution confirmed | 90% |
| External script load | 95% |
| Auto-execute handler + reflection | 85% |

#### Confidence Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| `DEFINITE` | 95-100% | Confirmed execution |
| `VERY_HIGH` | 85-95% | Strong evidence |
| `HIGH` | 70-85% | Reliable detection |
| `MEDIUM` | 50-70% | Probable vulnerability |
| `LOW` | 30-50% | Possible vulnerability |
| `UNCERTAIN` | <30% | Needs verification |

#### Usage

```python
from brsxss.core.confidence_calculator import ConfidenceCalculator

calc = ConfidenceCalculator()

result = calc.calculate(
    reflection_result=reflection,
    context_info={'specific_context': 'javascript'},
    payload='<img src=x onerror=alert(1)>',
    dom_confirmed=True,
    classification_result=xss_result
)

print(f"{result.percentage}%")       # "95%"
print(result.level.value)            # "definite"
print(result.primary_reason)         # "DOM execution confirmed"
```

---

### 6. Scoring Engine Integration

**File**: `brsxss/core/scoring_engine.py`

Severity synchronized with confidence to prevent contradictions.

#### Severity Rules

| Condition | Minimum Severity |
|-----------|------------------|
| 95%+ confidence + DOM confirmed | HIGH |
| 85%+ confidence | MEDIUM |
| External script load | HIGH |
| Auto-execute event handler | HIGH |
| Stored XSS + auto-execute | CRITICAL |
| HTML comment context | LOW (cap) |

---

## Integration

All classifiers are automatically integrated into the scanner:

```python
# In brsxss/core/scanner.py

from .xss_type_classifier import get_xss_classifier
from .context_parser import get_context_parser
from .payload_classifier import get_payload_classifier
from .payload_analyzer import get_payload_analyzer

class XSSScanner:
    def __init__(self):
        # New v4.0.0 classifiers
        self.xss_classifier = get_xss_classifier()
        self.context_parser = get_context_parser()
        self.payload_classifier = get_payload_classifier()
        self.payload_analyzer = get_payload_analyzer()  # Phase 7
```

### Vulnerability Output

Each vulnerability now includes (v4.0.0 with PayloadAnalyzer):

```json
{
  "url": "https://example.com/search",
  "parameter": "q",
  "payload": "<img src=x onerror=alert(1)>",
  "vulnerability_type": "DOM XSS (Event Handler)",
  "context": "html > img > onerror",
  "payload_class": "Html Attribute | via img.onerror | (Auto-Execute)",
  "trigger": "img.onerror",
  "trigger_element": "img",
  "trigger_attribute": "onerror",
  "trigger_mechanism": "error_triggered",
  "is_deterministic": true,
  "requires_interaction": false,
  "execution": "error_triggered",
  "injection_class": "html_attribute",
  "xss_type_hint": "DOM XSS (Event Handler)",
  "contains_external_resource": false,
  "severity": "high",
  "confidence": 0.95,
  "confidence_level": "definite",
  "confidence_reason": "Deterministic trigger: img.onerror",
  "classification": {
    "xss_type": "DOM XSS (Event Handler)",
    "trigger_type": "auto_execute",
    "source": "url_parameter",
    "confidence_modifier": 0.20,
    "severity_minimum": "high",
    "payload_analysis": {
      "trigger_element": "img",
      "trigger_attribute": "onerror",
      "trigger_vector": "img.onerror",
      "execution": "error_triggered",
      "is_deterministic": true,
      "injection_class": "html_attribute",
      "xss_type_hint": "DOM XSS (Event Handler)",
      "confidence_boost": 0.25,
      "severity_minimum": "high"
    }
  }
}
```

---

### 7. Classification Rules Matrix (Phase 8)

**File**: `brsxss/core/classification_rules.py`

Defines valid combinations of scan mode, source type, XSS type, and confidence ceiling.

#### Purpose

- Quick mode should NOT use "Reflected XSS" for unknown parameters
- Deterministic payloads (`<script>`, `onerror=`) should have high confidence
- Different modes use different terminology (heuristic vs confirmed)

#### Truth Table

| Mode | Source | Parameter | Allowed Types | Confidence Ceiling |
|------|--------|-----------|---------------|-------------------|
| quick | unknown | unknown | DOM-Based, Potential DOM | 80% |
| quick | url_parameter | known | Reflected, Potential Reflected | 85% |
| quick | url_fragment | N/A | DOM-Based, Potential DOM | 80% |
| standard | unknown | unknown | DOM-Based, DOM Event Handler | 90% |
| standard | url_parameter | known | Reflected | 95% |
| standard | url_fragment | N/A | DOM-Based, DOM Event Handler | 95% |
| deep | any | any | Full classification | 100% |

#### Deterministic Pattern Overrides

| Pattern | Min Confidence | Type Override |
|---------|---------------|---------------|
| `<script` | 95% | None (type preserved) |
| `<script src=` | 98% | DOM XSS (Script) |
| `onerror=` | 90% | DOM XSS (Event Handler) |
| `onload=` | 90% | DOM XSS (Event Handler) |

#### Usage

```python
from brsxss.core.classification_rules import validate_classification, apply_classification_rules

# Validate a classification
result = validate_classification(
    mode="quick",
    source="unknown",
    proposed_type="Reflected XSS",
    parameter="unknown",
    confidence=0.80,
    payload="<script>alert(1)</script>"
)

print(result['corrected_type'])       # "DOM-Based XSS"
print(result['corrected_confidence']) # 0.95 (script tag override)
print(result['reason'])               # "Parameter unknown, cannot be Reflected"

# Apply to vulnerability dict
vuln = {"vulnerability_type": "Reflected XSS", "parameter": "unknown", ...}
apply_classification_rules(vuln, scan_mode="quick")
# vuln now has corrected vulnerability_type
```

---

## Testing

### Unit Tests

```bash
# Test all classifiers
python -c "
from brsxss.core.xss_type_classifier import get_xss_classifier
from brsxss.core.context_parser import get_context_parser
from brsxss.core.payload_classifier import get_payload_classifier
from brsxss.core.payload_analyzer import get_payload_analyzer
from brsxss.core.classification_rules import validate_classification

print('XSS Classifier:', get_xss_classifier())
print('Context Parser:', get_context_parser())
print('Payload Classifier:', get_payload_classifier())
print('Payload Analyzer:', get_payload_analyzer())
print('Classification Rules: validate_classification loaded')
print('All OK')
"
```

### Integration Test

```bash
# Test classification pipeline
brs-xss scan https://xss-game.appspot.com/level1 --verbose
```

---

## Notes

- **Backward Compatibility**: Old field names (`reflection_type`, `context`, `confidence`) preserved
- **Performance**: All classifiers use regex and standard library (no external dependencies)
- **Caching**: Singleton pattern for classifier instances
- **Quick Mode**: Uses "Potential" / "heuristic" terminology, not lower confidence for deterministic payloads

