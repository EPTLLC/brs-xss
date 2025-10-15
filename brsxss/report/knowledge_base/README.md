# BRS-XSS Knowledge Base

## Overview

The Knowledge Base is an expert system for XSS vulnerability reporting. It provides detailed, context-specific information about different types of XSS vulnerabilities including descriptions, attack vectors, and remediation guidance.

**Version**: 1.0.0  
**Build**: 2025.10.10  
**Revision**: stable

## Architecture

**Modular Design**: Each context type has its own Python module with expert knowledge.

**Dynamic Loading**: The `__init__.py` automatically discovers and loads all knowledge modules at runtime.

**Simple Integration**: The report generator enriches vulnerability data by calling `get_vulnerability_details(context)`.

**Versioning**: Full semantic versioning support with KB_VERSION tracking.

**Schema Validation**: JSON Schema for CI/CD validation of all modules.

## Available Contexts

### Core HTML Contexts
- `html_content.py` (398 lines) - XSS in HTML body/content
- `html_attribute.py` (529 lines) - XSS in HTML attributes  
- `html_comment.py` (68 lines) - XSS in HTML comments

### JavaScript Contexts
- `javascript_context.py` (636 lines) - Direct JavaScript code injection
- `js_string.py` (619 lines) - JavaScript string literal injection
- `js_object.py` (619 lines) - JavaScript object context injection

### Style and Markup
- `css_context.py` (675 lines) - CSS injection and style attribute XSS
- `svg_context.py` (288 lines) - SVG-based XSS vectors
- `markdown_context.py` (101 lines) - Markdown rendering XSS

### Data Formats
- `json_value.py` (72 lines) - JSON context XSS
- `xml_content.py` (81 lines) - XML/XHTML XSS vectors

### URL and Protocol
- `url_context.py` (545 lines) - URL/protocol-based XSS

### Advanced Vectors
- `dom_xss.py` (350 lines) - DOM-based XSS (client-side)
- `template_injection.py` (107 lines) - Client-side template injection (Angular, Vue, React, etc.)
- `postmessage_xss.py` (125 lines) - PostMessage API vulnerabilities
- `wasm_context.py` (110 lines) - WebAssembly context XSS

### Fallback
- `default.py` (156 lines) - Generic XSS information for unknown contexts

## Statistics

- **Total Lines**: 5,922 (Python + JSON + YAML)
- **Python Code**: 5,535 lines
- **Modules**: 18 (17 contexts + 1 loader)
- **Average per Module**: 307 lines
- **Content Size**: ~145 KB
- **Status**: Production-ready

## New Features (v1.0.0)

### 1. Versioning System
```python
from brsxss.report.knowledge_base import KB_VERSION, get_kb_info

print(KB_VERSION)  # "1.0.0"
info = get_kb_info()
# Returns: version, build, revision, total_contexts, available_contexts
```

### 2. SIEM/Triage Integration
Enhanced metadata for each vulnerability:
```python
DETAILS = {
    "title": "...",
    "severity": "critical",  # low, medium, high, critical
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "reliability": "certain",  # tentative, firm, certain
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "html", "reflected", "stored"],
    ...
}
```

### 3. CLI Commands
Access Knowledge Base from command line:
```bash
# Show KB info
python3 main.py kb info

# List all contexts
python3 main.py kb list

# Show specific context
python3 main.py kb show html_content
python3 main.py kb show html_attribute --section remediation

# Search contexts
python3 main.py kb search "dom xss"

# Export context
python3 main.py kb export html_content output.json
python3 main.py kb export dom_xss output.md --format markdown
```

### 4. Schema Validation
JSON Schema for CI/CD validation:
```bash
# Schema location
brsxss/report/knowledge_base/schema.json

# Run validation tests
pytest tests/test_knowledge_base.py -v
```

### 5. YAML Metadata
Quick module revision without importing Python:
```yaml
# html_content.meta.yaml
module: html_content
version: 1.0.0
severity: critical
cvss_score: 8.8
cwe: [CWE-79]
tags: [xss, html, reflected]
```

### 6. Reverse Mapping
Payload → Context → Defense mapping:
```python
from brsxss.report.knowledge_base.reverse_map import (
    find_contexts_for_payload,
    get_defenses_for_context
)

# Find contexts for payload
info = find_contexts_for_payload("<script>alert(1)</script>")
print(info['contexts'])  # ['html_content', 'html_comment', 'svg_context']
print(info['defenses'])  # ['html_encoding', 'csp', 'sanitization']

# Get defenses for context
defenses = get_defenses_for_context('html_content')
# Returns: [{"defense": "html_encoding", "priority": 1, "required": True}, ...]
```

## Structure

Each knowledge module exports a `DETAILS` dictionary with:

```python
DETAILS = {
    # Required fields
    "title": "Vulnerability name",
    "description": "Detailed explanation of the vulnerability",
    "attack_vector": "How attackers exploit this vulnerability",
    "remediation": "How to fix and prevent this vulnerability",
    
    # Optional metadata (recommended for SIEM integration)
    "severity": "critical",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/...",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "html"],
    
    # Optional examples
    "examples": [
        {
            "name": "Basic HTML Injection",
            "payload": "<img src=x onerror=alert(1)>",
            "poc_url": "https://vulnerable.com/?q=<payload>",
            "screenshot": "kb/example.png"
        }
    ]
}
```

## Content Quality

Each module contains:
- Professional headers with project metadata
- Detailed vulnerability descriptions
- Real-world attack examples with code
- Modern bypass techniques
- Framework-specific guidance (React, Vue, Angular)
- Security checklists
- Testing payloads
- Tool recommendations
- CVE and OWASP references
- Defense-in-depth strategies

## Usage

### Basic Usage
```python
from brsxss.report.knowledge_base import get_vulnerability_details

# Get context-specific details
details = get_vulnerability_details("html_attribute")
# Returns: {"title": "...", "description": "...", "attack_vector": "...", "remediation": "..."}

# Unknown contexts return default information
details = get_vulnerability_details("unknown_context")
# Returns default XSS information
```

### Advanced Usage
```python
from brsxss.report.knowledge_base import (
    get_kb_version,
    get_kb_info,
    list_contexts
)

# Get version
version = get_kb_version()  # "1.0.0"

# Get full KB info
info = get_kb_info()
print(info['total_contexts'])  # 17
print(info['available_contexts'])  # List of all contexts

# List all contexts
contexts = list_contexts()  # Sorted list
```

## Adding New Contexts

To add a new context:

1. Create a new Python file in this directory (e.g., `new_context.py`)
2. Add the file header with project metadata
3. Export a `DETAILS` dictionary with the required fields
4. The module will be automatically discovered and loaded

Example:

```python
#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: YYYY-MM-DD HH:MM:SS UTC+3
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: New Context
"""

DETAILS = {
    "title": "Cross-Site Scripting in New Context",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/...",
    "reliability": "firm",
    "cwe": ["CWE-79"],
    "tags": ["xss", "new"],
    "description": "Detailed description...",
    "attack_vector": "Attack techniques...",
    "remediation": "Security measures...",
}
```

## Context Mapping

The knowledge base maps to vulnerability contexts detected by BRS-XSS scanner:

- `html_content` → `ContextType.HTML_CONTENT`
- `html_attribute` → `ContextType.HTML_ATTRIBUTE`
- `html_comment` → `ContextType.HTML_COMMENT`
- `javascript_context` → `ContextType.JAVASCRIPT`
- `js_string` → `ContextType.JS_STRING`
- `js_object` → `ContextType.JS_OBJECT`
- `css_context` → `ContextType.CSS_STYLE`
- `url_context` → `ContextType.URL_PARAMETER`
- `json_value` → `ContextType.JSON_VALUE`
- `xml_content` → `ContextType.XML_CONTENT`

## Coverage

The knowledge base covers:

**Classic XSS Vectors:**
- HTML content injection
- HTML attribute breakout
- JavaScript code injection
- CSS injection

**Modern Attack Techniques:**
- DOM-based XSS (client-side)
- Client-side template injection (CSTI)
- Prototype pollution
- Mutation XSS (mXSS)
- PostMessage API exploitation

**Framework-Specific:**
- Angular/AngularJS template injection
- Vue.js v-html abuse
- React dangerouslySetInnerHTML
- Handlebars/Mustache bypasses

**Advanced Vectors:**
- SVG-based attacks
- WebAssembly context XSS
- Markdown rendering XSS
- JSON/XML injection
- URL protocol handlers

**Bypass Techniques:**
- Encoding bypasses (Unicode, URL, HTML entities)
- WAF evasion
- Filter circumvention
- Case variation
- Polyglot payloads

## Maintenance

- Keep information current with latest XSS techniques and bypasses
- Update remediation advice as new security best practices emerge
- Add new contexts as the scanner detects new vulnerability types
- Ensure all content is in English per project standards
- Regular testing of module loading and integration
- Update metadata (severity, CVSS) when standards change
- Run validation tests before releases

## Security Standards

All information in the knowledge base is based on:

- OWASP Testing Guide
- OWASP XSS Prevention Cheat Sheet
- CWE-79: Cross-site Scripting
- CVSS v3.1 Specification
- Modern browser security research
- Real-world penetration testing experience
- Framework-specific security documentation
- Industry best practices
- Latest CVE disclosures

## Testing

The knowledge base is tested for:
- Module loading (all 17 contexts load successfully)
- Data structure integrity (all required fields present)
- Schema validation (JSON Schema compliance)
- Integration with report generator
- No import or runtime errors
- Proper fallback to default context
- Metadata completeness (severity, CVSS, CWE)
- CLI functionality

Test command:
```bash
# Run all KB tests
pytest tests/test_knowledge_base.py -v

# Run specific test class
pytest tests/test_knowledge_base.py::TestKnowledgeBaseStructure -v
```

## File Size Guidelines

Based on complexity and importance:
- **Critical contexts** (HTML, JS, CSS, URL): 400-700 lines
- **Advanced contexts** (DOM XSS, SVG, Template Injection): 250-400 lines  
- **Specialized contexts** (JSON, XML, Markdown, PostMessage): 70-150 lines
- **Fallback** (default): 150+ lines

Files should be:
- Informative and comprehensive
- Easy to read and maintain
- Not excessively long (max ~700 lines)
- Properly structured with clear sections

## Integration with SIEM/Triage Tools

The Knowledge Base provides structured data for security tools:

**CVSS Scoring**: Calculate risk scores for prioritization  
**Severity Levels**: Filter and triage vulnerabilities  
**Reliability**: Confidence scoring for false positive reduction  
**CWE Mapping**: Compliance and categorization  
**OWASP Mapping**: Standard security framework alignment  
**Tags**: Flexible categorization and filtering

Example SIEM integration:
```python
details = get_vulnerability_details('html_content')
siem_event = {
    'severity': details['severity'],
    'cvss_score': details['cvss_score'],
    'cwe': details['cwe'],
    'reliability': details['reliability'],
    'description': details['description']
}
```

## Contributing

When adding new contexts or updating existing ones:

1. Follow the DETAILS structure
2. Include all required fields
3. Add metadata (severity, CVSS, CWE)
4. Create corresponding .meta.yaml file
5. Run validation tests
6. Update this README if needed
7. Ensure English-only content

---

**Company**: EasyProTech LLC (www.easypro.tech)  
**Developer**: Brabus  
**Contact**: https://t.me/easyprotech  
**Version**: 1.0.0  
**Status**: Production-Ready  
**Last Updated**: 2025-10-10
