#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10
Status: Created
Telegram: https://t.me/easyprotech

Reverse Mapping System: Payload → Context → Defense
"""

from typing import List, Dict, Set

# Payload → Context mapping
PAYLOAD_TO_CONTEXT = {
    "<script>alert(1)</script>": {
        "contexts": ["html_content", "html_comment", "svg_context"],
        "severity": "critical",
        "defenses": ["html_encoding", "csp", "sanitization"]
    },
    "<img src=x onerror=alert(1)>": {
        "contexts": ["html_content", "markdown_context", "xml_content"],
        "severity": "high",
        "defenses": ["html_encoding", "attribute_sanitization", "csp"]
    },
    "javascript:alert(1)": {
        "contexts": ["url_context", "html_attribute"],
        "severity": "high",
        "defenses": ["url_validation", "protocol_whitelist"]
    },
    "{{constructor.constructor('alert(1)')()}}": {
        "contexts": ["template_injection"],
        "severity": "critical",
        "defenses": ["template_sandboxing", "aot_compilation", "csp"]
    },
    "'; alert(1); var x='": {
        "contexts": ["js_string"],
        "severity": "critical",
        "defenses": ["javascript_encoding", "json_serialization", "csp"]
    },
    "<svg onload=alert(1)>": {
        "contexts": ["svg_context", "html_content"],
        "severity": "high",
        "defenses": ["svg_sanitization", "csp", "content_type_headers"]
    }
}

# Defense → Effectiveness mapping
DEFENSE_TO_EFFECTIVENESS = {
    "html_encoding": {
        "effective_against": [
            "html_content", "html_attribute", "html_comment"
        ],
        "implementation": [
            "htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",  # PHP
            "html.escape(input, quote=True)",  # Python
            "element.textContent = input"  # JavaScript
        ],
        "bypass_difficulty": "high"
    },
    "csp": {
        "effective_against": [
            "html_content", "javascript_context", "css_context", 
            "svg_context", "template_injection"
        ],
        "implementation": [
            "Content-Security-Policy: default-src 'self'; script-src 'nonce-random'"
        ],
        "bypass_difficulty": "very_high"
    },
    "javascript_encoding": {
        "effective_against": ["js_string", "javascript_context"],
        "implementation": [
            "JSON.stringify(input)",
            "json.dumps(input)",
            "json_encode($input, JSON_HEX_TAG)"
        ],
        "bypass_difficulty": "high"
    },
    "url_validation": {
        "effective_against": ["url_context"],
        "implementation": [
            "new URL(input, base)",  # JavaScript
            "urllib.parse.urlparse(input)",  # Python
            "parse_url($input)"  # PHP
        ],
        "bypass_difficulty": "medium"
    },
    "sanitization": {
        "effective_against": [
            "html_content", "svg_context", "markdown_context", "xml_content"
        ],
        "implementation": [
            "DOMPurify.sanitize(input)",  # JavaScript
            "bleach.clean(input)",  # Python
            "HTMLPurifier"  # PHP
        ],
        "bypass_difficulty": "medium"
    }
}

# Context → Recommended defenses
CONTEXT_TO_DEFENSES = {
    "html_content": [
        {"defense": "html_encoding", "priority": 1, "required": True},
        {"defense": "csp", "priority": 1, "required": True},
        {"defense": "sanitization", "priority": 2, "required": False}
    ],
    "html_attribute": [
        {"defense": "html_encoding", "priority": 1, "required": True},
        {"defense": "url_validation", "priority": 1, "required": True},
        {"defense": "csp", "priority": 2, "required": True}
    ],
    "javascript_context": [
        {"defense": "avoid_inline_js", "priority": 1, "required": True},
        {"defense": "json_serialization", "priority": 1, "required": True},
        {"defense": "csp", "priority": 1, "required": True}
    ],
    "js_string": [
        {"defense": "javascript_encoding", "priority": 1, "required": True},
        {"defense": "json_serialization", "priority": 1, "required": True},
        {"defense": "csp", "priority": 2, "required": True}
    ],
    "url_context": [
        {"defense": "url_validation", "priority": 1, "required": True},
        {"defense": "protocol_whitelist", "priority": 1, "required": True},
        {"defense": "csp", "priority": 2, "required": True}
    ]
}


def find_contexts_for_payload(payload: str) -> Dict:
    """Find contexts where payload is effective"""
    return PAYLOAD_TO_CONTEXT.get(payload, {
        "contexts": [],
        "severity": "unknown",
        "defenses": []
    })


def get_defenses_for_context(context: str) -> List[Dict]:
    """Get recommended defenses for a context"""
    return CONTEXT_TO_DEFENSES.get(context, [])


def get_defense_info(defense: str) -> Dict:
    """Get detailed information about a defense mechanism"""
    return DEFENSE_TO_EFFECTIVENESS.get(defense, {})


def find_payload_bypasses(payload: str) -> List[str]:
    """Find contexts where payload might be blocked"""
    info = find_contexts_for_payload(payload)
    return info.get("defenses", [])


def reverse_lookup(query_type: str, query: str) -> Dict:
    """
    Universal reverse lookup function
    
    query_type: 'payload', 'context', 'defense'
    query: the actual query string
    """
    if query_type == 'payload':
        return find_contexts_for_payload(query)
    elif query_type == 'context':
        return {
            "defenses": get_defenses_for_context(query),
            "context": query
        }
    elif query_type == 'defense':
        return get_defense_info(query)
    else:
        return {}


# Export all functions
__all__ = [
    'find_contexts_for_payload',
    'get_defenses_for_context',
    'get_defense_info',
    'find_payload_bypasses',
    'reverse_lookup',
    'PAYLOAD_TO_CONTEXT',
    'DEFENSE_TO_EFFECTIVENESS',
    'CONTEXT_TO_DEFENSES'
]

