#!/usr/bin/env python3

"""
Project: BRS-XSS Scanner
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: New - Strategy Rules Implementation
Telegram: https://t.me/EasyProTech

Switching rules for adaptive XSS scanning strategy.
"""

from dataclasses import dataclass, field
from typing import Optional, Any, Callable
from abc import ABC, abstractmethod
from enum import Enum


class RuleType(Enum):
    """Types of switching rules"""
    CONTEXT_SWITCH = "context_switch"
    WAF_BYPASS = "waf_bypass"
    ENCODING = "encoding"
    MUTATION = "mutation"
    FALLBACK = "fallback"


@dataclass
class SwitchRule(ABC):
    """Base class for strategy switching rules"""
    id: str
    name: str
    description: Optional[str] = None
    rule_type: RuleType = RuleType.FALLBACK
    priority: int = 0
    enabled: bool = True
    
    # Conditions for when this rule applies
    conditions: dict[str, Any] = field(default_factory=dict)
    
    # Actions to take when rule triggers
    actions: list[dict[str, Any]] = field(default_factory=list)
    
    @abstractmethod
    def evaluate(self, context: dict[str, Any]) -> bool:
        """Check if this rule should trigger"""
        pass
    
    @abstractmethod
    def apply(self, context: dict[str, Any]) -> dict[str, Any]:
        """Apply the rule and return modified context/actions"""
        pass
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type.value,
            "priority": self.priority,
            "enabled": self.enabled,
            "conditions": self.conditions,
            "actions": self.actions,
        }


@dataclass
class ContextSwitchRule(SwitchRule):
    """
    Rule for switching between injection contexts.
    
    Example: If HTML context fails, try JavaScript context.
    """
    rule_type: RuleType = RuleType.CONTEXT_SWITCH
    
    # Source and target contexts
    from_context: Optional[str] = None
    to_context: Optional[str] = None
    
    # Trigger conditions
    min_failures: int = 3  # Switch after N failures
    
    def evaluate(self, context: dict[str, Any]) -> bool:
        """Check if context switch should happen"""
        if not self.enabled:
            return False
        
        current_context = context.get("context_type")
        failures = context.get("consecutive_failures", 0)
        
        # Check if we're in the source context
        if self.from_context and current_context != self.from_context:
            return False
        
        # Check failure threshold
        if failures < self.min_failures:
            return False
        
        return True
    
    def apply(self, context: dict[str, Any]) -> dict[str, Any]:
        """Apply context switch"""
        return {
            "action": "switch_context",
            "from": self.from_context or context.get("context_type"),
            "to": self.to_context,
            "reason": f"Switching after {context.get('consecutive_failures', 0)} failures",
        }


@dataclass
class WAFBypassRule(SwitchRule):
    """
    Rule for WAF bypass strategies.
    
    Example: If WAF blocks <script>, try event handlers.
    """
    rule_type: RuleType = RuleType.WAF_BYPASS
    
    # WAF detection
    waf_name: Optional[str] = None  # Specific WAF or None for any
    
    # Bypass technique
    bypass_technique: str = "encoding"  # encoding, mutation, alternative
    bypass_config: dict[str, Any] = field(default_factory=dict)
    
    def evaluate(self, context: dict[str, Any]) -> bool:
        """Check if WAF bypass should be attempted"""
        if not self.enabled:
            return False
        
        waf_detected = context.get("waf_detected", False)
        if not waf_detected:
            return False
        
        # Check specific WAF if configured
        if self.waf_name:
            detected_waf = context.get("waf_name", "").lower()
            if self.waf_name.lower() not in detected_waf:
                return False
        
        return True
    
    def apply(self, context: dict[str, Any]) -> dict[str, Any]:
        """Apply WAF bypass"""
        return {
            "action": "waf_bypass",
            "technique": self.bypass_technique,
            "config": self.bypass_config,
            "waf": context.get("waf_name", "unknown"),
        }


@dataclass
class EncodingRule(SwitchRule):
    """
    Rule for encoding strategies.
    
    Example: If raw payload blocked, try URL encoding.
    """
    rule_type: RuleType = RuleType.ENCODING
    
    # Encoding type
    encoding_type: str = "url"  # url, html_entity, unicode, base64, double
    
    # When to apply
    on_block: bool = True  # Apply when payload is blocked
    on_filter: bool = True  # Apply when payload is filtered
    
    def evaluate(self, context: dict[str, Any]) -> bool:
        """Check if encoding should be applied"""
        if not self.enabled:
            return False
        
        blocked = context.get("payload_blocked", False)
        filtered = context.get("payload_filtered", False)
        
        if self.on_block and blocked:
            return True
        if self.on_filter and filtered:
            return True
        
        return False
    
    def apply(self, context: dict[str, Any]) -> dict[str, Any]:
        """Apply encoding"""
        return {
            "action": "encode",
            "encoding": self.encoding_type,
            "original_payload": context.get("current_payload", ""),
        }


@dataclass
class MutationRule(SwitchRule):
    """
    Rule for payload mutation strategies.
    
    Example: If alert() blocked, try confirm() or prompt().
    """
    rule_type: RuleType = RuleType.MUTATION
    
    # Mutation type
    mutation_type: str = "function_swap"  # function_swap, case_swap, tag_swap, obfuscate
    
    # Mutation config
    mutations: dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        # Default mutations
        if not self.mutations:
            self.mutations = {
                # Function swaps
                "alert": "confirm",
                "confirm": "prompt",
                "prompt": "print",
                # Tag swaps
                "script": "svg",
                "svg": "img",
                "img": "body",
                # Case swaps handled separately
            }
    
    def evaluate(self, context: dict[str, Any]) -> bool:
        """Check if mutation should be applied"""
        if not self.enabled:
            return False
        
        # Apply after failures
        failures = context.get("consecutive_failures", 0)
        return failures >= 2
    
    def apply(self, context: dict[str, Any]) -> dict[str, Any]:
        """Apply mutation"""
        payload = context.get("current_payload", "")
        mutated = payload
        
        if self.mutation_type == "function_swap":
            for original, replacement in self.mutations.items():
                if original in payload.lower():
                    mutated = payload.replace(original, replacement)
                    mutated = mutated.replace(original.upper(), replacement.upper())
                    break
        
        elif self.mutation_type == "case_swap":
            # Swap case of tag names
            import re
            def swap_case(match):
                tag = match.group(1)
                return "<" + "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(tag)
                )
            mutated = re.sub(r"<([a-zA-Z]+)", swap_case, payload)
        
        elif self.mutation_type == "tag_swap":
            for original, replacement in self.mutations.items():
                if f"<{original}" in payload.lower():
                    mutated = payload.replace(f"<{original}", f"<{replacement}")
                    mutated = mutated.replace(f"</{original}", f"</{replacement}")
                    break
        
        return {
            "action": "mutate",
            "mutation_type": self.mutation_type,
            "original": payload,
            "mutated": mutated,
        }


# Preset rules
def get_default_rules() -> list[SwitchRule]:
    """Get default set of switching rules"""
    return [
        # Context switching
        ContextSwitchRule(
            id="ctx-html-to-js",
            name="HTML to JS Switch",
            description="Switch from HTML to JavaScript context after failures",
            from_context="html",
            to_context="javascript",
            min_failures=3,
            priority=10,
        ),
        ContextSwitchRule(
            id="ctx-js-to-attr",
            name="JS to Attribute Switch",
            description="Switch from JavaScript to attribute context",
            from_context="javascript",
            to_context="attribute",
            min_failures=3,
            priority=9,
        ),
        ContextSwitchRule(
            id="ctx-attr-to-url",
            name="Attribute to URL Switch",
            description="Switch from attribute to URL context",
            from_context="attribute",
            to_context="url",
            min_failures=3,
            priority=8,
        ),
        
        # WAF bypass
        WAFBypassRule(
            id="waf-cloudflare",
            name="Cloudflare Bypass",
            description="Bypass techniques for Cloudflare WAF",
            waf_name="cloudflare",
            bypass_technique="encoding",
            bypass_config={"encoding": "unicode", "double_encode": True},
            priority=10,
        ),
        WAFBypassRule(
            id="waf-akamai",
            name="Akamai Bypass",
            description="Bypass techniques for Akamai WAF",
            waf_name="akamai",
            bypass_technique="mutation",
            bypass_config={"mutation": "case_swap"},
            priority=10,
        ),
        WAFBypassRule(
            id="waf-generic",
            name="Generic WAF Bypass",
            description="Generic WAF bypass techniques",
            waf_name=None,  # Any WAF
            bypass_technique="encoding",
            bypass_config={"encoding": "html_entity"},
            priority=5,
        ),
        
        # Encoding
        EncodingRule(
            id="enc-url",
            name="URL Encoding",
            description="Apply URL encoding to blocked payloads",
            encoding_type="url",
            priority=8,
        ),
        EncodingRule(
            id="enc-html",
            name="HTML Entity Encoding",
            description="Apply HTML entity encoding",
            encoding_type="html_entity",
            priority=7,
        ),
        EncodingRule(
            id="enc-unicode",
            name="Unicode Encoding",
            description="Apply Unicode encoding",
            encoding_type="unicode",
            priority=6,
        ),
        EncodingRule(
            id="enc-double",
            name="Double Encoding",
            description="Apply double URL encoding",
            encoding_type="double",
            priority=5,
        ),
        
        # Mutation
        MutationRule(
            id="mut-func",
            name="Function Swap",
            description="Swap blocked functions (alert -> confirm)",
            mutation_type="function_swap",
            priority=7,
        ),
        MutationRule(
            id="mut-case",
            name="Case Swap",
            description="Swap case of tag names",
            mutation_type="case_swap",
            priority=6,
        ),
        MutationRule(
            id="mut-tag",
            name="Tag Swap",
            description="Swap blocked tags (script -> svg)",
            mutation_type="tag_swap",
            priority=5,
        ),
    ]
