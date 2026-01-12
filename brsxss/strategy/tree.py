#!/usr/bin/env python3

"""
Project: BRS-XSS Scanner
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: New - Strategy Tree Implementation
Telegram: https://t.me/EasyProTech

Decision tree structure for adaptive XSS scanning.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
import json
import uuid


class NodeType(Enum):
    """Types of strategy tree nodes"""

    ROOT = "root"
    CONTEXT = "context"  # HTML, JS, URL, CSS context
    PAYLOAD = "payload"  # Specific payload type
    ENCODING = "encoding"  # Encoding strategy
    WAF_BYPASS = "waf_bypass"  # WAF evasion technique
    MUTATION = "mutation"  # Payload mutation
    CONDITION = "condition"  # Conditional branch
    SUCCESS = "success"  # Successful path marker
    FAILURE = "failure"  # Failed path marker


@dataclass
class StrategyNode:
    """Single node in the strategy tree"""

    id: str
    type: NodeType
    name: str
    description: Optional[str] = None

    # Node configuration
    config: dict[str, Any] = field(default_factory=dict)

    # Condition for this node (when to use it)
    condition: Optional[str] = None  # e.g., "waf_detected", "context == 'html'"

    # Children nodes (branches)
    children: list["StrategyNode"] = field(default_factory=list)

    # Success/failure tracking
    success_count: int = 0
    failure_count: int = 0

    # Priority (higher = try first)
    priority: int = 0

    # Is this node enabled?
    enabled: bool = True

    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5  # Unknown, assume 50%
        return self.success_count / total

    def add_child(self, child: "StrategyNode") -> "StrategyNode":
        """Add child node"""
        self.children.append(child)
        return child

    def find_node(self, node_id: str) -> Optional["StrategyNode"]:
        """Find node by ID in subtree"""
        if self.id == node_id:
            return self
        for child in self.children:
            found = child.find_node(node_id)
            if found:
                return found
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "description": self.description,
            "config": self.config,
            "condition": self.condition,
            "children": [c.to_dict() for c in self.children],
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_rate,
            "priority": self.priority,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StrategyNode":
        """Create from dictionary"""
        node = cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            type=NodeType(data.get("type", "context")),
            name=data.get("name", "Unknown"),
            description=data.get("description"),
            config=data.get("config", {}),
            condition=data.get("condition"),
            success_count=data.get("success_count", 0),
            failure_count=data.get("failure_count", 0),
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
        )
        for child_data in data.get("children", []):
            node.children.append(cls.from_dict(child_data))
        return node


@dataclass
class StrategyTree:
    """Complete strategy tree for XSS scanning"""

    id: str
    name: str
    description: Optional[str] = None
    root: Optional[StrategyNode] = None

    # Metadata
    version: str = "1.0"
    author: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    # Usage stats
    total_uses: int = 0
    total_successes: int = 0

    def __post_init__(self):
        if self.root is None:
            self.root = StrategyNode(
                id="root",
                type=NodeType.ROOT,
                name="Root",
                description="Strategy tree root node",
            )

    @property
    def success_rate(self) -> float:
        """Overall success rate"""
        if self.total_uses == 0:
            return 0.0
        return self.total_successes / self.total_uses

    def find_node(self, node_id: str) -> Optional[StrategyNode]:
        """Find node by ID"""
        if self.root:
            return self.root.find_node(node_id)
        return None

    def get_next_actions(
        self,
        context: dict[str, Any],
        current_node: Optional[StrategyNode] = None,
    ) -> list[StrategyNode]:
        """
        Get next possible actions based on current context.

        Args:
            context: Current scan context (waf_detected, context_type, etc.)
            current_node: Current position in tree (None = start from root)

        Returns:
            List of applicable child nodes sorted by priority
        """
        node = current_node or self.root
        if not node:
            return []

        applicable = []
        for child in node.children:
            if not child.enabled:
                continue

            # Check condition
            if child.condition:
                if not self._evaluate_condition(child.condition, context):
                    continue

            applicable.append(child)

        # Sort by priority (descending) then success rate (descending)
        applicable.sort(key=lambda n: (n.priority, n.success_rate), reverse=True)
        return applicable

    def _evaluate_condition(self, condition: str, context: dict[str, Any]) -> bool:
        """Evaluate a condition string against context"""
        try:
            # Simple condition evaluation
            # Supports: key == value, key != value, key, !key
            condition = condition.strip()

            if "==" in condition:
                key, value = condition.split("==", 1)
                key = key.strip()
                value = value.strip().strip("'\"")
                return str(context.get(key, "")).lower() == value.lower()

            if "!=" in condition:
                key, value = condition.split("!=", 1)
                key = key.strip()
                value = value.strip().strip("'\"")
                return str(context.get(key, "")).lower() != value.lower()

            if condition.startswith("!"):
                key = condition[1:].strip()
                return not context.get(key)

            return bool(context.get(condition))

        except Exception:
            return True  # Default to true on error

    def record_result(self, node_id: str, success: bool):
        """Record success/failure for a node"""
        node = self.find_node(node_id)
        if node:
            if success:
                node.success_count += 1
                self.total_successes += 1
            else:
                node.failure_count += 1
        self.total_uses += 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "root": self.root.to_dict() if self.root else None,
            "version": self.version,
            "author": self.author,
            "tags": self.tags,
            "total_uses": self.total_uses,
            "total_successes": self.total_successes,
            "success_rate": self.success_rate,
        }

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StrategyTree":
        """Create from dictionary"""
        tree = cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            name=data.get("name", "Unknown"),
            description=data.get("description"),
            version=data.get("version", "1.0"),
            author=data.get("author"),
            tags=data.get("tags", []),
            total_uses=data.get("total_uses", 0),
            total_successes=data.get("total_successes", 0),
        )
        if data.get("root"):
            tree.root = StrategyNode.from_dict(data["root"])
        return tree

    @classmethod
    def from_json(cls, json_str: str) -> "StrategyTree":
        """Create from JSON string"""
        return cls.from_dict(json.loads(json_str))


def create_default_strategy() -> StrategyTree:
    """Create the default XSS scanning strategy tree"""
    tree = StrategyTree(
        id="default",
        name="Default XSS Strategy",
        description="Adaptive XSS scanning strategy with context switching and WAF bypass",
        author="BRS-XSS",
        tags=["default", "adaptive", "waf-bypass"],
    )

    root = tree.root
    assert root is not None, "Tree root must be initialized"

    # Level 1: Context detection
    html_ctx = root.add_child(
        StrategyNode(
            id="ctx-html",
            type=NodeType.CONTEXT,
            name="HTML Context",
            description="Payload reflected in HTML body",
            condition="context_type == 'html'",
            priority=10,
        )
    )

    js_ctx = root.add_child(
        StrategyNode(
            id="ctx-js",
            type=NodeType.CONTEXT,
            name="JavaScript Context",
            description="Payload reflected in JavaScript",
            condition="context_type == 'javascript'",
            priority=10,
        )
    )

    attr_ctx = root.add_child(
        StrategyNode(
            id="ctx-attr",
            type=NodeType.CONTEXT,
            name="HTML Attribute Context",
            description="Payload reflected in HTML attribute",
            condition="context_type == 'attribute'",
            priority=10,
        )
    )

    url_ctx = root.add_child(
        StrategyNode(
            id="ctx-url",
            type=NodeType.CONTEXT,
            name="URL Context",
            description="Payload reflected in URL/href",
            condition="context_type == 'url'",
            priority=10,
        )
    )

    # Level 2: WAF detection branch
    for ctx in [html_ctx, js_ctx, attr_ctx, url_ctx]:
        waf_branch = ctx.add_child(
            StrategyNode(
                id=f"{ctx.id}-waf",
                type=NodeType.CONDITION,
                name="WAF Detected?",
                condition="waf_detected",
                priority=5,
            )
        )

        no_waf = ctx.add_child(
            StrategyNode(
                id=f"{ctx.id}-nowaf",
                type=NodeType.CONDITION,
                name="No WAF",
                condition="!waf_detected",
                priority=5,
            )
        )

        # WAF bypass strategies
        waf_branch.add_child(
            StrategyNode(
                id=f"{ctx.id}-waf-encode",
                type=NodeType.ENCODING,
                name="URL Encoding",
                description="Try URL-encoded payloads",
                config={"encoding": "url"},
                priority=8,
            )
        )

        waf_branch.add_child(
            StrategyNode(
                id=f"{ctx.id}-waf-html",
                type=NodeType.ENCODING,
                name="HTML Entity Encoding",
                description="Try HTML entity encoded payloads",
                config={"encoding": "html_entity"},
                priority=7,
            )
        )

        waf_branch.add_child(
            StrategyNode(
                id=f"{ctx.id}-waf-unicode",
                type=NodeType.ENCODING,
                name="Unicode Encoding",
                description="Try Unicode encoded payloads",
                config={"encoding": "unicode"},
                priority=6,
            )
        )

        waf_branch.add_child(
            StrategyNode(
                id=f"{ctx.id}-waf-mutation",
                type=NodeType.MUTATION,
                name="Payload Mutation",
                description="Try mutated payloads",
                config={"mutation": "case_swap"},
                priority=5,
            )
        )

        # No WAF - direct payloads
        no_waf.add_child(
            StrategyNode(
                id=f"{ctx.id}-direct",
                type=NodeType.PAYLOAD,
                name="Direct Payloads",
                description="Try standard payloads",
                config={"payload_type": "standard"},
                priority=10,
            )
        )

    # Add context-specific payloads
    # HTML context
    html_ctx.children[-1].add_child(
        StrategyNode(
            id="html-script",
            type=NodeType.PAYLOAD,
            name="Script Tag",
            config={"payload": "<script>alert(1)</script>"},
            priority=10,
        )
    )

    html_ctx.children[-1].add_child(
        StrategyNode(
            id="html-img",
            type=NodeType.PAYLOAD,
            name="IMG Onerror",
            config={"payload": "<img src=x onerror=alert(1)>"},
            priority=9,
        )
    )

    html_ctx.children[-1].add_child(
        StrategyNode(
            id="html-svg",
            type=NodeType.PAYLOAD,
            name="SVG Onload",
            config={"payload": "<svg onload=alert(1)>"},
            priority=8,
        )
    )

    # JS context
    js_ctx.children[-1].add_child(
        StrategyNode(
            id="js-breakout",
            type=NodeType.PAYLOAD,
            name="String Breakout",
            config={"payload": "';alert(1);//"},
            priority=10,
        )
    )

    js_ctx.children[-1].add_child(
        StrategyNode(
            id="js-template",
            type=NodeType.PAYLOAD,
            name="Template Literal",
            config={"payload": "${alert(1)}"},
            priority=9,
        )
    )

    # Attribute context
    attr_ctx.children[-1].add_child(
        StrategyNode(
            id="attr-event",
            type=NodeType.PAYLOAD,
            name="Event Handler",
            config={"payload": '" onmouseover=alert(1) x="'},
            priority=10,
        )
    )

    attr_ctx.children[-1].add_child(
        StrategyNode(
            id="attr-breakout",
            type=NodeType.PAYLOAD,
            name="Attribute Breakout",
            config={"payload": '"><script>alert(1)</script>'},
            priority=9,
        )
    )

    # URL context
    url_ctx.children[-1].add_child(
        StrategyNode(
            id="url-javascript",
            type=NodeType.PAYLOAD,
            name="JavaScript Protocol",
            config={"payload": "javascript:alert(1)"},
            priority=10,
        )
    )

    url_ctx.children[-1].add_child(
        StrategyNode(
            id="url-data",
            type=NodeType.PAYLOAD,
            name="Data URI",
            config={"payload": "data:text/html,<script>alert(1)</script>"},
            priority=9,
        )
    )

    return tree
