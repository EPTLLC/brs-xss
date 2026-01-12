#!/usr/bin/env python3

"""
Project: BRS-XSS Scanner
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: New - Strategy Engine Implementation
Telegram: https://t.me/EasyProTech

Strategy engine for executing PTT decision trees.
"""

from dataclasses import dataclass, field
from typing import Optional, Any, Generator

from .tree import StrategyTree, StrategyNode, NodeType, create_default_strategy
from .rules import SwitchRule, get_default_rules


@dataclass
class StrategyContext:
    """Current context for strategy execution"""

    # Target info
    url: str = ""
    parameter: str = ""

    # Detection results
    context_type: str = "html"  # html, javascript, attribute, url, css
    waf_detected: bool = False
    waf_name: Optional[str] = None

    # Current state
    current_payload: str = ""
    current_node_id: Optional[str] = None

    # Tracking
    consecutive_failures: int = 0
    total_attempts: int = 0
    successful_payloads: list[str] = field(default_factory=list)
    failed_payloads: list[str] = field(default_factory=list)

    # Flags
    payload_blocked: bool = False
    payload_filtered: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for rule evaluation"""
        return {
            "url": self.url,
            "parameter": self.parameter,
            "context_type": self.context_type,
            "waf_detected": self.waf_detected,
            "waf_name": self.waf_name,
            "current_payload": self.current_payload,
            "current_node_id": self.current_node_id,
            "consecutive_failures": self.consecutive_failures,
            "total_attempts": self.total_attempts,
            "payload_blocked": self.payload_blocked,
            "payload_filtered": self.payload_filtered,
        }

    def record_success(self, payload: str):
        """Record successful payload"""
        self.successful_payloads.append(payload)
        self.consecutive_failures = 0
        self.total_attempts += 1

    def record_failure(self, payload: str):
        """Record failed payload"""
        self.failed_payloads.append(payload)
        self.consecutive_failures += 1
        self.total_attempts += 1


@dataclass
class StrategyAction:
    """Action to be executed by the scanner"""

    action_type: str  # test_payload, switch_context, encode, mutate, skip
    payload: Optional[str] = None
    encoding: Optional[str] = None
    context: Optional[str] = None
    node_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class StrategyEngine:
    """
    Engine for executing PTT strategy trees.

    Coordinates between the strategy tree, switching rules,
    and the scanner to provide adaptive payload selection.
    """

    def __init__(
        self,
        tree: Optional[StrategyTree] = None,
        rules: Optional[list[SwitchRule]] = None,
    ):
        self.tree = tree or create_default_strategy()
        self.rules = rules or get_default_rules()
        self.context = StrategyContext()

        # Execution state
        self._current_node: Optional[StrategyNode] = None
        self._visited_nodes: set[str] = set()
        self._action_history: list[StrategyAction] = []

        # Limits
        self.max_attempts_per_context = 10
        self.max_total_attempts = 100

    def initialize(
        self,
        url: str,
        parameter: str,
        context_type: str = "html",
        waf_detected: bool = False,
        waf_name: Optional[str] = None,
    ):
        """Initialize strategy for a new target"""
        self.context = StrategyContext(
            url=url,
            parameter=parameter,
            context_type=context_type,
            waf_detected=waf_detected,
            waf_name=waf_name,
        )
        self._current_node = self.tree.root
        self._visited_nodes.clear()
        self._action_history.clear()

    def get_next_action(self) -> Optional[StrategyAction]:
        """
        Get the next action to execute.

        Returns None when strategy is exhausted.
        """
        if self.context.total_attempts >= self.max_total_attempts:
            return None

        # Check switching rules first
        rule_action = self._check_rules()
        if rule_action:
            self._action_history.append(rule_action)
            return rule_action

        # Get next node from tree
        node_action = self._get_next_node_action()
        if node_action:
            self._action_history.append(node_action)
            return node_action

        return None

    def generate_actions(self) -> Generator[StrategyAction, None, None]:
        """Generator that yields actions until strategy is exhausted"""
        while True:
            action = self.get_next_action()
            if action is None:
                break
            yield action

    def record_result(self, action: StrategyAction, success: bool):
        """Record the result of an action"""
        if success:
            self.context.record_success(action.payload or "")
            if action.node_id:
                self.tree.record_result(action.node_id, True)
        else:
            self.context.record_failure(action.payload or "")
            if action.node_id:
                self.tree.record_result(action.node_id, False)

    def _check_rules(self) -> Optional[StrategyAction]:
        """Check if any switching rules should trigger"""
        ctx_dict = self.context.to_dict()

        # Sort rules by priority
        sorted_rules = sorted(
            [r for r in self.rules if r.enabled],
            key=lambda r: r.priority,
            reverse=True,
        )

        for rule in sorted_rules:
            if rule.evaluate(ctx_dict):
                result = rule.apply(ctx_dict)

                if result.get("action") == "switch_context":
                    self.context.context_type = result.get(
                        "to", self.context.context_type
                    )
                    self.context.consecutive_failures = 0
                    return StrategyAction(
                        action_type="switch_context",
                        context=result.get("to"),
                        metadata=result,
                    )

                elif result.get("action") == "encode":
                    return StrategyAction(
                        action_type="encode",
                        payload=self.context.current_payload,
                        encoding=result.get("encoding"),
                        metadata=result,
                    )

                elif result.get("action") == "mutate":
                    return StrategyAction(
                        action_type="test_payload",
                        payload=result.get("mutated"),
                        metadata=result,
                    )

                elif result.get("action") == "waf_bypass":
                    return StrategyAction(
                        action_type="waf_bypass",
                        metadata=result,
                    )

        return None

    def _get_next_node_action(self) -> Optional[StrategyAction]:
        """Get next action from strategy tree"""
        if not self._current_node:
            return None

        # Get applicable children
        ctx_dict = self.context.to_dict()
        children = self.tree.get_next_actions(ctx_dict, self._current_node)

        # Filter out visited nodes (unless we've reset)
        unvisited = [c for c in children if c.id not in self._visited_nodes]

        if not unvisited:
            # Try to backtrack
            if self._current_node.type != NodeType.ROOT:
                # Move up (simplified - in real impl would track parent)
                self._current_node = self.tree.root
                self._visited_nodes.clear()
                return self._get_next_node_action()
            return None

        # Select best node
        node = unvisited[0]
        self._visited_nodes.add(node.id)
        self._current_node = node
        self.context.current_node_id = node.id

        # Generate action based on node type
        if node.type == NodeType.PAYLOAD:
            payload = node.config.get("payload", "")
            self.context.current_payload = payload
            return StrategyAction(
                action_type="test_payload",
                payload=payload,
                node_id=node.id,
                metadata={"node_name": node.name},
            )

        elif node.type == NodeType.ENCODING:
            encoding = node.config.get("encoding", "url")
            return StrategyAction(
                action_type="encode",
                encoding=encoding,
                node_id=node.id,
                metadata={"node_name": node.name},
            )

        elif node.type == NodeType.MUTATION:
            mutation = node.config.get("mutation", "case_swap")
            return StrategyAction(
                action_type="mutate",
                node_id=node.id,
                metadata={"mutation": mutation, "node_name": node.name},
            )

        elif node.type == NodeType.WAF_BYPASS:
            return StrategyAction(
                action_type="waf_bypass",
                node_id=node.id,
                metadata=node.config,
            )

        elif node.type in [NodeType.CONTEXT, NodeType.CONDITION]:
            # These are branching nodes, recurse
            return self._get_next_node_action()

        return None

    def get_statistics(self) -> dict[str, Any]:
        """Get strategy execution statistics"""
        return {
            "total_attempts": self.context.total_attempts,
            "successful_payloads": len(self.context.successful_payloads),
            "failed_payloads": len(self.context.failed_payloads),
            "success_rate": (
                len(self.context.successful_payloads)
                / max(1, self.context.total_attempts)
            ),
            "current_context": self.context.context_type,
            "waf_detected": self.context.waf_detected,
            "actions_taken": len(self._action_history),
            "tree_success_rate": self.tree.success_rate,
        }

    def export_tree(self) -> dict[str, Any]:
        """Export the strategy tree with updated statistics"""
        return self.tree.to_dict()

    def import_tree(self, tree_data: dict[str, Any]):
        """Import a strategy tree"""
        self.tree = StrategyTree.from_dict(tree_data)
        self._current_node = self.tree.root
