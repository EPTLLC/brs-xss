#!/usr/bin/env python3

"""
Project: BRS-XSS Scanner
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: New - PTT Strategy Module
Telegram: https://t.me/EasyProTech

Pentesting Task Trees (PTT) - Adaptive scanning strategy.

This module implements decision trees for intelligent payload selection
and context switching during XSS scanning.
"""

from .tree import StrategyTree, StrategyNode, NodeType, create_default_strategy
from .rules import (
    SwitchRule,
    ContextSwitchRule,
    WAFBypassRule,
    EncodingRule,
    MutationRule,
)
from .engine import StrategyEngine

__all__ = [
    "StrategyTree",
    "StrategyNode",
    "NodeType",
    "create_default_strategy",
    "SwitchRule",
    "ContextSwitchRule",
    "WAFBypassRule",
    "EncodingRule",
    "MutationRule",
    "StrategyEngine",
]
