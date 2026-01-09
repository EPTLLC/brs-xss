#!/usr/bin/env python3

"""
Project: BRS-XSS Benchmark Suite
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 13:00:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Benchmark suite for BRS-XSS scanner performance and accuracy testing.
Produces JSON artifacts for version comparison.
"""

from .runner import BenchmarkRunner
from .models import BenchmarkResult, BenchmarkHistory, VersionComparison
from .targets import DVWATarget, WebGoatTarget, XSSGameTarget

__all__ = [
    "BenchmarkRunner",
    "BenchmarkResult",
    "BenchmarkHistory",
    "VersionComparison",
    "DVWATarget",
    "WebGoatTarget",
    "XSSGameTarget",
]
