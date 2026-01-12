#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Payload Statistics - Tracks payload generation metrics.
"""

from typing import Any
from collections import Counter


class PayloadStatistics:
    """Tracks payload generation statistics"""

    def __init__(self):
        self.generated_count = 0
        self.context_counts: Counter = Counter()
        self.pool_sizes: list[int] = []
        self.final_sizes: list[int] = []

    def update(self, payloads: list, context_type: str, pool_size: int):
        """
        Update statistics after payload generation.

        Args:
            payloads: list of generated payloads
            context_type: Context type for these payloads
            pool_size: Size of initial payload pool
        """
        self.generated_count += len(payloads)
        self.context_counts[context_type] += len(payloads)
        self.pool_sizes.append(pool_size)
        self.final_sizes.append(len(payloads))

    def get_stats(self) -> dict[str, Any]:
        """Get current statistics"""
        return {
            "generated_count": self.generated_count,
            "context_distribution": dict(self.context_counts),
            "avg_pool_size": sum(self.pool_sizes) / max(len(self.pool_sizes), 1),
            "avg_final_size": sum(self.final_sizes) / max(len(self.final_sizes), 1),
            "generations": len(self.pool_sizes),
        }

    def reset(self):
        """Reset all statistics"""
        self.generated_count = 0
        self.context_counts.clear()
        self.pool_sizes.clear()
        self.final_sizes.clear()
