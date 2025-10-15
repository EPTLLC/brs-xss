#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 11:05:10 AM UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from dataclasses import dataclass, field
from typing import Dict

@dataclass
class DiscoveredParameter:
    """Represents a discovered entry point for testing (URL or Form)."""
    url: str
    method: str  # GET or POST
    params: Dict[str, str] = field(default_factory=dict)

    def __hash__(self):
        # Allow adding to sets for deduplication
        return hash((self.url, self.method, tuple(sorted(self.params.keys()))))

    def __eq__(self, other):
        if not isinstance(other, DiscoveredParameter):
            return NotImplemented
        return self.__hash__() == other.__hash__()
