#!/usr/bin/env python3

"""
BRS-XSS Prediction Cache

Caching system for ML predictions to improve performance.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import time
from typing import Dict, Optional, Any

from .prediction_types import PredictionResult


class PredictionCache:
    """Prediction cache for acceleration"""
    
    def __init__(self, max_size: int = 1000):
        """
        Initialize cache.
        
        Args:
            max_size: Maximum cache size
        """
        self.cache: Dict[str, PredictionResult] = {}
        self.max_size = max_size
        self.access_times: Dict[str, float] = {}
    
    def get(self, key: str) -> Optional[PredictionResult]:
        """Get from cache"""
        if key in self.cache:
            self.access_times[key] = time.time()
            return self.cache[key]
        return None
    
    def put(self, key: str, result: PredictionResult):
        """Add to cache"""
        # Clear cache if it's full
        if len(self.cache) >= self.max_size:
            self._evict_oldest()
        
        self.cache[key] = result
        self.access_times[key] = time.time()
    
    def _evict_oldest(self):
        """Remove oldest entries"""
        # Remove 20% of oldest entries
        to_remove = int(self.max_size * 0.2)
        
        sorted_items = sorted(self.access_times.items(), key=lambda x: x[1])
        
        for key, _ in sorted_items[:to_remove]:
            self.cache.pop(key, None)
            self.access_times.pop(key, None)
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
        self.access_times.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Cache statistics"""
        return {
            'cache_size': len(self.cache),
            'max_size': self.max_size,
            'hit_ratio': 0.0,  # Need to add counters for accurate statistics
        }