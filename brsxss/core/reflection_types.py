#!/usr/bin/env python3

"""
BRS-XSS Reflection Types

Data types for reflection detection system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Wed 15 Oct 2025 01:50:12 MSK - Fixed MyPy type errors
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from dataclasses import dataclass, field
from enum import Enum


class ReflectionType(Enum):
    """Types of input reflection"""
    EXACT = "exact"                 # Exact reflection
    PARTIAL = "partial"             # Partial reflection
    ENCODED = "encoded"             # Encoded reflection
    FILTERED = "filtered"           # Filtered reflection
    OBFUSCATED = "obfuscated"       # Obfuscated reflection
    MODIFIED = "modified"           # Modified reflection
    NOT_REFLECTED = "not_reflected" # No reflection found


class ReflectionContext(Enum):
    """Context where reflection occurs"""
    HTML_CONTENT = "html_content"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    CSS_STYLE = "css_style"
    HTML_COMMENT = "html_comment"
    URL_PARAMETER = "url_parameter"
    UNKNOWN = "unknown"


@dataclass
class ReflectionPoint:
    """Single reflection point"""
    position: int                    # Position in response
    reflected_value: str             # What was reflected
    original_value: str              # Original input value
    reflection_type: ReflectionType  # Type of reflection
    context: ReflectionContext       # Context of reflection
    
    # Quality metrics
    completeness: float = 1.0        # How complete the reflection is (0-1)
    accuracy: float = 1.0            # How accurate the reflection is (0-1)
    characters_preserved: float = 1.0 # Percentage of characters preserved
    
    # Context details
    surrounding_content: str = ""     # Content around reflection
    tag_name: str = ""               # HTML tag if applicable
    attribute_name: str = ""         # Attribute name if applicable
    
    # Analysis
    special_chars_preserved: List[str] = field(default_factory=list)
    encoding_applied: str = "none"
    filters_detected: List[str] = field(default_factory=list)


@dataclass
class ReflectionResult:
    """Complete reflection analysis result"""
    input_value: str                 # Original input
    total_reflections: int = 0       # Total reflection count
    reflection_points: List[ReflectionPoint] = field(default_factory=list)
    
    # Overall quality
    overall_reflection_type: ReflectionType = ReflectionType.NOT_REFLECTED
    overall_quality_score: float = 0.0  # Overall quality (0-1)
    
    # Statistics
    contexts_found: List[ReflectionContext] = field(default_factory=list)
    reflection_types_found: List[ReflectionType] = field(default_factory=list)
    
    # Analysis summary
    is_exploitable: bool = False
    exploitation_confidence: float = 0.0
    recommended_payloads: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        
        # Update computed fields
        self.total_reflections = len(self.reflection_points)
        
        if self.reflection_points:
            # Determine overall reflection type
            self.overall_reflection_type = self._determine_overall_type()
            
            # Calculate overall quality
            self.overall_quality_score = self._calculate_overall_quality()
            
            # Update statistics
            self.contexts_found = list(set(rp.context for rp in self.reflection_points))
            self.reflection_types_found = list(set(rp.reflection_type for rp in self.reflection_points))
    
    def _determine_overall_type(self) -> ReflectionType:
        """Determine overall reflection type from individual points"""
        if not self.reflection_points:
            return ReflectionType.NOT_REFLECTED
        
        # Priority order for determining overall type
        priority_order = [
            ReflectionType.EXACT,
            ReflectionType.PARTIAL,
            ReflectionType.MODIFIED,
            ReflectionType.OBFUSCATED,
            ReflectionType.ENCODED,
            ReflectionType.FILTERED
        ]
        
        for reflection_type in priority_order:
            if any(rp.reflection_type == reflection_type for rp in self.reflection_points):
                return reflection_type
        
        return ReflectionType.NOT_REFLECTED
    
    def _calculate_overall_quality(self) -> float:
        """Calculate overall quality score"""
        if not self.reflection_points:
            return 0.0
        
        # Weight different metrics
        total_score = 0.0
        total_weight = 0.0
        
        for rp in self.reflection_points:
            # Base score from reflection type
            type_scores = {
                ReflectionType.EXACT: 1.0,
                ReflectionType.PARTIAL: 0.8,
                ReflectionType.MODIFIED: 0.7,
                ReflectionType.OBFUSCATED: 0.6,
                ReflectionType.ENCODED: 0.5,
                ReflectionType.FILTERED: 0.3,
                ReflectionType.NOT_REFLECTED: 0.0
            }
            
            base_score = type_scores.get(rp.reflection_type, 0.0)
            
            # Adjust by quality metrics
            quality_score = (
                base_score * 0.4 +
                rp.completeness * 0.3 +
                rp.accuracy * 0.2 +
                rp.characters_preserved * 0.1
            )
            
            # Weight by context importance
            context_weights = {
                ReflectionContext.HTML_CONTENT: 1.0,
                ReflectionContext.JAVASCRIPT: 1.0,
                ReflectionContext.HTML_ATTRIBUTE: 0.8,
                ReflectionContext.CSS_STYLE: 0.6,
                ReflectionContext.HTML_COMMENT: 0.3,
                ReflectionContext.URL_PARAMETER: 0.7,
                ReflectionContext.UNKNOWN: 0.5
            }
            
            weight = context_weights.get(rp.context, 0.5)
            
            total_score += quality_score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0


@dataclass 
class ReflectionConfig:
    """Configuration for reflection detection"""
    max_search_length: int = 10000   # Max response length to search
    similarity_threshold: float = 0.6 # Lowered from 0.8 for better partial detection
    min_reflection_length: int = 2    # Lowered from 3 to catch shorter reflections
    case_sensitive: bool = False      # Case sensitive comparison
    context_window: int = 50          # Characters around reflection to analyze context
    
    # Analysis options
    analyze_encoding: bool = True     # Analyze encoding applied
    analyze_context: bool = True      # Analyze reflection context
    extract_surrounding: bool = True  # Extract surrounding content
    
    # Performance options
    max_reflections_per_input: int = 100  # Max reflections to find per input
    
    def __post_init__(self):
        """Validate configuration"""
        if self.similarity_threshold < 0.0 or self.similarity_threshold > 1.0:
            raise ValueError("similarity_threshold must be between 0.0 and 1.0")
        
        if self.min_reflection_length < 1:
            raise ValueError("min_reflection_length must be at least 1")