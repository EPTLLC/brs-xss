#!/usr/bin/env python3

"""
BRS-XSS Payload Generator

Main orchestrator for XSS payload generation system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Вс 10 авг 2025 19:31:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Optional, Any

from .payload_types import GeneratedPayload, GenerationConfig, EvasionTechnique
from .context_payloads import ContextPayloadGenerator
from .evasion_techniques import EvasionTechniques
from .waf_evasions import WAFEvasions
from .blind_xss import BlindXSSManager
from ..payloads.payload_manager import PayloadManager
from ..utils.logger import Logger

logger = Logger("core.payload_generator")


class PayloadGenerator:
    """
    Main XSS payload generation orchestrator.
    
    Coordinates multiple specialized generators to create
    context-aware payloads with evasion techniques.
    """
    
    def __init__(self, config: GenerationConfig = None, blind_xss_webhook: str = None):
        """
        Initialize payload generator.
        
        Args:
            config: Generation configuration
            blind_xss_webhook: Webhook URL for blind XSS detection
        """
        self.config = config or GenerationConfig()
        
        # Initialize generators
        self.context_generator = ContextPayloadGenerator()
        self.payload_manager = PayloadManager()
        self.evasion_techniques = EvasionTechniques()
        self.waf_evasions = WAFEvasions()
        self.blind_xss = BlindXSSManager(blind_xss_webhook) if blind_xss_webhook else None
        
        # Statistics
        self.generated_count = 0
        self.generation_stats = {
            'total_generated': 0,
            'by_context': {},
            'by_technique': {},
            'success_rate': 0.0
        }
        
        logger.info("Payload generator initialized")
    
    def generate_payloads(
        self,
        context_info: Dict[str, Any],
        detected_wafs: Optional[List[Any]] = None,
        max_payloads: Optional[int] = None
    ) -> List[GeneratedPayload]:
        """
        Generate context-aware XSS payloads.
        
        Args:
            context_info: Context analysis results
            detected_wafs: Detected WAF information
            max_payloads: Maximum number of payloads (overrides config)
            
        Returns:
            List of generated payloads
        """
        max_count = max_payloads or self.config.max_payloads
        context_type = context_info.get('context_type', 'unknown')
        
        logger.debug(f"Generating max {max_count} payloads for context: {context_type}")
        
        all_payloads = []
        
        # Generate base context payloads from context generator
        base_payloads = self.context_generator.get_context_payloads(
            context_type, context_info
        )
        
        # Add ALL payloads from payload manager (comprehensive coverage)
        comprehensive_payloads = self.payload_manager.get_all_payloads()
        
        # Combine context-specific and comprehensive payloads
        combined_payloads = base_payloads + comprehensive_payloads
        
        # Convert to GeneratedPayload objects (filter empty payloads)
        for i, payload in enumerate(combined_payloads):
            # Skip empty or invalid payloads
            if not payload or not str(payload).strip():
                continue
                
            # Determine if this is a context-specific or comprehensive payload
            is_context_specific = i < len(base_payloads)
            description = "Context-specific payload" if is_context_specific else "Comprehensive payload"
            effectiveness = 0.9 if is_context_specific else 0.7
            
            all_payloads.append(GeneratedPayload(
                payload=str(payload).strip(),
                context_type=context_type,
                evasion_techniques=[],
                effectiveness_score=effectiveness,
                description=description
            ))
        
        # Apply evasion techniques if enabled
        if self.config.include_evasions:
            evasion_payloads = self._apply_evasion_techniques(
                base_payloads, context_info
            )
            all_payloads.extend(evasion_payloads)
        
        # Generate WAF-specific payloads if enabled
        if self.config.include_waf_specific and detected_wafs:
            waf_payloads = self._generate_waf_specific_payloads(
                base_payloads, detected_wafs
            )
            all_payloads.extend(waf_payloads)
        
        # Filter by effectiveness threshold
        filtered_payloads = [
            p for p in all_payloads 
            if p.effectiveness_score >= self.config.effectiveness_threshold
        ]
        
        # Sort by effectiveness and limit count
        sorted_payloads = sorted(
            filtered_payloads,
            key=lambda p: p.effectiveness_score,
            reverse=True
        )[:max_count]
        
        # Update statistics
        self._update_statistics(sorted_payloads, context_type)
        
        logger.info(f"Generated {len(sorted_payloads)} payloads for {context_type}")
        return sorted_payloads
    
    def generate_single_payload(
        self,
        context_info: Dict[str, Any],
        technique: EvasionTechnique = None
    ) -> Optional[GeneratedPayload]:
        """
        Generate a single optimized payload.
        
        Args:
            context_info: Context information
            technique: Specific evasion technique to use
            
        Returns:
            Single best payload or None
        """
        context_type = context_info.get('context_type', 'unknown')
        
        # Get best base payload for context
        base_payloads = self.context_generator.get_context_payloads(
            context_type, context_info
        )
        
        if not base_payloads:
            return None
        
        best_payload = base_payloads[0]  # First is usually most effective
        
        # Apply specific technique if requested
        if technique:
            modified_payloads = self._apply_specific_technique(
                best_payload, technique
            )
            if modified_payloads:
                best_payload = modified_payloads[0]
        
        result = GeneratedPayload(
            payload=best_payload,
            context_type=context_type,
            evasion_techniques=[technique.value] if technique else [],
            effectiveness_score=0.9,
            description="Optimized single payload"
        )
        
        self.generated_count += 1
        logger.debug(f"Generated single payload: {best_payload[:50]}...")
        
        return result
    
    def _apply_evasion_techniques(
        self,
        base_payloads: List[str],
        context_info: Dict[str, Any]
    ) -> List[GeneratedPayload]:
        """Apply various evasion techniques to base payloads"""
        evasion_payloads = []
        
        # Limit base payloads to avoid explosion
        limited_base = base_payloads[:5]
        
        for base_payload in limited_base:
            # Apply each evasion technique
            techniques_map = {
                'case_variation': self.evasion_techniques.apply_case_variations,
                'url_encoding': self.evasion_techniques.apply_url_encoding,
                'html_entity_encoding': self.evasion_techniques.apply_html_entity_encoding,
                'unicode_escaping': self.evasion_techniques.apply_unicode_escaping,
                'comment_insertion': self.evasion_techniques.apply_comment_insertions,
                'whitespace_variation': self.evasion_techniques.apply_whitespace_variations,
                'mixed_encoding': self.evasion_techniques.apply_mixed_encoding
            }
            
            for technique_name, technique_func in techniques_map.items():
                try:
                    variants = technique_func(base_payload)
                    
                    for variant in variants[:3]:  # Limit variants per technique
                        if variant != base_payload:  # Avoid duplicates
                            evasion_payloads.append(GeneratedPayload(
                                payload=variant,
                                context_type=context_info.get('context_type', 'unknown'),
                                evasion_techniques=[technique_name],
                                effectiveness_score=0.7,
                                description=f"Evasion: {technique_name}"
                            ))
                
                except Exception as e:
                    logger.warning(f"Failed to apply {technique_name}: {e}")
                    continue
        
        logger.debug(f"Generated {len(evasion_payloads)} evasion payloads")
        return evasion_payloads
    
    def _generate_waf_specific_payloads(
        self,
        base_payloads: List[str],
        detected_wafs: List[Any]
    ) -> List[GeneratedPayload]:
        """Generate WAF-specific evasion payloads"""
        waf_payloads = []
        
        # Use first few base payloads to avoid explosion
        for base_payload in base_payloads[:3]:
            waf_specific = self.waf_evasions.generate_waf_specific_payloads(
                base_payload, detected_wafs
            )
            waf_payloads.extend(waf_specific)
        
        logger.debug(f"Generated {len(waf_payloads)} WAF-specific payloads")
        return waf_payloads
    
    def _apply_specific_technique(
        self,
        payload: str,
        technique: EvasionTechnique
    ) -> List[str]:
        """Apply a specific evasion technique"""
        technique_map = {
            EvasionTechnique.CASE_VARIATION: self.evasion_techniques.apply_case_variations,
            EvasionTechnique.URL_ENCODING: self.evasion_techniques.apply_url_encoding,
            EvasionTechnique.HTML_ENTITY_ENCODING: self.evasion_techniques.apply_html_entity_encoding,
            EvasionTechnique.UNICODE_ESCAPING: self.evasion_techniques.apply_unicode_escaping,
            EvasionTechnique.COMMENT_INSERTION: self.evasion_techniques.apply_comment_insertions,
            EvasionTechnique.WHITESPACE_VARIATION: self.evasion_techniques.apply_whitespace_variations,
            EvasionTechnique.MIXED_ENCODING: self.evasion_techniques.apply_mixed_encoding
        }
        
        technique_func = technique_map.get(technique)
        if technique_func:
            return technique_func(payload)
        
        return [payload]
    
    def _update_statistics(self, payloads: List[GeneratedPayload], context_type: str):
        """Update generation statistics"""
        self.generated_count += len(payloads)
        self.generation_stats['total_generated'] = self.generated_count
        
        # Update context statistics
        if context_type not in self.generation_stats['by_context']:
            self.generation_stats['by_context'][context_type] = 0
        self.generation_stats['by_context'][context_type] += len(payloads)
        
        # Update technique statistics
        for payload in payloads:
            for technique in payload.evasion_techniques:
                if technique not in self.generation_stats['by_technique']:
                    self.generation_stats['by_technique'][technique] = 0
                self.generation_stats['by_technique'][technique] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics"""
        return self.generation_stats.copy()
    
    def reset_statistics(self):
        """Reset generation statistics"""
        self.generated_count = 0
        self.generation_stats = {
            'total_generated': 0,
            'by_context': {},
            'by_technique': {},
            'success_rate': 0.0
        }
        logger.info("Generation statistics reset")
    
    def update_config(self, config: GenerationConfig):
        """Update generation configuration"""
        self.config = config
        logger.info(f"Generation config updated: max_payloads={config.max_payloads}")
    
    def bulk_generate_payloads(
        self,
        contexts: List[Dict[str, Any]],
        detected_wafs: Optional[List[Any]] = None
    ) -> Dict[str, List[GeneratedPayload]]:
        """
        Generate payloads for multiple contexts efficiently.
        
        Args:
            contexts: List of context information dicts
            detected_wafs: Detected WAF information
            
        Returns:
            Dictionary mapping context types to payload lists
        """
        results = {}
        
        logger.info(f"Bulk generating payloads for {len(contexts)} contexts")
        
        for i, context_info in enumerate(contexts):
            context_type = context_info.get('context_type', f'context_{i}')
            
            try:
                payloads = self.generate_payloads(
                    context_info=context_info,
                    detected_wafs=detected_wafs,
                    max_payloads=self.config.max_payloads // len(contexts)
                )
                results[context_type] = payloads
                
            except Exception as e:
                logger.error(f"Error generating payloads for context {context_type}: {e}")
                results[context_type] = []
        
        logger.info(f"Bulk generation completed: {len(results)} context types")
        return results