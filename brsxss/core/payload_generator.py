#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:12:02 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Optional, Any, Mapping, Set
from collections import Counter
from itertools import islice
from functools import lru_cache
import hashlib
import random

from .payload_types import GeneratedPayload, GenerationConfig, EvasionTechnique
from .context_payloads import ContextPayloadGenerator
from .evasion_techniques import EvasionTechniques
from .waf_evasions import WAFEvasions
from .blind_xss import BlindXSSManager
from ..payloads.payload_manager import PayloadManager
from ..payloads.context_matrix import ContextMatrix, Context
from ..utils.logger import Logger

# Type alias for WAF detection results
DetectedWAF = Any

logger = Logger("core.payload_generator")

# Clean module exports
__all__ = ["PayloadGenerator", "DetectedWAF"]


class PayloadGenerator:
    """
    Main XSS payload generation orchestrator.
    
    Coordinates multiple specialized generators to create
    context-aware payloads with evasion techniques.
    """
    
    def __init__(self, config: Optional[GenerationConfig] = None, blind_xss_webhook: Optional[str] = None):
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
        self.context_matrix = ContextMatrix()  # New context-aware payload system
        self.evasion_techniques = EvasionTechniques()
        self.waf_evasions = WAFEvasions()
        # Blind XSS manager: if webhook provided explicitly, prefer it and allow generation
        self._explicit_webhook = bool(blind_xss_webhook)
        self.blind_xss = BlindXSSManager(blind_xss_webhook) if blind_xss_webhook else None
        
        # Statistics with Counter for better performance
        self.generated_count = 0
        self.generation_stats = {
            "total_generated": 0,
            "by_context": Counter(),
            "by_technique": Counter(),
            "by_source": Counter(),
            "success_rate": 0.0,
        }
        
        # Deterministic random generator (for future use in tie-breaking)
        self._rand = random.Random(getattr(self.config, "seed", 1337))
        
        # Warning state for safe mode
        self._warned_blind = False
        
        # Validate configuration on initialization
        self._validate_config()
        
        logger.info("Payload generator initialized")
    
    def _validate_config(self):
        """Validate configuration parameters"""
        fields = [
            ("max_payloads", 1, 100000),
            ("effectiveness_threshold", 0.0, 1.0),
            ("max_manager_payloads", 0, 200000),
            ("max_evasion_bases", 0, 1000),
            ("evasion_variants_per_tech", 0, 50),
            ("waf_bases", 0, 100),
        ]
        
        for name, lo, hi in fields:
            val = getattr(self.config, name, None)
            if val is None or not (lo <= val <= hi):
                raise ValueError(f"Invalid config: {name}={val}, expected range [{lo}, {hi}]")
        
        # Validate pool_cap if present
        pool_cap = getattr(self.config, "pool_cap", 10000)
        if not (100 <= pool_cap <= 200000):
            raise ValueError(f"Invalid config: pool_cap={pool_cap}, expected range [100, 200000]")
    
    def _norm_key(self, s: str) -> str:
        """Normalize payload for deduplication with optional hashing"""
        # Remove whitespace, comments, convert to lowercase
        cleaned = " ".join(s.split()).lower()
        # Use hash for crypto-resistant deduplication if enabled
        use_hash = getattr(self.config, "norm_hash", False)
        return hashlib.sha256(cleaned.encode()).hexdigest() if use_hash else cleaned
    
    @lru_cache(maxsize=65536)
    def _norm_key_cached(self, s: str) -> str:
        """Cached version of _norm_key for better performance on large pools"""
        return self._norm_key(s)
    
    def _safe_list(self, xs):
        """Convert to safe list, protecting against generators/None"""
        return xs if isinstance(xs, list) else list(xs or [])
    
    def _get_weights(self):
        """Get weights with universal compatibility for dict/object"""
        defaults = {
            "context_specific": 0.92,
            "context_matrix": 0.90, 
            "comprehensive": 0.70,
            "evasion": 0.75
        }
        w = getattr(self.config, "weights", None)
        if w is None:
            return defaults
        if isinstance(w, dict):
            return {k: float(w.get(k, v)) for k, v in defaults.items()}
        return {k: float(getattr(w, k, v)) for k, v in defaults.items()}
    
    def _wrap(self, ctx: str, payload: Any, tag: str, eff: float) -> GeneratedPayload:
        """Wrap payload in GeneratedPayload object with length protection"""
        payload_str = str(payload).strip() if payload is not None else ""
        max_len = getattr(self.config, "payload_max_len", 4096)
        if len(payload_str) > max_len:
            payload_str = payload_str[:max_len]
        return GeneratedPayload(
            payload=payload_str,
            context_type=ctx,
            evasion_techniques=[],
            effectiveness_score=eff,
            description=tag
        )
    
    def generate_payloads(
        self,
        context_info: Mapping[str, Any],
        detected_wafs: Optional[List[DetectedWAF]] = None,
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
        max_count = max(1, min(max_count, getattr(self.config, "pool_cap", 10000)))
        context_type = context_info.get('context_type', 'unknown')
        
        # Configuration limits with safe defaults
        manager_cap = getattr(self.config, "max_manager_payloads", 2000)
        evasion_bases = getattr(self.config, "max_evasion_bases", 10)
        evasion_variants = getattr(self.config, "evasion_variants_per_tech", 2)
        waf_bases = getattr(self.config, "waf_bases", 3)
        
        # Quiet logging for large pools
        pool_cap = getattr(self.config, "pool_cap", 10000)
        logger.debug(f"Generating max {max_count} for context={context_type} "
                    f"(manager={manager_cap}, evasion_bases={evasion_bases}, pool_cap={pool_cap})")
        
        # Build payload pool without excessive memory allocation
        pool: List[GeneratedPayload] = []
        
        # Get configurable weights for payload sources
        weights = self._get_weights()
        w_ctx = weights["context_specific"]
        w_mat = weights["context_matrix"]
        w_all = weights["comprehensive"]
        
        # 1. Base context payloads from context generator with error handling
        try:
            base_payloads = self.context_generator.get_context_payloads(context_type, dict(context_info))
        except Exception as e:
            logger.error(f"context_generator failed: {e}")
            base_payloads = []
        
        pool.extend([self._wrap(context_type, p, "Context-specific", w_ctx) 
                    for p in base_payloads if str(p).strip()])
        
        # 2. Context Matrix payloads - always include polyglots; context-specific if recognized
        matrix_payloads = []
        context_mapping = {
            'html_content': Context.HTML,
            'html_attribute': Context.ATTRIBUTE, 
            'javascript': Context.JAVASCRIPT,
            'css': Context.CSS,
            'uri': Context.URI,
            'svg': Context.SVG
        }
        if context_type in context_mapping:
            matrix_context = context_mapping.get(context_type, Context.HTML)
            matrix_payloads = list(self.context_matrix.get_context_payloads(matrix_context))
            if getattr(self.config, 'enable_aggressive', False):
                matrix_payloads.extend(self.context_matrix.get_aggr_payloads())
        # Polyglots are useful in any context, include them always
        matrix_payloads.extend(self.context_matrix.get_polyglot_payloads())
        
        pool.extend([self._wrap(context_type, p, "Context-matrix", w_mat) 
                    for p in matrix_payloads if str(p).strip()])
        
        # 3. payloads with cap to avoid memory issues
        comprehensive_payloads = islice(self.payload_manager.get_all_payloads(), manager_cap)
        pool.extend([self._wrap(context_type, p, "Comprehensive", w_all) 
                    for p in comprehensive_payloads if str(p).strip()])
        
        # Hard cap pool size to prevent memory issues
        pool_cap = getattr(self.config, "pool_cap", 10000)
        if len(pool) > pool_cap:
            # Keep proportions: take top by priority (already sorted by effectiveness)
            pool = pool[:pool_cap]
        
        # 4. Sдержанный evasion - только на лучших базовых пейлоадах
        if self.config.include_evasions and pool:
            base_for_evasion = [p.payload for p in pool[:min(evasion_bases, len(pool))]]
            evasion_payloads = self._apply_evasion_techniques(
                base_for_evasion, dict(context_info), limit_per_tech=evasion_variants
            )
            pool.extend(evasion_payloads)
        
        # 5. WAF-specific payloads - только на топ базовых
        if self.config.include_waf_specific and detected_wafs:
            base_for_waf = [p.payload for p in pool[:min(waf_bases, len(pool))]]
            waf_payloads = self._generate_waf_specific_payloads(base_for_waf, detected_wafs)
            pool.extend(waf_payloads)

        # 5.1 Blind XSS payloads (insert into pool so they participate in filtering/sorting)
        explicit_webhook = self._explicit_webhook
        safe_mode = getattr(self.config, "safe_mode", True)
        if safe_mode and self.config.include_blind_xss and not explicit_webhook and not self._warned_blind:
            logger.warning("include_blind_xss ignored due to safe_mode")
            self._warned_blind = True
        elif self.blind_xss and ((not safe_mode and self.config.include_blind_xss) or explicit_webhook):
            ct = context_type
            if ct == "html_content":
                bctx = "html"
            elif ct == "html_attribute":
                bctx = "attribute"
            elif ct in ("javascript", "js_string"):
                bctx = "javascript"
            elif ct in ("css", "css_style"):
                bctx = "css"
            else:
                bctx = "html"
            # Support both legacy generate_payloads(ctx, info) and new generate_blind_payloads(ctx)
            if hasattr(self.blind_xss, "generate_payloads"):
                blind_payloads = self.blind_xss.generate_payloads(bctx, context_info)
            else:
                blind_payloads = self.blind_xss.generate_blind_payloads(bctx)
            blind_limit = getattr(self.config, "blind_batch_limit", 10)
            for s in blind_payloads[:blind_limit]:
                if isinstance(s, GeneratedPayload):
                    pool.append(s)
                else:
                    pool.append(self._wrap(context_type, s, "BlindXSS", 0.95))
        
        # 6. Early filtering, deduplication, and sorting
        thr = getattr(self.config, 'effectiveness_threshold', 0.65)
        seen: Set[str] = set()
        filtered: List[GeneratedPayload] = []
        
        for p in pool:
            if p.effectiveness_score < thr:
                continue
            key = self._norm_key_cached(p.payload)
            if key in seen:
                continue
            seen.add(key)
            filtered.append(p)
        
        # Stable sort: by score desc, then by payload for determinism
        sorted_payloads = sorted(
            filtered,
            key=lambda x: (-x.effectiveness_score, x.payload)
        )[:max_count]
        
        # (Blind XSS were already inserted into the pool above)
        
        # Final deduplication after blind XSS to prevent duplicates
        seen_final: Set[str] = set()
        final: List[GeneratedPayload] = []
        for p in sorted_payloads:
            k = self._norm_key_cached(p.payload)
            if k in seen_final:
                continue
            seen_final.add(k)
            final.append(p)
        sorted_payloads = final[:max_count]
        
        # Update statistics with Counter
        self._update_statistics(sorted_payloads, context_type, len(pool))
        
        logger.info(f"Generated {len(sorted_payloads)} payloads for context={context_type}")
        logger.debug(f"candidates={len(pool)} filtered={len(filtered)} final={len(sorted_payloads)}")
        
        return sorted_payloads
    
    def generate_single_payload(
        self,
        context_info: Dict[str, Any],
        technique: Optional[EvasionTechnique] = None
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
        context_info: Mapping[str, Any],
        limit_per_tech: int = 2
    ) -> List[GeneratedPayload]:
        """Apply various evasion techniques to base payloads"""
        evasion_payloads = []
        
        # Limit base payloads to avoid explosion
        limited_base = base_payloads[:5]
        
        for base_payload in limited_base:
            # Skip empty or overly long payloads for safety
            if not base_payload or len(base_payload) > 4096:
                continue
                
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
                    
                    for variant in variants[:limit_per_tech]:  # Use configurable limit
                        if variant != base_payload:  # Avoid duplicates
                            evasion_payloads.append(GeneratedPayload(
                                payload=variant,
                                context_type=context_info.get('context_type', 'unknown'),
                                evasion_techniques=[technique_name],
                                effectiveness_score=0.75,
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
        detected_wafs: List[DetectedWAF]
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
    
    def _update_statistics(self, payloads: List[GeneratedPayload], context_type: str, 
                          total_candidates: Optional[int] = None):
        """Update generation statistics with real success rate calculation"""
        self.generated_count += len(payloads)
        self.generation_stats["total_generated"] = self.generated_count
        self.generation_stats["by_context"][context_type] += len(payloads)  # type: ignore[index]
        
        # Update technique and source statistics with Counter
        for payload in payloads:
            for t in payload.evasion_techniques:
                self.generation_stats["by_technique"][t] += 1  # type: ignore[index]
            self.generation_stats["by_source"][payload.description] += 1  # type: ignore[index]
        
        # Calculate real success rate: payloads that passed threshold vs total candidates
        prev_rate = self.generation_stats["success_rate"]
        if total_candidates and total_candidates > 0:
            batch_rate = len(payloads) / float(total_candidates)
        else:
            batch_rate = 1.0  # Fallback when no candidate count available
        self.generation_stats["success_rate"] = (0.9 * prev_rate) + (0.1 * batch_rate)  # type: ignore[operator]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics"""
        return self.generation_stats.copy()
    
    def reset_statistics(self):
        """Reset generation statistics with proper Counter types"""
        self.generated_count = 0
        self.generation_stats = {
            "total_generated": 0,
            "by_context": Counter(),
            "by_technique": Counter(),
            "by_source": Counter(),
            "success_rate": 0.0,
        }
        logger.info("Generation statistics reset")
    
    def update_config(self, config: GenerationConfig):
        """Update generation configuration with validation"""
        old_config = self.config
        self.config = config
        try:
            self._validate_config()
            logger.info(f"Generation config updated: max_payloads={config.max_payloads}")
        except ValueError as e:
            # Restore old config if validation fails
            self.config = old_config
            raise e
    
    def bulk_generate_payloads(
        self,
        contexts: List[Dict[str, Any]],
        detected_wafs: Optional[List[DetectedWAF]] = None
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
        
        # Equal quota distribution with stable order
        quota = max(1, self.config.max_payloads // max(1, len(contexts)))
        
        for i, context_info in enumerate(contexts):
            ctx_name = context_info.get("context_type", f"context_{i}")
            
            try:
                payloads = self.generate_payloads(
                    context_info=dict(context_info),
                    detected_wafs=detected_wafs,
                    max_payloads=quota
                )
                results[ctx_name] = payloads
                
            except Exception as e:
                logger.error(f"Error generating payloads for context {ctx_name}: {e}")
                results[ctx_name] = []
        
        logger.info(f"Bulk generation completed: {len(results)} context types")
        return results