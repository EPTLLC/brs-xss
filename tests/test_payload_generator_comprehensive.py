#!/usr/bin/env python3

# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 10:30:00 MSK
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
Comprehensive tests for PayloadGenerator to achieve high coverage
"""

import pytest
from unittest.mock import patch
from brsxss.core.payload_generator import PayloadGenerator
from brsxss.core.payload_types import GenerationConfig, Weights


class TestPayloadGeneratorComprehensive:
    """Comprehensive tests for high PayloadGenerator coverage"""

    def test_context_matrix_error_handling(self):
        """Test Context Matrix error handling"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        # Test that matrix errors don't break generation - wrap in try/catch in actual code
        context_info = {'context_type': 'unknown_format'}  # Will skip matrix loading
        payloads = gen.generate_payloads(context_info)
        # Should still generate payloads from other sources
        assert len(payloads) > 0

    def test_waf_specific_generation(self):
        """Test WAF-specific payload generation"""
        config = GenerationConfig()
        config.include_waf_specific = True
        gen = PayloadGenerator(config)
        
        context_info = {'context_type': 'html_content'}
        detected_wafs = ['cloudflare', 'aws_waf']
        
        payloads = gen.generate_payloads(context_info, detected_wafs=detected_wafs)
        assert len(payloads) > 0

    def test_single_payload_generation(self):
        """Test generate_single_payload method"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        context_info = {'context_type': 'html_content'}
        payload = gen.generate_single_payload(context_info)
        
        assert payload is not None
        assert payload.payload
        assert payload.context_type == 'html_content'

    def test_evasion_techniques_application(self):
        """Test evasion techniques application"""
        config = GenerationConfig()
        config.include_evasions = True
        gen = PayloadGenerator(config)
        
        base_payloads = ["<script>alert(1)</script>"]
        context_info = {'context_type': 'html_content'}
        
        evasion_payloads = gen._apply_evasion_techniques(base_payloads, context_info)
        assert len(evasion_payloads) > 0

    def test_evasion_with_long_payload(self):
        """Test evasion techniques with oversized payload"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        # Test with very long payload (>4096)
        long_payload = "A" * 5000
        base_payloads = [long_payload]
        context_info = {'context_type': 'html_content'}
        
        # Should skip oversized payloads
        evasion_payloads = gen._apply_evasion_techniques(base_payloads, context_info)
        # May return empty list due to length protection
        assert isinstance(evasion_payloads, list)

    def test_bulk_generation(self):
        """Test bulk payload generation"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        contexts = [
            {'context_type': 'html_content'},
            {'context_type': 'javascript'},
            {'context_type': 'html_attribute'}
        ]
        
        results = gen.bulk_generate_payloads(contexts)
        assert len(results) == 3
        assert all(len(payloads) > 0 for payloads in results.values())

    def test_bulk_generation_with_error(self):
        """Test bulk generation with context error"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        # Mock to cause error in one context
        with patch.object(gen, 'generate_payloads', side_effect=[Exception("Error"), []]):
            contexts = [
                {'context_type': 'html_content'},
                {'context_type': 'javascript'}
            ]
            
            results = gen.bulk_generate_payloads(contexts)
            assert len(results) == 2  # Should handle error gracefully

    def test_apply_specific_technique(self):
        """Test _apply_specific_technique method"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        payload = "<script>alert(1)</script>"
        
        # Test with valid technique
        result = gen._apply_specific_technique(payload, "case_variation")
        assert isinstance(result, list)
        
        # Test with invalid technique
        result = gen._apply_specific_technique(payload, "nonexistent_technique")
        assert result == [payload]  # Should return original

    def test_statistics_tracking(self):
        """Test comprehensive statistics tracking"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        context_info = {'context_type': 'html_content'}
        gen.generate_payloads(context_info)
        
        stats = gen.get_statistics()
        assert stats["total_generated"] > 0
        assert "html_content" in stats["by_context"]
        assert "by_source" in stats
        assert 0.0 <= stats["success_rate"] <= 1.0

    def test_config_update_rollback(self):
        """Test config update with rollback on error"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        # Try to update with invalid config
        bad_config = GenerationConfig()
        bad_config.max_payloads = -1  # Invalid
        
        with pytest.raises(ValueError):
            gen.update_config(bad_config)
        
        # Original config should be preserved
        assert gen.config.max_payloads == 500

    def test_aggressive_mode(self):
        """Test aggressive payload mode"""
        config = GenerationConfig()
        config.enable_aggressive = True
        gen = PayloadGenerator(config)
        
        context_info = {'context_type': 'html_content'}
        payloads = gen.generate_payloads(context_info)
        
        # Should generate more payloads with aggressive mode
        assert len(payloads) > 0

    def test_unknown_context_type(self):
        """Test generation with unknown context type"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        context_info = {'context_type': 'unknown_format'}
        payloads = gen.generate_payloads(context_info)
        
        # Should still generate payloads from comprehensive source
        assert len(payloads) > 0

    def test_empty_pool_handling(self):
        """Test handling when pool is empty"""
        config = GenerationConfig()
        config.effectiveness_threshold = 1.0  # Very high threshold
        gen = PayloadGenerator(config)
        
        # Mock to return empty payloads
        with patch.object(gen.context_generator, 'get_context_payloads', return_value=[]):
            with patch.object(gen.payload_manager, 'get_all_payloads', return_value=[]):
                context_info = {'context_type': 'html_content'}
                payloads = gen.generate_payloads(context_info)
                
                # Should handle empty pool gracefully
                assert isinstance(payloads, list)

    def test_blind_xss_without_webhook(self):
        """Test blind XSS generation without webhook"""
        config = GenerationConfig()
        config.include_blind_xss = True
        config.safe_mode = False
        
        # No webhook provided
        gen = PayloadGenerator(config)
        
        context_info = {'context_type': 'html_content'}
        payloads = gen.generate_payloads(context_info)
        
        # Should work without blind XSS manager
        assert len(payloads) > 0

    def test_norm_key_cached_performance(self):
        """Test cached normalization performance"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        # Test cache hit
        key1 = gen._norm_key_cached("test payload")
        key2 = gen._norm_key_cached("test payload")  # Should hit cache
        
        assert key1 == key2

    def test_safe_list_helper(self):
        """Test _safe_list helper function"""
        config = GenerationConfig()
        gen = PayloadGenerator(config)
        
        # Test with list
        result = gen._safe_list([1, 2, 3])
        assert result == [1, 2, 3]
        
        # Test with None
        result = gen._safe_list(None)
        assert result == []
        
        # Test with generator
        result = gen._safe_list(x for x in [1, 2, 3])
        assert result == [1, 2, 3]

    def test_weights_dataclass_integration(self):
        """Test Weights dataclass integration"""
        config = GenerationConfig()
        config.weights = Weights(
            context_specific=0.95,
            context_matrix=0.85,
            comprehensive=0.60,
            evasion=0.80
        )
        
        gen = PayloadGenerator(config)
        context_info = {'context_type': 'html_content'}
        payloads = gen.generate_payloads(context_info)
        
        # Should use custom weights
        assert len(payloads) > 0
        if payloads:
            assert payloads[0].effectiveness_score >= 0.85

    def test_pool_cap_smart_trimming(self):
        """Test smart pool trimming by source priority"""
        config = GenerationConfig()
        config.pool_cap = 200  # Small but valid for testing
        config.max_payloads = 20
        
        gen = PayloadGenerator(config)
        context_info = {'context_type': 'html_content'}
        payloads = gen.generate_payloads(context_info)
        
        # Should respect pool cap and still generate quality payloads
        assert len(payloads) <= config.max_payloads
        assert len(payloads) > 0

    def test_context_specific_only_mode(self):
        """Test context_specific_only configuration"""
        config = GenerationConfig()
        config.context_specific_only = True
        gen = PayloadGenerator(config)
        
        context_info = {'context_type': 'html_content'}
        payloads = gen.generate_payloads(context_info)
        
        # Should generate payloads even in context-only mode
        assert len(payloads) > 0
