#!/usr/bin/env python3

# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 09:50:00 MSK
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
Critical tests for PayloadGenerator stability and reliability
"""

import pytest
from brsxss.core.payload_generator import PayloadGenerator
from brsxss.core.payload_types import GenerationConfig


class TestPayloadGeneratorCritical:
    """Critical functionality tests for PayloadGenerator"""

    def test_config_validation(self):
        """Test configuration validation catches invalid values"""
        
        # Test invalid max_payloads
        with pytest.raises(ValueError, match="Invalid config: max_payloads"):
            bad_config = GenerationConfig()
            bad_config.max_payloads = -1
            PayloadGenerator(bad_config)
        
        # Test invalid effectiveness_threshold
        with pytest.raises(ValueError, match="Invalid config: effectiveness_threshold"):
            bad_config = GenerationConfig()
            bad_config.effectiveness_threshold = 2.0
            PayloadGenerator(bad_config)
        
        # Test invalid pool_cap
        with pytest.raises(ValueError, match="Invalid config: pool_cap"):
            bad_config = GenerationConfig()
            bad_config.pool_cap = 50  # Too small
            PayloadGenerator(bad_config)

    def test_pool_cap_enforcement(self):
        """Test that pool never exceeds pool_cap"""
        config = GenerationConfig()
        config.pool_cap = 100  # Small cap
        config.max_payloads = 50
        
        gen = PayloadGenerator(config)
        context_info = {'context_type': 'html_content'}
        payloads = gen.generate_payloads(context_info)
        
        # Should generate payloads without exceeding cap
        assert len(payloads) <= config.max_payloads
        assert len(payloads) > 0  # Should still generate some payloads

    def test_safe_mode_blind_xss(self):
        """Test that blind XSS is disabled in safe mode"""
        config = GenerationConfig()
        config.safe_mode = True
        config.include_blind_xss = True
        config.max_payloads = 10
        
        gen = PayloadGenerator(config)
        context_info = {'context_type': 'html_content'}
        
        # Should generate payloads but warn about blind XSS
        payloads = gen.generate_payloads(context_info)
        assert len(payloads) > 0
        
        # Test unsafe mode (would need webhook for full test)
        config.safe_mode = False
        gen_unsafe = PayloadGenerator(config)
        payloads_unsafe = gen_unsafe.generate_payloads(context_info)
        assert len(payloads_unsafe) > 0

    def test_determinism_seed(self):
        """Test that same seed produces identical output"""
        config1 = GenerationConfig()
        config1.seed = 42
        config1.max_payloads = 20
        
        config2 = GenerationConfig()
        config2.seed = 42  # Same seed
        config2.max_payloads = 20
        
        gen1 = PayloadGenerator(config1)
        gen2 = PayloadGenerator(config2)
        
        context_info = {'context_type': 'html_content'}
        
        payloads1 = gen1.generate_payloads(context_info)
        payloads2 = gen2.generate_payloads(context_info)
        
        # Should produce identical results
        assert len(payloads1) == len(payloads2)
        if payloads1 and payloads2:
            assert payloads1[0].payload == payloads2[0].payload
            assert payloads1[0].effectiveness_score == payloads2[0].effectiveness_score

    def test_dedup_final(self):
        """Test that final deduplication eliminates all duplicates"""
        config = GenerationConfig()
        config.max_payloads = 50
        config.safe_mode = False  # Allow blind XSS for dedup test
        
        gen = PayloadGenerator(config)
        context_info = {'context_type': 'html_content'}
        payloads = gen.generate_payloads(context_info)
        
        # Check for duplicates
        payload_strings = [p.payload for p in payloads]
        unique_payloads = set(payload_strings)
        
        assert len(payload_strings) == len(unique_payloads), "Found duplicate payloads after final deduplication"

    def test_success_rate_calculation(self):
        """Test that success_rate reflects real filtering ratio"""
        config = GenerationConfig()
        config.effectiveness_threshold = 0.9  # Very high threshold
        config.max_payloads = 10
        
        gen = PayloadGenerator(config)
        context_info = {'context_type': 'html_content'}
        
        # Generate with high threshold
        gen.generate_payloads(context_info)
        success_rate = gen.generation_stats['success_rate']
        
        # Success rate should be low due to high threshold
        assert 0.0 <= success_rate <= 1.0
        assert success_rate < 0.5  # Should be low due to filtering

    def test_payload_length_protection(self):
        """Test that overly long payloads are truncated"""
        config = GenerationConfig()
        config.max_payloads = 10
        
        gen = PayloadGenerator(config)
        
        # Test _wrap method directly with long payload
        long_payload = "A" * 5000  # Longer than 4096 limit
        wrapped = gen._wrap("html_content", long_payload, "test", 0.8)
        
        assert len(wrapped.payload) <= 4096
        assert wrapped.payload == "A" * 4096

    def test_weights_configuration(self):
        """Test configurable weights for payload sources"""
        config = GenerationConfig()
        config.weights = {
            'context_specific': 0.95,
            'context_matrix': 0.85,
            'comprehensive': 0.60
        }
        config.max_payloads = 10
        
        gen = PayloadGenerator(config)
        context_info = {'context_type': 'html_content'}
        payloads = gen.generate_payloads(context_info)
        
        # Should generate payloads with custom weights
        assert len(payloads) > 0
        
        # Top payloads should have high effectiveness scores due to custom weights
        if payloads:
            assert payloads[0].effectiveness_score >= 0.85
