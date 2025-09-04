#!/usr/bin/env python3

# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 10:35:00 MSK
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
Tests for core modules to improve overall coverage
"""

import pytest
from unittest.mock import Mock, patch
from brsxss.core.config_manager import ConfigManager
from brsxss.core.reflection_detector import ReflectionDetector
from brsxss.core.context_analyzer import ContextAnalyzer
from brsxss.core.scoring_engine import ScoringEngine
from brsxss.report.sarif_reporter import SARIFReporter
from brsxss.report.data_models import VulnerabilityData


class TestCoreModules:
    """Tests for core modules to improve coverage"""

    def test_config_manager_basic(self):
        """Test ConfigManager basic functionality"""
        config = ConfigManager()
        assert config is not None
        
        # Test config loading
        app_config = config.get_app_config()
        assert app_config is not None
        assert "name" in app_config

    def test_reflection_detector_basic(self):
        """Test ReflectionDetector basic functionality"""
        detector = ReflectionDetector()
        
        # Test with simple reflection
        original = "<script>alert(1)</script>"
        response_text = f"Hello {original} world"
        
        reflections = detector.detect_reflections(original, response_text)
        assert isinstance(reflections, list)

    def test_context_analyzer_basic(self):
        """Test ContextAnalyzer basic functionality"""
        analyzer = ContextAnalyzer()
        
        # Test HTML context analysis
        html = "<div>test</div>"
        context = analyzer.analyze_context(html, "test")
        assert context is not None

    def test_scoring_engine_basic(self):
        """Test ScoringEngine basic functionality"""
        engine = ScoringEngine()
        
        # Mock reflection result
        reflection_result = Mock()
        reflection_result.reflection_type = "exact"
        reflection_result.confidence = 0.9
        
        context_info = {'context_type': 'html_content'}
        payload = "<script>alert(1)</script>"
        
        # Test scoring
        result = engine.score_vulnerability(payload, reflection_result, context_info)
        assert result is not None

    def test_sarif_reporter_comprehensive(self):
        """Test SARIFReporter comprehensive functionality"""
        reporter = SARIFReporter()
        
        # Test with multiple vulnerability types
        vulnerabilities = [
            VulnerabilityData(
                id="test-1",
                title="Reflected XSS",
                description="Test reflected XSS",
                severity="high",
                confidence=0.9,
                url="https://example.com/search?q=test",
                parameter="q",
                payload="<script>alert(1)</script>",
                vulnerability_type="reflected_xss",
                context_type="html_content"
            ),
            VulnerabilityData(
                id="test-2", 
                title="DOM XSS",
                description="Test DOM XSS",
                severity="medium",
                confidence=0.7,
                url="https://example.com/app",
                parameter="hash",
                payload="javascript:alert(1)",
                vulnerability_type="dom_xss",
                context_type="javascript"
            )
        ]
        
        scan_info = {
            'start_time': '2025-09-04T10:00:00Z',
            'end_time': '2025-09-04T10:05:00Z',
            'targets_scanned': 2,
            'duration': '5m'
        }
        
        sarif_report = reporter.generate_sarif(vulnerabilities, scan_info)
        
        # Validate SARIF structure
        assert sarif_report['version'] == '2.1.0'
        assert len(sarif_report['runs']) == 1
        assert len(sarif_report['runs'][0]['results']) == 2
        
        # Test rule mapping
        results = sarif_report['runs'][0]['results']
        reflected_result = next(r for r in results if r['ruleId'] == 'XSS001')
        dom_result = next(r for r in results if r['ruleId'] == 'XSS003')
        
        assert reflected_result is not None
        assert dom_result is not None

    def test_vulnerability_data_model(self):
        """Test VulnerabilityData model"""
        vuln = VulnerabilityData(
            id="test",
            title="Test XSS",
            description="Test description",
            severity="high",
            confidence=0.95,
            url="https://example.com",
            parameter="test",
            payload="<script>alert(1)</script>"
        )
        
        assert vuln.id == "test"
        assert vuln.severity == "high"
        assert vuln.confidence == 0.95

    def test_context_analyzer_edge_cases(self):
        """Test ContextAnalyzer with edge cases"""
        analyzer = ContextAnalyzer()
        
        # Test with empty content
        context = analyzer.analyze_context("", "test")
        assert context is not None
        
        # Test with special characters
        context = analyzer.analyze_context("<script>alert('test')</script>", "test")
        assert context is not None

    def test_reflection_detector_edge_cases(self):
        """Test ReflectionDetector with edge cases"""
        detector = ReflectionDetector()
        
        # Test with no reflection
        reflections = detector.detect_reflections("test", "no match here")
        assert isinstance(reflections, list)
        
        # Test with multiple reflections
        original = "test"
        response = "test found test again test"
        reflections = detector.detect_reflections(original, response)
        assert isinstance(reflections, list)

    def test_scoring_engine_edge_cases(self):
        """Test ScoringEngine with various scenarios"""
        engine = ScoringEngine()
        
        # Test with low confidence reflection
        reflection_result = Mock()
        reflection_result.reflection_type = "partial"
        reflection_result.confidence = 0.3
        
        context_info = {'context_type': 'unknown'}
        payload = "test"
        
        result = engine.score_vulnerability(payload, reflection_result, context_info)
        assert result is not None
        assert result.overall_score >= 0

    def test_config_manager_file_operations(self):
        """Test ConfigManager file operations"""
        config = ConfigManager()
        
        # Test getting different config sections
        scanner_config = config.get_scanner_config()
        assert scanner_config is not None
        
        payload_config = config.get_payloads_config()
        assert payload_config is not None
        
        ml_config = config.get_ml_config()
        assert ml_config is not None
