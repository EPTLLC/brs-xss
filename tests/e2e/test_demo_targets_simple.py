#!/usr/bin/env python3

# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 10:50:00 MSK
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
Simplified E2E tests that actually work in CI
"""

import pytest
import json
import tempfile
from brsxss.core.config_manager import ConfigManager
from brsxss.report.sarif_reporter import SARIFReporter
from brsxss.report.data_models import VulnerabilityData


class TestDemoTargetsSimple:
    """Simplified E2E tests for CI compatibility"""

    def test_config_manager_initialization(self):
        """Test that ConfigManager can be initialized"""
        config = ConfigManager()
        assert config is not None

    def test_sarif_generation_e2e(self):
        """Test SARIF generation end-to-end"""
        # Create test vulnerability data
        vuln = VulnerabilityData(
            id="test-1",
            title="Test XSS",
            description="Test vulnerability",
            severity="high",
            confidence=0.9,
            url="https://example.com/test?param=value",
            parameter="param",
            payload="<script>alert(1)</script>",
            vulnerability_type="reflected_xss",
            context_type="html_content"
        )
        
        # Generate SARIF report
        reporter = SARIFReporter()
        scan_info = {
            'start_time': '2025-09-04T10:00:00Z',
            'targets_scanned': 1,
            'duration': '30s'
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            reporter.save_sarif([vuln], scan_info, f.name)
            
            # Validate SARIF structure
            with open(f.name, 'r') as rf:
                sarif_data = json.load(rf)
                
            assert sarif_data['version'] == '2.1.0'
            assert 'runs' in sarif_data
            assert len(sarif_data['runs']) == 1
            assert 'tool' in sarif_data['runs'][0]
            assert 'results' in sarif_data['runs'][0]
            assert len(sarif_data['runs'][0]['results']) == 1

    def test_vulnerability_data_model(self):
        """Test VulnerabilityData model works correctly"""
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
