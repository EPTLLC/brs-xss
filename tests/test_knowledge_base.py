#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base Validation Tests
"""

import pytest
import json
from pathlib import Path

# Import knowledge base functions
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from brsxss.report.knowledge_base import (
    get_vulnerability_details,
    get_kb_version,
    get_kb_info,
    list_contexts,
    KB_VERSION
)


class TestKnowledgeBaseStructure:
    """Test KB structure and integrity"""
    
    @pytest.fixture
    def schema(self):
        """Load JSON schema"""
        schema_path = Path(__file__).parent.parent / "brsxss" / "report" / "knowledge_base" / "schema.json"
        with open(schema_path) as f:
            return json.load(f)
    
    @pytest.fixture
    def all_contexts(self):
        """Get all available contexts"""
        return list_contexts()
    
    def test_kb_version_exists(self):
        """Test that KB version is defined"""
        assert KB_VERSION is not None
        assert isinstance(KB_VERSION, str)
        assert len(KB_VERSION.split('.')) == 3  # Semantic versioning
    
    def test_get_kb_version(self):
        """Test get_kb_version function"""
        version = get_kb_version()
        assert version == KB_VERSION
    
    def test_get_kb_info(self):
        """Test get_kb_info returns valid structure"""
        info = get_kb_info()
        assert 'version' in info
        assert 'build' in info
        assert 'revision' in info
        assert 'total_contexts' in info
        assert 'available_contexts' in info
        assert isinstance(info['total_contexts'], int)
        assert info['total_contexts'] > 0
    
    def test_list_contexts(self, all_contexts):
        """Test list_contexts returns contexts"""
        assert len(all_contexts) > 0
        assert 'default' in all_contexts
        assert 'html_content' in all_contexts
    
    def test_all_contexts_loadable(self, all_contexts):
        """Test that all contexts can be loaded"""
        for context in all_contexts:
            details = get_vulnerability_details(context)
            assert details is not None
            assert isinstance(details, dict)
    
    def test_required_fields_present(self, all_contexts):
        """Test that all contexts have required fields"""
        required_fields = ['title', 'description', 'attack_vector', 'remediation']
        
        for context in all_contexts:
            details = get_vulnerability_details(context)
            for field in required_fields:
                assert field in details, f"Context '{context}' missing field '{field}'"
                assert details[field], f"Context '{context}' has empty field '{field}'"
    
    def test_field_types(self, all_contexts):
        """Test that fields are of correct type"""
        for context in all_contexts:
            details = get_vulnerability_details(context)
            
            # Title must be string
            assert isinstance(details.get('title'), str)
            
            # Description must be string
            assert isinstance(details.get('description'), str)
            
            # If severity exists, must be valid
            if 'severity' in details:
                assert details['severity'] in ['low', 'medium', 'high', 'critical']
            
            # If CVSS exists, must be valid
            if 'cvss_score' in details:
                assert isinstance(details['cvss_score'], (int, float))
                assert 0.0 <= details['cvss_score'] <= 10.0
    
    def test_content_quality(self, all_contexts):
        """Test content quality (minimum lengths)"""
        for context in all_contexts:
            details = get_vulnerability_details(context)
            
            # Title should be meaningful
            assert len(details['title']) >= 10, f"Context '{context}' has too short title"
            
            # Description should be substantial
            assert len(details['description']) >= 50, f"Context '{context}' has too short description"
    
    def test_default_fallback(self):
        """Test that unknown context falls back to default"""
        unknown = get_vulnerability_details('unknown_context_xyz')
        default = get_vulnerability_details('default')
        
        # Should return default context
        assert unknown == default
    
    def test_case_insensitive(self):
        """Test that context lookup is case-insensitive"""
        lower = get_vulnerability_details('html_content')
        upper = get_vulnerability_details('HTML_CONTENT')
        mixed = get_vulnerability_details('Html_Content')
        
        assert lower == upper == mixed


class TestKnowledgeBaseMetadata:
    """Test metadata fields for SIEM integration"""
    
    def test_severity_field(self):
        """Test severity field in contexts"""
        # At least one context should have severity
        details = get_vulnerability_details('html_content')
        if 'severity' in details:
            assert details['severity'] in ['low', 'medium', 'high', 'critical']
    
    def test_cvss_score(self):
        """Test CVSS score if present"""
        details = get_vulnerability_details('html_content')
        if 'cvss_score' in details:
            assert isinstance(details['cvss_score'], (int, float))
            assert 0.0 <= details['cvss_score'] <= 10.0
    
    def test_cvss_vector(self):
        """Test CVSS vector format"""
        details = get_vulnerability_details('html_content')
        if 'cvss_vector' in details:
            assert details['cvss_vector'].startswith('CVSS:3.')
    
    def test_cwe_format(self):
        """Test CWE format"""
        details = get_vulnerability_details('html_content')
        if 'cwe' in details:
            assert isinstance(details['cwe'], list)
            for cwe in details['cwe']:
                assert cwe.startswith('CWE-')


class TestKnowledgeBaseIntegration:
    """Test KB integration with other components"""
    
    def test_importable(self):
        """Test that KB can be imported"""
        from brsxss.report.knowledge_base import get_vulnerability_details
        assert callable(get_vulnerability_details)
    
    def test_no_import_errors(self):
        """Test that all KB modules import without errors"""
        from brsxss.report import knowledge_base
        assert hasattr(knowledge_base, 'get_vulnerability_details')
        assert hasattr(knowledge_base, 'KB_VERSION')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

