#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27
Status: Updated - Uses BRS-KB as single source of truth
Telegram: https://t.me/easyprotech

Knowledge Base Validation Tests
Tests BRS-KB integration with BRS-XSS
"""

import pytest

# BRS-KB is the single source of truth for knowledge base
import brs_kb


class TestKnowledgeBaseStructure:
    """Test KB structure and integrity"""

    @pytest.fixture
    def all_contexts(self):
        """Get all available contexts"""
        return brs_kb.list_contexts()

    def test_kb_version_exists(self):
        """Test that KB version is defined"""
        version = brs_kb.KB_VERSION
        assert version is not None
        assert isinstance(version, str)
        assert len(version.split(".")) == 3  # Semantic versioning

    def test_get_kb_version(self):
        """Test get_kb_version function"""
        version = brs_kb.get_kb_version()
        assert version == brs_kb.KB_VERSION

    def test_get_kb_info(self):
        """Test get_kb_info returns valid structure"""
        info = brs_kb.get_kb_info()
        assert "version" in info
        assert "build" in info
        assert "revision" in info
        assert "total_contexts" in info
        assert "available_contexts" in info
        assert isinstance(info["total_contexts"], int)
        assert info["total_contexts"] > 0
        # BRS-KB should have 100+ contexts
        assert info["total_contexts"] >= 100

    def test_list_contexts(self, all_contexts):
        """Test list_contexts returns contexts"""
        assert len(all_contexts) > 0
        assert "default" in all_contexts
        assert "html_content" in all_contexts
        # BRS-KB should have modern contexts
        assert "javascript" in all_contexts
        assert "css" in all_contexts
        assert "websocket" in all_contexts

    def test_all_contexts_loadable(self, all_contexts):
        """Test that all contexts can be loaded"""
        for context in all_contexts:
            details = brs_kb.get_vulnerability_details(context)
            assert details is not None
            assert isinstance(details, dict)

    def test_required_fields_present(self, all_contexts):
        """Test that all contexts have required fields"""
        required_fields = ["title", "description", "attack_vector", "remediation"]

        for context in all_contexts:
            details = brs_kb.get_vulnerability_details(context)
            for field in required_fields:
                assert field in details, f"Context '{context}' missing field '{field}'"
                assert details[field], f"Context '{context}' has empty field '{field}'"

    def test_field_types(self, all_contexts):
        """Test that fields are of correct type"""
        for context in all_contexts:
            details = brs_kb.get_vulnerability_details(context)

            # Title must be string
            assert isinstance(details.get("title"), str)

            # Description must be string
            assert isinstance(details.get("description"), str)

            # If severity exists, must be valid
            if "severity" in details:
                assert details["severity"] in ["low", "medium", "high", "critical"]

            # If CVSS exists, must be valid
            if "cvss_score" in details:
                assert isinstance(details["cvss_score"], (int, float))
                assert 0.0 <= details["cvss_score"] <= 10.0

    def test_content_quality(self, all_contexts):
        """Test content quality (minimum lengths)"""
        for context in all_contexts:
            details = brs_kb.get_vulnerability_details(context)

            # Title should be meaningful
            assert (
                len(details["title"]) >= 10
            ), f"Context '{context}' has too short title"

            # Description should be substantial
            assert (
                len(details["description"]) >= 50
            ), f"Context '{context}' has too short description"

    def test_default_fallback(self):
        """Test that unknown context falls back to default"""
        unknown = brs_kb.get_vulnerability_details("unknown_context_xyz")
        default = brs_kb.get_vulnerability_details("default")

        # Should return default context
        assert unknown == default

    def test_case_insensitive(self):
        """Test that context lookup is case-insensitive"""
        lower = brs_kb.get_vulnerability_details("html_content")
        upper = brs_kb.get_vulnerability_details("HTML_CONTENT")
        mixed = brs_kb.get_vulnerability_details("Html_Content")

        assert lower == upper == mixed


class TestKnowledgeBaseMetadata:
    """Test metadata fields for SIEM integration"""

    def test_severity_field(self):
        """Test severity field in contexts"""
        details = brs_kb.get_vulnerability_details("html_content")
        # BRS-KB should have severity for all contexts
        assert "severity" in details
        assert details["severity"] in ["low", "medium", "high", "critical"]

    def test_cvss_score(self):
        """Test CVSS score is present"""
        details = brs_kb.get_vulnerability_details("html_content")
        # BRS-KB should have CVSS for all contexts
        assert "cvss_score" in details
        assert isinstance(details["cvss_score"], (int, float))
        assert 0.0 <= details["cvss_score"] <= 10.0

    def test_cvss_vector(self):
        """Test CVSS vector format"""
        details = brs_kb.get_vulnerability_details("html_content")
        if "cvss_vector" in details:
            assert details["cvss_vector"].startswith("CVSS:3.")

    def test_cwe_format(self):
        """Test CWE format"""
        details = brs_kb.get_vulnerability_details("html_content")
        if "cwe" in details:
            assert isinstance(details["cwe"], list)
            for cwe in details["cwe"]:
                assert cwe.startswith("CWE-")


class TestKnowledgeBaseIntegration:
    """Test KB integration with other components"""

    def test_brs_kb_importable(self):
        """Test that BRS-KB can be imported"""
        import brs_kb

        assert callable(brs_kb.get_vulnerability_details)
        assert callable(brs_kb.list_contexts)
        assert callable(brs_kb.get_kb_info)

    def test_payloads_available(self):
        """Test that payloads are available from BRS-KB"""
        info = brs_kb.get_kb_info()
        assert "total_payloads" in info
        assert info["total_payloads"] > 3000  # BRS-KB should have 3000+ payloads


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
