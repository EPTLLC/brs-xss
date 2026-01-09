#!/usr/bin/env python3

"""
Project: BRS-XSS Tests for ReportGenerator
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:45:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
import json
from pathlib import Path

from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics


@pytest.fixture
def mock_vuln_data():
    """Provides a sample list of VulnerabilityData objects."""
    return [
        VulnerabilityData(
            id="xss_1",
            title="XSS in 'q' parameter",
            description="A simple XSS vulnerability.",
            severity="high",
            confidence=0.9,
            url="http://test.com/search",
            parameter="q",
            payload="<script>alert(1)</script>",
            context="html_content",
        )
    ]


@pytest.fixture
def mock_scan_stats():
    """Provides a sample ScanStatistics object."""
    return ScanStatistics(
        total_urls_tested=1,
        total_parameters_tested=1,
        total_payloads_tested=100,
        total_requests_sent=200,
        scan_duration=123.45,
        vulnerabilities_found=1,
    )


def test_generates_html_report(tmp_path: Path, mock_vuln_data, mock_scan_stats):
    """
    Test that the ReportGenerator can successfully create an HTML report.
    """
    # Arrange
    config = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.HTML])
    generator = ReportGenerator(config)

    # Act
    generated_files = generator.generate_report(
        mock_vuln_data, mock_scan_stats, {"url": "http://test.com"}
    )

    # Assert
    assert ReportFormat.HTML in generated_files
    html_file = Path(generated_files[ReportFormat.HTML])
    assert html_file.exists()

    content = html_file.read_text()
    assert "BRS-XSS Security Report" in content
    assert "XSS in 'q' parameter" in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content  # Check for escaping


def test_generates_json_report(tmp_path: Path, mock_vuln_data, mock_scan_stats):
    """
    Test that the ReportGenerator can successfully create a JSON report.
    """
    # Arrange
    config = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.JSON])
    generator = ReportGenerator(config)

    # Act
    generated_files = generator.generate_report(
        mock_vuln_data, mock_scan_stats, {"url": "http://test.com"}
    )

    # Assert
    assert ReportFormat.JSON in generated_files
    json_file = Path(generated_files[ReportFormat.JSON])
    assert json_file.exists()

    data = json.loads(json_file.read_text())
    assert data["summary"]["total_vulnerabilities"] == 1
    assert data["vulnerabilities"][0]["title"] == "XSS in 'q' parameter"


def test_generates_sarif_report(tmp_path: Path, mock_vuln_data, mock_scan_stats):
    """
    Test that the ReportGenerator can successfully create a SARIF report.
    """
    # Arrange
    config = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.SARIF])
    generator = ReportGenerator(config)

    # Act
    generated_files = generator.generate_report(
        mock_vuln_data, mock_scan_stats, {"url": "http://test.com"}
    )

    # Assert
    assert ReportFormat.SARIF in generated_files
    sarif_file = Path(generated_files[ReportFormat.SARIF])
    assert sarif_file.exists()

    data = json.loads(sarif_file.read_text())
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["tool"]["driver"]["name"] == "BRS-XSS"
