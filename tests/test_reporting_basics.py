import json
from pathlib import Path

from brsxss.report.data_models import VulnerabilityData, ScanStatistics
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.report_generator import ReportGenerator
from brsxss.report.sarif_reporter import SARIFReporter
from brsxss.utils.paths import sanitize_filename, atomic_write, build_result_path


def sample_vuln() -> VulnerabilityData:
    return VulnerabilityData(
        id="v1",
        title="Reflected XSS",
        description="Test",
        severity="high",
        confidence=0.9,
        url="https://example.com/search?q=1",
        parameter="q",
        payload="\" onmouseover=alert(1)"
    )


def test_sarif_reporter_basic_structure(tmp_path):
    reporter = SARIFReporter()
    sarif = reporter.generate_sarif([sample_vuln()], {
        "targets_scanned": 1,
        "duration": "1s",
        "command_line": "brs-xss scan https://example.com"
    })
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "BRS-XSS"
    assert len(sarif["runs"][0]["results"]) == 1


def test_report_generator_formats(tmp_path):
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.JSON, ReportFormat.HTML, ReportFormat.SARIF])
    gen = ReportGenerator(cfg)
    stats = ScanStatistics(total_requests_sent=1, scan_duration=0.1)
    files = gen.generate_report([sample_vuln()], stats, target_info={"url": "https://example.com"})
    # Ensure files exist
    for fmt, path in files.items():
        assert Path(path).exists(), f"Missing report for {fmt}"


def test_paths_utils(tmp_path):
    unsafe = "https://ex ample.com//a/b?q=1#frag"
    safe = sanitize_filename(unsafe)
    assert "/" not in safe and " " not in safe

    # atomic write creates and replaces content safely
    target = tmp_path / "file.txt"
    atomic_write(str(target), "one")
    assert target.read_text() == "one"
    atomic_write(str(target), "two")
    assert target.read_text() == "two"

    # build_result_path creates directories and returns path
    built = build_result_path(str(tmp_path / "out"), "my name", ".json")
    assert built.endswith(".json")
    # Writing to built path works
    atomic_write(built, json.dumps({"ok": True}))
    assert Path(built).exists()
