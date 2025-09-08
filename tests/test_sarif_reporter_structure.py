import json
from pathlib import Path

import brsxss
from brsxss.report.sarif_reporter import SARIFReporter
from brsxss.report.data_models import VulnerabilityData


def _make_vuln(**overrides):
    base = dict(
        id="v1",
        title="Reflected XSS",
        description="Test vuln",
        severity="high",
        confidence=0.9,
        url="https://example.com/search?q=test",
        parameter="q",
        payload="<script>alert(1)</script>",
        method="GET",
        vulnerability_type="reflected_xss",
        context_type="html_content",
    )
    base.update(overrides)
    return VulnerabilityData(**base)


def test_generate_sarif_core_fields_present():
    reporter = SARIFReporter()
    vuln = _make_vuln()
    sarif = reporter.generate_sarif([vuln], scan_info={})

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert sarif["runs"], "runs should not be empty"

    run0 = sarif["runs"][0]
    driver = run0["tool"]["driver"]
    # semanticVersion should be set and match package version
    assert driver.get("semanticVersion") == brsxss.__version__

    # Rules should contain XSS001 with help fields
    rules = {r["id"]: r for r in driver.get("rules", [])}
    r1 = rules.get("XSS001")
    assert r1 is not None
    assert "help" in r1 and r1.get("help", {}).get("text")
    assert r1.get("helpUri", "").startswith("http")

    # Results should carry tags in properties
    results = run0.get("results", [])
    assert results, "results must contain at least one item"
    props = results[0].get("properties", {})
    assert isinstance(props.get("tags"), list) and "xss" in props["tags"]


def test_save_sarif_adds_run_encoding_and_column_kind(tmp_path: Path):
    reporter = SARIFReporter()
    vuln = _make_vuln()
    out = tmp_path / "report.sarif.json"
    reporter.save_sarif([vuln], scan_info={}, output_path=str(out))

    data = json.loads(out.read_text(encoding="utf-8"))
    run0 = data["runs"][0]
    assert run0.get("columnKind") == "utf16CodeUnits"
    assert run0.get("defaultEncoding") == "utf-8"
