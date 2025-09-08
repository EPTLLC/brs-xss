import json
from brsxss.report.templates import HTMLTemplate, JSONTemplate, SARIFTemplate, JUnitTemplate


def sample_data(with_vulns: bool):
    vulns = []
    if with_vulns:
        vulns = [
            {
                "url": "http://example.com/?q=1",
                "parameter": "q",
                "context": "javascript",
                "payload": "<script>alert(1)</script>",
                "severity": "high",
                "confidence": 0.9,
                "exploitation_likelihood": 0.6,
                "detection_score": 8.1,
            }
        ]
    return {
        "vulnerabilities": vulns,
        "statistics": {"scan_duration": 1.2, "total_requests": 12, "parameters_tested": 3},
        "target_info": {"url": "http://example.com"},
        "policy": {"min_vulnerability_score": 0.2},
    }


def test_html_template_branches():
    html = HTMLTemplate()
    out_empty = html.generate(sample_data(False))
    assert "No Vulnerabilities Found" in out_empty
    out_with = html.generate(sample_data(True))
    assert "Vulnerabilities Found" in out_with
    assert "BRS-XSS Security Report" in out_with


def test_json_template_counts_and_summary():
    js = JSONTemplate()
    out = js.generate(sample_data(True))
    data = json.loads(out)
    assert data["summary"]["total_vulnerabilities"] == 1
    assert data["summary"]["risk_levels"]["high"] == 1
    summary = js.generate_summary({"statistics": {"scan_duration": 1}})
    assert "scan_summary" in json.loads(summary)


def test_sarif_and_junit_templates():
    sarif = SARIFTemplate()
    s = sarif.generate(sample_data(True))
    assert "runs" in json.loads(s)
    # Summary returns full SARIF
    s2 = sarif.generate_summary(sample_data(False))
    assert "runs" in json.loads(s2)

    junit = JUnitTemplate()
    x = junit.generate(sample_data(True))
    assert "<testsuites" in x and "<failure" in x
    x2 = junit.generate(sample_data(False))
    assert "<testsuite" in x2 and "<testcase" in x2
