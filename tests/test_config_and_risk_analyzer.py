from types import SimpleNamespace
import os

from brsxss.core.config_manager import ConfigManager
from brsxss.core.risk_analyzer import RiskAnalyzer
from brsxss.core.scoring_types import SeverityLevel


def test_config_manager_defaults_and_env(tmp_path, monkeypatch):
    # Create temp config directory
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    cfg_file = cfg_dir / "default.yaml"
    cfg_file.write_text("scanner:\n  max_depth: 2\nreporting:\n  format: json\n", encoding="utf-8")

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Environment override
        monkeypatch.setenv("BRSXSS_MAX_DEPTH", "5")
        cm = ConfigManager()  # should find config/default.yaml
        assert cm.get("scanner.max_depth") == 5
        assert cm.get("reporting.format") == "json"

        # Update and save
        cm.set("logging.level", "DEBUG")
        out_path = tmp_path / "config" / "saved.yaml"
        cm.save(str(out_path))
        assert out_path.exists()

        # Validate
        errors = cm.validate()
        assert errors == []
        summary = cm.get_config_summary()
        assert "sections" in summary and isinstance(summary["sections"], list)
    finally:
        os.chdir(cwd)


def test_risk_analyzer_end_to_end():
    ra = RiskAnalyzer()
    ctx = {
        "context_type": "javascript",
        "tag_name": "script",
        "filters_detected": [],
        "encoding_detected": "none",
        "user_controllable": True,
    }
    payload = "<script>document.cookie = 'x'; fetch('https://ex')</script>"
    rr = SimpleNamespace(reflection_type="exact")
    response = SimpleNamespace(headers={
        "content-security-policy": "default-src 'self'",
        "x-xss-protection": "1; mode=block",
    })

    risks = ra.identify_risk_factors(ctx, payload, rr)
    mitigations = ra.identify_mitigating_factors(ctx, response)
    recs = ra.generate_recommendations(SeverityLevel.HIGH, ctx, risks, mitigations)

    assert any("JavaScript" in r or "JavaScript" in r.capitalize() for r in risks)
    assert any("Content Security Policy" in m for m in mitigations)
    assert any("CSP" in x or "sanitize" in x.lower() for x in recs)
