from brsxss.utils.validators import URLValidator, ParameterValidator, PayloadValidator, ConfigValidator, FileValidator, InputSanitizer


def test_url_validator_normalization_and_warnings(tmp_path):
    res = URLValidator.validate_url("example.com/path")
    assert res.valid and res.normalized_value.startswith("http://")
    assert any("protocol" in w.lower() for w in res.warnings)

    res2 = URLValidator.validate_url("http://localhost:8080")
    assert res2.valid and any("localhost" in w.lower() for w in res2.warnings)


def test_parameter_validator_and_analysis():
    name_res = ParameterValidator.validate_parameter_name("on:load")
    assert name_res.valid and any("unusual" in w.lower() for w in name_res.warnings)

    analysis = ParameterValidator.analyze_parameter_value("https://ex.com?a=1&b=2<script>alert(1)</script>")
    assert 'url' in analysis['type_hints']
    assert 'html_tags' in analysis['patterns']
    assert any(ch in analysis['special_chars'] for ch in ['<', '>'])


def test_payload_validator_and_sanitizer():
    res = PayloadValidator.validate_payload("<script>document.cookie</script>")
    assert res.valid and any("dangerous" in w.lower() for w in res.warnings)

    s = PayloadValidator.sanitize_payload_for_logging("<script>alert(1)</script>" * 30)
    assert len(s) <= 210  # truncated and sanitized


def test_config_validator_and_file_validator(tmp_path):
    cfg = {
        'target_url': 'https://example.org',
        'max_depth': 3,
        'max_urls': 100,
        'max_concurrent': 5,
        'timeout': 10,
        'user_agent': 'ua',
    }
    res = ConfigValidator.validate_scan_config(cfg)
    assert res.valid

    out = tmp_path / "out.json"
    fres = FileValidator.validate_output_path(str(out))
    assert fres.valid and out.parent.exists()


def test_input_sanitizer_variants():
    assert InputSanitizer.sanitize_for_shell("; rm -rf /") == "rm -rf /"
    assert InputSanitizer.sanitize_for_filename("a<b>c|d:e?f*g\"h/i") == "a_b_c_d_e_f_g_h_i"
    d = InputSanitizer.sanitize_for_display("<a href='x'>&")
    assert d == "&lt;a href=&#x27;x&#x27;&gt;&amp;"
