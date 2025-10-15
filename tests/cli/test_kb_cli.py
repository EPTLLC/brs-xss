#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI kb commands
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:08:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from typer.testing import CliRunner
from cli.main import app


def test_kb_info_list_and_show():
    runner = CliRunner()
    r1 = runner.invoke(app, ["kb", "info"])  
    assert r1.exit_code == 0 and "Knowledge Base" in r1.stdout
    r2 = runner.invoke(app, ["kb", "list", "--format", "simple"]) 
    assert r2.exit_code == 0 and len(r2.stdout.strip()) > 0
    # Try known context from reverse_map or default set
    r3 = runner.invoke(app, ["kb", "show", "html_content", "--format", "json", "--section", "description"], catch_exceptions=False) 
    assert r3.exit_code == 0 and "description" in r3.stdout.lower()


def test_kb_export_and_not_found(tmp_path):
    runner = CliRunner()
    out_json = tmp_path / "ctx.json"
    out_yaml = tmp_path / "ctx.yaml"
    out_md = tmp_path / "ctx.md"
    rj = runner.invoke(app, ["kb", "export", "html_content", str(out_json), "--format", "json"]) 
    assert rj.exit_code == 0 and out_json.exists()
    ry = runner.invoke(app, ["kb", "export", "html_content", str(out_yaml), "--format", "yaml"]) 
    assert ry.exit_code == 0 and out_yaml.exists()
    rm = runner.invoke(app, ["kb", "export", "html_content", str(out_md), "--format", "markdown"]) 
    assert rm.exit_code == 0 and out_md.exists()
    rbad = runner.invoke(app, ["kb", "export", "unknown_ctx", str(tmp_path / "z.json"), "--format", "json"]) 
    assert rbad.exit_code == 0 and "not found" in rbad.stdout.lower()

