#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI kb commands (more)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 01:12:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from typer.testing import CliRunner
from cli.main import app


def test_kb_search_no_results():
    runner = CliRunner()
    r = runner.invoke(app, ["kb", "search", "zzzz_not_found_zzz"]) 
    assert r.exit_code == 0 and "No contexts found matching" in r.stdout


def test_kb_search_with_results():
    runner = CliRunner()
    r = runner.invoke(app, ["kb", "search", "html"]) 
    assert r.exit_code == 0 and "Search Results" in r.stdout


def test_kb_list_json_format():
    runner = CliRunner()
    r = runner.invoke(app, ["kb", "list", "--format", "json"]) 
    assert r.exit_code == 0 and r.stdout.strip().startswith("[")


def test_kb_show_section_json_and_unknown():
    runner = CliRunner()
    r1 = runner.invoke(app, ["kb", "show", "html_content", "--format", "json", "--section", "description"]) 
    assert r1.exit_code == 0 and "description" in r1.stdout
    r2 = runner.invoke(app, ["kb", "show", "unknown_ctx"]) 
    assert r2.exit_code == 2 and "Context 'unknown_ctx' not found" in r2.stdout


