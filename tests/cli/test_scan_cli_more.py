#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI scan command more
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:12:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from typer.testing import CliRunner
from cli.commands.scan import app as scan_app


def test_scan_cli_invalid_url():
    runner = CliRunner()
    result = runner.invoke(scan_app, ["not a url"])  # invalid
    assert result.exit_code != 0 and "ERROR" in result.stdout


def test_scan_cli_no_params_early_exit():
    runner = CliRunner()
    result = runner.invoke(scan_app, ["http://example.com"])  # no query/data
    # Branch: no parameters found -> Exit(0)
    assert result.exit_code == 0 and "No parameters found" in result.stdout


