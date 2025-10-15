#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI scan command smoke
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:53:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from typer.testing import CliRunner
from cli.commands.scan import app


def test_scan_cli_exits_when_no_parameters_found():
    runner = CliRunner()
    result = runner.invoke(app, ["https://example.com"])  # no query params
    assert result.exit_code == 0
    assert "No parameters found" in result.stdout or "WARNING: No parameters found" in result.stdout


