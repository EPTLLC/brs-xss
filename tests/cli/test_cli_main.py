#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI main
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:05:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from typer.testing import CliRunner
from cli.main import app


def test_cli_version_command():
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0 and "BRS-XSS v" in result.stdout


def test_cli_config_show(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("scanner:\n  max_depth: 3\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["config", "--show", "--config", str(cfg)])
    assert result.exit_code == 0 and "Configuration:" in result.stdout
