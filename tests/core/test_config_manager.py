#!/usr/bin/env python3

"""
Project: BRS-XSS Tests for ConfigManager
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:20:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
import os
from unittest.mock import patch

from brsxss.detect.xss.reflected.config_manager import ConfigManager

# --- Mock Data ---
MOCK_DEFAULT_YAML = """
scanner:
  timeout: 15
  user_agent: "BRS-XSS Default"
scoring:
  weights:
    impact: 0.4
"""

MOCK_USER_TOML = """
[scanner]
timeout = 30
"""


@pytest.fixture
def mock_fs(fs):
    """Fixture to create a mock filesystem with config files."""
    # fs is from pyfakefs
    default_path = "/etc/brs-xss/default.yaml"
    user_path = os.path.expanduser("~/.config/brs-xss/user.toml")

    fs.create_file(default_path, contents=MOCK_DEFAULT_YAML)
    fs.create_file(user_path, contents=MOCK_USER_TOML)

    # Patch os.path.exists for the ConfigManager's internal checks
    with patch("os.path.exists") as mock_exists:
        mock_exists.side_effect = lambda path: path in [default_path, user_path]
        yield


def test_loads_default_config(mock_fs):
    """
    Test that ConfigManager loads default values correctly.
    """
    with patch.dict(os.environ, {"BRS_XSS_CONFIG_PATH": "/etc/brs-xss/default.yaml"}):
        cm = ConfigManager()
        assert cm.get("scanner.timeout") == 15
        assert cm.get("scanner.user_agent") == "BRS-XSS Default"


def test_overrides_with_user_config(mock_fs):
    """
    Test that user configuration correctly overrides default values.
    """
    with patch.dict(
        os.environ,
        {
            "BRS_XSS_CONFIG_PATH": "/etc/brs-xss/default.yaml",
            "BRS_XSS_USER_CONFIG_PATH": os.path.expanduser(
                "~/.config/brs-xss/user.toml"
            ),
        },
    ):
        cm = ConfigManager()
        # This value should be from user.toml
        assert cm.get("scanner.timeout") == 30
        # This value should remain from default.yaml
        assert cm.get("scanner.user_agent") == "BRS-XSS Default"


def test_get_nested_value(mock_fs):
    """
    Test that nested values can be retrieved with dot notation.
    """
    with patch.dict(os.environ, {"BRS_XSS_CONFIG_PATH": "/etc/brs-xss/default.yaml"}):
        cm = ConfigManager()
        assert cm.get("scoring.weights.impact") == 0.4
