#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0-beta.2
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 09 Jan 2026 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Custom Payloads Loader - allows users to add their own XSS payloads.

Supported formats:
1. Plain text file (one payload per line)
2. YAML file with structured payloads

Default locations:
- ~/.brs-xss/custom_payloads.txt
- ~/.brs-xss/custom_payloads.yaml

Can also be specified via:
- CLI: --custom-payloads /path/to/file
- Environment: BRS_XSS_CUSTOM_PAYLOADS=/path/to/file
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from brsxss.utils.logger import Logger

logger = Logger("core.custom_payloads")


@dataclass
class CustomPayload:
    """Custom payload with optional metadata"""

    payload: str
    context: Optional[str] = None  # html_content, attribute, javascript, etc.
    tags: list[str] = field(default_factory=list)
    description: Optional[str] = None

    def __hash__(self):
        return hash(self.payload)

    def __eq__(self, other):
        if isinstance(other, CustomPayload):
            return self.payload == other.payload
        return False


class CustomPayloadsLoader:
    """
    Loader for user-defined custom payloads.

    Supports:
    - Plain text files (one payload per line)
    - YAML files with structured payloads
    - Multiple file sources
    """

    DEFAULT_LOCATIONS = [
        Path.home() / ".brs-xss" / "custom_payloads.txt",
        Path.home() / ".brs-xss" / "custom_payloads.yaml",
        Path.home() / ".brs-xss" / "custom_payloads.yml",
        Path.home() / ".config" / "brs-xss" / "custom_payloads.txt",
        Path.home() / ".config" / "brs-xss" / "custom_payloads.yaml",
    ]

    def __init__(self):
        self._payloads: list[CustomPayload] = []
        self._loaded_files: list[str] = []

    def load_from_env(self) -> int:
        """Load from environment variable BRS_XSS_CUSTOM_PAYLOADS"""
        env_path = os.environ.get("BRS_XSS_CUSTOM_PAYLOADS")
        if env_path:
            return self.load_from_file(Path(env_path))
        return 0

    def load_from_defaults(self) -> int:
        """Load from default locations"""
        total = 0
        for path in self.DEFAULT_LOCATIONS:
            if path.exists():
                total += self.load_from_file(path)
        return total

    def load_from_file(self, path: Path) -> int:
        """
        Load payloads from a file.

        Args:
            path: Path to payload file

        Returns:
            Number of payloads loaded
        """
        if not path.exists():
            logger.warning(f"Custom payloads file not found: {path}")
            return 0

        if str(path) in self._loaded_files:
            return 0  # Already loaded

        try:
            suffix = path.suffix.lower()

            if suffix in (".yaml", ".yml"):
                count = self._load_yaml(path)
            else:
                count = self._load_text(path)

            if count > 0:
                self._loaded_files.append(str(path))
                logger.info(f"Loaded {count} custom payloads from {path}")

            return count

        except Exception as e:
            logger.error(f"Failed to load custom payloads from {path}: {e}")
            return 0

    def _load_text(self, path: Path) -> int:
        """Load plain text file (one payload per line)"""
        content = path.read_text(encoding="utf-8")
        count = 0

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            payload = CustomPayload(payload=line)
            if payload not in self._payloads:
                self._payloads.append(payload)
                count += 1

        return count

    def _load_yaml(self, path: Path) -> int:
        """Load YAML file with structured payloads"""
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not installed, falling back to text parsing")
            return self._load_text(path)

        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)

        if not data:
            return 0

        count = 0
        payloads_list = data.get("payloads", data if isinstance(data, list) else [])

        for item in payloads_list:
            if isinstance(item, str):
                payload = CustomPayload(payload=item)
            elif isinstance(item, dict):
                payload = CustomPayload(
                    payload=item.get("payload", ""),
                    context=item.get("context"),
                    tags=item.get("tags", []),
                    description=item.get("description"),
                )
            else:
                continue

            if payload.payload and payload not in self._payloads:
                self._payloads.append(payload)
                count += 1

        return count

    def get_payloads(self) -> list[CustomPayload]:
        """Get all loaded custom payloads"""
        return self._payloads.copy()

    def get_payload_strings(self) -> list[str]:
        """Get just the payload strings"""
        return [p.payload for p in self._payloads]

    def get_payloads_for_context(self, context: str) -> list[CustomPayload]:
        """Get payloads filtered by context"""
        return [p for p in self._payloads if p.context is None or p.context == context]

    def count(self) -> int:
        """Get number of loaded payloads"""
        return len(self._payloads)

    def clear(self):
        """Clear all loaded payloads"""
        self._payloads.clear()
        self._loaded_files.clear()


# Global instance
_loader: Optional[CustomPayloadsLoader] = None


def get_custom_payloads_loader() -> CustomPayloadsLoader:
    """Get or create global custom payloads loader"""
    global _loader
    if _loader is None:
        _loader = CustomPayloadsLoader()
    return _loader


def load_custom_payloads(
    custom_file: Optional[str] = None,
    load_defaults: bool = True,
) -> list[str]:
    """
    Convenience function to load custom payloads.

    Args:
        custom_file: Optional path to custom payloads file
        load_defaults: Whether to load from default locations

    Returns:
        List of payload strings
    """
    loader = get_custom_payloads_loader()

    # Load from environment
    loader.load_from_env()

    # Load from defaults
    if load_defaults:
        loader.load_from_defaults()

    # Load from specified file
    if custom_file:
        loader.load_from_file(Path(custom_file))

    return loader.get_payload_strings()


def create_example_file():
    """Create example custom payloads file"""
    example_dir = Path.home() / ".brs-xss"
    example_dir.mkdir(parents=True, exist_ok=True)

    example_txt = example_dir / "custom_payloads.txt.example"
    example_yaml = example_dir / "custom_payloads.yaml.example"

    txt_content = """# BRS-XSS Custom Payloads
# One payload per line. Lines starting with # are comments.

# Basic payloads
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>

# Event handlers
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

# SVG payloads
<svg><script>alert(1)</script></svg>
<svg onload=alert(1)>

# Add your custom payloads below:
"""

    yaml_content = """# BRS-XSS Custom Payloads (YAML format)
# Structured format with optional metadata

payloads:
  # Simple payload (string only)
  - "<script>alert('custom')</script>"

  # Payload with context hint
  - payload: "<img src=x onerror=alert(1)>"
    context: html_content
    tags: [img, onerror]
    description: "Image tag with onerror handler"

  # Payload for attribute context
  - payload: "javascript:alert(1)"
    context: href_attribute
    tags: [javascript, uri]

  # Payload for JavaScript context
  - payload: "';alert(1);//"
    context: javascript
    tags: [string_break]

# Add your custom payloads below:
"""

    if not example_txt.exists():
        example_txt.write_text(txt_content)
        logger.info(f"Created example file: {example_txt}")

    if not example_yaml.exists():
        example_yaml.write_text(yaml_content)
        logger.info(f"Created example file: {example_yaml}")
