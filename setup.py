#!/usr/bin/env python3

# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Thu 09 Jan 2026 UTC
# Status: Beta - v4.0.0-beta.1
# Telegram: https://t.me/EasyProTech

"""
Legacy setup.py for backward compatibility.
Main configuration is in pyproject.toml.
Version is read dynamically from pyproject.toml.
"""

from setuptools import setup, find_packages


# Read version from pyproject.toml
def get_version():
    try:
        import toml

        with open("pyproject.toml", "r") as f:
            data = toml.load(f)
            return data.get("project", {}).get("version", "4.0.0-beta.1")
    except Exception:
        # Fallback: parse manually
        try:
            with open("pyproject.toml", "r") as f:
                for line in f:
                    if line.strip().startswith("version"):
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            return parts[1].strip().strip('"').strip("'")
        except Exception:
            pass
    return "4.0.0-beta.1"


if __name__ == "__main__":
    setup(
        name="brs-xss",
        version=get_version(),
        packages=find_packages(exclude=["tests", "tests.*", "benchmarks"]),
        entry_points={
            "console_scripts": [
                "brs-xss=cli.main:app",
            ],
        },
    )
