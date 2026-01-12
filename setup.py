#!/usr/bin/env python3

# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Fri 10 Jan 2026 UTC
# Status: Beta - v4.0.0-beta.2
# Telegram: https://t.me/EasyProTech

"""
Legacy setup.py for backward compatibility.
Main configuration is in pyproject.toml.
Version and dependencies are read dynamically from pyproject.toml.
"""

from setuptools import setup, find_packages


def get_version():
    """Read version from pyproject.toml."""
    try:
        import toml

        with open("pyproject.toml", "r") as f:
            data = toml.load(f)
            return data.get("project", {}).get("version", "4.0.0-beta.2")
    except Exception:
        pass

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
    return "4.0.0-beta.2"


def get_dependencies():
    """Read dependencies from pyproject.toml."""
    deps = []
    try:
        import toml

        with open("pyproject.toml", "r") as f:
            data = toml.load(f)
            deps = data.get("project", {}).get("dependencies", [])
            return deps
    except Exception:
        pass

    # Fallback: parse manually from pyproject.toml
    try:
        with open("pyproject.toml", "r") as f:
            content = f.read()
            # Find dependencies section
            import re

            match = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
            if match:
                deps_str = match.group(1)
                # Extract quoted strings
                deps = re.findall(r'"([^"]+)"', deps_str)
                return deps
    except Exception:
        pass

    # Ultimate fallback: hardcoded list (sync with pyproject.toml)
    return [
        "aiohttp>=3.8,<4.0",
        "aiohttp-socks>=0.8,<1.0",
        "typer>=0.16,<0.17",
        "rich>=13.0,<14.0",
        "pyyaml>=6.0,<7.0",
        "jinja2>=3.1,<4.0",
        "babel>=2.12,<3.0",
        "polib>=1.2,<2.0",
        "playwright>=1.40.0,<1.60.0",
        "beautifulsoup4>=4.12.3,<4.13",
        "brs-kb>=4.0.0",
        "pydantic>=2.0.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "websockets>=11.0",
        "aiofiles>=23.0.0",
        "weasyprint>=60.0,<62.0",
    ]


if __name__ == "__main__":
    setup(
        name="brs-xss",
        version=get_version(),
        description="Context-aware async XSS scanner powered by BRS-KB",
        author="Brabus",
        license="MIT",
        python_requires=">=3.10",
        packages=find_packages(exclude=["tests", "tests.*", "benchmarks"]),
        install_requires=get_dependencies(),
        entry_points={
            "console_scripts": [
                "brs-xss=cli.main:app",
            ],
        },
    )
