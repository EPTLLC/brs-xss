#!/usr/bin/env python3

"""
Project: BRS-XSS Version Bumper
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 09 Jan 2026 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Script to update version across all project files.
Single command to bump version everywhere.

Usage:
    python scripts/bump_version.py 4.0.0-beta.2
    python scripts/bump_version.py --show  # Show current version
"""

import re
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent


def get_current_version() -> str:
    """Get current version from pyproject.toml"""
    pyproject = PROJECT_ROOT / "pyproject.toml"
    content = pyproject.read_text()
    match = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
    if match:
        return match.group(1)
    return "unknown"


def update_pyproject(new_version: str) -> bool:
    """Update version in pyproject.toml"""
    pyproject = PROJECT_ROOT / "pyproject.toml"
    content = pyproject.read_text()
    new_content = re.sub(
        r'^(version\s*=\s*["\'])([^"\']+)(["\'])',
        f"\\g<1>{new_version}\\g<3>",
        content,
        flags=re.MULTILINE,
    )
    if new_content != content:
        pyproject.write_text(new_content)
        print(f"[OK] pyproject.toml: {new_version}")
        return True
    return False


def update_readme(new_version: str) -> bool:
    """Update version badge in README.md"""
    readme = PROJECT_ROOT / "README.md"
    content = readme.read_text()

    # Update version badge
    new_content = re.sub(
        r"(version-)[^-]+(-.+\.svg)", f"\\g<1>{new_version}\\g<2>", content
    )

    # Update beta warning if present
    new_content = re.sub(
        r"(v)\d+\.\d+\.\d+(-beta\.\d+)?( includes)",
        f"\\g<1>{new_version}\\g<3>",
        new_content,
    )

    if new_content != content:
        readme.write_text(new_content)
        print(f"[OK] README.md: {new_version}")
        return True
    return False


def update_dockerfile(new_version: str) -> bool:
    """Update version in Dockerfile"""
    dockerfile = PROJECT_ROOT / "Dockerfile"
    if not dockerfile.exists():
        return False

    content = dockerfile.read_text()

    # Update label
    new_content = re.sub(
        r'(org\.opencontainers\.image\.version=")[^"]+(")',
        f"\\g<1>{new_version}\\g<2>",
        content,
    )

    # Update comment
    new_content = re.sub(
        r"(# BRS-XSS v)\d+\.\d+\.\d+(-beta\.\d+)?", f"\\g<1>{new_version}", new_content
    )

    if new_content != content:
        dockerfile.write_text(new_content)
        print(f"[OK] Dockerfile: {new_version}")
        return True
    return False


def update_version_py(new_version: str) -> bool:
    """Update fallback version and comments in version.py"""
    version_py = PROJECT_ROOT / "brsxss" / "version.py"
    content = version_py.read_text()

    # Update fallback version
    new_content = re.sub(
        r'(or\s*["\'])\d+\.\d+\.\d+(-beta\.\d+)?(["\'])',
        f"\\g<1>{new_version}\\g<3>",
        content,
    )

    # Update header comments
    new_content = re.sub(
        r"(Project: BRS-XSS v)\d+\.\d+\.\d+(-beta\.\d+)?",
        f"\\g<1>{new_version}",
        new_content,
    )
    new_content = re.sub(
        r"(Status: Beta - v)\d+\.\d+\.\d+(-beta\.\d+)?",
        f"\\g<1>{new_version}",
        new_content,
    )

    if new_content != content:
        version_py.write_text(new_content)
        print(f"[OK] brsxss/version.py: {new_version}")
        return True
    return False


def update_init_py(new_version: str) -> bool:
    """Update __init__.py header"""
    init_py = PROJECT_ROOT / "brsxss" / "__init__.py"
    content = init_py.read_text()

    new_content = re.sub(
        r"(Status: Beta - v)\d+\.\d+\.\d+(-beta\.\d+)?", f"\\g<1>{new_version}", content
    )

    if new_content != content:
        init_py.write_text(new_content)
        print(f"[OK] brsxss/__init__.py: {new_version}")
        return True
    return False


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("--help", "-h"):
        print("Usage: python scripts/bump_version.py <new_version>")
        print("       python scripts/bump_version.py --show")
        print("\nExample: python scripts/bump_version.py 4.0.0-beta.2")
        sys.exit(0 if sys.argv[1:] and sys.argv[1] in ("--help", "-h") else 1)

    if sys.argv[1] == "--show":
        print(f"Current version: {get_current_version()}")
        sys.exit(0)

    new_version = sys.argv[1]

    # Validate version format
    if not re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$", new_version):
        print(f"ERROR: Invalid version format: {new_version}")
        print("Expected format: X.Y.Z or X.Y.Z-suffix (e.g., 4.0.0-beta.2)")
        sys.exit(1)
    current = get_current_version()

    print(f"Bumping version: {current} -> {new_version}")
    print("-" * 40)

    updated = 0
    updated += update_pyproject(new_version)
    updated += update_readme(new_version)
    updated += update_dockerfile(new_version)
    updated += update_version_py(new_version)
    updated += update_init_py(new_version)

    print("-" * 40)
    print(f"Updated {updated} files")
    print('\nVerify: python -c "import brsxss; print(brsxss.__version__)"')


if __name__ == "__main__":
    main()
