#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - No marketing wording lint
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 03:40:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path


def test_no_marketing_wording_in_user_facing_text():
    repo = Path(__file__).resolve().parents[2]
    banned = [
        "production-ready",
        "enterprise-grade",
        "world-class",
        "state-of-the-art",
    ]
    # Scope: CLI, top-level README/CHANGELOG, report module (excluding KB content)
    include_paths = [
        repo / "cli",
        repo / "README.md",
        repo / "CHANGELOG.md",
        repo / "brsxss" / "report",
    ]
    exclude_dirs = {
        str(repo / "brsxss" / "report" / "knowledge_base"),
        str(repo / "venv"),
        str(repo / "results"),
        str(repo / ".git"),
    }

    def should_scan(p: Path) -> bool:
        if any(str(p).startswith(ed + "/") for ed in exclude_dirs):
            return False
        if p.is_dir():
            return True
        # Text-like files only
        return p.suffix in {".py", ".md", ".txt"}

    violations = []
    for root in include_paths:
        if root.is_file():
            files = [root]
        else:
            files = [p for p in root.rglob("*") if should_scan(p) and p.is_file()]
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for word in banned:
                if word in text:
                    violations.append((str(f.relative_to(repo)), word.strip()))

    assert not violations, f"Marketing wording found: {violations}"


