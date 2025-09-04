#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 22:36:10 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import os
import re
import tempfile
from pathlib import Path


def sanitize_filename(name: str, max_len: int = 128) -> str:
    """Sanitize a string to be a safe filename."""
    name = name.replace('https://', '').replace('http://', '')
    name = re.sub(r"/+", "_", name)
    name = re.sub(r"[^\w\-_.]", "_", name)
    name = re.sub(r"_{2,}", "_", name).strip("._-")
    if len(name) > max_len:
        name = name[:max_len].rstrip("._-")
    return name or "report"


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def atomic_write(file_path: str, content: str, mode: str = "w", encoding: str = "utf-8") -> None:
    """Write to a temp file and atomically replace the target file."""
    target = Path(file_path)
    ensure_dir(str(target.parent))
    fd, tmp_path = tempfile.mkstemp(prefix=target.stem + "_", suffix=target.suffix, dir=str(target.parent))
    try:
        with os.fdopen(fd, mode, encoding=encoding) as f:
            f.write(content)
        os.replace(tmp_path, file_path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def build_result_path(base_dir: str, filename: str, ext: str) -> str:
    ensure_dir(base_dir)
    safe_name = sanitize_filename(filename)
    return str(Path(base_dir) / f"{safe_name}{ext}")


