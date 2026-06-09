from __future__ import annotations

import sys
from pathlib import Path


def runtime_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def runtime_private_dir() -> Path:
    return runtime_base_dir() / "private"
