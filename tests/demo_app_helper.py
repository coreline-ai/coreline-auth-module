from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

import pytest


def load_demo_app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ModuleType:
    """Load the demo app against a per-test SQLite DB.

    The demo module owns global app/storage objects, so tests must not import it
    at module import time. Reloading with a temporary DB prevents smoke tests
    from mutating a developer's live demo database.
    """

    monkeypatch.setenv("CORELINE_AUTH_DEMO_DB", str(tmp_path / "auth.sqlite3"))
    sys.modules.pop("coreline_auth.examples.saas_app", None)
    return importlib.import_module("coreline_auth.examples.saas_app")
