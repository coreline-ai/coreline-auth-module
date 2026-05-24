"""Environment-backed settings for the Coreline Auth SaaS demo."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from coreline_auth.security import generate_token


@dataclass(frozen=True, slots=True)
class DemoSettings:
    owner_email: str
    owner_password: str
    db_path: Path
    demo_mode: bool
    csrf_secret: str
    csrf_secret_configured: bool


def load_demo_settings() -> DemoSettings:
    csrf_secret_configured = "CORELINE_AUTH_DEMO_CSRF_SECRET" in os.environ
    return DemoSettings(
        owner_email=os.getenv("CORELINE_AUTH_DEMO_OWNER_EMAIL", "owner@example.com"),
        owner_password=os.getenv("CORELINE_AUTH_DEMO_OWNER_PASSWORD", "coreline-" + "demo-password"),
        db_path=Path(os.getenv("CORELINE_AUTH_DEMO_DB", ".coreline-auth-demo/auth.sqlite3")),
        demo_mode=os.getenv("CORELINE_AUTH_DEMO_MODE", "true").strip().lower() in {"1", "true", "yes", "on"},
        csrf_secret=os.getenv("CORELINE_AUTH_DEMO_CSRF_SECRET") or generate_token(),
        csrf_secret_configured=csrf_secret_configured,
    )
