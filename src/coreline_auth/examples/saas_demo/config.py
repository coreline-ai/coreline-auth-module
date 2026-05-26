"""Environment-backed settings for the Coreline Auth SaaS demo."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from coreline_auth.security import generate_token

_CSRF_SECRET_FILE_NAME = "csrf.secret"


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
    db_path = Path(os.getenv("CORELINE_AUTH_DEMO_DB", ".coreline-auth-demo/auth.sqlite3"))
    return DemoSettings(
        owner_email=os.getenv("CORELINE_AUTH_DEMO_OWNER_EMAIL", "owner@example.com"),
        owner_password=os.getenv("CORELINE_AUTH_DEMO_OWNER_PASSWORD", "coreline-" + "demo-password"),
        db_path=db_path,
        demo_mode=os.getenv("CORELINE_AUTH_DEMO_MODE", "true").strip().lower() in {"1", "true", "yes", "on"},
        csrf_secret=os.getenv("CORELINE_AUTH_DEMO_CSRF_SECRET") or _load_or_create_demo_csrf_secret(db_path),
        csrf_secret_configured=csrf_secret_configured,
    )


def _load_or_create_demo_csrf_secret(db_path: Path) -> str:
    """Keep local demo CSRF stable across uvicorn --reload restarts.

    Without this, editing the demo while a browser tab is open rotates the
    in-memory secret and makes existing logout forms fail with "Invalid CSRF
    token". The file is scoped to the local demo data directory and should not
    be used as a production secret source.
    """

    secret_path = db_path.parent / _CSRF_SECRET_FILE_NAME
    try:
        existing = secret_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        existing = ""
    if existing:
        return existing
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret = generate_token()
    secret_path.write_text(secret + "\n", encoding="utf-8")
    try:
        secret_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return secret
