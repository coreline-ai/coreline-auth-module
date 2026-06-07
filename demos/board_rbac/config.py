"""Environment-backed settings for the board RBAC demo."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class BoardDemoSettings:
    board_prefix: str = "/demo-board"
    db_path: Path = Path(".coreline-auth-demo/board-rbac.sqlite3")
    auth_db_path: Path = Path(".coreline-auth-demo/board-rbac-auth.sqlite3")
    demo_mode: bool = True
    session_cookie_name: str = "coreline_board_demo_session"
    csrf_cookie_name: str = "coreline_board_demo_csrf"

    @property
    def use_sqlite(self) -> bool:
        return str(self.db_path) != ":memory:"


def load_demo_settings(env: dict[str, str] | None = None) -> BoardDemoSettings:
    values = env if env is not None else dict(os.environ)
    db_path = Path(values.get("CORELINE_BOARD_DEMO_DB", ".coreline-auth-demo/board-rbac.sqlite3"))
    auth_db_path = Path(values.get("CORELINE_BOARD_DEMO_AUTH_DB", ".coreline-auth-demo/board-rbac-auth.sqlite3"))
    return BoardDemoSettings(
        board_prefix=values.get("CORELINE_BOARD_DEMO_PREFIX", "/demo-board"),
        db_path=db_path,
        auth_db_path=auth_db_path,
        demo_mode=_as_bool(values.get("CORELINE_BOARD_DEMO_MODE"), True),
        session_cookie_name=values.get("CORELINE_BOARD_DEMO_SESSION_COOKIE", "coreline_board_demo_session"),
        csrf_cookie_name=values.get("CORELINE_BOARD_DEMO_CSRF_COOKIE", "coreline_board_demo_csrf"),
    )


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
