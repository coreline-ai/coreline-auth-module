"""Standalone Board RBAC demo app for Coreline Auth self-tests.

Run from the ``packages/coreline-auth`` checkout:

  PYTHONPATH=.:src uv run uvicorn demos.board_rbac.app:app --reload --port 8011

This app is intentionally outside ``src/coreline_auth``. It demonstrates how a
host app can consume Coreline Auth while keeping board roles and permissions in
its own domain boundary.
"""

from __future__ import annotations

import html
import hmac
import secrets
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from coreline_auth import AuthProfile, AuthenticationFailed, CorelineAuthConfig, CorelineAuthService, Role
from coreline_auth.storage import MemoryAuthStorage, SQLiteAuthStorage

from .auth_adapter import CorelineAuthUserDirectory, DemoBoardSessionVerifier
from .config import BoardDemoSettings, load_demo_settings
from .layout import render_page
from .seed import DEMO_BOARD_PASSWORD, DEMO_BOARD_USERS, seed_demo_board
from .service import BoardService
from .storage import MemoryBoardStorage, SQLiteBoardStorage
from .web import BoardWebSettings, mount_board_routes

BOARD_LOGOUT_CSRF_COOKIE = "coreline_board_demo_logout_csrf"


def create_app(
    *,
    board_prefix: str = "/demo-board",
    db_path: str | Path | None = None,
    auth_db_path: str | Path | None = None,
    use_sqlite: bool = False,
    settings: BoardDemoSettings | None = None,
) -> FastAPI:
    settings = settings or BoardDemoSettings(
        board_prefix=board_prefix,
        db_path=Path(db_path or ":memory:"),
        auth_db_path=Path(auth_db_path or ":memory:"),
        demo_mode=True,
    )
    _validate_prefix(settings.board_prefix)
    use_sqlite = use_sqlite or settings.use_sqlite
    auth_storage = SQLiteAuthStorage(settings.auth_db_path) if use_sqlite else MemoryAuthStorage()
    _migrate_legacy_board_auth_roles(auth_storage)
    auth = CorelineAuthService(
        storage=auth_storage,
        config=CorelineAuthConfig(profile=AuthProfile.RBAC, owner_email=None, require_email_verified=False),
    )
    board_storage = SQLiteBoardStorage(settings.db_path) if use_sqlite else MemoryBoardStorage()
    seeded_users = seed_demo_board(auth, board_storage)
    board_roles_by_user_id = {user.id: board_role for board_role, user in seeded_users.items()}
    service = BoardService(storage=board_storage)

    app = FastAPI(title="Coreline Auth Board RBAC Demo")
    app.state.auth = auth
    app.state.board_storage = board_storage
    app.state.board_service = service
    app.state.board_roles_by_user_id = board_roles_by_user_id
    app.state.board_demo_settings = settings

    web_settings = BoardWebSettings(
        prefix=settings.board_prefix,
        login_path="/login",
        logout_path="/logout",
        dashboard_path="/",
        session_cookie_name=settings.session_cookie_name,
        csrf_cookie_name=settings.csrf_cookie_name,
    )

    def board_page(title: str, body: str) -> HTMLResponse:
        return render_page(title, body, board_prefix=settings.board_prefix, login_path="/login", logout_path="/logout", dashboard_path="/")

    mount_board_routes(
        app,
        session_verifier=DemoBoardSessionVerifier(auth, board_roles_by_user_id),
        board_service=service,
        user_directory=CorelineAuthUserDirectory(auth),
        render_page=board_page,
        settings=web_settings,
    )

    @app.get("/", response_class=HTMLResponse)
    def home() -> HTMLResponse:
        return render_page(
            "Coreline Auth Board RBAC Demo",
            f"""
            <h1>Coreline Auth Board RBAC Demo</h1>
            <p class='muted'>인증 코어 밖에서 Coreline Auth를 소비하는 권한별 게시판 데모입니다. 계정을 선택하면 로그인 폼이 해당 이메일로 채워집니다.</p>
            <section class='card'><h2>권한별 테스트 계정</h2><p>공통 비밀번호: <code>{DEMO_BOARD_PASSWORD}</code></p>{_account_cards(settings.board_prefix)}</section>
            <section class='card'><h2>역할 경계</h2><p><code>owner/admin/viewer/user</code>는 Coreline Auth role이고, <code>author/moderator</code>는 이 board demo 내부 role mapping입니다.</p></section>
            <a class='button' href='{html.escape(settings.board_prefix)}'>게시판 열기</a>
            """,
            board_prefix=settings.board_prefix,
        )

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> HTMLResponse:
        selected_email = _selected_email(request.query_params.get("email")) if settings.demo_mode else None
        email = selected_email or "owner-board@example.com"
        next_path = _safe_next(request.query_params.get("next"), default=settings.board_prefix)
        password_value = DEMO_BOARD_PASSWORD if settings.demo_mode else ""
        return render_page(
            "Board RBAC Login",
            f"""
            <h1>Board RBAC Login</h1>
            <section class='card'><form method='post' action='/login'>
              <label>Email</label><input name='email' type='email' value='{html.escape(email, quote=True)}' required>
              <label>Password</label><input name='password' type='password' value='{html.escape(password_value, quote=True)}' required>
              <input type='hidden' name='next' value='{html.escape(next_path, quote=True)}'>
              <button>로그인</button>
            </form></section>
            <details class='card role-accounts' open><summary><h2>권한별 테스트 계정</h2><span class='muted'>클릭하면 이메일이 선택됩니다.</span></summary>{_account_table(settings.board_prefix)}</details>
            """,
            board_prefix=settings.board_prefix,
        )

    @app.post("/login")
    def login(email: str = Form(...), password: str = Form(...), next: str = Form("/demo-board")):
        try:
            issued = auth.login_password(email=email, password=password)
        except (AuthenticationFailed, Exception) as exc:
            return render_page("Login failed", f"<section class='card error'><h1>로그인 실패</h1><p>{html.escape(str(exc))}</p></section>", board_prefix=settings.board_prefix)
        response = RedirectResponse(_safe_next(next, default=settings.board_prefix), status_code=303)
        response.set_cookie(settings.session_cookie_name, issued.token, httponly=True, samesite="lax", path="/")
        return response

    @app.get("/logout", response_class=HTMLResponse)
    def logout_page(request: Request) -> HTMLResponse:
        token = _logout_csrf_token_for_request(request)
        response = render_page(
            "Board RBAC Logout",
            f"<h1>Board RBAC Logout</h1><section class='card'><p class='muted'>로그아웃은 세션 상태를 변경하므로 CSRF 토큰이 필요합니다.</p><form method='post' action='/logout'>{_logout_csrf_field(token)}<button class='danger'>로그아웃</button> <a class='button secondary' href='{html.escape(settings.board_prefix)}'>취소</a></form></section>",
            board_prefix=settings.board_prefix,
        )
        _issue_logout_csrf_cookie(response, token)
        return response

    @app.post("/logout")
    def logout(request: Request, csrf_token: str = Form("")):
        if not _require_logout_csrf(request, csrf_token):
            return Response("Forbidden", status_code=403)
        token = request.cookies.get(settings.session_cookie_name)
        if token:
            auth.logout(token)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(settings.session_cookie_name, path="/")
        response.delete_cookie(BOARD_LOGOUT_CSRF_COOKIE, path="/")
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    return app


def _account_cards(board_prefix: str) -> str:
    cards = []
    for entry in DEMO_BOARD_USERS:
        href = f"/login?email={html.escape(entry.email, quote=True)}&next={html.escape(board_prefix, quote=True)}"
        cards.append(
            f"""
            <a class='account-card' href='{href}' data-board-role='{html.escape(entry.board_role)}'>
              <h3>{html.escape(entry.headline)} <span class='pill'>{html.escape(entry.board_role)}</span></h3>
              <code>{html.escape(entry.email)}</code>
              <span class='muted'>Auth role: {html.escape(entry.auth_role.value)}</span>
              <span>{html.escape(entry.expected_permission)}</span>
            </a>
            """
        )
    return f"<div class='account-grid'>{''.join(cards)}</div>"


def _account_table(board_prefix: str) -> str:
    rows = "".join(
        f"<tr><td><a href='/login?email={html.escape(entry.email, quote=True)}&next={html.escape(board_prefix, quote=True)}'><code>{html.escape(entry.email)}</code></a></td><td>{html.escape(entry.board_role)}</td><td>{html.escape(entry.auth_role.value)}</td><td>{html.escape(entry.expected_permission)}</td></tr>"
        for entry in DEMO_BOARD_USERS
    )
    return f"<table class='role-table'><thead><tr><th>Email</th><th>Board role</th><th>Auth role</th><th>검증 항목</th></tr></thead><tbody>{rows}</tbody></table>"


def _selected_email(value: str | None) -> str | None:
    if not value or "@" not in value or len(value) > 320 or any(char in value for char in "\r\n"):
        return None
    allowed = {entry.email for entry in DEMO_BOARD_USERS}
    return value if value in allowed else None


def _safe_next(value: str | None, *, default: str) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "://" in value or "\r" in value or "\n" in value:
        return default
    return value


def _logout_csrf_token_for_request(request: Request) -> str:
    return request.cookies.get(BOARD_LOGOUT_CSRF_COOKIE) or secrets.token_urlsafe(32)


def _issue_logout_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(BOARD_LOGOUT_CSRF_COOKIE, token, httponly=False, samesite="lax", path="/")


def _logout_csrf_field(token: str) -> str:
    return f"<input type='hidden' name='csrf_token' value='{html.escape(token, quote=True)}'>"


def _require_logout_csrf(request: Request, form_token: str) -> bool:
    cookie_token = request.cookies.get(BOARD_LOGOUT_CSRF_COOKIE)
    return bool(form_token and cookie_token and hmac.compare_digest(form_token, cookie_token))


def _migrate_legacy_board_auth_roles(storage: MemoryAuthStorage | SQLiteAuthStorage) -> None:
    """Convert pre-split demo auth rows to auth-core roles before reads."""

    if not isinstance(storage, SQLiteAuthStorage):
        return
    user_permissions_json = '["dashboard:read", "profile:read"]'
    with storage._lock:  # demo-only compatibility path; public reads would fail before migration.
        storage.db.execute("UPDATE auth_users SET role = 'user' WHERE role IN ('author', 'moderator')")
        storage.db.execute(
            "UPDATE auth_sessions SET role = 'user', permissions_json = ? WHERE role IN ('author', 'moderator')",
            (user_permissions_json,),
        )
        storage.db.commit()


def _validate_prefix(prefix: str) -> None:
    if not prefix.startswith("/") or prefix.startswith("//") or "\r" in prefix or "\n" in prefix:
        raise ValueError("board_prefix must be an absolute local path")


app = create_app(settings=load_demo_settings())
