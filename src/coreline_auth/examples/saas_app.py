"""A complete but small SaaS-style web app for self-testing Coreline Auth.

Run:
  cd packages/coreline-auth
  uv run uvicorn coreline_auth.examples.saas_app:app --reload --port 8010

Default admin login:
  owner@example.com / CORELINE_AUTH_DEMO_OWNER_PASSWORD default

This demo also supports local email/password signup. Google/Facebook links start
real OAuth when provider credentials are configured, and otherwise use the
development social connector for local end-to-end testing.
"""

from __future__ import annotations

import html
import os

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from coreline_auth import AuditEvent, AuthProfile, AuthenticationFailed, CorelineAuthConfig, CorelineAuthService, CsrfProtector, DevSocialConnector, FacebookOAuthConnector, GoogleOAuthConnector, InMemoryEmailSender, Role
from coreline_auth.examples.board_seed import DEMO_BOARD_PASSWORD, DEMO_BOARD_USERS, seed_demo_board
from coreline_auth.examples.board_service import BoardService
from coreline_auth.examples.board_storage import SQLiteBoardStorage
from coreline_auth.examples.board_web import mount_board_routes
from coreline_auth.fastapi_adapter import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, mount_admin_routes, mount_auth_routes, request_context
from coreline_auth.storage import SQLiteAuthStorage
from coreline_auth.examples.saas_demo.config import load_demo_settings
from coreline_auth.examples.saas_demo.csrf import csrf_token_for_page, demo_csrf_middleware
from coreline_auth.examples.saas_demo.layout import render_page

settings = load_demo_settings()
OWNER_EMAIL = settings.owner_email
OWNER_PASSWORD = settings.owner_password
DB_PATH = settings.db_path
DEMO_MODE = settings.demo_mode

storage = SQLiteAuthStorage(DB_PATH)
email_sender = InMemoryEmailSender()
audit_events: list[AuditEvent] = []
csrf = CsrfProtector(secret_key=settings.csrf_secret, allow_weak_dev_secret=DEMO_MODE and settings.csrf_secret_configured)
auth = CorelineAuthService(
    storage=storage,
    config=CorelineAuthConfig(profile=AuthProfile.RBAC, owner_email=None, require_email_verified=False),
    email_sender=email_sender,
    audit_sink=audit_events.append,
)
existing_owner = auth.storage.get_user_by_email(OWNER_EMAIL)
if existing_owner is None:
    auth.create_user(email=OWNER_EMAIL, role=Role.ADMIN, password=OWNER_PASSWORD, email_verified=True, display_name="Coreline Admin")
elif DEMO_MODE:
    # Keep the local self-test app recoverable even when a previous demo DB was
    # created with a different password during development.
    auth.set_password(existing_owner.id, OWNER_PASSWORD)

app = FastAPI(title="Coreline Auth Demo SaaS")
mount_auth_routes(app, auth, expose_magic_link_token=DEMO_MODE, secure_cookies=False)
mount_admin_routes(app, auth)


def page(title: str, body: str, *, public: bool = False) -> HTMLResponse:
    return render_page(
        title=title,
        body=body,
        csrf_token=csrf_token_for_page(csrf),
        public=public,
        demo_mode=DEMO_MODE,
        role_entries=DEMO_BOARD_USERS,
    )


def safe_next_path(value: str | None, *, default: str = "/") -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\r" in value or "\n" in value:
        return default
    return value


def current_principal(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    try:
        return auth.verify_session(token)
    except AuthenticationFailed:
        return None


board_storage = SQLiteBoardStorage(DB_PATH)
if DEMO_MODE:
    seed_demo_board(auth, board_storage)
board_service = BoardService(auth, storage=board_storage)
mount_board_routes(app, auth, board_service=board_service, render_page=page)


app.middleware("http")(demo_csrf_middleware(csrf))

@app.get("/healthz")
def healthz() -> dict[str, bool]:
    return {"ok": True}


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    principal = current_principal(request)
    if principal is None:
        return RedirectResponse("/login", status_code=303)
    return page(
        "Coreline Auth Dashboard",
        f"""
        <h1>Coreline Auth Demo</h1>
        <p class='muted'>가입, 로그인, 세션, 권한 보호 페이지를 검증하는 자체 테스트 앱입니다.</p>
        <section class='card'>
          <h2>로그인 상태</h2>
          <p><b>Email</b>: {html.escape(principal.email)}</p>
          <p><b>Role</b>: {html.escape(principal.session.role.value)}</p>
          <p><b>Permissions</b>: <code>{html.escape(', '.join(principal.session.permissions))}</code></p>
          <p><b>Status</b>: <code>{html.escape(principal.user.status.value)}</code></p>
          <div class='nav'><a class='button' href='/board'>게시판 열기</a><a class='button secondary' href='/admin'>관리자 페이지 열기</a><form method='post' action='/logout' style='display:inline'><button class='danger'>로그아웃</button></form></div>
        </section>
        """,
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    selected_email = request.query_params.get("email") if DEMO_MODE else None
    next_path = safe_next_path(request.query_params.get("next"))
    if current_principal(request) is not None and not selected_email:
        return RedirectResponse(next_path, status_code=303)
    last = email_sender.sent_magic_links[-1] if email_sender.sent_magic_links else None
    magic = ""
    if DEMO_MODE and last:
        magic = f"<div class='banner'><b>개발용 매직링크:</b> <a class='button secondary' href='/magic-link/consume?token={html.escape(last.token)}'>매직링크로 로그인</a><p class='muted'>운영에서는 이메일 발송기로 대체합니다.</p></div>"
    owner_hint = (
        f"<p class='muted'>관리자 계정: <code>{html.escape(OWNER_EMAIL)}</code> / <code>{html.escape(OWNER_PASSWORD)}</code></p>"
        if DEMO_MODE
        else "<p class='muted'>관리자 계정 정보는 환경변수로 설정하며 운영 모드에서는 화면에 표시하지 않습니다.</p>"
    )
    if selected_email and ("@" not in selected_email or len(selected_email) > 320):
        selected_email = None
    email_value = html.escape(selected_email or OWNER_EMAIL) if DEMO_MODE else ""
    password_value = html.escape(OWNER_PASSWORD) if DEMO_MODE else ""
    next_notice = f"<div class='banner'>로그인 후 <code>{html.escape(next_path)}</code> 화면으로 이동합니다.</div>" if next_path != "/" else ""
    role_account_hint = ""
    if DEMO_MODE:
        accounts = "".join(
            f"<tr><td><a href='/login?email={html.escape(entry.email, quote=True)}'><code>{html.escape(entry.email)}</code></a></td><td><code>{html.escape(entry.role.value)}</code></td><td>{html.escape(entry.expected_permission)}</td></tr>"
            for entry in DEMO_BOARD_USERS
        )
        role_account_hint = (
            "<details class='card role-accounts' open><summary><h2>권한별 게시판 테스트 계정</h2>"
            "<span class='muted'>Email 클릭 → 로그인 폼 자동 입력</span></summary>"
            f"<p class='muted'>모든 테스트 계정 비밀번호: <code>{html.escape(DEMO_BOARD_PASSWORD)}</code></p>"
            "<table style='width:100%;border-spacing:0 10px'><thead><tr><th>Email</th><th>Role</th><th>게시판 권한</th></tr></thead>"
            f"<tbody>{accounts}</tbody></table></details>"
        )
    return page(
        "Login",
        f"""
        <h1>Coreline Auth Login</h1>
        {owner_hint}
        <div class='nav'><a class='button secondary' href='/signup'>새 계정 가입</a><a class='button secondary' href='/login?next=/board'>게시판 데모 보기</a><a class='button secondary' href='/password-reset'>비밀번호 재설정</a><a class='button secondary' href='/social/google'>Google 로그인</a><a class='button secondary' href='/social/facebook'>Facebook 로그인</a></div>
        <div class='notice'>Google/Facebook은 provider credential이 있으면 실제 OAuth redirect를 시작하고, 없으면 개발용 social connector로 테스트합니다.</div>
        {next_notice}
        <div class='login-grid'>
          <section class='card'><h2>이메일/비밀번호 로그인</h2><form method='post' action='/login'>
            <label>Email</label><input name='email' type='email' value='{email_value}' autocomplete='username' required>
            <label>Password</label><input name='password' type='password' value='{password_value}' autocomplete='current-password' required>
            <input type='hidden' name='next' value='{html.escape(next_path, quote=True)}'>
            <button>로그인</button> <a class='button secondary' href='/password-reset'>비밀번호 재설정</a>
          </form></section>
          <section class='card'><h2>매직링크 로그인</h2><form method='post' action='/magic-link/request'>
            <label>Email</label><input name='email' type='email' value='{email_value}' autocomplete='username' required>
            <input type='hidden' name='return_to' value='/'>
            <button class='secondary'>매직링크 요청</button>
          </form>{magic}</section>
        </div>
        {role_account_hint}
        """,
        public=True,
    )


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    if current_principal(request) is not None:
        return RedirectResponse("/", status_code=303)
    return page(
        "Sign up",
        """
        <h1>Coreline Auth Sign up</h1>
        <p class='muted'>데모에서는 가입 계정이 <code>author</code> 권한으로 생성되어 게시판 글/댓글 작성과 본인 글 수정·삭제를 테스트할 수 있습니다. 관리자 페이지는 admin 계정만 접근 가능합니다.</p>
        <section class='card'><form method='post' action='/signup'>
          <label>Email</label><input name='email' type='email' placeholder='new-user@example.com' autocomplete='username' required>
          <label>Password</label><input name='password' type='password' minlength='8' placeholder='8자 이상' autocomplete='new-password' required>
          <label>Display name</label><input name='display_name' type='text' placeholder='홍길동'>
          <button>가입하고 로그인</button> <a class='button secondary' href='/login'>로그인으로 돌아가기</a>
        </form></section>
        """,
        public=True,
    )


@app.post("/signup")
def signup_form(request: Request, email: str = Form(...), password: str = Form(...), display_name: str = Form("")):
    try:
        user = auth.create_user(email=email, role=Role.AUTHOR, password=password, email_verified=True, display_name=display_name or None)
        issued = auth.login_password(email=user.primary_email, password=password, context=request_context(request))
    except Exception as exc:
        return page("Sign up failed", f"<div class='card error'><h1>가입 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/signup'>돌아가기</a></div>", public=True)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.get("/social/{provider}", response_class=HTMLResponse)
def social_start(request: Request, provider: str):
    if provider not in {"google", "facebook"}:
        return Response("Unknown provider", status_code=404)
    connector = configured_connector(provider, request)
    if connector is not None:
        state = auth.begin_social_login(provider=provider, return_to="/")
        return RedirectResponse(connector.authorization_url(state=state), status_code=303)
    provider_name = "Google" if provider == "google" else "Facebook"
    return page(
        f"{provider_name} login",
        f"""
        <h1>{html.escape(provider_name)} 로그인</h1>
        <section class='card'>
          <p>실제 OAuth를 사용하려면 <code>CORELINE_AUTH_{provider.upper()}_CLIENT_ID</code>, <code>CORELINE_AUTH_{provider.upper()}_CLIENT_SECRET</code> 환경변수가 필요합니다.</p>
          <p>현재는 개발용 social connector로 provider identity linking, 사용자 자동 생성, session 발급 흐름을 테스트할 수 있습니다.</p>
          <form method='post' action='/social/{html.escape(provider)}/dev'>
            <label>Demo email</label><input name='email' type='email' value='{html.escape(provider)}-user@example.com' required>
            <label>Display name</label><input name='display_name' type='text' value='Demo {html.escape(provider_name)} User'>
            <button>{html.escape(provider_name)} 개발용 로그인</button>
            <a class='button secondary' href='/login'>돌아가기</a>
          </form>
        </section>
        """,
        public=True,
    )


def configured_connector(provider: str, request: Request):
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/social/{provider}/callback"
    if provider == "google":
        client_id = os.getenv("CORELINE_AUTH_GOOGLE_CLIENT_ID", "")
        client_secret = os.getenv("CORELINE_AUTH_GOOGLE_CLIENT_SECRET", "")
        if client_id and client_secret:
            return GoogleOAuthConnector.from_credentials(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
    if provider == "facebook":
        client_id = os.getenv("CORELINE_AUTH_FACEBOOK_CLIENT_ID", "")
        client_secret = os.getenv("CORELINE_AUTH_FACEBOOK_CLIENT_SECRET", "")
        if client_id and client_secret:
            return FacebookOAuthConnector.from_credentials(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
    return None


@app.get("/social/{provider}/callback")
def social_callback(request: Request, provider: str, code: str, state: str):
    connector = configured_connector(provider, request)
    if connector is None:
        return Response("Provider is not configured", status_code=400)
    try:
        profile = connector.exchange_code(code=code)
        issued = auth.login_social(profile=profile, state=state, context=request_context(request))
    except Exception as exc:
        return page("Social login failed", f"<div class='card error'><h1>소셜 로그인 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.post("/social/{provider}/dev")
def social_dev_login(request: Request, provider: str, email: str = Form(...), display_name: str = Form("")):
    if provider not in {"google", "facebook"}:
        return Response("Unknown provider", status_code=404)
    profile = DevSocialConnector(provider).fake_profile(email=email, display_name=display_name or None)
    try:
        issued = auth.login_social(profile=profile, context=request_context(request))
    except Exception as exc:
        return page("Social login failed", f"<div class='card error'><h1>소셜 로그인 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.post("/login")
def login_form(request: Request, email: str = Form(...), password: str = Form(...), next: str = Form("/")):
    try:
        issued = auth.login_password(email=email, password=password, context=request_context(request))
    except Exception as exc:
        return page("Login failed", f"<div class='card error'><h1>로그인 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    response = RedirectResponse(safe_next_path(next), status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.get("/password-reset", response_class=HTMLResponse)
def password_reset_page():
    last = email_sender.sent_password_resets[-1] if email_sender.sent_password_resets else None
    dev_link = ""
    if DEMO_MODE and last:
        dev_link = f"<div class='banner'><b>개발용 reset token:</b> <a class='button secondary' href='/password-reset/consume?token={html.escape(last.token)}'>새 비밀번호 설정</a></div>"
    return page(
        "Password reset",
        f"""
        <h1>비밀번호 재설정</h1>
        <section class='card'>
          <form method='post' action='/password-reset/request'>
            <label>Email</label><input name='email' type='email' value='{html.escape(OWNER_EMAIL)}' required>
            <button>재설정 메일 요청</button> <a class='button secondary' href='/login'>로그인으로</a>
          </form>
          {dev_link}
        </section>
        """,
        public=True,
    )


@app.post("/password-reset/request")
def password_reset_request(email: str = Form(...)):
    try:
        auth.request_password_reset(email)
    except Exception:
        # Public UI keeps the same response shape to avoid account enumeration.
        pass
    return RedirectResponse("/password-reset", status_code=303)


@app.get("/password-reset/consume", response_class=HTMLResponse)
def password_reset_consume_page(token: str):
    return page(
        "Set new password",
        f"""
        <h1>새 비밀번호 설정</h1>
        <section class='card'>
          <form method='post' action='/password-reset/consume'>
            <input type='hidden' name='token' value='{html.escape(token, quote=True)}'>
            <label>New password</label><input name='password' type='password' minlength='8' autocomplete='new-password' required>
            <button>비밀번호 변경</button> <a class='button secondary' href='/login'>취소</a>
          </form>
        </section>
        """,
        public=True,
    )


@app.post("/password-reset/consume")
def password_reset_consume_form(token: str = Form(...), password: str = Form(...)):
    try:
        auth.consume_password_reset(token, password)
    except Exception as exc:
        return page("Password reset failed", f"<div class='card error'><h1>재설정 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/password-reset'>돌아가기</a></div>", public=True)
    return page("Password reset complete", "<div class='card'><h1>비밀번호가 변경되었습니다</h1><a class='button' href='/login'>로그인</a></div>", public=True)


@app.post("/magic-link/request")
def magic_link_request(email: str = Form(...), return_to: str = Form("/")):
    try:
        auth.request_magic_link(email=email, return_to=return_to)
    except Exception as exc:
        return page("Magic link failed", f"<div class='card error'><h1>요청 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    return RedirectResponse("/login", status_code=303)


@app.get("/magic-link/consume")
def magic_link_consume(request: Request, token: str):
    try:
        issued = auth.consume_magic_link(token=token, context=request_context(request))
    except Exception as exc:
        return page("Magic link failed", f"<div class='card error'><h1>매직링크 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.post("/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        auth.logout(token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@app.get("/logout", response_class=HTMLResponse)
def logout_confirm(request: Request):
    if current_principal(request) is None:
        return RedirectResponse("/login", status_code=303)
    return page(
        "Logout",
        """
        <h1>로그아웃 확인</h1>
        <section class='card'>
          <p class='muted'>주소창에서 <code>/logout</code>을 직접 열어도 안전하게 처리하기 위해, 실제 로그아웃은 아래 버튼으로 POST 요청을 보낼 때만 실행합니다.</p>
          <form method='post' action='/logout'>
            <button class='danger'>로그아웃</button>
            <a class='button secondary' href='/'>취소</a>
          </form>
        </section>
        """,
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, query: str = "", status: str = "", role: str = ""):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    try:
        principal = auth.verify_session(token, required_permission="users:read")
    except Exception:
        return Response("Forbidden", status_code=403)
    from coreline_auth import CorelineAdminService

    try:
        users = CorelineAdminService(auth).list_users(actor_session_token=token, query=query, status=status, role=role)
    except Exception as exc:
        return page("Admin filter failed", f"<div class='card error'><h1>관리자 필터 오류</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/admin'>필터 초기화</a></div>")

    def select_options(values: list[tuple[str, str]], current: str) -> str:
        return "".join(
            f"<option value='{html.escape(value)}'{' selected' if value == current else ''}>{html.escape(label)}</option>"
            for value, label in values
        )

    role_values = [("user", "user"), ("viewer", "viewer"), ("author", "author"), ("moderator", "moderator"), ("admin", "admin"), ("owner", "owner")]
    filter_role_options = select_options([("", "전체 role")] + role_values, role)
    filter_status_options = select_options([("", "전체 status"), ("active", "active"), ("disabled", "disabled"), ("banned", "banned")], status)
    rows = "".join(
        f"""<tr><td>{html.escape(user.primary_email)}</td><td>{html.escape(user.role.value)}</td><td>{html.escape(user.status.value)}</td><td>
        <form method='post' action='/admin/users/{html.escape(user.id)}/role' style='display:inline-block;min-width:180px'><select name='role'>{select_options(role_values, user.role.value)}</select><button class='secondary'>Role 변경</button></form>
        <form method='post' action='/admin/users/{html.escape(user.id)}/ban' style='display:inline-block;min-width:220px'><input name='reason' type='text' placeholder='Ban reason' aria-label='Ban reason for {html.escape(user.primary_email)}'><button class='danger'>Ban</button></form>
        <form method='post' action='/admin/users/{html.escape(user.id)}/unban' style='display:inline-block'><input name='reason' type='text' placeholder='Unban reason'><button class='secondary'>Unban</button></form>
        </td></tr>"""
        for user in users
    )
    return page(
        "Admin",
        f"""<h1>관리자 페이지</h1><p class='muted'>{html.escape(principal.email)} 계정으로 사용자/권한을 관리합니다.</p>
        <section class='card'><h2>검색/필터</h2><form method='get' action='/admin'>
          <label>Query</label><input name='query' type='search' placeholder='email, display name, user id' value='{html.escape(query)}'>
          <div class='grid'><div><label>Status</label><select name='status'>{filter_status_options}</select></div><div><label>Role</label><select name='role'>{filter_role_options}</select></div></div>
          <button>검색</button> <a class='button secondary' href='/admin'>초기화</a>
        </form></section>
        <section class='card'><table style='width:100%;border-spacing:0 10px'><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table><a class='button' href='/'>대시보드</a> <a class='button secondary' href='/board'>게시판</a> <a class='button secondary' href='/admin/audit'>감사 로그</a></section>""",
    )


@app.get("/admin/audit", response_class=HTMLResponse)
def admin_audit_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    try:
        principal = auth.verify_session(token, required_permission="audit:read")
    except Exception:
        return Response("Forbidden", status_code=403)
    events = auth.list_audit_events(limit=100)
    rows = "".join(
        f"""<tr><td>{html.escape(event.created_at.isoformat())}</td><td>{html.escape(event.action)}</td><td>{html.escape(event.actor_user_id or '-')}</td><td>{html.escape(event.target_user_id or '-')}</td><td><code>{html.escape(str(event.metadata))}</code></td></tr>"""
        for event in events
    ) or "<tr><td colspan='5'>아직 감사 이벤트가 없습니다.</td></tr>"
    return page(
        "Audit log",
        f"""<h1>감사 로그</h1><p class='muted'>{html.escape(principal.email)} 계정으로 최근 100개 이벤트를 확인합니다.</p>
        <section class='card'><table style='width:100%;border-spacing:0 10px'><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Metadata</th></tr></thead><tbody>{rows}</tbody></table><a class='button secondary' href='/admin'>관리자</a></section>""",
    )


@app.post("/admin/users/{user_id}/role")
def admin_role(request: Request, user_id: str, role: str = Form(...)):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    from coreline_auth import CorelineAdminService
    try:
        CorelineAdminService(auth).update_user_role(actor_session_token=token, user_id=user_id, role=Role(role))
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{user_id}/ban")
def admin_ban(request: Request, user_id: str, reason: str = Form("")):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    from coreline_auth import CorelineAdminService
    try:
        CorelineAdminService(auth).ban_user(actor_session_token=token, user_id=user_id, reason=reason)
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{user_id}/unban")
def admin_unban(request: Request, user_id: str, reason: str = Form("")):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    from coreline_auth import CorelineAdminService
    try:
        CorelineAdminService(auth).unban_user(actor_session_token=token, user_id=user_id, reason=reason)
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse("/admin", status_code=303)
