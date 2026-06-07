from __future__ import annotations

from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from fastapi.testclient import TestClient

from coreline_auth import Role
from demo_app_helper import load_demo_app


def _csrf_from_page(text: str) -> str:
    return text.split("name='csrf_token' value='", 1)[1].split("'", 1)[0]


def _csrf(client: TestClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    return _csrf_from_page(response.text)


def _login_owner(client: TestClient) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(page.text)},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _signup(client: TestClient, *, email: str | None = None, password: str = "signup-password") -> str:
    chosen = email or f"signup-{uuid4().hex}@example.com"
    response = client.post(
        "/signup",
        data={"email": chosen, "password": password, "display_name": "Signup User", "csrf_token": _csrf(client, "/signup")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "coreline_auth_session" in response.cookies
    return chosen


def test_demo_saas_password_login_dashboard_admin_logout(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    assert client.get("/", follow_redirects=False).status_code == 303
    login_page = client.get("/login")
    assert "Coreline Auth Login" in login_page.text
    assert f"viewer-{'board'}@example.com" not in login_page.text

    login = client.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)}, follow_redirects=False)
    assert login.status_code == 303
    assert "coreline_auth_session" in login.cookies
    dashboard = client.get("/")
    assert "Coreline Auth Demo" in dashboard.text
    assert "내 계정 요약" in dashboard.text
    assert "내 권한" in dashboard.text
    assert "현재 세션" in dashboard.text
    assert "내 최근 활동" in dashboard.text
    assert "/" + "board" not in dashboard.text
    admin_page = client.get("/admin")
    assert admin_page.status_code == 200
    assert "검색/필터" in admin_page.text
    assert "Ban reason" in admin_page.text
    assert client.post("/logout", data={"csrf_token": _csrf(client, "/")}, follow_redirects=False).status_code == 303


def test_demo_auth_only_has_no_board_route_or_menu(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    assert client.get("/" + "board", follow_redirects=False).status_code == 404
    login_page = client.get("/login")
    assert "/" + "board" not in login_page.text
    assert "게시" + "판" not in login_page.text
    assert "권한별 " + "게시" + "판" + " 테스트 계정" not in login_page.text


def test_demo_logout_direct_url_and_stale_csrf(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    _login_owner(client)

    logout_page = client.get("/logout")
    assert logout_page.status_code == 200
    assert "로그아웃 확인" in logout_page.text
    assert "method='post' action='/logout'" in logout_page.text

    stale = client.post("/logout", data={"csrf_token": "stale.invalid"}, follow_redirects=False)
    assert stale.status_code == 303
    assert stale.headers["location"] == "/logout?csrf=expired"
    confirmation = client.get(stale.headers["location"])
    assert "보안 토큰이 만료되었습니다" in confirmation.text
    assert client.post("/logout", data={"csrf_token": _csrf_from_page(confirmation.text)}, follow_redirects=False).status_code == 303


def test_demo_csrf_cookie_is_stable_across_auth_pages(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    _login_owner(client)
    dashboard = client.get("/")
    old_dashboard_csrf = _csrf_from_page(dashboard.text)

    assert client.get("/account").status_code == 200
    logout = client.post("/logout", data={"csrf_token": old_dashboard_csrf}, follow_redirects=False)

    assert logout.status_code == 303


def test_demo_saas_magic_link_flow(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    before = len(demo.email_sender.sent_magic_links)
    assert client.post("/magic-link/request", data={"email": "owner@example.com", "return_to": "/", "csrf_token": _csrf(client, "/login")}, follow_redirects=False).status_code == 303
    assert len(demo.email_sender.sent_magic_links) == before + 1
    token = demo.email_sender.sent_magic_links[-1].token
    consume = client.get(f"/magic-link/consume?token={token}", follow_redirects=False)
    assert consume.status_code == 303
    assert "coreline_auth_session" in consume.cookies


def test_demo_saas_signup_user_flow(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    email = _signup(client)
    dashboard = client.get("/")
    assert email in dashboard.text
    assert "user" in dashboard.text
    assert client.get("/admin").status_code == 403


def test_demo_saas_social_dev_login_flow(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    google = client.get("/social/google")
    assert google.status_code == 200
    assert "개발용 social connector" in google.text
    response = client.post(
        "/social/google/dev",
        data={"email": "google-dev@example.com", "display_name": "Google Dev", "csrf_token": _csrf_from_page(google.text)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "coreline_auth_session" in response.cookies
    assert "google-dev@example.com" in client.get("/").text


def test_demo_saas_configured_oidc_start_uses_pkce_nonce_and_cookies(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CORELINE_AUTH_GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setenv("CORELINE_AUTH_GOOGLE_CLIENT_SECRET", "google-secret")
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app, base_url="http://localhost")

    response = client.get("/social/google", follow_redirects=False)

    assert response.status_code == 303
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["client_id"] == ["google-client"]
    assert query["nonce"]
    assert query["code_challenge"]
    assert query["code_challenge_method"] == ["S256"]
    assert "coreline_auth_oauth_google_nonce" in response.cookies
    assert "coreline_auth_oauth_google_code_verifier" in response.cookies


def test_demo_password_reset_flow(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    email = _signup(client, password="old-demo-password")
    client.post("/logout", data={"csrf_token": _csrf(client, "/")}, follow_redirects=False)

    response = client.post("/password-reset/request", data={"email": email, "csrf_token": _csrf(client, "/password-reset")}, follow_redirects=True)
    assert response.status_code == 200
    assert "새 비밀번호 설정" in response.text
    token = response.text.split("token=")[1].split("'")[0]
    reset = client.post("/password-reset/consume", data={"token": token, "password": "changed-demo-password", "csrf_token": _csrf_from_page(response.text)})
    assert reset.status_code == 200
    assert "비밀번호가 변경되었습니다" in reset.text
    login = client.post("/login", data={"email": email, "password": "changed-demo-password", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)
    assert login.status_code == 303


def test_demo_admin_audit_and_system_pages(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    _login_owner(client)
    client.post("/magic-link/request", data={"email": "owner@example.com", "return_to": "/", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)

    audit = client.get("/admin/audit")
    assert audit.status_code == 200
    assert "감사 로그" in audit.text
    assert "auth.magic_link.request" in audit.text
    assert "필터 오류" in client.get("/admin/audit?since=not-a-date").text

    system = client.get("/system")
    assert system.status_code == 200
    assert "시스템 상태" in system.text
    assert "Provider readiness" in system.text


def test_demo_admin_role_dashboard_filters_users(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    demo.auth.create_user(email="managed-user@example.com", role=Role.USER, password="coreline-demo-password", email_verified=True)
    client = TestClient(demo.app)
    _login_owner(client)

    admin = client.get("/admin")
    assert admin.status_code == 200
    assert "전체 사용자 대시보드" in admin.text
    assert "운영 KPI" in admin.text
    assert "권한별 사용자 현황" in admin.text
    assert "권한 매트릭스" in admin.text
    assert "managed-user@example.com" in admin.text
    assert "/" + "board" not in admin.text

    filtered = client.get("/admin?role=user#admin-users")
    assert filtered.status_code == 200
    assert "선택된 role: <code>user</code>" in filtered.text
    assert "managed-user@example.com" in filtered.text


def test_demo_admin_forbidden_page_for_non_admin_user(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    email = _signup(client)

    admin = client.get("/admin")

    assert admin.status_code == 403
    assert "403 Forbidden" in admin.text
    assert "관리자 권한이 필요합니다" in admin.text
    assert email in admin.text
    assert "필요 권한" in admin.text
    assert "users:read" in admin.text
    assert "대시보드로 돌아가기" in admin.text


def test_demo_sidebar_keeps_only_auth_product_menus(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    login_page = client.get("/login")
    assert "Application" not in login_page.text
    assert "Admin" not in login_page.text
    assert "Demo app" in login_page.text
    assert "/" + "board" not in login_page.text
    assert "Google 로그인" in login_page.text
    assert "내 계정 요약" not in login_page.text

    _login_owner(client)
    dashboard = client.get("/")

    assert "내 계정 요약" in dashboard.text
    assert "사용자 상태와 role 변경" in dashboard.text
    assert "비밀번호 재설정" not in dashboard.text
    assert "게시" + "판" not in dashboard.text


def test_demo_regular_user_dashboard_and_account_self_service(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    email = _signup(client)

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert email in dashboard.text
    assert "내 권한" in dashboard.text
    assert "dashboard:read" in dashboard.text
    assert "현재 세션" in dashboard.text
    assert "auth.login.password" in dashboard.text

    account = client.get("/account")
    assert account.status_code == 200
    assert "내 계정" in account.text
    assert client.post("/account/profile", data={"display_name": "User Updated", "csrf_token": _csrf_from_page(account.text)}, follow_redirects=False).status_code == 303
    assert "User Updated" in client.get("/account").text

    security = client.get("/account/security")
    assert "보안 센터" in security.text
    failed = client.post(
        "/account/password",
        data={"current_password": "wrong-password", "new_password": "changed-password", "confirm_password": "changed-password", "csrf_token": _csrf_from_page(security.text)},
    )
    assert "현재 비밀번호가 올바르지 않습니다" in failed.text
    changed = client.post(
        "/account/password",
        data={"current_password": "signup-password", "new_password": "changed-password", "confirm_password": "changed-password", "csrf_token": _csrf_from_page(client.get("/account/security").text)},
        follow_redirects=False,
    )
    assert changed.status_code == 303
    assert client.get("/account/sessions").status_code == 200
    assert "auth.account.password_change" in client.get("/account/activity").text


def test_demo_account_can_revoke_current_session(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    _signup(client)
    token = client.cookies.get("coreline_auth_session")
    principal = demo.auth.verify_session(token)
    sessions = client.get("/account/sessions")
    assert "현재 세션 로그아웃" in sessions.text

    revoked = client.post(
        f"/account/sessions/{principal.session.id}/revoke",
        data={"csrf_token": _csrf_from_page(sessions.text)},
        follow_redirects=False,
    )

    assert revoked.status_code == 303
    assert revoked.headers["location"] == "/login"
    assert client.get("/", follow_redirects=False).status_code == 303


def test_demo_admin_user_detail_lifecycle_and_email_outbox(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    managed = demo.auth.create_user(email="detail-user@example.com", role=Role.USER, password="coreline-demo-password", email_verified=True)
    admin = TestClient(demo.app)
    _login_owner(admin)

    detail = admin.get(f"/admin/users/{managed.id}")
    assert detail.status_code == 200
    assert "사용자 상세" in detail.text
    assert "detail-user@example.com" in detail.text

    disabled = admin.post(f"/admin/users/{managed.id}/disable", data={"reason": "test disable", "csrf_token": _csrf_from_page(detail.text)}, follow_redirects=False)
    assert disabled.status_code == 303
    assert demo.auth.storage.get_user(managed.id).status.value == "disabled"

    password_set = admin.post(f"/admin/users/{managed.id}/password", data={"password": "admin-set-password", "csrf_token": _csrf(admin, f"/admin/users/{managed.id}")}, follow_redirects=False)
    assert password_set.status_code == 303

    admin.post("/magic-link/request", data={"email": "owner@example.com", "return_to": "/", "csrf_token": _csrf(admin, "/login")}, follow_redirects=False)
    admin.post("/password-reset/request", data={"email": "owner@example.com", "csrf_token": _csrf(admin, "/password-reset")}, follow_redirects=False)
    magic_token = demo.email_sender.sent_magic_links[-1].token
    reset_token = demo.email_sender.sent_password_resets[-1].token
    outbox = admin.get("/system/email")
    assert outbox.status_code == 200
    assert "이메일 Outbox" in outbox.text
    assert magic_token not in outbox.text
    assert reset_token not in outbox.text


def test_demo_system_readiness_does_not_expose_provider_secrets(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CORELINE_AUTH_GOOGLE_CLIENT_ID", "google-client-id")
    monkeypatch.setenv("CORELINE_AUTH_GOOGLE_CLIENT_SECRET", "super-secret-google-value")
    monkeypatch.setenv("CORELINE_AUTH_FACEBOOK_CLIENT_ID", "facebook-client-id")
    monkeypatch.setenv("CORELINE_AUTH_FACEBOOK_CLIENT_SECRET", "super-secret-facebook-value")
    demo = load_demo_app(monkeypatch, tmp_path)
    admin = TestClient(demo.app)
    _login_owner(admin)

    system = admin.get("/system")

    assert "Google OAuth" in system.text
    assert "Facebook OAuth" in system.text
    assert "ready" in system.text
    assert "super-secret-google-value" not in system.text
    assert "super-secret-facebook-value" not in system.text


def test_login_next_redirects_to_account(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    login_page = client.get("/login?next=/account")

    assert login_page.status_code == 200
    assert "로그인 후 <code>/account</code> 화면으로 이동합니다" in login_page.text
    assert "name='next' value='/account'" in login_page.text

    login = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "coreline-demo-password", "next": "/account", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )

    assert login.status_code == 303
    assert login.headers["location"] == "/account"


def test_demo_favicon_is_silent_no_content(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    response = client.get("/favicon.ico")

    assert response.status_code == 204
