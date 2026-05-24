from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from demo_app_helper import load_demo_app


def _csrf_from_page(text: str) -> str:
    return text.split("name='csrf_token' value='", 1)[1].split("'", 1)[0]


def _csrf(client: TestClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    return _csrf_from_page(response.text)


def test_demo_saas_password_login_dashboard_admin_logout(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    assert client.get("/", follow_redirects=False).status_code == 303
    login_page = client.get("/login")
    assert "Coreline Auth Login" in login_page.text

    login = client.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)}, follow_redirects=False)
    assert login.status_code == 303
    assert "coreline_auth_session" in login.cookies
    assert "Coreline Auth Demo" in client.get("/").text
    admin_page = client.get("/admin")
    assert admin_page.status_code == 200
    assert "검색/필터" in admin_page.text
    assert "Ban reason" in admin_page.text
    assert "moderator" in admin_page.text
    assert client.post("/logout", data={"csrf_token": _csrf(client, "/")}, follow_redirects=False).status_code == 303


def test_demo_logout_direct_url_shows_safe_confirmation(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    assert client.get("/logout", follow_redirects=False).status_code == 303
    login_page = client.get("/login")
    login = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303

    logout_page = client.get("/logout")

    assert logout_page.status_code == 200
    assert "로그아웃 확인" in logout_page.text
    assert "method='post' action='/logout'" in logout_page.text
    assert client.post("/logout", data={"csrf_token": _csrf_from_page(logout_page.text)}, follow_redirects=False).status_code == 303


def test_demo_csrf_cookie_is_stable_across_pages_for_open_forms(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    login_page = client.get("/login")
    login = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    dashboard = client.get("/")
    old_dashboard_csrf = _csrf_from_page(dashboard.text)

    # Visiting another page used to rotate the CSRF cookie and invalidate the
    # still-open dashboard logout form.
    assert client.get("/board").status_code == 200

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


def test_demo_saas_signup_viewer_flow(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    email = f"signup-{uuid4().hex}@example.com"
    response = client.post(
        "/signup",
        data={"email": email, "password": "signup-password", "display_name": "Signup User", "csrf_token": _csrf(client, "/signup")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "coreline_auth_session" in response.cookies
    dashboard = client.get("/")
    assert email in dashboard.text
    assert "author" in dashboard.text
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
    dashboard = client.get("/")
    assert "google-dev@example.com" in dashboard.text


def test_demo_password_reset_flow(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    email = f"reset-{uuid4().hex}@example.com"
    signup = client.post(
        "/signup",
        data={"email": email, "password": "old-demo-password", "display_name": "Reset User", "csrf_token": _csrf(client, "/signup")},
        follow_redirects=False,
    )
    assert signup.status_code == 303
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


def test_demo_admin_audit_viewer(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    login = client.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)
    assert login.status_code == 303
    client.post("/magic-link/request", data={"email": "owner@example.com", "return_to": "/", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)

    audit = client.get("/admin/audit")

    assert audit.status_code == 200
    assert "감사 로그" in audit.text
    assert "auth.magic_link.request" in audit.text


def test_demo_mode_off_hides_owner_password_and_debug_tokens(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CORELINE_AUTH_DEMO_MODE", "false")
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    login_page = client.get("/login")
    assert "coreline-demo-password" not in login_page.text

    client.post("/magic-link/request", data={"email": "owner@example.com", "return_to": "/", "csrf_token": _csrf_from_page(login_page.text)}, follow_redirects=False)
    assert "개발용 매직링크" not in client.get("/login").text

    client.post("/password-reset/request", data={"email": "owner@example.com", "csrf_token": _csrf(client, "/password-reset")}, follow_redirects=False)
    reset_page = client.get("/password-reset")
    assert "개발용 reset token" not in reset_page.text


def test_demo_audit_viewer_uses_audit_read_permission(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    email = f"audit-denied-{uuid4().hex}@example.com"
    signup = client.post(
        "/signup",
        data={"email": email, "password": "signup-password", "display_name": "Audit Denied", "csrf_token": _csrf(client, "/signup")},
        follow_redirects=False,
    )
    assert signup.status_code == 303

    audit = client.get("/admin/audit")

    assert audit.status_code == 403


def test_login_role_account_click_prefills_email(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    page = client.get("/login")
    assert "href='/login?email=viewer-board@example.com'" in page.text
    selected = client.get("/login?email=moderator-board@example.com")

    assert selected.status_code == 200
    assert "value='moderator-board@example.com'" in selected.text
    assert "value='coreline-demo-password'" in selected.text


def test_demo_sidebar_keeps_only_core_product_menus(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    login_page = client.get("/login")
    assert "Application" not in login_page.text
    assert "Admin" not in login_page.text
    assert "Demo app" in login_page.text
    assert "href='/login?next=/board'" in login_page.text
    assert "게시판은 로그인 후 열립니다" in login_page.text
    assert "Google 로그인" in login_page.text
    assert "현재 세션과 권한 요약" not in login_page.text

    login = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    dashboard = client.get("/")

    assert "현재 세션과 권한 요약" in dashboard.text
    assert "RBAC 읽기/댓글/수정 검증" in dashboard.text
    assert "사용자 상태와 role 변경" in dashboard.text
    assert "게시판은 로그인 후 열립니다" not in dashboard.text
    assert "비밀번호 재설정" not in dashboard.text


def test_login_next_redirects_to_board(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    login_page = client.get("/login?next=/board")

    assert login_page.status_code == 200
    assert "로그인 후 <code>/board</code> 화면으로 이동합니다" in login_page.text
    assert "name='next' value='/board'" in login_page.text

    login = client.post(
        "/login",
        data={
            "email": "owner@example.com",
            "password": "coreline-demo-password",
            "next": "/board",
            "csrf_token": _csrf_from_page(login_page.text),
        },
        follow_redirects=False,
    )

    assert login.status_code == 303
    assert login.headers["location"] == "/board"


def test_demo_favicon_is_silent_no_content(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    response = client.get("/favicon.ico")

    assert response.status_code == 204
