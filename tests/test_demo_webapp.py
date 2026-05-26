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
    dashboard = client.get("/")
    assert "Coreline Auth Demo" in dashboard.text
    assert "내 계정 요약" in dashboard.text
    assert "내 권한" in dashboard.text
    assert "현재 세션" in dashboard.text
    assert "내 최근 활동" in dashboard.text
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


def test_demo_logout_with_stale_csrf_redirects_to_fresh_confirmation(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    login_page = client.get("/login")
    login = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303

    stale = client.post("/logout", data={"csrf_token": "stale.invalid"}, follow_redirects=False)

    assert stale.status_code == 303
    assert stale.headers["location"] == "/logout?csrf=expired"
    confirmation = client.get(stale.headers["location"])
    assert confirmation.status_code == 200
    assert "보안 토큰이 만료되었습니다" in confirmation.text
    assert client.post("/logout", data={"csrf_token": _csrf_from_page(confirmation.text)}, follow_redirects=False).status_code == 303


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
    assert "감사 로그 필터" in audit.text
    assert "auth.magic_link.request" in audit.text

    filtered = client.get("/admin/audit?action=auth.magic_link.request")
    assert filtered.status_code == 200
    assert "현재 필터: action=auth.magic_link.request" in filtered.text
    assert "auth.magic_link.request" in filtered.text

    invalid = client.get("/admin/audit?since=not-a-date")
    assert invalid.status_code == 200
    assert "필터 오류" in invalid.text
    assert "날짜는 ISO 형식" in invalid.text


def test_demo_admin_user_activity_card(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    login = client.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)
    assert login.status_code == 303
    # Generate a few user-owned activity signals so the card proves both
    # session and audit-log timelines are connected.
    assert client.get("/board").status_code == 200
    assert client.post("/logout", data={"csrf_token": _csrf(client, "/")}, follow_redirects=False).status_code == 303
    login_again = client.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)
    assert login_again.status_code == 303

    admin = client.get("/admin")

    assert admin.status_code == 200
    assert "href='#user-card-" in admin.text
    assert "개인 로그인 정보" in admin.text
    assert "로그인 횟수" in admin.text
    assert "세션 타임라인" in admin.text
    assert "로그아웃 시간" in admin.text
    assert "auth.login.password" in admin.text
    assert "auth.logout" in admin.text
    assert "owner@example.com" in admin.text


def test_demo_admin_role_dashboard_filters_users(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    login = client.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)
    assert login.status_code == 303

    admin = client.get("/admin")

    assert admin.status_code == 200
    assert "전체 사용자 대시보드" in admin.text
    assert "운영 KPI" in admin.text
    assert "전체 가입자" in admin.text
    assert "권한별 사용자 현황" in admin.text
    assert "권한별 활동 요약" in admin.text
    assert "권한 매트릭스" in admin.text
    assert "href='/admin?role=author#admin-users'" in admin.text
    assert "author-board@example.com" in admin.text
    assert "viewer-board@example.com" in admin.text
    assert "Login Count" in admin.text
    assert "Active Sessions" in admin.text

    filtered = client.get("/admin?role=viewer#admin-users")

    assert filtered.status_code == 200
    assert "선택된 role: <code>viewer</code>" in filtered.text
    assert "value='viewer' selected" in filtered.text
    assert "viewer-board@example.com" in filtered.text


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
    assert "관리자 권한이 필요합니다" in audit.text
    assert "필요 권한" in audit.text
    assert "audit:read" in audit.text


def test_demo_admin_forbidden_page_for_non_admin_user(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    login_page = client.get("/login?email=viewer-board@example.com")
    login = client.post(
        "/login",
        data={"email": "viewer-board@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303

    admin = client.get("/admin")

    assert admin.status_code == 403
    assert "403 Forbidden" in admin.text
    assert "관리자 권한이 필요합니다" in admin.text
    assert "viewer-board@example.com" in admin.text
    assert "현재 role" in admin.text
    assert "viewer" in admin.text
    assert "필요 권한" in admin.text
    assert "users:read" in admin.text
    assert "대시보드로 돌아가기" in admin.text
    assert "다른 계정으로 로그인" in admin.text


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
    assert "내 계정 요약" not in login_page.text

    login = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    dashboard = client.get("/")

    assert "내 계정 요약" in dashboard.text
    assert "RBAC 읽기/댓글/수정 검증" in dashboard.text
    assert "사용자 상태와 role 변경" in dashboard.text
    assert "게시판은 로그인 후 열립니다" not in dashboard.text
    assert "비밀번호 재설정" not in dashboard.text


def test_demo_regular_user_dashboard_shows_own_info(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    login_page = client.get("/login?email=viewer-board@example.com")
    login = client.post(
        "/login",
        data={"email": "viewer-board@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303

    dashboard = client.get("/")

    assert dashboard.status_code == 200
    assert "내 계정 요약" in dashboard.text
    assert "viewer-board@example.com" in dashboard.text
    assert "내 role" in dashboard.text
    assert "viewer" in dashboard.text
    assert "내 권한" in dashboard.text
    assert "board:read" in dashboard.text
    assert "현재 세션" in dashboard.text
    assert "내 최근 활동" in dashboard.text
    assert "auth.login.password" in dashboard.text
    assert "관리자 접근 테스트" in dashboard.text


def test_demo_account_self_service_pages_and_password_change(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    login_page = client.get("/login?email=viewer-board@example.com")
    login = client.post(
        "/login",
        data={"email": "viewer-board@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303

    account = client.get("/account")
    assert account.status_code == 200
    assert "내 계정" in account.text
    assert "프로필 수정" in account.text
    assert client.post("/account/profile", data={"display_name": "Viewer Updated", "csrf_token": _csrf_from_page(account.text)}, follow_redirects=False).status_code == 303
    assert "Viewer Updated" in client.get("/account").text

    security = client.get("/account/security")
    assert "보안 센터" in security.text
    assert "MFA 상태" in security.text
    assert "MFA 미등록" in security.text
    failed = client.post(
        "/account/password",
        data={"current_password": "wrong-password", "new_password": "changed-password", "confirm_password": "changed-password", "csrf_token": _csrf_from_page(security.text)},
    )
    assert "현재 비밀번호가 올바르지 않습니다" in failed.text
    changed = client.post(
        "/account/password",
        data={"current_password": "coreline-demo-password", "new_password": "changed-password", "confirm_password": "changed-password", "csrf_token": _csrf_from_page(client.get("/account/security").text)},
        follow_redirects=False,
    )
    assert changed.status_code == 303
    assert changed.headers["location"] == "/account/security?password=changed"

    assert client.get("/account/sessions").status_code == 200
    activity = client.get("/account/activity")
    assert activity.status_code == 200
    assert "auth.account.password_change" in activity.text

    assert client.post("/logout", data={"csrf_token": _csrf(client, "/")}, follow_redirects=False).status_code == 303
    old_login = client.post("/login", data={"email": "viewer-board@example.com", "password": "coreline-demo-password", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)
    assert old_login.status_code == 200
    new_login = client.post("/login", data={"email": "viewer-board@example.com", "password": "changed-password", "csrf_token": _csrf(client, "/login")}, follow_redirects=False)
    assert new_login.status_code == 303


def test_demo_account_can_revoke_current_session(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    login_page = client.get("/login?email=viewer-board@example.com")
    login = client.post(
        "/login",
        data={"email": "viewer-board@example.com", "password": "coreline-demo-password", "csrf_token": _csrf_from_page(login_page.text)},
        follow_redirects=False,
    )
    assert login.status_code == 303
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


def test_demo_admin_user_detail_lifecycle_and_system_health(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    admin = TestClient(demo.app)
    login = admin.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf(admin, "/login")}, follow_redirects=False)
    assert login.status_code == 303
    viewer = demo.auth.storage.get_user_by_email("viewer-board@example.com")
    assert viewer is not None

    detail = admin.get(f"/admin/users/{viewer.id}")
    assert detail.status_code == 200
    assert "사용자 상세" in detail.text
    assert "MFA / Security Center" in detail.text
    assert "관리자 비밀번호 설정" in detail.text
    assert "viewer-board@example.com" in detail.text

    disabled = admin.post(
        f"/admin/users/{viewer.id}/disable",
        data={"reason": "test disable", "csrf_token": _csrf_from_page(detail.text)},
        follow_redirects=False,
    )
    assert disabled.status_code == 303
    assert demo.auth.storage.get_user(viewer.id).status.value == "disabled"
    enabled = admin.post(
        f"/admin/users/{viewer.id}/enable",
        data={"reason": "test enable", "csrf_token": _csrf(admin, f"/admin/users/{viewer.id}")},
        follow_redirects=False,
    )
    assert enabled.status_code == 303
    assert demo.auth.storage.get_user(viewer.id).status.value == "active"

    password_set = admin.post(
        f"/admin/users/{viewer.id}/password",
        data={"password": "admin-set-password", "csrf_token": _csrf(admin, f"/admin/users/{viewer.id}")},
        follow_redirects=False,
    )
    assert password_set.status_code == 303
    viewer_client = TestClient(demo.app)
    viewer_login = viewer_client.post("/login", data={"email": "viewer-board@example.com", "password": "admin-set-password", "csrf_token": _csrf(viewer_client, "/login")}, follow_redirects=False)
    assert viewer_login.status_code == 303

    viewer_session = demo.auth.verify_session(viewer_client.cookies.get("coreline_auth_session")).session
    revoke = admin.post(
        f"/admin/sessions/{viewer_session.id}/revoke",
        data={"csrf_token": _csrf(admin, f"/admin/users/{viewer.id}")},
        headers={"referer": "https://evil.example/phish"},
        follow_redirects=False,
    )
    assert revoke.status_code == 303
    assert revoke.headers["location"] == "/admin"
    assert viewer_client.get("/", follow_redirects=False).status_code == 303

    system = admin.get("/system")
    assert system.status_code == 200
    assert "시스템 상태" in system.text
    assert "Health" in system.text
    assert "Provider readiness" in system.text
    assert "Google OAuth" in system.text
    assert "Facebook OAuth" in system.text
    assert "SMTP" in system.text
    assert "Runbook" in system.text


def test_demo_system_email_outbox_and_template_preview(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    admin = TestClient(demo.app)
    login = admin.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf(admin, "/login")}, follow_redirects=False)
    assert login.status_code == 303
    admin.post("/magic-link/request", data={"email": "owner@example.com", "return_to": "/", "csrf_token": _csrf(admin, "/login")}, follow_redirects=False)
    admin.post("/password-reset/request", data={"email": "owner@example.com", "csrf_token": _csrf(admin, "/password-reset")}, follow_redirects=False)
    magic_token = demo.email_sender.sent_magic_links[-1].token
    reset_token = demo.email_sender.sent_password_resets[-1].token

    outbox = admin.get("/system/email")

    assert outbox.status_code == 200
    assert "이메일 Outbox" in outbox.text
    assert "Queue summary" in outbox.text
    assert "magic_link" in outbox.text
    assert "password_reset" in outbox.text
    assert "Template preview" in outbox.text
    assert "Your Coreline sign-in link" in outbox.text
    assert "Reset your Coreline password" in outbox.text
    assert "Token fingerprint" in outbox.text
    assert magic_token not in outbox.text
    assert reset_token not in outbox.text


def test_demo_system_readiness_does_not_expose_provider_secrets(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CORELINE_AUTH_GOOGLE_CLIENT_ID", "google-client-id")
    monkeypatch.setenv("CORELINE_AUTH_GOOGLE_CLIENT_SECRET", "super-secret-google-value")
    monkeypatch.setenv("CORELINE_AUTH_FACEBOOK_CLIENT_ID", "facebook-client-id")
    monkeypatch.setenv("CORELINE_AUTH_FACEBOOK_CLIENT_SECRET", "super-secret-facebook-value")
    demo = load_demo_app(monkeypatch, tmp_path)
    admin = TestClient(demo.app)
    login = admin.post("/login", data={"email": "owner@example.com", "password": "coreline-demo-password", "csrf_token": _csrf(admin, "/login")}, follow_redirects=False)
    assert login.status_code == 303

    system = admin.get("/system")

    assert "Google OAuth" in system.text
    assert "Facebook OAuth" in system.text
    assert "ready" in system.text
    assert "super-secret-google-value" not in system.text
    assert "super-secret-facebook-value" not in system.text


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
