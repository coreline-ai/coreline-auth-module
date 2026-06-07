from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient

from coreline_auth import AuditEvent, AuthProfile, CorelineAuthConfig, CorelineAuthService, Role
from coreline_auth.fastapi_adapter import mount_admin_routes, mount_auth_routes
from coreline_auth.storage import MemoryAuthStorage

PASSWORD = "correct horse battery"


def make_admin_client(*, audit_sink: Callable[[AuditEvent], None] | None = None):
    app = FastAPI()
    auth = CorelineAuthService(
        storage=MemoryAuthStorage(),
        config=CorelineAuthConfig(profile=AuthProfile.ADMIN_VIEWER, owner_email=None, require_email_verified=False),
        audit_sink=audit_sink,
    )
    auth.create_user(email="admin@example.com", role=Role.ADMIN, password=PASSWORD, email_verified=True)
    user = auth.create_user(email="user@example.com", role=Role.USER, password=PASSWORD, email_verified=True)
    mount_auth_routes(app, auth, secure_cookies=False)
    mount_admin_routes(app, auth)
    client = TestClient(app)

    login = client.post("/auth/login", json={"email": "admin@example.com", "password": PASSWORD})
    token = login.cookies["coreline_auth_session"]
    return auth, client, {"Authorization": f"Bearer {token}"}, user


def test_admin_routes_list_filter_role_ban_unban() -> None:
    auth, client, headers, user = make_admin_client()
    auth.create_user(email="reader@example.com", role=Role.VIEWER, password=PASSWORD, email_verified=True, display_name="Reader")

    users = client.get("/auth/admin/users", headers=headers)
    assert users.status_code == 200
    assert len(users.json()["users"]) == 3

    by_query = client.get("/auth/admin/users?query=reader", headers=headers)
    assert [row["email"] for row in by_query.json()["users"]] == ["reader@example.com"]

    by_role = client.get("/auth/admin/users?role=viewer", headers=headers)
    assert [row["email"] for row in by_role.json()["users"]] == ["reader@example.com"]

    assert client.post(f"/auth/admin/users/{user.id}/role", headers=headers, json={"role": "viewer"}).status_code == 200
    assert client.post(f"/auth/admin/users/{user.id}/ban", headers=headers).json()["user"]["status"] == "banned"

    by_status = client.get("/auth/admin/users?status=banned", headers=headers)
    assert [row["email"] for row in by_status.json()["users"]] == ["user@example.com"]

    assert client.post(f"/auth/admin/users/{user.id}/unban", headers=headers).json()["user"]["status"] == "active"



def test_cookie_admin_post_without_csrf_is_blocked_by_default() -> None:
    _, client, _, user = make_admin_client()

    response = client.post(f"/auth/admin/users/{user.id}/role", json={"role": "viewer"})

    assert response.status_code == 403


def test_admin_role_update_rejects_board_demo_roles_in_core_api() -> None:
    _, client, headers, user = make_admin_client()

    assert client.post(f"/auth/admin/users/{user.id}/role", headers=headers, json={"role": "author"}).status_code == 422
    assert client.post(f"/auth/admin/users/{user.id}/role", headers=headers, json={"role": "moderator"}).status_code == 422



def test_admin_role_update_revokes_existing_target_sessions() -> None:
    _, client, headers, user = make_admin_client()
    user_login = client.post("/auth/login", json={"email": "user@example.com", "password": PASSWORD})
    old_token = user_login.cookies["coreline_auth_session"]
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"}).status_code == 200

    response = client.post(f"/auth/admin/users/{user.id}/role", headers=headers, json={"role": "viewer"})

    assert response.status_code == 200
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"}).status_code == 401


def test_admin_ban_and_unban_reason_is_audited() -> None:
    events: list[AuditEvent] = []
    _, client, headers, user = make_admin_client(audit_sink=events.append)

    ban = client.post(f"/auth/admin/users/{user.id}/ban", headers=headers, json={"reason": "spam reports"})
    assert ban.status_code == 200
    ban_event = [event for event in events if event.action == "auth.admin.user_ban"][-1]
    assert ban_event.metadata["reason"] == "spam reports"

    unban = client.post(f"/auth/admin/users/{user.id}/unban", headers=headers, json={"reason": "appeal accepted"})
    assert unban.status_code == 200
    unban_event = [event for event in events if event.action == "auth.admin.user_unban"][-1]
    assert unban_event.metadata["reason"] == "appeal accepted"


def test_admin_session_list_and_revoke_endpoint() -> None:
    auth, client, headers, user = make_admin_client()
    user_login = client.post("/auth/login", json={"email": "user@example.com", "password": PASSWORD})
    assert user_login.status_code == 200

    sessions = client.get(f"/auth/admin/users/{user.id}/sessions", headers=headers)
    assert sessions.status_code == 200
    payload = sessions.json()["sessions"]
    assert len(payload) == 1
    assert "session_token_hash" not in payload[0]

    session_id = payload[0]["id"]
    revoked = client.post(f"/auth/admin/sessions/{session_id}/revoke", headers=headers)
    assert revoked.status_code == 200
    assert auth.storage.sessions[session_id].revoked_at is not None


def test_admin_set_password_revokes_existing_user_sessions() -> None:
    auth, client, headers, user = make_admin_client()
    user_login = client.post("/auth/login", json={"email": "user@example.com", "password": PASSWORD})
    old_token = user_login.cookies["coreline_auth_session"]

    response = client.post(f"/auth/admin/users/{user.id}/password", headers=headers, json={"password": "new correct horse"})

    assert response.status_code == 200
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"}).status_code == 401
    assert client.post("/auth/login", json={"email": "user@example.com", "password": "new correct horse"}).status_code == 200


def test_viewer_cannot_access_admin_api() -> None:
    auth, client, _, user = make_admin_client()
    auth.create_user(email="viewer@example.com", role=Role.VIEWER, password=PASSWORD, email_verified=True)
    login = client.post("/auth/login", json={"email": "viewer@example.com", "password": PASSWORD})
    viewer_headers = {"Authorization": f"Bearer {login.cookies['coreline_auth_session']}"}

    assert client.get("/auth/admin/users", headers=viewer_headers).status_code == 403
    assert client.post(f"/auth/admin/users/{user.id}/ban", headers=viewer_headers, json={"reason": "no permission"}).status_code == 403


def test_admin_audit_api_requires_audit_read_and_redacts_metadata() -> None:
    auth, client, headers, _ = make_admin_client()
    auth._audit("auth.test.secret", metadata={"access_token": "raw", "nested": {"password": "raw-password"}, "safe": "ok"})

    response = client.get("/auth/admin/audit?action=auth.test.secret", headers=headers)

    assert response.status_code == 200
    event = response.json()["events"][0]
    assert event["metadata"] == {"access_token": "[REDACTED]", "nested": {"password": "[REDACTED]"}, "safe": "ok"}

    auth.create_user(email="viewer@example.com", role=Role.VIEWER, password=PASSWORD, email_verified=True)
    viewer_login = client.post("/auth/login", json={"email": "viewer@example.com", "password": PASSWORD})
    viewer_headers = {"Authorization": f"Bearer {viewer_login.cookies['coreline_auth_session']}"}
    assert client.get("/auth/admin/audit", headers=viewer_headers).status_code == 403


def test_admin_cannot_ban_self_or_remove_last_privileged_account() -> None:
    app = FastAPI()
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.ADMIN_VIEWER, owner_email=None, require_email_verified=False))
    admin_user = auth.create_user(email="solo-admin@example.com", role=Role.ADMIN, password=PASSWORD, email_verified=True)
    mount_auth_routes(app, auth, secure_cookies=False)
    mount_admin_routes(app, auth)
    client = TestClient(app)
    login = client.post("/auth/login", json={"email": "solo-admin@example.com", "password": PASSWORD})
    headers = {"Authorization": f"Bearer {login.cookies['coreline_auth_session']}"}

    assert client.post(f"/auth/admin/users/{admin_user.id}/ban", headers=headers).status_code == 403
    assert client.post(f"/auth/admin/users/{admin_user.id}/role", headers=headers, json={"role": "viewer"}).status_code == 403


def test_audit_metadata_is_capped() -> None:
    auth, client, headers, _ = make_admin_client()
    auth._audit("auth.test.large", metadata={"safe": "x" * 1200, **{f"k{i}": i for i in range(60)}})

    response = client.get("/auth/admin/audit?action=auth.test.large", headers=headers)

    metadata = response.json()["events"][0]["metadata"]
    assert metadata["safe"].endswith("...[TRUNCATED]")
    assert metadata["_truncated"] == "max_keys"


def test_admin_audit_api_filters_since_until() -> None:
    from datetime import timedelta
    from coreline_auth.models import now_utc

    auth, client, headers, _ = make_admin_client()
    now = now_utc()
    old = AuditEvent(action="auth.test.time", metadata={"n": "old"}, created_at=now - timedelta(days=2))
    fresh = AuditEvent(action="auth.test.time", metadata={"n": "fresh"}, created_at=now)
    auth.storage.record_audit_event(old)
    auth.storage.record_audit_event(fresh)

    response = client.get(
        "/auth/admin/audit",
        headers=headers,
        params={"action": "auth.test.time", "since": (now - timedelta(hours=1)).isoformat()},
    )

    assert response.status_code == 200
    assert [event["metadata"]["n"] for event in response.json()["events"]] == ["fresh"]

    response = client.get(
        "/auth/admin/audit",
        headers=headers,
        params={"action": "auth.test.time", "until": (now - timedelta(hours=1)).isoformat()},
    )

    assert response.status_code == 200
    assert [event["metadata"]["n"] for event in response.json()["events"]] == ["old"]
