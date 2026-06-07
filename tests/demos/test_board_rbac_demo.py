from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from coreline_auth import Role
from demos.board_rbac.app import create_app
from demos.board_rbac.seed import DEMO_BOARD_PASSWORD, DEMO_BOARD_USERS


def client() -> TestClient:
    return TestClient(create_app(use_sqlite=False), raise_server_exceptions=False)


def csrf_from_page(text: str) -> str:
    return text.split("name='csrf_token' value='", 1)[1].split("'", 1)[0]


def login(client: TestClient, email: str, *, next_path: str = "/demo-board") -> None:
    response = client.post(
        "/login",
        data={"email": email, "password": DEMO_BOARD_PASSWORD, "next": next_path},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == next_path
    assert "coreline_board_demo_session" in response.cookies


def test_home_and_login_show_role_account_selector() -> None:
    c = client()
    home = c.get("/")
    assert home.status_code == 200
    assert "권한별 테스트 계정" in home.text
    assert DEMO_BOARD_PASSWORD in home.text
    for entry in DEMO_BOARD_USERS:
        assert entry.email in home.text
        assert f"data-board-role='{entry.board_role}'" in home.text

    login_page = c.get("/login?email=author-board@example.com&next=/demo-board")
    assert login_page.status_code == 200
    assert "value='author-board@example.com'" in login_page.text
    assert f"value='{DEMO_BOARD_PASSWORD}'" in login_page.text
    assert "Board role" in login_page.text


def test_invalid_selected_email_is_ignored() -> None:
    c = client()
    page = c.get("/login?email=evil@example.com")
    assert page.status_code == 200
    assert "value='owner-board@example.com'" in page.text
    assert "value='evil@example.com'" not in page.text


def test_login_next_rejects_open_redirect() -> None:
    c = client()
    response = c.post(
        "/login",
        data={"email": "author-board@example.com", "password": DEMO_BOARD_PASSWORD, "next": "https://evil.example/callback"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/demo-board"


@pytest.mark.parametrize("bad_next", ["//evil.example", "/ok\r\nX: bad"])
def test_login_next_rejects_protocol_relative_and_header_injection(bad_next: str) -> None:
    c = client()
    response = c.post(
        "/login",
        data={"email": "author-board@example.com", "password": DEMO_BOARD_PASSWORD, "next": bad_next},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/demo-board"


def test_author_can_create_post_but_cannot_edit_other_post() -> None:
    c = client()
    login(c, "author-board@example.com")

    new_page = c.get("/demo-board/new")
    assert new_page.status_code == 200
    created = c.post(
        "/demo-board",
        data={"title": "Author created", "body": "body", "csrf_token": csrf_from_page(new_page.text)},
        follow_redirects=False,
    )
    assert created.status_code == 303
    assert created.headers["location"].startswith("/demo-board/post_")

    detail = c.get("/demo-board/seed_post_admin")
    assert detail.status_code == 200
    denied = c.post(
        "/demo-board/seed_post_admin/edit",
        data={"title": "bad", "body": "bad", "csrf_token": csrf_from_page(detail.text)},
        follow_redirects=False,
    )
    assert denied.status_code == 403
    assert "게시글 수정 실패" in denied.text


def test_moderator_can_edit_other_post() -> None:
    c = client()
    login(c, "moderator-board@example.com")

    edit_page = c.get("/demo-board/seed_post_author/edit")
    assert edit_page.status_code == 200
    saved = c.post(
        "/demo-board/seed_post_author/edit",
        data={"title": "Moderated title", "body": "updated by moderator", "csrf_token": csrf_from_page(edit_page.text)},
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert saved.headers["location"] == "/demo-board/seed_post_author"
    assert "Moderated title" in c.get(saved.headers["location"]).text


def test_viewer_is_read_only_in_ui_and_post_guard() -> None:
    c = client()
    login(c, "viewer-board@example.com")

    index = c.get("/demo-board")
    assert index.status_code == 200
    assert "새 글 작성 불가" in index.text
    assert "href='/demo-board/new'" not in index.text

    new_page = c.get("/demo-board/new")
    assert new_page.status_code == 403
    denied = c.post(
        "/demo-board",
        data={"title": "viewer", "body": "no", "csrf_token": c.cookies.get("coreline_board_demo_csrf", "")},
        follow_redirects=False,
    )
    assert denied.status_code == 403
    assert "missing permission: post:create" in denied.text


def test_owner_can_delete_any_post() -> None:
    c = client()
    login(c, "owner-board@example.com")

    detail = c.get("/demo-board/seed_post_user")
    assert detail.status_code == 200
    deleted = c.post(
        "/demo-board/seed_post_user/delete",
        data={"csrf_token": csrf_from_page(detail.text)},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/demo-board"
    assert c.get("/demo-board/seed_post_user").status_code == 404


def test_missing_or_stale_csrf_rejects_state_change() -> None:
    c = client()
    login(c, "author-board@example.com")
    denied = c.post(
        "/demo-board",
        data={"title": "bad", "body": "bad", "csrf_token": "stale.invalid"},
        follow_redirects=False,
    )
    assert denied.status_code == 403
    assert "missing or invalid csrf token" in denied.text


def test_auth_role_enum_remains_auth_only() -> None:
    with pytest.raises(ValueError):
        Role("author")
    with pytest.raises(ValueError):
        Role("moderator")
