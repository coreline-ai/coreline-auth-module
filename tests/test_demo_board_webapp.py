from __future__ import annotations

from urllib.parse import urlparse
from uuid import uuid4

from fastapi.testclient import TestClient

from demo_app_helper import load_demo_app


def _path(location: str) -> str:
    parsed = urlparse(location)
    return parsed.path or location


def _csrf_from_page(text: str) -> str:
    return text.split("name='csrf_token' value='", 1)[1].split("'", 1)[0]


def _csrf(client: TestClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    return _csrf_from_page(response.text)


def _signup(client: TestClient, *, prefix: str = "board-user") -> str:
    email = f"{prefix}-{uuid4().hex}@example.com"
    response = client.post(
        "/signup",
        data={"email": email, "password": "board-password", "display_name": "Board User", "csrf_token": _csrf(client, "/signup")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "coreline_auth_session" in response.cookies
    return email


def _create_post(client: TestClient, *, title: str | None = None, body: str = "게시판 본문") -> str:
    response = client.post(
        "/board",
        data={"title": title or f"게시판 테스트 {uuid4().hex}", "body": body, "csrf_token": _csrf(client, "/board/new")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return _path(response.headers["location"])


def test_board_requires_login_and_global_menu_links(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)

    response = client.get("/board", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    login_page = client.get("/login")
    assert "권한별 게시판 테스트 계정" in login_page.text
    assert "href='/signup'" in login_page.text
    assert "href='/admin'" not in login_page.text
    assert "href='/board'" not in login_page.text
    assert "href='/login?next=/board'" in login_page.text
    assert "로그인 후 RBAC 게시판 열기" in login_page.text


def test_board_post_detail_and_comment_flow_uses_session_cookie(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    client = TestClient(demo.app)
    email = _signup(client, prefix="board-author")

    board = client.get("/board")
    assert board.status_code == 200
    assert "게시판" in board.text
    assert email in board.text

    assert client.get("/board/new").status_code == 200
    title = f"댓글 플로우 {uuid4().hex}"
    post_path = _create_post(client, title=title, body="본문입니다.")

    detail = client.get(post_path)
    assert detail.status_code == 200
    assert title in detail.text
    assert "본문입니다." in detail.text
    assert "댓글 작성" in detail.text

    comment = client.post(f"{post_path}/comments", data={"body": "첫 댓글입니다.", "csrf_token": _csrf_from_page(detail.text)}, follow_redirects=False)
    assert comment.status_code == 303
    assert _path(comment.headers["location"]) == post_path

    updated = client.get(post_path)
    assert "첫 댓글입니다." in updated.text
    assert email in updated.text


def test_board_other_user_edit_and_delete_are_forbidden(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    author = TestClient(demo.app)
    _signup(author, prefix="board-owner")
    post_path = _create_post(author, title=f"권한 테스트 {uuid4().hex}", body="원본")

    other = TestClient(demo.app)
    _signup(other, prefix="board-other")

    detail = other.get(post_path)
    assert detail.status_code == 200
    assert "수정/삭제할 수 없습니다" in detail.text

    edit_page = other.get(f"{post_path}/edit")
    assert edit_page.status_code == 403
    assert "권한 없음" in edit_page.text

    csrf_token = _csrf_from_page(detail.text)
    edit = other.post(f"{post_path}/edit", data={"title": "탈취", "body": "변경", "csrf_token": csrf_token}, follow_redirects=False)
    assert edit.status_code == 403

    delete = other.post(f"{post_path}/delete", data={"csrf_token": csrf_token}, follow_redirects=False)
    assert delete.status_code == 403

    still_there = author.get(post_path)
    assert still_there.status_code == 200
    assert "원본" in still_there.text
    assert "탈취" not in still_there.text


def _login(client: TestClient, *, email: str, password: str = "coreline-demo-password") -> None:
    response = client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": _csrf(client, "/login")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "coreline_auth_session" in response.cookies


def test_demo_board_seeds_role_accounts_and_permission_posts(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)
    login_page = TestClient(demo.app).get("/login")
    assert login_page.status_code == 200
    assert "권한별 게시판 테스트 계정" in login_page.text
    assert "viewer-board@example.com" in login_page.text
    assert "moderator-board@example.com" in login_page.text

    for role in ("owner", "admin", "moderator", "author", "user", "viewer"):
        client = TestClient(demo.app)
        _login(client, email=f"{role}-board@example.com")
        board = client.get("/board")
        assert board.status_code == 200
        assert f"[{role}]" in board.text
        assert "[admin] 관리자 권한 테스트 게시글" in board.text


def test_demo_board_seeded_roles_exercise_different_permissions(monkeypatch, tmp_path) -> None:
    demo = load_demo_app(monkeypatch, tmp_path)

    viewer = TestClient(demo.app)
    _login(viewer, email="viewer-board@example.com")
    assert viewer.get("/board").status_code == 200
    denied_create = viewer.post(
        "/board",
        data={"title": "viewer write", "body": "should fail", "csrf_token": _csrf(viewer, "/board/new")},
        follow_redirects=False,
    )
    assert denied_create.status_code == 403

    user = TestClient(demo.app)
    _login(user, email="user-board@example.com")
    user_detail = user.get("/board/seed_post_user")
    assert user_detail.status_code == 200
    assert "수정/삭제할 수 없습니다" in user_detail.text
    denied_edit = user.post(
        "/board/seed_post_user/edit",
        data={"title": "user edit", "body": "should fail", "csrf_token": _csrf_from_page(user_detail.text)},
        follow_redirects=False,
    )
    assert denied_edit.status_code == 403

    author = TestClient(demo.app)
    _login(author, email="author-board@example.com")
    assert author.get("/board/seed_post_author/edit").status_code == 200

    moderator = TestClient(demo.app)
    _login(moderator, email="moderator-board@example.com")
    assert moderator.get("/board/seed_post_admin/edit").status_code == 200
