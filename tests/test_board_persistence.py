from __future__ import annotations

from coreline_auth import AuthProfile, CorelineAuthConfig, CorelineAuthService, Role
from coreline_auth.examples.board_service import BoardService
from coreline_auth.examples.board_storage import SQLiteBoardStorage
from coreline_auth.storage import MemoryAuthStorage


def test_sqlite_board_storage_persists_posts_and_comments(tmp_path) -> None:
    db_path = tmp_path / "auth-and-board.sqlite3"
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    user = auth.create_user(email="author@example.com", role=Role.AUTHOR, password="correct horse battery", email_verified=True)
    issued = auth.issue_session(user, provider="pytest")

    first_storage = SQLiteBoardStorage(db_path)
    try:
        first_service = BoardService(auth, storage=first_storage)
        post = first_service.create_post(issued.token, title="Persistent", body="Saved body")
        comment = first_service.create_comment(issued.token, post.id, body="Saved comment")
    finally:
        first_storage.close()

    second_storage = SQLiteBoardStorage(db_path)
    try:
        second_service = BoardService(auth, storage=second_storage)
        detail = second_service.get_post_detail(issued.token, post.id)
        assert detail.post.title == "Persistent"
        assert detail.comments[0].id == comment.id
        assert detail.comments[0].body == "Saved comment"
    finally:
        second_storage.close()
