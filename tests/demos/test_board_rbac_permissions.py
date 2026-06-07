from __future__ import annotations

import pytest

from demos.board_rbac.errors import BoardAuthorizationError
from demos.board_rbac.models import BoardActor
from demos.board_rbac.service import BoardService


def actor(role: str, *, user_id: str | None = None) -> BoardActor:
    return BoardActor(id=user_id or role, email=f"{role}@example.com", role=role, status="active")


def test_board_role_matrix_uses_board_local_roles() -> None:
    service = BoardService()
    author = actor("author", user_id="author")
    other = actor("author", user_id="other")
    moderator = actor("moderator", user_id="moderator")
    viewer = actor("viewer", user_id="viewer")
    owner = actor("owner", user_id="owner")

    post = service.create_post(author, title="Author post", body="body")
    assert service.can_update_post(author, post.id)
    assert not service.can_update_post(other, post.id)
    assert service.can_update_post(moderator, post.id)
    assert service.can_delete_post(owner, post.id)

    with pytest.raises(BoardAuthorizationError):
        service.create_post(viewer, title="Viewer post", body="body")
    with pytest.raises(BoardAuthorizationError):
        service.update_post(other, post.id, title="bad")


def test_board_comment_ownership_and_moderation() -> None:
    service = BoardService()
    author = actor("author", user_id="author")
    commenter = actor("author", user_id="commenter")
    other = actor("user", user_id="other")
    moderator = actor("moderator", user_id="moderator")

    post = service.create_post(author, title="Post", body="body")
    comment = service.create_comment(commenter, post.id, body="hello")

    updated = service.update_comment(commenter, comment.id, body="updated")
    assert updated.body == "updated"
    with pytest.raises(BoardAuthorizationError):
        service.update_comment(other, comment.id, body="bad")
    with pytest.raises(BoardAuthorizationError):
        service.delete_comment(other, comment.id)
    service.delete_comment(moderator, comment.id)
    assert service.list_comments(author, post.id) == []


def test_inactive_actor_is_denied_even_with_role() -> None:
    service = BoardService()
    inactive = BoardActor(id="inactive", email="inactive@example.com", role="owner", status="disabled")
    with pytest.raises(BoardAuthorizationError):
        service.list_posts(inactive)
