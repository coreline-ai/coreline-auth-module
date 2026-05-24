from __future__ import annotations

from dataclasses import replace

import pytest

from coreline_auth import AuthProfile, AuthenticationFailed, AuthorizationDenied, CorelineAuthConfig, CorelineAuthService, Role
from coreline_auth.examples.board_service import (
    BOARD_COMMENT_CREATE,
    BOARD_COMMENT_DELETE_ANY,
    BOARD_COMMENT_DELETE_OWN,
    BOARD_POST_CREATE,
    BOARD_POST_DELETE_ANY,
    BOARD_POST_DELETE_OWN,
    BOARD_POST_UPDATE_ANY,
    BOARD_POST_UPDATE_OWN,
    BOARD_READ,
    BoardService,
)
from coreline_auth.storage import MemoryAuthStorage


def make_auth() -> CorelineAuthService:
    return CorelineAuthService(
        storage=MemoryAuthStorage(),
        config=CorelineAuthConfig(profile=AuthProfile.ADMIN_VIEWER, owner_email=None, require_email_verified=False),
    )


def issue_token(auth: CorelineAuthService, *, email: str, role: Role = Role.USER, permissions: tuple[str, ...]) -> str:
    user = auth.create_user(email=email, role=role, email_verified=True)
    issued = auth.issue_session(user, provider="pytest")
    auth.storage.update_session(replace(issued.session, permissions=permissions))
    return issued.token


def test_board_read_create_and_detail_permissions() -> None:
    auth = make_auth()
    board = BoardService(auth=auth)
    author_token = issue_token(auth, email="author@example.com", permissions=(BOARD_READ, BOARD_POST_CREATE, BOARD_COMMENT_CREATE))
    reader_token = issue_token(auth, email="reader@example.com", permissions=(BOARD_READ,))
    no_read_token = issue_token(auth, email="blocked@example.com", permissions=(BOARD_POST_CREATE,))

    post = board.create_post(author_token, title="  First post  ", body="Hello board")
    comment = board.create_comment(author_token, post.id, body="Nice thread")

    assert post.title == "First post"
    assert board.list_posts(reader_token) == [post]
    detail = board.get_post_detail(reader_token, post.id)
    assert detail.post == post
    assert detail.comments == (comment,)
    with pytest.raises(AuthenticationFailed):
        board.list_posts("not-a-session-token")
    with pytest.raises(AuthorizationDenied):
        board.list_posts(no_read_token)
    with pytest.raises(AuthorizationDenied):
        board.get_post_detail(no_read_token, post.id)


def test_post_create_update_delete_own_and_any_permissions() -> None:
    auth = make_auth()
    board = BoardService(auth=auth)
    author_token = issue_token(
        auth,
        email="author@example.com",
        permissions=(BOARD_READ, BOARD_POST_CREATE, BOARD_POST_UPDATE_OWN, BOARD_POST_DELETE_OWN),
    )
    other_token = issue_token(auth, email="other@example.com", permissions=(BOARD_READ, BOARD_POST_UPDATE_OWN, BOARD_POST_DELETE_OWN))
    moderator_token = issue_token(auth, email="moderator@example.com", permissions=(BOARD_READ, BOARD_POST_UPDATE_ANY, BOARD_POST_DELETE_ANY))
    create_denied_token = issue_token(auth, email="no-create@example.com", permissions=(BOARD_READ,))

    with pytest.raises(AuthorizationDenied):
        board.create_post(create_denied_token, title="Nope", body="Missing create permission")

    own_post = board.create_post(author_token, title="Original", body="Body")
    updated_by_owner = board.update_post(author_token, own_post.id, title="Owner edit")
    assert updated_by_owner.title == "Owner edit"

    with pytest.raises(AuthorizationDenied):
        board.update_post(other_token, own_post.id, body="Cross-user edit")
    updated_by_moderator = board.update_post(moderator_token, own_post.id, body="Moderator edit")
    assert updated_by_moderator.body == "Moderator edit"

    own_delete_post = board.create_post(author_token, title="Delete me", body="Owned post")
    board.delete_post(author_token, own_delete_post.id)
    assert [post.id for post in board.list_posts(author_token)] == [own_post.id]

    any_delete_post = board.create_post(author_token, title="Mod delete me", body="Moderated post")
    with pytest.raises(AuthorizationDenied):
        board.delete_post(other_token, any_delete_post.id)
    board.delete_post(moderator_token, any_delete_post.id)
    assert [post.id for post in board.list_posts(author_token)] == [own_post.id]


def test_comment_create_and_delete_own_or_any_permissions() -> None:
    auth = make_auth()
    board = BoardService(auth=auth)
    author_token = issue_token(auth, email="author@example.com", permissions=(BOARD_READ, BOARD_POST_CREATE))
    commenter_token = issue_token(auth, email="commenter@example.com", permissions=(BOARD_READ, BOARD_COMMENT_CREATE, BOARD_COMMENT_DELETE_OWN))
    other_token = issue_token(auth, email="other@example.com", permissions=(BOARD_READ, BOARD_COMMENT_DELETE_OWN))
    moderator_token = issue_token(auth, email="moderator@example.com", permissions=(BOARD_READ, BOARD_COMMENT_DELETE_ANY))
    no_create_token = issue_token(auth, email="no-comment@example.com", permissions=(BOARD_READ,))

    post = board.create_post(author_token, title="Comments", body="Thread")
    with pytest.raises(AuthorizationDenied):
        board.create_comment(no_create_token, post.id, body="Blocked")

    own_comment = board.create_comment(commenter_token, post.id, body="I can remove this")
    board.delete_comment(commenter_token, own_comment.id)
    assert board.get_post_detail(commenter_token, post.id).comments == ()

    moderated_comment = board.create_comment(commenter_token, post.id, body="Needs moderation")
    with pytest.raises(AuthorizationDenied):
        board.delete_comment(other_token, moderated_comment.id)
    board.delete_comment(moderator_token, moderated_comment.id)
    assert board.get_post_detail(commenter_token, post.id).comments == ()


def test_board_admin_wildcard_permissions_work_with_core_auth_session() -> None:
    auth = make_auth()
    board = BoardService(auth=auth)
    admin = auth.create_user(email="admin@example.com", role=Role.ADMIN, email_verified=True)
    issued = auth.issue_session(admin, provider="pytest")

    post = board.create_post(issued.token, title="Admin post", body="Admin can use wildcard")
    board.update_post(issued.token, post.id, body="Updated")
    comment = board.create_comment(issued.token, post.id, body="Admin comment")
    board.delete_comment(issued.token, comment.id)
    board.delete_post(issued.token, post.id)
    assert board.list_posts(issued.token) == []
