"""Board demo domain service.

The domain service accepts ``BoardActor`` objects. Raw session tokens are handled
only by web/auth adapters and are never passed into storage.
"""

from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

from .errors import BoardAuthenticationError, BoardAuthorizationError, BoardNotFoundError, BoardValidationError
from .models import BoardActor, BoardComment, BoardPost, BoardPostDetail
from .permissions import (
    BOARD_COMMENT_CREATE,
    BOARD_COMMENT_DELETE_ANY,
    BOARD_COMMENT_DELETE_OWN,
    BOARD_COMMENT_UPDATE_ANY,
    BOARD_COMMENT_UPDATE_OWN,
    BOARD_POST_CREATE,
    BOARD_POST_DELETE_ANY,
    BOARD_POST_DELETE_OWN,
    BOARD_POST_UPDATE_ANY,
    BOARD_POST_UPDATE_OWN,
    BOARD_READ,
    BoardPermissionResolver,
)
from .storage import BoardStorageProtocol, MemoryBoardStorage


class BoardService:
    def __init__(self, *, storage: BoardStorageProtocol | None = None, permission_resolver: BoardPermissionResolver | None = None) -> None:
        self.storage = storage or MemoryBoardStorage()
        self.permissions = permission_resolver or BoardPermissionResolver()

    def list_posts(self, actor: BoardActor) -> list[BoardPost]:
        self._authorize(actor, BOARD_READ)
        return self.storage.list_posts()

    def get_post(self, actor: BoardActor, post_id: str) -> BoardPost:
        self._authorize(actor, BOARD_READ)
        return self._require_post(post_id)

    def get_post_detail(self, actor: BoardActor, post_id: str) -> BoardPostDetail:
        post = self.get_post(actor, post_id)
        comments = tuple(self.storage.list_comments(post_id))
        return BoardPostDetail(post=post, comments=comments)

    def create_post(self, actor: BoardActor, *, title: str, body: str) -> BoardPost:
        self._authorize(actor, BOARD_POST_CREATE)
        post = BoardPost(
            id=f"post_{uuid4().hex}",
            author_user_id=actor.id,
            title=self._clean_required(title, field_name="title", max_length=200),
            body=self._clean_required(body, field_name="body", max_length=20_000),
        )
        return self.storage.create_post(post)

    def update_post(self, actor: BoardActor, post_id: str, *, title: str | None = None, body: str | None = None) -> BoardPost:
        post = self._require_post(post_id)
        self._authorize_owned(actor, own_permission=BOARD_POST_UPDATE_OWN, any_permission=BOARD_POST_UPDATE_ANY, owner_user_id=post.author_user_id)
        updated = replace(
            post,
            title=self._clean_required(title, field_name="title", max_length=200) if title is not None else post.title,
            body=self._clean_required(body, field_name="body", max_length=20_000) if body is not None else post.body,
        )
        return self.storage.update_post(updated)

    def delete_post(self, actor: BoardActor, post_id: str) -> None:
        post = self._require_post(post_id)
        self._authorize_owned(actor, own_permission=BOARD_POST_DELETE_OWN, any_permission=BOARD_POST_DELETE_ANY, owner_user_id=post.author_user_id)
        self.storage.delete_post(post_id)

    def can_update_post(self, actor: BoardActor, post_id: str) -> bool:
        return self._can_manage_post(actor, post_id, own_permission=BOARD_POST_UPDATE_OWN, any_permission=BOARD_POST_UPDATE_ANY)

    def can_delete_post(self, actor: BoardActor, post_id: str) -> bool:
        return self._can_manage_post(actor, post_id, own_permission=BOARD_POST_DELETE_OWN, any_permission=BOARD_POST_DELETE_ANY)

    def list_comments(self, actor: BoardActor, post_id: str) -> list[BoardComment]:
        self._authorize(actor, BOARD_READ)
        return self.storage.list_comments(post_id)

    def get_comment(self, actor: BoardActor, comment_id: str) -> BoardComment:
        self._authorize(actor, BOARD_READ)
        return self._require_comment(comment_id)

    def create_comment(self, actor: BoardActor, post_id: str, *, body: str) -> BoardComment:
        self._authorize(actor, BOARD_COMMENT_CREATE)
        self._require_post(post_id)
        comment = BoardComment(
            id=f"comment_{uuid4().hex}",
            post_id=post_id,
            author_user_id=actor.id,
            body=self._clean_required(body, field_name="body", max_length=10_000),
        )
        return self.storage.create_comment(comment)

    def update_comment(self, actor: BoardActor, comment_id: str, *, body: str) -> BoardComment:
        comment = self._require_comment(comment_id)
        self._authorize_owned(actor, own_permission=BOARD_COMMENT_UPDATE_OWN, any_permission=BOARD_COMMENT_UPDATE_ANY, owner_user_id=comment.author_user_id)
        return self.storage.update_comment(replace(comment, body=self._clean_required(body, field_name="body", max_length=10_000)))

    def delete_comment(self, actor: BoardActor, comment_id: str) -> None:
        comment = self._require_comment(comment_id)
        self._authorize_owned(actor, own_permission=BOARD_COMMENT_DELETE_OWN, any_permission=BOARD_COMMENT_DELETE_ANY, owner_user_id=comment.author_user_id)
        self.storage.delete_comment(comment_id)

    def can(self, actor: BoardActor, permission: str) -> bool:
        try:
            self._authorize(actor, permission)
            return True
        except (BoardAuthenticationError, BoardAuthorizationError):
            return False

    def _can_manage_post(self, actor: BoardActor, post_id: str, *, own_permission: str, any_permission: str) -> bool:
        try:
            post = self._require_post(post_id)
            self._authorize_owned(actor, own_permission=own_permission, any_permission=any_permission, owner_user_id=post.author_user_id)
            return True
        except (BoardAuthenticationError, BoardAuthorizationError, BoardValidationError):
            return False

    def _actor_permissions(self, actor: BoardActor) -> tuple[str, ...]:
        if not actor or not actor.id:
            raise BoardAuthenticationError("invalid board actor")
        if actor.status.lower() != "active":
            raise BoardAuthorizationError("actor is not active")
        return self.permissions.permissions_for(role=actor.role, explicit_permissions=actor.permissions)

    def _authorize(self, actor: BoardActor, permission: str) -> None:
        permissions = self._actor_permissions(actor)
        if not self.permissions.allows(permissions, permission):
            raise BoardAuthorizationError(f"missing permission: {permission}")

    def _authorize_owned(self, actor: BoardActor, *, own_permission: str, any_permission: str, owner_user_id: str) -> None:
        permissions = self._actor_permissions(actor)
        if actor.id == owner_user_id and self.permissions.allows(permissions, own_permission):
            return
        if self.permissions.allows(permissions, any_permission):
            return
        expected = own_permission if actor.id == owner_user_id else any_permission
        raise BoardAuthorizationError(f"missing permission: {expected}")

    def _require_post(self, post_id: str) -> BoardPost:
        post = self.storage.get_post(post_id)
        if post is None:
            raise BoardNotFoundError("board post not found")
        return post

    def _require_comment(self, comment_id: str) -> BoardComment:
        comment = self.storage.get_comment(comment_id)
        if comment is None:
            raise BoardNotFoundError("board comment not found")
        return comment

    @staticmethod
    def _clean_required(value: str, *, field_name: str, max_length: int) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise BoardValidationError(f"board {field_name} is required")
        if len(cleaned) > max_length:
            raise BoardValidationError(f"board {field_name} is too long")
        return cleaned
