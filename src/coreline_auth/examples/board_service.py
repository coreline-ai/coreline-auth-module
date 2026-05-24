"""Auth-protected board domain service for the Coreline Auth example."""

from __future__ import annotations

from dataclasses import dataclass, replace
from uuid import uuid4

from coreline_auth import AuthenticationFailed, AuthorizationContext, AuthorizationDenied, CorelineAuthService, PolicyEngine, Principal, ResourceAuthorizer
from coreline_auth.errors import AuthValidationError
from coreline_auth.models import AuthProfile

from .board_models import BoardComment, BoardPost, BoardPostDetail
from .board_storage import MemoryBoardStorage

BOARD_READ = "board:read"
BOARD_POST_CREATE = "post:create"
BOARD_POST_UPDATE_OWN = "post:update:own"
BOARD_POST_UPDATE_ANY = "post:update:any"
BOARD_POST_DELETE_OWN = "post:delete:own"
BOARD_POST_DELETE_ANY = "post:delete:any"
BOARD_COMMENT_CREATE = "comment:create"
BOARD_COMMENT_UPDATE_OWN = "comment:update:own"
BOARD_COMMENT_UPDATE_ANY = "comment:update:any"
BOARD_COMMENT_DELETE_OWN = "comment:delete:own"
BOARD_COMMENT_DELETE_ANY = "comment:delete:any"


@dataclass(frozen=True, slots=True)
class BoardAuthorizationContext:
    principal: Principal
    permission: str
    resource_type: str = "board"
    resource_id: str | None = None
    owner_user_id: str | None = None


class BoardService:
    """Post/comment service using Coreline Auth sessions and RBAC permissions."""

    def __init__(
        self,
        auth: CorelineAuthService,
        *,
        storage: MemoryBoardStorage | None = None,
        authorizer: ResourceAuthorizer | None = None,
    ) -> None:
        self.auth = auth
        self.storage = storage or MemoryBoardStorage()
        self.policy = PolicyEngine(profile=AuthProfile.RBAC)
        self.authorizer = authorizer or ResourceAuthorizer(policy=self.policy)

    def list_posts(self, session_token: str) -> list[BoardPost]:
        self._authorize(session_token, BOARD_READ)
        return self.storage.list_posts()

    def get_post(self, session_token: str, post_id: str) -> BoardPost:
        self._authorize(session_token, BOARD_READ, resource_id=post_id)
        return self._require_post(post_id)

    def get_post_detail(self, session_token: str, post_id: str) -> BoardPostDetail:
        post = self.get_post(session_token, post_id)
        comments = tuple(self.storage.list_comments(post_id))
        return BoardPostDetail(post=post, comments=comments)

    def create_post(self, session_token: str, *, title: str, body: str) -> BoardPost:
        principal = self._authorize(session_token, BOARD_POST_CREATE)
        post = BoardPost(
            id=f"post_{uuid4().hex}",
            author_user_id=principal.user_id,
            title=self._clean_required(title, field_name="title", max_length=200),
            body=self._clean_required(body, field_name="body", max_length=20_000),
        )
        return self.storage.create_post(post)

    def update_post(self, session_token: str, post_id: str, *, title: str | None = None, body: str | None = None) -> BoardPost:
        principal = self._verify_session(session_token)
        post = self._require_post(post_id)
        self._authorize_owned_principal(
            principal,
            own_permission=BOARD_POST_UPDATE_OWN,
            any_permission=BOARD_POST_UPDATE_ANY,
            owner_user_id=post.author_user_id,
            resource_id=post.id,
        )
        updated = replace(
            post,
            title=self._clean_required(title, field_name="title", max_length=200) if title is not None else post.title,
            body=self._clean_required(body, field_name="body", max_length=20_000) if body is not None else post.body,
        )
        return self.storage.update_post(updated)

    def delete_post(self, session_token: str, post_id: str) -> None:
        principal = self._verify_session(session_token)
        post = self._require_post(post_id)
        self._authorize_owned_principal(
            principal,
            own_permission=BOARD_POST_DELETE_OWN,
            any_permission=BOARD_POST_DELETE_ANY,
            owner_user_id=post.author_user_id,
            resource_id=post.id,
        )
        self.storage.delete_post(post_id)

    def can_update_post(self, session_token: str, post_id: str) -> bool:
        return self._can_manage_post(session_token, post_id, own_permission=BOARD_POST_UPDATE_OWN, any_permission=BOARD_POST_UPDATE_ANY)

    def can_delete_post(self, session_token: str, post_id: str) -> bool:
        return self._can_manage_post(session_token, post_id, own_permission=BOARD_POST_DELETE_OWN, any_permission=BOARD_POST_DELETE_ANY)

    def list_comments(self, session_token: str, post_id: str) -> list[BoardComment]:
        self._authorize(session_token, BOARD_READ, resource_id=post_id)
        return self.storage.list_comments(post_id)

    def get_comment(self, session_token: str, comment_id: str) -> BoardComment:
        principal = self._verify_session(session_token)
        comment = self._require_comment(comment_id)
        self._authorize_principal(principal, BOARD_READ, resource_id=comment.post_id)
        return comment

    def create_comment(self, session_token: str, post_id: str, *, body: str) -> BoardComment:
        principal = self._authorize(session_token, BOARD_COMMENT_CREATE, resource_id=post_id)
        self._require_post(post_id)
        comment = BoardComment(
            id=f"comment_{uuid4().hex}",
            post_id=post_id,
            author_user_id=principal.user_id,
            body=self._clean_required(body, field_name="body", max_length=10_000),
        )
        return self.storage.create_comment(comment)

    def update_comment(self, session_token: str, comment_id: str, *, body: str) -> BoardComment:
        principal = self._verify_session(session_token)
        comment = self._require_comment(comment_id)
        self._authorize_owned_principal(
            principal,
            own_permission=BOARD_COMMENT_UPDATE_OWN,
            any_permission=BOARD_COMMENT_UPDATE_ANY,
            owner_user_id=comment.author_user_id,
            resource_id=comment.id,
        )
        return self.storage.update_comment(replace(comment, body=self._clean_required(body, field_name="body", max_length=10_000)))

    def delete_comment(self, session_token: str, comment_id: str) -> None:
        principal = self._verify_session(session_token)
        comment = self._require_comment(comment_id)
        self._authorize_owned_principal(
            principal,
            own_permission=BOARD_COMMENT_DELETE_OWN,
            any_permission=BOARD_COMMENT_DELETE_ANY,
            owner_user_id=comment.author_user_id,
            resource_id=comment.id,
        )
        self.storage.delete_comment(comment_id)

    def _can_manage_post(self, session_token: str, post_id: str, *, own_permission: str, any_permission: str) -> bool:
        try:
            principal = self._verify_session(session_token)
            post = self._require_post(post_id)
            self._authorize_owned_principal(
                principal,
                own_permission=own_permission,
                any_permission=any_permission,
                owner_user_id=post.author_user_id,
                resource_id=post.id,
            )
            return True
        except (AuthenticationFailed, AuthorizationDenied, AuthValidationError):
            return False

    def _authorize(self, session_token: str, permission: str, *, resource_id: str | None = None, owner_user_id: str | None = None) -> Principal:
        principal = self._verify_session(session_token)
        self._authorize_principal(principal, permission, resource_id=resource_id, owner_user_id=owner_user_id)
        return principal

    def _authorize_principal(self, principal: Principal, permission: str, *, resource_id: str | None = None, owner_user_id: str | None = None) -> None:
        self.authorizer.require(
            principal.session.permissions,
            permission,
            context=self._build_context(principal, resource_id=resource_id, owner_user_id=owner_user_id),
        )

    def _authorize_owned_principal(self, principal: Principal, *, own_permission: str, any_permission: str, owner_user_id: str, resource_id: str) -> None:
        context = self._build_context(principal, resource_id=resource_id, owner_user_id=owner_user_id)
        if self.authorizer.can(principal.session.permissions, own_permission, context=context).allowed:
            return
        if self.authorizer.can(principal.session.permissions, any_permission, context=context).allowed:
            return
        expected = own_permission if principal.user_id == owner_user_id else any_permission
        raise AuthorizationDenied(f"missing permission: {expected}")

    def _verify_session(self, session_token: str) -> Principal:
        if not session_token:
            raise AuthenticationFailed("invalid session")
        return self.auth.verify_session(session_token)

    def _build_context(self, principal: Principal, *, resource_id: str | None, owner_user_id: str | None) -> AuthorizationContext:
        return AuthorizationContext(
            actor_user_id=principal.user_id,
            actor_role=principal.session.role,
            actor_status=principal.user.status,
            resource_owner_id=owner_user_id,
            metadata={"resource_type": "board", "resource_id": resource_id} if resource_id else {"resource_type": "board"},
        )

    def _require_post(self, post_id: str) -> BoardPost:
        post = self.storage.get_post(post_id)
        if post is None:
            raise AuthValidationError("board post not found")
        return post

    def _require_comment(self, comment_id: str) -> BoardComment:
        comment = self.storage.get_comment(comment_id)
        if comment is None:
            raise AuthValidationError("board comment not found")
        return comment

    def _clean_required(self, value: str, *, field_name: str, max_length: int) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise AuthValidationError(f"board {field_name} is required")
        if len(cleaned) > max_length:
            raise AuthValidationError(f"board {field_name} is too long")
        return cleaned
