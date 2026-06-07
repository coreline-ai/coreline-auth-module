"""Adapters between Coreline Auth sessions and board demo actors."""

from __future__ import annotations

from typing import Protocol

from coreline_auth import AuthenticationFailed, CorelineAuthService

from .errors import BoardAuthenticationError
from .models import BoardActor


class SessionVerifier(Protocol):
    def verify(self, token: str) -> BoardActor: ...


class UserDirectory(Protocol):
    def label_for_user(self, user_id: str) -> str: ...


class DemoBoardSessionVerifier:
    """Map Coreline Auth sessions into board-owned demo roles.

    Coreline Auth intentionally keeps only auth-owned roles. This repo-local
    demo keeps its author/moderator vocabulary inside ``demos.board_rbac`` and
    maps seeded users to board roles after session verification.
    """

    def __init__(self, auth: CorelineAuthService, board_roles_by_user_id: dict[str, str]) -> None:
        self.auth = auth
        self.board_roles_by_user_id = board_roles_by_user_id

    def verify(self, token: str) -> BoardActor:
        if not token:
            raise BoardAuthenticationError("invalid session")
        try:
            principal = self.auth.verify_session(token)
        except AuthenticationFailed as exc:
            raise BoardAuthenticationError(str(exc)) from exc
        return BoardActor(
            id=principal.user_id,
            email=principal.email,
            role=self.board_roles_by_user_id.get(principal.user_id, principal.session.role.value),
            status=principal.user.status.value,
        )


class CorelineAuthUserDirectory:
    def __init__(self, auth: CorelineAuthService) -> None:
        self.auth = auth

    def label_for_user(self, user_id: str) -> str:
        user = self.auth.storage.get_user(user_id)
        if user is None:
            return user_id
        return user.primary_email


class StaticUserDirectory:
    def __init__(self, labels: dict[str, str] | None = None) -> None:
        self.labels = labels or {}

    def label_for_user(self, user_id: str) -> str:
        return self.labels.get(user_id, user_id)
