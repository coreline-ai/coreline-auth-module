"""Admin-mode core service.

The service mirrors proven auth admin patterns: list users, update roles, ban or
unban users, set passwords, and revoke sessions. HTTP exposure is provided by the
FastAPI adapter and remains permission-protected.
"""

from __future__ import annotations

from dataclasses import replace

from .errors import AuthorizationDenied, AuthValidationError
from .models import AuthCredential, AuthSession, AuthUser, Role, UserStatus, now_utc
from .service import CorelineAuthService


class CorelineAdminService:
    def __init__(self, auth: CorelineAuthService) -> None:
        self.auth = auth

    def list_users(self, *, actor_session_token: str, query: str | None = None, status: UserStatus | str | None = None, role: Role | str | None = None) -> list[AuthUser]:
        self.auth.verify_session(actor_session_token, required_permission="users:read")
        status_filter = self._coerce_status(status)
        role_filter = self._coerce_role(role)
        return self.auth.storage.list_users(query=query, status=status_filter, role=role_filter)

    def update_user_role(self, *, actor_session_token: str, user_id: str, role: Role) -> AuthUser:
        actor = self.auth.verify_session(actor_session_token, required_permission="users:write")
        user = self.auth._require_user(user_id)
        if self._is_privileged_role(user.role) and not self._is_privileged_role(role):
            self._require_another_active_privileged_user(user.id)
        updated = replace(user, role=role, updated_at=now_utc())
        self.auth.storage.update_user(updated)
        revoked = self.auth.storage.revoke_sessions_for_user(user.id)
        self.auth._audit("auth.admin.role_update", actor_user_id=actor.user_id, target_user_id=user.id, metadata={"role": role.value, "revoked_count": revoked})
        return updated

    def ban_user(self, *, actor_session_token: str, user_id: str, reason: str | None = None) -> AuthUser:
        actor = self.auth.verify_session(actor_session_token, required_permission="users:ban")
        user = self.auth._require_user(user_id)
        if user.id == actor.user_id:
            raise AuthorizationDenied("admins cannot ban their own account")
        if self._is_privileged_role(user.role):
            self._require_another_active_privileged_user(user.id)
        updated = replace(user, status=UserStatus.BANNED, updated_at=now_utc())
        self.auth.storage.update_user(updated)
        self.auth._audit("auth.admin.user_ban", actor_user_id=actor.user_id, target_user_id=user.id, metadata=self._reason_metadata(reason))
        return updated

    def unban_user(self, *, actor_session_token: str, user_id: str, reason: str | None = None) -> AuthUser:
        actor = self.auth.verify_session(actor_session_token, required_permission="users:ban")
        user = self.auth._require_user(user_id)
        updated = replace(user, status=UserStatus.ACTIVE, updated_at=now_utc())
        self.auth.storage.update_user(updated)
        self.auth._audit("auth.admin.user_unban", actor_user_id=actor.user_id, target_user_id=user.id, metadata=self._reason_metadata(reason))
        return updated

    def disable_user(self, *, actor_session_token: str, user_id: str, reason: str | None = None) -> AuthUser:
        actor = self.auth.verify_session(actor_session_token, required_permission="users:write")
        user = self.auth._require_user(user_id)
        if user.id == actor.user_id:
            raise AuthorizationDenied("admins cannot disable their own account")
        if self._is_privileged_role(user.role):
            self._require_another_active_privileged_user(user.id)
        updated = replace(user, status=UserStatus.DISABLED, updated_at=now_utc())
        self.auth.storage.update_user(updated)
        self.auth.storage.revoke_sessions_for_user(user.id)
        self.auth._audit("auth.admin.user_disable", actor_user_id=actor.user_id, target_user_id=user.id, metadata=self._reason_metadata(reason))
        return updated

    def enable_user(self, *, actor_session_token: str, user_id: str, reason: str | None = None) -> AuthUser:
        actor = self.auth.verify_session(actor_session_token, required_permission="users:write")
        user = self.auth._require_user(user_id)
        updated = replace(user, status=UserStatus.ACTIVE, updated_at=now_utc())
        self.auth.storage.update_user(updated)
        self.auth._audit("auth.admin.user_enable", actor_user_id=actor.user_id, target_user_id=user.id, metadata=self._reason_metadata(reason))
        return updated

    def set_user_password(self, *, actor_session_token: str, user_id: str, password: str) -> AuthCredential:
        actor = self.auth.verify_session(actor_session_token, required_permission="users:write")
        credential = self.auth.set_password(user_id, password, revoke_sessions=False)
        if self.auth.config.revoke_sessions_on_password_change:
            revoked = self.auth.storage.revoke_sessions_for_user(user_id)
            self.auth._audit("auth.admin.password_set.sessions_revoked", actor_user_id=actor.user_id, target_user_id=user_id, metadata={"revoked_count": revoked})
        self.auth._audit("auth.admin.password_set", actor_user_id=actor.user_id, target_user_id=user_id)
        return credential

    def list_sessions_for_user(self, *, actor_session_token: str, user_id: str) -> list[AuthSession]:
        self.auth.verify_session(actor_session_token, required_permission="users:read")
        self.auth._require_user(user_id)
        return self.auth.storage.list_sessions_for_user(user_id)

    def revoke_session(self, *, actor_session_token: str, session_id: str) -> None:
        actor = self.auth.verify_session(actor_session_token, required_permission="sessions:revoke")
        self.auth.revoke_session(session_id, actor_user_id=actor.user_id)


    def _is_privileged_role(self, role: Role) -> bool:
        return role in {Role.OWNER, Role.ADMIN}

    def _require_another_active_privileged_user(self, target_user_id: str) -> None:
        for user in self.auth.storage.list_users(status=UserStatus.ACTIVE):
            if user.id != target_user_id and self._is_privileged_role(user.role):
                return
        raise AuthorizationDenied("at least one active owner/admin account is required")

    def _coerce_role(self, role: Role | str | None) -> Role | None:
        if role is None or role == "":
            return None
        if isinstance(role, Role):
            return role
        try:
            return Role(str(role).strip().lower())
        except ValueError as exc:
            raise AuthValidationError("invalid role filter") from exc

    def _coerce_status(self, status: UserStatus | str | None) -> UserStatus | None:
        if status is None or status == "":
            return None
        if isinstance(status, UserStatus):
            return status
        try:
            return UserStatus(str(status).strip().lower())
        except ValueError as exc:
            raise AuthValidationError("invalid status filter") from exc

    def _reason_metadata(self, reason: str | None) -> dict[str, str]:
        normalized = reason.strip() if reason else ""
        return {"reason": normalized} if normalized else {}
