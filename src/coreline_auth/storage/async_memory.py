"""Async in-memory storage for tests and adapter scaffolding."""

from __future__ import annotations

from datetime import datetime

from coreline_auth.models import AuditEvent, AuthCredential, AuthIdentity, AuthMfaFactor, AuthRecoveryCode, AuthSession, AuthUser, FlowType, LoginFlow, Role, UserStatus
from coreline_auth.storage.memory import MemoryAuthStorage


class AsyncMemoryAuthStorage:
    """Async wrapper around `MemoryAuthStorage`.

    This is intentionally not a production store. Its purpose is to validate the
    async service contract before a real Postgres adapter exists.
    """

    def __init__(self) -> None:
        self.sync = MemoryAuthStorage()

    async def create_user(self, user: AuthUser) -> AuthUser:
        return self.sync.create_user(user)

    async def get_user(self, user_id: str) -> AuthUser | None:
        return self.sync.get_user(user_id)

    async def get_user_by_email(self, email: str) -> AuthUser | None:
        return self.sync.get_user_by_email(email)

    async def update_user(self, user: AuthUser) -> None:
        return self.sync.update_user(user)

    async def list_users(self, *, query: str | None = None, status: UserStatus | str | None = None, role: Role | str | None = None, limit: int | None = None, offset: int = 0) -> list[AuthUser]:
        return self.sync.list_users(query=query, status=status, role=role, limit=limit, offset=offset)

    async def upsert_identity(self, identity: AuthIdentity) -> AuthIdentity:
        return self.sync.upsert_identity(identity)

    async def get_identity(self, provider: str, provider_subject: str) -> AuthIdentity | None:
        return self.sync.get_identity(provider, provider_subject)

    async def upsert_credential(self, credential: AuthCredential) -> AuthCredential:
        return self.sync.upsert_credential(credential)

    async def get_password_credential(self, user_id: str) -> AuthCredential | None:
        return self.sync.get_password_credential(user_id)

    async def create_login_flow(self, flow: LoginFlow) -> LoginFlow:
        return self.sync.create_login_flow(flow)

    async def get_login_flow_by_state_hash(self, state_hash: str) -> LoginFlow | None:
        return self.sync.get_login_flow_by_state_hash(state_hash)

    async def update_login_flow(self, flow: LoginFlow) -> None:
        return self.sync.update_login_flow(flow)

    async def consume_login_flow_by_state_hash(self, state_hash: str, *, flow_type: FlowType, provider: str | None = None, now: datetime) -> LoginFlow | None:
        return self.sync.consume_login_flow_by_state_hash(state_hash, flow_type=flow_type, provider=provider, now=now)

    async def create_session(self, session: AuthSession) -> AuthSession:
        return self.sync.create_session(session)

    async def get_session_by_token_hash(self, token_hash: str) -> AuthSession | None:
        return self.sync.get_session_by_token_hash(token_hash)

    async def list_sessions_for_user(self, user_id: str) -> list[AuthSession]:
        return self.sync.list_sessions_for_user(user_id)

    async def update_session(self, session: AuthSession) -> None:
        return self.sync.update_session(session)

    async def revoke_session(self, session_id: str) -> None:
        return self.sync.revoke_session(session_id)

    async def revoke_sessions_for_user(self, user_id: str, *, except_session_id: str | None = None) -> int:
        return self.sync.revoke_sessions_for_user(user_id, except_session_id=except_session_id)

    async def cleanup_expired(self, *, now: datetime) -> dict[str, int]:
        return self.sync.cleanup_expired(now=now)

    async def record_audit_event(self, event: AuditEvent) -> AuditEvent:
        return self.sync.record_audit_event(event)

    async def list_audit_events(self, *, action: str | None = None, actor_user_id: str | None = None, target_user_id: str | None = None, since: datetime | None = None, until: datetime | None = None, limit: int = 100, offset: int = 0) -> list[AuditEvent]:
        return self.sync.list_audit_events(action=action, actor_user_id=actor_user_id, target_user_id=target_user_id, since=since, until=until, limit=limit, offset=offset)

    async def create_mfa_factor(self, factor: AuthMfaFactor) -> AuthMfaFactor:
        return self.sync.create_mfa_factor(factor)

    async def get_mfa_factor(self, factor_id: str) -> AuthMfaFactor | None:
        return self.sync.get_mfa_factor(factor_id)

    async def list_mfa_factors(self, user_id: str) -> list[AuthMfaFactor]:
        return self.sync.list_mfa_factors(user_id)

    async def update_mfa_factor(self, factor: AuthMfaFactor) -> None:
        return self.sync.update_mfa_factor(factor)

    async def create_recovery_code(self, code: AuthRecoveryCode) -> AuthRecoveryCode:
        return self.sync.create_recovery_code(code)

    async def list_recovery_codes(self, user_id: str) -> list[AuthRecoveryCode]:
        return self.sync.list_recovery_codes(user_id)

    async def mark_recovery_code_used(self, code_id: str, *, used_at: datetime) -> None:
        return self.sync.mark_recovery_code_used(code_id, used_at=used_at)

    async def health_check(self) -> None:
        return self.sync.health_check()
