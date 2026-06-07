"""In-memory storage for tests and embedded development."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import threading

from coreline_auth.errors import AuthValidationError
from coreline_auth.models import AuditEvent, AuthAssuranceLevel, AuthCredential, AuthIdentity, AuthMfaFactor, AuthRecoveryCode, AuthSession, AuthUser, FlowType, LoginFlow, Role, UserStatus, now_utc


def _email_key(email: str) -> str:
    return email.strip().lower()


class MemoryAuthStorage:
    def __init__(self) -> None:
        self.users: dict[str, AuthUser] = {}
        self.users_by_email: dict[str, str] = {}
        self.identities: dict[str, AuthIdentity] = {}
        self.credentials: dict[str, AuthCredential] = {}
        self.password_credentials_by_user: dict[str, str] = {}
        self.login_flows: dict[str, LoginFlow] = {}
        self.login_flows_by_state_hash: dict[str, str] = {}
        self.sessions: dict[str, AuthSession] = {}
        self.sessions_by_token_hash: dict[str, str] = {}
        self.audit_events: list[AuditEvent] = []
        self.mfa_factors: dict[str, AuthMfaFactor] = {}
        self.recovery_codes: dict[str, AuthRecoveryCode] = {}
        self._lock = threading.RLock()

    def create_user(self, user: AuthUser) -> AuthUser:
        key = _email_key(user.primary_email)
        if key in self.users_by_email:
            raise AuthValidationError("user email already exists")
        self.users[user.id] = user
        self.users_by_email[key] = user.id
        return user

    def get_user(self, user_id: str) -> AuthUser | None:
        return self.users.get(user_id)

    def get_user_by_email(self, email: str) -> AuthUser | None:
        user_id = self.users_by_email.get(_email_key(email))
        return self.users.get(user_id) if user_id else None

    def update_user(self, user: AuthUser) -> None:
        if user.id not in self.users:
            raise AuthValidationError("user not found")
        self.users[user.id] = user
        self.users_by_email[_email_key(user.primary_email)] = user.id

    def list_users(self, *, query: str | None = None, status: UserStatus | str | None = None, role: Role | str | None = None, limit: int | None = None, offset: int = 0) -> list[AuthUser]:
        users = sorted(self.users.values(), key=lambda user: user.created_at)
        search = query.strip().lower() if query else ""
        status_filter = UserStatus(str(status)) if isinstance(status, str) and status else status
        role_filter = Role(str(role)) if isinstance(role, str) and role else role
        if search:
            users = [
                user
                for user in users
                if search in user.id.lower()
                or search in user.primary_email.lower()
                or search in (user.display_name or "").lower()
            ]
        if status_filter is not None:
            users = [user for user in users if user.status == status_filter]
        if role_filter is not None:
            users = [user for user in users if user.role == role_filter]
        if offset:
            users = users[offset:]
        if limit is not None:
            users = users[:limit]
        return users

    def upsert_identity(self, identity: AuthIdentity) -> AuthIdentity:
        if identity.provider_subject:
            self.identities[f"{identity.provider}:{identity.provider_subject}"] = identity
        return identity

    def get_identity(self, provider: str, provider_subject: str) -> AuthIdentity | None:
        return self.identities.get(f"{provider}:{provider_subject}")

    def upsert_credential(self, credential: AuthCredential) -> AuthCredential:
        self.credentials[credential.id] = credential
        if credential.password_hash and credential.revoked_at is None:
            self.password_credentials_by_user[credential.user_id] = credential.id
        return credential

    def get_password_credential(self, user_id: str) -> AuthCredential | None:
        credential_id = self.password_credentials_by_user.get(user_id)
        return self.credentials.get(credential_id) if credential_id else None

    def create_login_flow(self, flow: LoginFlow) -> LoginFlow:
        if flow.state_hash and flow.state_hash in self.login_flows_by_state_hash:
            raise AuthValidationError("login flow state already exists")
        self.login_flows[flow.id] = flow
        if flow.state_hash:
            self.login_flows_by_state_hash[flow.state_hash] = flow.id
        return flow

    def get_login_flow_by_state_hash(self, state_hash: str) -> LoginFlow | None:
        flow_id = self.login_flows_by_state_hash.get(state_hash)
        return self.login_flows.get(flow_id) if flow_id else None

    def update_login_flow(self, flow: LoginFlow) -> None:
        with self._lock:
            if flow.id not in self.login_flows:
                raise AuthValidationError("login flow not found")
            self.login_flows[flow.id] = flow
            if flow.state_hash:
                self.login_flows_by_state_hash[flow.state_hash] = flow.id

    def consume_login_flow_by_state_hash(self, state_hash: str, *, flow_type: FlowType, provider: str | None = None, now: datetime) -> LoginFlow | None:
        with self._lock:
            flow_id = self.login_flows_by_state_hash.get(state_hash)
            flow = self.login_flows.get(flow_id) if flow_id else None
            if flow is None or flow.flow_type != flow_type:
                return None
            if provider is not None and flow.provider != provider:
                return None
            if flow.consumed_at is not None or flow.expires_at <= now:
                return None
            consumed = replace(flow, consumed_at=now)
            self.login_flows[flow.id] = consumed
            return consumed

    def create_session(self, session: AuthSession) -> AuthSession:
        if session.session_token_hash in self.sessions_by_token_hash:
            raise AuthValidationError("session token already exists")
        self.sessions[session.id] = session
        self.sessions_by_token_hash[session.session_token_hash] = session.id
        return session

    def get_session_by_token_hash(self, token_hash: str) -> AuthSession | None:
        session_id = self.sessions_by_token_hash.get(token_hash)
        return self.sessions.get(session_id) if session_id else None

    def list_sessions_for_user(self, user_id: str) -> list[AuthSession]:
        return sorted((session for session in self.sessions.values() if session.user_id == user_id), key=lambda session: session.created_at)

    def update_session(self, session: AuthSession) -> None:
        with self._lock:
            existing = self.sessions.get(session.id)
            if existing is None:
                raise AuthValidationError("session not found")
            # Revocation and AAL upgrades are monotonic security state. A stale
            # caller must never clear revocation or downgrade an AAL2 session.
            revoked_at = existing.revoked_at or session.revoked_at
            assurance_level = (
                AuthAssuranceLevel.AAL2
                if existing.assurance_level == AuthAssuranceLevel.AAL2 or session.assurance_level == AuthAssuranceLevel.AAL2
                else session.assurance_level
            )
            saved = replace(session, revoked_at=revoked_at, assurance_level=assurance_level)
            self.sessions[session.id] = saved
            self.sessions_by_token_hash[session.session_token_hash] = session.id

    def touch_session(self, session_id: str, *, last_seen_at: datetime, idle_expires_at: datetime | None) -> AuthSession | None:
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None or session.revoked_at is not None:
                return None
            updated = replace(session, last_seen_at=last_seen_at, idle_expires_at=idle_expires_at)
            self.sessions[session_id] = updated
            self.sessions_by_token_hash[updated.session_token_hash] = session_id
            return updated

    def set_session_assurance_level(self, session_id: str, *, assurance_level: AuthAssuranceLevel, last_seen_at: datetime) -> AuthSession | None:
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None or session.revoked_at is not None:
                return None
            updated = replace(session, assurance_level=assurance_level, last_seen_at=last_seen_at)
            self.sessions[session_id] = updated
            self.sessions_by_token_hash[updated.session_token_hash] = session_id
            return updated

    def revoke_session(self, session_id: str) -> None:
        session = self.sessions.get(session_id)
        if session is not None and session.revoked_at is None:
            self.sessions[session_id] = replace(session, revoked_at=now_utc())

    def revoke_sessions_for_user(self, user_id: str, *, except_session_id: str | None = None) -> int:
        revoked = 0
        revoked_at = now_utc()
        for session_id, session in list(self.sessions.items()):
            if session.user_id != user_id or session.revoked_at is not None or session_id == except_session_id:
                continue
            self.sessions[session_id] = replace(session, revoked_at=revoked_at)
            revoked += 1
        return revoked

    def cleanup_expired(self, *, now: datetime) -> dict[str, int]:
        expired_sessions = 0
        for session_id, session in list(self.sessions.items()):
            if session.revoked_at is not None:
                continue
            if session.expires_at <= now or (session.idle_expires_at is not None and session.idle_expires_at <= now):
                self.sessions[session_id] = replace(session, revoked_at=now)
                expired_sessions += 1

        expired_flows = 0
        for flow_id, flow in list(self.login_flows.items()):
            if flow.expires_at > now:
                continue
            self.login_flows.pop(flow_id, None)
            if flow.state_hash:
                self.login_flows_by_state_hash.pop(flow.state_hash, None)
            expired_flows += 1
        return {"sessions": expired_sessions, "login_flows": expired_flows}

    def record_audit_event(self, event: AuditEvent) -> AuditEvent:
        self.audit_events.append(event)
        return event

    def list_audit_events(
        self,
        *,
        action: str | None = None,
        actor_user_id: str | None = None,
        target_user_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        events = list(reversed(self.audit_events))
        if action:
            events = [event for event in events if event.action == action]
        if actor_user_id:
            events = [event for event in events if event.actor_user_id == actor_user_id]
        if target_user_id:
            events = [event for event in events if event.target_user_id == target_user_id]
        if since:
            events = [event for event in events if event.created_at >= since]
        if until:
            events = [event for event in events if event.created_at <= until]
        return events[offset: offset + limit]

    def create_mfa_factor(self, factor: AuthMfaFactor) -> AuthMfaFactor:
        self.mfa_factors[factor.id] = factor
        return factor

    def get_mfa_factor(self, factor_id: str) -> AuthMfaFactor | None:
        return self.mfa_factors.get(factor_id)

    def list_mfa_factors(self, user_id: str) -> list[AuthMfaFactor]:
        return [factor for factor in self.mfa_factors.values() if factor.user_id == user_id]

    def update_mfa_factor(self, factor: AuthMfaFactor) -> None:
        if factor.id not in self.mfa_factors:
            raise AuthValidationError("mfa factor not found")
        self.mfa_factors[factor.id] = factor

    def mark_mfa_factor_counter_used(self, factor_id: str, *, counter: int, used_at: datetime) -> AuthMfaFactor | None:
        with self._lock:
            factor = self.mfa_factors.get(factor_id)
            if factor is None:
                return None
            if factor.last_used_counter is not None and counter <= factor.last_used_counter:
                return None
            updated = replace(factor, last_used_at=used_at, last_used_counter=counter)
            self.mfa_factors[factor_id] = updated
            return updated

    def create_recovery_code(self, code: AuthRecoveryCode) -> AuthRecoveryCode:
        self.recovery_codes[code.id] = code
        return code

    def list_recovery_codes(self, user_id: str) -> list[AuthRecoveryCode]:
        return [code for code in self.recovery_codes.values() if code.user_id == user_id]

    def mark_recovery_code_used(self, code_id: str, *, used_at: datetime) -> None:
        with self._lock:
            code = self.recovery_codes.get(code_id)
            if code is None:
                raise AuthValidationError("recovery code not found")
            if code.used_at is not None:
                raise AuthValidationError("recovery code already used")
            self.recovery_codes[code_id] = replace(code, used_at=used_at)

    def health_check(self) -> None:
        return None
