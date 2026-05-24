"""Async PostgreSQL storage adapter using SQLAlchemy Core."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, delete, func, insert, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from coreline_auth.errors import AuthValidationError
from coreline_auth.models import (
    AuditEvent,
    AuthAssuranceLevel,
    AuthCredential,
    AuthIdentity,
    AuthMfaFactor,
    AuthRecoveryCode,
    AuthSession,
    AuthUser,
    CredentialType,
    FlowType,
    LoginFlow,
    MfaFactorType,
    Role,
    UserStatus,
    now_utc,
)
from coreline_auth.storage.sqlalchemy_schema import (
    auth_audit_events,
    auth_credentials,
    auth_identities,
    auth_login_flows,
    auth_mfa_factors,
    auth_recovery_codes,
    auth_sessions,
    auth_users,
    metadata,
)


def _dt(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
    else:
        parsed = value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _json(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


class AsyncPostgresAuthStorage:
    """Postgres-backed `AsyncAuthStorage` implementation.

    This adapter is optional and requires installing the `postgres` extra. It is
    intentionally separate from the default package imports so embedded SQLite
    users do not pull SQLAlchemy/asyncpg into their runtime.
    """

    def __init__(self, database_url: str | AsyncEngine, *, echo: bool = False) -> None:
        if isinstance(database_url, str):
            self.engine = create_async_engine(database_url, echo=echo, pool_pre_ping=True)
            self._owns_engine = True
        else:
            self.engine = database_url
            self._owns_engine = False
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    async def bootstrap(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def close(self) -> None:
        if self._owns_engine:
            await self.engine.dispose()

    async def health_check(self) -> None:
        async with self.sessionmaker() as session:
            await session.execute(select(1))

    async def create_user(self, user: AuthUser) -> AuthUser:
        async with self.sessionmaker.begin() as session:
            try:
                await session.execute(insert(auth_users).values(**self._user_values(user)))
            except IntegrityError as exc:
                raise AuthValidationError("user email already exists") from exc
        return user

    async def get_user(self, user_id: str) -> AuthUser | None:
        async with self.sessionmaker() as session:
            row = (await session.execute(select(auth_users).where(auth_users.c.id == user_id))).mappings().first()
        return self._user_from_row(row) if row else None

    async def get_user_by_email(self, email: str) -> AuthUser | None:
        async with self.sessionmaker() as session:
            row = (await session.execute(select(auth_users).where(auth_users.c.primary_email == email.lower()))).mappings().first()
        return self._user_from_row(row) if row else None

    async def update_user(self, user: AuthUser) -> None:
        async with self.sessionmaker.begin() as session:
            result = await session.execute(update(auth_users).where(auth_users.c.id == user.id).values(**self._user_values(user)))
        if result.rowcount == 0:
            raise AuthValidationError("user not found")

    async def list_users(self, *, query: str | None = None, status: UserStatus | str | None = None, role: Role | str | None = None, limit: int | None = None, offset: int = 0) -> list[AuthUser]:
        stmt = select(auth_users)
        clauses = []
        search = query.strip().lower() if query else ""
        if search:
            pattern = f"%{search}%"
            clauses.append(or_(func.lower(auth_users.c.id).like(pattern), func.lower(auth_users.c.primary_email).like(pattern), func.lower(func.coalesce(auth_users.c.display_name, "")).like(pattern)))
        if status:
            clauses.append(auth_users.c.status == UserStatus(str(status)).value)
        if role:
            clauses.append(auth_users.c.role == Role(str(role)).value)
        if clauses:
            stmt = stmt.where(and_(*clauses))
        stmt = stmt.order_by(auth_users.c.created_at.asc(), auth_users.c.id.asc()).offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        async with self.sessionmaker() as session:
            rows = (await session.execute(stmt)).mappings().all()
        return [self._user_from_row(row) for row in rows]

    async def upsert_identity(self, identity: AuthIdentity) -> AuthIdentity:
        values = self._identity_values(identity)
        stmt = pg_insert(auth_identities).values(**values)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_auth_identities_provider_subject",
            set_={"user_id": stmt.excluded.user_id, "email": stmt.excluded.email, "email_verified": stmt.excluded.email_verified, "last_seen_at": stmt.excluded.last_seen_at},
        )
        async with self.sessionmaker.begin() as session:
            await session.execute(stmt)
        return identity

    async def get_identity(self, provider: str, provider_subject: str) -> AuthIdentity | None:
        async with self.sessionmaker() as session:
            row = (await session.execute(select(auth_identities).where(auth_identities.c.provider == provider, auth_identities.c.provider_subject == provider_subject))).mappings().first()
        return self._identity_from_row(row) if row else None

    async def upsert_credential(self, credential: AuthCredential) -> AuthCredential:
        values = self._credential_values(credential)
        stmt = pg_insert(auth_credentials).values(**values)
        stmt = stmt.on_conflict_do_update(index_elements=[auth_credentials.c.id], set_={"password_hash": stmt.excluded.password_hash, "updated_at": stmt.excluded.updated_at, "revoked_at": stmt.excluded.revoked_at})
        async with self.sessionmaker.begin() as session:
            await session.execute(stmt)
        return credential

    async def get_password_credential(self, user_id: str) -> AuthCredential | None:
        stmt = select(auth_credentials).where(auth_credentials.c.user_id == user_id, auth_credentials.c.credential_type == "password", auth_credentials.c.revoked_at.is_(None)).order_by(auth_credentials.c.updated_at.desc()).limit(1)
        async with self.sessionmaker() as session:
            row = (await session.execute(stmt)).mappings().first()
        return self._credential_from_row(row) if row else None

    async def create_login_flow(self, flow: LoginFlow) -> LoginFlow:
        async with self.sessionmaker.begin() as session:
            try:
                await session.execute(insert(auth_login_flows).values(**self._flow_values(flow)))
            except IntegrityError as exc:
                raise AuthValidationError("login flow state already exists") from exc
        return flow

    async def get_login_flow_by_state_hash(self, state_hash: str) -> LoginFlow | None:
        async with self.sessionmaker() as session:
            row = (await session.execute(select(auth_login_flows).where(auth_login_flows.c.state_hash == state_hash))).mappings().first()
        return self._flow_from_row(row) if row else None

    async def update_login_flow(self, flow: LoginFlow) -> None:
        async with self.sessionmaker.begin() as session:
            result = await session.execute(update(auth_login_flows).where(auth_login_flows.c.id == flow.id).values(**self._flow_values(flow)))
        if result.rowcount == 0:
            raise AuthValidationError("login flow not found")

    async def consume_login_flow_by_state_hash(self, state_hash: str, *, flow_type: FlowType, provider: str | None = None, now: datetime) -> LoginFlow | None:
        stmt = (
            update(auth_login_flows)
            .where(
                auth_login_flows.c.state_hash == state_hash,
                auth_login_flows.c.flow_type == flow_type.value,
                auth_login_flows.c.consumed_at.is_(None),
                auth_login_flows.c.expires_at > now,
            )
            .values(consumed_at=now)
            .returning(auth_login_flows)
        )
        if provider is not None:
            stmt = stmt.where(auth_login_flows.c.provider == provider)
        async with self.sessionmaker.begin() as session:
            row = (await session.execute(stmt)).mappings().first()
        return self._flow_from_row(row) if row else None

    async def create_session(self, session: AuthSession) -> AuthSession:
        async with self.sessionmaker.begin() as db_session:
            try:
                await db_session.execute(insert(auth_sessions).values(**self._session_values(session)))
            except IntegrityError as exc:
                raise AuthValidationError("session token already exists") from exc
        return session

    async def get_session_by_token_hash(self, token_hash: str) -> AuthSession | None:
        async with self.sessionmaker() as session:
            row = (await session.execute(select(auth_sessions).where(auth_sessions.c.session_token_hash == token_hash))).mappings().first()
        return self._session_from_row(row) if row else None

    async def list_sessions_for_user(self, user_id: str) -> list[AuthSession]:
        async with self.sessionmaker() as session:
            rows = (await session.execute(select(auth_sessions).where(auth_sessions.c.user_id == user_id).order_by(auth_sessions.c.created_at.asc()))).mappings().all()
        return [self._session_from_row(row) for row in rows]

    async def update_session(self, session: AuthSession) -> None:
        values = {
            "expires_at": session.expires_at,
            "idle_expires_at": session.idle_expires_at,
            "revoked_at": session.revoked_at,
            "last_seen_at": session.last_seen_at,
            "assurance_level": session.assurance_level.value,
        }
        async with self.sessionmaker.begin() as db_session:
            result = await db_session.execute(update(auth_sessions).where(auth_sessions.c.id == session.id).values(**values))
        if result.rowcount == 0:
            raise AuthValidationError("session not found")

    async def revoke_session(self, session_id: str) -> None:
        async with self.sessionmaker.begin() as session:
            await session.execute(update(auth_sessions).where(auth_sessions.c.id == session_id).values(revoked_at=now_utc()))

    async def revoke_sessions_for_user(self, user_id: str, *, except_session_id: str | None = None) -> int:
        stmt = update(auth_sessions).where(auth_sessions.c.user_id == user_id, auth_sessions.c.revoked_at.is_(None)).values(revoked_at=now_utc())
        if except_session_id is not None:
            stmt = stmt.where(auth_sessions.c.id != except_session_id)
        async with self.sessionmaker.begin() as session:
            result = await session.execute(stmt)
        return int(result.rowcount or 0)

    async def cleanup_expired(self, *, now: datetime) -> dict[str, int]:
        async with self.sessionmaker.begin() as session:
            session_result = await session.execute(update(auth_sessions).where(auth_sessions.c.revoked_at.is_(None), or_(auth_sessions.c.expires_at <= now, and_(auth_sessions.c.idle_expires_at.is_not(None), auth_sessions.c.idle_expires_at <= now))).values(revoked_at=now))
            flow_result = await session.execute(delete(auth_login_flows).where(auth_login_flows.c.expires_at <= now))
        return {"sessions": int(session_result.rowcount or 0), "login_flows": int(flow_result.rowcount or 0)}

    async def record_audit_event(self, event: AuditEvent) -> AuditEvent:
        async with self.sessionmaker.begin() as session:
            await session.execute(insert(auth_audit_events).values(action=event.action, actor_user_id=event.actor_user_id, target_user_id=event.target_user_id, metadata_json=event.metadata, created_at=event.created_at))
        return event

    async def list_audit_events(self, *, action: str | None = None, actor_user_id: str | None = None, target_user_id: str | None = None, since: datetime | None = None, until: datetime | None = None, limit: int = 100, offset: int = 0) -> list[AuditEvent]:
        stmt = select(auth_audit_events)
        clauses = []
        if action:
            clauses.append(auth_audit_events.c.action == action)
        if actor_user_id:
            clauses.append(auth_audit_events.c.actor_user_id == actor_user_id)
        if target_user_id:
            clauses.append(auth_audit_events.c.target_user_id == target_user_id)
        if since:
            clauses.append(auth_audit_events.c.created_at >= since)
        if until:
            clauses.append(auth_audit_events.c.created_at <= until)
        if clauses:
            stmt = stmt.where(and_(*clauses))
        stmt = stmt.order_by(auth_audit_events.c.created_at.desc(), auth_audit_events.c.id.desc()).limit(limit).offset(offset)
        async with self.sessionmaker() as session:
            rows = (await session.execute(stmt)).mappings().all()
        return [AuditEvent(action=row["action"], actor_user_id=row["actor_user_id"], target_user_id=row["target_user_id"], metadata=_json(row["metadata_json"], {}), created_at=_dt(row["created_at"]) or now_utc()) for row in rows]

    async def create_mfa_factor(self, factor: AuthMfaFactor) -> AuthMfaFactor:
        async with self.sessionmaker.begin() as session:
            await session.execute(insert(auth_mfa_factors).values(**self._mfa_factor_values(factor)))
        return factor

    async def get_mfa_factor(self, factor_id: str) -> AuthMfaFactor | None:
        async with self.sessionmaker() as session:
            row = (await session.execute(select(auth_mfa_factors).where(auth_mfa_factors.c.id == factor_id))).mappings().first()
        return self._mfa_factor_from_row(row) if row else None

    async def list_mfa_factors(self, user_id: str) -> list[AuthMfaFactor]:
        async with self.sessionmaker() as session:
            rows = (await session.execute(select(auth_mfa_factors).where(auth_mfa_factors.c.user_id == user_id).order_by(auth_mfa_factors.c.created_at.asc(), auth_mfa_factors.c.id.asc()))).mappings().all()
        return [self._mfa_factor_from_row(row) for row in rows]

    async def update_mfa_factor(self, factor: AuthMfaFactor) -> None:
        async with self.sessionmaker.begin() as session:
            result = await session.execute(update(auth_mfa_factors).where(auth_mfa_factors.c.id == factor.id).values(**self._mfa_factor_values(factor)))
        if result.rowcount == 0:
            raise AuthValidationError("mfa factor not found")

    async def create_recovery_code(self, code: AuthRecoveryCode) -> AuthRecoveryCode:
        async with self.sessionmaker.begin() as session:
            await session.execute(insert(auth_recovery_codes).values(id=code.id, user_id=code.user_id, code_hash=code.code_hash, created_at=code.created_at, used_at=code.used_at))
        return code

    async def list_recovery_codes(self, user_id: str) -> list[AuthRecoveryCode]:
        async with self.sessionmaker() as session:
            rows = (await session.execute(select(auth_recovery_codes).where(auth_recovery_codes.c.user_id == user_id).order_by(auth_recovery_codes.c.created_at.asc(), auth_recovery_codes.c.id.asc()))).mappings().all()
        return [AuthRecoveryCode(id=row["id"], user_id=row["user_id"], code_hash=row["code_hash"], created_at=_dt(row["created_at"]) or now_utc(), used_at=_dt(row["used_at"])) for row in rows]

    async def mark_recovery_code_used(self, code_id: str, *, used_at: datetime) -> None:
        async with self.sessionmaker.begin() as session:
            result = await session.execute(update(auth_recovery_codes).where(auth_recovery_codes.c.id == code_id, auth_recovery_codes.c.used_at.is_(None)).values(used_at=used_at))
        if result.rowcount == 0:
            raise AuthValidationError("recovery code not found or already used")

    @staticmethod
    def _user_values(user: AuthUser) -> dict[str, Any]:
        return {"id": user.id, "primary_email": user.primary_email.lower(), "primary_email_verified": user.primary_email_verified, "role": user.role.value, "display_name": user.display_name, "avatar_url": user.avatar_url, "status": user.status.value, "created_at": user.created_at, "updated_at": user.updated_at, "last_login_at": user.last_login_at}

    @staticmethod
    def _identity_values(identity: AuthIdentity) -> dict[str, Any]:
        return {"id": identity.id, "user_id": identity.user_id, "provider": identity.provider, "provider_subject": identity.provider_subject, "email": identity.email.lower() if identity.email else None, "email_verified": identity.email_verified, "linked_at": identity.linked_at, "last_seen_at": identity.last_seen_at}

    @staticmethod
    def _credential_values(credential: AuthCredential) -> dict[str, Any]:
        return {"id": credential.id, "user_id": credential.user_id, "credential_type": credential.credential_type.value, "password_hash": credential.password_hash, "created_at": credential.created_at, "updated_at": credential.updated_at, "revoked_at": credential.revoked_at}

    @staticmethod
    def _flow_values(flow: LoginFlow) -> dict[str, Any]:
        return {"id": flow.id, "flow_type": flow.flow_type.value, "provider": flow.provider, "state_hash": flow.state_hash, "nonce_hash": flow.nonce_hash, "email": flow.email.lower() if flow.email else None, "return_to": flow.return_to, "created_at": flow.created_at, "expires_at": flow.expires_at, "consumed_at": flow.consumed_at, "metadata_json": flow.metadata}

    @staticmethod
    def _session_values(session: AuthSession) -> dict[str, Any]:
        return {"id": session.id, "session_token_hash": session.session_token_hash, "user_id": session.user_id, "subject": session.subject, "email": session.email.lower() if session.email else None, "provider": session.provider, "role": session.role.value, "permissions_json": list(session.permissions), "assurance_level": session.assurance_level.value, "created_at": session.created_at, "expires_at": session.expires_at, "idle_expires_at": session.idle_expires_at, "revoked_at": session.revoked_at, "last_seen_at": session.last_seen_at, "user_agent_hash": session.user_agent_hash, "ip_hash": session.ip_hash}

    @staticmethod
    def _mfa_factor_values(factor: AuthMfaFactor) -> dict[str, Any]:
        return {"id": factor.id, "user_id": factor.user_id, "factor_type": factor.factor_type.value, "name": factor.name, "secret_hash": factor.secret_hash, "credential_id": factor.credential_id, "public_key": factor.public_key, "sign_count": factor.sign_count, "enabled": factor.enabled, "created_at": factor.created_at, "last_used_at": factor.last_used_at, "last_used_counter": factor.last_used_counter}

    @staticmethod
    def _user_from_row(row: RowMapping) -> AuthUser:
        return AuthUser(id=row["id"], primary_email=row["primary_email"], primary_email_verified=bool(row["primary_email_verified"]), role=Role(row["role"]), display_name=row["display_name"], avatar_url=row["avatar_url"], status=UserStatus(row["status"]), created_at=_dt(row["created_at"]) or now_utc(), updated_at=_dt(row["updated_at"]) or now_utc(), last_login_at=_dt(row["last_login_at"]))

    @staticmethod
    def _identity_from_row(row: RowMapping) -> AuthIdentity:
        return AuthIdentity(id=row["id"], user_id=row["user_id"], provider=row["provider"], provider_subject=row["provider_subject"], email=row["email"], email_verified=bool(row["email_verified"]), linked_at=_dt(row["linked_at"]) or now_utc(), last_seen_at=_dt(row["last_seen_at"]))

    @staticmethod
    def _credential_from_row(row: RowMapping) -> AuthCredential:
        return AuthCredential(id=row["id"], user_id=row["user_id"], credential_type=CredentialType(row["credential_type"]), password_hash=row["password_hash"], created_at=_dt(row["created_at"]) or now_utc(), updated_at=_dt(row["updated_at"]) or now_utc(), revoked_at=_dt(row["revoked_at"]))

    @staticmethod
    def _flow_from_row(row: RowMapping) -> LoginFlow:
        return LoginFlow(id=row["id"], flow_type=FlowType(row["flow_type"]), provider=row["provider"], state_hash=row["state_hash"], nonce_hash=row["nonce_hash"], email=row["email"], return_to=row["return_to"], created_at=_dt(row["created_at"]) or now_utc(), expires_at=_dt(row["expires_at"]) or now_utc(), consumed_at=_dt(row["consumed_at"]), metadata=_json(row["metadata_json"], {}))

    @staticmethod
    def _session_from_row(row: RowMapping) -> AuthSession:
        return AuthSession(id=row["id"], session_token_hash=row["session_token_hash"], user_id=row["user_id"], subject=row["subject"], email=row["email"], provider=row["provider"], role=Role(row["role"]), permissions=tuple(_json(row["permissions_json"], [])), assurance_level=AuthAssuranceLevel(row["assurance_level"] or "aal1"), created_at=_dt(row["created_at"]) or now_utc(), expires_at=_dt(row["expires_at"]) or now_utc(), idle_expires_at=_dt(row["idle_expires_at"]), revoked_at=_dt(row["revoked_at"]), last_seen_at=_dt(row["last_seen_at"]), user_agent_hash=row["user_agent_hash"], ip_hash=row["ip_hash"])

    @staticmethod
    def _mfa_factor_from_row(row: RowMapping) -> AuthMfaFactor:
        return AuthMfaFactor(id=row["id"], user_id=row["user_id"], factor_type=MfaFactorType(row["factor_type"]), name=row["name"], secret_hash=row["secret_hash"], credential_id=row["credential_id"], public_key=row["public_key"], sign_count=int(row["sign_count"]), enabled=bool(row["enabled"]), created_at=_dt(row["created_at"]) or now_utc(), last_used_at=_dt(row["last_used_at"]), last_used_counter=row["last_used_counter"])
