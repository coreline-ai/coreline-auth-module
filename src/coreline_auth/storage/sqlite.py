"""SQLite storage adapter independent from host project databases."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

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
    from_iso,
    now_utc,
    to_iso,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS auth_users (
  id TEXT PRIMARY KEY,
  primary_email TEXT NOT NULL UNIQUE,
  primary_email_verified INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'user',
  display_name TEXT,
  avatar_url TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS auth_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_subject TEXT,
  email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  linked_at TEXT NOT NULL,
  last_seen_at TEXT,
  UNIQUE(provider, provider_subject)
);
CREATE TABLE IF NOT EXISTS auth_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  credential_type TEXT NOT NULL,
  password_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_password_credential_active
  ON auth_credentials(user_id, credential_type)
  WHERE credential_type = 'password' AND revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS auth_login_flows (
  id TEXT PRIMARY KEY,
  flow_type TEXT NOT NULL,
  provider TEXT,
  state_hash TEXT UNIQUE,
  nonce_hash TEXT,
  email TEXT,
  return_to TEXT NOT NULL DEFAULT '/',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS auth_sessions (
  id TEXT PRIMARY KEY,
  session_token_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  subject TEXT,
  email TEXT,
  provider TEXT,
  role TEXT NOT NULL,
  permissions_json TEXT NOT NULL,
  assurance_level TEXT NOT NULL DEFAULT 'aal1',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  idle_expires_at TEXT,
  revoked_at TEXT,
  last_seen_at TEXT,
  user_agent_hash TEXT,
  ip_hash TEXT
);
CREATE TABLE IF NOT EXISTS auth_audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  actor_user_id TEXT,
  target_user_id TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_mfa_factors (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  factor_type TEXT NOT NULL,
  name TEXT NOT NULL,
  secret_hash TEXT,
  credential_id TEXT,
  public_key TEXT,
  sign_count INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  last_used_counter INTEGER
);
CREATE TABLE IF NOT EXISTS auth_recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_auth_users_role_status_created ON auth_users(role, status, created_at, id);
CREATE INDEX IF NOT EXISTS ix_auth_login_flows_expires ON auth_login_flows(expires_at);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_created ON auth_sessions(user_id, created_at, id);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_expires ON auth_sessions(expires_at, idle_expires_at, revoked_at);
CREATE INDEX IF NOT EXISTS ix_auth_audit_action_created ON auth_audit_events(action, created_at);
CREATE INDEX IF NOT EXISTS ix_auth_audit_actor_created ON auth_audit_events(actor_user_id, created_at);
CREATE INDEX IF NOT EXISTS ix_auth_mfa_user_enabled ON auth_mfa_factors(user_id, enabled);
CREATE INDEX IF NOT EXISTS ix_auth_recovery_user_used ON auth_recovery_codes(user_id, used_at);
"""


def _optional_iso(value: Any) -> str | None:
    return to_iso(value) if value is not None else None


class SQLiteAuthStorage:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if self.db_path != Path(":memory:"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._configure_connection()
        self.bootstrap()

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def bootstrap(self) -> None:
        with self._lock:
            self.db.executescript(SCHEMA_SQL)
            self._ensure_legacy_columns()
            self.db.commit()

    def _configure_connection(self) -> None:
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        if self.db_path != Path(":memory:"):
            self.db.execute("PRAGMA journal_mode=WAL")
        self.db.commit()


    def _ensure_legacy_columns(self) -> None:
        session_columns = {row[1] for row in self.db.execute("PRAGMA table_info(auth_sessions)").fetchall()}
        if "assurance_level" not in session_columns:
            self.db.execute("ALTER TABLE auth_sessions ADD COLUMN assurance_level TEXT NOT NULL DEFAULT 'aal1'")
        mfa_columns = {row[1] for row in self.db.execute("PRAGMA table_info(auth_mfa_factors)").fetchall()}
        if mfa_columns and "last_used_counter" not in mfa_columns:
            self.db.execute("ALTER TABLE auth_mfa_factors ADD COLUMN last_used_counter INTEGER")

    def create_user(self, user: AuthUser) -> AuthUser:
        with self._lock:
            try:
                self.db.execute(
                    """
                    INSERT INTO auth_users (
                      id, primary_email, primary_email_verified, role, display_name, avatar_url,
                      status, created_at, updated_at, last_login_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (user.id, user.primary_email.lower(), int(user.primary_email_verified), user.role.value, user.display_name, user.avatar_url, user.status.value, to_iso(user.created_at), to_iso(user.updated_at), _optional_iso(user.last_login_at)),
                )
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                raise AuthValidationError("user email already exists") from exc
        return user

    def get_user(self, user_id: str) -> AuthUser | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,)).fetchone()
        return self._user_from_row(row) if row else None

    def get_user_by_email(self, email: str) -> AuthUser | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM auth_users WHERE primary_email = ?", (email.lower(),)).fetchone()
        return self._user_from_row(row) if row else None

    def update_user(self, user: AuthUser) -> None:
        with self._lock:
            cursor = self.db.execute(
                """
                UPDATE auth_users SET primary_email = ?, primary_email_verified = ?, role = ?, display_name = ?,
                  avatar_url = ?, status = ?, updated_at = ?, last_login_at = ? WHERE id = ?
                """,
                (user.primary_email.lower(), int(user.primary_email_verified), user.role.value, user.display_name, user.avatar_url, user.status.value, to_iso(user.updated_at), _optional_iso(user.last_login_at), user.id),
            )
            self.db.commit()
        if cursor.rowcount == 0:
            raise AuthValidationError("user not found")

    def list_users(self, *, query: str | None = None, status: UserStatus | str | None = None, role: Role | str | None = None, limit: int | None = None, offset: int = 0) -> list[AuthUser]:
        clauses: list[str] = []
        values: list[object] = []
        search = query.strip().lower() if query else ""
        if search:
            clauses.append("(LOWER(id) LIKE ? OR LOWER(primary_email) LIKE ? OR LOWER(COALESCE(display_name, '')) LIKE ?)")
            values.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        if status:
            status_value = UserStatus(str(status)).value
            clauses.append("status = ?")
            values.append(status_value)
        if role:
            role_value = Role(str(role)).value
            clauses.append("role = ?")
            values.append(role_value)
        sql = "SELECT * FROM auth_users"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at ASC, id ASC"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            values.extend([limit, offset])
        elif offset:
            sql += " LIMIT -1 OFFSET ?"
            values.append(offset)
        with self._lock:
            rows = self.db.execute(sql, tuple(values)).fetchall()
        return [self._user_from_row(row) for row in rows]

    def upsert_identity(self, identity: AuthIdentity) -> AuthIdentity:
        with self._lock:
            self.db.execute(
                """
                INSERT INTO auth_identities (id, user_id, provider, provider_subject, email, email_verified, linked_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, provider_subject) DO UPDATE SET
                  user_id = excluded.user_id, email = excluded.email,
                  email_verified = excluded.email_verified, last_seen_at = excluded.last_seen_at
                """,
                (identity.id, identity.user_id, identity.provider, identity.provider_subject, identity.email.lower() if identity.email else None, int(identity.email_verified), to_iso(identity.linked_at), _optional_iso(identity.last_seen_at)),
            )
            self.db.commit()
        return identity

    def get_identity(self, provider: str, provider_subject: str) -> AuthIdentity | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM auth_identities WHERE provider = ? AND provider_subject = ?", (provider, provider_subject)).fetchone()
        return self._identity_from_row(row) if row else None

    def upsert_credential(self, credential: AuthCredential) -> AuthCredential:
        with self._lock:
            self.db.execute(
                """
                INSERT INTO auth_credentials (id, user_id, credential_type, password_hash, created_at, updated_at, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash,
                  updated_at = excluded.updated_at, revoked_at = excluded.revoked_at
                """,
                (credential.id, credential.user_id, credential.credential_type.value, credential.password_hash, to_iso(credential.created_at), to_iso(credential.updated_at), _optional_iso(credential.revoked_at)),
            )
            self.db.commit()
        return credential

    def get_password_credential(self, user_id: str) -> AuthCredential | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM auth_credentials WHERE user_id = ? AND credential_type = 'password' AND revoked_at IS NULL ORDER BY updated_at DESC LIMIT 1", (user_id,)).fetchone()
        return self._credential_from_row(row) if row else None

    def create_login_flow(self, flow: LoginFlow) -> LoginFlow:
        with self._lock:
            try:
                self.db.execute(
                    """
                    INSERT INTO auth_login_flows (id, flow_type, provider, state_hash, nonce_hash, email, return_to, created_at, expires_at, consumed_at, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (flow.id, flow.flow_type.value, flow.provider, flow.state_hash, flow.nonce_hash, flow.email.lower() if flow.email else None, flow.return_to, to_iso(flow.created_at), to_iso(flow.expires_at), _optional_iso(flow.consumed_at), json.dumps(flow.metadata, sort_keys=True)),
                )
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                raise AuthValidationError("login flow state already exists") from exc
        return flow

    def get_login_flow_by_state_hash(self, state_hash: str) -> LoginFlow | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM auth_login_flows WHERE state_hash = ?", (state_hash,)).fetchone()
        return self._flow_from_row(row) if row else None

    def update_login_flow(self, flow: LoginFlow) -> None:
        with self._lock:
            cursor = self.db.execute(
                """
                UPDATE auth_login_flows SET flow_type = ?, provider = ?, state_hash = ?, nonce_hash = ?,
                  email = ?, return_to = ?, created_at = ?, expires_at = ?,
                  consumed_at = ?, metadata_json = ? WHERE id = ?
                """,
                (flow.flow_type.value, flow.provider, flow.state_hash, flow.nonce_hash, flow.email.lower() if flow.email else None, flow.return_to, to_iso(flow.created_at), to_iso(flow.expires_at), _optional_iso(flow.consumed_at), json.dumps(flow.metadata, sort_keys=True), flow.id),
            )
            self.db.commit()
        if cursor.rowcount == 0:
            raise AuthValidationError("login flow not found")

    def consume_login_flow_by_state_hash(self, state_hash: str, *, flow_type: FlowType, provider: str | None = None, now: datetime) -> LoginFlow | None:
        clauses = [
            "state_hash = ?",
            "flow_type = ?",
            "consumed_at IS NULL",
            "expires_at > ?",
        ]
        values: list[object] = [state_hash, flow_type.value, to_iso(now)]
        if provider is not None:
            clauses.append("provider = ?")
            values.append(provider)
        sql = f"""
            UPDATE auth_login_flows
            SET consumed_at = ?
            WHERE {' AND '.join(clauses)}
            RETURNING *
        """
        query_values = [to_iso(now), *values]
        with self._lock:
            row = self.db.execute(sql, tuple(query_values)).fetchone()
            self.db.commit()
        return self._flow_from_row(row) if row else None

    def create_session(self, session: AuthSession) -> AuthSession:
        with self._lock:
            try:
                self.db.execute(
                    """
                    INSERT INTO auth_sessions (id, session_token_hash, user_id, subject, email, provider, role, permissions_json, assurance_level, created_at, expires_at, idle_expires_at, revoked_at, last_seen_at, user_agent_hash, ip_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (session.id, session.session_token_hash, session.user_id, session.subject, session.email.lower() if session.email else None, session.provider, session.role.value, json.dumps(list(session.permissions), sort_keys=True), session.assurance_level.value, to_iso(session.created_at), to_iso(session.expires_at), _optional_iso(session.idle_expires_at), _optional_iso(session.revoked_at), _optional_iso(session.last_seen_at), session.user_agent_hash, session.ip_hash),
                )
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                raise AuthValidationError("session token already exists") from exc
        return session

    def get_session_by_token_hash(self, token_hash: str) -> AuthSession | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM auth_sessions WHERE session_token_hash = ?", (token_hash,)).fetchone()
        return self._session_from_row(row) if row else None

    def list_sessions_for_user(self, user_id: str) -> list[AuthSession]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM auth_sessions WHERE user_id = ? ORDER BY created_at ASC", (user_id,)).fetchall()
        return [self._session_from_row(row) for row in rows]

    def update_session(self, session: AuthSession) -> None:
        with self._lock:
            cursor = self.db.execute(
                """
                UPDATE auth_sessions
                SET expires_at = ?,
                    idle_expires_at = ?,
                    revoked_at = COALESCE(revoked_at, ?),
                    last_seen_at = ?,
                    assurance_level = CASE
                      WHEN assurance_level = 'aal2' THEN assurance_level
                      ELSE ?
                    END
                WHERE id = ?
                """,
                (to_iso(session.expires_at), _optional_iso(session.idle_expires_at), _optional_iso(session.revoked_at), _optional_iso(session.last_seen_at), session.assurance_level.value, session.id),
            )
            self.db.commit()
        if cursor.rowcount == 0:
            raise AuthValidationError("session not found")

    def touch_session(self, session_id: str, *, last_seen_at: datetime, idle_expires_at: datetime | None) -> AuthSession | None:
        with self._lock:
            row = self.db.execute(
                """
                UPDATE auth_sessions
                SET last_seen_at = ?, idle_expires_at = ?
                WHERE id = ? AND revoked_at IS NULL
                RETURNING *
                """,
                (_optional_iso(last_seen_at), _optional_iso(idle_expires_at), session_id),
            ).fetchone()
            self.db.commit()
        return self._session_from_row(row) if row else None

    def set_session_assurance_level(self, session_id: str, *, assurance_level: AuthAssuranceLevel, last_seen_at: datetime) -> AuthSession | None:
        with self._lock:
            row = self.db.execute(
                """
                UPDATE auth_sessions
                SET assurance_level = ?, last_seen_at = ?
                WHERE id = ? AND revoked_at IS NULL
                RETURNING *
                """,
                (assurance_level.value, _optional_iso(last_seen_at), session_id),
            ).fetchone()
            self.db.commit()
        return self._session_from_row(row) if row else None

    def revoke_session(self, session_id: str) -> None:
        with self._lock:
            self.db.execute("UPDATE auth_sessions SET revoked_at = ? WHERE id = ?", (to_iso(now_utc()), session_id))
            self.db.commit()

    def revoke_sessions_for_user(self, user_id: str, *, except_session_id: str | None = None) -> int:
        revoked_at = to_iso(now_utc())
        with self._lock:
            if except_session_id is None:
                cursor = self.db.execute(
                    "UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                    (revoked_at, user_id),
                )
            else:
                cursor = self.db.execute(
                    "UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND id != ?",
                    (revoked_at, user_id, except_session_id),
                )
            self.db.commit()
        return int(cursor.rowcount or 0)

    def cleanup_expired(self, *, now: datetime) -> dict[str, int]:
        now_iso = to_iso(now)
        with self._lock:
            session_cursor = self.db.execute(
                "UPDATE auth_sessions SET revoked_at = ? WHERE revoked_at IS NULL AND (expires_at <= ? OR (idle_expires_at IS NOT NULL AND idle_expires_at <= ?))",
                (now_iso, now_iso, now_iso),
            )
            flow_cursor = self.db.execute("DELETE FROM auth_login_flows WHERE expires_at <= ?", (now_iso,))
            self.db.commit()
        return {"sessions": int(session_cursor.rowcount or 0), "login_flows": int(flow_cursor.rowcount or 0)}

    def record_audit_event(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self.db.execute(
                """
                INSERT INTO auth_audit_events (action, actor_user_id, target_user_id, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event.action, event.actor_user_id, event.target_user_id, json.dumps(event.metadata, sort_keys=True), to_iso(event.created_at)),
            )
            self.db.commit()
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
        clauses: list[str] = []
        values: list[object] = []
        if action:
            clauses.append("action = ?")
            values.append(action)
        if actor_user_id:
            clauses.append("actor_user_id = ?")
            values.append(actor_user_id)
        if target_user_id:
            clauses.append("target_user_id = ?")
            values.append(target_user_id)
        if since:
            clauses.append("created_at >= ?")
            values.append(to_iso(since))
        if until:
            clauses.append("created_at <= ?")
            values.append(to_iso(until))
        sql = "SELECT * FROM auth_audit_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        values.extend([limit, offset])
        with self._lock:
            rows = self.db.execute(sql, tuple(values)).fetchall()
        return [
            AuditEvent(
                action=row["action"],
                actor_user_id=row["actor_user_id"],
                target_user_id=row["target_user_id"],
                metadata=json.loads(row["metadata_json"] or "{}"),
                created_at=from_iso(row["created_at"]),
            )
            for row in rows
        ]

    def create_mfa_factor(self, factor: AuthMfaFactor) -> AuthMfaFactor:
        with self._lock:
            self.db.execute(
                """
                INSERT INTO auth_mfa_factors (id, user_id, factor_type, name, secret_hash, credential_id, public_key, sign_count, enabled, created_at, last_used_at, last_used_counter)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (factor.id, factor.user_id, factor.factor_type.value, factor.name, factor.secret_hash, factor.credential_id, factor.public_key, factor.sign_count, int(factor.enabled), to_iso(factor.created_at), _optional_iso(factor.last_used_at), factor.last_used_counter),
            )
            self.db.commit()
        return factor

    def get_mfa_factor(self, factor_id: str) -> AuthMfaFactor | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM auth_mfa_factors WHERE id = ?", (factor_id,)).fetchone()
        return self._mfa_factor_from_row(row) if row else None

    def list_mfa_factors(self, user_id: str) -> list[AuthMfaFactor]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM auth_mfa_factors WHERE user_id = ? ORDER BY created_at ASC, id ASC", (user_id,)).fetchall()
        return [self._mfa_factor_from_row(row) for row in rows]

    def update_mfa_factor(self, factor: AuthMfaFactor) -> None:
        with self._lock:
            cursor = self.db.execute(
                "UPDATE auth_mfa_factors SET name = ?, secret_hash = ?, credential_id = ?, public_key = ?, sign_count = ?, enabled = ?, last_used_at = ?, last_used_counter = ? WHERE id = ?",
                (factor.name, factor.secret_hash, factor.credential_id, factor.public_key, factor.sign_count, int(factor.enabled), _optional_iso(factor.last_used_at), factor.last_used_counter, factor.id),
            )
            self.db.commit()
        if cursor.rowcount == 0:
            raise AuthValidationError("mfa factor not found")

    def mark_mfa_factor_counter_used(self, factor_id: str, *, counter: int, used_at: datetime) -> AuthMfaFactor | None:
        with self._lock:
            row = self.db.execute(
                """
                UPDATE auth_mfa_factors
                SET last_used_at = ?, last_used_counter = ?
                WHERE id = ? AND (last_used_counter IS NULL OR last_used_counter < ?)
                RETURNING *
                """,
                (to_iso(used_at), counter, factor_id, counter),
            ).fetchone()
            self.db.commit()
        return self._mfa_factor_from_row(row) if row else None

    def create_recovery_code(self, code: AuthRecoveryCode) -> AuthRecoveryCode:
        with self._lock:
            self.db.execute(
                "INSERT INTO auth_recovery_codes (id, user_id, code_hash, created_at, used_at) VALUES (?, ?, ?, ?, ?)",
                (code.id, code.user_id, code.code_hash, to_iso(code.created_at), _optional_iso(code.used_at)),
            )
            self.db.commit()
        return code

    def list_recovery_codes(self, user_id: str) -> list[AuthRecoveryCode]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM auth_recovery_codes WHERE user_id = ? ORDER BY created_at ASC, id ASC", (user_id,)).fetchall()
        return [AuthRecoveryCode(id=row["id"], user_id=row["user_id"], code_hash=row["code_hash"], created_at=from_iso(row["created_at"]), used_at=from_iso(row["used_at"]) if row["used_at"] else None) for row in rows]

    def mark_recovery_code_used(self, code_id: str, *, used_at: datetime) -> None:
        with self._lock:
            cursor = self.db.execute("UPDATE auth_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL", (to_iso(used_at), code_id))
            self.db.commit()
        if cursor.rowcount == 0:
            raise AuthValidationError("recovery code not found or already used")

    def health_check(self) -> None:
        with self._lock:
            self.db.execute("SELECT 1").fetchone()

    def _user_from_row(self, row: sqlite3.Row) -> AuthUser:
        return AuthUser(id=row["id"], primary_email=row["primary_email"], primary_email_verified=bool(row["primary_email_verified"]), role=Role(row["role"]), display_name=row["display_name"], avatar_url=row["avatar_url"], status=UserStatus(row["status"]), created_at=from_iso(row["created_at"]), updated_at=from_iso(row["updated_at"]), last_login_at=from_iso(row["last_login_at"]) if row["last_login_at"] else None)

    def _identity_from_row(self, row: sqlite3.Row) -> AuthIdentity:
        return AuthIdentity(id=row["id"], user_id=row["user_id"], provider=row["provider"], provider_subject=row["provider_subject"], email=row["email"], email_verified=bool(row["email_verified"]), linked_at=from_iso(row["linked_at"]), last_seen_at=from_iso(row["last_seen_at"]) if row["last_seen_at"] else None)

    def _credential_from_row(self, row: sqlite3.Row) -> AuthCredential:
        return AuthCredential(id=row["id"], user_id=row["user_id"], credential_type=CredentialType(row["credential_type"]), password_hash=row["password_hash"], created_at=from_iso(row["created_at"]), updated_at=from_iso(row["updated_at"]), revoked_at=from_iso(row["revoked_at"]) if row["revoked_at"] else None)

    def _flow_from_row(self, row: sqlite3.Row) -> LoginFlow:
        return LoginFlow(id=row["id"], flow_type=FlowType(row["flow_type"]), provider=row["provider"], state_hash=row["state_hash"], nonce_hash=row["nonce_hash"], email=row["email"], return_to=row["return_to"], created_at=from_iso(row["created_at"]), expires_at=from_iso(row["expires_at"]), consumed_at=from_iso(row["consumed_at"]) if row["consumed_at"] else None, metadata=json.loads(row["metadata_json"] or "{}"))

    def _session_from_row(self, row: sqlite3.Row) -> AuthSession:
        return AuthSession(id=row["id"], session_token_hash=row["session_token_hash"], user_id=row["user_id"], subject=row["subject"], email=row["email"], provider=row["provider"], role=Role(row["role"]), permissions=tuple(json.loads(row["permissions_json"] or "[]")), assurance_level=AuthAssuranceLevel(row["assurance_level"] or "aal1"), created_at=from_iso(row["created_at"]), expires_at=from_iso(row["expires_at"]), idle_expires_at=from_iso(row["idle_expires_at"]) if row["idle_expires_at"] else None, revoked_at=from_iso(row["revoked_at"]) if row["revoked_at"] else None, last_seen_at=from_iso(row["last_seen_at"]) if row["last_seen_at"] else None, user_agent_hash=row["user_agent_hash"], ip_hash=row["ip_hash"])

    def _mfa_factor_from_row(self, row: sqlite3.Row) -> AuthMfaFactor:
        return AuthMfaFactor(
            id=row["id"],
            user_id=row["user_id"],
            factor_type=MfaFactorType(row["factor_type"]),
            name=row["name"],
            secret_hash=row["secret_hash"],
            credential_id=row["credential_id"],
            public_key=row["public_key"],
            sign_count=int(row["sign_count"]),
            enabled=bool(row["enabled"]),
            created_at=from_iso(row["created_at"]),
            last_used_at=from_iso(row["last_used_at"]) if row["last_used_at"] else None,
            last_used_counter=row["last_used_counter"],
        )
