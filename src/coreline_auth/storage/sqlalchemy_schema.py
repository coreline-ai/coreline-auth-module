"""SQLAlchemy Core schema for async production adapters."""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, MetaData, String, Table, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

metadata = MetaData()

json_type = JSONB

auth_users = Table(
    "auth_users",
    metadata,
    # Existing Coreline IDs are opaque strings such as usr_<hex>; keep Text.
    # Postgres deployments can still index and shard at the application layer.
    Column("id", Text, primary_key=True),
    Column("primary_email", Text, nullable=False, unique=True),
    Column("primary_email_verified", Boolean, nullable=False, server_default="false"),
    Column("role", String(32), nullable=False, server_default="user"),
    Column("display_name", Text),
    Column("avatar_url", Text),
    Column("status", String(32), nullable=False, server_default="active"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_login_at", DateTime(timezone=True)),
)
Index("ix_auth_users_role_status_created", auth_users.c.role, auth_users.c.status, auth_users.c.created_at, auth_users.c.id)

auth_identities = Table(
    "auth_identities",
    metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, nullable=False),
    Column("provider", Text, nullable=False),
    Column("provider_subject", Text),
    Column("email", Text),
    Column("email_verified", Boolean, nullable=False, server_default="false"),
    Column("linked_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_seen_at", DateTime(timezone=True)),
    UniqueConstraint("provider", "provider_subject", name="uq_auth_identities_provider_subject"),
)

auth_credentials = Table(
    "auth_credentials",
    metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, nullable=False),
    Column("credential_type", String(32), nullable=False),
    Column("password_hash", Text),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("revoked_at", DateTime(timezone=True)),
)
Index("uq_auth_password_credential_active", auth_credentials.c.user_id, auth_credentials.c.credential_type, unique=True, postgresql_where=(auth_credentials.c.credential_type == "password") & auth_credentials.c.revoked_at.is_(None))

auth_login_flows = Table(
    "auth_login_flows",
    metadata,
    Column("id", Text, primary_key=True),
    Column("flow_type", String(64), nullable=False),
    Column("provider", Text),
    Column("state_hash", Text, unique=True),
    Column("nonce_hash", Text),
    Column("email", Text),
    Column("return_to", Text, nullable=False, server_default="/"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True)),
    Column("metadata_json", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
)
Index("ix_auth_login_flows_expires", auth_login_flows.c.expires_at)

auth_sessions = Table(
    "auth_sessions",
    metadata,
    Column("id", Text, primary_key=True),
    Column("session_token_hash", Text, nullable=False, unique=True),
    Column("user_id", Text, nullable=False),
    Column("subject", Text),
    Column("email", Text),
    Column("provider", Text),
    Column("role", String(32), nullable=False),
    Column("permissions_json", JSONB, nullable=False),
    Column("assurance_level", String(32), nullable=False, server_default="aal1"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("idle_expires_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    Column("last_seen_at", DateTime(timezone=True)),
    Column("user_agent_hash", Text),
    Column("ip_hash", Text),
)
Index("ix_auth_sessions_user_created", auth_sessions.c.user_id, auth_sessions.c.created_at, auth_sessions.c.id)
Index("ix_auth_sessions_expires", auth_sessions.c.expires_at, auth_sessions.c.idle_expires_at, auth_sessions.c.revoked_at)

auth_audit_events = Table(
    "auth_audit_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("action", Text, nullable=False),
    Column("actor_user_id", Text),
    Column("target_user_id", Text),
    Column("metadata_json", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
Index("ix_auth_audit_action_created", auth_audit_events.c.action, auth_audit_events.c.created_at)
Index("ix_auth_audit_actor_created", auth_audit_events.c.actor_user_id, auth_audit_events.c.created_at)

auth_mfa_factors = Table(
    "auth_mfa_factors",
    metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, nullable=False),
    Column("factor_type", String(32), nullable=False),
    Column("name", Text, nullable=False),
    Column("secret_hash", Text),
    Column("credential_id", Text),
    Column("public_key", Text),
    Column("sign_count", Integer, nullable=False, server_default="0"),
    Column("enabled", Boolean, nullable=False, server_default="true"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_used_at", DateTime(timezone=True)),
    Column("last_used_counter", Integer),
)
Index("ix_auth_mfa_user_enabled", auth_mfa_factors.c.user_id, auth_mfa_factors.c.enabled)

auth_recovery_codes = Table(
    "auth_recovery_codes",
    metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, nullable=False),
    Column("code_hash", Text, nullable=False, unique=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("used_at", DateTime(timezone=True)),
)
Index("ix_auth_recovery_user_used", auth_recovery_codes.c.user_id, auth_recovery_codes.c.used_at)
