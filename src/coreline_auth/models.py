"""Pure domain models for Coreline Auth."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def from_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    BANNED = "banned"


class CredentialType(StrEnum):
    PASSWORD = "password"


class FlowType(StrEnum):
    MAGIC_LINK = "magic_link"
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    OAUTH = "oauth"


class AuthAssuranceLevel(StrEnum):
    AAL1 = "aal1"
    AAL2 = "aal2"


class MfaFactorType(StrEnum):
    TOTP = "totp"
    PASSKEY = "passkey"


class AuthProfile(StrEnum):
    SINGLE_OWNER = "single_owner"
    ADMIN_VIEWER = "admin_viewer"
    RBAC = "rbac"


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MODERATOR = "moderator"
    AUTHOR = "author"
    VIEWER = "viewer"
    USER = "user"


@dataclass(slots=True)
class AuthUser:
    id: str
    primary_email: str
    primary_email_verified: bool = False
    role: Role = Role.USER
    display_name: str | None = None
    avatar_url: str | None = None
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)
    last_login_at: datetime | None = None


@dataclass(slots=True)
class AuthIdentity:
    id: str
    user_id: str
    provider: str
    provider_subject: str | None = None
    email: str | None = None
    email_verified: bool = False
    linked_at: datetime = field(default_factory=now_utc)
    last_seen_at: datetime | None = None


@dataclass(slots=True)
class AuthCredential:
    id: str
    user_id: str
    credential_type: CredentialType
    password_hash: str | None = None
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)
    revoked_at: datetime | None = None


@dataclass(slots=True)
class LoginFlow:
    id: str
    flow_type: FlowType
    provider: str | None = None
    state_hash: str | None = None
    nonce_hash: str | None = None
    email: str | None = None
    return_to: str = "/"
    created_at: datetime = field(default_factory=now_utc)
    expires_at: datetime = field(default_factory=now_utc)
    consumed_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AuthSession:
    id: str
    session_token_hash: str
    user_id: str
    subject: str | None
    email: str | None
    provider: str | None
    role: Role
    permissions: tuple[str, ...]
    assurance_level: AuthAssuranceLevel = AuthAssuranceLevel.AAL1
    created_at: datetime = field(default_factory=now_utc)
    expires_at: datetime = field(default_factory=now_utc)
    idle_expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_seen_at: datetime | None = None
    user_agent_hash: str | None = None
    ip_hash: str | None = None


@dataclass(slots=True)
class AuthMfaFactor:
    id: str
    user_id: str
    factor_type: MfaFactorType
    name: str
    secret_hash: str | None = None
    credential_id: str | None = None
    public_key: str | None = None
    sign_count: int = 0
    enabled: bool = True
    created_at: datetime = field(default_factory=now_utc)
    last_used_at: datetime | None = None
    last_used_counter: int | None = None


@dataclass(slots=True)
class AuthPasskeyChallenge:
    id: str
    user_id: str | None
    challenge_hash: str
    purpose: str
    created_at: datetime = field(default_factory=now_utc)
    expires_at: datetime = field(default_factory=now_utc)
    consumed_at: datetime | None = None


@dataclass(slots=True)
class AuthRecoveryCode:
    id: str
    user_id: str
    code_hash: str
    created_at: datetime = field(default_factory=now_utc)
    used_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    action: str
    actor_user_id: str | None = None
    target_user_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=now_utc)


@dataclass(frozen=True, slots=True)
class RequestContext:
    ip: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True, slots=True)
class IssuedSession:
    token: str
    session: AuthSession


@dataclass(frozen=True, slots=True)
class MagicLinkChallenge:
    token: str
    flow: LoginFlow


@dataclass(frozen=True, slots=True)
class Principal:
    user: AuthUser
    session: AuthSession

    @property
    def user_id(self) -> str:
        return self.user.id

    @property
    def email(self) -> str:
        return self.user.primary_email
