"""Profile/role based permission engine."""

from __future__ import annotations

from dataclasses import dataclass

from .models import AuthProfile, Role

ALL_PERMISSIONS = "*"
ANY_SCOPE = "any"
OWN_SCOPE = "own"
READ_ONLY_PERMISSIONS: tuple[str, ...] = (
    "profile:read",
    "health:read",
    "dashboard:read",
    "services:read",
    "toolbox:read",
    "clients:read",
    "settings:read",
    "logs:read",
)
USER_PERMISSIONS: tuple[str, ...] = (
    "profile:read",
    "dashboard:read",
)
RBAC_ROLE_PERMISSIONS: dict[Role, tuple[str, ...]] = {
    Role.OWNER: (ALL_PERMISSIONS,),
    Role.ADMIN: (ALL_PERMISSIONS,),
    Role.VIEWER: READ_ONLY_PERMISSIONS,
    Role.USER: USER_PERMISSIONS,
}


@dataclass(frozen=True, slots=True)
class PermissionStatement:
    resource: str
    action: str
    scope: str | None = None

    @classmethod
    def parse(cls, value: str) -> PermissionStatement:
        value = value.strip()
        if value == ALL_PERMISSIONS:
            return cls(resource=ALL_PERMISSIONS, action=ALL_PERMISSIONS)
        parts = value.split(":")
        if len(parts) == 2:
            return cls(resource=parts[0], action=parts[1])
        if len(parts) == 3:
            return cls(resource=parts[0], action=parts[1], scope=parts[2])
        raise ValueError(f"invalid permission statement: {value!r}")

    @property
    def value(self) -> str:
        if self.resource == ALL_PERMISSIONS and self.action == ALL_PERMISSIONS and self.scope is None:
            return ALL_PERMISSIONS
        if self.scope:
            return f"{self.resource}:{self.action}:{self.scope}"
        return f"{self.resource}:{self.action}"


@dataclass(frozen=True, slots=True)
class PolicyEngine:
    profile: AuthProfile = AuthProfile.SINGLE_OWNER
    owner_email: str | None = None

    def permissions_for(self, *, role: Role, email: str | None = None) -> tuple[str, ...]:
        if self.profile == AuthProfile.SINGLE_OWNER:
            if self.owner_email and email and email.lower() != self.owner_email.lower():
                return ()
            return (ALL_PERMISSIONS,) if role == Role.OWNER else ()
        if self.profile == AuthProfile.ADMIN_VIEWER:
            if role in {Role.OWNER, Role.ADMIN}:
                return (ALL_PERMISSIONS,)
            if role == Role.VIEWER:
                return READ_ONLY_PERMISSIONS
            if role == Role.USER:
                return USER_PERMISSIONS
            return ()
        if self.profile == AuthProfile.RBAC:
            return RBAC_ROLE_PERMISSIONS.get(role, ())
        return ()

    def allows(self, permissions: tuple[str, ...] | list[str], required: str) -> bool:
        return any(_permission_matches(granted, required) for granted in permissions)


def _permission_matches(granted: str, required: str) -> bool:
    if granted == ALL_PERMISSIONS or granted == required:
        return True

    try:
        granted_statement = PermissionStatement.parse(granted)
        required_statement = PermissionStatement.parse(required)
    except ValueError:
        return False

    if granted_statement.resource not in {ALL_PERMISSIONS, required_statement.resource}:
        return False
    if granted_statement.action not in {ALL_PERMISSIONS, required_statement.action}:
        return False

    # A resource/action wildcard must still honor the grant's scope: a scoped
    # grant such as "record:*:own" only covers its scope, never the broader
    # unscoped/any requirements (AUTHZ-001).
    if granted_statement.scope is None or granted_statement.scope == ALL_PERMISSIONS:
        return True
    if granted_statement.scope == required_statement.scope:
        return True
    if granted_statement.scope == ANY_SCOPE and required_statement.scope in {None, OWN_SCOPE}:
        return True
    return False
