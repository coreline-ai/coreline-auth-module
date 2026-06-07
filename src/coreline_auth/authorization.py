"""Ownership-aware resource authorization helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import AuthorizationDenied
from .models import AuthProfile, Principal, Role, UserStatus
from .permissions import ANY_SCOPE, OWN_SCOPE, PermissionStatement, PolicyEngine


@dataclass(frozen=True, slots=True)
class PermissionDecision:
    allowed: bool
    required: str
    reason: str = ""
    matched_permission: str | None = None
    scope: str | None = None

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    actor_user_id: str | None = None
    actor_role: Role | None = None
    actor_status: UserStatus | str | None = UserStatus.ACTIVE
    resource_owner_id: str | None = None
    resource_status: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_principal(
        cls,
        principal: Principal,
        *,
        resource_owner_id: str | None = None,
        resource_status: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuthorizationContext:
        return cls(
            actor_user_id=principal.user.id,
            actor_role=principal.session.role,
            actor_status=principal.user.status,
            resource_owner_id=resource_owner_id,
            resource_status=resource_status,
            metadata=dict(metadata or {}),
        )

    @property
    def actor_active(self) -> bool:
        if self.actor_status is None:
            return True
        if isinstance(self.actor_status, UserStatus):
            return self.actor_status == UserStatus.ACTIVE
        return str(self.actor_status).lower() == UserStatus.ACTIVE.value

    @property
    def owns_resource(self) -> bool:
        return self.actor_user_id is not None and self.resource_owner_id is not None and self.actor_user_id == self.resource_owner_id


@dataclass(frozen=True, slots=True)
class ResourceAuthorizer:
    """Evaluate resource/action permissions.

    When ``scope`` is omitted, resource/action checks keep the legacy
    ownership-aware expansion: an owned resource can satisfy unscoped checks
    with ``:own`` or ``:any`` grants. Pass ``scope=OWN_SCOPE`` or
    ``scope=ANY_SCOPE`` to make the required scope explicit.
    """

    policy: PolicyEngine = field(default_factory=lambda: PolicyEngine(profile=AuthProfile.RBAC))

    def can(
        self,
        permissions: Iterable[str] | None,
        required: str | None = None,
        *,
        resource: str | None = None,
        action: str | None = None,
        scope: str | None = None,
        context: AuthorizationContext | None = None,
    ) -> PermissionDecision:
        statement = self._required_statement(required=required, resource=resource, action=action, scope=scope)
        ctx = context or AuthorizationContext()
        effective_permissions = tuple(permissions or ())
        if not effective_permissions and ctx.actor_role is not None:
            effective_permissions = self.policy.permissions_for(role=ctx.actor_role)

        if not ctx.actor_active:
            return PermissionDecision(False, statement.value, reason="actor is not active")

        for candidate in self._candidate_requirements(statement, ctx):
            matched = self._matched_permission(effective_permissions, candidate)
            if matched is not None:
                return PermissionDecision(
                    True,
                    statement.value,
                    reason="allowed",
                    matched_permission=matched,
                    scope=PermissionStatement.parse(candidate).scope,
                )

        return PermissionDecision(False, statement.value, reason=f"missing permission: {statement.value}")

    def require(
        self,
        permissions: Iterable[str] | None,
        required: str | None = None,
        *,
        resource: str | None = None,
        action: str | None = None,
        scope: str | None = None,
        context: AuthorizationContext | None = None,
    ) -> PermissionDecision:
        decision = self.can(permissions, required=required, resource=resource, action=action, scope=scope, context=context)
        if not decision.allowed:
            raise AuthorizationDenied(decision.reason)
        return decision

    def can_action(
        self,
        permissions: Iterable[str] | None,
        *,
        resource: str,
        action: str,
        scope: str | None = None,
        context: AuthorizationContext | None = None,
    ) -> PermissionDecision:
        return self.can(permissions, resource=resource, action=action, scope=scope, context=context)

    def _required_statement(self, *, required: str | None, resource: str | None, action: str | None, scope: str | None) -> PermissionStatement:
        if required is not None:
            if scope is not None:
                raise ValueError("scope cannot be combined with a required permission string")
            return PermissionStatement.parse(required)
        if not resource or not action:
            raise ValueError("required permission or resource/action must be provided")
        return PermissionStatement(resource=resource, action=action, scope=scope)

    def _candidate_requirements(self, statement: PermissionStatement, context: AuthorizationContext) -> tuple[str, ...]:
        if statement.scope == ANY_SCOPE:
            candidates = (
                PermissionStatement(statement.resource, statement.action, ANY_SCOPE).value,
                PermissionStatement(statement.resource, statement.action).value,
            )
        elif statement.scope == OWN_SCOPE:
            candidates = (
                PermissionStatement(statement.resource, statement.action, OWN_SCOPE).value,
                PermissionStatement(statement.resource, statement.action, ANY_SCOPE).value,
                PermissionStatement(statement.resource, statement.action).value,
            ) if context.owns_resource else (
                PermissionStatement(statement.resource, statement.action, ANY_SCOPE).value,
                PermissionStatement(statement.resource, statement.action).value,
            )
        else:
            candidates = (
                PermissionStatement(statement.resource, statement.action).value,
                PermissionStatement(statement.resource, statement.action, OWN_SCOPE).value,
                PermissionStatement(statement.resource, statement.action, ANY_SCOPE).value,
            ) if context.owns_resource else (
                PermissionStatement(statement.resource, statement.action).value,
                PermissionStatement(statement.resource, statement.action, ANY_SCOPE).value,
            )
        return tuple(dict.fromkeys(candidates))

    def _matched_permission(self, permissions: tuple[str, ...], required: str) -> str | None:
        for granted in permissions:
            if self.policy.allows((granted,), required):
                return granted
        return None
