from __future__ import annotations

import pytest

from coreline_auth import AuthProfile, AuthorizationContext, CorelineAuthConfig, CorelineAuthService, ResourceAuthorizer, Role
from coreline_auth.permissions import ANY_SCOPE, OWN_SCOPE, PolicyEngine
from coreline_auth.storage import MemoryAuthStorage

PASSWORD = "correct horse battery"


def make_service() -> CorelineAuthService:
    return CorelineAuthService(
        storage=MemoryAuthStorage(),
        config=CorelineAuthConfig(profile=AuthProfile.RBAC, owner_email=None, require_email_verified=False),
    )


def create_and_login(service: CorelineAuthService, *, email: str, role: Role):
    user = service.create_user(email=email, role=role, password=PASSWORD, email_verified=True)
    issued = service.login_password(email=email, password=PASSWORD)
    return user, issued


def test_policy_engine_keeps_legacy_profiles_and_adds_core_rbac_roles() -> None:
    legacy = PolicyEngine(profile=AuthProfile.ADMIN_VIEWER)
    assert legacy.permissions_for(role=Role.OWNER) == ("*",)
    assert legacy.permissions_for(role=Role.ADMIN) == ("*",)
    assert legacy.permissions_for(role=Role.USER) == ("profile:read", "dashboard:read")
    assert legacy.allows(("services:*",), "services:write")
    assert legacy.allows(("record:update:any",), "record:update:own")
    assert not legacy.allows(("record:update:own",), "record:update:any")

    rbac = PolicyEngine(profile=AuthProfile.RBAC)
    assert rbac.permissions_for(role=Role.OWNER) == ("*",)
    assert rbac.permissions_for(role=Role.ADMIN) == ("*",)
    assert "dashboard:read" in rbac.permissions_for(role=Role.USER)
    assert rbac.permissions_for(role=Role.VIEWER) == (
        "profile:read",
        "health:read",
        "dashboard:read",
        "services:read",
        "toolbox:read",
        "clients:read",
        "settings:read",
        "logs:read",
    )
    with pytest.raises(ValueError):
        Role("moderator")
    with pytest.raises(ValueError):
        Role("author")


def test_policy_engine_scoped_action_wildcard_does_not_bypass_scope() -> None:
    policy = PolicyEngine(profile=AuthProfile.RBAC)

    assert policy.allows(("record:*:own",), "record:delete:own")
    assert not policy.allows(("record:*:own",), "record:delete:any")
    assert not policy.allows(("record:*:own",), "record:delete")
    assert policy.allows(("record:*:any",), "record:delete:own")


def test_owner_and_admin_have_full_resource_authorization() -> None:
    service = make_service()
    owner, owner_session = create_and_login(service, email="owner@example.com", role=Role.OWNER)
    admin, admin_session = create_and_login(service, email="admin@example.com", role=Role.ADMIN)
    authorizer = ResourceAuthorizer(policy=service.policy)

    owner_decision = authorizer.can(
        owner_session.session.permissions,
        resource="record",
        action="delete",
        context=AuthorizationContext(actor_user_id=owner.id, resource_owner_id="someone_else"),
    )
    admin_decision = authorizer.can(
        admin_session.session.permissions,
        "audit:read",
        context=AuthorizationContext(actor_user_id=admin.id),
    )

    assert owner_decision.allowed
    assert owner_decision.matched_permission == "*"
    assert admin_decision.allowed
    assert admin_decision.matched_permission == "*"


def test_explicit_grants_can_update_and_delete_own_record_only() -> None:
    authorizer = ResourceAuthorizer(policy=PolicyEngine(profile=AuthProfile.RBAC))
    own_context = AuthorizationContext(actor_user_id="u1", resource_owner_id="u1")
    other_context = AuthorizationContext(actor_user_id="u1", resource_owner_id="u2")
    permissions = ("record:update:own", "record:delete:own")

    assert authorizer.can(permissions, resource="record", action="update", context=own_context).allowed
    assert authorizer.can(permissions, resource="record", action="delete", context=own_context).allowed
    assert not authorizer.can(permissions, resource="record", action="update", context=other_context).allowed
    assert not authorizer.can(permissions, resource="record", action="delete", context=other_context).allowed


def test_viewer_is_read_only_and_user_has_limited_core_dashboard_access() -> None:
    service = make_service()
    viewer, viewer_session = create_and_login(service, email="viewer@example.com", role=Role.VIEWER)
    user, user_session = create_and_login(service, email="user@example.com", role=Role.USER)
    authorizer = ResourceAuthorizer(policy=service.policy)

    viewer_context = AuthorizationContext(actor_user_id=viewer.id)
    user_context = AuthorizationContext(actor_user_id=user.id, resource_owner_id=user.id)

    assert authorizer.can(viewer_session.session.permissions, "dashboard:read", context=viewer_context).allowed
    assert authorizer.can(viewer_session.session.permissions, "services:read", context=viewer_context).allowed
    assert not authorizer.can(viewer_session.session.permissions, "users:read", context=viewer_context).allowed

    assert authorizer.can(user_session.session.permissions, "dashboard:read", context=user_context).allowed
    assert authorizer.can(user_session.session.permissions, "profile:read", context=user_context).allowed
    assert not authorizer.can(user_session.session.permissions, resource="record", action="update", context=user_context).allowed
    assert not authorizer.can(user_session.session.permissions, resource="record", action="delete", context=user_context).allowed


def test_action_wildcard_grant_still_enforces_scope() -> None:
    # AUTHZ-001: "record:*:own" means "all actions on records I own". It must not
    # collapse into an unscoped/any grant just because the action is a wildcard.
    engine = PolicyEngine(profile=AuthProfile.RBAC)
    assert engine.allows(("record:*:own",), "record:delete:own")
    assert engine.allows(("record:*:own",), "record:update:own")
    assert not engine.allows(("record:*:own",), "record:delete")
    assert not engine.allows(("record:*:own",), "record:delete:any")
    assert engine.allows(("record:*:any",), "record:delete:own")
    assert engine.allows(("services:*",), "services:write")


def test_resource_authorizer_scoped_action_wildcard_blocks_other_owners() -> None:
    authorizer = ResourceAuthorizer(policy=PolicyEngine(profile=AuthProfile.RBAC))
    grant = ("record:*:own",)
    own_context = AuthorizationContext(actor_user_id="u1", resource_owner_id="u1")
    other_context = AuthorizationContext(actor_user_id="u1", resource_owner_id="u2")

    assert authorizer.can(grant, resource="record", action="delete", context=own_context).allowed
    assert not authorizer.can(grant, resource="record", action="delete", context=other_context).allowed


def test_resource_authorizer_supports_explicit_scope_checks() -> None:
    authorizer = ResourceAuthorizer(policy=PolicyEngine(profile=AuthProfile.RBAC))
    own_context = AuthorizationContext(actor_user_id="u1", resource_owner_id="u1")

    assert not authorizer.can(("record:delete:own",), resource="record", action="delete", scope=ANY_SCOPE, context=own_context).allowed
    assert authorizer.can(("record:delete:any",), resource="record", action="delete", scope=OWN_SCOPE, context=own_context).allowed
    assert authorizer.can_action(("record:delete:any",), resource="record", action="delete", scope=OWN_SCOPE, context=own_context).allowed

    with pytest.raises(ValueError):
        authorizer.can(("record:delete:any",), "record:delete:any", scope=ANY_SCOPE, context=own_context)


def test_admin_can_read_users_and_inactive_actor_is_denied() -> None:
    service = make_service()
    admin, admin_session = create_and_login(service, email="admin-reader@example.com", role=Role.ADMIN)
    authorizer = ResourceAuthorizer(policy=service.policy)

    active_context = AuthorizationContext(actor_user_id=admin.id, resource_owner_id="someone_else")
    banned_context = AuthorizationContext(actor_user_id=admin.id, actor_status="banned", resource_owner_id="someone_else")

    assert authorizer.can(admin_session.session.permissions, "users:read", context=active_context).allowed
    assert not authorizer.can(admin_session.session.permissions, "users:read", context=banned_context).allowed
