from __future__ import annotations

from coreline_auth import AuthProfile, AuthorizationContext, CorelineAuthConfig, CorelineAuthService, ResourceAuthorizer, Role
from coreline_auth.permissions import PolicyEngine
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


def test_policy_engine_keeps_legacy_profiles_and_adds_rbac_roles() -> None:
    legacy = PolicyEngine(profile=AuthProfile.ADMIN_VIEWER)
    assert legacy.permissions_for(role=Role.OWNER) == ("*",)
    assert legacy.permissions_for(role=Role.ADMIN) == ("*",)
    assert legacy.permissions_for(role=Role.USER) == ("profile:read", "dashboard:read")
    assert legacy.allows(("services:*",), "services:write")
    assert legacy.allows(("post:update:any",), "post:update:own")
    assert not legacy.allows(("post:update:own",), "post:update:any")

    rbac = PolicyEngine(profile=AuthProfile.RBAC)
    assert rbac.permissions_for(role=Role.OWNER) == ("*",)
    assert rbac.permissions_for(role=Role.ADMIN) == ("*",)
    assert "post:update:own" in rbac.permissions_for(role=Role.AUTHOR)
    assert "comment:delete:any" in rbac.permissions_for(role=Role.MODERATOR)
    assert "post:create" in rbac.permissions_for(role=Role.USER)


def test_owner_and_admin_have_full_resource_authorization() -> None:
    service = make_service()
    owner, owner_session = create_and_login(service, email="owner@example.com", role=Role.OWNER)
    admin, admin_session = create_and_login(service, email="admin@example.com", role=Role.ADMIN)
    authorizer = ResourceAuthorizer(policy=service.policy)

    owner_decision = authorizer.can(
        owner_session.session.permissions,
        resource="post",
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


def test_author_can_update_and_delete_own_post_only() -> None:
    service = make_service()
    author, author_session = create_and_login(service, email="author@example.com", role=Role.AUTHOR)
    other, _ = create_and_login(service, email="other@example.com", role=Role.USER)
    authorizer = ResourceAuthorizer(policy=service.policy)

    own_context = AuthorizationContext(actor_user_id=author.id, resource_owner_id=author.id)
    other_context = AuthorizationContext(actor_user_id=author.id, resource_owner_id=other.id)

    assert authorizer.can(author_session.session.permissions, resource="post", action="update", context=own_context).allowed
    assert authorizer.can(author_session.session.permissions, resource="post", action="delete", context=own_context).allowed
    assert not authorizer.can(author_session.session.permissions, resource="post", action="update", context=other_context).allowed
    assert not authorizer.can(author_session.session.permissions, resource="post", action="delete", context=other_context).allowed


def test_viewer_is_read_only_and_user_can_limited_create_comment() -> None:
    service = make_service()
    viewer, viewer_session = create_and_login(service, email="viewer@example.com", role=Role.VIEWER)
    user, user_session = create_and_login(service, email="user@example.com", role=Role.USER)
    authorizer = ResourceAuthorizer(policy=service.policy)

    viewer_context = AuthorizationContext(actor_user_id=viewer.id)
    user_context = AuthorizationContext(actor_user_id=user.id, resource_owner_id=user.id)

    assert authorizer.can(viewer_session.session.permissions, "board:read", context=viewer_context).allowed
    assert not authorizer.can(viewer_session.session.permissions, "post:create", context=viewer_context).allowed
    assert not authorizer.can(viewer_session.session.permissions, "comment:create", context=viewer_context).allowed

    assert authorizer.can(user_session.session.permissions, "board:read", context=user_context).allowed
    assert authorizer.can(user_session.session.permissions, "post:create", context=user_context).allowed
    assert authorizer.can(user_session.session.permissions, "comment:create", context=user_context).allowed
    assert not authorizer.can(user_session.session.permissions, resource="post", action="update", context=user_context).allowed
    assert not authorizer.can(user_session.session.permissions, resource="post", action="delete", context=user_context).allowed


def test_moderator_can_moderate_comments_and_inactive_actor_is_denied() -> None:
    service = make_service()
    moderator, moderator_session = create_and_login(service, email="moderator@example.com", role=Role.MODERATOR)
    authorizer = ResourceAuthorizer(policy=service.policy)

    active_context = AuthorizationContext(actor_user_id=moderator.id, resource_owner_id="someone_else")
    banned_context = AuthorizationContext(actor_user_id=moderator.id, actor_status="banned", resource_owner_id="someone_else")

    assert authorizer.can(moderator_session.session.permissions, resource="comment", action="delete", context=active_context).allowed
    assert not authorizer.can(moderator_session.session.permissions, resource="comment", action="delete", context=banned_context).allowed
