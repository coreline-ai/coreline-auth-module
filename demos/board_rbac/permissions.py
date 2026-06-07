"""Board-owned permission vocabulary and role mapping for the demo."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

ALL_PERMISSIONS = "*"
BOARD_READ = "board:read"
BOARD_POST_CREATE = "post:create"
BOARD_POST_UPDATE_OWN = "post:update:own"
BOARD_POST_UPDATE_ANY = "post:update:any"
BOARD_POST_DELETE_OWN = "post:delete:own"
BOARD_POST_DELETE_ANY = "post:delete:any"
BOARD_COMMENT_CREATE = "comment:create"
BOARD_COMMENT_UPDATE_OWN = "comment:update:own"
BOARD_COMMENT_UPDATE_ANY = "comment:update:any"
BOARD_COMMENT_DELETE_OWN = "comment:delete:own"
BOARD_COMMENT_DELETE_ANY = "comment:delete:any"

BOARD_READ_ONLY_PERMISSIONS: tuple[str, ...] = (BOARD_READ,)
BOARD_USER_PERMISSIONS: tuple[str, ...] = BOARD_READ_ONLY_PERMISSIONS + (BOARD_POST_CREATE, BOARD_COMMENT_CREATE)
BOARD_AUTHOR_PERMISSIONS: tuple[str, ...] = BOARD_USER_PERMISSIONS + (
    BOARD_POST_UPDATE_OWN,
    BOARD_POST_DELETE_OWN,
    BOARD_COMMENT_UPDATE_OWN,
    BOARD_COMMENT_DELETE_OWN,
)
BOARD_MODERATOR_PERMISSIONS: tuple[str, ...] = BOARD_READ_ONLY_PERMISSIONS + (
    BOARD_POST_UPDATE_ANY,
    BOARD_POST_DELETE_ANY,
    BOARD_COMMENT_CREATE,
    BOARD_COMMENT_UPDATE_ANY,
    BOARD_COMMENT_DELETE_ANY,
)
BOARD_ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "owner": (ALL_PERMISSIONS,),
    "admin": (ALL_PERMISSIONS,),
    "moderator": BOARD_MODERATOR_PERMISSIONS,
    "author": BOARD_AUTHOR_PERMISSIONS,
    "user": BOARD_USER_PERMISSIONS,
    "viewer": BOARD_READ_ONLY_PERMISSIONS,
}


def permission_matches(granted: str, required: str) -> bool:
    if granted == ALL_PERMISSIONS or granted == required:
        return True
    granted_parts = granted.split(":")
    required_parts = required.split(":")
    if len(granted_parts) != len(required_parts):
        return False
    if len(granted_parts) < 2:
        return False
    resource_ok = granted_parts[0] in {ALL_PERMISSIONS, required_parts[0]}
    action_ok = granted_parts[1] in {ALL_PERMISSIONS, required_parts[1]}
    if not resource_ok or not action_ok:
        return False
    if len(required_parts) == 2:
        return True
    granted_scope = granted_parts[2]
    required_scope = required_parts[2]
    return granted_scope == required_scope or granted_scope == "any" and required_scope == "own"


@dataclass(frozen=True, slots=True)
class BoardPermissionResolver:
    role_permissions: dict[str, tuple[str, ...]] | None = None

    def permissions_for(self, *, role: str, explicit_permissions: Iterable[str] = ()) -> tuple[str, ...]:
        explicit = tuple(explicit_permissions)
        if explicit:
            return explicit
        mapping = self.role_permissions or BOARD_ROLE_PERMISSIONS
        return mapping.get(role, ())

    def allows(self, permissions: Iterable[str], required: str) -> bool:
        return any(permission_matches(permission, required) for permission in permissions)
