"""Deterministic board RBAC demo seed data."""

from __future__ import annotations

from dataclasses import dataclass, replace

from coreline_auth import CorelineAuthService, Role
from coreline_auth.models import AuthUser, UserStatus, now_utc

from .models import BoardComment, BoardPost
from .storage import BoardStorageProtocol

DEMO_BOARD_PASSWORD = "coreline-" + "demo-password"


@dataclass(frozen=True, slots=True)
class DemoBoardUser:
    board_role: str
    auth_role: Role
    email: str
    display_name: str
    headline: str
    expected_permission: str


DEMO_BOARD_USERS: tuple[DemoBoardUser, ...] = (
    DemoBoardUser("owner", Role.OWNER, "owner-board@example.com", "Owner Demo", "전체 권한 소유자", "모든 게시글/댓글 관리 가능"),
    DemoBoardUser("admin", Role.ADMIN, "admin-board@example.com", "Admin Demo", "관리자", "모든 게시글/댓글 관리 가능"),
    DemoBoardUser("moderator", Role.USER, "moderator-board@example.com", "Moderator Demo", "운영자", "모든 게시글 수정/삭제, 댓글 작성/수정/삭제 가능"),
    DemoBoardUser("author", Role.USER, "author-board@example.com", "Author Demo", "작성자", "게시글 작성 + 본인 글/댓글 수정/삭제 가능"),
    DemoBoardUser("user", Role.USER, "user-board@example.com", "User Demo", "일반 사용자", "게시글/댓글 작성 가능, 수정/삭제 불가"),
    DemoBoardUser("viewer", Role.VIEWER, "viewer-board@example.com", "Viewer Demo", "읽기 전용 사용자", "게시판 읽기만 가능"),
)


def seed_demo_board(auth: CorelineAuthService, storage: BoardStorageProtocol, *, reset_passwords: bool = True) -> dict[str, AuthUser]:
    users = {entry.board_role: _ensure_user(auth, entry, reset_passwords=reset_passwords) for entry in DEMO_BOARD_USERS}
    for entry in DEMO_BOARD_USERS:
        user = users[entry.board_role]
        post = BoardPost(
            id=f"seed_post_{entry.board_role}",
            author_user_id=user.id,
            title=f"[{entry.board_role}] {entry.headline} 권한 테스트 게시글",
            body=(
                f"Board 역할(role): {entry.board_role}\n"
                f"Auth 역할(role): {entry.auth_role.value}\n"
                f"기대 권한: {entry.expected_permission}\n"
                "이 데이터는 coreline-auth repo-local board RBAC demo seed입니다."
            ),
        )
        _upsert_post(storage, post)
    admin_post_id = "seed_post_admin"
    if storage.get_post(admin_post_id) is not None:
        for entry in DEMO_BOARD_USERS:
            user = users[entry.board_role]
            _upsert_comment(
                storage,
                BoardComment(
                    id=f"seed_comment_{entry.board_role}",
                    post_id=admin_post_id,
                    author_user_id=user.id,
                    body=f"{entry.board_role}: {entry.expected_permission}",
                ),
            )
    return users


def _ensure_user(auth: CorelineAuthService, entry: DemoBoardUser, *, reset_passwords: bool) -> AuthUser:
    existing = auth.storage.get_user_by_email(entry.email)
    if existing is None:
        return auth.create_user(
            email=entry.email,
            role=entry.auth_role,
            password=DEMO_BOARD_PASSWORD if reset_passwords else None,
            email_verified=True,
            display_name=entry.display_name,
        )
    updated = replace(existing, role=entry.auth_role, display_name=entry.display_name, primary_email_verified=True, status=UserStatus.ACTIVE, updated_at=now_utc())
    auth.storage.update_user(updated)
    if reset_passwords:
        auth.set_password(updated.id, DEMO_BOARD_PASSWORD, revoke_sessions=False)
    return updated


def _upsert_post(storage: BoardStorageProtocol, post: BoardPost) -> None:
    existing = storage.get_post(post.id)
    if existing is None:
        storage.create_post(post)
    else:
        storage.update_post(replace(existing, title=post.title, body=post.body))


def _upsert_comment(storage: BoardStorageProtocol, comment: BoardComment) -> None:
    existing = storage.get_comment(comment.id)
    if existing is None:
        storage.create_comment(comment)
    else:
        storage.update_comment(replace(existing, body=comment.body))
