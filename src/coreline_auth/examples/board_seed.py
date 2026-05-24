"""Demo board seed data for role/permission testing.

The seed is intentionally deterministic and enabled only by the SaaS demo app.
It creates one user and one post per role so manual QA can quickly switch
accounts and verify RBAC behavior without hand-crafting fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from coreline_auth import CorelineAuthService, Role
from coreline_auth.models import AuthUser, UserStatus, now_utc

from .board_models import BoardComment, BoardPost
from .board_storage import MemoryBoardStorage

DEMO_BOARD_PASSWORD = "coreline-" + "demo-password"


@dataclass(frozen=True, slots=True)
class DemoBoardUser:
    role: Role
    email: str
    display_name: str
    headline: str
    expected_permission: str


DEMO_BOARD_USERS: tuple[DemoBoardUser, ...] = (
    DemoBoardUser(Role.OWNER, "owner-board@example.com", "Owner Demo", "전체 권한 소유자", "모든 게시글/댓글 관리 가능"),
    DemoBoardUser(Role.ADMIN, "admin-board@example.com", "Admin Demo", "관리자", "모든 게시글/댓글 관리 가능"),
    DemoBoardUser(Role.MODERATOR, "moderator-board@example.com", "Moderator Demo", "운영자", "모든 게시글 수정/삭제, 댓글 작성/삭제 가능"),
    DemoBoardUser(Role.AUTHOR, "author-board@example.com", "Author Demo", "작성자", "게시글 작성 + 본인 글 수정/삭제 가능"),
    DemoBoardUser(Role.USER, "user-board@example.com", "User Demo", "일반 사용자", "게시글/댓글 작성 가능, 수정/삭제 불가"),
    DemoBoardUser(Role.VIEWER, "viewer-board@example.com", "Viewer Demo", "읽기 전용 사용자", "게시판 읽기만 가능"),
)


ROLE_TEST_NOTES = (
    "테스트 방법:\n"
    "1. 이 계정으로 로그인합니다.\n"
    "2. 게시글 목록/상세 접근 여부를 확인합니다.\n"
    "3. 새 글 작성, 수정, 삭제, 댓글 작성 버튼을 눌러 role별 권한 차이를 확인합니다.\n"
    "4. 같은 비밀번호를 사용합니다: " + DEMO_BOARD_PASSWORD + "\n"
)


def seed_demo_board(auth: CorelineAuthService, storage: MemoryBoardStorage, *, reset_passwords: bool = True) -> dict[Role, AuthUser]:
    """Create deterministic role users and board posts for the demo app.

    The function is idempotent: existing users are updated to the intended role
    and existing posts/comments are refreshed instead of duplicated.
    """

    users = {entry.role: _ensure_user(auth, entry, reset_passwords=reset_passwords) for entry in DEMO_BOARD_USERS}
    _upsert_role_posts(storage, users)
    _upsert_permission_matrix_comment(storage, users)
    return users


def _ensure_user(auth: CorelineAuthService, entry: DemoBoardUser, *, reset_passwords: bool) -> AuthUser:
    existing = auth.storage.get_user_by_email(entry.email)
    if existing is None:
        return auth.create_user(
            email=entry.email,
            role=entry.role,
            password=DEMO_BOARD_PASSWORD if reset_passwords else None,
            email_verified=True,
            display_name=entry.display_name,
        )
    updated = replace(
        existing,
        role=entry.role,
        display_name=entry.display_name,
        primary_email_verified=True,
        status=UserStatus.ACTIVE,
        updated_at=now_utc(),
    )
    auth.storage.update_user(updated)
    if reset_passwords:
        auth.set_password(updated.id, DEMO_BOARD_PASSWORD)
    return updated


def _upsert_role_posts(storage: MemoryBoardStorage, users: dict[Role, AuthUser]) -> None:
    for entry in DEMO_BOARD_USERS:
        user = users[entry.role]
        post = BoardPost(
            id=f"seed_post_{entry.role.value}",
            author_user_id=user.id,
            title=f"[{entry.role.value}] {entry.headline} 권한 테스트 게시글",
            body=(
                f"이 게시글은 {entry.display_name} 계정으로 생성된 권한 테스트용 더미 데이터입니다.\n\n"
                f"역할(role): {entry.role.value}\n"
                f"기대 권한: {entry.expected_permission}\n\n"
                f"{ROLE_TEST_NOTES}"
            ),
        )
        _upsert_post(storage, post)


def _upsert_permission_matrix_comment(storage: MemoryBoardStorage, users: dict[Role, AuthUser]) -> None:
    matrix_post_id = "seed_post_admin"
    if storage.get_post(matrix_post_id) is None:
        return
    for entry in DEMO_BOARD_USERS:
        user = users[entry.role]
        comment = BoardComment(
            id=f"seed_comment_{entry.role.value}",
            post_id=matrix_post_id,
            author_user_id=user.id,
            body=f"{entry.role.value}: {entry.expected_permission}",
        )
        _upsert_comment(storage, comment)


def _upsert_post(storage: MemoryBoardStorage, post: BoardPost) -> None:
    existing = storage.get_post(post.id)
    if existing is None:
        storage.create_post(post)
        return
    storage.update_post(replace(existing, author_user_id=post.author_user_id, title=post.title, body=post.body))


def _upsert_comment(storage: MemoryBoardStorage, comment: BoardComment) -> None:
    existing = storage.get_comment(comment.id)
    if existing is None:
        storage.create_comment(comment)
        return
    storage.update_comment(replace(existing, post_id=comment.post_id, author_user_id=comment.author_user_id, body=comment.body))
