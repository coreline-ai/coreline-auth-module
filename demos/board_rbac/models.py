"""Board demo domain models.

``author_user_id`` is intentionally an opaque actor identifier supplied by the
integrating identity system. Board storage does not require, create, or enforce
foreign keys to authentication tables.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


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


@dataclass(slots=True)
class BoardPost:
    id: str
    author_user_id: str
    title: str
    body: str
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)


@dataclass(slots=True)
class BoardComment:
    id: str
    post_id: str
    author_user_id: str
    body: str
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)


@dataclass(frozen=True, slots=True)
class BoardPostDetail:
    post: BoardPost
    comments: tuple[BoardComment, ...]


@dataclass(frozen=True, slots=True)
class BoardActor:
    id: str
    email: str | None = None
    role: str = "user"
    status: str = "active"
    permissions: tuple[str, ...] = ()
