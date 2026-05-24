"""Board domain models for the Coreline Auth SaaS-style example."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from coreline_auth.models import now_utc


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
