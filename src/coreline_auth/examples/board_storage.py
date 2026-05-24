"""In-memory board storage for the Coreline Auth SaaS-style example."""

from __future__ import annotations

from dataclasses import replace

from coreline_auth.errors import AuthValidationError
from coreline_auth.models import now_utc

from .board_models import BoardComment, BoardPost


def _sort_key(value: BoardPost | BoardComment) -> tuple[object, str]:
    return (value.created_at, value.id)


class MemoryBoardStorage:
    """Small in-memory repository for posts and comments.

    This storage is intentionally process-local and deterministic for tests/demo
    code. It does not log or persist request payloads.
    """

    def __init__(self) -> None:
        self.posts: dict[str, BoardPost] = {}
        self.comments: dict[str, BoardComment] = {}
        self.comment_ids_by_post: dict[str, set[str]] = {}

    def create_post(self, post: BoardPost) -> BoardPost:
        if post.id in self.posts:
            raise AuthValidationError("board post already exists")
        self.posts[post.id] = post
        self.comment_ids_by_post.setdefault(post.id, set())
        return post

    def get_post(self, post_id: str) -> BoardPost | None:
        return self.posts.get(post_id)

    def list_posts(self) -> list[BoardPost]:
        return sorted(self.posts.values(), key=_sort_key)

    def update_post(self, post: BoardPost) -> BoardPost:
        if post.id not in self.posts:
            raise AuthValidationError("board post not found")
        saved = replace(post, updated_at=now_utc())
        self.posts[saved.id] = saved
        return saved

    def delete_post(self, post_id: str) -> None:
        if post_id not in self.posts:
            raise AuthValidationError("board post not found")
        self.posts.pop(post_id)
        for comment_id in list(self.comment_ids_by_post.pop(post_id, set())):
            self.comments.pop(comment_id, None)

    def create_comment(self, comment: BoardComment) -> BoardComment:
        if comment.id in self.comments:
            raise AuthValidationError("board comment already exists")
        if comment.post_id not in self.posts:
            raise AuthValidationError("board post not found")
        self.comments[comment.id] = comment
        self.comment_ids_by_post.setdefault(comment.post_id, set()).add(comment.id)
        return comment

    def get_comment(self, comment_id: str) -> BoardComment | None:
        return self.comments.get(comment_id)

    def list_comments(self, post_id: str) -> list[BoardComment]:
        if post_id not in self.posts:
            raise AuthValidationError("board post not found")
        comment_ids = self.comment_ids_by_post.get(post_id, set())
        return sorted((self.comments[comment_id] for comment_id in comment_ids if comment_id in self.comments), key=_sort_key)

    def update_comment(self, comment: BoardComment) -> BoardComment:
        existing = self.comments.get(comment.id)
        if existing is None:
            raise AuthValidationError("board comment not found")
        if comment.post_id != existing.post_id:
            raise AuthValidationError("board comment post cannot be changed")
        saved = replace(comment, updated_at=now_utc())
        self.comments[saved.id] = saved
        return saved

    def delete_comment(self, comment_id: str) -> None:
        comment = self.comments.pop(comment_id, None)
        if comment is None:
            raise AuthValidationError("board comment not found")
        self.comment_ids_by_post.get(comment.post_id, set()).discard(comment_id)


BoardStorage = MemoryBoardStorage

import sqlite3
import threading
from pathlib import Path

from coreline_auth.models import from_iso, to_iso

BOARD_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS board_posts (
  id TEXT PRIMARY KEY,
  author_user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS board_comments (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL,
  author_user_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_board_comments_post_created ON board_comments(post_id, created_at, id);
"""


class SQLiteBoardStorage:
    """SQLite-backed board storage for the self-test SaaS app."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if self.db_path != Path(":memory:"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        if self.db_path != Path(":memory:"):
            self.db.execute("PRAGMA journal_mode=WAL")
        self.db.commit()
        self.bootstrap()

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def bootstrap(self) -> None:
        with self._lock:
            self.db.executescript(BOARD_SCHEMA_SQL)
            self.db.commit()

    def create_post(self, post: BoardPost) -> BoardPost:
        with self._lock:
            try:
                self.db.execute(
                    "INSERT INTO board_posts (id, author_user_id, title, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (post.id, post.author_user_id, post.title, post.body, to_iso(post.created_at), to_iso(post.updated_at)),
                )
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                raise AuthValidationError("board post already exists") from exc
        return post

    def get_post(self, post_id: str) -> BoardPost | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM board_posts WHERE id = ?", (post_id,)).fetchone()
        return self._post_from_row(row) if row else None

    def list_posts(self) -> list[BoardPost]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM board_posts ORDER BY created_at ASC, id ASC").fetchall()
        return [self._post_from_row(row) for row in rows]

    def update_post(self, post: BoardPost) -> BoardPost:
        saved = replace(post, updated_at=now_utc())
        with self._lock:
            cursor = self.db.execute(
                "UPDATE board_posts SET title = ?, body = ?, updated_at = ? WHERE id = ?",
                (saved.title, saved.body, to_iso(saved.updated_at), saved.id),
            )
            self.db.commit()
        if cursor.rowcount == 0:
            raise AuthValidationError("board post not found")
        return saved

    def delete_post(self, post_id: str) -> None:
        with self._lock:
            cursor = self.db.execute("DELETE FROM board_posts WHERE id = ?", (post_id,))
            if cursor.rowcount == 0:
                self.db.rollback()
                raise AuthValidationError("board post not found")
            self.db.execute("DELETE FROM board_comments WHERE post_id = ?", (post_id,))
            self.db.commit()

    def create_comment(self, comment: BoardComment) -> BoardComment:
        if self.get_post(comment.post_id) is None:
            raise AuthValidationError("board post not found")
        with self._lock:
            try:
                self.db.execute(
                    "INSERT INTO board_comments (id, post_id, author_user_id, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (comment.id, comment.post_id, comment.author_user_id, comment.body, to_iso(comment.created_at), to_iso(comment.updated_at)),
                )
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                raise AuthValidationError("board comment already exists") from exc
        return comment

    def get_comment(self, comment_id: str) -> BoardComment | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM board_comments WHERE id = ?", (comment_id,)).fetchone()
        return self._comment_from_row(row) if row else None

    def list_comments(self, post_id: str) -> list[BoardComment]:
        if self.get_post(post_id) is None:
            raise AuthValidationError("board post not found")
        with self._lock:
            rows = self.db.execute("SELECT * FROM board_comments WHERE post_id = ? ORDER BY created_at ASC, id ASC", (post_id,)).fetchall()
        return [self._comment_from_row(row) for row in rows]

    def update_comment(self, comment: BoardComment) -> BoardComment:
        existing = self.get_comment(comment.id)
        if existing is None:
            raise AuthValidationError("board comment not found")
        if comment.post_id != existing.post_id:
            raise AuthValidationError("board comment post cannot be changed")
        saved = replace(comment, updated_at=now_utc())
        with self._lock:
            self.db.execute("UPDATE board_comments SET body = ?, updated_at = ? WHERE id = ?", (saved.body, to_iso(saved.updated_at), saved.id))
            self.db.commit()
        return saved

    def delete_comment(self, comment_id: str) -> None:
        with self._lock:
            cursor = self.db.execute("DELETE FROM board_comments WHERE id = ?", (comment_id,))
            self.db.commit()
        if cursor.rowcount == 0:
            raise AuthValidationError("board comment not found")

    def _post_from_row(self, row: sqlite3.Row) -> BoardPost:
        return BoardPost(
            id=row["id"],
            author_user_id=row["author_user_id"],
            title=row["title"],
            body=row["body"],
            created_at=from_iso(row["created_at"]),
            updated_at=from_iso(row["updated_at"]),
        )

    def _comment_from_row(self, row: sqlite3.Row) -> BoardComment:
        return BoardComment(
            id=row["id"],
            post_id=row["post_id"],
            author_user_id=row["author_user_id"],
            body=row["body"],
            created_at=from_iso(row["created_at"]),
            updated_at=from_iso(row["updated_at"]),
        )
