"""Memory and SQLite board storage for the repo-local RBAC demo."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace
from pathlib import Path
from threading import RLock
from typing import Protocol

from .errors import BoardNotFoundError, BoardValidationError
from .models import BoardComment, BoardPost, from_iso, now_utc, to_iso


class BoardStorageProtocol(Protocol):
    def create_post(self, post: BoardPost) -> BoardPost: ...
    def get_post(self, post_id: str) -> BoardPost | None: ...
    def list_posts(self) -> list[BoardPost]: ...
    def update_post(self, post: BoardPost) -> BoardPost: ...
    def delete_post(self, post_id: str) -> None: ...
    def create_comment(self, comment: BoardComment) -> BoardComment: ...
    def get_comment(self, comment_id: str) -> BoardComment | None: ...
    def list_comments(self, post_id: str) -> list[BoardComment]: ...
    def update_comment(self, comment: BoardComment) -> BoardComment: ...
    def delete_comment(self, comment_id: str) -> None: ...


def _sort_key(value: BoardPost | BoardComment) -> tuple[object, str]:
    return (value.created_at, value.id)


class MemoryBoardStorage:
    def __init__(self) -> None:
        self.posts: dict[str, BoardPost] = {}
        self.comments: dict[str, BoardComment] = {}
        self.comment_ids_by_post: dict[str, set[str]] = {}
        self._lock = RLock()

    def create_post(self, post: BoardPost) -> BoardPost:
        with self._lock:
            if post.id in self.posts:
                raise BoardValidationError("board post already exists")
            self.posts[post.id] = post
            self.comment_ids_by_post.setdefault(post.id, set())
            return post

    def get_post(self, post_id: str) -> BoardPost | None:
        with self._lock:
            return self.posts.get(post_id)

    def list_posts(self) -> list[BoardPost]:
        with self._lock:
            return sorted(self.posts.values(), key=_sort_key)

    def update_post(self, post: BoardPost) -> BoardPost:
        with self._lock:
            existing = self.posts.get(post.id)
            if existing is None:
                raise BoardNotFoundError("board post not found")
            if post.author_user_id != existing.author_user_id:
                raise BoardValidationError("board post author cannot be changed")
            saved = replace(post, created_at=existing.created_at, updated_at=now_utc())
            self.posts[saved.id] = saved
            return saved

    def delete_post(self, post_id: str) -> None:
        with self._lock:
            if post_id not in self.posts:
                raise BoardNotFoundError("board post not found")
            self.posts.pop(post_id)
            for comment_id in list(self.comment_ids_by_post.pop(post_id, set())):
                self.comments.pop(comment_id, None)

    def create_comment(self, comment: BoardComment) -> BoardComment:
        with self._lock:
            if comment.id in self.comments:
                raise BoardValidationError("board comment already exists")
            if comment.post_id not in self.posts:
                raise BoardNotFoundError("board post not found")
            self.comments[comment.id] = comment
            self.comment_ids_by_post.setdefault(comment.post_id, set()).add(comment.id)
            return comment

    def get_comment(self, comment_id: str) -> BoardComment | None:
        with self._lock:
            return self.comments.get(comment_id)

    def list_comments(self, post_id: str) -> list[BoardComment]:
        with self._lock:
            if post_id not in self.posts:
                raise BoardNotFoundError("board post not found")
            comment_ids = self.comment_ids_by_post.get(post_id, set())
            return sorted((self.comments[comment_id] for comment_id in comment_ids if comment_id in self.comments), key=_sort_key)

    def update_comment(self, comment: BoardComment) -> BoardComment:
        with self._lock:
            existing = self.comments.get(comment.id)
            if existing is None:
                raise BoardNotFoundError("board comment not found")
            if comment.post_id != existing.post_id:
                raise BoardValidationError("board comment post cannot be changed")
            if comment.author_user_id != existing.author_user_id:
                raise BoardValidationError("board comment author cannot be changed")
            saved = replace(comment, created_at=existing.created_at, updated_at=now_utc())
            self.comments[saved.id] = saved
            return saved

    def delete_comment(self, comment_id: str) -> None:
        with self._lock:
            comment = self.comments.pop(comment_id, None)
            if comment is None:
                raise BoardNotFoundError("board comment not found")
            self.comment_ids_by_post.get(comment.post_id, set()).discard(comment_id)


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
  updated_at TEXT NOT NULL,
  FOREIGN KEY(post_id) REFERENCES board_posts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_board_comments_post_created ON board_comments(post_id, created_at, id);
"""


class SQLiteBoardStorage:
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

    def __enter__(self) -> SQLiteBoardStorage:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

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
                raise BoardValidationError("board post already exists") from exc
        return post

    def get_post(self, post_id: str) -> BoardPost | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM board_posts WHERE id = ?", (post_id,)).fetchone()
        return self._post_from_row(row) if row else None

    def list_posts(self) -> list[BoardPost]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM board_posts ORDER BY created_at, id").fetchall()
        return [self._post_from_row(row) for row in rows]

    def update_post(self, post: BoardPost) -> BoardPost:
        with self._lock:
            existing = self.get_post(post.id)
            if existing is None:
                raise BoardNotFoundError("board post not found")
            if post.author_user_id != existing.author_user_id:
                raise BoardValidationError("board post author cannot be changed")
            saved = replace(post, created_at=existing.created_at, updated_at=now_utc())
            cursor = self.db.execute(
                "UPDATE board_posts SET title = ?, body = ?, updated_at = ? WHERE id = ? AND author_user_id = ?",
                (saved.title, saved.body, to_iso(saved.updated_at), saved.id, saved.author_user_id),
            )
            if cursor.rowcount != 1:
                self.db.rollback()
                raise BoardNotFoundError("board post not found")
            self.db.commit()
        return saved

    def delete_post(self, post_id: str) -> None:
        with self._lock:
            cursor = self.db.execute("DELETE FROM board_posts WHERE id = ?", (post_id,))
            if cursor.rowcount != 1:
                self.db.rollback()
                raise BoardNotFoundError("board post not found")
            self.db.commit()

    def create_comment(self, comment: BoardComment) -> BoardComment:
        with self._lock:
            try:
                self.db.execute(
                    "INSERT INTO board_comments (id, post_id, author_user_id, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (comment.id, comment.post_id, comment.author_user_id, comment.body, to_iso(comment.created_at), to_iso(comment.updated_at)),
                )
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                self.db.rollback()
                if self.get_post(comment.post_id) is None:
                    raise BoardNotFoundError("board post not found") from exc
                raise BoardValidationError("board comment already exists") from exc
        return comment

    def get_comment(self, comment_id: str) -> BoardComment | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM board_comments WHERE id = ?", (comment_id,)).fetchone()
        return self._comment_from_row(row) if row else None

    def list_comments(self, post_id: str) -> list[BoardComment]:
        with self._lock:
            if self.get_post(post_id) is None:
                raise BoardNotFoundError("board post not found")
            rows = self.db.execute("SELECT * FROM board_comments WHERE post_id = ? ORDER BY created_at, id", (post_id,)).fetchall()
        return [self._comment_from_row(row) for row in rows]

    def update_comment(self, comment: BoardComment) -> BoardComment:
        with self._lock:
            existing = self.get_comment(comment.id)
            if existing is None:
                raise BoardNotFoundError("board comment not found")
            if comment.post_id != existing.post_id:
                raise BoardValidationError("board comment post cannot be changed")
            if comment.author_user_id != existing.author_user_id:
                raise BoardValidationError("board comment author cannot be changed")
            saved = replace(comment, created_at=existing.created_at, updated_at=now_utc())
            cursor = self.db.execute(
                "UPDATE board_comments SET body = ?, updated_at = ? WHERE id = ? AND post_id = ? AND author_user_id = ?",
                (saved.body, to_iso(saved.updated_at), saved.id, saved.post_id, saved.author_user_id),
            )
            if cursor.rowcount != 1:
                self.db.rollback()
                raise BoardNotFoundError("board comment not found")
            self.db.commit()
        return saved

    def delete_comment(self, comment_id: str) -> None:
        with self._lock:
            cursor = self.db.execute("DELETE FROM board_comments WHERE id = ?", (comment_id,))
            if cursor.rowcount != 1:
                self.db.rollback()
                raise BoardNotFoundError("board comment not found")
            self.db.commit()

    @staticmethod
    def _post_from_row(row: sqlite3.Row) -> BoardPost:
        return BoardPost(
            id=row["id"],
            author_user_id=row["author_user_id"],
            title=row["title"],
            body=row["body"],
            created_at=from_iso(row["created_at"]),
            updated_at=from_iso(row["updated_at"]),
        )

    @staticmethod
    def _comment_from_row(row: sqlite3.Row) -> BoardComment:
        return BoardComment(
            id=row["id"],
            post_id=row["post_id"],
            author_user_id=row["author_user_id"],
            body=row["body"],
            created_at=from_iso(row["created_at"]),
            updated_at=from_iso(row["updated_at"]),
        )
