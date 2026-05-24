"""Persistent MFA secret vault implementations."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import RLock

from .encryption import SecretEnvelopeProtector
from .models import now_utc


class SQLiteMfaSecretVault:
    """SQLite-backed encrypted TOTP secret vault.

    Store this table in the same SQLite file as `SQLiteAuthStorage` for simple
    deployments, or in a separate protected SQLite file if operationally easier.
    The database only sees AES-GCM ciphertext; the master key must be supplied
    by the host environment or a real secret manager.
    """

    def __init__(self, db_path: str | Path, *, protector: SecretEnvelopeProtector) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.protector = protector
        self._lock = RLock()
        self.db = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA busy_timeout=5000")
            self.db.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_mfa_secret_vault (
                  factor_id TEXT PRIMARY KEY,
                  secret_ciphertext TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                """
            )
            self.db.commit()

    def store_totp_secret(self, *, factor_id: str, secret: str) -> None:
        aad = factor_id.encode("utf-8")
        ciphertext = self.protector.encrypt(secret, aad=aad)
        with self._lock:
            self.db.execute(
                """
                INSERT INTO auth_mfa_secret_vault (factor_id, secret_ciphertext, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(factor_id) DO UPDATE SET
                  secret_ciphertext = excluded.secret_ciphertext,
                  updated_at = excluded.updated_at
                """,
                (factor_id, ciphertext, now_utc().isoformat()),
            )
            self.db.commit()

    def load_totp_secret(self, *, factor_id: str) -> str | None:
        with self._lock:
            row = self.db.execute("SELECT secret_ciphertext FROM auth_mfa_secret_vault WHERE factor_id = ?", (factor_id,)).fetchone()
        if row is None:
            return None
        return self.protector.decrypt(row["secret_ciphertext"], aad=factor_id.encode("utf-8"))

    def close(self) -> None:
        with self._lock:
            self.db.close()


class RedisMfaSecretVault:
    """Redis-backed encrypted TOTP secret vault for multi-node deployments.

    The Redis client is duck-typed and should expose `set(name, value)` and
    `get(name)`. Values are AES-GCM ciphertext produced by
    `SecretEnvelopeProtector`; Redis never stores raw TOTP secrets.
    """

    def __init__(self, redis_client, *, protector: SecretEnvelopeProtector, key_prefix: str = "coreline-auth:mfa-secret:") -> None:
        self.redis = redis_client
        self.protector = protector
        self.key_prefix = key_prefix

    def store_totp_secret(self, *, factor_id: str, secret: str) -> None:
        ciphertext = self.protector.encrypt(secret, aad=factor_id.encode("utf-8"))
        self.redis.set(self.key_prefix + factor_id, ciphertext)

    def load_totp_secret(self, *, factor_id: str) -> str | None:
        raw = self.redis.get(self.key_prefix + factor_id)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return self.protector.decrypt(str(raw), aad=factor_id.encode("utf-8"))
