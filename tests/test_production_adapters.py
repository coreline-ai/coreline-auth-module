from __future__ import annotations

import sqlite3
from pathlib import Path

from coreline_auth import AuthProfile, CorelineAuthConfig, CorelineAuthService, SecretEnvelopeProtector, SQLiteMfaSecretVault, totp_code
from coreline_auth.redis_rate_limit import RedisFixedWindowRateLimiter
from coreline_auth.storage import SQLiteAuthStorage


def test_secret_envelope_protector_round_trips_and_rejects_wrong_aad() -> None:
    protector = SecretEnvelopeProtector(SecretEnvelopeProtector.generate_master_key())
    token = protector.encrypt("sensitive-totp-secret", aad=b"factor-1")

    assert token.startswith("v1.aes256gcm.")
    assert "sensitive-totp-secret" not in token
    assert protector.decrypt(token, aad=b"factor-1") == "sensitive-totp-secret"

    try:
        protector.decrypt(token, aad=b"factor-2")
    except Exception as exc:
        assert "invalid encrypted secret" in str(exc)
    else:  # pragma: no cover - defensive guard
        raise AssertionError("wrong AAD should not decrypt")


def test_sqlite_mfa_secret_vault_persists_ciphertext_only(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    protector = SecretEnvelopeProtector(SecretEnvelopeProtector.generate_master_key())
    vault = SQLiteMfaSecretVault(db_path, protector=protector)
    try:
        vault.store_totp_secret(factor_id="mfa_1", secret="JBSWY3DPEHPK3PXP")
    finally:
        vault.close()

    raw = db_path.read_bytes()
    assert b"JBSWY3DPEHPK3PXP" not in raw

    reopened = SQLiteMfaSecretVault(db_path, protector=protector)
    try:
        assert reopened.load_totp_secret(factor_id="mfa_1") == "JBSWY3DPEHPK3PXP"
    finally:
        reopened.close()


def test_sqlite_mfa_secret_vault_survives_service_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    master_key = SecretEnvelopeProtector.generate_master_key()
    storage = SQLiteAuthStorage(db_path)
    vault = SQLiteMfaSecretVault(db_path, protector=SecretEnvelopeProtector(master_key))
    try:
        service = CorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False), mfa_secret_vault=vault)
        user = service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
        factor, secret = service.begin_totp_enrollment(user.id)
        service.verify_totp_enrollment(user_id=user.id, factor_id=factor.id, code=totp_code(secret))
    finally:
        vault.close()
        storage.close()

    reopened_storage = SQLiteAuthStorage(db_path)
    reopened_vault = SQLiteMfaSecretVault(db_path, protector=SecretEnvelopeProtector(master_key))
    try:
        service = CorelineAuthService(storage=reopened_storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False), mfa_secret_vault=reopened_vault)
        assert service.verify_totp(user_id=user.id, code=totp_code(secret)).id == factor.id
    finally:
        reopened_vault.close()
        reopened_storage.close()

    with sqlite3.connect(db_path) as db:
        ciphertext = db.execute("SELECT secret_ciphertext FROM auth_mfa_secret_vault WHERE factor_id = ?", (factor.id,)).fetchone()[0]
    assert ciphertext.startswith("v1.aes256gcm.")
    assert secret not in ciphertext


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}
        self.ttls: dict[str, int] = {}

    def eval(self, _script: str, _numkeys: int, key: str, limit: int, window_seconds: int):
        current = self.values.get(key)
        if current is not None and current >= int(limit):
            return [0, self.ttls.get(key, int(window_seconds))]
        self.values[key] = (current or 0) + 1
        self.ttls[key] = int(window_seconds)
        return [1, self.ttls[key]]


def test_redis_fixed_window_rate_limiter_uses_hashed_keys_and_retry_after() -> None:
    redis = FakeRedis()
    limiter = RedisFixedWindowRateLimiter(redis, key_prefix="test:")

    assert limiter.check("user@example.com", limit=2, window_seconds=30).allowed is True
    assert limiter.check("user@example.com", limit=2, window_seconds=30).allowed is True
    denied = limiter.check("user@example.com", limit=2, window_seconds=30)

    assert denied.allowed is False
    assert denied.retry_after_seconds == 30
    stored_key = next(iter(redis.values))
    assert stored_key.startswith("test:")
    assert "user@example.com" not in stored_key


def test_decrypt_errors_are_uniform() -> None:
    protector = SecretEnvelopeProtector(SecretEnvelopeProtector.generate_master_key())
    bad_tokens = ["bad-prefix", "v1.aes256gcm.not-base64!", "v1.aes256gcm." + "AA=="]

    for token in bad_tokens:
        try:
            protector.decrypt(token)
        except Exception as exc:
            assert str(exc) == "invalid encrypted secret"
        else:  # pragma: no cover
            raise AssertionError("bad ciphertext should not decrypt")


class FakeRedisVault:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def set(self, key: str, value: str) -> None:
        self.values[key] = value

    def get(self, key: str):
        return self.values.get(key)


def test_redis_mfa_secret_vault_stores_ciphertext_only() -> None:
    from coreline_auth import RedisMfaSecretVault

    redis = FakeRedisVault()
    protector = SecretEnvelopeProtector(SecretEnvelopeProtector.generate_master_key())
    vault = RedisMfaSecretVault(redis, protector=protector, key_prefix="test:mfa:")

    vault.store_totp_secret(factor_id="mfa_1", secret="JBSWY3DPEHPK3PXP")

    stored = redis.values["test:mfa:mfa_1"]
    assert "JBSWY3DPEHPK3PXP" not in stored
    assert stored.startswith("v1.aes256gcm.")
    assert vault.load_totp_secret(factor_id="mfa_1") == "JBSWY3DPEHPK3PXP"
