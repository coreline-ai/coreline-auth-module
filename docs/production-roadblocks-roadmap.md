# Coreline Auth Production Roadblocks Roadmap

This document turns the v0.5.0rc1 production-readiness review into concrete engineering decisions. It separates issues that are already handled, issues patched in this cycle, and items that require larger adapters or architecture work.

## Summary

Coreline Auth is suitable for local/personal and single-process production-style deployments. For high-traffic SaaS or multi-node deployments, the remaining work is mostly around distributed coordination and async database adapters.

| Area | Current status | Production decision |
|---|---|---|
| Session touch write pressure | Throttled by `session_touch_interval_seconds` with regression tests | Keep default throttle; tune per deployment |
| SQLite write contention | Single SQLite connection + lock, WAL + busy timeout | Accept for embedded/single-node; use Postgres adapter for SaaS |
| Rate limiting | In-process limiter + optional Redis adapter | Use Redis adapter for multi-worker/multi-node |
| MFA TOTP secret persistence | In-memory dev vault + encrypted SQLite vault | Use `SQLiteMfaSecretVault` or host vault with envelope key |
| Async storage | `AsyncAuthStorage`, `AsyncCorelineAuthService`, and `AsyncPostgresAuthStorage` scaffold present | Use Postgres adapter for pooled SaaS deployments after DSN smoke |
| Risk-based auth | Context hashes are stored | v0.6+ policy engine extension |

## P0/P1 production hardening decisions

### 1. Session touch throttling

`CorelineAuthService.verify_session()` already skips DB writes until `session_touch_interval_seconds` has elapsed. This prevents every authenticated request from becoming a session write.

Recommended production settings:

- Read-heavy API: `session_touch_interval_seconds=300`
- Admin console: `session_touch_interval_seconds=60`
- Strict idle tracking: `session_touch_interval_seconds=0`, only if DB write capacity is sufficient

Regression coverage:

- `test_session_touch_interval_throttles_update_session`
- `test_session_touch_interval_zero_updates_session`

### 2. MFA secret protection

TOTP verification requires the original TOTP secret. Coreline Auth stores only `secret_hash` in `auth_mfa_factors`; the raw TOTP secret lives behind a `MfaSecretVault`.

Production options:

1. `SQLiteMfaSecretVault` + `SecretEnvelopeProtector` for single-node encrypted persistence.
2. Host-managed vault implementation using KMS/Secrets Manager/Vault.
3. Do not use `InMemoryMfaSecretVault` for production because secrets disappear on restart and are not shared across nodes.

Example:

```python
from coreline_auth import SecretEnvelopeProtector, SQLiteMfaSecretVault

protector = SecretEnvelopeProtector(master_key_b64=os.environ["CORELINE_AUTH_ENVELOPE_KEY"])
vault = SQLiteMfaSecretVault("/var/lib/coreline-auth/auth.sqlite3", protector=protector)
```

Generate a key:

```python
from coreline_auth import SecretEnvelopeProtector
print(SecretEnvelopeProtector.generate_master_key())
```

### 3. Distributed rate limiting

The default `FixedWindowRateLimiter` is process-local. For multi-worker/multi-node deployments, inject `RedisFixedWindowRateLimiter`.

```python
from coreline_auth import RedisFixedWindowRateLimiter

limiter = RedisFixedWindowRateLimiter(redis_client)
auth = CorelineAuthService(..., rate_limiter=limiter)
```

The adapter hashes user keys before storing Redis keys so raw emails/IP values are not exposed in Redis key names.

## Remaining v0.6+ roadmap

### Phase A — Postgres / SQLAlchemy async adapter

Goal: support pooled, async-safe storage for SaaS traffic.

Deliverables:

- `AsyncAuthStorage` protocol — done
- `AsyncCorelineAuthService` core auth/session flows — done
- `mount_async_auth_routes()` minimum JSON adapter — done
- SQLAlchemy Core schema + async adapter — done
- Postgres integration test gated by `CORELINE_AUTH_POSTGRES_DSN` — done
- Docker-backed local Postgres smoke target `make postgres-docker-smoke` — done
- Alembic migration scaffold + offline SQL smoke — done
- Atomic login-flow consume for async magic-link flow — done
- Full async parity for admin/MFA/social flows — later

Risk: large API surface because current service methods are synchronous.

Recommended next implementation order:

1. Run Postgres smoke with `CORELINE_AUTH_POSTGRES_DSN` in the target environment.
2. Apply Alembic online migration in the target DB and keep offline SQL in release artifacts.
3. Extend atomic consume semantics to password-reset/social state when those async flows are added.
4. Expand admin/MFA/social async parity only after the core adapter is stable.

### Phase B — Redis-backed shared stores

Goal: shared state for distributed deployments.

Deliverables:

- Redis rate limit adapter is now present
- Optional Redis-backed login-flow/session cache if needed
- Operational docs for Redis TLS/auth/namespace separation

### Phase C — Risk-based authentication

Goal: detect session theft and step up or revoke risky sessions.

Existing signals:

- `user_agent_hash`
- `ip_hash`
- `assurance_level`

Future policy:

- New country/ASN/device fingerprint mismatch -> require AAL2
- Severe mismatch -> revoke session and audit `auth.session.risk_revoke`
- Admin actions always require AAL2 when MFA exists

### Phase D — Full WebAuthn

Goal: complete passkey registration/assertion flow.

Current state: package helper covers challenge hashing, HTTPS/localhost origin guard, RP ID hash validation, assertion signature verification, user-present/user-verified flags, and sign-counter replay protection. Full browser ceremony UX and attestation trust policy remain host-application decisions.

Required for a product integration:

- Browser registration/assertion UI
- Attestation object parser or specialist WebAuthn library integration
- Product-specific attestation trust policy
- Credential persistence table and admin recovery flow

## Explicit non-goals for v0.5

- Tenant/organization model
- Billing/workspace/team SaaS features
- Mandatory Redis/Postgres dependencies
- Mandatory cloud KMS dependency


## R5 microscope audit hardening status

The R5 audit identified five release-blocker classes. The codebase now has direct regression coverage for the locally testable blockers.

| R5 item | Status | Implementation / test fence |
|---|---|---|
| B-1 AAL2 silent breakage | Fixed | SQLite `update_session()` persists `assurance_level`; `test_sqlite_aal2_survives_db_roundtrip` |
| B-2 login-flow consume race | Fixed | `consume_login_flow_by_state_hash()` atomic storage contract; magic-link/password-reset/social/email-verification use it |
| B-3 recovery-code race | Fixed | `mark_recovery_code_used()` requires unused row; concurrent step-up test |
| B-4 observability gap | Fixed at package level | standard `coreline_auth` logger, optional `MetricSink`, Prometheus text sink, JSONL security event sink, email/audit best-effort logging |
| B-5 test blind spot | Fixed for blockers | `tests/test_release_blockers_r5.py` adds DB round-trip and concurrency fences |

Additional High items addressed in the same batch:

- TOTP same-window replay is blocked with `last_used_counter`.
- CSRF signatures use HMAC-SHA256.
- `health_check()` exists on sync/async storage adapters.
- JWKS unknown-kid refetch has a negative cooldown to reduce DoS amplification.

Remaining production work is integration-oriented rather than blocker-level: host-level SIEM/Grafana/OTel deployment, external Redis/Postgres service operation, and product-specific WebAuthn attestation trust policy.

## GA final hardening status

The follow-up GA pass closes the remaining locally implementable Medium/Operational items without adding SaaS product features.

| Item | Status | Implementation / test fence |
|---|---|---|
| Argon2 explicit parameters | Fixed | `PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)` |
| AES-GCM decrypt error detail | Fixed | uniform `invalid encrypted secret`; `test_decrypt_errors_are_uniform` |
| Admin audit time filter exposure | Fixed | `/auth/admin/audit?since=...&until=...`; `test_admin_audit_api_filters_since_until` |
| Package-level observability sinks | Fixed | `InMemoryMetricSink`, `LoggingMetricSink`, `PrometheusTextMetricSink`, `JsonLineSecurityEventSink`; `tests/test_observability.py` |
| Redis-backed MFA vault | Fixed | `RedisMfaSecretVault` stores only AES-GCM ciphertext; `test_redis_mfa_secret_vault_stores_ciphertext_only` |
| WebAuthn/passkey groundwork | Fixed for package helper scope | challenge hash, origin/RP shape, RP ID hash, signature, user presence/verification, sign counter replay; `tests/test_webauthn.py` |

Explicit boundary: Coreline Auth now provides the security-critical passkey verification helper, but a production host must still choose browser UX, attestation trust policy, credential storage table shape, and recovery/rollback policy.
