<div align="center">

<img width="2752" height="1536" alt="인증 보안 솔루션 주요 특징" src="https://github.com/user-attachments/assets/75adcfe0-b9b5-4b6c-8b6f-556df498230f" />

# 🔐 Coreline Auth

**A production-grade, framework-agnostic authentication module for Python**

_Independent auth · session · permission · admin core — built for reuse across the Coreline project family._

<br/>

[![Version](https://img.shields.io/badge/version-0.5.0--rc2-blue.svg?style=for-the-badge)](./CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.12+-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-149%20passed-success.svg?style=for-the-badge&logo=pytest&logoColor=white)](./tests/)
[![Status](https://img.shields.io/badge/status-release%20candidate-orange.svg?style=for-the-badge)](#-roadmap)

[![Security](https://img.shields.io/badge/security-Argon2id%20%7C%20AES--GCM%20%7C%20RS256-red.svg?style=flat-square)](./docs/security-checklist.md)
[![MFA](https://img.shields.io/badge/MFA-TOTP%20%7C%20WebAuthn%20%7C%20AAL2-blueviolet.svg?style=flat-square)](./docs/mfa-passkey-scope.md)
[![Storage](https://img.shields.io/badge/storage-SQLite%20%7C%20Postgres%20%7C%20Redis-336791.svg?style=flat-square&logo=postgresql&logoColor=white)](./docs/production-roadblocks-roadmap.md)
[![Observability](https://img.shields.io/badge/observability-Prometheus%20%7C%20JSONL%20SIEM-E6522C.svg?style=flat-square&logo=prometheus&logoColor=white)](./src/coreline_auth/observability.py)
[![Readiness](https://img.shields.io/badge/readiness-secret--safe%20CLI-1f883d.svg?style=flat-square)](./docs/ops-readiness.md)
[![Zero Coupling](https://img.shields.io/badge/CoreMCP%20coupling-0%20imports-brightgreen.svg?style=flat-square)](./src/coreline_auth/)

<br/>

[Quick Start](#-quick-start) ·
[Features](#-features) ·
[Architecture](#-architecture) ·
[API](#-api-surface) ·
[Security](#-security-primitives) ·
[Production](#-production-deployment) ·
[Docs](#-documentation)

</div>

---

## 📌 Overview

> Coreline Auth는 **Lucia / Better Auth 의 Python 등가물** 을 목표로 한 완전 독립 인증 모듈입니다.
> CoreMCP 의 하위 기능이 아닌, 별도 제품형 모듈로 관리되며, CoreMCP 는 `single_owner` profile 의 첫 소비자일 뿐입니다.

```
✓ Standalone — zero coupling to host projects (verified by grep guard in CI)
✓ Hardened    — 6 rounds of expert review · Argon2id · AAD-bound AEAD · HMAC CSRF · OIDC azp/nbf/max_age
✓ Pluggable  — Storage / EmailSender / RateLimiter / MfaVault / SocialConnector / MetricSink Protocols
✓ Observable — Prometheus counters · JSONL SIEM forwarder · structured logging via stdlib
✓ Async-ready — Postgres async adapter · AsyncCorelineAuthService · Alembic migrations
✓ Demo-ready — signup/login · account center · admin console · board RBAC · system readiness
```

---

## 📑 Table of Contents

<details>
<summary><b>Click to expand</b></summary>

- [Overview](#-overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [API Surface](#-api-surface)
- [Security Primitives](#-security-primitives)
- [Permission Model](#-permission-model)
- [Production Deployment](#-production-deployment)
  - [Storage adapters](#storage-adapters)
  - [Encrypted MFA vault](#encrypted-mfa-vault)
  - [Distributed rate limiting](#distributed-rate-limiting)
  - [Observability sinks](#observability-sinks)
  - [SMTP & email providers](#smtp--email-providers)
  - [OAuth / OIDC providers](#oauth--oidc-providers)
  - [Operational defaults](#operational-defaults)
  - [Secret-safe readiness check](#secret-safe-readiness-check)
- [Reference Comparison](#-reference-comparison)
- [Self-Test Webapp](#-self-test-webapp)
- [Testing](#-testing)
- [Roadmap](#-roadmap)
- [Documentation](#-documentation)
- [Independence Principles](#-independence-principles)
- [License](#-license)

</details>

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔑 Authentication
- 📧 **Email + Password** with Argon2id hashing
- ✨ **Magic Link** (one-time, hash-only storage)
- 🔁 **Password Reset** with session revoke
- ✉️ **Email Verification**
- 🌐 **OAuth 2.0 / OIDC** (Google / Facebook / Generic)
- 🔏 **ID Token verification** — RS256 + JWKS + `azp` + `nbf` + `max_age` + nonce policy
- ⏱️ **Login timing hardening** (dummy Argon2 verify)
- 🚦 **Per-user rate limiting** (in-process + Redis)

</td>
<td width="50%" valign="top">

### 🛡️ Multi-Factor & Sessions
- 🔢 **TOTP** enrollment / verify with counter replay reject
- 🎫 **Recovery codes** (one-time, hash-only)
- 🆙 **AAL2 step-up** with persistence
- 🔓 **Passkey / WebAuthn** registration + assertion
- 🍪 **Cookie session** (Secure / HttpOnly / SameSite=Lax)
- 🛂 **Bearer token** support
- ⏳ **Session touch throttle** to reduce DB write pressure
- 🔄 **Idle + absolute expiry** with auto-touch

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🚧 Security Hardening
- 🔐 **HMAC-SHA256 CSRF** with session binding
- 🛡️ **AES-256-GCM envelope encryption** for MFA secrets
- 🚫 **Open-redirect guard** (same-origin only)
- 🔁 **Atomic state consume** (one-time tokens are race-safe)
- 📵 **Audit metadata redaction** + size cap + depth cap
- 🎭 **Verified-email-only social linking**
- 🚷 **Self-ban + last-owner lockout protection**
- 🧂 **Secret entropy guard** (weak-secret marker rejection)

</td>
<td width="50%" valign="top">

### 🏗️ Operations & Storage
- 🗄️ **Memory / SQLite** (sync) + **Postgres async** storage
- 🔧 **Alembic migrations** scaffold
- 📊 **Prometheus** text exporter (counter-only, zero deps)
- 📜 **JSONL SIEM** event sink
- 🩺 **Health-check protocol** on every storage adapter
- ✅ **Secret-safe readiness CLI** for local/CI production checks
- 📬 **Email outbox + template preview** for dev SMTP-free testing
- 🔌 **Pluggable Protocols** (Storage / Email / RateLimiter / Vault / MetricSink)
- 🐘 **WAL + busy_timeout** on SQLite
- 👮 **RBAC** with owner/admin/moderator/author/viewer/user roles

</td>
</tr>
</table>

### 🧭 Included production-style web surfaces

The bundled SaaS demo is intentionally more than a login page. It is a complete
host-app reference showing how the module behaves in real application screens.

| Surface | Routes | Purpose |
|---|---|---|
| Auth flows | `/login`, `/signup`, `/magic-link/*`, `/password-reset/*`, `/social/*` | Email/password, signup, magic-link, reset, and Google/Facebook/OIDC connector wiring |
| Account center | `/account`, `/account/security`, `/account/sessions`, `/account/activity` | Personal profile, password change, MFA/security status, own session revoke, own activity |
| RBAC board | `/board`, `/board/new`, `/board/{id}` | Permission + ownership demo for author/moderator/admin paths |
| Admin console | `/admin`, `/admin/users/{id}`, `/admin/audit` | User counts, role distribution, user detail, disable/enable, password set, session revoke, audit filters |
| System console | `/system`, `/system/email` | Storage health, provider readiness, runbook, email outbox, template preview |

---

## 🚀 Quick Start

### Installation

```bash
# core install
uv add coreline-auth

# with Postgres async adapter
uv sync --extra postgres
```

### Minimal example (`single_owner` profile)

```python
from fastapi import FastAPI
from coreline_auth import (
    CorelineAuthConfig, CorelineAuthService,
    AuthProfile, CsrfProtector,
)
from coreline_auth.storage import SQLiteAuthStorage
from coreline_auth.fastapi_adapter import mount_auth_routes, mount_admin_routes

# 1) Wire storage + service
storage = SQLiteAuthStorage("/var/lib/coreline-auth/auth.sqlite3")
auth = CorelineAuthService(
    storage=storage,
    config=CorelineAuthConfig(
        profile=AuthProfile.SINGLE_OWNER,
        owner_email="owner@example.com",
        session_ttl_seconds=86400 * 7,
        revoke_sessions_on_password_change=True,
    ),
)
auth.bootstrap_owner(email="owner@example.com", password="change-me-strong-pw")

# 2) Mount routes (CSRF + admin)
app = FastAPI()
csrf = CsrfProtector(secret_key="<32+ char high-entropy secret>")
mount_auth_routes(app, auth, csrf_protector=csrf, secure_cookies=True)
mount_admin_routes(app, auth, csrf_protector=csrf)
```

### Multi-user RBAC profile

```python
from coreline_auth import CorelineAuthConfig, AuthProfile

config = CorelineAuthConfig(
    profile=AuthProfile.RBAC,
    require_email_verified=True,
    login_limit_per_minute=10,
    magic_link_limit_per_minute=5,
    session_touch_interval_seconds=60,  # write-throttle for read-heavy APIs
)
```

### Verify a session

```python
from coreline_auth.fastapi_adapter import require_session, require_permission
from fastapi import Depends

@app.get("/me", dependencies=[Depends(require_session(auth))])
def me(): ...

@app.post("/posts", dependencies=[Depends(require_permission(auth, "posts:write"))])
def create_post(): ...
```

<details>
<summary><b>Run the bundled demo SaaS app in 30 seconds</b></summary>

```bash
make run-demo
# → http://127.0.0.1:8010/login
# Default credentials (demo mode only):  owner@example.com / coreline-demo-password
```

</details>

---

## 🏛️ Architecture

```mermaid
flowchart TB
    Client[🌐 Browser / API Client]

    subgraph Adapter["FastAPI Adapter Layer"]
        Routes[mount_auth_routes / mount_admin_routes]
        CSRF[CsrfProtector · HMAC-SHA256]
        Cookie[Session cookie · Secure HttpOnly]
    end

    subgraph Service["CorelineAuthService · framework-agnostic"]
        Login[login_password / magic_link / oauth]
        Session[verify_session · issue_session · revoke]
        MFA[TOTP · recovery code · AAL2 step-up · WebAuthn]
        Admin[CorelineAdminService · RBAC enforcement]
        Audit[redacted metadata · size cap · sink fan-out]
    end

    subgraph Protocols["Pluggable Protocols"]
        Storage[(AuthStorage)]
        Email[EmailSender]
        Limiter[RateLimiter]
        Vault[MfaSecretVault]
        Metric[MetricSink]
    end

    subgraph Adapters["Production Adapters"]
        SQLite[SQLiteAuthStorage<br/>WAL · busy_timeout · RLock]
        Postgres[(AsyncPostgresAuthStorage<br/>SQLAlchemy + Alembic)]
        SMTP[SmtpEmailSender<br/>STARTTLS / SMTPS / SSLContext]
        Redis[(RedisFixedWindowRateLimiter<br/>atomic Lua)]
        AesVault[SQLiteMfaSecretVault<br/>AES-256-GCM + AAD]
        Prom[PrometheusTextMetricSink<br/>JsonLineSecurityEventSink]
    end

    Client --> Adapter
    Adapter --> Service
    Service --> Protocols
    Protocols -.-> Adapters

    style Service fill:#1f6feb,stroke:#0969da,color:#fff
    style Protocols fill:#8250df,stroke:#6e40c9,color:#fff
    style Adapters fill:#1a7f37,stroke:#1f883d,color:#fff
```

### Dependency direction

```
CoreMCP / your-app  ──▶  coreline_auth  ──▶  (Postgres / Redis / KMS · optional)
                                │
                                └──▶  argon2-cffi · cryptography · pydantic · httpx · fastapi
```

> ⛔ Coreline Auth **never** imports CoreMCP. Verified by a `grep` guard in `make test`.

### Internal module boundaries

| Area | Modules | Notes |
|---|---|---|
| Public facade | `service.py`, `async_service.py`, `admin.py` | Stable service APIs; internals delegate cross-cutting audit/rate-limit/email helpers to `service_support.py`. |
| Domain primitives | `models.py`, `errors.py`, `permissions.py`, `authorization.py` | Framework-free dataclasses, enums, policy checks. |
| Storage contracts | `storage/base.py`, `storage/protocols.py`, `storage/async_base.py`, `storage/async_protocols.py` | `AuthStorage` / `AsyncAuthStorage` remain the all-in-one public contracts; domain protocols document adapter responsibilities. |
| Storage adapters | `storage/memory.py`, `storage/sqlite.py`, `storage/postgres.py` | Embedded sync and production async implementations. |
| Social/OIDC | `social/{models,connectors,discovery,verification}.py` | Keeps `coreline_auth.social` import compatibility while avoiding a large single module. |
| Web adapters | `fastapi_adapter.py`, `fastapi_async_adapter.py` | Host-framework integration only; no storage-specific logic. |
| Demo app | `examples/saas_app.py`, `examples/saas_demo/*`, `examples/board_*` | Production-style self-test app; layout/config/CSRF and board domain are split from route wiring. |

### Recommended import policy

For application code, prefer stable top-level imports for core primitives:

```python
from coreline_auth import CorelineAuthConfig, CorelineAuthService, AuthProfile
from coreline_auth.storage import SQLiteAuthStorage
from coreline_auth.fastapi_adapter import mount_auth_routes
```

For specialized integrations, import from the domain package:

```python
from coreline_auth.social import GoogleOAuthConnector, verify_oidc_id_token
from coreline_auth.storage.protocols import SessionStore, AuditEventStore
```

The broad `coreline_auth.__init__` exports are kept for v0.x compatibility; new
code should use domain-specific paths when that makes ownership clearer.

---

## 🧩 API Surface

### Service-layer entry points

| Method | Returns | Notes |
|---|---|---|
| `bootstrap_owner(email, password=None)` | `AuthUser` | Idempotent owner setup for `single_owner` |
| `create_user(email, role, password, email_verified)` | `AuthUser` | RBAC user provisioning |
| `login_password(email, password, context=...)` | `IssuedSession` | Argon2id verify + dummy verify on miss |
| `request_magic_link(email, return_to)` | `MagicLinkChallenge` | Hash-only token storage |
| `consume_magic_link(token, context=...)` | `IssuedSession` | Atomic `WHERE consumed_at IS NULL` |
| `request_password_reset(email)` | `MagicLinkChallenge` | Dummy work on user-miss (timing safe) |
| `consume_password_reset(token, new_password)` | `AuthUser` | Revokes all sessions on success |
| `verify_session(token, required_permission=...)` | `Principal` | Touch throttling + permission check |
| `logout(token)` | `None` | Hash-only revocation |
| `begin_social_login(provider, return_to)` | `state` token | Provider-agnostic |
| `login_social(profile, state, context=...)` | `IssuedSession` | Verified-email-only linking |
| `begin_totp_enrollment(user_id)` | `(factor, secret)` | Vault stores raw secret encrypted |
| `verify_totp_enrollment(user_id, factor_id, code)` | `AuthMfaFactor` | One-time activation |
| `step_up_totp(session_token, code)` | `Principal` | Persists AAL2 in DB ✓ |
| `generate_recovery_codes(user_id, count=10)` | `list[str]` | Hash-only storage |
| `step_up_recovery_code(session_token, code)` | `Principal` | Atomic one-time recovery-code step-up |
| `require_aal2(session_token)` | `Principal` | Sensitive-action guard |
| `revoke_session(session_id, actor_user_id=...)` | `None` | Session revoke with audit |
| `list_audit_events(...)` | `list[AuditEvent]` | Action/actor/target/time range filters |
| `health_check()` | `None` | Delegates to storage adapter health check |

### Admin service entry points

| Method | Permission | Notes |
|---|---|---|
| `list_users(...)` | `users:read` | Query/status/role filters for admin dashboards |
| `update_user_role(...)` | `users:write` | Blocks self-demotion and last privileged lockout |
| `ban_user(...)` / `unban_user(...)` | `users:ban` | Reason metadata is audit-redacted/capped |
| `disable_user(...)` / `enable_user(...)` | `users:write` | Non-destructive lifecycle control |
| `set_user_password(...)` | `users:write` | Revokes existing sessions after password set |
| `list_sessions_for_user(...)` | `sessions:revoke` | Admin session visibility |
| `revoke_session(...)` | `sessions:revoke` | Targeted session revoke |

### Async service parity

`AsyncCorelineAuthService` exposes the production async subset used by the
Postgres adapter: password login, magic link, session verify/logout, audit list,
cleanup, best-effort email delivery, best-effort audit, and metric sink hooks.

### FastAPI adapter

```python
mount_auth_routes(app, auth, *,
    secure_cookies: bool = True,            # production default
    csrf_protector: CsrfProtector | None,
    csrf_cookie_samesite: str = "strict",
    expose_magic_link_token: bool = False,  # demo-only
)

mount_admin_routes(app, auth, *,
    csrf_protector: CsrfProtector | None,
)

# Dependency factories
require_session(auth) -> Callable
require_permission(auth, "users:read") -> Callable
```

<details>
<summary><b>Public symbols exported by <code>__init__.py</code></b></summary>

> 90 symbols including: `CorelineAuthService`, `CorelineAuthConfig`, `AuthStorage`, `AsyncAuthStorage`, `SQLiteAuthStorage`, `AsyncPostgresAuthStorage`, `MemoryAuthStorage`, `AsyncMemoryAuthStorage`, `CsrfProtector`, `SecretEnvelopeProtector`, `SQLiteMfaSecretVault`, `RedisMfaSecretVault`, `FixedWindowRateLimiter`, `RedisFixedWindowRateLimiter`, `MetricSink`, `InMemoryMetricSink`, `LoggingMetricSink`, `PrometheusTextMetricSink`, `JsonLineSecurityEventSink`, `GoogleOAuthConnector`, `FacebookOAuthConnector`, `GenericOIDCConnector`, `DevSocialConnector`, `verify_google_id_token`, `verify_oidc_id_token`, `verify_passkey_assertion_response`, `verify_passkey_registration_response`, `generate_webauthn_challenge`, `OAuthPKCE`, `JWKSCache`, `OIDCMetadataClient`, and the full RBAC primitive set.

</details>

---

## 🛡️ Security Primitives

| Primitive | Algorithm / Standard | Source |
|---|---|---|
| **Password hashing** | Argon2id (argon2-cffi default params) | [`security.py`](./src/coreline_auth/security.py) |
| **Opaque tokens** | `secrets.token_urlsafe(32)` (256 bits) — hash-only DB storage | [`security.py`](./src/coreline_auth/security.py) |
| **Session token storage** | SHA-256 hashed; raw token never persisted | [`models.py`](./src/coreline_auth/models.py) |
| **Magic-link / reset / verify tokens** | Hash-only with TTL + one-time atomic consume | [`service.py`](./src/coreline_auth/service.py) |
| **CSRF** | HMAC-SHA256, double-submit cookie + session-bound context | [`csrf.py`](./src/coreline_auth/csrf.py) |
| **MFA secret vault** | AES-256-GCM envelope, 12-byte nonce, AAD = factor_id | [`encryption.py`](./src/coreline_auth/encryption.py) |
| **TOTP** | RFC 6238 SHA-1, drift window=1, **counter replay reject** | [`mfa.py`](./src/coreline_auth/mfa.py) |
| **Recovery codes** | Hash-only, one-time, atomic `WHERE used_at IS NULL` | [`storage/sqlite.py`](./src/coreline_auth/storage/sqlite.py) |
| **OIDC ID token** | RS256, `iss` / `aud` / `exp` / `iat` / `nbf` / `azp` / `nonce` / `max_age` | [`social/verification.py`](./src/coreline_auth/social/verification.py) |
| **JWKS** | TTL cache + per-kid negative cache cooldown (anti-DoS) | [`social/discovery.py`](./src/coreline_auth/social/discovery.py) |
| **PKCE** | RFC 7636, S256, 64-byte verifier default | [`social/models.py`](./src/coreline_auth/social/models.py) |
| **WebAuthn** | rpIdHash + sign-counter replay + ECDSA-P256 / RSA PKCS1v15 | [`webauthn.py`](./src/coreline_auth/webauthn.py) |
| **Audit redaction** | key-name allowlist + max_keys=50 / max_str=1000 / max_depth=4 | [`storage/audit.py`](./src/coreline_auth/storage/audit.py) |
| **Readiness checks** | Secret-safe env readiness; no external connection by default | [`ops_readiness.py`](./src/coreline_auth/ops_readiness.py) |

### Threat model summary

<details>
<summary><b>What Coreline Auth protects against</b></summary>

- ✅ Brute-force password attacks (Argon2 + rate limit + dummy verify on miss)
- ✅ Account enumeration via login timing
- ✅ Account enumeration via password-reset timing
- ✅ Magic-link replay (one-time atomic consume)
- ✅ Recovery code replay (one-time atomic mark)
- ✅ TOTP code replay within 30s window (counter tracking)
- ✅ CSRF on cookie-backed POST flows (HMAC + session binding)
- ✅ Session fixation (token regenerated on login)
- ✅ Session hijack mitigation (Secure / HttpOnly / SameSite=Lax + ip/UA hash)
- ✅ OIDC `azp` confusion / `nbf` future / aged tokens
- ✅ JWKS kid-miss DoS amplification
- ✅ Encrypted-at-rest TOTP secrets (AES-GCM with AAD)
- ✅ Audit log secret leakage (metadata redaction)
- ✅ Last-admin lockout / self-ban
- ✅ Open redirect via `return_to` (same-origin only)
- ✅ WebAuthn signature counter replay

</details>

<details>
<summary><b>Out of scope (host responsibility)</b></summary>

- ❌ Browser attestation parsing (delegated to host or specialist library)
- ❌ PKCE verifier persistence (host stores in short-lived runtime state)
- ❌ Provider access/refresh token persistence (host opt-in via `ProviderTokenVault`)
- ❌ KMS / cloud secret management for master keys
- ❌ Tenant / organization / billing
- ❌ Email deliverability monitoring (host integrates with SES/Resend/SendGrid)

</details>

---

## 👮 Permission Model

```mermaid
flowchart LR
    subgraph Profile
        SO[single_owner] --> OWNER
        AV[admin_viewer] --> A1[OWNER + viewer-only]
        RB[rbac] --> ALL[OWNER · ADMIN · MODERATOR · AUTHOR · VIEWER · USER]
    end

    subgraph Permissions["Permission strings"]
        users_read["users:read"]
        users_write["users:write"]
        users_ban["users:ban"]
        sessions_revoke["sessions:revoke"]
        audit_read["audit:read"]
        posts_write["posts:write · scope:own"]
    end

    OWNER --> users_read & users_write & users_ban & sessions_revoke & audit_read
    ALL --> posts_write
```

| Role | Scope | Default permissions |
|---|---|---|
| **OWNER** | global | full admin + everything below |
| **ADMIN** | global | `users:read/write/ban` · `sessions:revoke` · `audit:read` |
| **MODERATOR** | global | `users:read` · `posts:moderate` |
| **AUTHOR** | own | `posts:write` |
| **VIEWER** | global | `posts:read` |
| **USER** | own | self-profile only |

→ See [`authorization.py`](./src/coreline_auth/authorization.py) for `ResourceAuthorizer` and scope evaluation (`own` vs `any`).

---

## 🚢 Production Deployment

### Storage adapters

<table>
<tr><th>Adapter</th><th>When to use</th><th>Notes</th></tr>
<tr>
<td><code>MemoryAuthStorage</code></td>
<td>Tests, ephemeral demos</td>
<td>Thread-safe via RLock</td>
</tr>
<tr>
<td><code>SQLiteAuthStorage</code></td>
<td>Single-node, personal SaaS, embedded</td>
<td>WAL · busy_timeout=5000ms · foreign_keys=ON · 8 indexes</td>
</tr>
<tr>
<td><code>AsyncPostgresAuthStorage</code></td>
<td>Multi-node, high-throughput SaaS</td>
<td>SQLAlchemy 2.0 async · asyncpg · Alembic schema</td>
</tr>
</table>

```bash
# Generate offline migration SQL (no DB required)
make postgres-migration-sql

# Smoke against an ephemeral Postgres container
make postgres-docker-smoke

# Real environment migration
CORELINE_AUTH_POSTGRES_DSN="postgresql+asyncpg://user:pass@host/db" \
  uv run --extra postgres alembic -c alembic.ini upgrade head
```

### Encrypted MFA vault

```python
from coreline_auth import SecretEnvelopeProtector, SQLiteMfaSecretVault

# Generate once; store outside the database (KMS / Secrets Manager / .env)
master_key = SecretEnvelopeProtector.generate_master_key()

protector = SecretEnvelopeProtector(master_key_b64=master_key)
vault = SQLiteMfaSecretVault(
    "/var/lib/coreline-auth/auth.sqlite3",
    protector=protector,
)
auth = CorelineAuthService(..., mfa_secret_vault=vault)
```

> 🔒 **AAD = `factor_id`** prevents copy-paste rebind attacks across factors.
> 🔄 **Versioned prefix** (`v1.aes256gcm.`) leaves room for future algorithm migration.

### Distributed rate limiting

```python
import redis
from coreline_auth import RedisFixedWindowRateLimiter

limiter = RedisFixedWindowRateLimiter(redis.Redis.from_url(os.environ["REDIS_URL"]))
auth = CorelineAuthService(..., rate_limiter=limiter)
```

> ⚡ Atomic Lua script — no TOCTOU races.
> 🔑 Keys are `hash_secret(raw_key)` — raw emails/IPs never leak into Redis key names.

### Observability sinks

```python
from coreline_auth import (
    PrometheusTextMetricSink,
    JsonLineSecurityEventSink,
    LoggingMetricSink,
)

# Option A — Prometheus counters exposed at /metrics
prom = PrometheusTextMetricSink(prefix="coreline_auth")
auth = CorelineAuthService(..., metric_sink=prom)

@app.get("/metrics")
def metrics():
    return Response(prom.render(), media_type="text/plain; version=0.0.4")

# Option B — SIEM forwarder (JSON lines)
siem = JsonLineSecurityEventSink("/var/log/coreline-auth/events.jsonl")
auth = CorelineAuthService(..., metric_sink=siem)

# Option C — structured logging via stdlib (works with structlog/loguru handlers)
auth = CorelineAuthService(..., metric_sink=LoggingMetricSink())
```

### SMTP & email providers

```python
from coreline_auth import SmtpEmailSender
import ssl

sender = SmtpEmailSender(
    host="smtp.example.com",
    port=465,                              # SMTPS
    username="auth@example.com",
    password=os.environ["SMTP_PASSWORD"],
    from_email="auth@example.com",
    base_url="https://auth.example.com",
    use_ssl=True,                          # SMTPS direct
    # use_tls=True,                        # STARTTLS alternative
    ssl_context=ssl.create_default_context(),
)
```

> Implement `EmailSender` Protocol to plug Resend / SES / SendGrid / Postmark / Mailgun.

### OAuth / OIDC providers

```python
from coreline_auth import (
    GoogleOAuthConnector,
    GenericOIDCConnector,
    OIDCMetadataClient,
    JWKSCache,
    verify_google_id_token,
)

# Google with hardened metadata client
metadata_client = OIDCMetadataClient(
    allowed_hosts={"accounts.google.com"},
    max_response_bytes=64 * 1024,
)
google = GoogleOAuthConnector.from_credentials(
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    redirect_uri="https://your.app/auth/social/google/callback",
)

# ID token verification (with kid-miss cooldown)
jwks_cache = JWKSCache(metadata_client, ttl_seconds=3600, kid_miss_refetch_cooldown_seconds=60)
profile = verify_google_id_token(
    id_token,
    audience=os.environ["GOOGLE_CLIENT_ID"],
    jwks=jwks_cache.get_jwks("https://www.googleapis.com/oauth2/v3/certs"),
    expected_nonce=flow_nonce,
    expected_azp=os.environ["GOOGLE_CLIENT_ID"],
    max_age_seconds=600,
)

# Generic OIDC via discovery
oidc = GenericOIDCConnector.from_issuer(
    provider="company-sso",
    issuer="https://sso.company.com",
    client_id="...", client_secret="...", redirect_uri="...",
    metadata_fetcher=metadata_client,
)
```

#### Demo Google/Facebook config

```bash
CORELINE_AUTH_GOOGLE_CLIENT_ID=... \
CORELINE_AUTH_GOOGLE_CLIENT_SECRET=... \
CORELINE_AUTH_FACEBOOK_CLIENT_ID=... \
CORELINE_AUTH_FACEBOOK_CLIENT_SECRET=... \
make run-demo
```

Callback URLs:

```
http://127.0.0.1:8010/social/google/callback
http://127.0.0.1:8010/social/facebook/callback
```

### Operational defaults

| Setting | Default | Notes |
|---|---|---|
| `secure_cookies` | `True` | **Local HTTP demos must opt out:** `mount_auth_routes(..., secure_cookies=False)` |
| `csrf_cookie_samesite` | `"strict"` | Cross-site SSO callback flows: evaluate `Lax` per-route |
| `session_touch_interval_seconds` | `60` | Set `300` for read-heavy APIs to reduce write pressure |
| `revoke_sessions_on_password_change` | `True` | All sessions terminated on password reset / admin set |
| Rate limiter | in-process | **Multi-worker:** swap in `RedisFixedWindowRateLimiter` |
| MFA secret vault | `InMemoryMfaSecretVault` | **Production:** `SQLiteMfaSecretVault` + envelope key from KMS |

→ Full release-gate checklist: [`docs/security-checklist.md`](./docs/security-checklist.md)

### Secret-safe readiness check

Use this before attaching the module to a real project or deployment. It checks
whether production integrations are configured without connecting to external
services and without printing secret values.

```bash
make readiness-check
uv run python -m coreline_auth.ops_readiness --json
```

| Area | Required variables | Output policy |
|---|---|---|
| Google OAuth | `CORELINE_AUTH_GOOGLE_CLIENT_ID`, `CORELINE_AUTH_GOOGLE_CLIENT_SECRET` | Ready/missing only |
| Facebook OAuth | `CORELINE_AUTH_FACEBOOK_CLIENT_ID`, `CORELINE_AUTH_FACEBOOK_CLIENT_SECRET` | Ready/missing only |
| SMTP | `CORELINE_AUTH_SMTP_HOST`, `CORELINE_AUTH_SMTP_FROM` | Host readiness only; no password output |
| Redis | `CORELINE_AUTH_REDIS_URL` | Presence check only |
| Postgres | `CORELINE_AUTH_POSTGRES_DSN` | Presence check only |
| WebAuthn | `CORELINE_AUTH_WEBAUTHN_RP_ID`, `CORELINE_AUTH_WEBAUTHN_ORIGIN` | Presence check only |

→ Full runbook: [`docs/ops-readiness.md`](./docs/ops-readiness.md)

---

## 📊 Reference Comparison

| Capability | **coreline-auth** | Authlib | FastAPI-Users | Lucia | Better Auth |
|---|:---:|:---:|:---:|:---:|:---:|
| Argon2id password + dummy verify | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ |
| Magic link (atomic one-time) | ✅ | ❌ | ⚠️ | ⚠️ | ✅ |
| OIDC `azp` + `nbf` + `max_age` + nonce | ✅ | ✅ | ❌ | ❌ | ⚠️ |
| JWKS kid-miss DoS cooldown | ✅ | ❌ | ❌ | ❌ | ❌ |
| TOTP counter replay reject | ✅ | ❌ | ❌ | ⚠️ | ⚠️ |
| Encrypted MFA vault (AAD-bound) | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| WebAuthn (registration + assertion) | ✅ | ❌ | ❌ | ⚠️ | ✅ |
| CSRF HMAC + session binding | ✅ | ❌ | ❌ | ⚠️ | ✅ |
| Distributed rate limit (Lua atomic) | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| Async + Postgres adapter | ✅ | N/A | ✅ | ✅ | ✅ |
| Health-check Protocol | ✅ | ❌ | ❌ | ❌ | ❌ |
| Audit (persistent + redacted + capped) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Prometheus + SIEM hooks | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| Zero host-project coupling | ✅ | ✅ | ✅ | ✅ | ✅ |

→ Full reference comparison: [`docs/reference-comparison.md`](./docs/reference-comparison.md)

---

## 🧪 Self-Test Webapp

A complete SaaS-style demo lives under [`src/coreline_auth/examples/`](./src/coreline_auth/examples/) — a single `uvicorn` command boots a working login/signup/board app exercising every primitive in the module.

```bash
make run-demo                # http://127.0.0.1:8010/login
make smoke-demo              # pytest-only smoke
make smoke-demo-secure       # production-mode smoke (CSRF + demo-off + audit redaction)
make readiness-check          # secret-safe production readiness config check
```

Demo mode seeds representative users so every permission path can be tested
without editing the database. The password is shared only in demo mode:

| Role | Example account | What to verify |
|---|---|---|
| Admin login | `owner@example.com` / `coreline-demo-password` | Admin dashboard, audit, system, user lifecycle |
| OWNER | `owner-board@example.com` / `coreline-demo-password` | Full board ownership permissions |
| ADMIN | `admin-board@example.com` / `coreline-demo-password` | Board-wide management paths |
| MODERATOR | `moderator-board@example.com` / `coreline-demo-password` | Moderate posts/comments without user admin |
| AUTHOR | `author-board@example.com` / `coreline-demo-password` | Own post/comment create/edit/delete |
| USER | `user-board@example.com` / `coreline-demo-password` | Basic board participation |
| VIEWER | `viewer-board@example.com` / `coreline-demo-password` | Read-only board and styled 403 for admin/system routes |

<table>
<tr><th>Flow</th><th>Endpoint</th><th>Notes</th></tr>
<tr><td>Email / password login</td><td><code>/login</code></td><td>Argon2id + dummy verify on miss</td></tr>
<tr><td>Sign-up</td><td><code>/signup</code></td><td>Email verification required (RBAC profile)</td></tr>
<tr><td>Magic link</td><td><code>/magic-link/request</code> · <code>/magic-link/consume</code></td><td>One-time atomic consume</td></tr>
<tr><td>Password reset</td><td><code>/password-reset/request</code> · <code>/password-reset/consume</code></td><td>Revokes sessions on success</td></tr>
<tr><td>Social login</td><td><code>/social/{provider}/start</code> · <code>/callback</code></td><td>Dev connector when credentials absent</td></tr>
<tr><td>Account self-service</td><td><code>/account</code> · <code>/account/security</code> · <code>/account/sessions</code> · <code>/account/activity</code></td><td>Profile, password change, MFA status, self session revoke, personal activity</td></tr>
<tr><td>Board (RBAC + ownership)</td><td><code>/board</code></td><td>Persistent SQLite + author scope</td></tr>
<tr><td>Admin dashboard</td><td><code>/admin</code> · <code>/admin/users/{id}</code></td><td>Role/status distribution, user detail, disable/enable, password set, session revoke</td></tr>
<tr><td>Audit viewer</td><td><code>/admin/audit</code></td><td>Requires <code>audit:read</code>; action/actor/target/time range filters</td></tr>
<tr><td>System health</td><td><code>/system</code></td><td>Storage health, provider readiness, runbook card</td></tr>
<tr><td>Email outbox</td><td><code>/system/email</code></td><td>Dev sender queue + template preview without external SMTP</td></tr>
</table>

→ Full guide: [`docs/self-test-webapp.md`](./docs/self-test-webapp.md)<br/>
→ Ops readiness: [`docs/ops-readiness.md`](./docs/ops-readiness.md)

### 🖼️ Demo screenshots

> **18 pages captured 2026-05-26** from `make run-demo` with `CORELINE_AUTH_DEMO_MODE=true`. Click any image to view full resolution.

#### 🔐 Authentication flows

<table>
<tr>
<td width="50%" align="center">
<a href="./docs/screenshots/01-login.png"><img src="./docs/screenshots/01-login.png" alt="Login page" width="100%"/></a>
<br/><sub><b>🔑 Login</b> · <code>/login</code> — Email/password + magic link + social + per-role test accounts</sub>
</td>
<td width="50%" align="center">
<a href="./docs/screenshots/02-signup.png"><img src="./docs/screenshots/02-signup.png" alt="Signup page" width="100%"/></a>
<br/><sub><b>📝 Signup</b> · <code>/signup</code> — RBAC user provisioning with email verification</sub>
</td>
</tr>
<tr>
<td width="50%" align="center">
<a href="./docs/screenshots/03-password-reset.png"><img src="./docs/screenshots/03-password-reset.png" alt="Password reset" width="100%"/></a>
<br/><sub><b>🔁 Password Reset</b> · <code>/password-reset</code> — Timing-safe (dummy verify on user-miss)</sub>
</td>
<td width="50%" align="center">
<a href="./docs/screenshots/04-magic-link-page.png"><img src="./docs/screenshots/04-magic-link-page.png" alt="Magic link consume" width="100%"/></a>
<br/><sub><b>✨ Magic Link</b> · <code>/magic-link/consume</code> — Atomic one-time token consume</sub>
</td>
</tr>
<tr>
<td width="50%" align="center" colspan="2">
<a href="./docs/screenshots/05-social-google-dev.png"><img src="./docs/screenshots/05-social-google-dev.png" alt="Social login" width="50%"/></a>
<br/><sub><b>🌐 Social Login (Google / OIDC)</b> · <code>/social/{provider}</code> — Real OAuth with credentials, deterministic dev connector without</sub>
</td>
</tr>
</table>

#### 🏠 Application & Board (RBAC)

<table>
<tr>
<td width="50%" align="center">
<a href="./docs/screenshots/06-dashboard.png"><img src="./docs/screenshots/06-dashboard.png" alt="Dashboard" width="100%"/></a>
<br/><sub><b>🏠 Dashboard</b> · <code>/</code> — Current session, role, permissions overview</sub>
</td>
<td width="50%" align="center">
<a href="./docs/screenshots/07-board-list.png"><img src="./docs/screenshots/07-board-list.png" alt="Board list" width="100%"/></a>
<br/><sub><b>📋 Board (RBAC + ownership)</b> · <code>/board</code> — Persistent SQLite + author/moderator scope</sub>
</td>
</tr>
<tr>
<td width="50%" align="center" colspan="2">
<a href="./docs/screenshots/08-board-new.png"><img src="./docs/screenshots/08-board-new.png" alt="New post" width="50%"/></a>
<br/><sub><b>✍️ New Post</b> · <code>/board/new</code> — Permission-gated write with CSRF token</sub>
</td>
</tr>
</table>

#### 👤 Self-service account UX

<table>
<tr>
<td width="50%" align="center">
<a href="./docs/screenshots/09-account-profile.png"><img src="./docs/screenshots/09-account-profile.png" alt="Account profile" width="100%"/></a>
<br/><sub><b>👤 Profile</b> · <code>/account</code> — Display name + identity providers + email verification status</sub>
</td>
<td width="50%" align="center">
<a href="./docs/screenshots/10-account-security.png"><img src="./docs/screenshots/10-account-security.png" alt="Account security" width="100%"/></a>
<br/><sub><b>🔒 Security</b> · <code>/account/security</code> — Self-serve password change with current-password verification</sub>
</td>
</tr>
<tr>
<td width="50%" align="center">
<a href="./docs/screenshots/11-account-sessions.png"><img src="./docs/screenshots/11-account-sessions.png" alt="Account sessions" width="100%"/></a>
<br/><sub><b>📱 Sessions</b> · <code>/account/sessions</code> — Active sessions list with IP/UA hash + per-row revoke</sub>
</td>
<td width="50%" align="center">
<a href="./docs/screenshots/12-account-activity.png"><img src="./docs/screenshots/12-account-activity.png" alt="Account activity" width="100%"/></a>
<br/><sub><b>📒 Activity</b> · <code>/account/activity</code> — Self-readable audit feed (filtered to actor)</sub>
</td>
</tr>
</table>

#### 👮 Admin & Operations

<table>
<tr>
<td width="50%" align="center">
<a href="./docs/screenshots/13-admin-users.png"><img src="./docs/screenshots/13-admin-users.png" alt="Admin users" width="100%"/></a>
<br/><sub><b>👮 User Management</b> · <code>/admin</code> — Role update, ban/unban, disable, session revoke · last-owner lockout protected</sub>
</td>
<td width="50%" align="center">
<a href="./docs/screenshots/14-admin-user-detail.png"><img src="./docs/screenshots/14-admin-user-detail.png" alt="Admin user detail" width="100%"/></a>
<br/><sub><b>🔍 User Detail</b> · <code>/admin/users/{id}</code> — Identities, sessions, recent audit, password set</sub>
</td>
</tr>
<tr>
<td width="50%" align="center">
<a href="./docs/screenshots/15-admin-audit.png"><img src="./docs/screenshots/15-admin-audit.png" alt="Audit viewer" width="100%"/></a>
<br/><sub><b>📜 Audit Viewer</b> · <code>/admin/audit</code> — Persistent audit · <code>audit:read</code> required · metadata redacted</sub>
</td>
<td width="50%" align="center">
<a href="./docs/screenshots/16-system-readiness.png"><img src="./docs/screenshots/16-system-readiness.png" alt="System readiness" width="100%"/></a>
<br/><sub><b>🩺 Readiness</b> · <code>/system</code> — Secret-safe env check (Google / SMTP / Redis / Postgres / WebAuthn)</sub>
</td>
</tr>
<tr>
<td width="50%" align="center">
<a href="./docs/screenshots/17-system-email.png"><img src="./docs/screenshots/17-system-email.png" alt="System email" width="100%"/></a>
<br/><sub><b>📧 Email Preview</b> · <code>/system/email</code> — Template render check (magic / verify / reset bodies)</sub>
</td>
<td width="50%" align="center">
<a href="./docs/screenshots/18-logout.png"><img src="./docs/screenshots/18-logout.png" alt="Logout" width="100%"/></a>
<br/><sub><b>🚪 Logout</b> · <code>/logout</code> — Session token revoked + cookie cleared</sub>
</td>
</tr>
</table>

> 💡 **Regenerate screenshots:** boot the demo (`make run-demo`, port 8010), then drive a headless browser through the route list. Login + admin pages need owner credentials; `/account/*` pages need any active session.

---

## 🧬 Testing

```bash
cd packages/coreline-auth

# Full test suite (149 tests, ~17s)
make test

# Direct invocations
uv run pytest -q
uv run python -c "import coreline_auth"

# Independence guard
! grep -RIn "CoreMCP\|coremcp" src/coreline_auth

# Secret leak guard
make secret-grep

# Postgres integration (requires container)
make postgres-docker-smoke
```

| Suite | Coverage |
|---|---|
| `test_core_auth.py` | login / magic-link / verify / revoke / RBAC |
| `test_fastapi_adapter.py` | CSRF / cookies / bearer / opt-out |
| `test_admin_api.py` | RBAC admin · last-owner · audit pagination |
| `test_social_connectors.py` | Google / Facebook / OIDC discovery |
| `test_id_token_verification.py` | RS256 + azp + nbf + max_age + nonce |
| `test_mfa_groundwork.py` | TOTP enroll / verify / recovery / AAL2 |
| `test_webauthn.py` | Passkey challenge / assertion / sign counter |
| `test_production_adapters.py` | AES-GCM / Redis Lua / encrypted vault |
| `test_observability.py` | Prometheus / JSONL / metric sinks |
| `test_async_service.py` | Async service layer parity |
| `test_postgres_storage.py` | SQLAlchemy async + Alembic |
| `test_release_blockers_r5.py` | **R5 regression** — AAL2 round-trip + concurrent consume races |
| `test_demo_webapp.py` | SaaS demo flows — account/admin/system/email/dashboard UX |
| `test_demo_config.py` | Demo config safety defaults |
| `test_ops_readiness.py` | Secret-safe readiness CLI/output |

---

## 🗺️ Roadmap

| Version | Status | Highlights |
|---|---|---|
| **v0.4** | ✅ Shipped | Initial core + RBAC board demo + admin/OIDC/MFA groundwork |
| **v0.5.0-rc1** | ✅ Shipped | CSRF · OIDC `azp/nbf/max_age` · TOTP/AAL2 · audit redaction · production hardening |
| **v0.5.0-rc2** | 🟡 Current | Account center · admin user detail · system/email console · readiness CLI · async hardening |
| **v0.5.0 GA** | 🔜 Next | External SMTP/OAuth/Postgres/Redis/WebAuthn smoke + docs polish |
| **v0.6** | 🧭 Designed | Deeper async parity · provider token vault workflows · external integration hardening |
| **v0.7** | 🌟 Candidate | Risk-based auth · device fingerprint AAL2 escalation · async email providers |
| **v1.0** | 🎯 Target | API stability commitment · SemVer guarantee · namespaced exports |

→ Detailed roadmap: [`docs/production-roadblocks-roadmap.md`](./docs/production-roadblocks-roadmap.md)

---

## 📚 Documentation

<table>
<tr><th>📁 Topic</th><th>📄 Document</th></tr>
<tr><td><strong>Security gate</strong></td><td><a href="./docs/security-checklist.md">security-checklist.md</a></td></tr>
<tr><td><strong>Performance gate</strong></td><td><a href="./docs/performance-checklist.md">performance-checklist.md</a></td></tr>
<tr><td><strong>Production roadmap</strong></td><td><a href="./docs/production-roadblocks-roadmap.md">production-roadblocks-roadmap.md</a></td></tr>
<tr><td><strong>Production hardening review</strong></td><td><a href="./docs/production-hardening-review-20260524.md">production-hardening-review-20260524.md</a></td></tr>
<tr><td><strong>Reference comparison</strong></td><td><a href="./docs/reference-comparison.md">reference-comparison.md</a></td></tr>
<tr><td><strong>Self-test webapp guide</strong></td><td><a href="./docs/self-test-webapp.md">self-test-webapp.md</a></td></tr>
<tr><td><strong>Ops readiness runbook</strong></td><td><a href="./docs/ops-readiness.md">ops-readiness.md</a></td></tr>
<tr><td><strong>MFA / passkey scope</strong></td><td><a href="./docs/mfa-passkey-scope.md">mfa-passkey-scope.md</a></td></tr>
<tr><td><strong>OIDC real-provider smoke</strong></td><td><a href="./docs/oidc-real-provider-smoke.md">oidc-real-provider-smoke.md</a></td></tr>
<tr><td><strong>SQLite migration checklist</strong></td><td><a href="./docs/migration-checklist.md">migration-checklist.md</a></td></tr>
<tr><td><strong>Advanced production review</strong></td><td><a href="./docs/advanced-production-review.md">advanced-production-review.md</a></td></tr>
<tr><td><strong>v0.1 gap review</strong></td><td><a href="./docs/v0.1-gap-review.md">v0.1-gap-review.md</a></td></tr>
<tr><td><strong>Dev plans (history)</strong></td><td><a href="./dev-plan/">dev-plan/</a></td></tr>
<tr><td><strong>Changelog</strong></td><td><a href="./CHANGELOG.md">CHANGELOG.md</a></td></tr>
</table>

---

## 🧱 Independence Principles

1. 🚫 `src/coreline_auth/` **never** imports `coremcp` or `apps.api.coremcp`. Enforced by `make import-guard`.
2. 🔁 Dependency direction is unidirectional: `CoreMCP → coreline_auth`. The reverse is a hard violation.
3. 🧪 Every storage / vault / limiter / email / metric adapter is a **Protocol** — host applications can substitute their own.
4. 🔑 Coreline Auth **does not store** provider access/refresh tokens or PKCE verifiers by default. Hosts opt into persistence via `ProviderTokenVault`.
5. 🛡️ Demo-only features (`expose_magic_link_token=True`, default demo password) are gated by `CORELINE_AUTH_DEMO_MODE=true` and refused otherwise.

---

## 📦 Project Stats

```
Source:     ~5,800 LOC across 39 modules (excluding examples)
Tests:      149 passed · 1 skipped (external dep) · 22 test files
Reviews:    6 expert review rounds — see dev-plan/ for receipts
Coupling:   0 imports of host project (CoreMCP)
Deps:       argon2-cffi · cryptography · fastapi · pydantic · httpx · email-validator
Optional:   sqlalchemy[asyncio] · asyncpg · alembic (Postgres extra)
Python:     3.12
```

---

## 📄 License

MIT License. See [`LICENSE`](./LICENSE) and [`SECURITY.md`](./SECURITY.md).

---

<div align="center">

**Built with** ☕ **and 6 rounds of microscope review.**

[⬆ Back to top](#-coreline-auth)

</div>
