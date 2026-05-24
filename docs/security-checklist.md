# Coreline Auth Security Checklist

## Release gate

- CSRF is enabled for cookie-backed browser POST flows.
- Bearer JSON API clients can opt out of CSRF because they do not rely on ambient cookies.
- Password login runs a dummy Argon2 verify for missing users/credentials.
- Password reset and admin password set revoke existing sessions.
- Social linking falls back to email only when provider email is verified.
- Demo owner password and debug magic/reset tokens are shown only with `CORELINE_AUTH_DEMO_MODE=true`.
- Audit viewer requires `audit:read`.
- Audit metadata redacts token/password/secret/credential/authorization keys.
- Provider access/refresh/id tokens are not stored by default.
- TOTP seeds must be stored through a host-provided encrypted `MfaSecretVault` in production.

## v0.5.0rc1 follow-up hardening

- CSRF double-submit cookie/header comparison uses constant-time comparison.
- Cookie-backed CSRF tokens are session-bound after login and anonymous-only before login.
- Auth adapter cookies default to `Secure`; local demos explicitly opt out for HTTP localhost.
- Password reset requests run dummy password-verification work for unknown/inactive users to reduce timing-based email enumeration.
- SMTP sender uses an explicit `ssl.create_default_context()` for STARTTLS and supports direct SMTPS.
- Admin APIs block self-ban and last active owner/admin lockout.
- ID token verification rejects unexpected nonce claims when no nonce was requested.
- Audit metadata is redacted and capped for key count, string length, list length, and nesting depth.

## Remaining medium-risk items resolved

- The unused `pkce_verifier_encrypted` schema/model field was removed. PKCE verifiers remain host-managed runtime material and are not persisted by Coreline Auth.
- `CsrfProtector` rejects obviously weak static secrets by default; local demos/tests must opt in with `allow_weak_dev_secret=True`.
- The built-in fixed-window rate limiter is explicitly process-local and conforms to a pluggable `RateLimiter` protocol for shared production implementations.

## Operational notes

- `secure_cookies=True` is the production default. Local HTTP demos must explicitly pass `secure_cookies=False`; otherwise modern browsers will drop Secure cookies on `http://localhost`.
- CSRF cookies currently use `SameSite=Strict` in the FastAPI adapter. This is correct for same-site form POST flows. If a future browser SSO flow needs the CSRF cookie on a cross-site callback, evaluate a dedicated callback cookie or `SameSite=Lax` for that flow only.
- The bundled fixed-window limiter is process-local. Multi-worker or multi-host deployments must provide a shared adapter such as Redis to enforce limits consistently across workers.

## Production adapter checks

- Use `SQLiteMfaSecretVault` or a host-managed encrypted `MfaSecretVault` for TOTP in production; do not rely on `InMemoryMfaSecretVault` outside development.
- Store `SecretEnvelopeProtector` master keys outside the database and rotate through a host-managed procedure.
- Use `RedisFixedWindowRateLimiter` or an equivalent shared `RateLimiter` for multi-worker/multi-node deployments.
- Keep `session_touch_interval_seconds` above zero for high-throughput read-heavy APIs to avoid turning every session verification into a database write.

## Pre-production checks

```bash
cd packages/coreline-auth
make test
make smoke-demo-secure
! grep -RIn "CoreMCP\|coremcp" src/coreline_auth
```
