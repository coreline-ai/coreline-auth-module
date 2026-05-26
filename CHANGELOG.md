# Changelog

## v0.5.0-rc2 — 2026-05-26

- Added account self-service pages for profile, security, sessions, and activity.
- Added admin user detail lifecycle actions, system health, email outbox, and provider readiness UI.
- Added secret-safe `coreline_auth.ops_readiness` CLI and `make readiness-check`.
- Added audit filtering, expanded demo tests, and updated operational docs.
- Hardened async service parity so email/audit sink failures are best-effort and observable.

## v0.5.0-rc1 — 2026-05-24

- Added CSRF integration for cookie-backed FastAPI/demo flows.
- Hardened social account linking to verified-email fallback only.
- Added session revocation after password reset/admin password changes.
- Added login timing dummy Argon2 verification.
- Added SQLite WAL/busy-timeout/index/session-touch hardening.
- Added hardened OIDC metadata client, JWKS TTL cache, azp/nbf/max-age ID token checks.
- Added persistent audit storage, admin audit API, metadata redaction.
- Added TOTP/AAL2 foundation and one-time recovery codes.
