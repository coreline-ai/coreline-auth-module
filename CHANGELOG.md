# Changelog

## v0.5.0-rc1 — 2026-05-24

- Added CSRF integration for cookie-backed FastAPI/demo flows.
- Hardened social account linking to verified-email fallback only.
- Added session revocation after password reset/admin password changes.
- Added login timing dummy Argon2 verification.
- Added SQLite WAL/busy-timeout/index/session-touch hardening.
- Added hardened OIDC metadata client, JWKS TTL cache, azp/nbf/max-age ID token checks.
- Added persistent audit storage, admin audit API, metadata redaction.
- Added TOTP/AAL2 foundation and one-time recovery codes.
