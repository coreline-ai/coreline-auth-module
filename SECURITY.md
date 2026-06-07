# Security Policy

Coreline Auth is an independent authentication, authorization, session, MFA, OAuth/OIDC, and admin-core module intended for reuse across Coreline projects.

Coreline Auth는 CoreMCP와 독립적으로 동작하는 인증/인가/세션/MFA/OAuth/OIDC/관리자 코어 모듈입니다. 이 문서는 `coreline-auth-module` 저장소 기준의 보안 정책입니다.

---

## Supported Scope

| Area | Status | Security support |
|---|---:|---|
| `main` branch | Active | Yes |
| `v0.5.x` release candidates | Active | Yes, best effort until GA |
| Demo SaaS app under `src/coreline_auth/examples/` | Demo/self-test | Best effort |
| Local development mode | Development only | Best effort |
| Historical dev-plan documents | Reference | No runtime support |

If a report affects a specific release candidate, include the exact commit SHA, tag, or package version.

---

## Reporting a Vulnerability

Please do **not** open a public issue with exploit details, live tokens, screenshots containing credentials, private URLs, or full logs.

Preferred reporting path:

1. Use GitHub **Private vulnerability reporting / Security Advisory** for this repository if available.
2. If private reporting is unavailable, contact the repository owner privately and open only a minimal public issue such as “Security report available privately”.
3. Include impact, reproduction steps, affected version/commit, environment, and a suggested mitigation if known.

Recommended report template:

```text
Title:
Affected version or commit:
Severity estimate: Critical / High / Medium / Low
Affected area: password/session/CSRF/OAuth/OIDC/MFA/admin/storage/demo/adapter
Environment: OS, Python version, storage backend, FastAPI deployment mode
Summary:
Reproduction steps:
Expected result:
Actual result:
Impact:
Logs or screenshots: redact all tokens/secrets
Suggested mitigation:
```

We prioritize reports that affect session integrity, account takeover, token leakage, MFA bypass, CSRF bypass, OAuth/OIDC verification, admin authorization, storage confidentiality, and production deployment safety.

---

## Never Send Raw Secrets

Always redact these values before reporting:

- Session tokens and cookie values
- Password reset tokens
- Magic-link tokens
- Email verification tokens
- OAuth authorization codes, access tokens, refresh tokens, and ID tokens
- OIDC client secrets
- CSRF cookies and CSRF form/header tokens
- TOTP seeds, MFA enrollment secrets, and recovery codes
- AES/envelope encryption master keys
- SMTP credentials
- Redis/Postgres connection strings containing credentials
- Demo admin passwords if changed from local defaults

Use placeholders such as `<redacted-session-token>` or `<redacted-client-secret>`.

---

## Security Model

Coreline Auth is designed as a reusable module with secure-by-default primitives and explicit production hardening gates.

Core expectations:

- Passwords are hashed with Argon2.
- Session, reset, magic-link, verification, and recovery tokens are stored hash-only.
- Browser form flows use CSRF protection.
- CSRF verification uses constant-time comparison.
- CSRF tokens are bound to session context where applicable.
- Password reset and admin password changes revoke existing sessions.
- Login failure paths perform dummy password verification to reduce timing enumeration.
- OAuth/OIDC verification checks issuer, audience, `azp`, `nbf`, max age, nonce policy, and JWKS constraints.
- MFA/TOTP recovery codes are one-time and hash-only.
- Sensitive metadata is redacted before audit output.
- Demo mode is for local development and self-test only.

Detailed module gates:

- [`docs/security-checklist.md`](./docs/security-checklist.md)
- [`docs/production-hardening-review-20260524.md`](./docs/production-hardening-review-20260524.md)
- [`docs/production-roadblocks-roadmap.md`](./docs/production-roadblocks-roadmap.md)
- [`docs/performance-checklist.md`](./docs/performance-checklist.md)

---

## Production Deployment Checklist

Before production use:

- Use HTTPS only.
- Keep `secure_cookies=True` in production.
- Use strong, unique secrets for CSRF, encryption, OIDC, SMTP, and storage credentials.
- Disable or tightly control demo mode.
- Configure trusted OAuth/OIDC redirect URIs exactly.
- Use production SMTP or an async email sender with failure monitoring.
- Use Postgres/Redis adapters for multi-process or horizontally scaled deployments.
- Confirm rate limiting is shared across workers when deployed with more than one process.
- Confirm storage backups protect encrypted fields and key material separately.
- Run the full test suite and production smoke checklist before release.

Recommended commands:

```bash
make test
make smoke-demo-secure
```

For local HTTP development, explicitly configure development settings rather than weakening production defaults.

---

## Demo App Safety Notes

The included SaaS demo app is intended for local validation of login, signup, social login simulation, admin controls, audit viewer, account self-service, system readiness, and email outbox flows.

Demo-specific behavior is **not** a production recommendation:

- Local default accounts and passwords are for testing only.
- Development social connector simulates Google/Facebook login only when real provider credentials are absent.
- Demo database files under `.coreline-auth-demo/` must not be committed or deployed.
- Local `secure_cookies=False` is acceptable only for HTTP localhost testing.

---

## Out of Scope / Usually Not a Vulnerability

The following are generally not considered vulnerabilities by themselves unless they can be chained to meaningful impact:

- Missing tenant/organization features in the standalone module.
- Missing enterprise SSO connectors beyond documented OAuth/OIDC support.
- Demo mode exposing local test credentials on localhost.
- In-memory adapters being unsuitable for multi-worker production when documentation states this limitation.
- Rate limiting not being distributed when using the in-memory limiter intentionally.
- Reports requiring a fully compromised host or database without crossing an additional security boundary.

Still report suspicious behavior if it affects the security model above.

---

## Dependency and Supply Chain Notes

- Review new dependencies carefully, especially auth, crypto, OAuth/OIDC, SMTP, Redis, and database libraries.
- Prefer lockfile-based reproducible installs.
- Avoid adding external network dependencies to core auth paths unless they are explicit adapters.
- Keep provider-specific OAuth/OIDC logic isolated behind connector/verifier modules.

---

## Disclosure and Fix Process

Typical handling flow:

1. Triage and reproduce locally.
2. Classify severity and affected scope.
3. Patch with regression tests.
4. Run module tests and relevant demo smoke checks.
5. Update release notes or advisory text without prematurely exposing exploit details.
6. Credit the reporter if they want attribution.

Thank you for helping keep Coreline Auth safe.
