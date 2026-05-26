# Coreline Auth Ops Readiness

Coreline Auth can check production-readiness configuration without printing secrets or requiring external services.

## Local check

```bash
cd packages/coreline-auth
make readiness-check
uv run python -m coreline_auth.ops_readiness --json
```

The output contains only variable names and readiness states. It never prints client secrets, passwords, tokens, DSNs, or SMTP credentials.

## Readiness variables

| Area | Variables | Meaning |
|---|---|---|
| Google OAuth | `CORELINE_AUTH_GOOGLE_CLIENT_ID`, `CORELINE_AUTH_GOOGLE_CLIENT_SECRET` | Enables real Google OAuth redirect/callback when registered with the correct callback URL. |
| Facebook OAuth | `CORELINE_AUTH_FACEBOOK_CLIENT_ID`, `CORELINE_AUTH_FACEBOOK_CLIENT_SECRET` | Enables real Facebook OAuth redirect/callback when registered with Meta. |
| SMTP | `CORELINE_AUTH_SMTP_HOST`, `CORELINE_AUTH_SMTP_FROM` | Indicates an SMTP sender can be configured. Username/password may be optional depending on the server. |
| Redis | `CORELINE_AUTH_REDIS_URL` | Required for shared rate limit state in multi-worker/multi-node deployments. |
| Postgres | `CORELINE_AUTH_POSTGRES_DSN` | Required for async Postgres storage and production migrations. |
| WebAuthn | `CORELINE_AUTH_WEBAUTHN_RP_ID`, `CORELINE_AUTH_WEBAUTHN_ORIGIN` | Required for host-side browser passkey ceremony. Core verification primitives are already included. |

## What this does not do

- It does not send an SMTP email.
- It does not complete Google/Facebook OAuth login.
- It does not connect to Redis or Postgres by default.
- It does not implement browser-specific passkey attestation parsing for the host app.

Those checks need the real deployment environment. The readiness check verifies that local configuration is complete enough to attempt them safely.
