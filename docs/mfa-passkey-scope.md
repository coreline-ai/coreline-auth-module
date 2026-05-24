# MFA / Passkey Scope Note

Coreline Auth v0.5 foundation includes working TOTP enrollment/verification, one-time recovery codes, and AAL2 session step-up guards.

## Implemented now

- TOTP secret generation and verification using RFC 6238-compatible HMAC-SHA1 codes.
- TOTP enrollment is pending until the first valid code is provided.
- Session step-up upgrades `AuthSession.assurance_level` from `aal1` to `aal2`.
- Recovery codes are stored hash-only and become invalid after first use.
- `require_aal2()` can protect sensitive service actions.
- Passkey dataclasses/challenge contracts remain available for future WebAuthn integration.

## Production secret policy

TOTP verification requires access to the TOTP seed. Coreline Auth therefore uses a `MfaSecretVault` interface. The bundled `InMemoryMfaSecretVault` is for tests/demo only. Production hosts should provide an encrypted vault implementation and keep raw TOTP seeds out of SQL and logs.

## Deferred passkey work

Full WebAuthn/passkey requires browser challenge ceremony, origin/RP ID verification, attestation policy, counter checks, and credential persistence. That is intentionally split into a later dedicated phase.
