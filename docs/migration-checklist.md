# Coreline Auth Migration Compatibility Checklist

Before upgrading an existing Coreline Auth SQLite DB:

1. Back up the DB file.
2. Start the module once in a staging copy so `bootstrap()` can create missing tables/indexes.
3. Verify required tables exist: `auth_users`, `auth_sessions`, `auth_login_flows`, `auth_audit_events`, `auth_mfa_factors`, `auth_recovery_codes`.
4. Verify legacy `auth_sessions` has `assurance_level` after bootstrap.
5. Run `cd packages/coreline-auth && make test`.
6. Run the host app login/logout/password reset smoke.

Rollback: restore the DB backup and previous package version.
