# Coreline Auth Performance Checklist

## SQLite profile

- `SQLiteAuthStorage` enables `foreign_keys=ON`, `busy_timeout=5000`, and WAL for file-backed DBs.
- Auth/session/login-flow lookup indexes are created during bootstrap.
- SQLite auth and board storages use `threading.RLock` around connection access.
- `verify_session()` throttles `last_seen_at` writes with `session_touch_interval_seconds`.
- `cleanup_expired()` revokes expired sessions and removes expired login flows.
- Admin user listing supports storage-level filtering and pagination.
- `FixedWindowRateLimiter` cleans expired buckets and caps bucket count.

## Recommended defaults

- Keep `session_touch_interval_seconds >= 60` for normal web traffic.
- Run `cleanup_expired()` from the host app on a periodic timer.
- Use SQLite for small single-process deployments; add a dedicated adapter for multi-process/high-write deployments.
