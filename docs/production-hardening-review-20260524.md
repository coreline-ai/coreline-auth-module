# Coreline Auth Production Hardening Review — 2026-05-24

작성 일시: `2026-05-24 08:52:12 KST`

이 문서는 `packages/coreline-auth`를 독립 인증 모듈로 프로덕션화하기 위해 보안, 성능, 운영, 추가 기능 관점에서 다시 점검한 전문가 리뷰다. CoreMCP 본체에 흡수하지 않고, Coreline Auth 자체 폴더와 개발 계획에서 관리한다.

## 0. 종합 결론

Coreline Auth v0.4는 이미 독립 패키지, email/password, magic link, password reset, social/OIDC connector, JWKS 검증 helper, RBAC board demo, admin API/UI, audit demo, SQLite storage를 갖췄다. 다만 “실제 SaaS 인증 core”로 배포하려면 아래 항목이 release gate다.

| 영역 | 현재 판단 | 프로덕션 전 필수 보강 |
|---|---|---|
| 인증 core | B+ | password reset/admin password 변경 시 세션 revoke, login timing hardening |
| Cookie web auth | B- | CSRF 적용, secure cookie profile, demo debug token guard |
| Social/OIDC | B | verified email linking policy, JWKS fetch/cache/SSRF guard, `azp`/`nbf`/max age 검증 |
| Storage/성능 | B- | session touch write-throttle, SQLite WAL/busy_timeout/lock, pagination/index |
| Email | B | SMTP TLS context, template escaping, 운영용 debug token 차단 |
| MFA/passkey | C | 모델만 있음. TOTP/recovery/AAL2 enforcement 필요 |
| Admin/audit | B | persistent audit table, `audit:read` 권한 분리, 필터/pagination |

## 1. High Priority 보안 발견사항

### H-1. Cookie 기반 state-changing route에 CSRF enforcement가 아직 연결되지 않음

- 위치: `src/coreline_auth/fastapi_adapter.py:60-154`, `src/coreline_auth/examples/saas_app.py:168-347`, `src/coreline_auth/csrf.py:22-42`
- 근거: `CsrfProtector`는 존재하지만 `/login`, `/logout`, `/password-reset/*`, admin/board POST route에 dependency 또는 hidden token 검증으로 연결되어 있지 않다.
- 영향: 같은 브라우저 cookie가 자동 첨부되는 구조에서 state-changing POST가 CSRF 위험을 가진다. `SameSite=Lax`는 방어에 도움은 되지만 명시적 CSRF token 대체로 보기는 어렵다.
- 권고: `mount_auth_routes(..., csrf_protector=...)`, demo form hidden token, `X-CSRF-Token` JSON adapter 지원. Bearer-only API는 opt-out 가능하게 분리.

### H-2. Social login email fallback linking이 `email_verified=False`에도 기존 계정에 붙을 수 있음

- 위치: `src/coreline_auth/service.py:280-287`
- 근거: provider identity가 없으면 `profile.email`만으로 기존 사용자를 조회하고 identity를 연결한다. `profile.email_verified` 조건이 없다.
- 영향: provider가 검증되지 않은 email을 반환하거나 connector 구현이 느슨하면 기존 계정 탈취 경로가 될 수 있다.
- 권고: provider subject 우선. email fallback은 `profile.email_verified is True`이고 명시 정책이 `verified_email_linking`일 때만 허용. 미검증 email은 신규 pending user 생성 또는 reject.

### H-3. Password reset / admin password set 이후 기존 세션이 유지됨

- 위치: `src/coreline_auth/service.py:227-247`, `src/coreline_auth/admin.py:65-69`
- 근거: `consume_password_reset()`은 `set_password()` 후 해당 user의 세션을 revoke하지 않는다. admin password set도 동일하다.
- 영향: 탈취된 세션이 비밀번호 변경 이후에도 살아 있을 수 있다.
- 권고: `revoke_sessions_for_user(user_id, except_session_id=None)` storage API 추가. password reset/admin password set 후 전체 세션 revoke. 감사 이벤트 기록.

### H-4. 로그인 실패 타이밍이 계정 존재 여부를 노출할 수 있음

- 위치: `src/coreline_auth/service.py:113-124`
- 근거: user 없음/비활성은 Argon2 verify 없이 즉시 실패하고, password mismatch는 Argon2 verify 비용이 발생한다.
- 영향: 고해상도 timing 공격으로 email enumeration 보조 신호가 될 수 있다.
- 권고: module startup 시 dummy Argon2 hash를 생성하고 user 없음/credential 없음에도 dummy verify를 수행한다.

### H-5. Demo app이 운영 설정으로 오해될 경우 debug token/password 노출 위험

- 위치: `src/coreline_auth/examples/saas_app.py:47`, `:122-130`, `:263-268`
- 근거: `mount_auth_routes(..., expose_magic_link_token=True)`, login page에 기본 owner password 표시, magic/reset token 링크 표시.
- 영향: 데모 편의 기능이 production deployment로 잘못 배포되면 즉시 계정 탈취 위험.
- 권고: `CORELINE_AUTH_DEMO_MODE=true`가 명시될 때만 debug token/password 표시. false일 때는 앱 시작 실패 또는 숨김.

## 2. Medium Priority 보안/운영 발견사항

### M-1. OIDC discovery 기본 fetcher가 SSRF/size/cache guard 없이 `httpx.get`을 사용

- 위치: `src/coreline_auth/social.py:154-174`
- 근거: fetcher 주입은 가능하지만 기본 경로는 URL policy, response size cap, cache TTL이 없다.
- 권고: `OIDCMetadataClient` 추가. https-only, localhost dev 예외, max bytes, content-type, timeout, cache TTL, allowed issuer host option.

### M-2. ID token 검증이 `azp`, `nbf`, max token age 검증을 아직 포함하지 않음

- 위치: `src/coreline_auth/social.py:588-655`
- 근거: issuer/aud/exp/iat/nonce/signature는 검증한다. 다중 audience의 `azp`, `nbf`, `iat` max age 정책은 없다.
- 권고: `authorized_party` field, `expected_azp`, `max_age_seconds`, `nbf` 검증 추가.

### M-3. Session verify가 매 요청마다 DB write를 수행

- 위치: `src/coreline_auth/service.py:313-327`
- 근거: `verify_session()`이 매번 `last_seen_at`과 `idle_expires_at`을 갱신한다.
- 영향: 읽기 요청도 모두 쓰기 트랜잭션이 되어 SQLite lock contention과 write amplification 발생.
- 권고: `session_touch_interval_seconds`를 두고 마지막 갱신 후 N초 이상 지났을 때만 update. 권한 확인만 필요한 API는 read-only verify 옵션 제공.

### M-4. SQLite adapter가 WAL/busy_timeout/lock 없이 `check_same_thread=False` 사용

- 위치: `src/coreline_auth/storage/sqlite.py:102-109`, `examples/board_storage.py:119-128`
- 근거: FastAPI sync endpoint가 threadpool에서 동시에 실행되면 같은 connection에 동시 접근할 수 있다.
- 권고: `threading.RLock`으로 write section 보호, `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout`, `PRAGMA foreign_keys=ON` 적용. 장기적으로 connection-per-request 또는 async adapter 옵션.

### M-5. In-process rate limiter는 bucket cleanup/distributed backend가 없음

- 위치: `src/coreline_auth/rate_limit.py:15-27`
- 근거: `_buckets`가 만료된 key를 적극 청소하지 않는다. multi-worker에서는 공유되지 않는다.
- 권고: expired bucket eviction, max bucket cap, `RateLimiter` protocol 추가. Redis adapter는 별도 optional.

### M-6. Admin/audit viewer가 영속 audit 저장소와 `audit:read` 권한을 쓰지 않음

- 위치: `src/coreline_auth/examples/saas_app.py:36`, `:395-412`
- 근거: audit event는 process-local list에 저장되고, viewer 권한은 `users:read`다.
- 권고: `auth_audit_events` table, `AuditStorage` protocol, admin audit API/UI는 `audit:read` 권한으로 보호.

## 3. 성능/확장성 개선 항목

| ID | 항목 | 현재 병목 | 권고 |
|---|---|---|---|
| P-1 | Session touch write throttle | 모든 인증 확인이 DB write | `session_touch_interval_seconds` + read-only verify |
| P-2 | User listing pagination | `admin.py:21-39`에서 전체 list 후 Python filter | storage-level query/filter/limit/offset |
| P-3 | DB indexes | session/user/flow lookup은 기본 index/unique 일부만 있음 | `auth_users(role,status)`, `auth_sessions(user_id,revoked_at,expires_at)`, `auth_login_flows(expires_at,consumed_at)` |
| P-4 | Expired row cleanup | flows/sessions가 누적 | `cleanup_expired_flows`, `cleanup_expired_sessions` API + test |
| P-5 | SMTP latency | request path에서 blocking send | sender queue/callback boundary 문서화, adapter는 sync/async sender protocol 분리 |

## 4. 추가로 필요한 기능

### Release blocker에 가까운 기능

1. CSRF integration for cookie flows
2. Session revoke-on-password-change
3. Verified-email-only social account linking policy
4. SQLite concurrency hardening
5. Persistent audit store
6. Production demo mode guard

### v0.5 확장 기능

1. TOTP enrollment/verify + recovery codes hash-only
2. AAL2 enforcement for sensitive admin action
3. WebAuthn/passkey challenge store + interface contract
4. OIDC metadata/JWKS cached fetcher
5. Admin audit viewer filter/pagination/export
6. Password policy profile: min length, common password deny hook, breached password checker interface

### v0.6 이후 후보

1. Redis/distributed rate limiter adapter
2. Async SQLAlchemy/Postgres storage adapter
3. Device/session risk signals
4. Email provider adapters: SES/Resend/SendGrid as optional packages
5. Tenant/organization support는 별도 제품 전략 확정 전까지 보류

## 5. 개발 순서 권고

1. **Security Release Gate**: H-1~H-5 우선. 작은 패치지만 실 배포 위험을 크게 낮춘다.
2. **Storage/Performance Gate**: P-1~P-4. SQLite 기반 demo/소규모 운영 안정성 확보.
3. **OIDC/Social Gate**: M-1~M-2 + linking policy. Google/OIDC production 신뢰성 확보.
4. **Audit/Admin Gate**: persistent audit + `audit:read`.
5. **MFA v0.5**: TOTP/recovery/AAL2를 실제 동작으로 승격.

## 6. 현재 강점

- Password는 Argon2를 사용하고 원문 저장 없음 (`security.py:36-46`).
- Session/magic/reset/verification token은 opaque token + hash-only storage 구조다.
- Open redirect는 relative path만 허용한다 (`security.py:49-61`).
- Provider token은 기본적으로 `SocialProfile`에 포함하지 않고 저장하지 않는 정책이 명확하다 (`social.py:1-10`).
- Google/OIDC ID token은 RS256 signature, issuer, audience, exp, iat, nonce를 검증한다 (`social.py:588-655`).
- Board demo가 ownership-aware authorization을 실제 도메인에서 검증한다.
