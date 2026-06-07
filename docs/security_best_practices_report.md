# Coreline Auth 보안 재리뷰 보고서 — 패치 후 2차 감사

분석일: 2026-05-29
대상 경로: `/Users/hwanchoi/project_202605/CoreMCP/packages/coreline-auth`
대상 버전: `0.5.0rc1` 작업 트리 기준
범위: `src/coreline_auth`, FastAPI adapter, storage adapters, OAuth/OIDC, MFA, WebAuthn, demo SaaS app, 관련 테스트

## Executive Summary

직전 패치로 사용자가 지정한 P0/P1/P2 항목은 코드 레벨에서 대부분 적절히 닫혔다. 특히 세션 `touch` stale-write, role 변경 후 세션 권한 유지, cookie-auth admin CSRF, TOTP replay counter CAS, magic-link 이메일 escaping, WebAuthn origin/RP 검증, demo OIDC PKCE/nonce/ID-token 연결은 재검토 결과 개선이 확인된다.

이번 2차 감사 중 기존 목록 밖의 **인가 엔진 wildcard scope 처리 결함(AUTHZ-001)** 이 추가로 확인되어, 재리뷰 과정에서 최소 패치와 회귀 테스트를 즉시 적용했다. 이후 권장 순서대로 후속 패치를 진행하여 **MFA step-up rate limit, `set_password()` session revoke 기본 동작, email normalization, OAuth direct URL validation, ResourceAuthorizer explicit scope, MFA vault production guardrail**까지 적용 완료했다.

### 현재 위험 요약

| 등급 | 건수 | 핵심 항목 |
|---|---:|---|
| Critical | 0 | 없음 — AUTHZ-001 패치 완료 |
| High | 0 | MFA step-up rate limit 패치 완료 |
| Medium | 0 / 잔여 운영 주의 | scope-less semantics, OAuth URL, email normalization, `set_password`, MFA vault guardrail 패치 완료 |
| Low/Info | 2 | Async service parity/production caveat, custom email template raw variable footgun |

## 2026-05-29 후속 패치 상태

| 권장 순서 | 항목 | 현재 상태 |
|---:|---|---|
| 1 | MFA-001 step-up rate limit | `mfa_verify_limit_per_minute`와 user-hash 기반 shared limiter 적용 |
| 2 | SESSION-001 `set_password()` revoke semantics | 기본 config에 따라 session revoke, bootstrap/create/reset/admin은 명시 opt-out |
| 3 | INPUT-001 email normalization | `email-validator` 기반 core/async/SMTP 검증 적용 |
| 4 | SOCIAL-001 direct OAuth URL validation | `OAuthConnector.__init__`에서 HTTPS/no-credentials/no-fragment 검증 |
| 5 | AUTHZ-002 scope-less semantics | `scope=` 명시 API 추가, legacy inference는 문서화 |
| 6 | MFA-VAULT-001 production guardrail | TOTP enrollment 기본 fail-closed, local/test opt-in + warning |

## 직전 Findings 패치 확인

| 기존 이슈 | 현재 상태 | 근거 |
|---|---|---|
| session touch가 stale `revoked_at=None` 저장 가능 | 해결 확인 | `verify_session()`이 `touch_session()`만 호출하고, storage가 `revoked_at IS NULL` 조건으로 업데이트: `src/coreline_auth/service.py:352-359`, `src/coreline_auth/storage/sqlite.py:392-404`, `src/coreline_auth/storage/postgres.py:242-251` |
| role 변경 후 기존 session permissions 유지 | 해결 확인 | role update 후 대상 user sessions revoke: `src/coreline_auth/admin.py:32-35` |
| cookie-auth admin POST CSRF optional default | 핵심 경로 해결 확인 | cookie-auth state-changing route는 CSRF protector 없으면 403: `src/coreline_auth/fastapi_adapter.py:95-102`, `src/coreline_auth/fastapi_adapter.py:298-305` |
| TOTP replay counter CAS 아님 | 해결 확인 | `mark_mfa_factor_counter_used()` atomic update: `src/coreline_auth/service.py:424-427`, `src/coreline_auth/storage/sqlite.py:542-554`, `src/coreline_auth/storage/postgres.py:328-337` |
| magic-link email `return_to` HTML/URL escaping 없음 | 해결 확인 | return_to validation + URL/HTML escaped link variables: `src/coreline_auth/security.py:69-77`, `src/coreline_auth/email.py:142-153` |
| WebAuthn origin/RP prefix check | 해결 확인 | `urlparse` + exact host/subdomain matching: `src/coreline_auth/webauthn.py:134-158` |
| OAuth/OIDC demo flow PKCE/nonce/ID-token 미연결 | 해결 확인 | demo start/callback에 PKCE+nonce cookie+JWKS ID token verify 연결: `src/coreline_auth/examples/saas_app.py:900-1002`, connector ID token path: `src/coreline_auth/social/connectors.py:118-145` |

## Findings

### AUTHZ-001

- Rule ID: AUTHZ-001
- Severity: **Critical — 2차 리뷰 중 패치 완료**
- Location: 기존 취약 지점 `src/coreline_auth/permissions.py:_permission_matches`, 현재 패치 위치 lines `114-128`; 회귀 테스트 `tests/test_authorization.py:40-46`
- Evidence before patch:

```python
if granted_statement.action == ALL_PERMISSIONS:
    return True
```

The previous early return allowed a scoped wildcard such as `post:*:own` to satisfy broader requirements before scope validation.

- Current patched code:

```python
if granted_statement.action not in {ALL_PERMISSIONS, required_statement.action}:
    return False

# A resource/action wildcard must still honor the grant's scope.
if granted_statement.scope is None or granted_statement.scope == ALL_PERMISSIONS:
    return True
if granted_statement.scope == required_statement.scope:
    return True
if granted_statement.scope == ANY_SCOPE and required_statement.scope in {None, OWN_SCOPE}:
    return True
return False
```

- Verified behavior after patch:

```text
PolicyEngine().allows(("post:*:own",), "post:delete:any") == False
PolicyEngine().allows(("post:*:own",), "post:delete") == False
PolicyEngine().allows(("post:*:own",), "post:delete:own") == True
```

- Impact if unpatched: A host app issuing custom scoped wildcard permissions could accidentally grant broader access than intended.
- Fix status: patched in `src/coreline_auth/permissions.py`; regression test added in `tests/test_authorization.py`.
- Remaining note: `ResourceAuthorizer` still has a separate scope inference ambiguity documented as AUTHZ-002.

### MFA-001

- Rule ID: MFA-001
- Severity: **High**
- Location: `src/coreline_auth/service.py:431-438`, `src/coreline_auth/service.py:450-464`
- Evidence:

```python
def step_up_totp(self, session_token: str, *, code: str) -> Principal:
    principal = self.verify_session(session_token)
    factor = self.verify_totp(user_id=principal.user_id, code=code)
```

```python
def step_up_recovery_code(self, session_token: str, *, code: str) -> Principal:
    principal = self.verify_session(session_token)
    code_hash = hash_secret(code)
```

There is no `_check_rate_limit()` or equivalent attempt throttle in either path.

- Impact: Once an attacker has an AAL1 session, they can brute-force 6-digit TOTP attempts aggressively. The new CAS prevents same-code replay but does not limit incorrect guesses.
- Fix: Add `mfa_limit_per_minute` and enforce rate limits on at least `(user_id, session_id, factor/method)` before verification. Consider exponential backoff or temporary factor lockout after repeated failures. Recovery code attempts should share the same step-up limiter.
- Mitigation: Host apps should wrap `step_up_totp`/`step_up_recovery_code` with external rate limiting until core support is added.
- False positive notes: If all MFA step-up is only exposed behind a separate edge/WAF rate limiter, exploitability is reduced, but that protection is not visible in the module.

### AUTHZ-002

- Rule ID: AUTHZ-002
- Severity: Medium
- Location: `src/coreline_auth/authorization.py:_candidate_requirements`, lines `147-155`
- Evidence:

```python
else:
    candidates = (
        PermissionStatement(statement.resource, statement.action).value,
        PermissionStatement(statement.resource, statement.action, OWN_SCOPE).value,
        PermissionStatement(statement.resource, statement.action, ANY_SCOPE).value,
    ) if context.owns_resource else (...)
```

- Verified behavior:

```text
ResourceAuthorizer().can(("post:delete:own",), resource="post", action="delete", context=owning_context)
# => allowed=True, required='post:delete', matched_permission='post:delete:own'
```

- Impact: A caller who requests `resource="post", action="delete"` without specifying `scope="own"` may accidentally authorize owner-scoped permissions. This can create inconsistent authorization semantics across code paths.
- Fix: Make scope explicit in `can_action()` or add an option such as `infer_own_scope=True` defaulting to false. Alternatively document that scope-less checks intentionally infer own/any candidates and require host apps to pass `required="post:delete:any"` for broad operations.
- Mitigation: In host apps, always use explicit permission strings with scope for resource actions: `post:delete:own` or `post:delete:any`.
- False positive notes: This may be intentional ergonomics for ownership-aware helpers. The issue is ambiguity rather than a certain exploit in the bundled demo.

### SOCIAL-001

- Rule ID: SOCIAL-001
- Severity: Medium
- Location: `src/coreline_auth/social/connectors.py:26-30`, outbound calls at `110-163`
- Evidence:

```python
class OAuthConnector:
    def __init__(self, config: OAuthProviderConfig) -> None:
        if not config.client_id or not config.client_secret or not config.redirect_uri:
            raise AuthConfigurationError(...)
        self.config = config
```

The direct `OAuthProviderConfig` path does not normalize or enforce HTTPS/no-credentials/host policy for `auth_url`, `token_url`, or `userinfo_url`. Factories such as `GenericOIDCConnector.from_endpoints()` do normalize endpoints, but `OAuthConnector(OAuthProviderConfig(...))` is exported.

- Impact: A misconfigured or user-influenced provider config can make the connector POST credentials/code to an insecure or internal URL. This is primarily a secure-by-default/SSRF hardening gap.
- Fix: Validate all URLs in `OAuthConnector.__init__` using `_normalize_provider_url()`: `auth_url`, `token_url`, `userinfo_url`, and optional `issuer`; reject credentials/fragments and non-local HTTP. Consider an explicit `allowed_hosts`/`provider_host` policy for production integrations.
- Mitigation: Host apps should only instantiate via safe provider factories or validate environment-configured endpoints before constructing `OAuthProviderConfig`.
- False positive notes: If configs are compile-time trusted constants, direct exploitation is unlikely.

### INPUT-001

- Rule ID: INPUT-001
- Severity: Medium
- Location: `src/coreline_auth/service_support.py:58-62`, `src/coreline_auth/email.py:124-129`
- Evidence:

```python
def normalize_email(self, email: str) -> str:
    value = email.strip().lower()
    if not value or "@" not in value or len(value) > 320:
        raise AuthValidationError("invalid email")
    return value
```

SMTP sender similarly checks only `from_email` contains `@`.

- Impact: Core service can persist malformed emails containing control characters or invalid local/domain syntax when called directly or from form routes. Python `EmailMessage` rejects CR/LF headers, so classic header injection is mostly prevented at send time, but malformed identities can cause delivery failures, account uniqueness anomalies, and inconsistent behavior between FastAPI JSON routes (`EmailStr`) and direct/demo form usage.
- Fix: Use the existing `email-validator` dependency in core normalization: `validate_email(..., check_deliverability=False)`; reject all C0 controls and normalize domain case/IDNA. Apply equivalent validation to `SmtpEmailSender.from_email`.
- Mitigation: Host apps should validate email before calling `CorelineAuthService.create_user()`/`request_magic_link()`.
- False positive notes: FastAPI adapter JSON models use Pydantic email types, reducing this risk for those endpoints.

### SESSION-001

- Rule ID: SESSION-001
- Severity: Medium
- Location: `src/coreline_auth/service.py:119-125`, config at `src/coreline_auth/service.py:57`, demo manual revoke at `src/coreline_auth/examples/saas_app.py:738-742`
- Evidence:

```python
revoke_sessions_on_password_change: bool = True
...
def set_password(self, user_id: str, password: str) -> AuthCredential:
    ...
    saved = self.storage.upsert_credential(credential)
    self._audit("auth.password.set", target_user_id=user.id)
    return saved
```

- Impact: `consume_password_reset()` and admin password setting revoke sessions, and the demo account password route manually revokes other sessions. But the public service method `set_password()` does not honor `revoke_sessions_on_password_change` by itself. Host apps that implement a “change password” endpoint by calling `set_password()` directly may leave stolen sessions alive.
- Fix: Split internal password upsert from user-facing password change. For example, add `set_password(..., revoke_sessions: bool | None = None, except_session_id: str | None = None)` where `None` follows config, and update bootstrap/create-user paths to explicitly disable revoke when appropriate.
- Mitigation: Document that any user-initiated password change must call `revoke_sessions_for_user()` after `set_password()` until API semantics are tightened.
- False positive notes: Current bundled password reset/admin/demo flows explicitly revoke; the risk is host API misuse.

### MFA-VAULT-001

- Rule ID: MFA-VAULT-001
- Severity: Medium
- Location: `src/coreline_auth/service.py:91`, `src/coreline_auth/mfa.py:21-31`
- Evidence:

```python
self.mfa_secret_vault = mfa_secret_vault or InMemoryMfaSecretVault()
```

```python
class InMemoryMfaSecretVault:
    """Development vault. Production apps should provide an encrypted vault."""
    self._secrets: dict[str, str] = {}
```

- Impact: Production deployments that enable TOTP but forget to pass `SQLiteMfaSecretVault`, `RedisMfaSecretVault`, or another encrypted vault will store TOTP seeds in process memory only and lose them on restart. This is more of a secure-default footgun than a remote exploit.
- Fix: Add config such as `allow_in_memory_mfa_vault=False` or `mfa_enabled=True` requiring explicit vault injection. Alternatively emit a startup/readiness warning/failure when TOTP APIs are used with the development vault outside test/demo mode.
- Mitigation: Production apps should always instantiate an encrypted vault with `SecretEnvelopeProtector` and a host-managed master key.
- False positive notes: In-memory vault is appropriate for unit tests and ephemeral demos.

### ASYNC-001

- Rule ID: ASYNC-001
- Severity: Low / Medium if used as production auth facade
- Location: `src/coreline_auth/async_service.py:43-49`, implemented methods end around `201-205`
- Evidence:

```python
"""Async service for production storage adapters.
...
v0.6 grows async parity behind this additive class.
"""
```

The async service currently covers core login/session/magic-link/list-audit, but lacks sync-service parity for password reset, email verification, social login, admin, and MFA step-up.

- Impact: If a PostgreSQL/async deployment treats `AsyncCorelineAuthService` as a full replacement, critical lifecycle features may be absent or reimplemented inconsistently by host code.
- Fix: Document non-parity prominently and add parity tests before recommending async service for production auth flows. Prefer routing unsupported flows through sync service or implement async equivalents with the same atomic storage methods.
- Mitigation: Use sync `CorelineAuthService` for full v0.1/v0.5 features or restrict async adapter exposure to the implemented flows.
- False positive notes: The class docstring already says it is additive/scaffold; this is an operational risk.

### EMAIL-001

- Rule ID: EMAIL-001
- Severity: Low
- Location: `src/coreline_auth/email.py:142-153`, custom template compatibility variables
- Evidence:

```python
rendered = self.templates.magic_link.render(
    token=token,
    return_to=return_to,
    return_to_url=quote(return_to, safe=""),
    return_to_html=html_escape(return_to, quote=True),
    magic_link_url=magic_link_url,
    magic_link_url_html=html_escape(magic_link_url, quote=True),
)
```

- Impact: Default templates now use escaped URL variables, but raw `${token}` and `${return_to}` remain available for custom template compatibility. A custom HTML template that uses raw variables in attributes can reintroduce injection risk.
- Fix: Document template variable safety tiers and prefer `*_html` or full `*_url_html` in HTML templates. Consider linting template strings or deprecating raw variables for HTML body rendering.
- Mitigation: Treat `EmailTemplate.html_body` as an HTML sink and only insert escaped variables.
- False positive notes: Default templates are currently safe.

## Positive Security Observations

- Password hashing uses Argon2 via `argon2-cffi`; no custom password hash algorithm was introduced.
- Session/magic/reset tokens are high-entropy opaque values and persisted as hashes only in storage tests.
- Login-flow consume is atomic in SQLite/Postgres via `UPDATE ... RETURNING` with `consumed_at IS NULL` and expiration predicates.
- Audit metadata redaction covers token/password/secret/credential/authorization keys and caps size/depth.
- CSRF helper uses HMAC-signed double-submit tokens and session binding when a session cookie exists.
- OIDC ID token verifier rejects `alg=none`/HS256, checks RS256 signature, issuer, audience, exp/iat/nbf, azp, and nonce.
- `src/coreline_auth` still has no `coremcp` / `apps.api.coremcp` imports.

## Recommended Fix Order

1. **MFA-001**: 완료 — TOTP/recovery-code step-up shared rate limit 적용.
2. **SESSION-001**: 완료 — `set_password()`가 기본적으로 password-change session revoke 정책을 따른다.
3. **INPUT-001**: 완료 — core/async/SMTP email normalization을 `email-validator`로 강화.
4. **SOCIAL-001**: 완료 — direct `OAuthProviderConfig` URL을 connector 생성 시 검증.
5. **AUTHZ-002**: 완료 — `ResourceAuthorizer`에 explicit `scope=` 지원 및 문서화.
6. **MFA-VAULT-001**: 완료 — TOTP enrollment 기본 fail-closed, local/test opt-in guardrail.
7. **ASYNC-001 / EMAIL-001**: 잔여 Low/Info — production 문서화/템플릿 안전 가이드 권장.

## Verification Commands Run

```bash
uv run python - <<'PY'
from coreline_auth.permissions import PolicyEngine
from coreline_auth.authorization import ResourceAuthorizer, AuthorizationContext
p = PolicyEngine()
print(p.allows(("post:*:own",), "post:delete:any"))
print(p.allows(("post:*:own",), "post:delete"))
print(p.allows(("post:*:own",), "post:delete:own"))
print(ResourceAuthorizer().can(("post:delete:own",), resource="post", action="delete", context=AuthorizationContext(actor_user_id="u1", resource_owner_id="u1")))
PY
```

Observed:

```text
False
False
True
PermissionDecision(allowed=True, required='post:delete', reason='allowed', matched_permission='post:delete:own', scope='own')
```

Full test suite was re-run after the follow-up patches and this report update: `173 passed, 1 skipped in 15.30s`.
