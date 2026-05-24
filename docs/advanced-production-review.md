# Coreline Auth Advanced Production Review

작성 일시: `2026-05-23`

이 문서는 현재 Coreline Auth 구현을 “프로덕션급 인증 모듈 + 실제 권한 검증 데모 앱” 기준으로 재평가하고, 참조 구현에서 흡수할 기능을 정리한다.

## 1. 현재 구현 수준

| 영역 | 현재 상태 | 판단 |
|---|---:|---|
| 독립 패키지 | 있음 | CoreMCP와 runtime import 분리됨 |
| Email/password | 있음 | Argon2 hash 사용, 기본 안전성 좋음 |
| Magic link | 있음 | hash-only, 1회 사용, TTL 구조 있음 |
| Session | 있음 | opaque token + hash-only 저장 |
| Multi-user | 부분 | signup/user role은 있으나 권한 정책이 단순 |
| Admin core/API | 부분 | list/role/ban/unban/password/session revoke 있음 |
| Google/Facebook | 부분 | connector + dev social login 있음. nonce/prompt/PKCE URL 파라미터와 token/userinfo normalization 하드닝 적용 |
| Generic OIDC | 초기 | issuer endpoint 직접 설정과 mockable discovery helper 있음. ID token/JWKS 검증은 후속 |
| MFA/passkey | 없음 | 고급 보안 확장 필요 |
| Production email | 없음 | SMTP/SES/Resend 등 adapter 필요 |
| Demo app | 부분 | login/signup/admin은 있으나 실제 도메인 권한 검증 대상이 없음 |
| Board/RBAC demo | 없음 | 권한 자격 확인용 핵심 데모로 추가 필요 |

## 2. 참조 구현별 흡수 전략

| 참조 | 핵심 특징 | 흡수할 것 | 버릴 것 |
|---|---|---|---|
| Better Auth Admin | Admin plugin, role/permission access control, session management | resource/action 기반 permission statement, admin user/session APIs | TypeScript runtime 의존, organization plugin 전체 |
| Better Auth Plugins | Magic link, passkey, MFA 등 plugin 생태계 | optional feature module 구조 | 50+ plugin을 한 번에 복제 |
| Logto RBAC | Role, permission/scope, API resource 모델 | `resource:action` permission, Generic OIDC connector, API resource 사고 | Logto 서버 wrapper화 |
| Logto Social Connectors | Google/Facebook/social connector, token vault 옵션 | provider connector interface, provider subject pinning, Generic OIDC, token vault optional interface | 모든 social provider 즉시 구현 |
| Supabase Auth | Magic link/OTP/social login, admin user API, JWT+RLS | magic link TTL/rate limit, admin API ergonomics, MFA assurance level 개념 | Supabase/Postgres/RLS 의존 |
| Appwrite Permissions | team/role 기반 resource permissions | resource-level permission 문자열과 ownership check | BaaS/team 모델 전체 |
| Keycloak | identity brokering, realm/client/role, enterprise SSO | OIDC/JWKS 검증, identity provider abstraction | realm/enterprise 운영 복잡도 |
| Ory Kratos | self-service login/registration flow, MFA/passkey, headless identity | flow state-machine, bring-your-own UI | 별도 identity server 운영 모델 |

## 3. 프로덕션급 목표 정의

Coreline Auth는 단순 login helper가 아니라 다음을 제공해야 한다.

1. **Multi-user by default** — 가입, 로그인, 세션, role, permission, ban 상태를 기본 지원.
2. **Resource-level authorization** — “본인 글 수정 가능, 타인 글 수정 불가, admin은 전체 가능” 같은 실제 앱 권한을 표현.
3. **Provider identity linking** — Google/Facebook/OIDC identity를 user와 안전하게 연결.
4. **Admin mode** — user/session/role/ban/audit/password reset을 관리.
5. **Production email** — magic link, verification, reset password를 실제 메일로 발송 가능.
6. **MFA/passkey-ready** — TOTP/WebAuthn을 extension으로 붙일 수 있는 구조.
7. **Self-test demo app** — 게시판 수준의 도메인 앱으로 권한을 실제 검증.

## 4. Board demo 권한 모델

게시판은 인증 모듈 검증에 적합하다. 이유는 “소유자 권한”과 “관리자 권한”이 모두 필요하기 때문이다.

### Roles

| Role | 설명 |
|---|---|
| `owner` | 모든 권한 |
| `admin` | 사용자/게시글/댓글 관리 |
| `moderator` | 게시글/댓글 moderation |
| `author` | 게시글 작성, 본인 글 수정/삭제 |
| `viewer` | 읽기 전용 |
| `user` | 기본 가입자. profile + board read |

### Permissions

| Permission | 의미 |
|---|---|
| `users:read` | 사용자 목록 보기 |
| `users:write` | role/password 변경 |
| `users:ban` | ban/unban |
| `sessions:revoke` | 세션 revoke |
| `board:read` | 게시판 읽기 |
| `post:create` | 게시글 작성 |
| `post:update:own` | 본인 게시글 수정 |
| `post:update:any` | 모든 게시글 수정 |
| `post:delete:own` | 본인 게시글 삭제 |
| `post:delete:any` | 모든 게시글 삭제 |
| `comment:create` | 댓글 작성 |
| `comment:delete:own` | 본인 댓글 삭제 |
| `comment:delete:any` | 모든 댓글 삭제 |
| `audit:read` | audit 보기 |

## 5. 구현 리스크

| 리스크 | 대응 |
|---|---|
| 한 번에 모든 고급 기능 추가로 auth core 불안정 | Phase별 gate와 테스트 분리 |
| OAuth provider token 유출 | provider token은 기본 미저장, token vault는 opt-in encrypted storage |
| Cookie CSRF | SameSite=Lax + state-changing route CSRF helper 적용 |
| RBAC 과설계 | board demo에 필요한 resource/action/ownership부터 구현 |
| demo와 core coupling | demo는 `examples/` 하위에 두고 core API만 사용 |
| CoreMCP 오염 | Coreline Auth source에서 CoreMCP import 금지 유지 |

## 6. Social/OIDC hardening 상태

- `GenericOIDCConnector`는 `issuer + authorization/token/userinfo endpoint` 직접 설정 또는 `.well-known/openid-configuration` discovery helper로 구성한다.
- Discovery helper는 `metadata_fetcher` 주입을 지원해 테스트/운영에서 캐시·SSRF guard·mock HTTP client를 외부에서 붙일 수 있다.
- `authorization_url`은 기존 Google/Facebook 기본 파라미터를 유지하면서 `nonce`, `prompt`, `code_challenge`, `code_challenge_method=S256`, `login_hint` 등 extra param을 opt-in으로 붙인다.
- OIDC userinfo는 `sub` 누락 시 실패하고, `email_verified`가 누락되면 기본적으로 `False`로 취급한다. Facebook은 기존 Graph profile 호환을 위해 email 존재 시 verified 처리하되 명시 claim이 있으면 claim을 따른다.
- Provider token response는 `SocialProfile`에 포함하지 않고 Coreline Auth 저장소에도 저장하지 않는다. 장기 provider API access가 필요하면 앱 경계에서 encrypted `ProviderTokenVault` 구현을 opt-in으로 연결한다.

## 7. 최종 권고

다음 개발은 단순 기능 추가가 아니라 “Coreline Auth v0.2 production foundation”으로 진행한다.

우선순위:

1. RBAC/resource authorization 엔진 고도화
2. Board demo app 추가
3. Admin UI/API 강화
4. Google/Facebook/OIDC production hardening
5. Production email + password reset
6. MFA/passkey groundwork
7. 테스트/문서/릴리즈 체계

## 8. 참고 링크

- Better Auth Admin: https://better-auth.com/docs/plugins/admin
- Better Auth Plugins: https://better-auth.com/docs/plugins
- Supabase Auth: https://supabase.com/docs/guides/auth/
- Supabase Magic Link: https://supabase.com/docs/guides/auth/auth-magic-link
- Supabase Social Login: https://supabase.com/docs/guides/auth/social-login
- Appwrite Auth: https://appwrite.io/docs/products/auth
- Appwrite Permissions: https://appwrite.io/docs/advanced/platform/permissions
- Logto RBAC: https://docs.logto.io/authorization/role-based-access-control
- Logto Social Connectors: https://docs.logto.io/connectors/social-connectors
- Keycloak Docs: https://www.keycloak.org/documentation
- Ory Kratos: https://www.ory.sh/kratos
