# Coreline Auth Reference Comparison

작성 일시: `2026-05-23`

이 문서는 기존 인증 오픈소스/서비스의 특징을 Coreline Auth에 어떻게 흡수했는지 정리한다. “더 낫다”는 범용 우열이 아니라 **Coreline 프로젝트군에 더 적합한 선택**이라는 의미다.

## 정밀 비교표

| 참조 구현 | 주요 특징 | Coreline Auth에 도입 | 아직 미도입/후속 | Coreline Auth의 현재 장점 |
|---|---|---|---|---|
| Better Auth | email/password, social provider, plugin, Admin plugin, role/permission access control | admin core, role update, ban/unban, session revoke, role-permission 분리 | TS plugin ecosystem, passkey plugin, organization plugin | Python/FastAPI에 직접 embed 가능. Coreline 프로젝트에 독립 package로 재사용 가능 |
| Supabase Auth | password, magic link/OTP, social login, JWT, Postgres/RLS 연동 | magic link 1회성/TTL, redirect guard, social login 개념 | Postgres/RLS, JWT 기반 access token | SQLite/memory로 로컬·개인 프로젝트에 가볍게 도입. opaque session hash-only 저장 |
| Appwrite Auth | email/password, OAuth2 30+ provider, sessions, teams/roles/permissions | OAuth2 provider UX, role/team-permission 사고 일부 | BaaS server, team membership 모델 | 별도 BaaS 없이 앱 내부 인증 모듈로 실행 가능 |
| Logto | RBAC, permission/scope, API resource, social connectors, token vault | role/permission 분리, Google/Facebook connector, provider identity 분리 | Secret Vault, organization/API resource 관리 콘솔, full OIDC federation | 자체 user/session/permission DB를 직접 소유. Coreline 앱에 커스텀 적용 쉬움 |
| Keycloak | enterprise IAM, identity brokering, social login, SSO/realm/client/role | provider identity brokering 개념 | realm/client/protocol mapper 등 enterprise 운영 | 훨씬 작고 내장형. 개인/소규모 Coreline 앱에 적합 |
| Ory Kratos | headless identity flows, password/social/passwordless/MFA | login flow state-machine, headless adapter 사고 | full self-service flow UI, MFA/passkey | 외부 identity server 없이 package import로 사용 가능 |

## 현재 도입된 기능

- Email/password
- Magic link
- Multi-user signup
- Role-based permissions: `owner`, `admin`, `viewer`, `user`
- Admin core/API: user list, role update, ban/unban, password set, session revoke
- Google/Facebook OAuth connector skeleton + actual redirect/callback path when env credentials exist
- Dev social connector for local Google/Facebook flow testing
- Session hash-only storage
- Magic-link hash-only storage
- SQLite/memory storage
- SaaS-style demo app

## 아직 Better Auth/Logto/Appwrite 대비 부족한 부분

- Generic OIDC connector
- Production email sender adapters
- MFA/passkey
- Provider token vault
- Organization/team model
- Admin UI package 분리

## 참고 공식 문서

- Better Auth Admin plugin: https://better-auth.com/docs/plugins/admin
- Better Auth basic/social/plugin model: https://better-auth.com/docs/basic-usage
- Supabase Auth: https://supabase.com/docs/guides/auth/
- Supabase Magic Link: https://supabase.com/docs/guides/auth/auth-magic-link
- Supabase Social Login: https://supabase.com/docs/guides/auth/social-login
- Appwrite Auth/Teams/Permissions: https://appwrite.io/docs/products/auth
- Logto RBAC: https://docs.logto.io/authorization/role-based-access-control
- Logto Social connectors: https://docs.logto.io/connectors/social-connectors
- Keycloak documentation: https://www.keycloak.org/documentation
- Ory Kratos: https://www.ory.sh/kratos
