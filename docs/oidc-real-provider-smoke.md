# OIDC / Google Real Provider Smoke Checklist

이 문서는 Coreline Auth의 OIDC/Google 커넥터를 실제 provider credential로 점검할 때 사용하는 최소 smoke 절차다.

## 사전 조건

- HTTPS callback URL 또는 localhost 개발 callback URL을 provider console에 등록한다.
- Google/OIDC client id, client secret은 애플리케이션 환경변수로만 주입한다.
- provider access/refresh/id token 원문은 Coreline Auth 모델, audit, log에 저장하지 않는다.

## Google smoke

1. `CORELINE_AUTH_GOOGLE_CLIENT_ID`와 `CORELINE_AUTH_GOOGLE_CLIENT_SECRET`을 설정한다.
2. 데모 또는 호스트 앱에서 `/social/google`을 연다.
3. Google consent 후 callback이 성공하고 session cookie가 발급되는지 확인한다.
4. `/` 또는 `/auth/me`에서 email, role, permissions가 정상인지 확인한다.
5. 동일 email의 기존 계정 linking은 Google `email_verified=true`일 때만 허용되는지 확인한다.
6. 로그/audit/DB에서 `access_token`, `refresh_token`, `id_token` 원문이 없는지 검색한다.

## Generic OIDC smoke

1. issuer discovery URL이 HTTPS인지 확인한다. localhost 개발 외 HTTP는 거부되어야 한다.
2. `OIDCMetadataClient(allowed_hosts={...})`로 discovery fetch를 수행한다.
3. JWKS kid miss 시 `JWKSCache`가 refresh하는지 확인한다.
4. ID token 검증에서 `iss`, `aud`, `azp`, `exp`, `nbf`, `iat/max_age`, `nonce` mismatch가 각각 거부되는지 확인한다.

## 실패 시 확인

- callback URL mismatch
- provider console의 client type/web origin 설정
- `azp` mismatch: multi-audience token이면 client id와 일치해야 한다.
- issuer mismatch: discovery document issuer와 configured issuer가 byte-exact하게 같은지 확인한다.
