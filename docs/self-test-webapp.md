# Coreline Auth Self-Test Webapp

## 목적

인증 모듈을 CoreMCP나 다른 host app에 붙이기 전에, `coreline-auth` 자체가 실제 웹 SaaS처럼 로그인/세션/권한 흐름을 처리하는지 확인한다.

현재 self-test 표면은 두 개로 분리되어 있다.

| 표면 | 위치 | 실행 | 목적 |
|---|---|---|---|
| Auth-only SaaS demo | `src/coreline_auth/examples/saas_app.py` | `make run-demo` | 로그인, 가입, 계정센터, admin, audit, system/email |
| Board RBAC demo | `demos/board_rbac/` | `make run-demo-board` | Coreline Auth를 소비하는 host-style 게시판 RBAC/세션/CSRF 검증 |

`demos/board_rbac`는 repo checkout 전용 demo fixture다. `src/coreline_auth` 패키지에 포함되지 않고 wheel에도 포함되지 않는다. 이전 local sibling 폴더였던 `packages/coreline-board`와 `packages/coreline-board-saas`는 이 demo 이식 후 현재 checkout에서 제거되었으며, 이 self-test의 source-of-truth는 `demos/board_rbac`다.

## Auth-only demo 실행

```bash
cd packages/coreline-auth
make run-demo
```

브라우저에서 접속:

```txt
http://127.0.0.1:8010/login
```

기본 계정:

```txt
owner@example.com / coreline-demo-password
```

환경변수로 변경 가능:

```bash
CORELINE_AUTH_DEMO_OWNER_EMAIL=me@example.com \
CORELINE_AUTH_DEMO_OWNER_PASSWORD='change-me-password' \
CORELINE_AUTH_DEMO_DB=.coreline-auth-demo/auth.sqlite3 \
make run-demo
```

`make run-demo`는 auth-only 상태를 유지한다. board route를 기본 mount하지 않는다.

## Auth-only 수동 테스트 시나리오

1. `/login` 접속.
2. 기본 계정으로 로그인.
3. `/` dashboard 접근 확인.
4. `/admin` 권한 보호 페이지 접근 확인.
5. 로그아웃 후 `/admin` 접근 시 `/login` redirect 확인.
6. `/signup`에서 새 계정을 만들고 dashboard/account 접근 확인.
7. 새 계정은 `/account/*` 접근 가능하지만 `/admin`, `/admin/audit`, `/system`은 403인지 확인.
8. 매직링크 요청.
9. 화면에 표시된 개발용 매직링크 클릭.
10. dashboard 재접근 확인.
11. 같은 매직링크 재사용 시 실패 확인.
12. `/password-reset/request`에서 비밀번호 재설정을 요청하고 개발용 reset link로 새 비밀번호를 설정.
13. 새 비밀번호로 로그인 확인.
14. Google/Facebook 버튼으로 개발용 social login을 수행.
15. admin 계정으로 사용자 검색/필터, role 변경, disable/enable reason 동작 확인.
16. `/admin/audit`에서 최근 감사 이벤트를 확인.
17. `/account`에서 표시 이름을 수정하고 dashboard 카드에 반영되는지 확인.
18. `/account/security`에서 MFA 상태와 AAL 안내를 확인하고 비밀번호 변경을 수행.
19. `/account/sessions`에서 현재/다른 세션 목록과 revoke 버튼을 확인.
20. `/account/activity`에서 로그인·로그아웃·비밀번호 변경·세션 revoke 이벤트를 확인.
21. `/admin/users/{id}`에서 사용자 상세, MFA 상태, 세션, 활동, admin password set, disable/enable을 확인.
22. `/admin/audit`에서 action, actor, target, since/until, limit/offset 필터를 적용해 결과가 줄어드는지 확인.
23. `/system`에서 storage health, provider readiness, 운영 runbook 카드가 보이는지 확인.
24. `/system/email`에서 개발용 email outbox와 magic link/password reset/email verification template preview를 확인.

## Board RBAC demo 실행

```bash
cd packages/coreline-auth
make run-demo-board
```

브라우저에서 접속:

```txt
http://127.0.0.1:8011/
http://127.0.0.1:8011/demo-board
```

기본 데이터 경로:

```txt
.coreline-auth-demo/board-rbac.sqlite3
.coreline-auth-demo/board-rbac-auth.sqlite3
```

환경변수로 변경 가능:

```bash
CORELINE_BOARD_DEMO_PREFIX=/demo-board \
CORELINE_BOARD_DEMO_DB=.coreline-auth-demo/board-rbac.sqlite3 \
CORELINE_BOARD_DEMO_AUTH_DB=.coreline-auth-demo/board-rbac-auth.sqlite3 \
make run-demo-board
```

## Board RBAC 권한별 계정

공통 비밀번호는 `coreline-demo-password`다. 홈 화면과 로그인 화면의 “권한별 테스트 계정”에서 계정을 선택하면 `/login?email=<account>&next=/demo-board` 흐름으로 email/password가 채워진다.

| Board role | Email | Auth role | 기대 권한 |
|---|---|---|---|
| owner | `owner-board@example.com` | `owner` | 모든 게시글/댓글 관리 가능 |
| admin | `admin-board@example.com` | `admin` | 모든 게시글/댓글 관리 가능 |
| moderator | `moderator-board@example.com` | `user` | 모든 게시글 수정/삭제, 댓글 작성/수정/삭제 가능 |
| author | `author-board@example.com` | `user` | 게시글 작성, 본인 글/댓글 수정·삭제 가능 |
| user | `user-board@example.com` | `user` | 게시글/댓글 작성 가능, 수정/삭제 불가 |
| viewer | `viewer-board@example.com` | `viewer` | 읽기 전용 |

`owner/admin/viewer/user`는 Coreline Auth role이고, `author`, `moderator`는 `demos/board_rbac` 내부 board role mapping이다. Auth `Role` enum에는 board-local role을 추가하지 않는다.

## Board RBAC 수동 테스트 시나리오

1. `/` 접속 후 6개 권한별 계정 카드가 보이는지 확인.
2. `author-board@example.com`을 선택해 `/login`으로 이동.
3. 로그인 form에 email과 공통 password가 채워졌는지 확인.
4. 로그인 후 `/demo-board`로 이동하는지 확인.
5. author 계정으로 `/demo-board/new`에서 게시글 작성.
6. author 계정으로 다른 사용자의 seeded post 수정/삭제가 403으로 막히는지 확인.
7. moderator 계정으로 다른 사용자의 seeded post 수정/삭제가 가능한지 확인.
8. owner/admin 계정으로 전체 게시글/댓글 관리가 가능한지 확인.
9. user 계정으로 게시글/댓글 작성은 가능하지만 다른 글 수정/삭제는 막히는지 확인.
10. viewer 계정에서 “새 글 작성 불가”가 보이고 POST 작성 요청이 403인지 확인.
11. stale/missing CSRF token으로 게시글/댓글/삭제 POST가 403인지 확인.
12. `next=https://evil.example` 또는 `next=//evil.example` 로그인이 `/demo-board`로 fallback되는지 확인.

## Board RBAC 테스트 포인트

- board service/storage API는 raw session token을 받지 않고 `BoardActor` principal만 받는다.
- board web adapter만 Coreline Auth session cookie를 읽고 `verify_session()` 결과를 board actor로 변환한다.
- 모든 board state-changing form은 CSRF hidden field와 cookie를 함께 검증한다.
- UI 버튼 숨김과 POST 권한 차단을 모두 테스트한다.
- `demos/board_rbac`는 `coreline_board` 또는 `coreline_board_saas` sibling package를 import하지 않는다.
- `src/coreline_auth`는 board demo 또는 sibling board package를 import하지 않는다.

## Self-service / Admin 점검 포인트

- 일반 사용자는 `/account/*`에서 자기 정보만 조회·관리한다.
- 비밀번호 변경은 현재 비밀번호 검증 후 처리하며, 성공 시 현재 세션을 제외한 다른 세션을 종료한다.
- 본인 세션 revoke는 세션 소유권을 확인한 뒤 수행한다. 현재 세션을 revoke하면 로그인 화면으로 이동한다.
- 비관리자가 `/admin`, `/admin/audit`, `/system`에 접근하면 디자인된 403 안내 화면이 표시된다.
- 관리자는 `/admin/users/{id}`에서 사용자 상태 전환, role 변경, 비밀번호 설정, 세션 revoke, MFA 상태 확인을 한 화면에서 수행한다.
- `/system`은 외부 인프라 없이 storage health와 개발용 email queue 상태를 확인하는 운영 smoke 화면이다.
- `/system/email`은 SMTP credential 없이도 template과 InMemoryEmailSender 큐를 확인한다. token 원문/부분값 대신 hash fingerprint만 표시한다.
- `/admin/audit` 필터는 ISO datetime 문자열을 받으며 잘못된 입력은 raw error 대신 UI 오류 카드로 표시한다.

## 자동 테스트

```bash
cd packages/coreline-auth
make smoke-demo
make smoke-demo-board
make import-guard
uv run pytest -q tests/test_demo_webapp.py tests/demos tests/test_import_boundaries.py
make test
make readiness-check
```

## 주의

- 데모앱은 개발용 매직링크 token을 화면에 표시한다.
- 운영에서는 `EmailSender` 구현체를 통해 이메일로만 발송해야 한다.
- `secure=True` cookie는 HTTPS 배포에서 host project가 설정한다.
- board RBAC demo는 checkout self-test fixture이며 production board product가 아니다.

## 현재 소셜 로그인 상태

Google/Facebook은 credential이 있으면 실제 OAuth redirect/callback을 사용하고, 없으면 개발용 social connector로 로그인 흐름을 검증합니다. Generic OIDC, PKCE, Google/OIDC ID token RS256+JWKS 검증 helper가 구현되어 있으며 provider token은 기본 저장하지 않습니다.

## 운영 readiness 확인

```bash
make readiness-check
uv run python -m coreline_auth.ops_readiness --json
```

이 명령은 외부 서비스에 연결하지 않고 Google/Facebook OAuth, SMTP, Redis, Postgres, WebAuthn 환경변수의 준비 상태만 확인합니다. secret 값은 출력하지 않습니다.
