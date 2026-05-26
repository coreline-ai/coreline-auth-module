# Coreline Auth Self-Test Webapp

## 목적

인증 모듈을 CoreMCP에 붙이기 전에, 모듈 자체가 실제 웹 SaaS처럼 로그인/세션/권한 흐름을 처리하는지 확인한다.

## 실행

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

## 수동 테스트 시나리오

1. `/login` 접속.
2. 기본 계정으로 로그인.
3. `/` dashboard 접근 확인.
4. `/board` 게시판 메뉴 접근 확인.
5. `/board/new`에서 게시글 작성.
6. `/board/{id}` 상세에서 댓글 작성.
7. 작성자 계정에서는 게시글 수정/삭제 버튼이 보이는지 확인.
8. 별도 브라우저 또는 시크릿 창에서 `/signup`으로 새 계정을 만들고 같은 게시글 상세에 접근.
9. 다른 사용자의 게시글 수정(`/board/{id}/edit`) 또는 삭제(`/board/{id}/delete`)가 403/권한 안내로 막히는지 확인.
10. `/admin` 권한 보호 페이지 접근 확인.
11. 로그아웃 후 `/admin` 접근 시 `/login` redirect 확인.
12. `/signup`에서 새 author 계정 가입.
13. author 계정은 dashboard/board 접근 가능하지만 `/admin`은 403인지 확인.
14. 매직링크 요청.
15. 화면에 표시된 개발용 매직링크 클릭.
16. dashboard 재접근 확인.
17. 같은 매직링크 재사용 시 실패 확인.
18. `/password-reset`에서 비밀번호 재설정을 요청하고 개발용 reset link로 새 비밀번호를 설정.
19. 새 비밀번호로 로그인 확인.
20. Google/Facebook 버튼으로 개발용 social login을 수행.
21. admin 계정으로 사용자 검색/필터, role 변경, ban/unban reason 동작 확인.
22. `/admin/audit`에서 최근 감사 이벤트를 확인.
23. `/account`에서 표시 이름을 수정하고 dashboard 카드에 반영되는지 확인.
24. `/account/security`에서 MFA 상태와 AAL 안내를 확인하고 비밀번호 변경을 수행.
25. `/account/sessions`에서 현재/다른 세션 목록과 revoke 버튼을 확인.
26. `/account/activity`에서 로그인·로그아웃·비밀번호 변경·세션 revoke 이벤트를 확인.
27. `/admin/users/{id}`에서 사용자 상세, MFA 상태, 세션, 활동, admin password set, disable/enable을 확인.
28. `/admin/audit`에서 action, actor, target, since/until, limit/offset 필터를 적용해 결과가 줄어드는지 확인.
29. `/system`에서 storage health, provider readiness, 운영 runbook 카드가 보이는지 확인.
30. `/system/email`에서 개발용 email outbox와 magic link/password reset/email verification template preview를 확인.

## 게시판 권한 테스트 포인트

- 모든 게시판 화면은 `coreline_auth_session` cookie 기반 세션을 다시 검증한다.
- `/board`, `/board/new`, `/board/{id}`는 로그인하지 않으면 `/login`으로 redirect된다.
- 현재 데모 board UI는 `examples.board_service.BoardService`를 직접 사용한다.
- 게시글/댓글 작성과 본인 글 수정·삭제는 `author` 권한으로 검증한다.
- 관리자/소유자는 wildcard 권한으로 전체 수정·삭제가 가능하다.
- 다른 사용자의 게시글 수정/삭제는 `BoardService`의 ownership-aware RBAC에서 403으로 차단한다.

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
uv run pytest tests/test_demo_webapp.py tests/test_demo_board_webapp.py tests/test_fastapi_adapter.py tests/test_email_lifecycle.py
make smoke-demo
make test
make readiness-check
```

## 주의

- 데모앱은 개발용 매직링크 token을 화면에 표시한다.
- 운영에서는 `EmailSender` 구현체를 통해 이메일로만 발송해야 한다.
- `secure=True` cookie는 HTTPS 배포에서 host project가 설정한다.

## 현재 소셜 로그인 상태

Google/Facebook은 credential이 있으면 실제 OAuth redirect/callback을 사용하고, 없으면 개발용 social connector로 로그인 흐름을 검증합니다. Generic OIDC, PKCE, Google/OIDC ID token RS256+JWKS 검증 helper가 구현되어 있으며 provider token은 기본 저장하지 않습니다.

## 운영 readiness 확인

```bash
make readiness-check
uv run python -m coreline_auth.ops_readiness --json
```

이 명령은 외부 서비스에 연결하지 않고 Google/Facebook OAuth, SMTP, Redis, Postgres, WebAuthn 환경변수의 준비 상태만 확인합니다. secret 값은 출력하지 않습니다.
