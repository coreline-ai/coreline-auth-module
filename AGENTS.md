# AGENTS.md — Coreline Auth

Coreline Auth는 CoreMCP 하위 기능이 아니라 독립 인증 모듈입니다.

## 핵심 규칙

- `src/coreline_auth`는 `coremcp.*` 또는 `apps.api.coremcp.*`를 import하지 않는다.
- CoreMCP 전용 적용 코드는 CoreMCP 쪽 adapter에 둔다.
- 의존 방향은 항상 `CoreMCP -> coreline_auth` 단방향이다.
- password/session/magic-link token 원문을 DB/log/audit에 저장하지 않는다.
- 자체 암호 알고리즘을 만들지 않는다. password hashing은 검증된 라이브러리를 사용한다.
- v0.1은 독립 core + 단순 SaaS형 웹앱 검증까지 포함한다.
- v0.2 social/OIDC connector는 v0.1 안정화 이후 진행한다.
