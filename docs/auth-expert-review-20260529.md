# coreline-auth 인증 전문가 코드 레벨 감사 리포트

**대상 버전:** 0.5.0rc1
**분석일:** 2026-05-29
**분석 대상:** `/Users/hwanchoi/project_202605/CoreMCP/packages/coreline-auth`
**분석 범위:** 13개 서브시스템(핵심 인증 플로우, 세션/토큰 수명주기, 패스워드/시크릿 해싱, MFA/TOTP & 복구코드, WebAuthn/패스키, CSRF 방어, 인가/권한/관리자, 레이트 리미팅/브루트포스, 이메일 발송 & 검증, 소셜 로그인/OAuth2/OIDC, 저장소 계층, FastAPI 어댑터, 관측성/운영 준비/감사)에 대한 코드 레벨 정밀 감사 및 적대적 검증
**평가 기준:** OWASP ASVS 4.0, OWASP Top 10 (2021), NIST SP 800-63B, RFC 6749/6750/7636/6238/7519, OpenID Connect Core 1.0, WebAuthn Level 2, CWE

---

## 요약 (Executive Summary)

coreline-auth는 Argon2id 패스워드 해싱, SHA256 토큰 단방향 해싱(원문 미저장), AES-256-GCM 시크릿 봉투 암호화, 타이밍 공격 방어(`hmac.compare_digest`, `verify_dummy_password`), 기본 거부(default-deny) 인가 모델 등 **암호학적 기본기와 보안 설계 원칙이 전반적으로 견고한** 독립 인증 모듈이다. 그러나 적대적 검증 결과, 권한 모델의 핵심 매칭 로직에서 **인가 우회(critical)** 결함 1건이 확인되었으며, MFA 검증 경로의 레이트 리미팅 부재·복구코드 엔트로피 부족·비동기 서비스 기능 격차 등 **즉시 조치가 필요한 high 등급 결함 6건**이 존재한다.

### 심각도별 발견 건수

| 심각도 | 건수(검증 완료) | 비고 |
|--------|----------------|------|
| Critical | 1 | 인가 우회 |
| High | 6 | MFA/세션/비동기/CSRF 만료 |
| Medium | 16 | 설계 명확성·구성 안전·동시성·문서화 |
| Low/Info | 다수 | 방어 심화(defense-in-depth) 개선 권고 |
| **검증 완료 medium 이상 합계** | **23** | |

### 핵심 결론

- **인가 모델의 행동 와일드카드(`*`) 처리가 스코프 검증을 건너뛰어**(AUTHZ-001), `post:*:own` 권한이 `post:delete`(스코프 무관)와 일치하는 **권한 범위 우회**가 가능하다. 이는 권한 모델의 근본 무결성을 깨뜨리는 단일 최우선 결함이다.
- **MFA 검증 경로(`step_up_totp`/`step_up_recovery_code`)에 레이트 리미팅이 전혀 없어**(RLIM-02), 세션 확보 후 6자리 TOTP(100만 경우의 수) 또는 복구코드에 대한 무제한 브루트포스가 가능하다. 복구코드 엔트로피도 NIST 권고 160비트에 미달하는 120비트(REC-01)이다.
- **비동기 서비스(`AsyncCorelineAuthService`)는 패스워드 재설정·이메일 검증을 미구현**(ASYNC-PARITY-01, PASS-RESET-01)하여, 프로덕션 PostgreSQL 비동기 배포 시 핵심 인증 기능이 부분 마비되며, 1회성 토큰 보장이 보증되지 않는다.
- **InMemoryMfaSecretVault가 평문 저장이면서 기본값**(VAULT-01)이라, 명시적 강제 없이 docstring에만 의존하므로 운영 배포 시 TOTP 시드 평문 노출 위험이 있다.
- 데모/예제 한정 결함과 다수의 low/info 항목은 방어 심화 차원의 개선 권고로, 핵심 라이브러리의 암호학적 정확성은 양호하다.

---

## 심각도별 발견 항목 요약 표

| ID | 서브시스템 | 제목 | 심각도 | 위치 | 표준 |
|----|-----------|------|--------|------|------|
| AUTHZ-001 | 인가/권한/관리자 | 행동 와일드카드 사용 시 스코프 검증 우회 | **Critical** | permissions.py:118-119 | OWASP ASVS V4.1.1, V4.1.3 |
| ASYNC-01 | 핵심 인증 플로우 | 비동기 서비스 세션 AAL 지정 누락 | **High** | async_service.py:163 | NIST SP 800-63B 4.1, ASVS 3.1.2 |
| PASS-RESET-01 | 핵심 인증 플로우 | 패스워드 재설정 토큰 1회성 미보장(비동기) | **High** | async_service.py:1-259 | OWASP ASVS 2.4.3, NIST 5.1.4.1 |
| REC-01 | MFA/TOTP | 복구코드 엔트로피 120비트(NIST 160비트 미달) | **High** | mfa.py:38-39 | OWASP ASVS 2.4.4, NIST 5.1.2 |
| VAULT-01 | MFA/TOTP | MFA 시크릿 저장소 암호화가 선택사항(기본값 평문) | **High** | mfa.py:16-18 | OWASP ASVS 2.1.1, NIST 5.1.4.2 |
| CSRF-01 | CSRF 방어 | CSRF 토큰 명시적 만료 메커니즘 부재 | **High** | csrf.py:49-51 | OWASP ASVS 4.8.1, A01:2021 |
| RLIM-02 | 레이트 리미팅 | MFA 코드/복구코드 검증 경로 미보호 | **High** | service.py:397-410, 430-443 | OWASP ASVS 2.4.3, NIST 5.1.5 |
| CRED-02 | 패스워드/자격증명 | 패스워드 최소 길이 8자(NIST 12자 미만) | Medium | security.py:37-40 | NIST 5.1.1.2, ASVS 2.1.1 |
| CRED-04 | 패스워드/자격증명 | InMemoryMfaSecretVault 평문 저장(기본값) | Medium | mfa.py:21-31 | NIST 5.2.5, ASVS 2.4.5 |
| ASYNC-PARITY-01 | 핵심 인증 플로우 | 비동기 서비스 재설정/이메일검증 미구현 | Medium | async_service.py:1-259 | OWASP ASVS 2.4 |
| TOTP-REPLAY-01 | 핵심 인증 플로우 | TOTP 리플레이 방어 race condition | Medium | service.py:397-410 | RFC 6238, NIST 5.1.5.2 |
| AAL2-01 | MFA/TOTP | AAL2 스텝업 후 세션 재발급 부재 | Medium | service.py:412-418, 430-442 | OWASP ASVS 4.1.3 |
| LOG-01 | MFA/TOTP | MFA 실패 로깅 부재 및 감사 제한 | Medium | service.py:397-410 | OWASP ASVS 4.1.2, NIST 7 |
| ENROLL-01 | MFA/TOTP | TOTP 중복 등록 방지 부재 | Medium | service.py:371-385 | OWASP ASVS 2.4.3 |
| WAUTH-02 | WebAuthn/패스키 | credential 간 교차 사용 방지 로직 부재 | Medium | webauthn.py:82, 93-94 | WebAuthn L2 §7.2, ASVS 2.4.5 |
| WAUTH-03 | WebAuthn/패스키 | 서명 알고리즘 협상 불충분(키 강도 미검증) | Medium | webauthn.py:145-154 | WebAuthn L2 §6.5.7, RFC 7515 |
| WAUTH-04 | WebAuthn/패스키 | Sign counter 0일 때 단조성 검증 생략 | Medium | webauthn.py:117-119 | WebAuthn L2 §6.5.9 |
| CSRF-02 | CSRF 방어 | 데모 약한 시크릿 검사 우회 가능성 | Medium | examples/saas_app.py:50 | OWASP ASVS 3.2.1, NIST 5.1.4.2 |
| CSRF-04 | CSRF 방어 | CSRF 쿠키 HTTPOnly 미설정 | Medium | fastapi_adapter.py:120 | OWASP ASVS 4.8.3, CWE-614 |
| RLIM-05 | 레이트 리미팅 | IP 기반 레이트 리미팅 부재 | Medium | service.py:127-147 | OWASP ASVS 2.3.1, RFC 7239 |
| EMAIL-03 | 이메일 발송 | SMTP TLS 검증 조건부 실행(평문 가능) | Medium | email.py:162-167 | RFC 3207, NIST SP 800-52r2 |
| OAUTH-01 | 소셜/OAuth2/OIDC | redirect_uri 형식 검증 부재 | Medium | connectors.py:27-28 | RFC 6749 §3.1.2.1, ASVS 5.1.5 |
| STOR-02 | 저장소 계층 | 이메일 UNIQUE 제약 대소문자 민감(SQLite) | Medium | sqlite.py:36, 205 | OWASP ASVS 2.2.3, RFC 5890 |
| STOR-05 | 저장소 계층 | PostgreSQL 대소문자 무시 이메일 조회 미구현 | Medium | postgres.py:110 | OWASP ASVS 2.2.3, RFC 5890 |
| ERR-01 | FastAPI 어댑터 | 에러 응답에서 검증 규칙 메시지 노출 | Medium | fastapi_adapter.py:112,139,165 | A01:2021, ASVS 4.3.3 |
| CSRF-01(웹) | FastAPI 어댑터 | CSRF 보호 적용 명시성 부족(설정 실수) | Medium | fastapi_adapter.py:75-79, 95-112 | OWASP ASVS 4.1.3 |
| OBS-01 | 관측성/운영 | LoggingMetricSink 민감정보 누수 위험 | Medium | observability.py:40-47 | A09:2021, CWE-532 |
| OBS-03 | 관측성/운영 | assert_secret_safe 불완전한 검증 로직 | Medium | ops_readiness.py:126-137 | OWASP ASVS 2.1.1, CWE-200 |

> 참고: 검증 과정에서 일부 항목은 본래 제기된 등급이 조정되었다. CRED-02/CRED-04(→Low로 하향 검토 의견 존재), TOTP-01·CSRF-03·CSRF-05·OBS-02·STOR-01/04/07·RLIM-04/06·EMAIL-02·OAUTH-02·AUTHZ-003·WAUTH-05(→Low), CRED-01·STOR-03(→Info)는 아래 참고 항목 및 상세 절에서 별도 명시한다.

---

## 상세 발견 항목

### [CRITICAL] AUTHZ-001 — 행동 와일드카드 사용 시 스코프 검증 우회(scope bypass)

- **심각도:** Critical
- **위치:** `permissions.py:118-119`
- **표준:** OWASP ASVS 4.0 V4.1.1, V4.1.3 (Authorization Logic)

**설명**
`_permission_matches()` 함수에서 granted 권한의 행동(action) 부분이 와일드카드(`*`)인 경우, 스코프 필드를 검증하지 않고 즉시 `True`를 반환한다. 이로 인해 `post:*:own`(자신이 소유한 게시물에 대한 모든 행동)이 `post:delete`(모든 게시물 삭제, 스코프 무관)와 일치하게 되어, 권한 범위 제약을 무효화한다.

**코드 근거**
```python
# permissions.py:118-119
if granted_statement.action == ALL_PERMISSIONS:
    return True
# 스코프 검증 로직(라인 123-131)은 라인 120에서 액션이 일치해야만 도달 가능
```
실제 호출: `_permission_matches('post:*:own', 'post:delete')` → `True` (granted_statement.action='*', granted_statement.scope='own', required_statement.scope=None)

**검증 결과**
라인 118-119에서 `granted_statement.action`이 `ALL_PERMISSIONS('*')`와 일치할 때 스코프 검증 없이 즉시 `True`를 반환하는 코드 사실이 확인되었다. 스코프 검증 로직(라인 123-131)은 라인 120(액션 일치)에 도달해야만 실행되므로, 와일드카드 경로에서는 전혀 수행되지 않는다. 실제 악용 경로: `granted='post:*:own'`, `required='post:delete'`일 때 `ResourceAuthorizer._candidate_requirements()`가 `context.owns_resource=False`에서 `post:delete:any` 또는 `post:delete` 후보를 생성하고, `_permission_matches('post:*:own', 'post:delete:any')` 호출 시 라인 118에서 스코프 검증 없이 `True`를 반환한다. 결과적으로 스코프 `own`의 제약이 무효화되어 스코프 없는 행동과 일치하므로, 권한 모델의 근본적 우회가 발생한다. ASVS V4.1.1/V4.1.3을 직접 위배하는 authorization bypass이므로 critical 등급은 타당하다.

**권고**
라인 118-119의 action 와일드카드 검증 후 스코프 검증 로직을 추가한다. granted 권한이 스코프를 가진 경우, required 권한의 스코프와 호환성을 검증해야 한다. 구체적으로 action/resource 와일드카드 검증을 **스코프 검증 다음에** 수행하거나, 와일드카드 경로에서도 라인 123-131의 스코프 검증 로직을 반드시 거치도록 재구성한다.

---

### [HIGH] ASYNC-01 — 비동기 서비스: 세션 AAL 지정 누락으로 동기 서비스와 불일치

- **심각도:** High
- **위치:** `async_service.py:163`
- **표준:** NIST SP 800-63B 4.1 (Assurance Levels), OWASP ASVS 4.0 3.1.2 (Session Creation)

**설명**
동기 서비스(`service.py:318`)는 세션 발행 시 `assurance_level=AuthAssuranceLevel.AAL1`을 명시적으로 설정하지만, 비동기 서비스(`async_service.py:163`)에서는 이 필드를 지정하지 않는다. 모델 기본값이 AAL1이므로 현재 동작은 우연히 맞지만, 구조적 불일치로 인해 향후 기본값 변경 시 보안 회귀 위험이 있다. 또한 `step_up_totp`(service.py:412-418), `step_up_recovery_code`(service.py:430-443)는 AAL2로 상승시키는 메서드를 동기 서비스에만 제공하므로, 비동기 서비스에서는 `require_aal2` 강제 기능을 사용할 수 없다.

**코드 근거**
```python
# 비동기 (async_service.py:163) — assurance_level 누락
session = AuthSession(..., created_at=now, expires_at=...)

# 동기 (service.py:318) — 명시
session = AuthSession(..., assurance_level=AuthAssuranceLevel.AAL1, created_at=now, expires_at=...)
```

**검증 결과**
비동기 서비스는 `assurance_level`을 명시하지 않으나 모델 기본값이 AAL1이므로 현재 보안 요구사항은 충족한다. 그러나 향후 기본값 변경 시 회귀 위험이 있고, `step_up_totp`/`step_up_recovery_code`/`require_aal2`가 동기 서비스에만 구현되어 AAL2 기능 격차가 존재한다.

**권고**
비동기 `issue_session`(async_service.py:158-165)에 `assurance_level=AuthAssuranceLevel.AAL1`을 명시적으로 추가하고, `step_up_totp`/`step_up_recovery_code`를 비동기로 구현하여 AAL2 기능을 활성화한다.

---

### [HIGH] PASS-RESET-01 — 패스워드 재설정 토큰 1회성 미보장: 비동기 환경에서 재사용 가능

- **심각도:** High
- **위치:** `async_service.py:1-259` (전체)
- **표준:** RFC 6239(Password Reset Token), OWASP ASVS 4.0 2.4.3(Forgotten Password), NIST SP 800-63B 5.1.4.1(Memorized Secret Reset)

**설명**
동기 서비스는 `storage.consume_login_flow_by_state_hash`(memory.py:115-127)를 통해 재설정 토큰을 1회만 사용하도록 `consumed_at`을 설정한다(memory.py:125: `consumed = replace(flow, consumed_at=now)`). 그러나 비동기 서비스는 `request_password_reset`/`consume_password_reset`을 구현하지 않으므로, 비동기 저장소 어댑터에서 1회성 보장 로직이 제대로 구현되지 않으면 동일 토큰으로 여러 번 재설정이 가능하다. 특히 분산 환경에서 race condition 시 같은 토큰으로 여러 접근이 발생할 수 있다.

**코드 근거**
```python
# service.py:242-245 (동기) — consume 시 1회성 보장
# consume_password_reset 내부에서 consume_login_flow_by_state_hash 호출

# async_service.py — request_password_reset, consume_password_reset 자체 미구현
```

**검증 결과**
`async_service.py`(라인 1-259)에 `request_password_reset`/`consume_password_reset`이 완전히 부재하며 동기 `service.py`(라인 222-259)에만 구현되어 있다. 비동기 Postgres 스토리지(postgres.py:188-204)의 `consume_login_flow_by_state_hash`는 `UPDATE...WHERE...RETURNING` 단일 SQL 문이지만, 명시적 격리 수준 없이 PostgreSQL 기본값(READ COMMITTED)에서 실행되므로 분산 환경 race condition 가능성이 존재한다. 메모리 스토리지는 `threading.RLock()`으로 보호되나(memory.py:115-127), 비동기 적응에서는 격리 수준 명시가 필요하다. RFC 6239, OWASP ASVS 2.4.3, NIST 5.1.4.1 기준 위반.

**권고**
비동기 서비스에 `request_password_reset`/`consume_password_reset`을 동기 서비스와 동일하게 구현하고, 비동기 저장소 어댑터에서 `consume_login_flow_by_state_hash` 호출 시 원자성을 보장하는 트랜잭션(SERIALIZABLE 또는 REPEATABLE READ)을 사용한다.

---

### [HIGH] REC-01 — 복구코드 엔트로피: 120비트로 NIST 권고 160비트 미달

- **심각도:** High (본래 제기 medium에서 상향)
- **위치:** `src/coreline_auth/mfa.py:38-39`
- **표준:** OWASP ASVS 2.4.4, NIST SP 800-63B 5.1.2

**설명**
`generate_recovery_code()`는 `generate_token()[:20]`을 사용한다. `generate_token()`은 `secrets.token_urlsafe(32)`(base64url, 64문자 알파벳)이므로 20문자는 **20 × log2(64) = 120비트** 엔트로피이다. NIST SP 800-63B는 복구코드에 최소 160비트를 권고하므로 요구사항에 미달한다(본래 finding은 이를 160비트로 잘못 계산했음).

**코드 근거**
```python
def generate_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)  # _TOKEN_BYTES=32

def generate_recovery_code() -> str:
    return generate_token()[:20]  # 20자 base64url = 120비트(160비트 아님)
```

**검증 결과**
코드 위치(mfa.py:38-39), `generate_token()` 구현(`token_urlsafe(32)`), base64url 64문자 알파벳이 모두 확인되었다. 엔트로피는 20 × 6 = **120비트**로, NIST SP 800-63B 권고 160비트에 미달한다. PRNG는 `secrets` 모듈을 사용하므로 암호학적으로 약한 것은 아니나(CWE-326 해당, 약한 PRNG 아님), 엔트로피 길이 자체가 표준 미달이므로 실제 보안 결함이 존재한다. 따라서 medium에서 high로 상향이 타당하다.

**권고**
복구코드 엔트로피를 최소 160비트로 상향한다(예: `generate_token()[:27]` 또는 별도 엔트로피 산출). 동시에 사용자 경험을 위해 8자씩 그룹화·하이픈 구분(`XXXX-XXXX-...`) 포맷을 제공하되, 엔트로피 부족 해결을 우선한다.

---

### [HIGH] VAULT-01 — MFA 시크릿 저장소: 암호화 구현이 선택사항(기본값 평문)

- **심각도:** High
- **위치:** `src/coreline_auth/mfa.py:16-18`
- **표준:** OWASP ASVS 2.1.1(Password Storage), NIST SP 800-63B 5.1.4.2(Secrets Protection)

**설명**
`MfaSecretVault` 프로토콜은 `store_totp_secret()`/`load_totp_secret()`만 정의하고 암호화 책임을 구현체에 맡긴다. `InMemoryMfaSecretVault`(개발용)는 평문 저장이며, `service.py:91`에서 기본값으로 설정된다(`self.mfa_secret_vault = mfa_secret_vault or InMemoryMfaSecretVault()`). 개발 중 기본값을 그대로 두면 실수로 프로덕션에 배포될 가능성이 있다.

**코드 근거**
```python
class InMemoryMfaSecretVault:
    """Development vault. Production apps should provide an encrypted vault."""
    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}  # 평문 저장
    def store_totp_secret(self, *, factor_id: str, secret: str) -> None:
        self._secrets[factor_id] = secret

# service.py:91
self.mfa_secret_vault = mfa_secret_vault or InMemoryMfaSecretVault()
```

**검증 결과**
(1) `MfaSecretVault`는 Protocol로서 암호화를 강제하지 않으며, (2) `InMemoryMfaSecretVault`는 평문 dict 저장(mfa.py:25, 28), (3) `service.py:91`에서 기본값으로 할당, (4) 프로덕션에서 비암호화 저장소 사용을 거부하거나 경고하는 코드 메커니즘이 없고 docstring에만 의존함이 확인되었다. `SQLiteMfaSecretVault`/`RedisMfaSecretVault`는 `SecretEnvelopeProtector`로 AES-GCM 암호화를 정상 구현하나, 기본값을 비암호화로 둔 정책 설계 오류다. ASVS 2.1.1, NIST 5.1.4.2 위반. 개발자 실수로 프로덕션 배포 시 TOTP 시드 평문 노출 → 2FA 우회 → 계정 침해 경로가 성립하므로 high 등급이 타당하다.

**권고**
(1) 프로덕션에서 명시적으로 암호화 저장소(`SQLiteMfaSecretVault`/`RedisMfaSecretVault`)를 요구하고, (2) `CorelineAuthConfig`에 vault 유형 설정을 추가하여 비암호화 저장소 사용을 방지하며, (3) 최소한 서비스 초기화 시 `InMemoryMfaSecretVault` 사용 경고 로그를 출력한다.

---

### [HIGH] CSRF-01 — CSRF 토큰 명시적 만료 메커니즘 부재

- **심각도:** High
- **위치:** `src/coreline_auth/csrf.py:49-51`
- **표준:** OWASP ASVS 4.0 4.8.1, OWASP Top 10 2021 A01:2021

**설명**
CSRF 토큰이 시간 기반 만료 검증을 수행하지 않는다. 발급된 토큰은 이론상 무한정 유효하며, 오래된 토큰 재사용이 가능하다. 토큰은 nonce와 signature로만 구성되어(csrf.py:17-23) 발급 시간 정보가 없다.

**코드 근거**
```python
# csrf.py:17-23 — CsrfToken 데이터클래스: nonce, signature 필드만 (timestamp 없음)
# csrf.py:49-51 — issue_for_context()는 발급 시간을 토큰에 포함하지 않음
# csrf.py:53-58 — verify_for_context()는 HMAC 서명 검증만, 타임스탬프 비교 없음
```

**검증 결과**
`CsrfToken`이 nonce/signature만 포함하고, `issue_for_context()`가 발급 시간을 포함하지 않으며, `verify_for_context()`가 시간 기반 검증 없이 HMAC 서명만 수행함이 확인되었다. 세션 기반 바인딩(fastapi_adapter.py:106-110)이 존재하나 이는 간접 방어일 뿐 토큰 자체의 만료를 보장하지 않는다. 세션 갱신 시 새 토큰이 발급되더라도 이전 토큰을 명시적으로 무효화하지 않아 오래된 토큰 재사용 가능성이 남는다. ASVS 4.8.1(CSRF 토큰 만료를 세션 수명과 동기화)을 충족하지 못하므로 high 유지(세션 바인딩에 의한 제한은 존재).

**권고**
토큰에 발급 시간을 포함하고 검증 시 `now - issued_at < MAX_CSRF_AGE`를 확인한다. CSRF 토큰 만료를 세션 수명과 동기화한다.

---

### [HIGH] RLIM-02 — MFA 코드 및 복구 코드 검증 경로 미보호

- **심각도:** High
- **위치:** `service.py:397-410, 430-443`
- **표준:** OWASP ASVS 2.4.3(Account Recovery), NIST SP 800-63B 5.1.5(Out-of-Band Devices)

**설명**
`step_up_totp()`/`step_up_recovery_code()`에 레이트 리미팅이 적용되지 않는다. 세션 확보 후 공격자가 6자리 TOTP(100만 경우의 수) 또는 복구코드를 무제한 시도해 MFA를 무효화할 수 있다.

**코드 근거**
```python
# service.py:412-418 step_up_totp() — _check_rate_limit() 호출 없음
#   line 413: factor = self.verify_totp(...) 직접 호출
# service.py:430-443 step_up_recovery_code() — _check_rate_limit() 호출 없음
# 비교: service.py:129 login_password(), service.py:154 request_magic_link()는 _check_rate_limit() 호출
```

**검증 결과**
두 메서드 모두 `_check_rate_limit()` 호출이 없음이 확인되었다. `verify_totp()` 내부의 리플레이 방어(`last_used_counter`)는 동일 코드 재사용만 차단할 뿐 다른 6자리 조합의 무제한 시도를 막지 못한다. 복구코드도 일회용 플래그(`used_at`)만 있고 시도 횟수 제한이 없다. `login_password`/`request_magic_link`는 명시적으로 레이트 리미팅을 호출하는 것과 대조된다. ASVS 2.4.3, NIST 5.1.5 위배. session_token 기반이더라도 MFA 다단계 인증은 브루트포스로부터 보호되어야 한다.

**권고**
session_token/user_id 기반으로 MFA 검증 단계에 레이트 리미팅을 적용한다. 예: `_check_rate_limit(f'mfa_totp_step_up:{principal.user_id}', limit=5)`를 `step_up_totp` 초반에 추가하고, 복구코드도 동일하게 처리한다.

---

### [MEDIUM] CRED-02 — 패스워드 최소 길이 8자는 NIST 권고 12자 미만

- **심각도:** Medium (검증 의견: Low로 하향 가능 — 강력한 Argon2id 해싱으로 실제 위험 제한적)
- **위치:** `security.py:37-40`
- **표준:** NIST SP 800-63B 5.1.1.2, OWASP ASVS 2.1.1

**설명**
`hash_password()`가 최소 길이를 8자로만 검증한다. NIST는 사용자 선택 패스워드 최소 12자(또는 8자 + 복잡도)를 권고하므로, `'12345678'` 같은 약한 패스워드도 통과한다.

**코드 근거**
```python
def hash_password(password: str) -> str:
    if len(password) < 8:
        raise AuthValidationError('password must be at least 8 characters')
    return _password_hasher.hash(password)
```

**검증 결과**
코드 사실은 정확하다. 다만 심각도는 Medium→Low로 조정 가능하다: (1) Argon2id(time_cost=3, memory_cost=65536, parallelism=4)로 약한 패스워드도 저장소에서 안전하게 보호됨, (2) `production-hardening-review-20260524.md`에서 패스워드 정책 프로파일이 v0.5 확장 기능으로 계획됨, (3) release blocker 우선순위에서 제외됨. 엔트로피 부족 자체는 존재하나 강력한 해싱으로 실제 위험은 제한적이다.

**권고**
최소 길이를 12자 이상으로 상향하거나 복잡도 정책을 추가한다. NIST는 복잡도보다 길이 연장을 권고하므로 12자 이상이 최적이다.

---

### [MEDIUM] CRED-04 / STOR-03 — InMemoryMfaSecretVault TOTP 시크릿 평문 저장

- **심각도:** Medium (CRED-04) / Info (STOR-03 — 코드 결함이 아닌 배포 선택 문제)
- **위치:** `mfa.py:21-31`, `service.py:380-390`, `storage/sqlite.py:113`
- **표준:** NIST SP 800-63B 5.1.4/5.2.5, OWASP ASVS 2.4.5, CWE-312

**설명**
`InMemoryMfaSecretVault`가 TOTP 시크릿을 평문 dict에 저장하며(mfa.py:25, 28) `service.py:91`에서 기본값이다. 메모리 덤프/프로세스 탈취/스와프에서 시크릿 탈취가 가능하다. (VAULT-01과 동일 근본 원인이며, 본 항목은 평문 저장 자체의 데이터 노출 관점.)

**검증 결과**
코드 사실은 일치하나 다음 완화 요소로 심각도가 medium으로 조정된다: (1) `docs/production-roadblocks-roadmap.md:43`에서 프로덕션 사용 금지를 명시, (2) `SQLiteMfaSecretVault`/`RedisMfaSecretVault`(AES-256-GCM)가 실제 구현·테스트됨(test_production_adapters.py:27-73), (3) `__init__.py`에서 대체 구현을 공개 API로 export, (4) SECURITY.md 체크리스트 가이드 제공. 다만 환경 자동 감지·런타임 경고·deprecation warning이 부재하여 설정 오류 위험이 남는다. STOR-03 관점에서는 docstring에 개발 전용임을 명시하고 프로토콜로 암호화 구현 주입이 가능하므로 코드 결함이 아닌 배포 선택 문제(info)다.

**권고**
`InMemoryMfaSecretVault`를 deprecate하고 기본값을 `None`으로 변경하여 명시적 구성을 강제하거나, 프로덕션 감지 시 경고를 발생시킨다. docstring을 "Development only. Plaintext storage—NEVER use in production"으로 강화한다.

---

### [MEDIUM] ASYNC-PARITY-01 — 비동기 서비스: 패스워드 재설정 및 이메일 검증 미구현

- **심각도:** Medium
- **위치:** `async_service.py:1-259`
- **표준:** OWASP ASVS 4.0 2.4(Authentication API Architecture), Best Practice(동기/비동기 동등성)

**설명**
`AsyncCorelineAuthService`는 로그인·매직링크·세션 검증 등 기본 플로우만 구현하고 `request_password_reset`, `consume_password_reset`, `request_email_verification`, `consume_email_verification`이 빠져있다. 주석(async_service.py:44-48)에서 "코어 플로우만 의도적으로 제공"이라 명시되어 있으나, 프로덕션 비동기 저장소(PostgreSQL) 사용 시 패스워드 재설정·이메일 검증을 완전히 사용할 수 없다.

**코드 근거**
```
async_service.py 구현 현황:
- request_magic_link (127-140): 구현됨
- consume_magic_link (142-156): 구현됨
- issue_session (158-165): 구현됨
- verify_session (167-188): 구현됨
- request_password_reset / consume_password_reset: 없음
- request_email_verification / consume_email_verification: 없음
```

**검증 결과**
네 메서드의 부재가 확인되었다. 의도적 제한(44-48)이지만 프로덕션 PostgreSQL async 환경에서 핵심 인증 기능을 사용할 수 없는 실질적 제약을 의미하며, 문서화가 암묵적이라 마이그레이션 시나리오에서 놓치기 쉽다.

**권고**
누락된 4개 메서드를 동기 서비스와 동일 로직으로 구현하거나, 미구현 목록을 명확히 문서화하고 비동기 환경에서의 가이드를 제공한다.

---

### [MEDIUM] TOTP-REPLAY-01 — TOTP 리플레이 방어 race condition

- **심각도:** Medium
- **위치:** `service.py:397-410`, `service.py:404-406`
- **표준:** RFC 6238(TOTP), NIST SP 800-63B 5.1.5.2(Multi-Factor OTP Devices)

**설명**
`verify_totp`는 `last_used_counter`로 동일 카운터 리플레이를 차단하나(line 404-406), 카운터 체크(404)와 업데이트(407-408) 사이에 lock이 없어 동일 코드를 제출하는 동시 요청이 모두 검증을 통과할 수 있다. `step_up_totp`에서는 `verify_totp` 호출(414)과 세션 업데이트(416)가 분리되어 동시 요청 시 두 세션 모두 AAL2로 승격될 수 있다.

**코드 근거**
```python
# verify_totp
404: if factor.last_used_counter is not None and counter <= factor.last_used_counter: continue
407-408: updated = replace(factor, last_used_at=now_utc(), last_used_counter=counter)
         self.storage.update_mfa_factor(updated)
```

**검증 결과**
체크와 업데이트 사이 lock 부재로 동시 요청 취약성이 확인되었다. `totp_counter_for_code`(mfa.py:56-67)는 시간 기반 카운터를 반환하므로 같은 코드는 같은 카운터를 가지며, 두 요청이 동시에 factor를 읽고 체크를 통과하면 둘 다 업데이트한다. 대조적으로 복구코드는 `mark_recovery_code_used`에서 원자적 `UPDATE ... WHERE id=? AND used_at IS NULL`로 이를 방어한다. RFC 6238/NIST 5.1.5.2상 OTP는 일회용이어야 하나 동시 환경에서 보장이 깨진다. TOTP 윈도우(30초)·rate limiting·단일 세션 동시 step-up의 희소성으로 실제 악용이 제한적이어서 medium이다.

**권고**
TOTP 검증과 카운터 업데이트를 원자적 트랜잭션으로 처리하거나, 검증+상태 업데이트를 한 번에 수행하는 전용 메서드(`verify_and_consume_totp`)를 제공한다.

---

### [MEDIUM] AAL2-01 — AAL2 스텝업 이후 세션 재발급 메커니즘 없음

- **심각도:** Medium (검증 의견: High로 상향 가능)
- **위치:** `src/coreline_auth/service.py:412-418, 430-442`
- **표준:** OWASP ASVS 4.1.3(Reauthentication)

**설명**
`step_up_totp()`/`step_up_recovery_code()`가 세션의 `assurance_level`을 AAL1→AAL2로 변경하지만 세션 토큰 자체는 변경하지 않는다. AAL2 인증 전 토큰이 탈취된 경우 공격자도 동일 토큰으로 AAL2 리소스에 접근할 수 있다.

**코드 근거**
```python
def step_up_totp(self, session_token: str, *, code: str) -> Principal:
    principal = self.verify_session(session_token)
    factor = self.verify_totp(user_id=principal.user_id, code=code)
    updated_session = replace(principal.session, assurance_level=AuthAssuranceLevel.AAL2, last_seen_at=now_utc())
    self.storage.update_session(updated_session)  # 토큰 hash는 동일
    return Principal(user=principal.user, session=updated_session)
```

**검증 결과**
동일 `session_token_hash`를 유지하며 `assurance_level`만 변경됨이 확인되었다(`models.py:125`의 hash가 유일 식별자). `test_release_blockers_r5.py:38-55`에서도 step_up 후 동일 `issued.token`으로 `require_aal2`가 성공함을 확인할 수 있다. `require_aal2()`는 `assurance_level`에만 의존하므로 토큰 손상 시 보호가 작동하지 않는다. 토큰 탈취 가능성과 권장 방안(세션 고정 방지 재발급) 부재를 고려할 때 medium 이상이 타당하며, high로 상향도 보수적으로 정당하다.

**권고**
AAL2 스텝업 완료 후 새 세션을 발급하고 이전 토큰을 무효화한다: (1) `issue_session()` 호출로 새 토큰 생성, (2) 기존 세션 revoke, (3) 클라이언트에 새 토큰 반환. 세션 고정(Session Fixation) 공격을 방지한다.

---

### [MEDIUM] LOG-01 — MFA 실패 로깅 부재 및 감사 기록 제한

- **심각도:** Medium
- **위치:** `src/coreline_auth/service.py:397-410`
- **표준:** OWASP ASVS 4.1.2(Login Attempt Tracking), NIST SP 800-63B 7

**설명**
`verify_totp()`가 코드 불일치 실패 시 조용히 `continue`하며 로깅하지 않는다. 리플레이 차단 시에만 `_metric()`을 호출(405)하고, 일반 검증 실패는 추적되지 않아 브루트포스 MFA 공격 탐지·모니터링이 어렵다.

**코드 근거**
```python
def verify_totp(self, *, user_id: str, code: str) -> AuthMfaFactor:
    for factor in self.storage.list_mfa_factors(user_id):
        ...
        if counter is None:
            continue  # 조용한 실패, 로깅 없음
        if factor.last_used_counter is not None and counter <= factor.last_used_counter:
            self._metric("auth.mfa.totp_replay_blocked", {"factor_id": factor.id})
            continue
        ...
    raise AuthenticationFailed("invalid mfa code")  # 일괄 실패, context 없음
```

**검증 결과**
잘못된 코드 시 조용한 `continue`, 리플레이 탐지는 `_metric()`만 호출(`_audit()` 없음), 최종 실패는 generic 예외만 발생함이 확인되었다. `step_up_recovery_code()`도 "invalid recovery code" 예외 시 감사 로깅이 없다. 더 근본적으로 verify_totp/verify_totp_enrollment/step_up_recovery_code 모두 rate limiting이 없어(RLIM-02와 연계) 브루트포스에 취약하다.

**권고**
모든 MFA 검증 시도(성공/실패)를 감사 로그에 기록하고 실패 원인을 분류(invalid_code, replay_detected, invalid_factor)한다. 리플레이 시도는 높은 우선순위로 로깅하고, 반복 실패(브루트포스 패턴) 감지가 가능하도록 로그 구조를 설계한다.

---

### [MEDIUM] ENROLL-01 — TOTP 등록 시 중복 등록 방지 메커니즘 부재

- **심각도:** Medium
- **위치:** `src/coreline_auth/service.py:371-385`
- **표준:** OWASP ASVS 2.4.3(Authenticator Binding)

**설명**
`begin_totp_enrollment()`이 동일 사용자에 대해 여러 번 호출될 수 있으며, 매 호출마다 새로운 `enabled=False` MfaFactor를 생성한다. 미완료 등록이 누적되어 저장소·시크릿 저장소에 쓰레기가 남는다.

**코드 근거**
```python
def begin_totp_enrollment(self, user_id, *, name="Authenticator"):
    ...
    factor = AuthMfaFactor(id=f"mfa_{uuid4().hex}", ..., enabled=False)
    self.storage.create_mfa_factor(factor)  # 여러 번 호출 가능
    self.storage.mfa_secret_vault.store_totp_secret(factor_id=factor.id, secret=secret)
    return factor, secret
```

**검증 결과**
1명 사용자가 5회 연속 호출 시 5개의 미완료 인수가 누적되고 각각 시크릿이 저장됨이 확인되었다. `name` 파라미터는 중복 방지 역할을 하지 않으며, `cleanup_expired()`(sqlite.py:399-408, memory.py:164-181)는 세션·로그인 플로우만 정리하고 미완료 MFA 인수는 정리하지 않는다. 다만 `verify_totp_enrollment()`의 line 389 조기 반환(`enabled=True`)은 이미 활성화된 인수의 재등록을 방지하는 방어 기능이다. 직접 인증 우회는 아니며 리소스 누적·혼동 가능성이 주 우려이므로 medium이 적절하다.

**권고**
사용자당 최대 1개의 incomplete enrollment을 허용하도록 제한한다: 기존 `enabled=False` factor 재사용/삭제, 또는 enrollment_timeout(예: 15분) 설정으로 시간 초과 시 자동 정리한다.

---

### [MEDIUM] WAUTH-02 — credential 간 교차 사용 방지 로직 부재

- **심각도:** Medium (본래 제기 high에서 하향)
- **위치:** `webauthn.py:82, 93-94`
- **표준:** WebAuthn L2 §7.2(Authentication Ceremony), OWASP ASVS 2.4.5

**설명**
`verify_passkey_assertion_response()`가 `credential_id`를 not-empty 검사만 하고, 호출자가 제공한 credential_id와 저장된 credential의 소유권 매핑을 검증하지 않는다. credential 유효성·소유권 검증이 전적으로 호스트 책임이므로 호출자 실수 여지가 크다.

**코드 근거**
```python
# webauthn.py:93-94 — not-empty 검사만
if not credential_id:
    raise ...
# 저장된 credential과의 일치·현재 사용자 소유 여부 검증 없음
# line 120-122 — caller-provided public_key 기반 서명 검증만 수행
```

**검증 결과**
`verify_passkey_assertion_response()`는 설계상 암호화 검증 primitive이며 스토리지 책임 분리를 의도한다(docstring). WebAuthn L2 §7.2에서도 "userHandle 식별"·"저장된 credential 비교"는 relying party(host) 책임이다. 그러나 docstring이 너무 간결하여 호출자 책임(challenge binding, credential lookup)을 명시하지 않고, 호스트가 credential_id 매칭을 놓치면 스푸핑이 가능하다. 본래 high는 과장(실제 위험이 호스트 구현 오류에 의존)이며, coreline-auth 자체의 암호화 검증은 안전하므로 medium이 적절하다.

**권고**
API 설계를 재검토하여 `credential_id`/`expected_credential_id`를 명확히 분리하거나, docstring에 호스트가 반환된 credential_id를 실제 저장 credential과 비교해야 함을 명시한다.

---

### [MEDIUM] WAUTH-03 — 서명 알고리즘 협상(Algorithm Agility) 불충분(키 강도 미검증)

- **심각도:** Medium (본래 제기 high에서 하향)
- **위치:** `webauthn.py:145-154`
- **표준:** WebAuthn L2 §6.5.7, RFC 7515(JWS Algorithms)

**설명**
`_verify_signature()`가 공개키 유형에 따라 SHA256을 고정 선택하나, 예상 서명 알고리즘이나 키 강도(EC 곡선·RSA 키 길이)를 검증하지 않는다. 약한 곡선(SECP192R1) 또는 RSA 512-bit 같은 약한 키를 등록할 수 있다.

**코드 근거**
```python
# webauthn.py:147-150 — isinstance로 EC/RSA 분기, SHA256 고정
# _load_public_key (138-142), verify_passkey_registration_response (48-72)
#   — 곡선 강도·키 길이 검증 없음
```

**검증 결과**
SHA256 고정이므로 "MD5/SHA1로 서명" 부분은 거짓양성이다. 실제 위험은 키 강도 검증 부재로, EC 곡선·RSA 길이 검증이 없어 약한 키 등록이 가능하다. attestation object 파싱은 호스트에 위임(line 58-62)되나, coreline-auth가 최소한의 키 강도 검증(EC 곡선 화이트리스트, RSA 최소 길이)을 제공하는 것이 권장된다. 약한 곡선 사용에 특정 조건이 필요하고 일반 사용자는 플랫폼 기본값을 쓰므로 high가 아닌 medium이다.

**권고**
`verify_passkey_registration_response()`에 `expected_credential_alg`(예: ES256, RS256) 매개변수를 추가하고, EC 곡선 화이트리스트·RSA 최소 길이 검증으로 약한 키를 거부한다.

---

### [MEDIUM] WAUTH-04 — Sign counter 초기값 0일 때 단조성 검증 생략

- **심각도:** Medium
- **위치:** `webauthn.py:117-119`
- **표준:** WebAuthn L2 §6.5.9(Sign Count Verification)

**설명**
`previous_sign_count > 0` 조건으로만 sign counter 검증을 수행하여(line 118), 이전 카운트가 정확히 0일 때는 현재 카운트가 0이어도 통과한다. 첫 사용 후 저장 전 동일 assertion(sign_count=0) 재생이 가능하다.

**코드 근거**
```python
# webauthn.py:118
if previous_sign_count > 0 and sign_count <= previous_sign_count:
    raise ...
# line 56 — Registration 시 sign_count=0 기본값
```

**검증 결과**
WebAuthn L2 §6.5.9는 현재==0이고 저장값==0인 경우 검증 생략을 허용하므로 spec 준수다. 그러나 등록 시 sign_count=0 기본값이고 호스트가 첫 assertion 후 카운트를 미저장하면 동일 assertion(0→0) 재사용이 가능한 현실적 약점이 있다. 테스트(test_webauthn.py:32,39)는 sign_count=1부터 시작하여 이 엣지케이스를 다루지 않는다. 호스트 책임이면서도 모듈이 더 방어적일 수 있는 지점이다.

**권고**
조건을 `if sign_count <= previous_sign_count:`로 변경하여 0→0도 거부하거나, 등록 시 최소값 1을 강제한다. 대안으로 "previous_sign_count는 마지막 검증 카운트이며 첫 사용 시에도 0으로 설정되어야 함"을 명확히 문서화한다.

---

### [MEDIUM] CSRF-02 — 데모의 약한 시크릿 검사 우회 가능성 (allow_weak_dev_secret)

- **심각도:** Medium (데모/예제 한정 — 본래 검토상 high가 과장이며 명시적 opt-in 필요)
- **위치:** `src/coreline_auth/examples/saas_app.py:50`
- **표준:** OWASP ASVS 4.0 3.2.1, NIST SP 800-63B 5.1.4.2

**설명**
예제 앱의 `allow_weak_dev_secret=DEMO_MODE and settings.csrf_secret_configured` 로직이, 개발자가 `CORELINE_AUTH_DEMO_CSRF_SECRET`를 약한 값으로 설정하면 약한 시크릿을 수락할 수 있다.

**코드 근거**
```python
# saas_app.py:50
allow_weak_dev_secret=DEMO_MODE and settings.csrf_secret_configured
# csrf.py:65-69 _looks_weak_secret()가 'demo','test' 마커를 확인하나
# csrf.py:34-35에서 allow_weak_dev_secret=true 시 완전히 무시
```

**검증 결과**
본래 주장 일부는 부정확하다: 약한 시크릿 수용은 DEMO_MODE=true **이면서 동시에** `csrf_secret_configured=true`(환경변수 `CORELINE_AUTH_DEMO_CSRF_SECRET` 존재, config.py:26)여야 한다. 환경변수 미설정 시 `allow_weak_dev_secret=false`가 되어 약한 시크릿 검사가 항상 적용되며, 기본값은 `_load_or_create_demo_csrf_secret`(config.py:38-61)이 `generate_token()`으로 고품질 시크릿을 생성한다. 약한 시크릿 수용은 개발자가 약한 값을 명시적 opt-in해야만 가능하다. 따라서 high는 과장이며 설계 명확성 문제다. examples/ 데모 코드이므로 심사 규칙에 따라 심각도를 한 단계 낮춰 평가한다.

**권고**
DEMO_MODE와 약한 시크릿 허용을 분리하고, 약한 시크릿 허용은 별도 환경변수(`CORELINE_AUTH_ALLOW_WEAK_SECRET=1`)로 명시적 opt-in을 요구한다.

---

### [MEDIUM] CSRF-04 — CSRF 쿠키의 HTTPOnly 미설정 (XSS 시 JavaScript 읽기 가능)

- **심각도:** Medium
- **위치:** `src/coreline_auth/fastapi_adapter.py:120`
- **표준:** OWASP ASVS 4.0 4.8.3, CWE-614

**설명**
CSRF 토큰 쿠키가 `httponly=False`로 설정되어(line 120) JavaScript 접근을 허용한다(form-based 클라이언트 지원 목적). XSS 취약점이 있으면 공격자가 토큰을 읽어 double-submit 방어를 무효화할 수 있다.

**코드 근거**
```python
# fastapi_adapter.py:120
response.set_cookie(csrf_cookie_name, token.value, httponly=False,
                    secure=secure_cookies, samesite=csrf_cookie_samesite, path='/')
```

**검증 결과**
`httponly=False`는 의도적 설계(form UI 지원)임이 확인되었다. XSS 존재 시 JS가 쿠키를 읽어 `x-csrf-token` 헤더에 넣어 double-submit을 우회할 수 있다(기술적 사실). 다만 (1) XSS라는 별도 critical 취약점이 전제되어야 하고, (2) CSRF 방어 자체(double-submit 검증 fastapi_adapter.py:103-104, HMAC 서명 csrf.py:57)는 정상 작동하며, (3) httponly=False는 form-based UI의 legitimate 요구사항이다. 복합 공격 전제이므로 medium이며 권장 우선순위는 낮다.

**권고**
이중 방어 구현: (1) 가능하면 HTTPOnly=True로 보호하고 토큰을 응답 본문/별도 속성에서 읽도록 하거나, (2) 현 설계 유지 시 XSS 방어(CSP, auto-escaping)가 필수임을 명확히 문서화한다.

---

### [MEDIUM] RLIM-05 — IP 기반 레이트 리미팅 부재 및 X-Forwarded-For 우회 가능성

- **심각도:** Medium
- **위치:** `service.py:127-147`, `redis_rate_limit.py:35-46`
- **표준:** OWASP ASVS 2.3.1(Brute Force Controls), RFC 7239(Forwarded HTTP Extension)

**설명**
모든 레이트 리미팅 키가 이메일/사용자 기반이라, 한 IP에서 여러 계정으로 분산 공격하거나 여러 IP에서 한 계정을 공격할 수 있다. `RequestContext`에 IP가 있으나(models.py:189) 레이트 리미팅에 사용되지 않는다.

**코드 근거**
```python
# service.py:129 — 이메일 기반만: f'login:{hash_secret(normalized_email)}'
# async_service.py:107 동일
# models.py:188-190 — RequestContext.ip 필드 존재하나 _check_rate_limit()에서 미사용
```

**검증 결과**
`RequestContext.ip`가 존재하고 주요 진입점이 context를 받으나, 모든 `_check_rate_limit()` 호출(service.py:129,154,191,224; async_service.py:107,132)에서 `context.ip`가 사용되지 않음이 확인되었다. `request_magic_link()`는 context 파라미터조차 받지 않는다(service.py:149). RFC 7239·ASVS 2.3.1이 요구하는 이중 차원(IP+이메일) 제어가 없으므로 medium이 타당하다. 프록시 신뢰 헤더 설정 지침 부재도 복합 위험이다.

**권고**
주요 인증 진입점에서 context를 활용하여 IP 기반 키(또는 이메일+IP 조합)도 추가한다. X-Forwarded-For/CF-Connecting-IP 등 신뢰 프록시 헤더만 사용하도록 문서화한다.

---

### [MEDIUM] EMAIL-03 — SMTP 인증 정보 전달 시 TLS 검증 부분 조건부 실행

- **심각도:** Medium
- **위치:** `src/coreline_auth/email.py:162-167`
- **표준:** RFC 3207(SMTP STARTTLS), NIST SP 800-52 Rev. 2

**설명**
`use_tls=True`(기본값)일 때만 starttls()를 호출하고 `use_ssl=True`이면 SMTP_SSL을 사용하나, `use_tls=False, use_ssl=False` 조합도 가능하여 이 경우 평문으로 자격증명이 전송된다.

**코드 근거**
```python
# email.py:162-167
if self.use_ssl:
    smtp_context = smtplib.SMTP_SSL(...)
else:
    smtp_context = smtplib.SMTP(...)
if self.use_tls and not self.use_ssl:
    smtp.starttls(...)
if self.username is not None:
    smtp.login(self.username, self.password or "")
```

**검증 결과**
(1) `__init__`에서 use_tls/use_ssl 유효성 검증이 없고(라인 103-134), (2) `_send`에서 `use_tls=False, use_ssl=False` 조합이 기술적으로 가능하여 평문 SMTP로 자격증명이 전달됨(라인 157-166)이 확인되었다. RFC 3207, NIST SP 800-52r2 위반이며 MITM에 취약하다. 다만 기본값이 use_tls=True(포트 587)로 안전하고 위험한 조합은 개발자가 명시적으로 비활성화해야 하므로 medium이 타당하다.

**권고**
`__init__`에서 `if not use_tls and not use_ssl: raise ValueError('SMTP requires either use_tls or use_ssl')`로 평문 조합을 차단하거나, use_ssl=True(포트 465 SMTPS)를 기본값으로 변경한다.

---

### [MEDIUM] OAUTH-01 — redirect_uri 형식 검증 부재 및 정확한 일치 강제 미흡

- **심각도:** Medium (검증 의견: Low로 하향 가능 — 설정 위생 문제)
- **위치:** `connectors.py:27-28`
- **표준:** RFC 6749 §3.1.2.1, OWASP ASVS 4.0 5.1.5

**설명**
`OAuthConnector.__init__`에서 redirect_uri가 비어있지 않음만 확인하고, HTTPS 스키마·절대 경로·쿼리 파라미터 제약 등 형식 검증을 하지 않는다.

**코드 근거**
```python
# connectors.py:27-28 — not-empty 검사만, _normalize_provider_url 미적용
# connectors.py:86-112 exchange_code — 구성된 redirect_uri를 token endpoint로 그대로 전송
# 비교: connectors.py:149-152 — auth_url/token_url/userinfo_url은 _normalize_provider_url로 검증
```

**검증 결과**
`http://attacker.com/callback`, `https://app.com#fragment`, `https://user:pass@app.com/callback`, `https://app.com?existing=param`이 모두 수용됨이 확인되었다(RFC 6749 §3.1.2.1, ASVS 5.1.5 위반). 다만 (1) OAuth 제공자가 토큰 교환 시 서버 측에서 redirect_uri를 재검증하므로 잘못된 설정은 exchange_code에서 실패, (2) 토큰 누수·계정 탈취 벡터가 아닌 설정 오류 감지(위생) 문제, (3) 다른 provider URL은 검증하나 redirect_uri만 비일관적으로 미검증임을 고려할 때 low로 하향 가능하다.

**권고**
`OAuthProviderConfig` 생성 시 redirect_uri를 `_normalize_provider_url`로 검증하는 validator를 추가하고, 앱이 인입 redirect_uri 파라미터와 정확 일치 검증해야 함을 문서화한다.

---

### [MEDIUM] STOR-02 — 이메일 고유 제약의 대소문자 민감성 취약점 (SQLite)

- **심각도:** Medium (이중 방어 존재로 본래 high에서 하향)
- **위치:** `sqlite.py:36, 205`
- **표준:** OWASP ASVS 2.2.3(중복 계정 예방), RFC 5890(이메일 비교)

**설명**
SQLite의 `primary_email UNIQUE` 제약이 기본 BINARY 콜레이션으로 대소문자를 구분한다. 애플리케이션이 `lower()`로 정규화하나, 마이그레이션·직접 INSERT 시 대소문자 혼합 이메일이 별도 사용자로 등록될 수 있다.

**코드 근거**
```sql
-- sqlite.py:35-37 — COLLATE 절 없음 → 기본 BINARY 콜레이션
CREATE TABLE IF NOT EXISTS auth_users (id TEXT PRIMARY KEY, primary_email TEXT NOT NULL UNIQUE, ...)
-- sqlite.py:205 — WHERE primary_email = ? (email.lower()), 애플리케이션 정규화 의존
```

**검증 결과**
UNIQUE 제약이 COLLATE BINARY를 사용함은 사실이나, 현재 구현은 이중 방어를 갖춘다: (1) 서비스 계층 `.lower()`(service_support.py:59), (2) 저장소 계층 `.lower()`(sqlite.py:191,205,215). `test_core_auth.py:41`에서 대소문자 혼합 로그인이 작동함을 증명한다. 저장소 계층 `.lower()`까지 제거되거나 직접 SQL 조작이 있어야만 실제화된다. 다만 ASVS 2.2.3 관점에서 스키마 자체가 강제하는 것이 모범 사례이므로 high→medium으로 하향한다.

**권고**
`primary_email`에 `COLLATE NOCASE`를 추가하거나, 마이그레이션으로 테이블 재생성 시 정의를 변경한다. 또는 정규화 후 조회 결과의 대소문자 불일치를 감지·거부하는 로직을 추가한다.

---

### [MEDIUM] STOR-05 — PostgreSQL 대소문자 무시 이메일 조회 미구현

- **심각도:** Medium (애플리케이션 정규화 이중 방어 존재)
- **위치:** `postgres.py:110`
- **표준:** OWASP ASVS 2.2.3, RFC 5890

**설명**
PostgreSQL 어댑터가 email 조회 시 case-insensitive 처리를 명시하지 않는다. TEXT 타입 기본 콜레이션이 대소문자를 구분하므로, citext 확장이나 ICU 콜레이션 없이는 DB 수준 보장이 없다.

**코드 근거**
```python
# postgres.py:110 — 애플리케이션 lower()만
row = (await session.execute(select(auth_users).where(auth_users.c.primary_email == email.lower()))).mappings().first()
# sqlalchemy_schema.py:19 — Column('primary_email', Text, nullable=False, unique=True), COLLATE 없음
```

**검증 결과**
기술적 주장은 정확하나 심각도가 과장되었다. 모든 이메일이 애플리케이션 레이어에서 lowercase 정규화되어 저장·조회된다: `normalize_email()`(service_support.py)의 `strip().lower()`, 모든 생성 경로(bootstrap_owner, create_user)가 정규화된 이메일만 전달, `_user_values`(postgres.py:319) 저장 시 `.lower()`, `get_user_by_email`(line 110) 조회 시 `.lower()`, `list_users`(line 125) 검색에 `func.lower()`. 현재 구현에서는 중복 저장이 불가능하다. 다만 마이그레이션·향후 정규화 로직 제거 시 잠재 위험이므로 best practice 권고값은 유효하다.

**권고**
SQLAlchemy 스키마에서 citext 또는 ICU 콜레이션을 적용하거나, PostgreSQL 마이그레이션에서 `CREATE EXTENSION IF NOT EXISTS citext; ALTER TABLE auth_users ALTER COLUMN primary_email TYPE citext;`를 실행한다. 인덱스도 콜레이션을 통일한다.

---

### [MEDIUM] ERR-01 — 에러 응답에서 검증 규칙 메시지 노출

- **심각도:** Medium
- **위치:** `fastapi_adapter.py:112, 139, 165`, `fastapi_async_adapter.py:80`
- **표준:** OWASP Top 10 2021 A01, OWASP ASVS 4.3.3(민감 정보 노출 방지)

**설명**
`AuthValidationError`/`AuthenticationFailed`/`AuthorizationDenied`를 `str(exc)`로 변환하여 HTTP 응답으로 반환한다. 입력 검증 규칙(예: `password must be at least 8 characters`, `return_to must start with a single '/'`)이 노출되어 공격자가 시스템 구성을 추측할 수 있다.

**코드 근거**
```python
# fastapi_adapter.py:112
raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
# fastapi_adapter.py:139 — request_magic_link의 AuthValidationError도 400으로 detail=str(exc)
```

**검증 결과**
`AuthValidationError`/`AuthenticationFailed`/`AuthorizationDenied`를 `str(exc)`로 반환함이 확인되었다(lines 112,129,139,165, async:80). 다만 `AuthConfigurationError`(csrf.py:33-35)는 애플리케이션 시작 단계(saas_app.py:50)에서만 인스턴스화되어 HTTP 응답으로 노출되지 않으므로 본래 주장 일부는 부정확하다. CSRF 토큰 실패 메시지("invalid csrf token")는 정상 방어 메시지다. 더 실제적인 문제는 security.py/async_service.py의 입력 검증 규칙 메시지가 공격자에게 검증 정책을 노출하는 것이다. medium이 타당하다.

**권고**
`AuthValidationError`/`AuthConfigurationError` 메시지를 클라이언트에 노출하지 않는다. 로깅 후 generic 메시지(`'invalid request'`)를 반환하고, 설정 오류는 서버 시작 단계에서만 처리한다.

---

### [MEDIUM] CSRF-01(웹) — CSRF 보호 적용 명시성 부족, 설정 실수 위험

- **심각도:** Medium
- **위치:** `fastapi_adapter.py:75-79, 95-112`, `fastapi_async_adapter.py:43-46, 63-80`
- **표준:** OWASP ASVS 4.1.3(CSRF 보호), OWASP Top 10 2021 A01

**설명**
`mount_auth_routes()`의 `csrf_protector=None` 기본값으로 CSRF 보호가 비활성화될 수 있다. `require_csrf()`가 `csrf_protector==None` 시 조용히 반환하므로 설정 실수가 무시된다.

**코드 근거**
```python
# fastapi_adapter.py:75 — csrf_protector: CsrfProtector | None = None
# fastapi_adapter.py:96-97 — if csrf_protector is None: return  (조건부 활성화, 오류 없음)
# fastapi_adapter.py:125 login()에서 require_csrf(request) 호출하나 None이면 무동작
```

**검증 결과**
(1) `csrf_protector` 기본값 None(fastapi_adapter.py:75, async:43), (2) `require_csrf()`가 None일 때 조용히 건너뜀(96-97, async:64-65), (3) 예제 saas_app.py:50은 CsrfProtector를 생성하나 66-67의 mount 호출에서 전달하지 않아 비활성화, (4) 12개 이상 POST 엔드포인트가 require_csrf를 호출하나 None일 때 무효임이 확인되었다. 긍정적 측면: 기본값 None은 Bearer 토큰 API opt-out 의도(security-checklist.md:6)이고, Bearer 토큰 시 CSRF 스킵(99-100)은 올바른 설계이며, 테스트(test_fastapi_adapter.py:34-50)가 활성화 경로를 검증한다. 보안 메커니즘 부재가 아닌 "조용한 설정 실수" 문제이므로 medium이 정확하다.

**권고**
기본값을 필수 매개변수로 변경하거나, `csrf_protector=None`일 때 Warning 로그를 출력한다. cookie-backed 브라우저 폼 배포 시 csrf_protector 미전달이 진정한 위험이므로 문서화·경고를 강화한다.

---

### [MEDIUM] OBS-01 — LoggingMetricSink의 민감정보 누수 위험

- **심각도:** Medium
- **위치:** `observability.py:40-47`
- **표준:** OWASP Top 10 2021 A09, CWE-532

**설명**
`LoggingMetricSink.__call__`이 metric 이름과 values 딕셔너리 전체를 로깅 레코드 extra에 그대로 포함한다. 호스트가 부주의하게 민감정보(access_token 등)를 metric values에 포함시키면 필터링 없이 전파된다.

**코드 근거**
```python
# observability.py:47
self.logger.info("coreline_auth.metric", extra={"metric": name, "values": dict(values)})
```

**검증 결과**
values 딕셔너리가 필터링 없이 extra로 전달됨이 확인되었다. 다만 (1) coreline-auth 내부 호출은 모두 safe(service_support.py:35,68에서 retry_after_seconds, kind 등 비민감 값만 전달), (2) `LoggingMetricSink`는 호스트가 선택적으로 구성하는 공개 API이며 내부에서 사용하지 않음, (3) API 설계 결함이 아닌 호스트 운영 습관 문제, (4) 고위험 악용 경로 제한적임을 고려하여 medium이 적절하다.

**권고**
metric values 자동 마스킹 로직 추가(token/password/secret/key/authorization 포함 값을 `[REDACTED]`로 치환), 또는 명확한 문서화로 호스트가 민감정보를 metric에 포함시키지 않도록 강제한다.

---

### [MEDIUM] OBS-03 — ops_readiness.assert_secret_safe 함수의 불완전한 검증 로직

- **심각도:** Medium (검증 의견: Low로 하향 가능 — 정적 텍스트 대상, 활성 취약점 아님)
- **위치:** `ops_readiness.py:126-137`
- **표준:** OWASP ASVS 4.0 2.1.1, CWE-200

**설명**
`assert_secret_safe`가 readiness check의 present/missing 필드에 `=`가 있는지만 검증하고, `_SECRET_MARKERS`(PASSWORD, TOKEN, KEY, SECRET)를 포함하는 note를 검증하려 하지만 로직이 불완전하다. 라인 133-137의 for 루프가 marker를 찾으면 `continue`만 하고 아무 조치도 취하지 않는다.

**코드 근거**
```python
# ops_readiness.py:133-137 — marker가 note에 있으면 continue만, 실제 값 검출 로직 없음
# 주석: 'Notes can mention secret *concepts*, but not actual values'와 구현 불일치
```

**검증 결과**
for 루프가 marker 발견 시 `continue`만 하고 raise 로직이 없어 주석 의도와 불일치함이 확인되었다. 다만 (1) note 필드는 관리자가 작성하는 정적 하드코딩 텍스트(라인 79,86,93,100,107,120)이며 환경 변수 값에서 파생되지 않음, (2) 실제 시크릿 값 누출 1차 방어선인 `=` 검사(라인 130-132)는 작동, (3) 개념 언급은 실제 값을 포함하지 않으므로 실무 영향 제한적임을 고려하여 medium→low로 조정 가능하다. 주석-코드 로직 불일치(부실 구현)이지 활성 취약점은 아니다.

**권고**
로직을 명확히 하거나 제거: 의도가 "값 금지"라면 `=`/`:` 또는 숫자 시퀀스 포함 여부 추가 검증, 의도가 "marker 언급 금지"라면 `continue` 대신 `raise ValueError`, 검증이 불필요하면 제거한다.

---

## 참고(low/info) 항목

### 검증 완료 — 본래 medium에서 low로 하향

| ID | 서브시스템 | 제목 | 심각도 | 위치 | 표준 |
|----|-----------|------|--------|------|------|
| TOTP-01 | MFA/TOTP | TOTP 검증 윈도우 기본값 1단계(구성 불가, RFC 준수) | Low | mfa.py:52 | RFC 6238 §5.2, ASVS 2.4.4 |
| WAUTH-05 | WebAuthn | Registration attestation 파싱 책임 문서화 부족(코드는 안전) | Low | webauthn.py:48-72 | WebAuthn L2 §7.1 |
| CSRF-03 | CSRF | 데모 폼 미들웨어 Content-Type 검증 부재(실제 우회 없음) | Low(데모) | examples/saas_demo/csrf.py:31-51 | ASVS 4.8.2, CWE-345 |
| CSRF-05 | CSRF | 데모 전역 CSRF 토큰 만료 검증 부재(의도적 설계) | Low(데모) | examples/saas_demo/csrf.py:18-28 | ASVS 4.8.1 |
| AUTHZ-003 | 인가 | ANY_SCOPE/OWN_SCOPE 계층 문서화 부족(유지보수성) | Low | permissions.py:10-11, 129-130 | ASVS V4.1.2, RFC 6749 §3.3 |
| RLIM-04 | 레이트 리미팅 | max_buckets 도달 시 FIFO 제거(cleanup 이미 자동 호출, window=60s) | Low | rate_limit.py:43-45 | CWE-770 |
| RLIM-06 | 레이트 리미팅 | Redis 실패 시 동작(실제는 fail-closed 가용성 문제) | Low | redis_rate_limit.py:39-46 | ASVS 2.3.1, CWE-391 |
| EMAIL-02 | 이메일 | Magic Link 토큰 URL 노출(DB는 hash-only, 악용 난이도 높음) | Low | email.py:63-64 | NIST 5.2.5, RFC 6238 |
| OAUTH-02 | 소셜/OIDC | OIDC fetcher SSRF/사이즈 제한(URL 정책 이미 보호, 실제는 DoS/MIME) | Low | discovery.py:82-102 | ASVS 5.2.4, CWE-918 |
| STOR-01 | 저장소 | 메모리 저장소 불완전 동시성 제어(테스트/임베디드 전용) | Low | memory.py:77-241 | CWE-366, ASVS 2.10.3 |
| STOR-04 | 저장소 | 감사 로그 키 기반 필터링 한계(현 실행 패턴에서 미노출) | Low | audit.py:49-62 | ASVS 2.4.1, CWE-532 |
| STOR-07 | 저장소 | SQLite DB 파일 권한 미설정(배포 레이어 책임) | Low | sqlite.py:145-153 | ASVS 2.1.9, CWE-276 |
| OBS-02 | 관측성 | JsonLineSecurityEventSink 필터링 부재(현 메트릭은 비민감) | Low | observability.py:81-105 | A09:2021, CWE-532 |
| CRED-01 | 패스워드 | hash_secret SHA256 토큰/패스워드 혼용(이미 함수 분리됨) | Info | security.py:25-26 | NIST 5.1.1.1, CWE-327 |

### 미검증 단일 분석 low/info 항목 (방어 심화 권고)

| ID | 서브시스템 | 제목 | 위치 |
|----|-----------|------|------|
| CRED-03 | 패스워드 | SecretEnvelopeProtector nonce 재사용/키 회전 정책 문서화 부족 | encryption.py:40-43 |
| CRED-05 | 패스워드 | hash_secret() 입력 검증 부족(빈 문자열/None) | security.py:25-26 |
| CRED-06 | 패스워드 | TOTP 시크릿 20바이트(160비트), 현대 권고 256비트 미만 | mfa.py:34-35 |
| CRED-07 | 패스워드 | recovery code 고정 20자 길이 공개 | mfa.py:38-39 |
| CRED-08 | 패스워드 | AAD에 factor_id만 사용, user_id 미포함(재할당 방어) | mfa_vault.py:43-45, 85 |
| CRED-09 | 패스워드 | 패스워드 재설정 이메일 발송 실패 처리 피드백 부족 | service.py:234-237 |
| CRED-10 | 패스워드 | SHA256을 이메일/IP/UA 등 PII 해싱에도 사용 | security.py:33-34 |
| SESS-02 | 세션 | AAL2 업그레이드 후 세션 갱신 시 중복 터치 | service.py:412-418, 430-442 |
| SESS-03 | 세션 | session_touch_interval=0 시 매 검증마다 DB 업데이트 | service.py:334-342 |
| SESS-04 | 세션 | IssuedSession.token 반환 후 클라이언트 보관 위험 문서화 | service.py:320 |
| TOTP-02 | MFA | totp_code() 외부 노출, 타이밍 분석 가능성 | mfa.py:42-49 |
| TOTP-03 | MFA | TOTP 입력 정규화 후 검증 명확성 | mfa.py:56-59 |
| VAULT-02 | MFA | SQLiteMfaSecretVault factor_id 불변 가정 의존 | mfa_vault.py:44-45, 85 |
| VAULT-03 | MFA | RedisMfaSecretVault TTL 부재로 영구 저장 | mfa_vault.py:84-94 |
| CRYPTO-01 | MFA | TOTP 시크릿 Base32 패딩 제거/복원 엣지케이스 | mfa.py:35 |
| PROTO-01 | MFA | load_totp_secret() None 반환 의미 모호(not_found vs decrypt_error) | mfa.py:16-18 |
| TEST-01 | MFA | TOTP 시간 윈도우 경계 케이스 테스트 미비 | tests/test_mfa_groundwork.py |
| WAUTH-06 | WebAuthn | transports/residentKey 등 확장 필드 미지원 | webauthn.py:48-123 |
| WAUTH-08 | WebAuthn | Base64url 디코딩 padding 오류 처리 미흡 | webauthn.py:167-168 |
| CSRF-08 | CSRF | 데모 미들웨어 다중 값 CSRF 토큰 처리 예측 불가 | examples/saas_demo/csrf.py:40 |
| AUTHZ-004 | 인가 | _candidate_requirements() 인지 복잡도 | authorization.py:132-156 |
| RLIM-07 | 레이트 리미팅 | 고정 60초 윈도우 설정 경직성 | service_support.py:32-34 |
| RLIM-08 | 레이트 리미팅 | password_reset 미존재 사용자도 레이트 소비(부분 열거 노이즈) | service.py:222-239 |
| EMAIL-04 | 이메일 | 이메일 발송 에러 로깅 민감도(현재 type만 기록, 안전) | service_support.py:64-69 |
| EMAIL-05 | 이메일 | InMemoryEmailSender 토큰 원문 저장(테스트 전용) | email.py:78-93 |
| OAUTH-03 | 소셜/OIDC | JWKS 캐시 TTL 1시간 기본값(긴급 key rotation 지연) | discovery.py:54 |
| OAUTH-04 | 소셜/OIDC | ID 토큰 nonce 검증 선택적(require_nonce 옵션 권장) | verification.py:122-126 |
| OAUTH-06 | 소셜/OIDC | JWK use/key_ops 미검증(kty만 검증) | verification.py:170-171 |
| STOR-06 | 저장소 | Protocol 런타임 미강제(parametrized 적합성 테스트 권장) | memory.py:33-53, protocols.py:41-48 |
| STOR-08 | 저장소 | PostgreSQL 타임존/마이크로초 버림 처리 | postgres.py:46-55 |
| STOR-09 | 저장소 | 세션 토큰 해시 비교 일회성 설명 부족(DB WHERE는 안전) | sqlite.py:84, postgres.py:79 |
| AUTH-01 | FastAPI | require_session/permission의 AuthValidationError 미처리 | fastapi_adapter.py:223-246 |
| INFO-01 | FastAPI | session.expires_at 응답 노출(세션 TTL 정책 노출) | fastapi_adapter.py:131, 153, 425 |
| ASYNC-01(어댑터) | FastAPI | 비동기 어댑터에서 sync csrf_protector 호출 | fastapi_async_adapter.py:76-78 |
| DOC-01 | FastAPI | require_permission 반환 타입 힌트/docstring 부족 | fastapi_adapter.py:235-246 |

---

## 서브시스템별 평가

### 1. 패스워드/시크릿 해싱 & 자격증명 관리
**요약:** Argon2id 강력 해싱, SHA256+HMAC 토큰 검증, AES-256-GCM 암호화, 타이밍 공격 방어, 해시 전용 저장 원칙이 잘 구현되어 있다.
**강점:** Argon2id 적절 파라미터(time_cost=3, memory_cost=65536, parallelism=4, salt_len=16) [security.py:17] · `hmac.compare_digest` 타이밍 방어 [security.py:29-30] · `verify_dummy_password` 열거 방어 [security.py:50-57] · 세션 토큰 hash-only 저장 [service.py:313-320] · 동일 에러 메시지로 정보 유출 방지 [service.py:127-147] · 마스터 키 32바이트 검증 [encryption.py:25-32]
**주요 리스크:** CRED-02(패스워드 8자 정책) · CRED-04(InMemoryMfaSecretVault 평문 기본값) · CRED-03/05/06/07/08/10(엔트로피·검증·AAD·PII 해싱 방어 심화)

### 2. 세션 & 토큰 수명주기 관리
**요약:** 세션 토큰 SHA256 해시 저장, 절대/유휴 타임아웃, 로그인 시 세션 고정 방지, 패스워드 변경 시 세션 회수가 구현되어 ASVS 4.0/NIST 기준에 부합한다.
**강점:** 매 발급 시 새 ID/토큰 생성·hash-only 저장(CWE-522 방지) [service.py:313-320] · 절대+유휴 타임아웃 [service.py:327-328] · 패스워드 변경 시 세션 회수 [service.py:255-257] · HttpOnly/Secure/SameSite=Lax 쿠키 [fastapi_adapter.py:82-83] · 256비트 토큰 [security.py:21-22]
**주요 리스크:** AAL2-01(스텝업 후 세션 재발급 부재) · SESS-02/03/04(중복 터치, 0 인터벌 성능, 토큰 보관 문서화)

### 3. 핵심 인증 플로우 (로그인/가입/재설정/매직링크/락아웃)
**요약:** 핵심 플로우는 Argon2 해싱·SHA256 토큰·레이트 리미팅·감사 로깅을 갖추나, 비동기 서비스 불완전 구현과 재설정 토큰 1회성 보장 부족이 핵심 리스크다.
**강점:** 타이밍 방어 `verify_dummy_password` [service.py:132-143] · 로그인 플로우 TTL 10분 [service.py:53] · 재설정 시 세션 폐지 [service.py:255-257] · return_to 오픈 리다이렉트 방어 [security.py:64-72] · 플로우별 독립 레이트 리미팅 [service.py:129,154,191,224] · 전 플로우 감사 기록
**주요 리스크:** ASYNC-01(AAL 누락) · PASS-RESET-01(비동기 1회성 미보장) · ASYNC-PARITY-01(재설정/이메일검증 미구현) · TOTP-REPLAY-01(리플레이 race condition)

### 4. MFA / TOTP & 복구코드
**요약:** RFC 6238 TOTP, AES-256-GCM 시크릿 저장, 리플레이 방어를 제공하나, 검증 경로 레이트 리미팅 부재와 복구코드 엔트로피 부족이 핵심 결함이다.
**강점:** RFC 6238 정확 구현(HMAC-SHA1, Dynamic Truncation) [mfa.py:42-49] · AES-256-GCM 시크릿 암호화 [mfa_vault.py:44-45] · `last_used_counter` 리플레이 방어 [service.py:404-406] · 복구코드 원자적 1회성 `mark_recovery_code_used` [service.py:436] · AAL2 스텝업/가드 [service.py:412-449] · 로드 시크릿 해시 검증 [service.py:463]
**주요 리스크:** REC-01(복구코드 120비트) · VAULT-01(시크릿 저장 암호화 선택사항) · RLIM-02(MFA 경로 미보호) · AAL2-01 · LOG-01 · ENROLL-01 · TOTP-REPLAY-01

### 5. WebAuthn / 패스키
**요약:** challenge 1회성, origin/RP ID 검증, 서명 검증, sign counter 재생 감지 등 핵심 검증 primitive는 적절하나, API가 호스트에 과도한 책임을 넘겨 오류 가능성을 높인다.
**강점:** challenge/RP ID 해시 `hmac.compare_digest` [security.py:30, webauthn.py:108] · origin/RP ID HTTPS 강제(localhost 예외) [webauthn.py:132-135] · sign counter 단조성 검증 [webauthn.py:118-119] · EC/RSA + SHA256 고정 · private key 미저장, PEM 공개키만 수락 [webauthn.py:69,82]
**주요 리스크:** WAUTH-02(교차 사용 방지 부재) · WAUTH-03(키 강도 미검증) · WAUTH-04(sign counter 0 단조성 생략) · WAUTH-05/06/08(문서화·확장·디코딩 처리)

### 6. CSRF 방어
**요약:** HMAC-SHA256 이중 제출 패턴과 세션 바인딩으로 견고하나, 토큰 명시적 만료 부재가 핵심 리스크다.
**강점:** HMAC-SHA256 + `compare_digest` [csrf.py:57] · 고엔트로피 nonce [security.py:22] · 시크릿 최소 32자 강제 [csrf.py:32] · 약한 시크릿 탐지 [csrf.py:65-69] · 세션 해시 바인딩 [fastapi_adapter.py:85-93] · Bearer 토큰 CSRF 스킵 [fastapi_adapter.py:98-100] · SameSite=strict 기본값 [fastapi_adapter.py:77]
**주요 리스크:** CSRF-01(만료 부재) · CSRF-04(HTTPOnly 미설정) · CSRF-02(데모 약한 시크릿) · CSRF-03/05/08(데모 미들웨어)

### 7. 인가 / 권한 / 관리자
**요약:** RBAC·다중 권한 프로필·기본 거부 원칙·마지막 특권 계정 보호가 잘 설계되었으나, `_permission_matches`의 와일드카드 스코프 우회가 치명적 결함이다.
**강점:** `actor_active` 비활성 사용자 거부 [authorization.py:54-59] · 권한 검증 전 비활성 확인(defense-in-depth) [authorization.py:70-99] · OWN_SCOPE 계층적 후보 구성 [authorization.py:132-156] · 마지막 특권 계정 보호 [admin.py:100-104] · 자기 계정 ban/disable 차단 [admin.py:40-41, 60-61] · 엄격한 PermissionStatement 파싱 [permissions.py:56-65]
**주요 리스크:** **AUTHZ-001(critical 와일드카드 스코프 우회)** · AUTHZ-003/004(문서화·복잡도)

### 8. 레이트 리미팅 / 브루트포스 방어
**요약:** 고정 윈도우 레이트 리미팅(프로세스 로컬 + Redis 분산)을 주요 인증 경로에 적용하나, MFA 경로 미보호와 IP 기반 제어 부재가 리스크다.
**강점:** 프로세스 로컬 scope 명시 [rate_limit.py:34] · Redis Lua 원자성(TOCTOU 방지) [redis_rate_limit.py:21-33] · 주요 인증 경로 전반 적용 [service.py:129,154,191,224] · 레이트 키 해시 보호 [security.py:25-26] · max_buckets 제한 [test_supporting_features.py:47-57]
**주요 리스크:** RLIM-02(MFA 경로 미보호, high) · RLIM-05(IP 기반 부재) · RLIM-04/06/07/08(FIFO·fail-closed·윈도우·열거 노이즈)

### 9. 이메일 발송 & 검증 흐름
**요약:** 토큰 hash-only 저장, SMTP 헤더 인젝션 방어, 발송 실패 best-effort 처리, 오픈 리다이렉트 방어가 NIST/OWASP 원칙을 따른다.
**강점:** 전 토큰 hash-only 저장 [service.py:157,194,230] · EmailMessage로 헤더 인젝션 방어 [email.py:149-167] · 발송 실패 시 타이밍 방어 [service_support.py:64-69] · return_to 오픈 리다이렉트 방어 [security.py:61-72] · 감사 민감정보 마스킹 [audit.py:10-62] · 이메일 소문자 정규화 [service_support.py:58-62]
**주요 리스크:** EMAIL-03(SMTP TLS 조건부, medium) · EMAIL-02/04/05(토큰 URL 노출·로깅·테스트 sender)

### 10. 소셜 로그인 / OAuth2 / OIDC
**요약:** OAuth2 코드 흐름과 OIDC ID 토큰 검증을 구현하며 RS256 강제·PKCE S256 등 강점이 명확하나, redirect_uri 형식 검증 부재가 위생 문제다.
**강점:** RS256 하드코딩, alg none/HS256 거부 [verification.py:64-65] · iss/aud/exp/iat/nbf 검증 [verification.py:72-120] · PKCE RFC7636 준수 [models.py:97-101, _utils.py:118-127] · 발급자 매칭 강제 [connectors.py:181] · 토큰 redaction [_utils.py:62-64] · JWKS kid-miss 재갱신 [discovery.py:69-78]
**주요 리스크:** OAUTH-01(redirect_uri 검증) · OAUTH-02/03/04/06(SSRF/DoS·캐시 TTL·nonce·JWK use)

### 11. 저장소 계층 보안
**요약:** SQLite/PostgreSQL/메모리 어댑터가 파라미터화 쿼리·감사 필터링·해시 저장을 구현하나, 이메일 콜레이션·MFA 평문 저장·메모리 동시성이 리스크다.
**강점:** 파라미터 바인딩 SQL 인젝션 방어 [sqlite.py:184-191, postgres.py:98] · Argon2 강제 [security.py:17] · 감사 키 기반 마스킹 [audit.py:10-62] · 토큰 해시 저장 [sqlite.py:84] · 이메일 정규화 [sqlite.py:191, postgres.py:319] · 부분 인덱스로 활성 credential 중복 방지 [sqlite.py:66-68] · 감사 메타데이터 크기 제한 DoS 방지 [audit.py:11-14]
**주요 리스크:** STOR-02/05(이메일 콜레이션) · STOR-03(MFA 평문, info) · STOR-01/04/07/08/09(동시성·필터링·파일권한·타임존)

### 12. FastAPI 어댑터 (동기/비동기)
**요약:** 쿠키 플래그·더블 서밋 CSRF·Bearer 지원의 현대적 설계로 인증 우회 가능성 없이 견고하나, 에러 메시지 노출과 CSRF 설정 명시성이 리스크다.
**강점:** HttpOnly 강제 [fastapi_adapter.py:83] · Secure 기본 True [fastapi_adapter.py:73] · SameSite=lax [fastapi_adapter.py:83] · 더블 서밋 CSRF [fastapi_adapter.py:103] · Bearer CSRF 면제 [fastapi_adapter.py:99-100] · 계정 열거 방어 [fastapi_adapter.py:160-163] · 만료/revoked 종합 검증 [service.py:325-328]
**주요 리스크:** ERR-01(검증 메시지 노출) · CSRF-01 웹(설정 실수) · AUTH-01/INFO-01/ASYNC-01/DOC-01(예외 처리·정보 노출·async·문서)

### 13. 관측성 / 운영 준비 / 감사
**요약:** secret-safe 설계 철학과 감사 메타데이터 자동 마스킹을 구현하나, 일부 sink의 PII 누수 위험과 assert_secret_safe 불완전 로직이 리스크다.
**강점:** MetricSink 프로토콜 exporter-neutral 설계 [observability.py:18] · JSONL append-only + RLock [observability.py:81-105] · redact_audit_metadata 마스킹 + 크기 제한 [audit.py:33-62] · Prometheus 고정 메트릭(카디널리티 공격 방지) [observability.py:50-78] · audit 2중 방어 [service_support.py:79-80]
**주요 리스크:** OBS-01(LoggingMetricSink 누수) · OBS-03(assert_secret_safe 로직) · OBS-02(JsonLine 필터링, low)

---

## 우선순위 개선 로드맵

### 즉시 (Release Blocker — 프로덕션 배포 전 필수)
- [ ] **AUTHZ-001 (Critical):** `permissions.py:118-119` 와일드카드 검증을 스코프 검증 다음으로 이동하거나, 와일드카드 경로에서도 스코프 호환성 검증을 강제한다. 회귀 테스트(`test_permission_matches_wildcard_respects_scope`) 추가.
- [ ] **RLIM-02 (High):** `step_up_totp`/`step_up_recovery_code` 초반에 `_check_rate_limit()`(user_id 기반, limit≈5) 추가. MFA 브루트포스 시도가 차단되는지 테스트.
- [ ] **REC-01 (High):** 복구코드 엔트로피를 ≥160비트로 상향(`generate_token()[:27]` 이상). 엔트로피 검증 테스트 추가.
- [ ] **VAULT-01 / CRED-04 (High/Medium):** `mfa_secret_vault` 기본값을 `None`으로 변경하여 명시적 구성을 강제하거나, `InMemoryMfaSecretVault` 사용 시 초기화 경고를 발생시킨다.
- [ ] **PASS-RESET-01 / ASYNC-PARITY-01 (High/Medium):** 비동기 서비스에 `request_password_reset`/`consume_password_reset`/`request_email_verification`/`consume_email_verification`을 구현하고, 비동기 저장소 1회성 보장(트랜잭션 격리)을 명시한다.

### 단기 (다음 마이너 릴리스)
- [ ] **CSRF-01 (High):** CSRF 토큰에 발급 시간 포함 + 만료 검증(세션 수명 동기화) 추가.
- [ ] **ASYNC-01 (High):** 비동기 `issue_session`에 `assurance_level=AAL1` 명시 + 비동기 AAL2 스텝업 구현.
- [ ] **AAL2-01 (Medium/High):** AAL2 스텝업 후 세션 토큰 재발급 + 기존 토큰 무효화(세션 고정 방지).
- [ ] **TOTP-REPLAY-01 (Medium):** TOTP 검증+카운터 업데이트를 원자적 트랜잭션으로 처리(`verify_and_consume_totp`).
- [ ] **RLIM-05 (Medium):** 인증 진입점에 IP 기반(또는 IP+이메일) 레이트 리미팅 키 추가 + 신뢰 프록시 헤더 문서화.
- [ ] **EMAIL-03 (Medium):** `SmtpEmailSender.__init__`에서 `use_tls=False, use_ssl=False` 조합을 ValueError로 차단.
- [ ] **ERR-01 (Medium):** 클라이언트 에러 응답을 generic 메시지로 통일, 검증 규칙·설정 메시지 노출 제거.
- [ ] **CSRF-01 웹 (Medium):** cookie-backed 배포 시 `csrf_protector` 미전달에 대한 경고/문서화 강화.

### 중기 (보안 강화 및 표준 정합성)
- [ ] **CRED-02 (Medium):** 패스워드 최소 길이 12자 상향 + 침해 패스워드 검사 훅(v0.5 계획 항목).
- [ ] **WAUTH-02/03/04 (Medium):** credential 소유권 검증 가이드 명시, `expected_credential_alg` + 키 강도 검증, sign counter 0→0 거부.
- [ ] **STOR-02/05 (Medium):** SQLite `COLLATE NOCASE` / PostgreSQL citext로 DB 수준 이메일 고유성 강제.
- [ ] **ENROLL-01 (Medium):** 사용자당 incomplete enrollment 1개 제한 + enrollment timeout 정리.
- [ ] **OBS-01/03 (Medium):** LoggingMetricSink/JsonLineSecurityEventSink에 마스킹 적용, `assert_secret_safe` 로직 정정/제거.
- [ ] **OAUTH-01/03/04/06 (Medium/Low):** redirect_uri validator, JWKS TTL 단축·무효화 API, `require_nonce` 옵션, JWK use/key_ops 검증.
- [ ] **CSRF-04 (Medium):** HTTPOnly 강화 검토 또는 XSS 방어(CSP) 필수 문서화.
- [ ] **LOG-01 (Medium):** MFA 검증 실패 분류 로깅으로 브루트포스 패턴 탐지 가능화.
- [ ] **방어 심화 (Low/Info):** TOTP 시크릿 256비트 상향, AAD에 user_id 포함, Redis 시크릿 TTL, 메모리 저장소 락 정합, 파일 권한 등.

---

## 종합 결론

coreline-auth 0.5.0rc1은 **암호학적 기본기(Argon2id, AES-256-GCM, 상수 시간 비교, 해시 전용 저장)와 보안 설계 원칙(기본 거부 인가, 타이밍 공격 방어, 오픈 리다이렉트 방어, 감사 마스킹)이 동급 모듈 대비 견고한 수준으로 구현**되어 있다. 13개 서브시스템 전반에 걸쳐 광범위한 강점이 코드 레벨로 확인되었으며, 적대적 검증을 통해 다수의 본래 high 제기 항목이 거짓양성 또는 medium/low로 정정되었다 — 이는 핵심 라이브러리의 방어가 실제로 작동하고 있음을 방증한다.

**그러나 현재 상태로 프로덕션 배포는 권장하지 않는다.** 단일 **critical 인가 우회(AUTHZ-001)** 가 권한 모델의 근본 무결성을 깨뜨리며, 행동 와일드카드를 사용하는 권한 구성이 존재하는 한 스코프 제약이 무력화된다. 이 결함만으로도 release blocker이다. 추가로 **6건의 high 결함** — MFA 검증 경로 브루트포스 노출(RLIM-02), 복구코드 엔트로피 미달(REC-01), 시크릿 저장 평문 기본값(VAULT-01), 비동기 서비스 기능 격차 및 토큰 1회성 미보장(ASYNC-01, PASS-RESET-01), CSRF 토큰 만료 부재(CSRF-01) — 은 프로덕션 환경, 특히 비동기 PostgreSQL 배포에서 실질적 보안·기능 위험을 초래한다.

**프로덕션 적합성 판단:**
- **동기(sync) + 암호화 vault + CSRF protector 명시 구성** 시에는 위 즉시/단기 항목(특히 AUTHZ-001, RLIM-02, REC-01, VAULT-01)을 해결한 후 **조건부 적합**.
- **비동기(async) PostgreSQL 배포**는 패스워드 재설정·이메일 검증·AAL2 기능 격차가 해소되기 전까지 **부적합**.

**권고 경로:** 로드맵의 "즉시" 5개 항목(AUTHZ-001, RLIM-02, REC-01, VAULT-01/CRED-04, PASS-RESET-01/ASYNC-PARITY-01)을 0.5.0 정식 릴리스 전 필수 수정 대상으로 지정하고, 회귀 테스트를 동반하여 해결할 것을 강력히 권고한다. "단기" 항목 완료 시 일반적인 cookie-backed 웹 및 Bearer API 배포 시나리오 모두에서 ASVS 4.0 Level 2 수준의 인증 모듈로 평가될 수 있다.