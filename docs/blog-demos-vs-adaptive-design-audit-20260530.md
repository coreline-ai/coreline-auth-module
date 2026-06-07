# blog-demos vs adaptive-html-v2 디자인 품질 차이 분석

작성일: 2026-05-30
대상:

- `blog-demos/*.html`
- `adaptive-html-v2-showcase/*.html`
- `adaptive-html-v2-rich-showcase/*.html`
- `~/.codex/skills/adaptive-html-blog-writer-v2`
- `~/.codex/skills/html-for-beginners`

## 결론

`blog-demos`의 디자인 품질이 더 좋아 보이는 핵심 이유는 “같은 스킬의 랜덤 차이”가 아니라, 실제로는 **서로 다른 디자인 시스템을 상속하고 있기 때문**이다.

`blog-demos`는 `html-for-beginners` 스킬의 editorial learning template와 거의 동일한 시각 언어를 사용한다. 반면 `adaptive-html-blog-writer-v2` 출력물은 v2의 `theme.css`, `components.css`, `layouts.css`를 상속한다. v2는 7개 모드 정보 구조는 갖췄지만, 시각 시스템은 더 일반적이고 템플릿적인 편이다.

따라서 보강 방향은 명확하다.

> `adaptive-html-blog-writer-v2`의 7개 모드 구조는 유지하되, 시각 토큰과 컴포넌트 문법은 `blog-demos/html-for-beginners` 계열의 editorial design system으로 승격한다.

## 관찰 요약

| 항목 | blog-demos | adaptive-html-v2 | 영향 |
|---|---|---|---|
| 디자인 정체성 | 기술 매거진/학습지 느낌 | 범용 카드형 문서 느낌 | blog-demos가 더 의도적으로 보임 |
| 폰트 | Pretendard Variable + Noto Serif KR 외부 로드 | 시스템 fallback 중심 | blog-demos 제목/본문 질감이 좋음 |
| H1 | 36px, line-height 1.35 | 최대 58px, line-height 1.08 | v2는 한국어 긴 제목에서 과하게 크고 뭉침 |
| 본문 폭 | 780px | 760px/980px | 둘 다 적절하지만 blog-demos 리듬이 더 안정적 |
| 섹션 리듬 | h2 margin-top 64px + h2-sub | section margin 38px 일괄 | blog-demos가 읽는 호흡이 좋음 |
| 컴포넌트 의미 | term/analogy/danger/good에 label/word/meaning 있음 | box 색상만 다르고 내부 구조 약함 | blog-demos가 정보 역할이 더 명확 |
| Hero box | 흰 카드 + 좌측 accent | 검정 박스 + 큰 그림자 | v2는 초반 시각 무게가 과함 |
| 강조 장치 | 형광 하이라이트 `.hl`, 빨강 배지 `.t` | 거의 없음 | blog-demos가 본문 집중점이 좋음 |
| 출처 처리 | 작고 조용한 source-note | 큰 source-box와 링크 대량 노출 | v2는 본문 마지막이 산만해짐 |
| SEO 문서성 | JSON-LD, index/follow | noindex/nofollow, JSON-LD 없음 | blog-demos가 공개 블로그 완성품에 가까움 |

## 정량 비교 예시

대표 beginner 문서 기준:

| 지표 | blog-demos beginner | adaptive v2 beginner | adaptive rich beginner |
|---|---:|---:|---:|
| HTML 길이 | 20,780 chars | 5,095 chars | 10,145 chars |
| 본문 텍스트 | 6,713 chars | 1,865 chars | 3,945 chars |
| h2 개수 | 6 | 6 | 8 |
| 고유 class 수 | 25 | 19 | 23 |
| 외부 폰트 링크 | 3 | 0 | 0 |
| JSON-LD | 1 | 0 | 0 |
| CSS rule | 92 | 84 | 91 |
| keyframes | 1 | 0 | 0 |
| border-left emphasis | 7 | 4 | 4 |

핵심은 CSS 양의 문제가 아니다. v2도 CSS rule 수는 충분하다. 차이는 **토큰의 질, 컴포넌트의 의미, 타이포그래피 리듬, 출력 규칙의 엄격도**에서 발생한다.

## 원인 분석

### 1. blog-demos는 `html-for-beginners` 디자인 시스템을 사용한다

`blog-demos` HTML에는 다음 특징이 반복된다.

- `--bg:#f5f5f0`
- `--accent:#e63946`
- `Pretendard Variable`
- `Noto Serif KR`
- `.h2-sub`
- `.hl`, `@keyframes hl-sweep`
- `.term .label/.word/.meaning`
- `.hero-analogy` 흰 카드 + 좌측 빨강 테두리

이 값과 구조는 `~/.codex/skills/html-for-beginners/assets/template.html` 및 `references/design-system.md`와 일치한다.

### 2. adaptive v2는 정보 구조 중심이고, 시각 품질 규칙이 얕다

`adaptive-html-blog-writer-v2/SKILL.md`는 7개 모드별 필수 블록을 잘 정의한다.

- beginner: hero analogy, terms, traps, practice
- expert: summary grid, risk matrix, roadmap
- article: lead, pull quote, argument
- education: goals, practice, quiz
- blog: hook, personal view
- seo: SERP, title/meta/tag
- platform: platform cards

하지만 시각 품질에 대해서는 다음 정도만 있다.

- 공통 CSS 상속
- h1 1개
- 모바일 1컬럼
- 외부 JS 금지
- 컴포넌트 3개 이상

즉, v2는 “무엇을 넣을지”는 잘 말하지만 “어떤 밀도와 리듬으로 보여줄지”는 약하다.

### 3. v2 theme 자체가 editorial보다 SaaS/card 문법에 가깝다

v2 `theme.css`에는 다음 특징이 있다.

- `h1: clamp(34px, 6vw, 58px)`
- `line-height: 1.08`
- `radial-gradient` 배경
- 큰 radius `22px`
- `box-shadow`
- `.hero-analogy` dark hero

이 조합은 긴 한국어 블로그 글에는 조금 과하다. 특히 H1이 크고 line-height가 낮아 제목이 “웅장하지만 읽기 어려운” 쪽으로 간다.

### 4. 출처와 메타 정보가 본문 경험을 침범한다

rich showcase는 검증 가능한 링크를 많이 넣기 위해 source-box가 커졌다. 정확성은 좋아졌지만 디자인 관점에서는 본문 마지막에 20개 이상의 링크가 나타나 시각적 피로를 만든다.

공개 블로그형 결과물에서는 출처를 다음처럼 처리하는 편이 낫다.

- 본문 중 직접 필요한 곳에는 2~4개 핵심 링크만 노출
- 전체 출처는 `source-note`로 작게 접거나 별도 source hub로 연결
- 외부 링크 나열은 footer 또는 부록으로 낮춘다

### 5. 콘텐츠 생성 단계에서 “디자인 컴포지션” 단계가 빠졌다

v2 생성물은 섹션과 내용을 채운 뒤 CSS를 입힌 느낌이다. blog-demos는 문장, 박스, 하이라이트, 부제, 목차가 서로 맞물려 있다.

고품질 HTML 생성에는 다음 중간 단계가 필요하다.

1. 콘텐츠 아웃라인
2. 독자 여정 설계
3. 섹션별 컴포넌트 배정
4. prose/box 비율 조정
5. 첫 화면 시각 구성
6. 출처/부록 밀도 조정
7. 모바일 리듬 확인

현재 v2는 1, 2는 어느 정도 있으나 3~7이 약하다.

## 보강 방안

### A. v2의 기본 테마를 editorial technical publication으로 교체

대상 파일:

- `~/.codex/skills/adaptive-html-blog-writer-v2/assets/theme.css`
- `~/.codex/skills/adaptive-html-blog-writer-v2/assets/components.css`
- `~/.codex/skills/adaptive-html-blog-writer-v2/assets/layouts.css`

핵심 변경:

- 배경: `#f5f5f0`
- 본문: `#1a1a1a`, soft text `#4a4a4a`
- 강조: `#e63946`
- h1: 36~42px 중심, line-height 1.25~1.35
- h2: 25~28px, margin-top 64px
- radius: 5~8px 중심
- shadow 최소화
- dark box는 마지막 `.try`에만 사용

### B. blog-demos 컴포넌트 문법을 v2 공통 컴포넌트로 승격

추가/강화할 클래스:

- `.h2-sub`
- `.summary-card`
- `.source-note`
- `.card-block`
- `.case-label`
- `.prompt-box`
- `.hl`, `.hl.blue`, `.hl.pink`
- `.tbl`
- `.term .label/.word/.meaning`
- `.danger .label/.name`
- `.good .label/.name`

### C. v2 layout template에 “부제와 의미 라벨”을 강제

예시:

```html
<h2><span class="num">1</span>섹션 제목</h2>
<p class="h2-sub">이 섹션에서 독자가 얻게 될 것을 한 줄로 설명한다.</p>
```

beginner, education, article, blog 모드는 거의 모든 h2에 `.h2-sub`를 붙이는 것이 좋다. expert/seo/platform은 표와 대시보드가 많으므로 summary block에 더 강한 라벨을 둔다.

### D. source-box를 footer형 source-note로 낮추기

현재 v2:

```html
<section class="source-box box">
  <h2>조사·검토 출처</h2>
  <ul>링크 20개...</ul>
</section>
```

권장:

```html
<div class="source-note">
  <div class="label">출처와 검토 기준</div>
  <p>본문은 OWASP, NIST, RFC, OpenID Connect, W3C WebAuthn 및 로컬 보안 리뷰 문서를 검토해 작성했습니다.</p>
  <p><a href="sources/index.html">전체 출처 링크 모음 보기</a></p>
</div>
```

### E. v2 SKILL.md에 Visual Composition Gate 추가

추가해야 할 규칙:

- 첫 화면은 kicker → h1 → sub → 얇은 divider → toc/summary 순서
- hero는 dark box 남발 금지, beginner의 핵심 요약은 흰 카드 + accent border 선호
- h1은 긴 한국어 제목일수록 42px 이하로 제한
- 본문 prose 65~75%, 박스 25~35% 유지
- `.hl`은 글당 2~4개만 사용
- 출처 링크 6개 초과 시 본문 내 나열 금지, source hub로 분리
- table은 `.tbl` wrapper 또는 모바일 카드 대체
- mode별 차이는 색이 아니라 정보 구조와 컴포넌트 조합으로 표현

### F. blog-demos를 golden examples로 등록

대상:

- `blog-demos/beginner-session-vs-token.html`
- `blog-demos/article-passwordless-future.html`
- `blog-demos/expert-password-hashing.html`
- `blog-demos/education-oauth-pkce.html`

이 파일들을 v2 skill의 `examples/` 또는 `references/golden/`에 넣고, 생성 전후 비교 기준으로 사용한다.

### G. 자동 QA 추가

검증 스크립트가 확인할 항목:

- h1 count = 1
- h1 computed font-size <= 44px at 1280px width
- body width 760~820px for reading modes
- `.h2-sub` section 대비 70% 이상 존재
- `.hl` 2~4개
- `.source-note` 사용, source-box 대형 링크 목록 금지
- screenshots: 1280px, 390px 2개 캡처
- mobile overflow 없음

## 권장 실행 순서

1. `html-for-beginners`의 `assets/template.html`과 `references/design-system.md`를 v2 reference로 이식한다.
2. v2 `theme.css/components.css`를 blog-demos 기반 editorial theme로 교체한다.
3. v2 layout template 7개에 `.h2-sub`, `.summary-card`, `.source-note` 위치를 반영한다.
4. `SKILL.md`에 Visual Composition Gate를 추가한다.
5. `quality-gates.md`에 디자인 품질 체크리스트를 추가한다.
6. blog-demos 4개를 golden examples로 등록한다.
7. 기존 adaptive showcase 7개를 재생성해 blog-demos 수준에 맞춰 비교한다.

## 최종 판단

`blog-demos`가 더 좋은 이유는 우연이 아니다. 그것은 더 좋은 디자인 시스템이 있기 때문이다.

`adaptive-html-blog-writer-v2`는 모드 분기와 정보 구조가 강점이고, `html-for-beginners/blog-demos`는 editorial visual system이 강점이다. 둘을 합치면 가장 좋다.

> v2 = 목적별 정보 구조
> blog-demos = 고품질 시각 언어
> 보강 방향 = v2 구조 위에 blog-demos 디자인 시스템을 입히기
