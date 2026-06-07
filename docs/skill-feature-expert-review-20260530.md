# 전문가 리뷰 — adaptive-html-blog-writer v2 (디자인·beginner 제외)

검토일: 2026-05-30 · 대상: `adaptive-html-blog-writer.skill` v2.0.0 (sha256 `d361a2b8…`)

## 1. 범위와 방법

- **검토 대상:** 12개 모드 — expert, article, education, blog, seo, platform, skill_audit, reference, comparison, case_study, landing_brief, checklist — 와 지원 시스템(모드 라우터, references[디자인 제외], recipes, schemas, tests, workflow, 품질 게이트).
- **제외(요청):** 디자인 시스템(theme/components/layouts CSS, `editorial-design-system.md`, `design-dna.md`, Step 6 Visual Composition Gate)과 **beginner** 모드.
- **근거:** 패키지에서 직접 추출한 `SKILL.md`/`manifest.json`/references/recipes/schemas/tests 원문 + 갤러리 13개 데모 산출물(각 모드 동작 증거).
- **관점:** "잘 만들었나"가 아니라 "어디서 깨지나"를 본다. 발견 항목은 패키지 실파일로 교차검증했다.

## 2. 총평

기능 폭과 산출물 품질은 우수하다(13개 데모 모두 게이트 통과, 표준 근거 인용, 사실성 표기). 다만 **여러 산출물 계층 간 단일 출처(single source of truth)가 없어 정의가 갈라지는 일관성 결함**이 핵심 리스크다. 모드 폭 확장(7→13) 과정에서 라우터·recipes·tests·schema가 같은 속도로 따라오지 못했고, 고위험 콘텐츠 모드(case_study/landing)에 사실성 가드가 빠져 있다. 기능 자체보다 **메타데이터 정합성과 안전 가드**를 보강하면 완성도가 크게 오른다.

### 헤드라인 스코어 (0~5)

| 영역 | 점수 | 한줄 |
|---|---:|---|
| 모드 설계(개별 12종) | 4.3 | 목적·필수 블록·레이아웃 매핑이 대체로 명확 |
| 모드 라우터/선택 | 3.0 | 단일 출처 부재·네이밍 불일치·합성 능력 상실 |
| References 체계 | 3.7 | 내용 좋으나 게이트/평가 중복·드리프트 |
| Recipes/Tests/Schemas | 2.8 | 신규 5모드 미커버, schema 드리프트 |
| 사실성·안전 가드 | 3.2 | 보편 원칙은 있으나 case/landing 모드별 가드 결여 |
| **종합** | **3.4 / 5** | 보완 후 통과 수준(고치면 4.3+) |

## 3. 발견 항목 (심각도순)

### 🔴 High

**F1. 모드 ID가 계층마다 다르다 (네이밍 불일치)**
- 증거: `manifest.json` modes = `[beginner, expert, article, education, blog, seo, platform, …]` vs `SKILL.md:54-67` 라우터 Mode 열 = `[…, seo_dashboard, education_html, expert_html, article_html, blog_writer, beginner_html, reference_html, comparison_html, case_study_html, landing_brief_html, …]`. 정확히 일치하는 건 `skill_audit`, `checklist_playbook` 둘뿐.
- 왜 문제: 자동화·라우팅·로그·스키마가 어떤 ID를 정본으로 쓸지 모호하다. `seo` vs `seo_dashboard`처럼 한 모드가 두 이름을 갖는다.
- 수정: 모드 ID를 하나로 고정(권장: 짧은 형 `seo`, `blog`, `expert`…)하고, 라우터 표의 Layout 열에만 `*-dashboard.html` 같은 레이아웃 파일명을 둔다. manifest·SKILL·references·schema가 같은 ID를 참조.

**F2. 고위험 콘텐츠 모드(case_study·landing)에 사실성 가드가 없다**
- 증거: 보편 원칙 `SKILL.md:29`("확인되지 않은 사실은 단정하지 않는다")는 있으나, `case_study`(상황·타임라인·결과 수치)와 `landing_brief`(가치 제안·성과)는 **지어내기 유혹이 가장 큰 모드**인데 모드별 가드가 없다. 데모가 "가상 사례 명시 / README 근거"로 안전했던 건 전적으로 작업 지시 덕분이었다.
- 왜 문제: 같은 스킬을 다른 사람이 돌리면 가짜 회사·가짜 지표·과장 벤치마크를 사실처럼 낼 수 있다.
- 수정: 모드 규칙에 명시 — case_study: "실제 사례는 출처 필수, 그 외는 **가상(illustrative)으로 라벨**하고 수치를 사실로 제시 금지." landing: "기능·성과는 코드/문서로 검증된 것만, 미검증 벤치마크·도입수치 금지."

**F3. 품질 게이트가 3중으로 존재하고 이미 드리프트했다**
- 증거: 같은 규칙이 `SKILL.md §7`, `references/quality-gates.md`, `tests/quality-checklist.md`+`tests/layout-checklist.md`에 중복. CSS 개수가 벌써 어긋남 — `SKILL.md:190`은 "theme+components+layouts+**print** 4개", `tests/layout-checklist.md:8`은 "CSS 3개(print 없음)", `references/quality-gates.md:5-6`은 "3개 + 필요시 print".
- 왜 문제: 검수 기준이 세 곳에서 갈라지면 무엇이 정답인지 알 수 없고, 시간이 갈수록 더 벌어진다.
- 수정: 게이트 단일 출처(`references/quality-gates.md`) 지정, 나머지는 "quality-gates.md 참조"로 축약. print.css 규칙 명문화("인쇄 대상일 때만 4번째").

### 🟠 Medium

**F4. v1의 다중 모드 합성 능력이 사라졌다 (회귀)**
- 증거: 현재 `references/mode-selection.md`는 우선순위 단일 선택 + "복합이면 blog_writer+렌더"만 명시. v1 mode-selection에는 "초보자용 블로그 HTML = beginner + blog_seo" 같은 **명시적 모드 합성**이 있었다.
- 왜 문제: "전문가용 비교 리포트", "교육용 체크리스트"처럼 두 목적이 겹치는 요청을 한 모드로만 처리하면 정보 구조가 손실된다.
- 수정: 라우터에 "주 모드 + 보조 모드(블록 차용)" 규칙 추가. 예: 주=comparison, 보조=expert(리스크 블록 차용).

**F5. recipes·golden-prompts가 신규 5모드를 커버하지 않는다**
- 증거: `recipes/` = audit, beginner, blog, expert, platform, seo (6/13). `tests/golden-prompts.md` = 8개(원래 모드들). reference·comparison·case_study·landing_brief·checklist용 recipe/golden prompt **0개**.
- 왜 문제: 신규 모드는 "트리거 예시"와 "회귀 테스트 프롬프트"가 없어 발동·검증이 약하다.
- 수정: 5개 모드 recipe 추가, golden-prompts에 5개 시나리오 추가(예: "이 라이브러리 소개 랜딩 만들어줘", "A vs B 비교표로").

**F6. 평가 프레임워크가 둘이고 기준이 다르다**
- 증거: `references/eval-rubric.md` = 7개 항목(28점 통과). `references/skill-audit-system.md` = 12개 진단 기준. `SKILL.md §7`/skill_audit 데모는 또 8개 기준 사용.
- 왜 문제: skill_audit 모드가 어떤 채점표를 써야 하는지 모호(7 vs 12 vs 8). 결과 재현성이 떨어진다.
- 수정: eval-rubric을 산출물 채점용으로, audit 12기준을 스킬 진단용으로 **역할 분리 명문화**하고 상호 참조. 또는 하나로 통합.

**F7. article은 '반론'을, blog는 '메타'를 필수에서 잃었다**
- 증거: `SKILL.md:174` article 블록 = `lead, pull quote, argument, case, takeaway` (counterpoint 없음 — v1엔 있었음). `SKILL.md:176` blog 블록 = `hook, personal note, view, example, how-to, soft CTA` (제목후보/메타/태그 없음).
- 왜 문제: 균형 잡힌 아티클의 핵심인 반론이 빠지고, "블로그 글" 요청 시 발행 메타가 보장되지 않는다(§7 게이트가 일부 backstop하나 블록 레벨 누락).
- 수정: article 필수에 `counterpoint` 복원. blog는 "seo 보조 블록(제목후보/메타/태그) 자동 첨부" 규칙 추가.

**F8. blog 메타데이터: schema와 reference가 어긋난다**
- 증거: `schemas/blog-meta.schema.json` 필수 = title_recommended/slug/meta_description/tags, `title_variants`는 느슨한 generic object. 그러나 enriched `references/blog-seo-system.md`의 스키마는 keywords_primary/secondary, estimated_reading_time, platform_notes, title_variants(4계열)까지 규정.
- 왜 문제: 같은 메타를 두 곳이 다르게 정의 → 검증 불가.
- 수정: schema를 reference 기준으로 확장하고 `title_variants`에 search/click/expert/beginner 4키를 enum/properties로 고정.

### 🟡 Low

**F9. reference 모드에 '신선도' 규약이 없다.** 매뉴얼/레퍼런스는 표준 개정으로 노후한다. → 헤더 meta에 "기준 시점/표준 버전" + 변동 항목 `확인 필요` 의무화.

**F10. platform은 단일/다중 범위가, comparison은 표/카드 선택이 모호하다.** platform 블록("platform cards + comparison")은 다중 플랫폼을 전제하나 "티스토리로 바꿔줘"는 단일. comparison은 `.tbl table`과 `.matrix` 카드가 중복. → 단일/다중 분기 규칙, "행 많으면 표·항목 적으면 카드" 가이드 추가.

**F11. checklist 항목에 표준 앵커링이 강제되지 않는다.** 데모는 ASVS 조항을 달았으나(좋음) 스킬은 요구 안 함. → 보안/컴플라이언스 체크리스트는 항목별 출처/표준 조항 표기 권장.

**F12. workflow에 렌더 검증 단계가 없다.** §4~6은 "품질검수→파일 제시"로 끝나고 실제 브라우저 렌더/링크 동작 확인이 강제되지 않는다(tests에 수동 언급뿐). → Step 7 "로컬 렌더/링크 확인" 추가.

## 4. 모드별 요약 (12종, 0~5)

| 모드 | 레이아웃 | 목적 명확 | 블록 완전성 | 데모 증거 | 핵심 갭 |
|---|---|:--:|:--:|:--:|---|
| expert | expert-report | 5 | 4 | 강 | 가정/신뢰도 블록 없음 |
| article | magazine-article | 4 | 3 | 강 | **counterpoint 누락(F7)** |
| education | course-module | 5 | 5 | 강 | 거의 없음(우수) |
| blog | personal-blog-essay | 4 | 3 | 강 | **메타/제목 블록 미보장(F7)** |
| seo | seo-dashboard | 5 | 4 | 강 | schema 드리프트(F8) |
| platform | platform-adaptation | 4 | 4 | 강 | 단일/다중 범위 모호(F10) |
| skill_audit | skill-audit-report | 4 | 4 | 강 | 채점표 3종 혼재(F6) |
| reference | reference-manual | 4 | 4 | 강 | 신선도 규약 없음(F9) |
| comparison | comparison-matrix | 5 | 4 | 강 | 표/카드 중복(F10) |
| case_study | case-study | 4 | 4 | 강 | **사실성 가드 없음(F2)** |
| landing_brief | landing-brief | 4 | 4 | 중 | **과장/사실성 가드 없음(F2)** |
| checklist | checklist-playbook | 5 | 4 | 강 | 표준 앵커링 미강제(F11) |

## 5. 우선순위 액션 (권장 순서)

1. **F1 모드 ID 통일** — manifest/SKILL/references/schema가 같은 ID 사용(반나절, 영향 큼).
2. **F2 case_study·landing 사실성 가드 명문화** — 모드 규칙 2줄씩 추가(안전 직결).
3. **F3 게이트 단일 출처화** — quality-gates.md 정본, print.css 규칙 확정.
4. **F7 article counterpoint 복원 + blog 메타 자동첨부.**
5. **F5 신규 5모드 recipe + golden-prompt 추가.**
6. **F6 평가 프레임워크 역할 분리, F8 schema 확장.**
7. F9~F12(저위험) 일괄 정리.

## 6. 제외 항목 메모

요청에 따라 디자인 시스템(theme/components/layouts CSS, editorial-design-system, design-dna, Visual Composition Gate)과 beginner 모드는 **검토하지 않았다.** 단, F3(게이트)·F1(네이밍)은 디자인 토큰 자체가 아니라 "검수/식별 메타" 차원이라 포함했다.
