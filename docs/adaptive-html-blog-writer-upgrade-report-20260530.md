# adaptive-html-blog-writer 업그레이드 보고서 (v1 → v2)

작성일: 2026-05-30

## 목표

현재 스킬 `adaptive-html-blog-writer`(v1, 8모드)에 `adaptive-html-learning-ultimate-merged.skill`(v3.0.0, 13모드)의 특징을 **전체 통합**하되, 스킬 이름·정체성은 `adaptive-html-blog-writer`로 **유지**하고 내부를 업그레이드한다.

- 결정: 이름 유지 + 업그레이드 / 전체 통합 (사용자 확인)
- 결과 패키지: `adaptive-html-blog-writer.skill` (덮어쓰기)
- 원본 백업: `adaptive-html-blog-writer.skill.bak-20260530`

## 흡수한 ultimate 특징

| 영역 | v1(기존) | v2(업그레이드) |
|---|---|---|
| 모드 | 8 | **13** (reference, comparison, case_study, landing_brief, checklist_playbook 추가) |
| 모드 라우터 | 표 1개 | 우선순위 + 레이아웃 매핑 라우터 |
| CSS | 단일 인라인 template | **레이어드**: theme / components / layouts / print + base.html |
| 레이아웃 | 2 (template, blog-template) | **13개 layouts/*.html 골격** |
| 컴포넌트 | 기본 박스 | + card-grid/mini-card, tag/tag-list, source-box, pull-quote, skip link, clamp() 반응형 |
| 평가 | 품질 게이트 | + **eval-rubric(0~5점, 28점 통과)** |
| 부가 | examples(.md) | + **recipes/**(모드별 프롬프트), **schemas/**(blog-meta, quality-report), **tests/**(4종 체크리스트), examples HTML 7종 |
| 인쇄 | 없음 | **print.css** |

## 보존한 v1 강점 (references에 병합)

- `writing-system.md`: 제목 4계열 규칙·금지어, 도입부 3유형, 본문 밀도(설명50/예시20/오해15/정리15), 톤 매핑
- `blog-seo-system.md`: SEO 세부 규칙, **Blog Metadata Schema(full JSON)**, Blog Quality Score(100점)
- `platform-system.md`: 티스토리/벨로그/네이버/워드프레스 발행 관점 세부 규칙
- `editorial-design-system.md`: 박스 선택 가이드(언제 무엇을) + 자주 발생하는 시각 사고

## 유지한 디자인 DNA

오프화이트 `#f5f5f0` · accent `#e63946` · Pretendard Variable + Noto Serif KR · h2 빨간 원번호 + h2-sub · term/analogy/danger/good · hero-analogy 흰 카드 · 마지막 검정 try · source-note. (ultimate CSS가 이미 동일 DNA였음 — 충돌 없음)

## 검증 (FINAL_VALIDATION_OK)

- zip 무결성 OK · 59 files · 상위 폴더 `adaptive-html-blog-writer/` 단일
- manifest valid JSON · name=adaptive-html-blog-writer · version=2.0.0 · modes=13 · layouts=13
- schemas valid JSON (2) · CSS 중괄호 균형 OK (theme/components/layouts/print)
- references=10 · recipes=6 · tests=4 · examples=8
- 스모크 테스트: base.html + 4 CSS 레이어 + beginner 레이아웃 합성 → parse OK · h1=1 · placeholder 0 · HTTP 200
  - `blog-demos/skill-v2-smoketest.html`
