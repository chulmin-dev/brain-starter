# My Brain — Index (L0 라우터)

> Claude가 세션에서 먼저 읽는 라우터. 카탈로그 행은 카테고리별 index-*.md(L1.5)로 분리.
> 새 페이지 생성/삭제 시 해당 index-*.md 갱신 + 아래 "행" 수 동기. 행 형식: `| [[경로/파일명]] | 한 줄 요약 |`

Last updated: 2026-10-03 — template system refresh. Detailed history: [[CHANGELOG]].

---

## 카테고리 라우팅 (L1.5)

| 카테고리 | 행 | 카탈로그 | 내용 |
|---|---|---|---|
| Projects | 0 | [[index-projects]] | 프로젝트 현황·devlog·사후평가 |
| Decisions | 0 | [[index-decisions]] | 확정·보류 결정 기록 |
| Insights | 0 | [[index-insights]] | 교훈·분석·best practice |
| People·Companies·Deals·Legal | 0 | [[index-entities]] | 인물·회사·거래·법적 사안 |
| 업무일지·Resources·Documents·Feedback·Brain Meta | 0 | [[index-ops]] | 월별 worklog·참고자료·문서·피드백·brain 메타 |
| Research | 0 | [[index-research]] | Research by domain; source artifacts remain separate |

## Active Projects

status:active 전망대는 세션 시작 훅이 런타임 생성·주입 (소스 아님). 수동 확인: [[index-projects]].

## 사용법

- 카테고리 파악 → 해당 index-*.md만 읽기(L1.5) → 대상 페이지 full read(L3). 여러 카테고리면 필요한 것만.
- 검색: `node bin/brain-search "<쿼리>"` · 커밋 전 점검: `node .tools/lint/lint.mjs --gate`
- 주요 명령: "미팅 정리해줘"(+회의록) / "오늘 세션 정리해줘" / "[이름/주제] 브리핑해줘" / "inbox 처리해줘"
- 처음이라면: "wiki 초기화해줘" 또는 "처음 시작하자" → BOOTSTRAP이 첫 seed 페이지를 만들어 줍니다.
