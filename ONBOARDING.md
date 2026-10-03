# 처음 만나는 Brain Starter

Obsidian으로 읽고 Claude Code와 함께 정리하는 **내 지식 저장소**입니다. 다른 사람의 노트가 아니라 빈 틀을 받았습니다. 처음에는 검색·기록·점검만 사용하면 충분합니다.

## 1. 어디에 무엇을 넣나요?

- **시스템 층**: `CLAUDE.md`(Claude의 작업 규칙), `.hooks/`(자동 동작), `.tools/`(검색·점검·그래프), `.claude/skills/`(자동 로드되는 작업 도우미). 설치된 도구와 내 지식은 구분합니다.
- **콘텐츠 층**: `raw/`에는 대화·회의록·문서 등 원본을 보존하고, `wiki/`에는 승인한 지식을 정리합니다. `research/`는 조사 자료를 따로 보관합니다. 원본을 몰래 고쳐 결론에 맞추지 않습니다.
- **필요한 것만 읽기(L0–L3)**: 세션 시작에 `wiki/index.md` 라우터(L0), 최근 활성 프로젝트 최대 3개(L1), Active Now가 들어옵니다. 주제별 `wiki/index-*.md` 카탈로그(L1.5)를 골라 읽고, 필요한 페이지 전체(L3)를 읽습니다. 이 템플릿에는 별도의 L2 로딩 단계가 없습니다.

주요 노트 위치와 `type`:

| 폴더(`wiki/` 아래) | 무엇을 기록하나요? | type |
|---|---|---|
| `projects/` | 프로젝트 목표·현황 | `project` |
| `decisions/` | 결정과 근거 | `decision` |
| `insights/` | 배운 점·분석 | `insight` |

처음에는 위 세 폴더만 익히면 충분합니다. 새 노트의 제목·유형·상태·짧은 요약과 연결은 Claude에게 함께 작성해 달라고 요청하세요. 같은 사실은 한 대표 페이지에서 관리하고 다른 노트는 링크로 참조합니다.

**status는 진행 상태를 정해진 단어로 표현합니다.**
- `active`: 진행 중(프로젝트·결정·배운 점).
- `confirmed`: 확정한 결정.
- `pending`: 아직 검토 중인 결정.
- `closed`: 끝난 프로젝트.
- `archived`: 보관한 노트.

폴더마다 허용되는 값이 다릅니다. 다른 유형이나 상태가 필요해지면 [CLAUDE.md의 전체 표](CLAUDE.md#frontmatter-and-statuses)를 참고하세요. 첫날부터 모두 외울 필요는 없습니다.

## 2. Claude가 자동으로 해주는 일과 하지 않는 일

- **시작**: 관련 인덱스와 활성 프로젝트를 불러오고, 아직 정리하지 않은 세션 수를 알려줍니다.
- **종료**: 조건에 맞는 Claude 대화를 `raw/sessions/`에 캡처합니다. 원본 저장이 곧 wiki 반영은 아닙니다. “오늘 세션 정리해줘”라고 요청하면 후보를 검토하고 승인한 지식만 반영합니다.
- **쓰기 후**: 노트 형식·연결을 점검해 경고합니다. 이미 끝난 쓰기를 취소하거나 모든 문제를 막는 것은 아닙니다.
- **자동 커밋은 기본 OFF**: 원하면 Claude Desktop의 Local 환경 편집기(톱니바퀴)에 `BRAIN_AUTOCOMMIT=1`을 넣고 새 세션을 여세요. Git Bash가 필요합니다. lint 통과 후 `wiki/`와 `research/`만 로컬 커밋하며, 이미 스테이징한 작업이 있으면 멈춥니다. pull/push는 하지 않습니다.

비밀키·비밀번호는 넣지 마세요. 캡처된 원본은 기본 Git 제외 대상입니다. 모델 호출·외부 수집·알림·자동 승격은 별도 설정과 명시적 승인이 필요합니다.

## 3. 매일 쓰는 명령

아래는 vault 루트에서 PowerShell 또는 Git Bash로 실행합니다. PATH 설정은 필요 없습니다.

```text
node bin/brain-search "첫 프로젝트"
node bin/brain-search "첫 프로젝트" --limit=5 --explain
node .tools/lint/lint.mjs --gate
node .tools/graph/link-audit.mjs --json
node .tools/graph/build-graph.mjs
```

- **검색**: grep으로 먼저 찾아서 원문을 읽습니다. 출력은 항상 JSON입니다. 아직 노트가 없으면 `empty-corpus`, 필터 조건에 맞는 문서가 없으면 `filters-exclude-all`(모두 종료 코드 2)이며 고장이 아닙니다. 검색할 문서가 있지만 문구가 없으면 빈 결과(종료 코드 0)를 반환합니다.
- **lint**: 커밋 전에 구조·링크를 확인합니다. 차단 항목은 고치고 다시 실행하며, 경고를 숨기려고 baseline을 늘리지 않습니다. 자동 대량 수정은 하지 않습니다.
- **graph**: audit은 링크 점검 JSON, build는 관계 그래프 JSON을 출력합니다. 위 두 명령은 파일을 쓰지 않습니다. 캐시 저장이 필요할 때만 `node .tools/graph/build-graph.mjs --write-cache`를 사용합니다.

Claude에게는 “미팅 정리해줘” + 회의록, “오늘 세션 정리해줘”, “첫 프로젝트 현황 알려줘”처럼 요청할 수 있습니다.

## 4. 함께 제공되는 스킬 3개

| 스킬 | 언제 쓰나요? | 예시 요청 |
|---|---|---|
| `prompt-tune` | 여러 단계의 작업 프롬프트를 목표·단계·확인지점 중심으로 다듬기(작업 자체를 실행하지 않음) | “프롬프트 다듬어줘: 자료 조사 → 비교 → 보고서 작성…” |
| `page-fetch` | 요청한 공개 페이지의 본문 추출, 기본 reader의 읽기 실패 복구 | “이 공개 페이지를 마크다운으로 가져와: https://example.org/” |
| `harvest` | 여러 페이지에서 지정한 데이터를 모아 JSON/CSV/Markdown으로 정리 | “https://example.org/의 여러 페이지에서 제목과 URL만 수집해줘.” |

세 스킬은 `.claude/skills/<이름>/SKILL.md`에서 **설치 없이 자동 로드**됩니다. 같은 이름의 개인 스킬이 있으면 프로젝트 스킬보다 우선하므로 중복을 피하세요. page-fetch 실행에는 Python 3.10+와 로컬 패키지가 필요하며, harvest의 fetch/crawl은 옆의 page-fetch를 사용합니다. 브라우저 자동화는 제공하지 않으며 JavaScript 전용 페이지는 직접 여세요. 선택 설치는 [SETUP.md의 스킬 설정](SETUP.md#included-skills)을 확인하세요. 로그인·CAPTCHA·유료벽 우회 권한은 제공하지 않습니다.

## 5. 세션에서 지식으로

세션 종료 시 대화 원본은 `raw/sessions/`에 보존됩니다. “미처리 세션을 wiki로 정리해줘”라고 요청하면 Claude가 원문과 기존 노트를 읽고 변경안을 제안합니다. 승인한 내용만 노트·카탈로그·로그에 반영하며, 원본은 수정하지 않습니다. 자세한 설정은 [SETUP.md](SETUP.md)를 참고하세요.

## 6. 첫 10분 체크리스트

Windows에 **Claude Desktop, Git for Windows, Node.js LTS(22.16+), python.org의 Python 3.12(Add python.exe to PATH 체크), Obsidian**을 설치하세요. 설치 후 Desktop을 완전히 재시작합니다.

- [ ] **내 vault 준비**: 템플릿에서 개인 저장소를 만들고 clone하거나 ZIP을 풀어 Obsidian vault로 여세요.
- [ ] **Desktop에서 열기**: **Code 탭 → Local 환경**에서 같은 native Windows 폴더를 선택하세요. hooks가 프로젝트 경로를 자동 설정하므로 `export`나 PATH 수정은 필요 없습니다. 필요할 때만 Local 환경 편집기에 `MY_BRAIN_DIR`과 실제 Windows 경로를 넣으세요(PowerShell profile은 Desktop에 적용되지 않습니다).
- [ ] **첫 안내와 스킬 확인**: 첫 세션의 안내를 따라가세요. `/onboarding`으로 다시 볼 수 있고, `/prompt-tune`, `/page-fetch`, `/harvest`는 프로젝트 스킬로 자동 로드됩니다. 검색·lint를 위해 선택 의존성을 설치할 필요는 없습니다.
- [ ] **기존 프로젝트 등록**(진행 중인 프로젝트가 있다면): “내가 진행 중인 프로젝트 폴더는 `<경로1>`, `<경로2>`야. 각 폴더를 **읽기만** 해서(README·문서·최근 변경 내역) 목표와 현재 상태 초안을 보여주고, 내가 승인한 내용만 `wiki/projects/`에 노트로, `wiki/index-projects.md`에 카탈로그로 만들어줘.” 프로젝트 폴더 자체는 수정·이동하지 않습니다. vault 밖 폴더라 Claude가 읽기 권한을 물으면 허용하세요.
- [ ] **첫 노트 작성**(진행 중인 프로젝트가 없다면): “처음 시작하자. 내 첫 프로젝트의 목표와 현재 상태를 물어보고, 내가 승인한 내용으로 `wiki/projects/`에 노트와 `wiki/index-projects.md` 카탈로그를 함께 만들어줘.” 예시 제목 “첫 프로젝트”는 설명용이며 자동으로 채워 넣지 않습니다.
  다른 프로젝트 폴더를 Code 탭에서 직접 열고 작업할 때는 이 vault의 규칙·hook·스킬이 적용되지 않습니다. 그 작업에서 얻은 결정·배운 점은 vault 세션으로 돌아와 “<프로젝트> 오늘 한 일 정리해줘”라고 요청해 기록하세요.
- [ ] **점검하고 검색**(첫 노트에 실제 적은 제목/문구로 검색).
  ```text
  node .tools/lint/lint.mjs --gate
  node bin/brain-search "첫 프로젝트"
  ```

첫 자동 안내 요청은 `.cache/brain/onboarded`에 기록합니다(체크리스트 완료 표시가 아니며 Git 제외). Python이 없어도 안내와 설치 경고는 Claude에게 전달되지만 대화 캡처·쓰기 점검은 Python 설치 후 Desktop을 재시작해야 작동합니다. 안내를 건너뛰려면 Desktop Local 환경 편집기에 `BRAIN_SKIP_ONBOARDING=1`을 넣으세요. `/onboarding`은 이 설정이나 기록과 관계없이 다시 안내합니다.

### Claude의 진행 방식

한국어로 짧게 인사하고 구조·자동 동작·명령·스킬·선택 기능을 요약한 뒤, “첫 10분 체크리스트를 함께 해볼까요? 이미 끝낸 단계가 있나요?”라고 물어보세요. 사용자가 원하면 현재 설정을 확인하면서 필요한 단계만 진행합니다. 노트는 사용자가 제공하고 승인한 내용만 작성하고, 선택 기능이나 의존성 설치는 동의 없이 켜지 않습니다. 기존 작업 요청이 있다면 안내가 작업을 막지 않게 하고, 원치 않으면 `/onboarding`으로 다시 볼 수 있다고 알려주세요.
