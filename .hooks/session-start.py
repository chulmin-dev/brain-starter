#!/usr/bin/env python3
"""
SessionStart 훅 — wiki/index.md를 L0로 주입.
- compiled: false 파일 카운트로 pending 경고
- L1 Pull: status:active 프로젝트 최근 3개 자동 로드 (V5 합의 2026-04-20)
- cwd guard: resolve() 기반으로 엣지케이스 처리
"""

import json
import os
import sys
import re
from pathlib import Path
from datetime import datetime

BRAIN_DIR = Path(os.environ.get("MY_BRAIN_DIR") or os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parent.parent)
INDEX_FILE = BRAIN_DIR / "wiki" / "index.md"
SESSIONS_DIR = BRAIN_DIR / "raw" / "sessions"
PROJECTS_DIR = BRAIN_DIR / "wiki" / "projects"

L1_MAX_CHARS = 16_000   # 문자 수 캡. 한국어 위주 텍스트는 자당 ~1토큰 수준이라 실제 토큰 상한은
                        # 영문 가정(~4K 토큰)보다 수 배 큼 — 스펙 v0.2 주석 정정, 동작 무변경
L1_MAX_FILES = 3        # 최대 로드 프로젝트 수
ACTIVE_NOW_MAX_CHARS = 6_000  # Active Now 전망대 캡 (U1a v0.2)
HEADER_MAX_BYTES = 400  # W2 forward-freeze 가드: 'Last updated:' 줄 재비대 경고 임계 (원본 트림 171B)


def count_pending_sessions() -> int:
    """미컴파일 세션 카운트 — compiled 상태 SSOT는 .tools/state/compiled.json (W3.1).
    pending = frontmatter compiled: false 이면서 원장 sessions 맵에 미기록인 파일."""
    if not SESSIONS_DIR.exists():
        return 0
    try:
        done = set()
        ledger = BRAIN_DIR / ".tools" / "state" / "compiled.json"
        try:
            done = set(json.loads(ledger.read_text(encoding="utf-8")).get("sessions", {}))
        except Exception:
            pass
        count = 0
        fm_re = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
        field_re = re.compile(r"^compiled:\s*(\S+)", re.MULTILINE)
        for f in SESSIONS_DIR.glob("*.md"):
            content = f.read_text(encoding="utf-8")
            m = fm_re.match(content)
            if not m:
                continue
            field_m = field_re.search(m.group(1))
            if field_m and field_m.group(1) == "false" and f.stem not in done:
                count += 1
        return count
    except Exception:
        return 0


def parse_frontmatter(text: str) -> dict:
    """간단한 YAML frontmatter 파싱 (중첩 없는 key: value)"""
    fm_re = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
    m = fm_re.match(text)
    if not m:
        return {}
    result = {}
    for line in m.group(1).splitlines():
        kv = line.split(":", 1)
        if len(kv) == 2:
            k = kv[0].strip()
            v = kv[1].strip().strip('"')
            result[k] = v
    return result


def load_active_projects() -> str:
    """
    L1 Pull: status:active 프로젝트를 updated 최신순으로 최대 L1_MAX_FILES개 로드.
    합산 L1_MAX_CHARS 초과 시 트리밍.
    반환: 컨텍스트 삽입용 문자열 (빈 문자열이면 주입 안 함)
    """
    if not PROJECTS_DIR.exists():
        return ""
    try:
        candidates = []
        for f in PROJECTS_DIR.glob("*.md"):
            try:
                content = f.read_text(encoding="utf-8")
                fm = parse_frontmatter(content)
                if fm.get("status") == "active":
                    updated_str = fm.get("updated", "1970-01-01")
                    try:
                        updated_dt = datetime.strptime(updated_str, "%Y-%m-%d")
                    except ValueError:
                        updated_dt = datetime.min
                    candidates.append((updated_dt, f, content))
            except Exception:
                continue

        if not candidates:
            return ""

        # updated 내림차순 정렬
        candidates.sort(key=lambda x: x[0], reverse=True)
        top = candidates[:L1_MAX_FILES]

        parts = []
        total_chars = 0
        for _, f, content in top:
            if total_chars >= L1_MAX_CHARS:
                break
            remaining = L1_MAX_CHARS - total_chars
            chunk = content[:remaining]
            truncated = len(content) > remaining
            label = f"### L1 — [[projects/{f.stem}]]"
            if truncated:
                label += " _(토큰 상한으로 일부 생략)_"
            parts.append(f"{label}\n\n{chunk}")
            total_chars += len(chunk)

        if not parts:
            return ""

        header = "\n\n---\n## Active Projects (L1 자동 로드)\n\n"
        return header + "\n\n---\n".join(parts)

    except Exception:
        return ""


def build_active_now() -> str:
    """Active Now 전망대 — status:active 프로젝트를 updated 역순 1줄씩 런타임 생성.
    index.md(소스)에 두지 않는 이유: 멀티머신 공유 충돌점·서브인덱스 드리프트 제거
    (U1a 스펙 v0.2, critic MAJOR-4 반영). summary SOT = frontmatter(200자 규칙).
    L1 pull(top-3 full)과는 '1줄 전망대 vs 상세' 계층 분담."""
    if not PROJECTS_DIR.exists():
        return ""
    try:
        rows = []
        for f in PROJECTS_DIR.glob("*.md"):
            try:
                fm = parse_frontmatter(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if fm.get("status") != "active":
                continue
            rows.append((fm.get("updated", ""), f.stem, fm.get("stage", ""), fm.get("summary", "")))
        if not rows:
            return ""
        rows.sort(reverse=True)
        lines = ["", "## Active Now (런타임 생성 — status:active, updated 역순)", ""]
        total = 0
        for updated, slug, stage, summary in rows:
            line = f"- [[projects/{slug}]] ({stage} · {updated}) — {summary}"
            total += len(line)
            if total > ACTIVE_NOW_MAX_CHARS:
                lines.append(f"- … (캡 {ACTIVE_NOW_MAX_CHARS}자 초과 — 나머지는 [[index-projects]] 참조)")
                break
            lines.append(line)
        return "\n".join(lines)
    except Exception:
        return ""


def header_health_notice(index_content: str) -> str:
    """Warn about an oversized or history-heavy router header without changing it."""
    try:
        header_line = ""
        for line in index_content.splitlines():
            if line.startswith("Last updated:"):
                header_line = line
                break
        if not header_line:
            return ""
        issues = []
        nbytes = len(header_line.encode("utf-8"))
        if nbytes > HEADER_MAX_BYTES:
            issues.append(f"헤더 줄 {nbytes}B (>{HEADER_MAX_BYTES}B 재비대)")
        if "이전:" in header_line:
            issues.append("헤더에 '이전:' 인라인 history 누적")
        if not issues:
            return ""
        return (
            "\n> ⚠️ **BRAIN 헤더 점검 (W2 forward-freeze)** — " + "; ".join(issues) + "\n"
            "> 조치: index.md 헤더를 단일 'Last updated:' 한 줄로 재트림 + 누적분은 CHANGELOG로 분리.\n"
        )
    except Exception:
        return ""


def onboarding_notice() -> str:
    """첫 안내 요청만 기록한다. 설정·파일 오류는 기존 세션을 방해하지 않는다."""
    if os.environ.get("BRAIN_SKIP_ONBOARDING") == "1":
        return ""
    try:
        marker = BRAIN_DIR / ".cache" / "brain" / "onboarded"
        if marker.exists():
            return ""
        guide = BRAIN_DIR / "ONBOARDING.md"
        # 가이드가 없거나 읽을 수 없으면 기록하지 않아 다음 세션에서 재시도한다.
        with guide.open(encoding="utf-8") as source:
            source.read()
        notice = (
            "\n\n---\n## Brain Starter — 첫 실행 안내\n\n"
            f"이 vault의 온보딩 단일 출처 `{guide}`를 읽으세요. "
            "파일의 'Claude의 진행 방식'에 따라 한국어로 짧게 인사하고 기능을 설명한 뒤, "
            "'첫 10분 체크리스트를 함께 해볼까요? 이미 끝낸 단계가 있나요?'라고 제안하세요. "
            "사용자가 원하면 필요한 단계만 함께 진행하세요. "
            "기존 작업을 막거나 승인 없이 선택 기능·의존성을 설치하지 마세요. "
            "나중에는 `/onboarding`으로 다시 안내받을 수 있다고 알려주세요.\n"
        )
        marker.parent.mkdir(parents=True, exist_ok=True)
        # 동시에 시작한 세션에서도 한 번만 안내한다. 완료가 아니라 안내 요청 표시다.
        with marker.open("x", encoding="utf-8", newline="\n") as receipt:
            receipt.write("onboarding requested\n")
        return notice
    except Exception:
        return ""


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        data = {}

    # cwd guard: resolve()로 symlink/trailing-slash 처리
    try:
        cwd_path = Path(data.get("cwd", "")).resolve()
        brain_resolved = BRAIN_DIR.resolve()
        if brain_resolved != cwd_path and brain_resolved not in cwd_path.parents:
            sys.exit(0)
    except Exception:
        sys.exit(0)

    if not INDEX_FILE.exists():
        sys.exit(0)

    index_content = INDEX_FILE.read_text(encoding="utf-8")
    pending = count_pending_sessions()
    l1_context = load_active_projects()
    active_now = build_active_now()

    pending_notice = ""
    if pending >= 3:
        pending_notice = f"\n> ⚠️ 미컴파일 세션 {pending}개 — '오늘 세션 정리해줘'로 반영 권장\n"
    elif pending >= 1:
        pending_notice = f"\n> 미컴파일 세션 {pending}개 있음\n"

    header_notice = header_health_notice(index_content)

    context = f"""## My Brain — 세션 컨텍스트 (L0)

개인 지식 베이스 인덱스. 관련 요청 시 이 vault의 wiki/ 하위 해당 페이지를 읽어 맥락 파악.
{pending_notice}{header_notice}
{index_content}
{active_now}

---
주요 명령:
- 미팅 정리: '미팅 정리해줘' + 회의록 붙여넣기
- 세션 정리: '오늘 세션 정리해줘'
- 브리핑: '[이름/주제] 브리핑해줘'
- 현황: '[프로젝트명] 현황 알려줘'
{l1_context}"""

    context += onboarding_notice()

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context
        }
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
