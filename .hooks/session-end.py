#!/usr/bin/env python3
"""
SessionEnd 훅 — Claude 세션을 raw/sessions/ 에 자동 저장.

발화조건 — 다음 중 1개:
  1) cwd가 brain 내부 (기존)
  2) 도구 write-touch: Write/Edit/MultiEdit/NotebookEdit tool_use의 file_path/notebook_path가 brain 하위
  3) 커밋 그라운드트루스: 세션 시작 이후 brain repo에 'claude:' 커밋 존재
     (룰 22 즉시 sync가 100% Bash라 도구 스캔이 못 보는 쓰기를 커밋으로 포착.
      알려진 한계: 동시 타 세션의 claude: 커밋 → 거짓 양성(빈도 낮음·피해 작음),
      커밋 보류 + Bash-only 쓰기 → 미포착(희귀))

절단 v2: 120턴 초과 시 앞 20 + 뒤 100 보존 + 중간 생략 마커 (결론부 유실 방지 — 기존 '앞 120'의 결함 수정).
- sidechain(서브에이전트) / tool_use·tool_result 노이즈 필터링
- compiled: false 플래그로 멱등성 추적
- MY_BRAIN_DIR env 오버라이드 (픽스처 테스트가 실 vault 오염 방지)
"""

import json
import sys
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

# Recursion guard
if os.environ.get("CLAUDE_INVOKED_BY") or os.environ.get("CLAUDE_CODE_SUBAGENT"):
    sys.exit(0)

BRAIN_DIR = Path(os.environ.get("MY_BRAIN_DIR") or os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parent.parent)
SESSIONS_DIR = BRAIN_DIR / "raw" / "sessions"
LOG_FILE = BRAIN_DIR / ".hooks" / "session-end.log"

WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
HEAD_TURNS = 20
TAIL_TURNS = 100
SOURCE_SAFENAME = re.compile(r"[^a-z0-9_-]")


def log(msg: str):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {msg}\n"
    print(entry.strip(), file=sys.stderr)
    try:
        with open(LOG_FILE, "a", encoding="utf-8", newline="\n") as f:
            f.write(entry)
    except Exception:
        pass


def claude_commit_since(start_ts: str) -> bool:
    """세션 시작 이후 brain repo의 'claude:' prefix 커밋 여부 (발화조건 3)."""
    if not start_ts or not (BRAIN_DIR / ".git").exists():
        return False
    try:
        r = subprocess.run(
            ["git", "-C", str(BRAIN_DIR), "log", "--since", start_ts,
             "--grep", "^claude:", "--oneline", "-5"],
            capture_output=True, text=True, timeout=5)
        return bool(r.stdout.strip())
    except Exception:
        return False


def main():
    try:
        data = json.load(sys.stdin)
    except Exception as e:
        log(f"stdin 파싱 실패: {e}")
        sys.exit(0)

    # 발화조건 1: cwd가 brain 내부 (resolve()로 symlink/trailing-slash 처리)
    in_brain = False
    try:
        cwd_path = Path(data.get("cwd", "")).resolve()
        brain_resolved = BRAIN_DIR.resolve()
        in_brain = brain_resolved == cwd_path or brain_resolved in cwd_path.parents
    except Exception:
        in_brain = False

    session_id = data.get("session_id", "unknown")
    raw_reason = data.get("reason", "unknown")
    reason = SOURCE_SAFENAME.sub("_", raw_reason)[:20]

    transcript_path = Path(data.get("transcript_path", ""))
    if not transcript_path.exists():
        if in_brain:
            log(f"transcript_path 없음: {transcript_path}")
        sys.exit(0)

    turns = []
    write_touch = False   # 발화조건 2
    first_ts = ""
    try:
        with open(transcript_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not first_ts and entry.get("timestamp"):
                    first_ts = str(entry["timestamp"])

                # sidechain(서브에이전트) 대화 제외 — wiki 노이즈 방지
                if entry.get("isSidechain"):
                    continue
                if entry.get("type") not in ("user", "assistant", None):
                    continue
                msg = entry.get("message", {})
                if not isinstance(msg, dict):
                    continue
                role = msg.get("role", "")
                if role not in ("user", "assistant"):
                    continue

                content = msg.get("content", "")
                if isinstance(content, list):
                    text_parts = []
                    for block in content:
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type")
                        if btype == "text":
                            text = block.get("text", "").strip()
                            if text:
                                text_parts.append(text)
                        elif btype == "tool_use" and block.get("name") in WRITE_TOOLS:
                            inp = block.get("input", {})
                            target = str(inp.get("file_path") or inp.get("notebook_path") or "")
                            try:
                                if target and Path(target).resolve().is_relative_to(BRAIN_DIR.resolve()):
                                    write_touch = True
                            except (OSError, ValueError):
                                pass
                        # tool_result, attachment 등은 무시
                    content = "\n".join(text_parts)

                if isinstance(content, str) and content.strip():
                    turns.append((role, content.strip()))
    except Exception as e:
        log(f"transcript 파싱 실패: {e}")
        sys.exit(0)

    if not turns:
        sys.exit(0)

    # 발화조건 판정 (1 → 2 → 3 순, 3은 git 호출이라 마지막)
    if in_brain:
        trigger = "cwd"
    elif write_touch:
        trigger = "write-touch"
    elif claude_commit_since(first_ts):
        trigger = "claude-commit"
    else:
        sys.exit(0)  # 비발화 — 무음 종료 (로그 스팸 방지)

    # 절단: 앞 HEAD_TURNS + 뒤 TAIL_TURNS 보존 (결론부 유지)
    omitted = 0
    if len(turns) > HEAD_TURNS + TAIL_TURNS:
        omitted = len(turns) - HEAD_TURNS - TAIL_TURNS
        turns = turns[:HEAD_TURNS] + [("__MARKER__", f"중간 {omitted}턴 생략 (앞 {HEAD_TURNS} + 뒤 {TAIL_TURNS} 보존)")] + turns[-TAIL_TURNS:]

    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")
    ts = datetime.now().strftime("%H%M%S")
    filename = SESSIONS_DIR / f"{today}_{ts}_{session_id[:8]}_{reason}.md"

    lines = [
        "---",
        f"date: {today}",
        f"session_id: {session_id}",
        f"reason: {raw_reason}",
        f"trigger: {trigger}",
        f"turns: {len([t for t in turns if t[0] != '__MARKER__'])}",
        f"truncated: {str(omitted > 0).lower()}",
        "compiled: false",
        "---",
        "",
        f"# Session — {today} {ts[:2]}:{ts[2:4]}",
        "",
    ]

    for role, content in turns:
        if role == "__MARKER__":
            lines.append(f"> ⚠️ {content}")
            lines.append("")
            continue
        label = "나" if role == "user" else "Claude"
        lines.append(f"## {label}")
        lines.append(content)
        lines.append("")

    lines += [
        "---",
        "",
        "> 이 세션을 wiki에 반영하려면: '오늘 세션 정리해줘'",
    ]

    try:
        filename.write_text("\n".join(lines), encoding="utf-8", newline="\n")
        log(f"저장 완료: {filename.name} (trigger={trigger}, {len(turns)}턴, omitted={omitted})")
    except Exception as e:
        log(f"파일 저장 실패: {e}")


if __name__ == "__main__":
    main()
