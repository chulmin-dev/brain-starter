#!/usr/bin/env bash
# session-end.py 캡처 픽스처 테스트 v2 — 5케이스 (스펙 v0.2 수용 기준 4).
# MY_BRAIN_DIR 오버라이드로 실 vault 오염 없이 실행. exit: 0=전부 PASS, 1=FAIL, 2=SKIP(미구현)
set -u
cd "$(dirname "$0")"
HOOK="$(cd ../../.hooks && pwd)/session-end.py"
PYTHON_RUNTIME="$(cd ../../.hooks && pwd)/python-runtime.cjs"


TMP=$(mktemp -d)
if command -v cygpath >/dev/null 2>&1; then TMP=$(cygpath -m "$TMP"); fi
trap 'rm -rf "$TMP"' EXIT
export MY_BRAIN_DIR="$TMP/brain"

reset_brain() { rm -rf "$MY_BRAIN_DIR"; mkdir -p "$MY_BRAIN_DIR"; }

# 픽스처 준비 (write-touch는 테스트 vault 경로로 치환)
sed "s|__BRAIN__|$MY_BRAIN_DIR|g" fixtures/t-write-touch.jsonl.tpl > "$TMP/t-write-touch.jsonl"
cp fixtures/t-no-touch.jsonl "$TMP/t-no-touch.jsonl"
# A sibling directory sharing the vault prefix must not count as a write-touch.
sed "s|__BRAIN__|$MY_BRAIN_DIR-other|g" fixtures/t-write-touch.jsonl.tpl > "$TMP/t-sibling-touch.jsonl"
# 절단 테스트용 130턴 transcript 생성 (turn-001..turn-130)
node "$PYTHON_RUNTIME" - "$TMP/t-long.jsonl" <<'PY'
import json, sys
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
    for i in range(1, 131):
        if i % 2:
            msg = {"role": "user", "content": f"turn-{i:03d} 질문"}
        else:
            msg = {"role": "assistant", "content": [{"type": "text", "text": f"turn-{i:03d} 응답"}]}
        f.write(json.dumps({"type": msg["role"], "isSidechain": False,
                            "timestamp": "2026-01-01T00:00:00.000Z", "message": msg},
                           ensure_ascii=False) + "\n")
PY

FAIL=0
run_case() { # name cwd transcript expect
  local name=$1 cwd=$2 tr=$3 expect=$4
  printf '{"cwd":"%s","session_id":"testcase","reason":"exit","transcript_path":"%s"}' "$cwd" "$tr" \
    | node "$PYTHON_RUNTIME" "$HOOK" >/dev/null 2>&1
  local n
  n=$(ls "$MY_BRAIN_DIR/raw/sessions" 2>/dev/null | wc -l)
  if [ "$n" -eq "$expect" ]; then
    echo "PASS: $name (captured=$n)"
  else
    echo "FAIL: $name (captured=$n, expect=$expect)"
    FAIL=1
  fi
}

# ① brain cwd → 캡처
reset_brain
run_case "1.in-brain-cwd" "$MY_BRAIN_DIR" "$TMP/t-no-touch.jsonl" 1

# ② 타 cwd + 도구 write-touch → 캡처
reset_brain
run_case "2.outside+write-touch" "/tmp" "$TMP/t-write-touch.jsonl" 1

# ③ 타 cwd + 무접촉 → 미캡처
reset_brain
run_case "3.outside+no-touch" "/tmp" "$TMP/t-no-touch.jsonl" 0
reset_brain
run_case "3b.outside+sibling-prefix-touch" "/tmp" "$TMP/t-sibling-touch.jsonl" 0

# ④ 타 cwd + Bash-only 쓰기 (claude: 커밋 그라운드트루스) → 캡처
reset_brain
git -C "$MY_BRAIN_DIR" init -q
git -C "$MY_BRAIN_DIR" -c user.email=t@t -c user.name=t commit -q --allow-empty -m "claude: test sync via bash"
run_case "4.outside+claude-commit" "/tmp" "$TMP/t-no-touch.jsonl" 1

# ⑤ 절단 방향 — 130턴: 앞 20(turn-001~020) + 뒤 100(turn-031~130) 보존, turn-021~030 생략
reset_brain
run_case "5.truncation-capture" "$MY_BRAIN_DIR" "$TMP/t-long.jsonl" 1
CAP=$(ls "$MY_BRAIN_DIR/raw/sessions"/*.md 2>/dev/null | head -1)
if [ -n "$CAP" ] && grep -q "turn-001" "$CAP" && grep -q "turn-130" "$CAP" \
   && ! grep -q "turn-025" "$CAP" && grep -q "생략" "$CAP"; then
  echo "PASS: 5.truncation-direction (head+tail 보존, 중간 생략 마커)"
else
  echo "FAIL: 5.truncation-direction"
  FAIL=1
fi

exit $FAIL
