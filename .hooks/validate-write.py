#!/usr/bin/env python3
"""PostToolUse advisory bridge. Never blocks an already-completed write."""
import json
import os
import subprocess
import sys
from pathlib import Path

root = Path(os.environ.get("MY_BRAIN_DIR") or os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parent.parent)
try:
    event = json.load(sys.stdin)
    inputs = event.get("tool_input", {})
    target = inputs.get("file_path") or inputs.get("notebook_path")
    if target:
        result = subprocess.run(["node", str(root / ".tools/lint/validate-write.mjs"), target],
                                cwd=event.get("cwd") or root, check=False, timeout=4,
                                capture_output=True, text=True, encoding="utf-8")
        warning = result.stderr.strip()
        if warning:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                     "additionalContext": warning}}, ensure_ascii=False))
except (ValueError, OSError, subprocess.TimeoutExpired):
    pass
