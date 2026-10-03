"""Append-only observation logging for page-fetch.

Every fetch appends one JSONL line under `~/.cache/brain/page-fetch/`.
Logging is best-effort: a logging failure must never break a
fetch — failures are swallowed with a single stderr warning.

The log is size-bounded. When it exceeds INSANE_OBSERVE_MAX_BYTES (default
5 MB) it is rotated `fetch-log.jsonl` -> `.1` -> `.2` -> `.3`; anything older
than `.3` is dropped. The log cannot grow without bound.

#20 follow-up (2026-05-24): the rotate decision (size-check → rename chain) is
serialized through `_atomic.exclusive_lock` so two concurrent fetches can't
both pass the size check, both rename `.2 → .3`, and corrupt the rotation
sequence. The append itself stays lock-free — POSIX `O_APPEND` writes of
small JSONL lines are atomic at the kernel level.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from ._atomic import exclusive_lock
from ._security import _sanitize_for_log

# Runtime crawl state is local to the user, never shipped in the skill tree.
OBSERVE_DIR = Path.home() / ".cache" / "brain" / "page-fetch"
LOG_PATH = OBSERVE_DIR / "fetch-log.jsonl"

_DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
_MAX_ROTATIONS = 3


def _max_bytes() -> int:
    """Resolve the rotation threshold, honoring INSANE_OBSERVE_MAX_BYTES."""
    raw = os.environ.get("INSANE_OBSERVE_MAX_BYTES")
    if raw is None:
        return _DEFAULT_MAX_BYTES
    try:
        val = int(raw)
        return val if val > 0 else _DEFAULT_MAX_BYTES
    except ValueError:
        return _DEFAULT_MAX_BYTES


def _rotate_if_needed() -> None:
    """Rotate the log when it exceeds the size threshold.

    fetch-log.jsonl -> fetch-log.1.jsonl -> .2 -> .3; .3 is dropped.

    #20: the size check and rename chain are serialized via
    `exclusive_lock(LOG_PATH)` so two concurrent writers can't both pass
    the size check and both run the rename sequence. The size is re-checked
    *inside* the lock — the first holder will have already rotated, so the
    second sees a small file and exits without acting.
    """
    if not LOG_PATH.is_file():
        return
    if LOG_PATH.stat().st_size <= _max_bytes():
        return

    with exclusive_lock(LOG_PATH):
        # Re-check under the lock: another thread may have rotated already.
        if not LOG_PATH.is_file():
            return
        if LOG_PATH.stat().st_size <= _max_bytes():
            return
        # Drop the oldest, then shift each rotation up by one.
        oldest = OBSERVE_DIR / f"fetch-log.{_MAX_ROTATIONS}.jsonl"
        if oldest.exists():
            oldest.unlink()
        for n in range(_MAX_ROTATIONS - 1, 0, -1):
            src = OBSERVE_DIR / f"fetch-log.{n}.jsonl"
            dst = OBSERVE_DIR / f"fetch-log.{n + 1}.jsonl"
            if src.exists():
                src.rename(dst)
        LOG_PATH.rename(OBSERVE_DIR / "fetch-log.1.jsonl")


def log(
    url: str,
    profile_used: str | None,
    verdict: str,
    attempts: int,
    ok: bool,
    *,
    elapsed_ms: float | None = None,
    impersonate: str | None = None,
    transform: str | None = None,
    hint_used: bool = False,
    fingerprint: str | None = None,
) -> None:
    """Append one observation line. Best-effort; never raises.

    P22 (2026-06-12): extended fields for winners hit-rate measurement:
      elapsed_ms   — wall-clock fetch time in milliseconds
      impersonate  — winning curl impersonate token (host-only)
      transform    — winning url_transform name (host-only)
      hint_used    — True when a winners hint was injected for this fetch

    P36 (2026-06-12): mis-record detection field:
      fingerprint  — short content fingerprint of the fetched body (or None).
                     Lets a log consumer spot when different probe methods to
                     the same host return identical bodies — i.e. a "success"
                     verdict that is actually the same challenge/block page.

    These fields are optional; callers that don't supply them produce None
    entries, preserving backward compatibility with existing log consumers.
    """
    try:
        OBSERVE_DIR.mkdir(parents=True, exist_ok=True)
        _rotate_if_needed()
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        # Sanitize before serialization: observations/fetch-log.jsonl is itself
        # read back into LLM context for subsequent turns, so any newline- or
        # control-char-smuggled instruction inside a host or URL would count
        # as a prompt-injection vector (consensus C5).
        # P22: impersonate/transform are sanitized with the same host-only
        # hygiene standard — they must never carry full paths or query strings.
        entry = {
            "ts": time.time(),
            "host": _sanitize_for_log(host, max_len=128),
            "url": _sanitize_for_log(url, max_len=512),
            "profile_used": profile_used,
            "verdict": verdict,
            "attempts": attempts,
            "ok": ok,
            "elapsed_ms": elapsed_ms,
            "impersonate": (
                _sanitize_for_log(impersonate, max_len=64)
                if impersonate is not None else None
            ),
            "transform": (
                _sanitize_for_log(transform, max_len=64)
                if transform is not None else None
            ),
            "hint_used": hint_used,
            # P36: fingerprint is a hex/short-string digest with no path or
            # query — sanitize on the same host-only standard for consistency.
            "fingerprint": (
                _sanitize_for_log(fingerprint, max_len=64)
                if fingerprint is not None else None
            ),
        }
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001 — logging must never break fetch
        print(f"[plus] warning: observation logging failed: {e}", file=sys.stderr)
