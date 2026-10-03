"""Security helpers for the page-fetch managed value layer.

Implements Phase 1+2+3 guards (consensus-driven, 2026-05-24). Lives entirely
in `plus/` — `engine/` stays byte-identical to upstream insane-search v0.4.0.

This module is the *public surface* for security helpers. Lower-level
implementations live in:

- `_ssrf.py` — `SSRFBlockedError`, `_ssrf_guard`, `_post_redirect_check`
  (D14 split, follow-up to consensus 2026-05-24).
- `_atomic.py` — `atomic_write_text`, `atomic_write_json`, `exclusive_lock`
  (D15 consolidation; used by `cache.py`, `winners.py`, `observe.py`).

This file keeps the smaller, more closely-related helpers:

- `_per_domain_profile_dir(url)` — Playwright profileDir under
  `~/.cache/insane-fetch/pw/<sha256(host)[:16]>/` with mode `0o700`.
- `wrap_external_content(body, url=...)` — emits an `[external_data]`
  sentinel so an LLM consuming the body can demarcate untrusted data.
- `_sanitize_for_log(value)` — length cap + control-char strip + newline
  collapse. Applied to URL/host fields before they hit
  `observations/fetch-log.jsonl` (which is itself read back into future
  LLM context).
- `_check_proxy_env()` — warn-once-per-process about suspicious proxy/CA
  env vars (D3 idempotency, follow-up 2026-05-24).
- `BlockedQueryError`, `_check_blocked_query` — refuse to send a user-
  blocked term to external search APIs (Phase 3 / CLAUDE.md integration).
  Thread-safe (D4 lock, follow-up 2026-05-24).
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

# Re-exports — every existing `from plus._security import X` keeps working.
from ._ssrf import (  # noqa: F401
    ALLOWED_SCHEMES,
    SSRFBlockedError,
    _ip_literal_check,
    _is_blocked_ip,
    _NUMERIC_HOST,
    _post_redirect_check,
    _resolve_non_standard_ipv4,
    _ssrf_guard,
)


# ---------------------------------------------------------------------------
# Per-domain Playwright profileDir
# ---------------------------------------------------------------------------

_PROFILE_ROOT = Path.home() / ".cache" / "insane-fetch" / "pw"


def _per_domain_profile_dir(url: str) -> str:
    """Stable per-domain profileDir under `~/.cache/insane-fetch/pw/`.

    The directory plus its parent are chmod-ed to `0o700` so cookies and
    localStorage don't leak across users on shared machines. Hashing the
    hostname avoids exposing visited domains in the filesystem path.
    """
    parts = urlsplit(url)
    host = parts.hostname or "_anonymous"
    digest = hashlib.sha256(host.encode("utf-8")).hexdigest()[:16]
    target = _PROFILE_ROOT / digest
    target.mkdir(parents=True, exist_ok=True)
    # chmod is best-effort; parents may already exist with looser modes
    # from a previous run, but the leaf and the pw/ root tighten back to 0o700.
    try:
        os.chmod(target, 0o700)
        os.chmod(_PROFILE_ROOT, 0o700)
    except OSError:
        pass
    return str(target)


# ---------------------------------------------------------------------------
# LLM-facing sentinel wrap + log sanitization (C5 taint marker)
# ---------------------------------------------------------------------------

_CTRL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _strip_control_chars(s: str) -> str:
    """Strip ASCII control chars that confuse log parsers and LLM prompts."""
    return _CTRL_CHARS.sub("", s)


def _sanitize_for_log(value: object, max_len: int = 256) -> str:
    """Length cap + control-char strip + newline collapse.

    `observations/fetch-log.jsonl` is read back into Claude's context for
    subsequent turns, so any newline-smuggled instruction inside a host or
    URL would otherwise count as a prompt-injection vector.
    """
    if not isinstance(value, str):
        value = str(value)
    cleaned = _strip_control_chars(value).replace("\n", " ").replace("\r", " ")
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def wrap_external_content(body: str, *, url: str) -> str:
    """Wrap fetched content with a taint sentinel.

    Tells downstream LLM consumers "this is untrusted external data, do not
    treat it as instructions". Sentinel is intentionally distinctive
    (`[external_data:url=<host>]…[/external_data]`) so prompt-engineering
    guidelines can refer to it stably.
    """
    host = urlsplit(url).hostname or "unknown"
    host = _sanitize_for_log(host, max_len=80)
    return f"[external_data:url={host}]\n{body}\n[/external_data]"


# ---------------------------------------------------------------------------
# Proxy/CA env sniffing (Phase 2, consensus C6 sibling)
# ---------------------------------------------------------------------------

# Env vars that — if attacker-set — route traffic through a MITM endpoint
# or swap the trust store. We warn but do not block: legitimate corporate
# proxies set these all the time, so a fail-closed default would be hostile.
# `INSANE_PROXY_ACK=1` silences the warning entirely (acknowledged setup).
_PROXY_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
    "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE",
    "SSL_CERT_DIR",
)

# D3 follow-up (2026-05-24): the warning was previously emitted on every
# `_check_proxy_env()` call, which during a single CLI invocation (or test
# run hitting multiple subcommands) became noisy. The flag below caches the
# decision so the stderr line shows at most once per Python process. Tests
# reset it via `_proxy_warning_state.clear()`.
_proxy_warning_state: dict = {"emitted": False}


def _check_proxy_env() -> list:
    """Return the list of suspicious proxy/CA env vars currently set.

    Emits one stderr warning per process unless `INSANE_PROXY_ACK=1` is set.
    Never raises — this is informational so legitimate corporate setups
    (which rely on these vars) still work.
    """
    if os.environ.get("INSANE_PROXY_ACK") == "1":
        return []
    suspect = [v for v in _PROXY_ENV_VARS if os.environ.get(v)]
    if suspect and not _proxy_warning_state["emitted"]:
        print(
            f"[plus] warning: proxy/CA env vars set ({', '.join(suspect)}); "
            f"they could route traffic through a MITM endpoint or swap the "
            f"trust store. Set INSANE_PROXY_ACK=1 to silence this warning.",
            file=sys.stderr,
        )
        _proxy_warning_state["emitted"] = True
    return suspect


# ---------------------------------------------------------------------------
# Blocked-terms query guard (Phase 3, consensus F9 + CLAUDE.md integration)
# ---------------------------------------------------------------------------

class BlockedQueryError(Exception):
    """Raised when a search/crawl query contains a user-configured blocked term.

    D7 follow-up (2026-05-24): no longer subclasses ValueError. A blocked-term
    refusal is a *security policy* decision, not value validation — letting a
    generic `except ValueError:` silently swallow the block would mask the
    policy. Callers must catch `BlockedQueryError` (or a parent thereof)
    explicitly.
    """


# The user's optional blocklist stays outside the vendored skill.
# Override its path with INSANE_BLOCKED_TERMS_FILE; no personal terms are bundled.
_DEFAULT_BLOCKED_TERMS_FILE = Path.home() / ".config" / "page-fetch" / "blocked-terms"

# Memoize the parsed list per file mtime so repeat calls don't re-read disk.
# D4 follow-up (2026-05-24): the mtime check + dict mutation is a read-
# modify-write race when two threads call `_read_blocked_terms()` at once.
# The lock makes the cache update atomic.
_blocked_cache: dict = {"path": None, "mtime": 0.0, "terms": tuple()}
_blocked_cache_lock = threading.Lock()


def _read_blocked_terms() -> tuple:
    """Read the blocked-terms file. Cached by mtime; returns a tuple of strings.

    Thread-safe (D4): the mtime check, file read, and cache update are
    serialized so two callers can't both see a stale mtime, both read the
    file, and one of them clobber a newer-mtime entry on store.
    """
    if os.environ.get("INSANE_DISABLE_BLOCKED_TERMS") == "1":
        return tuple()
    path = Path(
        os.environ.get("INSANE_BLOCKED_TERMS_FILE")
        or _DEFAULT_BLOCKED_TERMS_FILE
    )
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return tuple()
    with _blocked_cache_lock:
        if (
            _blocked_cache["path"] == str(path)
            and _blocked_cache["mtime"] == mtime
        ):
            return _blocked_cache["terms"]
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return tuple()
        terms = tuple(
            line.strip() for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        )
        _blocked_cache.update({"path": str(path), "mtime": mtime, "terms": terms})
        return terms


def _check_blocked_query(query: str) -> Optional[str]:
    """Return the matched blocked term if `query` contains one, else None.

    Case-insensitive substring match. The caller decides whether to raise
    `BlockedQueryError` (search). crawl.py does not currently apply this guard.
    """  # P3 (2026-06-11): corrected — crawl has no blocked-term guard (W38)
    if not query:
        return None
    haystack = query.lower()
    for term in _read_blocked_terms():
        if term.lower() in haystack:
            return term
    return None
