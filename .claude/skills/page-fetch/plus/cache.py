"""On-disk fetch cache for page-fetch.

Cache entries are JSON files under `~/.cache/insane-fetch/`, keyed by
sha256(canonical_url + device_class + fmt + selectors). Only STRONG_OK results
are stored by default — WEAK_OK could be an attacker's well-shaped challenge
page (≥3000 bytes, no challenge marker) and storing those would poison
subsequent calls (consensus F6).

P23 (2026-06-12):
  - canonical URL key: utm_* and other tracking params stripped + query keys
    sorted so `?a=1&utm_source=x` and `?a=1` map to the same cache entry.
    Implementation mirrors search.py's _normalize_url but is self-contained.
  - lazy-unlink: get() removes expired entries on read so the cache dir
    doesn't accumulate unbounded stale files.
  - --cache-weak / INSANE_CACHE_WEAK_OK opt-in: callers may accept WEAK_OK
    entries when the security default is relaxed explicitly. Default remains
    STRONG_OK-only to preserve the F6 / N12 blast-radius rationale.
  - prune(): remove only expired entries (finer-grained than clear()).
  - info(): return a dict with entry count and total size for `plus cache info`.

Atomic writes go through `plus._atomic.atomic_write_text` so cache, winners,
and observe rotation all share one tested implementation (D15 follow-up,
2026-05-24). Original consensus rationale F7 / N12 still applies: a concurrent
reader must never see a partial JSON document.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from ._atomic import atomic_write_text

CACHE_DIR = Path.home() / ".cache" / "insane-fetch"

# Default TTL is 6 hours; INSANE_CACHE_TTL (seconds) overrides.
_DEFAULT_TTL_SECONDS = 6 * 60 * 60

# Verdicts that are safe to persist under the default (STRONG_OK-only) policy.
# WEAK_OK lacks positive proof — an attacker can craft a 3KB+ stub that passes
# Layer 1-3 of the validator without delivering real content. STRONG_OK
# requires success_selectors matching, so caching it is safe (consensus F6).
_CACHEABLE_VERDICTS_STRONG = frozenset({"strong_ok"})
# P23: opt-in extension — when INSANE_CACHE_WEAK_OK=1 (or --cache-weak flag
# is passed and callers set this env), weak_ok is also cached. The blast
# radius is smaller than cache-poisoning STRONG_OK entries but still non-zero
# (wrong content served for up to TTL). Disabled by default.
_CACHEABLE_VERDICTS_WEAK = frozenset({"strong_ok", "weak_ok"})

# P23: tracking-parameter names/prefixes mirrored from search.py _normalize_url.
# Cache uses its own copy so cache.py stays independently importable without
# pulling in all of search.py. Keep in sync with search._TRACKING_PARAMS.
_CACHE_TRACKING_PARAMS: frozenset[str] = frozenset({
    "fbclid", "gclid", "msclkid", "dclid", "igshid",
    "mc_cid", "mc_eid", "ref", "_hsenc", "_hsmi",
})
_CACHE_TRACKING_PREFIXES: tuple[str, ...] = ("utm_",)


def _ttl_seconds() -> int:
    """Resolve the cache TTL, honoring the INSANE_CACHE_TTL env override."""
    raw = os.environ.get("INSANE_CACHE_TTL")
    if raw is None:
        return _DEFAULT_TTL_SECONDS
    try:
        val = int(raw)
        return val if val > 0 else _DEFAULT_TTL_SECONDS
    except ValueError:
        return _DEFAULT_TTL_SECONDS


def _weak_ok_enabled() -> bool:
    """P23: True when INSANE_CACHE_WEAK_OK=1 is set in the environment.

    Security default is STRONG_OK-only (F6). Callers that need to cache
    WEAK_OK results — e.g. repeat crawls where selectors are never supplied
    — must set this env or pass --cache-weak (which __main__ translates to
    the env variable before delegating to cache).
    """
    return os.environ.get("INSANE_CACHE_WEAK_OK") == "1"


def _cacheable_verdicts(weak_ok: bool | None = None) -> frozenset:
    """Return the set of verdicts that may be persisted under current policy.

    `weak_ok` is the authoritative signal when the caller threads it explicitly
    (preferred — no process-global state). When left None it falls back to the
    `INSANE_CACHE_WEAK_OK` env so external callers / tests that only set the env
    keep working.
    """
    enabled = _weak_ok_enabled() if weak_ok is None else weak_ok
    return _CACHEABLE_VERDICTS_WEAK if enabled else _CACHEABLE_VERDICTS_STRONG


def _canonical_url(url: str) -> str:
    """P23: Normalize URL for cache key to improve hit rate.

    Transformations:
      - Lowercase host.
      - Strip trailing slash from path.
      - Remove known tracking parameters (utm_*, fbclid, …).
      - Sort remaining query keys for stable comparison.
      - Drop fragment (#…): content is identical regardless of anchor.

    Mirrors search.py's _normalize_url but is self-contained so cache.py
    stays independently importable. Keep tracking lists in sync.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc.lower()
    path = parts.path.rstrip("/")
    query_str = ""
    if parts.query:
        params = parse_qs(parts.query, keep_blank_values=True)
        cleaned: dict = {}
        for k, v in params.items():
            k_lower = k.lower()
            if k_lower in _CACHE_TRACKING_PARAMS:
                continue
            if any(k_lower.startswith(p) for p in _CACHE_TRACKING_PREFIXES):
                continue
            cleaned[k] = v
        if cleaned:
            query_str = urlencode(
                sorted(
                    ((k, vi) for k, vs in cleaned.items() for vi in vs),
                    key=lambda kv: kv[0],
                ),
            )
    return urlunsplit((parts.scheme, netloc, path, query_str, ""))


def _selector_fingerprint(selectors) -> str:
    """Stable string for selectors so cache key is sensitive to caller intent.

    None and [] collapse to the empty string so callers that never supply
    selectors still share entries. Order-insensitive — `["a", "b"]` and
    `["b", "a"]` hash identically.
    """
    if not selectors:
        return ""
    return "|".join(sorted(s for s in selectors if s))


def _key(url: str, device: str, fmt: str, selectors=None) -> str:
    """sha256 hexdigest of the cache key tuple.

    P23: url is canonicalized before hashing so tracking-param variants
    map to the same entry.  Fields are NUL-delimited: a NUL byte cannot
    appear in a URL, device, format, or selector string, so distinct tuples
    can never collide on a shared boundary.
    """
    canonical = _canonical_url(url)
    sel = _selector_fingerprint(selectors)
    return hashlib.sha256(
        f"{canonical}\0{device}\0{fmt}\0{sel}".encode("utf-8")
    ).hexdigest()


def _path_for(url: str, device: str, fmt: str, selectors=None) -> Path:
    return CACHE_DIR / f"{_key(url, device, fmt, selectors)}.json"


def get(url: str, device: str, fmt: str, selectors=None) -> str | None:
    """Return cached content if a fresh entry exists, else None.

    P23: expired entries are lazily unlinked on read so stale files don't
    accumulate indefinitely between explicit clear()/prune() calls.
    """
    path = _path_for(url, device, fmt, selectors)
    if not path.is_file():
        return None
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        # Corrupted entry: remove it so it self-heals on the next put()
        # instead of re-failing every lookup until TTL/clear().
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    ts = entry.get("ts")
    if not isinstance(ts, (int, float)):
        return None
    if (time.time() - ts) > _ttl_seconds():
        # P23: lazy-unlink expired entry on read.
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    content = entry.get("content")
    return content if isinstance(content, str) else None


def put(url: str, device: str, fmt: str, verdict: str, content: str,
        selectors=None, *, weak_ok: bool | None = None) -> None:
    """Store an entry — only when `verdict` is in the active cacheable set.

    P23: the cacheable set is STRONG_OK-only by default (F6). Pass
    `weak_ok=True` (preferred — the CLI threads `--cache-weak` through here)
    or set INSANE_CACHE_WEAK_OK=1 to also accept WEAK_OK results. The explicit
    kwarg takes precedence and avoids the prior process-global env mutation.

    Atomic via `atomic_write_text`: a concurrent reader either sees the old
    file or the new file in full.
    """
    if verdict not in _cacheable_verdicts(weak_ok):
        # Below the active policy threshold — skip silently. Caller has
        # already checked result.ok; we just refuse to persist.
        return
    entry = {
        "ts": time.time(),
        "url": url,
        "verdict": verdict,
        "content": content,
        "selectors": list(selectors) if selectors else [],
    }
    path = _path_for(url, device, fmt, selectors)
    atomic_write_text(path, json.dumps(entry, ensure_ascii=False))


def clear() -> int:
    """Delete every cache entry. Returns the number of files removed."""
    if not CACHE_DIR.is_dir():
        return 0
    removed = 0
    for f in CACHE_DIR.glob("*.json"):
        try:
            f.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def prune() -> int:
    """P23: Delete only expired cache entries. Returns the number removed.

    Finer-grained than clear() — fresh entries are preserved. Useful for
    scheduled housekeeping without discarding still-valid cached content.
    """
    if not CACHE_DIR.is_dir():
        return 0
    ttl = _ttl_seconds()
    now = time.time()
    removed = 0
    for f in CACHE_DIR.glob("*.json"):
        try:
            entry = json.loads(f.read_text(encoding="utf-8"))
            ts = entry.get("ts")
            if not isinstance(ts, (int, float)) or (now - ts) > ttl:
                f.unlink(missing_ok=True)
                removed += 1
        except (json.JSONDecodeError, OSError, ValueError):
            # Corrupted entry — remove it too.
            try:
                f.unlink(missing_ok=True)
                removed += 1
            except OSError:
                pass
    return removed


def info() -> dict:
    """P23: Return a summary dict for `plus cache info`.

    Returns:
        {
            "cache_dir": str,
            "entry_count": int,     # total .json files
            "fresh_count": int,     # entries within TTL
            "expired_count": int,   # entries past TTL (candidates for prune)
            "total_bytes": int,     # sum of file sizes
        }
    """
    if not CACHE_DIR.is_dir():
        return {
            "cache_dir": str(CACHE_DIR),
            "entry_count": 0,
            "fresh_count": 0,
            "expired_count": 0,
            "total_bytes": 0,
        }
    ttl = _ttl_seconds()
    now = time.time()
    entry_count = fresh_count = expired_count = total_bytes = 0
    for f in CACHE_DIR.glob("*.json"):
        try:
            size = f.stat().st_size
            total_bytes += size
            entry_count += 1
            try:
                ts = json.loads(f.read_text(encoding="utf-8")).get("ts")
                if isinstance(ts, (int, float)) and (now - ts) <= ttl:
                    fresh_count += 1
                else:
                    expired_count += 1
            except (json.JSONDecodeError, OSError, ValueError):
                expired_count += 1
        except OSError:
            pass
    return {
        "cache_dir": str(CACHE_DIR),
        "entry_count": entry_count,
        "fresh_count": fresh_count,
        "expired_count": expired_count,
        "total_bytes": total_bytes,
    }
