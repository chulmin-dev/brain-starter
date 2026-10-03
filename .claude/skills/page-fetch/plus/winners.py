"""Host-specific winning combo memory.

Records (impersonate, url_transform, referer_strategy) tuples that succeeded
for a given host. On the next fetch to that host, we inject the cached combo
as `user_hint` so the engine's grid is biased to the known-good probe first
— removing cold-start cost for repeat domains.


Storage: `~/.cache/brain/page-fetch/winners.json` — a single small JSON file mapping
host → combo. Read-mostly. The write path is atomic (tempfile + replace,
via `_atomic.atomic_write_json`) and tolerant of corruption (returns empty
dict on parse error, self-heals on the next write).

D12 follow-up (2026-05-24): the load-then-save sequence in `record()` is a
read-modify-write that two processes can interleave even with atomic
replace — host A's write loses host B's update. `_atomic.exclusive_lock`
serializes the load-mutate-save block so the on-disk file accumulates
both updates.

Limitations the engine prevents from being fully exploited:
- `url_transform` is decided by the WAF profile inside `iter_transformed`,
  not by user_hint, so we *record* the winning transform for diagnostics
  but only *apply* `impersonate_first` + `referer_strategy` through hint.
  Engine PR could expose a `url_transform_first` hint to close that gap.

Phase 11 — weak_ok acceptance with TTL (2026-05-24)
---------------------------------------------------
Recording accepts both strong_ok and weak_ok; a winner is a retrieval hint,
not cached content or positive proof that the requested page was obtained.

Asymmetry with `cache.py` (which keeps strong_ok-only): cache stores
*content* that flows straight into the LLM turn, so an attacker stub there
is a direct content-poisoning vector. Winners stores a *combo hint* that
only re-orders the engine's probe grid; if the hint is wrong the next
fetch still grabs fresh response from the real server. Wrong combo →
degrades to cold-start fallback, no content poisoning. The risk surface
is materially smaller.

Phase 11 trade-off (kept conservative):
- `weak_ok` accepted by default — env `INSANE_DISABLE_WINNERS_WEAK_OK=1`
  restores strong_ok-only behaviour for callers who do supply selectors.
- 7-day TTL caps the worst-case lock-in window — a stale or
  attacker-influenced entry self-expires.
- Entries written before this change lack `recorded_at` and are treated as
  expired (re-recorded fresh on next visit).

Disable everything with `INSANE_DISABLE_WINNERS=1` (existing escape hatch).
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from ._atomic import atomic_write_json, exclusive_lock

_WINNERS_PATH = Path.home() / ".cache" / "brain" / "page-fetch" / "winners.json"

# Phase 11: 7-day TTL bounds the lock-in window for any single recorded
# combo. After expiry the entry is ignored on read and overwritten on the
# next successful fetch to the host.
_TTL_SECONDS = 7 * 24 * 3600

# Polarity matches the rest of the project's opt-out toggles
# (`INSANE_DISABLE_SSRF_GUARD`, `INSANE_DISABLE_BLOCKED_TERMS`, ...):
# unset/empty/anything-but-"1" → weak_ok accepted; "1" → strong-only.
_WEAK_OK_DISABLE_ENV = "INSANE_DISABLE_WINNERS_WEAK_OK"

# P22 (2026-06-12): negative-invalidation strike threshold.
# A hint that causes 2 consecutive failed fetches is considered unreliable
# and is deleted so the engine falls back to cold-start grid search.
_STRIKE_THRESHOLD = 2

# ADAPT-4: verdicts that mean the bypass ROUTE genuinely failed → strike.
# Transient outcomes (rate_limited, unknown, network error, budget cut)
# and URL-level outcomes (not_found / auth_required) do NOT strike the
# combo — they are not the route's fault. "unknown" is explicitly excluded:
# an exception or dependency failure must not evict a good combo.
_PENALIZE_VERDICTS: frozenset[str] = frozenset({"challenge", "blocked"})

# ADAPT-5: bounded LRU cap. Default 500 mirrors upstream learning.py MAX_ENTRIES.
# Prune runs in-memory on load; the pruned set is persisted on next write
# (converge-on-write pattern, same as upstream).
_MAX_ENTRIES: int = int(os.environ.get("INSANE_WINNERS_MAX", "500") or "500")


def _enabled() -> bool:
    return os.environ.get("INSANE_DISABLE_WINNERS") != "1"


def _weak_ok_accepted() -> bool:
    """Phase 11: weak_ok recording is on by default; `=1` restores strong-only."""
    return os.environ.get(_WEAK_OK_DISABLE_ENV) != "1"


def _now() -> float:
    """Wall-clock seconds since epoch. Indirection lets tests freeze time."""
    return time.time()


def _winners_key(host: str, device_class: str) -> str:
    """ADAPT-3: device-class-aware key so mobile and desktop combos coexist.

    Format: `host::desktop` or `host::mobile`.
    Legacy host-only keys (no `::`) written before ADAPT-3 are treated as
    cache misses (get_hint returns None) and overwritten on next write —
    backward-compat: they never crash lookups, just produce misses.
    """
    dev = "mobile" if device_class == "mobile" else "desktop"
    return f"{host}::{dev}"


def _prune(data: dict, now: Optional[float] = None) -> dict:
    """ADAPT-5: drop TTL-expired entries then enforce LRU cap. Pure (in-memory).

    Pruning is converge-on-write: this runs in _load() but the pruned dict is
    only persisted the next time _save() is called (same pattern as upstream
    learning.py). Expired entries are removed first; then if still over-cap,
    the least-recently-used (smallest recorded_at) entries are dropped.
    """
    cutoff = (now if now is not None else _now()) - _TTL_SECONDS
    kept: dict = {}
    for k, v in data.items():
        if not isinstance(v, dict):
            continue
        ts = v.get("recorded_at")
        if not isinstance(ts, (int, float)):
            continue  # no timestamp → expired (legacy entry)
        if ts >= cutoff:
            kept[k] = v
    if len(kept) > _MAX_ENTRIES:
        # Drop least-recently-used (smallest recorded_at) to reach cap.
        ordered = sorted(kept.items(), key=lambda kv: kv[1].get("recorded_at", 0))
        for k, _ in ordered[: len(kept) - _MAX_ENTRIES]:
            del kept[k]
    return kept


def _load() -> dict:
    """Read winners.json, pruning TTL-expired and over-cap entries in memory."""
    try:
        text = _WINNERS_PATH.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return {}
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    raw = data if isinstance(data, dict) else {}
    return _prune(raw)  # ADAPT-5: prune on every load; persisted on next write


def _save(data: dict) -> None:
    """Atomic write to winners.json. Best-effort; never raises."""
    try:
        atomic_write_json(_WINNERS_PATH, data, indent=2, sort_keys=True)
    except OSError:
        pass


def _is_fresh(combo: dict) -> bool:
    """Phase 11: entry is fresh iff `recorded_at` is a number within TTL.

    Missing/corrupt/future timestamps are treated as expired so legacy entries
    (no timestamp) and clock-skew anomalies don't poison the cache. A future
    `recorded_at` (greater than now) is also rejected — wall clock moved
    backwards or the entry was hand-edited, either way we can't trust the
    age claim.
    """
    ts = combo.get("recorded_at")
    if not isinstance(ts, (int, float)):
        return False
    now = _now()
    age = now - ts
    return 0 <= age <= _TTL_SECONDS


def get_hint(url: str, device_class: str = "desktop") -> Optional[dict]:
    """Return a `user_hint` dict for `url`'s host, or None if no record.

    ADAPT-3: keyed by `host::device_class` so mobile and desktop combos
    coexist. Legacy host-only keys (pre-ADAPT-3) yield a miss — they are
    never crashed on, just ignored (backward-compat).

    Output shape matches what `engine.fetch_chain.fetch` accepts via its
    `user_hint=` parameter — `impersonate_first` and `referer_strategy`.
    Phase 11: expired or timestamp-less entries return None (overwritten on
    next successful fetch).

    P22 (2026-06-12): also exposes `url_transform_first` when the stored
    combo has a winning `transform` value, so the engine's grid is biased
    to the known-good transform (previously recorded but never applied).
    """
    if not _enabled():
        return None
    host = urlsplit(url).hostname
    if not host:
        return None
    key = _winners_key(host, device_class)
    combo = _load().get(key)
    if not isinstance(combo, dict):
        return None
    if not _is_fresh(combo):
        return None

    hint: dict = {}
    impersonate = combo.get("impersonate")
    if isinstance(impersonate, str) and impersonate:
        hint["impersonate_first"] = impersonate
    referer = combo.get("referer")
    if isinstance(referer, str) and referer:
        hint["referer_strategy"] = referer
    # P22: apply url_transform_first when a non-trivial transform was recorded.
    # "original" means no transform — skip it to avoid no-op hint noise.
    transform = combo.get("transform")
    if isinstance(transform, str) and transform and transform != "original":
        hint["url_transform_first"] = transform
    return hint or None


def _pick_winning_attempt(result):
    """Return the trace attempt to learn from, or None.

    Order of preference:
    1. First STRONG_OK — caller supplied success_selectors and the response
       cleared positive proof. Always trusted regardless of env.
    2. First WEAK_OK — only when `INSANE_WINNERS_WEAK_OK` != "0" (default on).
       The asymmetry with cache.py is documented at module top: a wrong combo
       hint degrades to cold-start fallback, not to content poisoning, so the
       blast radius is materially smaller than persisting weak_ok content.

    Skips attempts that lack a curl `impersonate` (e.g. Playwright fallback)
    because the combo wouldn't be actionable as a `user_hint`.
    """
    weak_fallback = None
    accept_weak = _weak_ok_accepted()
    for att in (getattr(result, "trace", None) or []):
        verdict = getattr(att, "verdict", "")
        if not getattr(att, "impersonate", None):
            # Non-curl attempts can't seed user_hint regardless of verdict.
            continue
        if verdict == "strong_ok":
            return att
        if accept_weak and weak_fallback is None and verdict == "weak_ok":
            weak_fallback = att
        # A6 (Wave 3): SUSPECT_OK is explicitly excluded from winners.
        # It is not a trust token — uncertain outcome must not become a
        # sticky cross-session hint. Only STRONG_OK / WEAK_OK are recorded.
    return weak_fallback


def record(url: str, result, device_class: str = "desktop") -> None:
    """Persist a known-good probe combo for `url`'s host.

    ADAPT-3: keyed by `host::device_class` so mobile and desktop combos
    coexist without overwriting each other.

    Called from `engine_proxy._proxy_fetch` after each fetch. Best-effort:
    never raises, silently skips anything that doesn't qualify.

    Phase 11: also persists `weak_ok` (env-gated) and stamps `recorded_at`
    so `get_hint` can expire entries via the module TTL.

    D12: the read-modify-write of `winners.json` is wrapped in an exclusive
    file lock so two concurrent fetches to different hosts don't lose one
    another's update through last-writer-wins.
    """
    if not _enabled():
        return
    if not result or not getattr(result, "ok", False):
        return
    host = urlsplit(url).hostname
    if not host:
        return

    winning = _pick_winning_attempt(result)
    if winning is None:
        return

    # P36: fingerprint the successful body so a future fetch can detect that a
    # *different* probe combo returned an identical body — a strong signal the
    # "success" is the same challenge/block page echoed back, not real content.
    fingerprint = None
    try:
        from ._fingerprint import content_fingerprint
        fingerprint = content_fingerprint(getattr(result, "content", None))
    except Exception:  # noqa: BLE001 — fingerprinting is best-effort
        fingerprint = None

    combo = {
        "impersonate": getattr(winning, "impersonate", None),
        "transform": getattr(winning, "url_transform", "original"),
        "referer": getattr(winning, "referer", "self_root"),
        "verdict": winning.verdict,
        "profile_used": getattr(result, "profile_used", None),
        "recorded_at": _now(),
        # P22: reset strike counter on a successful hint-assisted fetch so a
        # transient network failure that triggered strikes doesn't permanently
        # suppress a valid entry once the host recovers.
        "strikes": 0,
        # P36: short content fingerprint of the winning body (None when the
        # fingerprint backend is unavailable or the body is empty).
        "fingerprint": fingerprint,
    }

    key = _winners_key(host, device_class)  # ADAPT-3: device-class key

    with exclusive_lock(_WINNERS_PATH):
        data = _load()
        prior = data.get(key)
        # P36 mis-record detection: same fingerprint, different combo → warn.
        # A genuinely-changing site varies its body across combos; an identical
        # fingerprint from a different impersonate/transform means both probes
        # were handed the same page (commonly a challenge/block stub that
        # happened to clear the shape gates).
        if (
            isinstance(prior, dict)
            and fingerprint is not None
            and prior.get("fingerprint") == fingerprint
            and (
                prior.get("impersonate") != combo["impersonate"]
                or prior.get("transform") != combo["transform"]
            )
        ):
            print(
                f"[plus] winners: WARNING — host {host} returned identical "
                f"content fingerprint for two different probe combos "
                f"({prior.get('impersonate')}/{prior.get('transform')} vs "
                f"{combo['impersonate']}/{combo['transform']}); the 'success' "
                f"may be a challenge/block page echoed back (P36 mis-record).",
                file=sys.stderr,
            )
        data[key] = combo
        _save(data)


def strike(url: str, result=None, device_class: str = "desktop") -> None:
    """P22 / ADAPT-4: record a failed fetch that used a winners hint.

    ADAPT-4: Only a REAL block (verdict `challenge` / `blocked` or result
    indicates grid exhaustion) earns a strike. Transient outcomes
    (rate_limited, unknown, network error, budget cut) and URL-level
    outcomes (not_found / auth_required) do NOT strike — they are not the
    route's fault. Specifically `unknown` is excluded: an exception or
    dependency failure must not evict a good combo.

    When result=None (legacy callers), the strike is always applied
    (conservative: unknown failure treated as real block to avoid regression
    in existing call sites during transition).

    ADAPT-3: keyed by device_class so strikes against a mobile combo don't
    affect the desktop entry for the same host.

    Each call increments the `strikes` counter. When the counter reaches
    `_STRIKE_THRESHOLD` the entry is deleted so the engine falls back to
    cold-start grid search. Best-effort (never raises).
    """
    if not _enabled():
        return
    host = urlsplit(url).hostname
    if not host:
        return

    # ADAPT-4: classify whether this failure should penalize the combo.
    if result is not None:
        verdict = getattr(result, "verdict", "") or ""
        # `exhausted` signal: result.ok is False and no strong verdict
        # (grid burned all attempts without a clear block page). Treat
        # grid-exhaustion as penalizable — same as upstream PENALIZE_REASONS.
        exhausted = (not getattr(result, "ok", False)
                     and verdict not in _PENALIZE_VERDICTS
                     and verdict not in {"unknown", "rate_limited",
                                         "auth_required", "not_found",
                                         "suspect_ok"})
        penalize = verdict in _PENALIZE_VERDICTS or exhausted
        if not penalize:
            return  # transient / URL-level failure — do not strike
    # result is None → legacy caller; apply strike unconditionally (conservative).

    key = _winners_key(host, device_class)
    try:
        with exclusive_lock(_WINNERS_PATH):
            data = _load()
            combo = data.get(key)
            if not isinstance(combo, dict):
                return
            new_strikes = int(combo.get("strikes") or 0) + 1
            if new_strikes >= _STRIKE_THRESHOLD:
                # Threshold reached — delete the entry so cold-start
                # grid search resumes on the next fetch to this host.
                del data[key]
            else:
                combo["strikes"] = new_strikes
                data[key] = combo
            _save(data)
    except Exception:  # noqa: BLE001 — strike is best-effort, never breaks fetch
        pass
