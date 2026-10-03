"""Monkey-patch wrapper installing plus' Phase 1 guards over the frozen engine.

`engine/` is a hard fork of insane-search v0.4.0 upstream. Phase 1 guards
(SSRF, per-domain profileDir) wrap engine's two public entrypoints from plus
without touching engine source.

Patched targets:
    engine.fetch_chain.fetch                — pre-SSRF + per-hop + post-redirect
                                              SSRF + winners hint
    engine.executor.run_playwright_fallback — per-domain profileDir
                                              (the old Cloudflare force_executor
                                              coercion was removed in P13/W9 —
                                              see `_proxy_fallback`)

`install()` is idempotent — safe to call multiple times. It inspects the
engine signatures and emits a `RuntimeWarning` if upstream drifts, since
silent monkey-patch failure on upstream sync is itself a security risk
(consensus VI4 finding).

For testing, `uninstall()` reverses the patch.
"""
from __future__ import annotations

import inspect
import os
import sys
import time
import traceback
import warnings
from typing import Any

from engine import fetch_chain as _engine_fetch_chain
from engine import executor as _engine_executor

from ._security import (
    SSRFBlockedError,
    _ip_literal_check,
    _per_domain_profile_dir,
    _post_redirect_check,
    _ssrf_guard,
)


_INSTALLED = False
_ORIGINAL_FETCH = None
_ORIGINAL_FALLBACK = None

# P10 (2026-06-11): once-per-process flag so a persistent winners failure
# emits exactly 1 stderr line rather than 1-per-fetch (W12).
_winners_warned: dict = {"emitted": False}


def _warn_winners(exc: Exception) -> None:
    """Emit a single stderr warning on first winners failure. Mirrors observe.py:109."""
    if _winners_warned["emitted"]:
        return
    _winners_warned["emitted"] = True
    print(
        f"[plus] warning: winners cache unavailable ({type(exc).__name__}: {exc}); "
        "fetch continues without combo hints. Check local cache permissions.",
        file=sys.stderr,
    )
    if os.environ.get("INSANE_DEBUG") == "1":
        traceback.print_exc(file=sys.stderr)


# M-CODE: one-shot pool warning so a permanently-broken SessionPool is not
# invisible. Mirrors the _warn_winners pattern — surfaces once on stderr, then
# degrades silently. The pool is best-effort (never blocks a fetch), but a
# broken pool should be observable for debugging.
_pool_warned: dict = {"emitted": False}


def _warn_pool(exc: Exception, site: str) -> None:
    """Emit a single stderr warning on first SessionPool failure."""
    if _pool_warned["emitted"]:
        return
    _pool_warned["emitted"] = True
    print(
        f"[plus] warning: SessionPool {site} failed ({type(exc).__name__}: {exc}); "
        "degrading to per-call Session. Set INSANE_DEBUG=1 for traceback.",
        file=sys.stderr,
    )
    if os.environ.get("INSANE_DEBUG") == "1":
        traceback.print_exc(file=sys.stderr)


# Frozen against insane-search v0.4.0. If upstream drops one of these we
# silently lose a guard — install() inspects and warns.
_EXPECTED_FETCH_PARAMS = {
    "url",
    "success_selectors",
    "device_class",
    "user_hint",
    "timeout",
    "max_attempts",
    "enable_playwright",
    "url_check",
    "ip_check",   # C8/P39r: connect-IP pin seam (keyword-default, optional)
    "session",    # A2: optional caller-supplied Session (pool); None = per-call
}
_EXPECTED_FALLBACK_PARAMS = {
    "url",
    "profile_id",
    "success_selectors",
    "device_class",
    "timeout",
    "profile_dir",
    "force_executor",
    "cookies",  # P21: curl→Chrome clearance handoff (keyword-default, optional)
    "capture_json",  # P32: opt-in CDP NetworkJournal envelope (keyword-default)
}


def _check_signature(fn, expected: set, name: str) -> None:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        warnings.warn(
            f"engine_proxy: could not inspect {name} signature; "
            "monkey-patch may silently fail on upstream drift",
            RuntimeWarning,
            stacklevel=3,
        )
        return
    params = [
        p for p in sig.parameters.values()
        if p.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
    ]
    actual = {p.name for p in params}
    missing = expected - actual
    if missing:
        warnings.warn(
            f"engine_proxy: upstream {name} dropped expected parameters "
            f"{sorted(missing)!r}; guards may be ineffective. "
            "Review UPSTREAM.md sync policy.",
            RuntimeWarning,
            stacklevel=3,
        )
    # If upstream adds a *new required* parameter, our wrapper still calls
    # the original with only `kwargs` we know about — TypeError at call time.
    # Surface this at install time so the failure mode is "loud warning" not
    # "silent crash on first fetch".
    new_required = [
        p.name for p in params
        if p.name not in expected and p.default is inspect.Parameter.empty
    ]
    if new_required:
        warnings.warn(
            f"engine_proxy: upstream {name} added new required parameters "
            f"{sorted(new_required)!r} that the wrapper does not pass through; "
            "calls will fail with TypeError. Update _EXPECTED_*_PARAMS and "
            "the wrapper signature.",
            RuntimeWarning,
            stacklevel=3,
        )


def _proxy_fetch(url: str, **kwargs: Any):
    """Wrapped `engine.fetch_chain.fetch` with SSRF pre/per-hop/post + winners.

    P22 (2026-06-12): observe.log is called here rather than in __main__ so
    all traffic routed through _proxy_fetch (fetch, search, crawl) is logged
    automatically — not only the explicit `plus fetch` CLI path.
    """
    # Pre-flight: refuse SSRF-prone URLs before the request leaves.
    _ssrf_guard(url)

    # Per-hop guard (patch queue item #2, C1): inject `_ssrf_guard` as the
    # engine's `url_check` callback so every redirect target is screened
    # *before* the next GET goes out. Without this the libcurl-followed
    # chain could pivot from an external host to an internal IP and the
    # caller would only learn after-the-fact via the post-redirect check
    # below.
    #
    # P10 (2026-06-11): compose with caller-supplied url_check rather than
    # letting caller replace the SSRF guard entirely (W10). Previously a
    # single kwarg could bypass all per-hop SSRF protection. The unified
    # bypass is now INSANE_DISABLE_SSRF_GUARD=1 (env-gated inside _ssrf_guard).
    # url_check=None is treated as "no caller check" — guard-only.
    caller_url_check = kwargs.get("url_check")
    if caller_url_check is not None:
        def _composed_url_check(u: str) -> None:
            _ssrf_guard(u)
            caller_url_check(u)  # type: ignore[misc]
        kwargs["url_check"] = _composed_url_check
    else:
        kwargs["url_check"] = _ssrf_guard

    # C8/P39r: inject the connect-IP pin check. The engine resolves each hop's
    # host once, asks `ip_check` to vet that exact IP, then pins it into libcurl
    # so the verified IP and the connected IP are identical — closing the
    # DNS-rebinding TOCTOU the per-hop url_check alone leaves open. Compose with
    # any caller-supplied ip_check (same policy as url_check: guard never
    # replaced). The pin itself is engine-side and honours INSANE_DISABLE_IP_PIN;
    # this callback only renders the SSRF verdict on the pre-resolved IP.
    caller_ip_check = kwargs.get("ip_check")
    if caller_ip_check is not None:
        def _composed_ip_check(u: str, ip: str) -> None:
            _ip_literal_check(u, ip)
            caller_ip_check(u, ip)  # type: ignore[misc]
        kwargs["ip_check"] = _composed_ip_check
    else:
        kwargs["ip_check"] = _ip_literal_check

    # P22: track whether a winners hint was injected for this fetch so the
    # observation log can record hit-rate and so failed hint fetches can be
    # struck from the winners store.
    _hint_used = False

    # Winners cache (Phase 3): inject the host's known-good probe combo as
    # user_hint when the caller didn't already supply one. Cuts cold-start
    # cost on repeat domains by skipping the engine's grid search.
    # Distinguish "not given" from "given empty" — a caller passing
    # `user_hint={}` is signalling "no hint" intentionally and should not be
    # overridden by learned state.
    # ADAPT-3: propagate device_class so winners keys are device-aware.
    # "auto" is treated as "desktop" for lookup/record purposes — the engine
    # resolves "auto" internally; we use whatever the caller passed.
    _device_class: str = str(kwargs.get("device_class") or "desktop")

    if "user_hint" not in kwargs or kwargs["user_hint"] is None:
        try:
            from .winners import get_hint
            learned = get_hint(url, device_class=_device_class)
            if learned:
                kwargs["user_hint"] = learned
                _hint_used = True
        except Exception as _exc:
            # P10 (2026-06-11): winners is opt-in — never break a fetch, but
            # surface the failure once so silent permanent degradation is visible.
            _warn_winners(_exc)

    # A2: per-host SessionPool (default OFF; enabled by INSANE_SESSION_POOL=1).
    # When ON, acquire a live curl_cffi Session keyed to the URL's host so TLS
    # handshake + connection are reused across calls to the same host. The
    # pool does not bypass any SSRF guard — guards already ran above. When OFF
    # (the default), this block is a no-op and kwargs stays unchanged, keeping
    # the code path byte-identical to today.
    # The caller must NOT supply a `session` kwarg when the pool is active;
    # we inject it here, and release it in the finally below.
    _pool_session = None
    if "session" not in kwargs:
        try:
            from ._session_pool import acquire as _pool_acquire, pool_enabled as _pool_on
            if _pool_on():
                _pool_session = _pool_acquire(url)
                if _pool_session is not None:
                    kwargs["session"] = _pool_session
        except Exception as _pool_exc:  # noqa: BLE001 — pool is best-effort
            _warn_pool(_pool_exc, "acquire")
            _pool_session = None

    # P22: wall-clock timing for the observation log.
    _t0 = time.monotonic()
    _elapsed_ms = 0.0
    try:
        result = _ORIGINAL_FETCH(url, **kwargs)
        _elapsed_ms = (time.monotonic() - _t0) * 1000.0
    finally:
        # A2: return the pooled session regardless of outcome (success or
        # exception). _elapsed_ms is set on the success path; the finally
        # block runs whether or not an exception propagates, so the pool
        # session is always released without swallowing the original exception.
        if _pool_session is not None:
            try:
                from ._session_pool import release as _pool_release
                _pool_release(url, _pool_session)
            except Exception as _pool_exc:  # noqa: BLE001
                _warn_pool(_pool_exc, "release")

    # Record the winning combo for next time (best-effort, no-op on failure).
    # P22 / ADAPT-4: if the fetch failed *and* a hint was used, strike only on
    # real blocks (verdict challenge/blocked/exhausted); transient and URL-level
    # failures do NOT strike a good combo.
    try:
        from .winners import record
        record(url, result, device_class=_device_class)
    except Exception as _exc:
        # P10 (2026-06-11): same policy — warn once, never raise.
        _warn_winners(_exc)

    if _hint_used and not getattr(result, "ok", False):
        try:
            from .winners import strike as _strike
            _strike(url, result=result, device_class=_device_class)
        except Exception:  # noqa: BLE001 — strike is best-effort
            pass

    # P22: observation logging is centralized here — covers fetch/search/crawl
    # paths. __main__ emits only the stderr trace summary, NOT a separate
    # observe.log call, so there is no double-logging (CR-M5: prior comment
    # claimed a second __main__ call that does not exist).
    try:
        from .observe import log as _obs_log
        # Extract winning impersonate/transform from the trace for logging.
        _winning_attempt = None
        for _att in (getattr(result, "trace", None) or []):
            if getattr(_att, "verdict", "") in ("strong_ok", "weak_ok"):
                _winning_attempt = _att
                break
        # P36: fingerprint the body so the observation log records when distinct
        # probe methods to a host return identical content (mis-record signal).
        _fingerprint = None
        try:
            from ._fingerprint import content_fingerprint as _cfp
            _fingerprint = _cfp(getattr(result, "content", None))
        except Exception:  # noqa: BLE001 — fingerprinting is best-effort
            _fingerprint = None
        _obs_log(
            url=url,
            profile_used=getattr(result, "profile_used", None),
            verdict=getattr(result, "verdict", "unknown"),
            attempts=len(getattr(result, "trace", None) or []),
            ok=bool(getattr(result, "ok", False)),
            elapsed_ms=round(_elapsed_ms, 1),
            impersonate=getattr(_winning_attempt, "impersonate", None),
            transform=getattr(_winning_attempt, "url_transform", None),
            hint_used=_hint_used,
            fingerprint=_fingerprint,
        )
    except Exception:  # noqa: BLE001 — logging must never break a fetch
        pass

    # Per-hop url_check (Step 3 patch #2) blocks every curl-driven redirect
    # before the GET fires, so this post-fetch sweep no longer needs to
    # catch them. What it still catches:
    #   * Playwright fallback paths — they don't go through _curl_probe.
    #   * The engine-stamped final URL on any code path that bypasses
    #     url_check (e.g. caller-supplied url_check=None for testing).
    #   * Each Attempt.url in trace — the per-attempt entry point, useful
    #     when URL transforms produce internal hosts.
    # It does NOT see curl_cffi-internal redirect chain hops; those are
    # enforced ahead of time by url_check.
    trace_urls = [
        a.url for a in (getattr(result, "trace", None) or [])
        if getattr(a, "url", None)
    ]
    final = getattr(result, "final_url", "") or url
    try:
        _post_redirect_check(final, trace_urls)
    except SSRFBlockedError as e:
        result.content = ""
        result.ok = False
        result.summary = (
            (getattr(result, "summary", "") or "")
            + f"\n⚠ post-redirect SSRF block: {e}; content withheld; trace retained"
        ).strip()
    return result


def _proxy_fallback(url: str, *, profile_id: str, **kwargs: Any):
    """Wrapped `engine.executor.run_playwright_fallback`.

    Sole correction: `profileDir` defaults to a per-domain hash under
    `~/.cache/insane-fetch/pw/` with mode `0o700`, replacing upstream's
    shared `/tmp/.insane_pw_profile` (cross-site cookie bleed).

    """
    if not kwargs.get("profile_dir"):
        try:
            kwargs["profile_dir"] = _per_domain_profile_dir(url)
        except OSError:
            # If we can't create the dir, fall through to engine default
            # rather than block the call entirely.
            pass

    return _ORIGINAL_FALLBACK(url, profile_id=profile_id, **kwargs)


def install() -> None:
    """Install guards over engine. Idempotent."""
    global _INSTALLED, _ORIGINAL_FETCH, _ORIGINAL_FALLBACK
    if _INSTALLED:
        return

    _check_signature(
        _engine_fetch_chain.fetch, _EXPECTED_FETCH_PARAMS, "fetch_chain.fetch"
    )
    _check_signature(
        _engine_executor.run_playwright_fallback,
        _EXPECTED_FALLBACK_PARAMS,
        "executor.run_playwright_fallback",
    )

    _ORIGINAL_FETCH = _engine_fetch_chain.fetch
    _ORIGINAL_FALLBACK = _engine_executor.run_playwright_fallback

    # Expose the original callables via `__wrapped__` so
    # `inspect.signature(... , follow_wrapped=True)` (the default) sees the
    # engine's real parameter set instead of `_proxy_fetch`'s opaque
    # `**kwargs`. This lets engine-side unit tests (patch #9) pin the
    # engine signature without first un-installing the proxy.
    _proxy_fetch.__wrapped__ = _ORIGINAL_FETCH  # type: ignore[attr-defined]
    _proxy_fallback.__wrapped__ = _ORIGINAL_FALLBACK  # type: ignore[attr-defined]

    _engine_fetch_chain.fetch = _proxy_fetch
    _engine_executor.run_playwright_fallback = _proxy_fallback

    # `engine/__init__.py` re-exports `fetch` at the package top level. Patch
    # it too so callers using `from engine import fetch` (e.g. plus/__main__,
    # plus/search, plus/crawl) get the proxied function. Only safe because
    # plus' own __init__ runs install() before those callers import engine.
    try:
        import engine as _engine_root
        _engine_root.fetch = _proxy_fetch
    except Exception:
        pass

    _INSTALLED = True


def uninstall() -> None:
    """Reverse the monkey-patch. Primarily for test isolation."""
    global _INSTALLED
    if not _INSTALLED:
        return
    _engine_fetch_chain.fetch = _ORIGINAL_FETCH
    _engine_executor.run_playwright_fallback = _ORIGINAL_FALLBACK
    try:
        import engine as _engine_root
        _engine_root.fetch = _ORIGINAL_FETCH
    except Exception:
        pass
    _INSTALLED = False


def is_installed() -> bool:
    return _INSTALLED
