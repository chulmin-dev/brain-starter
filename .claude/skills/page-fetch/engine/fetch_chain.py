"""Single entrypoint: insane-search generic fetch chain.

    from insane_search.engine import fetch
    result = fetch("https://example.com/path", success_selectors=["article"])

Public contract:
  * One function: `fetch(url, ...) -> FetchResult`.
  * Internal structure preserved as explicit phases so tests & debug logs
    can target each stage: probe → validate → detect → plan → execute → report.
  * `FetchResult.trace` exposes every attempt (transform × impersonate ×
    referer × executor) — callers can diagnose without re-running.

No site-specific branching. Site knowledge enters only via:
  * `success_selectors` (caller-supplied positive proof)
  * `user_hint` (optional runtime hints; never persisted by this module)
  * `observations/*.jsonl` (append-only log; separate concern)
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional
from urllib.parse import urljoin

from .validators import Verdict, ValidationResult, validate, TERMINAL_NONSUCCESS
from .waf_detector import detect, load_profile, _load_profiles, last_load_error
from .url_transforms import iter_transformed

# Verdicts that terminate the fetch loop. Centralised so probe / grid /
# Playwright fallback all gate on the same set (patch queue #6 follow-up).
# SUSPECT_OK is intentionally NOT here — it is non-terminal (A6/Wave 3).
_TERMINAL_VERDICTS: tuple[str, ...] = (Verdict.STRONG_OK.value, Verdict.WEAK_OK.value)


def _promote_transform_first(transform_order: list, user_hint: dict) -> list:
    """M3 (Wave 3): extract ADAPT-2 grid-front promotion as a pure helper.

    When a winners hint carries `url_transform_first` and that transform
    exists in the profile's `url_transform_order`, move it to position 0 so
    the known-good transform is tried first. Other transforms are kept (just
    reordered) so cold-start fallback is intact if the hint is stale.

    Unknown transforms (not in `transform_order`) and absent/empty hints are
    no-ops — the order is returned unchanged.
    """
    tf_first = user_hint.get("url_transform_first")
    if isinstance(tf_first, str) and tf_first and tf_first in transform_order:
        return [tf_first] + [t for t in transform_order if t != tf_first]
    return transform_order


# Patch queue #7: when the WAF detector cannot place the response into a
# known profile (probe fails outright, or hits are too weak), the loop
# falls through to `unknown_challenge` whose default grid is small
# (5 tls × 2 referers × 1 transform = 10 attempts). Operators who know a
# host is borderline can opt into a wider grid via env or user_hint.
# Axis-order assumption: with the Phase-8 (#4) loop, referer is outermost,
# so the appended `none` referer is the LAST batch tried — appropriate
# because it's the weakest naturalness signal (last-ditch fallback).
_PROBE_FAIL_EXPAND_ENV = "INSANE_PROBE_FAIL_EXPAND"
_PROBE_FAIL_EXPAND_TRUTHY = frozenset({"1", "true", "yes", "on"})
_UNKNOWN_CHALLENGE_EXTRA_TRANSFORMS: tuple[str, ...] = (
    "drop_www", "am_prefix", "mobile_subdomain",
)
_UNKNOWN_CHALLENGE_EXTRA_REFERERS: tuple[str, ...] = ("none",)
# Floor on `max_attempts` when expansion is active. Default fetch()
# `max_attempts=12` would cap before the new transforms / no-referer
# combos are reached; without this floor, the opt-in flag would be a
# no-op in practice. 40 covers ~half of the 4 × 3 × 5 = 60 expanded
# combos — operators wanting full coverage still raise it explicitly.
_EXPANDED_GRID_MAX_ATTEMPTS_FLOOR = 40


# Patch queue #8: cap body bytes streamed from curl-impersonate so a
# 50MB+ response cannot OOM the process. curl_cffi's `content_callback`
# is invoked per chunk; raising aborts the transfer (libcurl error 23).
# Engine still parses the chunks already received but never accumulates
# past the cap. Override via env `INSANE_MAX_BODY_BYTES` (positive int,
# bytes). Default 10 MiB matches the existing `_MAX_PARSE_BYTES`
# ceiling in `plus/crawl.py` / `plus/search.py` so downstream parsers
# never see a body larger than they would have truncated anyway.
_MAX_BODY_BYTES_ENV = "INSANE_MAX_BODY_BYTES"
_MAX_BODY_BYTES_DEFAULT = 10 * 1024 * 1024


def _max_body_bytes() -> int:
    raw = os.environ.get(_MAX_BODY_BYTES_ENV, "").strip()
    if not raw:
        return _MAX_BODY_BYTES_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        return _MAX_BODY_BYTES_DEFAULT
    return value if value > 0 else _MAX_BODY_BYTES_DEFAULT


# P27 (2026-06-12): per-probe wall-clock deadline. Designed symmetric to the
# body cap above — one cumulative budget spanning every redirect hop inside a
# single `_curl_probe`, re-read per call so an operator can twiddle the env
# between attempts. Without it a pathological redirect chain can burn
# ~`_MAX_REDIRECTS × timeout` ≈ 275s per attempt, multiplied across the grid.
# `0` (or non-positive / invalid) disables the deadline → legacy behaviour.
_MAX_PROBE_SECONDS_ENV = "INSANE_MAX_PROBE_SECONDS"
_MAX_PROBE_SECONDS_DEFAULT = 0  # disabled by default (back-compat)

# Stable contract prefix in the (None, err) tuple returned by `_curl_probe`
# when the per-probe deadline fires. Producer + tests reference the same
# constant so a future rename can't silently desynchronise them.
_PROBE_DEADLINE_PREFIX = "probe_deadline:"


def _max_probe_seconds() -> float:
    raw = os.environ.get(_MAX_PROBE_SECONDS_ENV, "").strip()
    if not raw:
        return float(_MAX_PROBE_SECONDS_DEFAULT)
    try:
        value = float(raw)
    except ValueError:
        print(
            f"WARNING: {_MAX_PROBE_SECONDS_ENV}={raw!r} is not a valid number; "
            f"deadline disabled",
            file=sys.stderr,
        )
        return 0.0
    return value if value > 0 else 0.0


def _env_int(name: str, default: int, min_value: int = 1) -> int:
    """Read an integer env var with a stderr warning on parse failure.

    P11 (2026-06-11): unguarded ``int(os.environ.get(...))`` calls in the
    fetch path crash every fetch on a single env typo. This helper matches
    the defensive pattern in ``_max_body_bytes``: invalid / non-positive
    values fall back to *default* and emit one warning line to stderr so
    the misconfiguration is visible without crashing the caller.

    ``min_value`` is a floor applied after a successful parse (e.g. ``1``
    for redirect counts so the loop runs at least once).
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(f"WARNING: {name}={raw!r} is not a valid integer; using default {default}", file=sys.stderr)
        return default
    if value < min_value:
        print(f"WARNING: {name}={raw!r} is below minimum {min_value}; using default {default}", file=sys.stderr)
        return default
    return value


# Stable contract prefix in the (None, err) tuple returned by
# `_curl_probe` when the cap fires. Producer + tests reference the same
# constant so a future rename can't silently desynchronise them.
_BODY_TOO_LARGE_PREFIX = "body_too_large:"


class _BodyCapAbort(RuntimeError):
    """Distinct exception raised by `_BodyCap` when the cap is exceeded.

    `RuntimeError` subclass so existing broad catches still apply, but
    the precise class lets tests assert intent without coupling to a
    generic `RuntimeError`. curl_cffi's CFFI bridge coerces all callback
    exceptions into a libcurl transport failure, so the type is only
    visible to the in-process `_do_get` caller — not to the engine's
    outer `except Exception` chain.
    """


class _BodyCap:
    """Streaming size guard for curl_cffi's `content_callback`.

    libcurl calls the callback with each received chunk; cumulative
    overflow triggers a synchronous `raise`, which libcurl translates
    into a transport error and aborts the transfer. The caller
    distinguishes "cap exceeded" from a regular transport error via the
    `_BodyTooLarge` sentinel below.

    Phase 10.1 (body rehydration): curl_cffi 0.15.0 diverts the entire
    body into the callback when `content_callback` is set, leaving
    `resp.content` empty. The validators downstream read `resp.text` /
    `resp.content`, so without this `chunks` accumulator a 200 OK page
    would look like a 0-byte body and verdict-out as CHALLENGE. The
    accumulator only grows for *accepted* chunks (i.e. within the cap);
    once the limit is exceeded we drop the partial body — it's about to
    raise anyway and the caller never reads it.
    """
    __slots__ = ("limit", "total", "exceeded", "chunks")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.total = 0
        self.exceeded = False
        self.chunks: list[bytes] = []

    def __call__(self, chunk: bytes) -> None:
        self.total += len(chunk)
        if self.total > self.limit:
            self.exceeded = True
            raise _BodyCapAbort("insane-fetch: body size cap exceeded")
        self.chunks.append(chunk)


class _BodyTooLarge(Exception):
    """Sentinel raised when a transport exception coincides with our
    `_BodyCap.exceeded` flag — distinguishes the cap-trip from other
    libcurl failures so `_curl_probe` can emit a stable error string.
    """

    def __init__(self, total: int, limit: int) -> None:
        self.total = total
        self.limit = limit
        super().__init__(f"{_BODY_TOO_LARGE_PREFIX}{total}>{limit}")


class _ProbeDeadlineExceeded(Exception):
    """P27 sentinel: the per-probe wall-clock budget elapsed mid-chain.

    Raised between redirect hops in `_curl_probe` so a runaway redirect
    chain returns a stable `probe_deadline:` error instead of consuming
    `_MAX_REDIRECTS × timeout` seconds. Distinct class so the producer +
    tests assert intent without coupling to a generic `RuntimeError`.
    """

    def __init__(self, elapsed: float, budget: float) -> None:
        self.elapsed = elapsed
        self.budget = budget
        super().__init__(f"{_PROBE_DEADLINE_PREFIX}{elapsed:.1f}s>{budget:.1f}s")


# P27 (2026-06-12): transport-error classification. A raw libcurl/transport
# failure today collapses to a generic `TypeName:msg` string that the grid
# cannot adapt to. These stable prefixes let the grid skip the same
# impersonate family on a TLS reject (the fingerprint is being refused, so
# retrying the same one wastes an attempt) and lengthen the timeout on a
# transport timeout. DNS errors are classified too but get no special grid
# treatment (resolution won't change mid-grid). The classifier is a pure
# substring match over the exception's repr — keep prefixes module-level so
# tests can't desync from producers.
_TLS_REJECTED_PREFIX = "tls_rejected:"
_TIMEOUT_PREFIX = "timeout:"
_DNS_ERROR_PREFIX = "dns_error:"

# Lowercased fragments that, when present in the transport exception text,
# map to each class. Ordered most-specific-first; first match wins.
_TLS_REJECT_FRAGMENTS: tuple[str, ...] = (
    "ssl", "tls", "certificate", "handshake", "wrong version number",
    "sslv3", "alert", "cipher",
)
_TIMEOUT_FRAGMENTS: tuple[str, ...] = (
    "timed out", "timeout", "operation too slow",
)
_DNS_FRAGMENTS: tuple[str, ...] = (
    "could not resolve", "name or service not known", "resolve host",
    "getaddrinfo", "no address associated",
)


def _classify_transport_error(exc: BaseException) -> str:
    """Return a stable classified error string for a transport exception.

    Falls back to the legacy `TypeName:msg` shape when nothing matches, so
    existing callers/tests that key on the generic format still work for
    unclassified failures.
    """
    text = f"{type(exc).__name__}: {exc}".lower()
    raw = f"{type(exc).__name__}:{str(exc)[:200]}"
    # SEC-L3: a raw libcurl message can embed the resolved IP / internal host.
    # This string only reaches stderr under --trace, but mask IPv4 literals by
    # default (opt back in via INSANE_DEBUG=1) so a diagnostic dump doesn't leak
    # resolved addresses into a transcript.
    if os.environ.get("INSANE_DEBUG") != "1":
        raw = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", raw)
    for frag in _TLS_REJECT_FRAGMENTS:
        if frag in text:
            return f"{_TLS_REJECTED_PREFIX}{raw}"
    for frag in _TIMEOUT_FRAGMENTS:
        if frag in text:
            return f"{_TIMEOUT_PREFIX}{raw}"
    for frag in _DNS_FRAGMENTS:
        if frag in text:
            return f"{_DNS_ERROR_PREFIX}{raw}"
    return raw


# C8 / P39r (2026-06-12): connect-IP pinning to close the DNS-rebinding TOCTOU.
# ---------------------------------------------------------------------------
# The shipped per-hop `url_check` (P28/C1) re-resolves the host inside the SSRF
# guard, but libcurl then resolves *again* independently when it connects — a
# rotating-DNS attacker can return a public IP to the guard's getaddrinfo and an
# internal IP to libcurl's connect(), leaving a microsecond rebinding window
# (UPSTREAM.md #1, "residual gap = microseconds between url_check resolve and
# libcurl connect").
#
# This closes it by making the *verified* IP and the *connected* IP identical:
#   1. resolve the hop's host exactly once (engine-side),
#   2. hand that IP literal to `ip_check(url, ip)` for the SSRF verdict,
#   3. pin the SAME IP into libcurl via CURLOPT_RESOLVE("host:port:ip") so the
#      socket connects to precisely the address we vetted — no second lookup.
#
# RESOLVE (not CONNECT_TO) is the right primitive: it overrides name resolution
# for one host:port while libcurl keeps the original hostname for TLS SNI and
# certificate validation, whereas CONNECT_TO is aimed at connecting to a
# different host entirely. curl_cffi clears the RESOLVE slist after every
# perform() (curl.py `clean_handles_and_buffers(clear_resolve=True)`), so a
# per-hop `setopt(RESOLVE, [entry])` applies to exactly that one request with no
# slist accumulation across redirect hops.
#
# Default ON; opt out with INSANE_DISABLE_IP_PIN=1 for the rare CDN/anycast host
# where pinning a single A-record IP breaks geo/edge routing. The pin is a
# *defence-in-depth* layer: when it is disabled (or resolution yields no usable
# IP), the per-hop url_check and the always-on post-redirect sweep still guard
# the fetch — so disabling it never opens a hole the engine had closed, it only
# reverts to the pre-C8 (still-guarded, narrow-window) behaviour.
_DISABLE_IP_PIN_ENV = "INSANE_DISABLE_IP_PIN"


def _ip_pin_disabled() -> bool:
    return os.environ.get(_DISABLE_IP_PIN_ENV, "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _pin_connect_ip(
    session: Optional[Any],
    target_url: str,
    *,
    ip_check: Optional[Callable[[str, str], None]],
) -> None:
    """Resolve `target_url`'s host once, vet the IP, and pin it into libcurl.

    Applies CURLOPT_RESOLVE on the curl_cffi `session`'s handle so the upcoming
    GET connects to exactly the resolved-and-vetted IP. No-op (returns without
    pinning) when the feature is disabled, no session/IP is available, or
    curl_cffi doesn't expose the handle — in every such case the caller's
    per-hop `url_check` plus the post-redirect sweep remain the guard.

    Raises whatever `ip_check` raises (an `SSRFBlockedError` surfaces through
    `_curl_probe`'s `_UrlCheckRejected` wrapping exactly like a `url_check`
    rejection), so a blocked address never gets pinned or connected.

    `ip_check is None` (bare CLI, legacy callers) is a hard no-op: with no
    vetter there is no security value in pinning, and — importantly — we must
    NOT resolve the host here, so the no-`ip_check` path issues exactly the
    same syscalls it did pre-C8 (no extra getaddrinfo). The pin only engages
    when plus injects `_ip_literal_check`.
    """
    if session is None or ip_check is None or _ip_pin_disabled():
        return
    # Only IP-literal RESOLVE entries make sense; a host that is already a
    # literal needs no pin (libcurl won't re-resolve it) — and the url_check
    # seam already vetted it.
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(target_url)
    except Exception:
        return
    host = parts.hostname
    if not host:
        return
    try:
        ipaddress.ip_address(host)
        return  # already a literal — no DNS step to pin, nothing to rebind.
    except ValueError:
        pass

    # Resolve exactly once. Prefer the first usable A/AAAA record; the chosen
    # IP is what we both vet AND pin, so they cannot diverge.
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # Resolution failed here — let libcurl try (DoH / its own resolver may
        # still succeed). url_check already ran on this URL; the post-redirect
        # sweep is the backstop. No pin to apply.
        #
        # DoH↔IP-pin interaction (CR Open Question, 2026-06-12): DoH "auto" mode
        # (`plus/doh.py:setup`) enables DoH *precisely because* the system
        # resolver is blocked — i.e. exactly when this `getaddrinfo` also fails.
        # So on a DoH-forced network the connect-IP pin is intentionally INACTIVE
        # (this early return), and the two are MUTUALLY EXCLUSIVE by construction:
        # libcurl resolves the host over DoH (CURLOPT_DOH_URL), and we don't try
        # to second-guess that resolution with a stale system-resolver IP (which
        # would just fail to connect, or worse pin a different address than DoH
        # would pick). The security guarantee on the DoH path is therefore the
        # always-on `_post_redirect_check` sweep (`allow_disable=False`) plus the
        # per-hop `url_check` — NOT the C8 connect-IP pin. This is a graceful
        # degradation to pre-C8 (still-guarded, narrow-window) behaviour, not a
        # hole: see UPSTREAM.md §P39r DoH note.
        return

    chosen_ip: Optional[str] = None
    for info in infos:
        addr = info[4][0]
        # Strip any IPv6 scope id (fe80::1%eth0) before vetting/pinning.
        addr = addr.split("%", 1)[0]
        if ip_check is not None:
            # Raises SSRFBlockedError on a blocked address → propagates out and
            # _curl_probe turns it into url_check_rejected: (no connect made).
            ip_check(target_url, addr)
        chosen_ip = addr
        break  # one vetted IP is enough to pin a deterministic connect target.

    if chosen_ip is None:
        return

    try:
        from curl_cffi.const import CurlOpt
    except Exception:
        # No CurlOpt (unexpected on 0.15.0); skip pinning. Guards still apply.
        return
    curl_handle = getattr(session, "curl", None)
    setopt = getattr(curl_handle, "setopt", None)
    if setopt is None:
        return
    # Format: "host:port:ip" (multiple IPs comma-separated, but we pin one).
    # curl_cffi auto-clears this slist after the perform() (clear_resolve=True),
    # so the entry scopes to exactly the next GET — no cross-hop leakage.
    try:
        setopt(CurlOpt.RESOLVE, [f"{host}:{port}:{chosen_ip}"])
    except Exception:
        # A setopt failure must not abort the fetch; fall back to libcurl's own
        # resolution, still guarded by url_check + post-redirect sweep.
        return


# P21 (2026-06-12): opt-in clearance persistence across CLI re-invocations.
# When `INSANE_COOKIE_JAR_DIR` is set, the engine loads a per-registrable-
# domain cookie jar into the shared Session at fetch() start and writes it
# back at fetch() end, so a Cloudflare/Akamai clearance cookie earned in one
# `python3 -m engine ...` survives into the next (the R7 workflow re-invokes
# a fresh process). Default OFF → behaviour identical to before. Jar files are
# chmod 0600, the directory 0700 — clearance tokens are bearer credentials.
# SECURITY: only cookie name/value/domain/path are stored; the jar is keyed by
# registrable domain so cross-site cookies never bleed (mirrors the per-domain
# profileDir isolation). Cookie *values* are never logged — the trace records
# only whether a jar was used and for which registrable domain.
_COOKIE_JAR_DIR_ENV = "INSANE_COOKIE_JAR_DIR"


def _cookie_jar_path(url: str) -> Optional[str]:
    """Return the jar file path for `url`'s registrable domain, or None.

    None when `INSANE_COOKIE_JAR_DIR` is unset (opt-out) or the directory
    can't be created. Pure path construction + mkdir; no I/O on the jar
    itself."""
    base = os.environ.get(_COOKIE_JAR_DIR_ENV, "").strip()
    if not base:
        return None
    try:
        from urllib.parse import urlsplit
        from .url_transforms import _registrable_domain

        host = urlsplit(url).hostname or "_anonymous"
        reg = _registrable_domain(host) or host
        os.makedirs(base, exist_ok=True)
        try:
            os.chmod(base, 0o700)
        except OSError:
            pass
        # Hash the registrable domain so visited domains don't appear in the
        # filesystem path (consistency with _per_domain_profile_dir).
        import hashlib

        # CR-L2 (accepted): 16 hex chars = 64-bit key space. A jar-filename
        # collision needs ~2^32 distinct registrable domains for ~50% odds —
        # far beyond a personal CLI's domain set; and even on collision the
        # replayed cookies stay domain-scoped (session.cookies.set domain=...),
        # so there is no silent cross-site bleed. Matches _per_domain_profile_dir.
        digest = hashlib.sha256(reg.encode("utf-8")).hexdigest()[:16]
        return os.path.join(base, f"{digest}.json")
    except Exception:
        return None


def _load_cookie_jar(session, url: str) -> Optional[str]:
    """Load a persisted cookie jar for `url` into `session`. Returns the
    registrable domain on success (for trace), else None. Never raises."""
    path = _cookie_jar_path(url)
    if not path or session is None:
        return None
    try:
        from urllib.parse import urlsplit
        from .url_transforms import _registrable_domain

        host = urlsplit(url).hostname or "_anonymous"
        reg = _registrable_domain(host) or host
        if not os.path.isfile(path):
            return reg  # jar enabled but empty (first run) — still report domain
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for c in data.get("cookies", []):
            name = c.get("name")
            value = c.get("value")
            if not name:
                continue
            try:
                session.cookies.set(
                    name, value,
                    domain=c.get("domain") or "",
                    path=c.get("path") or "/",
                )
            except Exception:
                # curl_cffi cookie-jar API quirks must not abort the fetch.
                continue
        return reg
    except Exception:
        return None


def _save_cookie_jar(session, url: str, *, jar_domain: Optional[str] = None) -> None:
    """Persist `session`'s cookies to the per-domain jar (0600). Never raises.

    M-SEC: when `jar_domain` is supplied (the registrable domain of the fetch
    target), only cookies whose own registrable domain matches `jar_domain` are
    written. Cookies with an empty/host-only domain (no explicit domain attribute)
    always belong to the current host and are kept. This prevents a foreign cookie
    that somehow entered the session from being at-rest in the wrong jar file.
    """
    path = _cookie_jar_path(url)
    if not path or session is None:
        return
    try:
        cookies = _session_cookies(session, jar_domain=jar_domain)
        if not cookies:
            return
        tmp = f"{path}.tmp.{os.getpid()}"
        # CR-L1: create the tmp with mode 0600 from the start (O_CREAT mode)
        # instead of chmod-after-write, closing the brief window where a stale
        # umask-derived 0644 tmp could be read. O_EXCL fails on a leftover
        # same-pid tmp from a crash, so unlink any stale one first, then create
        # exclusively.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"cookies": cookies}, f)
        os.replace(tmp, path)
    except Exception:
        # Best-effort persistence — a write failure must not fail the fetch.
        pass


def _session_cookies(session, *, jar_domain: Optional[str] = None) -> list[dict]:
    """Extract `session`'s cookies as a list of {name,value,domain,path} dicts.

    Tolerant of the several jar shapes curl_cffi / requests expose. Returns
    [] on any failure. Used both for jar persistence and the P21 Playwright
    handoff (curl → Chrome cookie replay).

    M-SEC: when `jar_domain` is supplied, cookies whose registrable domain
    differs from `jar_domain` are dropped before returning. Cookies with an
    empty/host-only domain (no explicit domain attribute) are always kept —
    they belong to the current host by definition. This prevents a foreign
    cookie on the session from being written into the wrong jar file.
    """
    out: list[dict] = []
    if session is None:
        return out

    # M-SEC: lazy-import the domain helper only when filtering is active.
    _rd = None
    if jar_domain:
        try:
            from .url_transforms import _registrable_domain as _rd
        except ImportError:
            _rd = None

    def _keep(cookie_domain: str) -> bool:
        """Return True iff this cookie belongs to the current jar_domain."""
        if not jar_domain or _rd is None:
            return True
        cd = (cookie_domain or "").lstrip(".")
        if not cd:
            return True          # host-only cookie → current host → keep
        return (_rd(cd) or cd) == jar_domain

    try:
        jar = getattr(session, "cookies", None)
        if jar is None:
            return out
        # Cookielib-style jar: iterable of Cookie objects with attributes.
        try:
            for c in jar:
                name = getattr(c, "name", None)
                if name is None:
                    continue
                dom = getattr(c, "domain", "") or ""
                if not _keep(dom):
                    continue
                out.append({
                    "name": name,
                    "value": getattr(c, "value", "") or "",
                    "domain": dom,
                    "path": getattr(c, "path", "/") or "/",
                })
            if out:
                return out
        except TypeError:
            pass
        # Dict-style fallback (name → value only).
        try:
            for name, value in dict(jar).items():
                out.append({"name": name, "value": value, "domain": "", "path": "/"})
        except Exception:
            pass
    except Exception:
        return []
    return out


def _impersonate_family(impersonate: Optional[str]) -> str:
    """Collapse an impersonate target to its browser family.

    `safari_ios` / `safari17_0` → `safari`; `chrome_android` / `chrome120`
    → `chrome`. Used by the P27 grid adaptation: a TLS reject on one variant
    means the whole family's fingerprint is being refused, so the grid skips
    its siblings instead of burning attempts on them.
    """
    if not impersonate:
        return ""
    head = impersonate.split("_", 1)[0]
    # Strip a trailing version run (chrome120 → chrome, safari17 → safari).
    return head.rstrip("0123456789") or head


def _expand_unknown_challenge_active(user_hint: dict) -> bool:
    """Return True iff opt-in flag is set via user_hint or env."""
    if user_hint.get("expand_unknown_challenge"):
        return True
    return (
        os.environ.get(_PROBE_FAIL_EXPAND_ENV, "").strip().lower()
        in _PROBE_FAIL_EXPAND_TRUTHY
    )


def _expand_unknown_challenge_grid(profile: dict) -> dict:
    """Return a *copy* of `profile` with extra transforms + referers.

    Tls candidates are left alone — `unknown_challenge` already lists
    five, broadening that axis further has diminishing returns. The
    expansion targets the axes most likely to surface a working combo
    for an unrecognised challenge: a mobile transform, a www-stripped
    transform, an apex `m.` prefix, and a no-referer attempt.
    """
    out = dict(profile)
    transforms = list(out.get("url_transform_order") or ["original"])
    for extra in _UNKNOWN_CHALLENGE_EXTRA_TRANSFORMS:
        if extra not in transforms:
            transforms.append(extra)
    out["url_transform_order"] = transforms
    refs = list(out.get("referer_strategies") or [])
    for extra in _UNKNOWN_CHALLENGE_EXTRA_REFERERS:
        if extra not in refs:
            refs.append(extra)
    out["referer_strategies"] = refs
    return out


# --- Referer strategies (name → function of original URL) --------------------
def _self_root(url: str) -> str:
    from urllib.parse import urlsplit
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}/"


REFERER_STRATEGIES = {
    "self_root": _self_root,
    "google_search": lambda _url: "https://www.google.com/",
    "none": lambda _url: "",
}


# --- Attempt & result schema (Codex: "evidence schema first") ----------------
@dataclass
class Attempt:
    phase: str                       # probe | grid | fallback
    executor: str                    # curl_cffi | playwright_mcp | playwright_real_chrome | ...
    url: str
    url_transform: str               # original | mobile_subdomain | ...
    impersonate: Optional[str]       # safari | chrome | ... | None (non-curl)
    referer: str
    status: int = 0
    body_size: int = 0
    verdict: str = ""
    reasons: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    error: Optional[str] = None
    # P32: opt-in CDP NetworkJournal payload. None unless the real-Chrome
    # fallback ran with capture_json=True; then it holds the captured
    # application/json XHR/fetch bodies ({url,status,body} dicts).
    captured_json: Optional[list[dict]] = None
    # ADAPT-1: cookies captured from the browser context after a successful
    # Playwright fallback. Each entry is {name,value,domain,path}; values are
    # NEVER logged (output-0 policy). Used to bridge clearance tokens back into
    # the curl session jar so subsequent same-host curl fetches replay them.
    captured_cookies: Optional[list[dict]] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        # L-SEC: output-0 policy — bearer tokens (cf_clearance, Akamai) in
        # captured_cookies must NEVER appear in any serialized output, including
        # the engine's `--json` CLI path. Redact values; keep name/domain/path
        # for diagnostics. captured_json is request payload data (not credentials)
        # and is left as-is.
        if d.get("captured_cookies"):
            d["captured_cookies"] = [
                {k: ("***" if k == "value" else v) for k, v in c.items()}
                for c in d["captured_cookies"]
            ]
        return d


@dataclass
class FetchResult:
    ok: bool
    content: str = ""
    final_url: str = ""
    verdict: str = ""
    profile_used: Optional[str] = None
    trace: list[Attempt] = field(default_factory=list)
    summary: str = ""
    # A7: failure-gate structured fields (additive, default empty/False/unknown).
    # Populated honestly on ok=False paths; empty/False on ok=True.
    untried_routes: list = field(default_factory=list)    # combos not tried when run stopped
    must_invoke_playwright_mcp: bool = False              # True when engine structurally can't solve
    grid_exhausted: bool = False                          # True when budget/attempts fully burned
    stop_reason: str = ""                                 # "exhausted"|"rate_limited"|"terminal_status"|"budget"

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "final_url": self.final_url,
            "verdict": self.verdict,
            "profile_used": self.profile_used,
            "trace": [a.to_dict() for a in self.trace],
            "summary": self.summary,
            "content_length": len(self.content),
            # A7: failure-gate fields (always included so --json consumers can parse them)
            "untried_routes": self.untried_routes,
            "must_invoke_playwright_mcp": self.must_invoke_playwright_mcp,
            "grid_exhausted": self.grid_exhausted,
            "stop_reason": self.stop_reason,
        }


# --- curl_cffi probe executor ------------------------------------------------
class _UrlCheckRejected(Exception):
    """Sentinel propagated past `_curl_probe`'s generic error handler.

    `_curl_probe` has an explicit `except _UrlCheckRejected: raise` clause
    in front of its `except Exception` so this sentinel reaches
    `_run_attempt` un-coerced. `_run_attempt` catches it and rewrites
    into an attempt-level `url_check_rejected:` error without leaking
    partial bytes to the caller.
    """

    def __init__(self, original: BaseException):
        self.original = original
        super().__init__(repr(original))


def _curl_probe(
    url: str, *, impersonate: str, referer: str, timeout: int = 20,
    session: Optional[Any] = None,
    url_check: Optional[Callable[[str], None]] = None,
    ip_check: Optional[Callable[[str, str], None]] = None,
) -> tuple[Any, Optional[str]]:
    """Returns (response, error_str). response may be None on exception.

    When `session` is supplied, the request reuses that curl_cffi Session so
    cookies set on earlier attempts (e.g. Cloudflare clearance) persist into
    later ones. With `session=None` the legacy per-call `cffi_requests.get`
    path is used for backward compatibility.

    Redirect handling is performed manually (allow_redirects=False) so that
    every hop can be inspected by `url_check` *before* the next request goes
    out. This is the engine-level half of patch-queue item #2 (C1): close
    the DNS-rebinding window at the moment a redirect target becomes known,
    not after the fact. `url_check(next_url) -> None` signals via raise; any
    exception propagates to the caller (`_run_attempt` marks the attempt
    UNKNOWN with an `url_check_rejected:` error string).

    P28 (2026-06-12): `url_check` is also invoked on the *entry* URL before
    the first GET (previously only redirect hops were screened). This shrinks
    the engine-direct SSRF surface — programmatic callers and the per-attempt
    transformed URLs (mobile_subdomain, am_prefix, …) are now pre-flight
    screened rather than only caught post-hoc by `plus`'s post-redirect sweep.
    The bare CLI still passes `url_check=None`, so this is a no-op there.

    C8 / P39r (2026-06-12): `ip_check(url, ip) -> None` is the connect-IP
    pinning seam. When supplied (with a `session`), each hop's host is resolved
    *once*, the resolved IP is vetted by `ip_check`, and that same IP is pinned
    into libcurl via CURLOPT_RESOLVE so the socket connects to exactly the
    vetted address — closing the DNS-rebinding TOCTOU that `url_check` alone
    leaves open (guard and libcurl would otherwise resolve independently). An
    `ip_check` rejection surfaces as the same `url_check_rejected:` error.
    `ip_check=None` (bare CLI, legacy callers) → no pinning, unchanged.
    """
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        return None, "curl_cffi not installed"

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    if referer:
        headers["Referer"] = referer

    _REDIRECT_CODES = {301, 302, 303, 307, 308}
    # Override via env: INSANE_MAX_REDIRECTS (positive integer; libcurl default = 10).
    _MAX_REDIRECTS = _env_int("INSANE_MAX_REDIRECTS", 10, min_value=1)

    def _get_location(headers) -> Optional[str]:
        # RFC 7230: header names are case-insensitive; some raw responses
        # only expose `location` lowercase. Probe both spellings.
        if not headers:
            return None
        return headers.get("Location") or headers.get("location")

    # Snapshot the cap for this probe; the same limit applies cumulatively
    # across every redirect hop (no per-hop reset — that would let a
    # 10-hop chain absorb `_MAX_REDIRECTS × body_limit` ≈ 100 MiB).
    # Re-read per `_curl_probe` call so an operator can twiddle the env
    # between attempts.
    body_limit = _max_body_bytes()
    # libcurl response headers have their own ~100 KiB ceiling, so we
    # only need to gate the body here. The total below is the sum of
    # body bytes streamed across every hop in this single probe.

    def _do_get(getter, target_url, running_total):
        """Issue one GET. The per-hop cap is `body_limit - running_total`
        so cumulative usage across redirects cannot exceed `body_limit`.
        Returns `(resp, hop_bytes)`; raises `_BodyTooLarge` (carrying
        the cumulative total) when libcurl aborts on overflow."""
        remaining = max(1, body_limit - running_total)
        cap = _BodyCap(remaining)
        try:
            resp = getter(
                target_url,
                impersonate=impersonate,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                content_callback=cap,
            )
        except Exception as e:
            # In real fetches this is `curl_cffi.requests.exceptions.RequestException`
            # (libcurl error 23). Tests use plain `RuntimeError`. The
            # broad except keeps both paths working; the `cap.exceeded`
            # flag is the canonical signal that *we* tripped the abort.
            if cap.exceeded:
                raise _BodyTooLarge(running_total + cap.total, body_limit) from e
            raise

        # Phase 10.1: rehydrate `resp.content` from the chunks we captured.
        # curl_cffi 0.15.0 routes the body into `content_callback` and
        # leaves `resp.content` empty; downstream validators read
        # `resp.text` / `resp.content`, so without this they see 0 bytes
        # and classify a perfectly-good 200 OK as CHALLENGE. Only write
        # when content is empty — if a future curl_cffi version (or a
        # test double) populates both, don't clobber it. setattr can
        # raise on Response objects that ban it; swallow that case
        # (validators will see 0 bytes, identical to pre-Phase-10
        # behaviour with no callback).
        try:
            if not getattr(resp, "content", None):
                resp.content = b"".join(cap.chunks)
                # Free the per-chunk fragments: `resp.content` now holds
                # the joined bytes and `cap` is otherwise discarded after
                # return. For a 10 MiB body this halves peak memory by
                # ~10 MiB during the brief overlap. (MED-1 follow-up.)
                cap.chunks.clear()
        except (AttributeError, TypeError):
            pass
        return resp, cap.total

    # P27: per-probe wall-clock deadline spanning all redirect hops. `0`
    # disables it (legacy). Snapshot start + budget once per probe.
    _probe_budget = _max_probe_seconds()
    _probe_start = time.monotonic()

    def _check_deadline() -> None:
        if _probe_budget <= 0:
            return
        elapsed = time.monotonic() - _probe_start
        if elapsed > _probe_budget:
            raise _ProbeDeadlineExceeded(elapsed, _probe_budget)

    try:
        getter = session.get if session is not None else cffi_requests.get
        current_url = url
        # P28 (2026-06-12): screen the entry URL before the first GET, mirroring
        # the per-hop check below. Wrapped in `_UrlCheckRejected` so rejection
        # surfaces as the established attempt-level `url_check_rejected:` error
        # instead of leaking out as a generic exception.
        if url_check is not None:
            try:
                url_check(current_url)
            except Exception as ue:
                raise _UrlCheckRejected(ue)
        # C8 / P39r: resolve-once → vet → pin the connect IP for this hop so
        # libcurl connects to exactly the address `ip_check` approved (closes
        # the rebinding window). Pin failures are swallowed inside the helper
        # (guards still apply); only an `ip_check` SSRF rejection escapes, and
        # we wrap it like a url_check rejection for a uniform error surface.
        if session is not None:
            try:
                _pin_connect_ip(session, current_url, ip_check=ip_check)
            except Exception as ue:
                raise _UrlCheckRejected(ue)
        running_total = 0
        resp, hop_bytes = _do_get(getter, current_url, running_total)
        running_total += hop_bytes
        hops = 0
        while (
            getattr(resp, "status_code", 0) in _REDIRECT_CODES
            and _get_location(getattr(resp, "headers", None))
        ):
            hops += 1
            if hops > _MAX_REDIRECTS:
                raise RuntimeError("max redirects exceeded")
            # P27: abort a slow redirect chain before issuing the next GET.
            _check_deadline()
            next_url = urljoin(current_url, _get_location(resp.headers))
            if url_check is not None:
                # Wrap caller exception in `_UrlCheckRejected` so the
                # explicit re-raise below propagates it past the generic
                # `except Exception` handler. `_run_attempt` catches the
                # sentinel and marks the attempt `url_check_rejected:`.
                try:
                    url_check(next_url)
                except Exception as ue:
                    raise _UrlCheckRejected(ue)
            current_url = next_url
            # C8 / P39r: re-pin per hop — the redirect target is a different
            # host:port, and curl_cffi cleared the previous RESOLVE entry after
            # the last perform(), so each hop gets a fresh resolve→vet→pin.
            if session is not None:
                try:
                    _pin_connect_ip(session, current_url, ip_check=ip_check)
                except Exception as ue:
                    raise _UrlCheckRejected(ue)
            resp, hop_bytes = _do_get(getter, current_url, running_total)
            running_total += hop_bytes
        # Stamp final URL on the response so downstream consumers
        # (_build_result, validators, post-redirect check) see the
        # post-redirect endpoint rather than the first hop. curl_cffi's
        # Response carries `__dict__`, so setattr always succeeds; if a
        # future response type rejects it the AttributeError surfaces
        # through the outer `except Exception` as a normal probe error.
        if hops > 0:
            resp.url = current_url
        return resp, None
    except _UrlCheckRejected:
        # Propagate to `_run_attempt` without coercing into generic err.
        raise
    except _BodyTooLarge as e:
        # Stable error string so downstream callers (and tests) can
        # distinguish a size-cap abort from other libcurl failures.
        return None, str(e)
    except _ProbeDeadlineExceeded as e:
        # P27: stable error string for the per-probe wall-clock abort.
        return None, str(e)
    except Exception as e:
        # P27: classify the transport failure (TLS reject / timeout / DNS)
        # into a stable prefix so the grid can adapt; unclassified failures
        # keep the legacy `TypeName:msg` shape.
        return None, _classify_transport_error(e)


def _run_attempt(
    url: str,
    *,
    transform_name: str,
    impersonate: str,
    referer_name: str,
    success_selectors: Optional[list[str]],
    known_bad_sizes: Optional[list[int]],
    timeout: int,
    phase: str,
    session: Optional[Any] = None,
    url_check: Optional[Callable[[str], None]] = None,
    ip_check: Optional[Callable[[str, str], None]] = None,
) -> tuple[Attempt, Any]:
    """Execute one curl_cffi attempt and produce an Attempt record."""
    referer_url = REFERER_STRATEGIES.get(referer_name, REFERER_STRATEGIES["none"])(url)
    t0 = time.time()
    try:
        resp, err = _curl_probe(
            url, impersonate=impersonate, referer=referer_url, timeout=timeout,
            session=session, url_check=url_check, ip_check=ip_check,
        )
    except _UrlCheckRejected as e:
        # url_check raised on a redirect hop — record as attempt-level
        # error without leaking partially-fetched bytes to the caller.
        elapsed = round(time.time() - t0, 3)
        att = Attempt(
            phase=phase,
            executor="curl_cffi",
            url=url,
            url_transform=transform_name,
            impersonate=impersonate,
            referer=referer_name,
            elapsed_s=elapsed,
        )
        att.verdict = Verdict.UNKNOWN.value
        orig = e.original
        att.error = f"url_check_rejected:{type(orig).__name__}:{str(orig)[:200]}"
        return att, None
    elapsed = round(time.time() - t0, 3)

    att = Attempt(
        phase=phase,
        executor="curl_cffi",
        url=url,
        url_transform=transform_name,
        impersonate=impersonate,
        referer=referer_name,
        elapsed_s=elapsed,
    )

    if err or resp is None:
        att.error = err or "no response"
        att.verdict = Verdict.UNKNOWN.value
        return att, None

    vr = validate(resp, success_selectors=success_selectors, known_bad_sizes=known_bad_sizes)
    att.status = vr.status
    att.body_size = vr.body_size
    att.verdict = vr.verdict.value
    att.reasons = vr.reasons
    return att, resp


# --- Main entrypoint ---------------------------------------------------------
def fetch(
    url: str,
    *,
    success_selectors: Optional[list[str]] = None,
    device_class: str = "auto",      # "auto" | "desktop" | "mobile"
    user_hint: Optional[dict] = None,
    timeout: int = 25,
    max_attempts: int = 12,
    enable_playwright: bool = True,   # hook left for executor module
    url_check: Optional[Callable[[str], None]] = None,
    ip_check: Optional[Callable[[str, str], None]] = None,
    session: Optional[Any] = None,   # A2: caller-supplied Session (pool); None = create per-call
) -> FetchResult:
    """Fetch `url` using the generic grid.

    Parameters
    ----------
    success_selectors
        Positive-proof CSS selectors. Presence of ≥1 match promotes verdict
        to STRONG_OK. Without them, best outcome is WEAK_OK.
    device_class
        "desktop" pins curl impersonate to desktop targets (safari/chrome/firefox).
        "mobile" pins to mobile targets (safari_ios/chrome_android) AND enables
        mobile URL transforms.
        "auto" (default) follows profile advice; tries desktop first, mobile on
        persistent failure.
    user_hint
        Optional runtime hints, e.g. `{"impersonate_first": "safari", "referer": "..."}`.
        Never stored. Only influences current call.
    timeout
        Per-attempt timeout in seconds.
    max_attempts
        Hard upper bound on total attempts across all phases.
    enable_playwright
        Placeholder — Playwright fallback invocation is delegated to
        `engine/executor.py` (separate module, capability-matched).
    ip_check
        C8 / P39r connect-IP pin seam. `ip_check(url, ip) -> None` vets the
        single resolved IP that the engine then pins into libcurl (closing the
        DNS-rebinding TOCTOU). Plus injects `_ip_literal_check`. `None` keeps
        the legacy behaviour (no pin). Honours `INSANE_DISABLE_IP_PIN=1`.
    """
    user_hint = user_hint or {}
    profiles = _load_profiles()
    # Patch queue #7: expanded `unknown_challenge` grid (4 × 3 × 5 = 60
    # combos) needs more headroom than the default `max_attempts=12`
    # otherwise the new transforms / no-referer never get reached. Raise
    # the floor for opt-in callers; an explicit higher value is honoured.
    if _expand_unknown_challenge_active(user_hint):
        max_attempts = max(max_attempts, _EXPANDED_GRID_MAX_ATTEMPTS_FLOOR)
    trace: list[Attempt] = []
    last_resp = None
    last_attempt: Optional[Attempt] = None
    profile_used: Optional[str] = None

    # Single curl_cffi Session shared across all attempts so cookies set on
    # attempt N (e.g. cf_clearance) are available to attempt N+1.
    # A2: when a caller-supplied session is provided (pool=ON), reuse it.
    # The caller owns the session lifecycle; we must NOT close it in finally.
    _session_owned = session is None
    if session is None:
        try:
            from curl_cffi import requests as cffi_requests
            session = cffi_requests.Session()
        except ImportError:
            session = None

    # P21: opt-in clearance persistence — preload any saved jar for this
    # registrable domain so a clearance cookie from a previous CLI run is
    # re-sent. `jar_domain` is None when the feature is off; non-None means
    # the jar is active (recorded in trace, values never logged).
    jar_domain = _load_cookie_jar(session, url)

    # P21: track the URL of the last successful (or best) curl attempt so the
    # Playwright fallback retries the *winning* transform rather than the bare
    # original URL — and so the curl session cookies can be replayed into Chrome.
    winning_url = url

    try:
        # Surface profile-loader failures as a trace entry so callers can see
        # that we're running on the in-code default (YAML missing / invalid /
        # PyYAML not installed). Never fatal by itself.
        load_err = last_load_error()
        if load_err:
            trace.append(Attempt(
                phase="probe",
                executor="profile_loader",
                url=url,
                url_transform="original",
                impersonate=None,
                referer="",
                verdict=Verdict.UNKNOWN.value,
                error=f"profiles_fallback: {load_err}",
            ))

        # P21: record that a persistent cookie jar is active (domain only,
        # never cookie values) so the trace shows clearance is being carried
        # across CLI runs without leaking the bearer token.
        if jar_domain is not None:
            trace.append(Attempt(
                phase="probe",
                executor="cookie_jar",
                url=url,
                url_transform="original",
                impersonate=None,
                referer="",
                verdict=Verdict.UNKNOWN.value,
                error=f"cookie_jar_active: domain={jar_domain}",
            ))

        # -------- Phase 1: probe with safe defaults ------------------------------
        base_impersonate = user_hint.get("impersonate_first") or "safari"
        if device_class == "mobile":
            base_impersonate = user_hint.get("impersonate_first") or "safari_ios"

        probe_attempt, probe_resp = _run_attempt(
            url,
            transform_name="original",
            impersonate=base_impersonate,
            referer_name=user_hint.get("referer_strategy") or "self_root",
            success_selectors=success_selectors,
            known_bad_sizes=None,
            timeout=timeout,
            phase="probe",
            session=session,
            url_check=url_check,
            ip_check=ip_check,
        )
        trace.append(probe_attempt)
        if probe_resp is not None:
            last_resp = probe_resp
            last_attempt = probe_attempt
            if probe_attempt.verdict in _TERMINAL_VERDICTS:
                return _build_result(probe_resp, probe_attempt, trace, profile_used=None)
            # ADAPT-7: terminal URL-level outcomes short-circuit the whole grid.
            if probe_attempt.verdict in TERMINAL_NONSUCCESS:
                summary = _format_summary(trace, None)
                return FetchResult(
                    ok=False,
                    content=getattr(probe_resp, "text", ""),
                    final_url=getattr(probe_resp, "url", url),
                    verdict=probe_attempt.verdict,
                    profile_used=None,
                    trace=trace,
                    summary=summary,
                    stop_reason="terminal_status",
                    grid_exhausted=False,
                )

        # -------- Phase 2: detect WAF, plan grid ---------------------------------
        if last_resp is not None:
            hits = detect(last_resp, profiles=profiles)
        else:
            hits = [type("H", (), {"profile_id": "unknown_challenge", "confidence": 0.1, "signals": ["no_probe_response"]})()]  # type: ignore

        # Try top profiles by confidence.
        attempts_used = len(trace)
        # A6: track best SUSPECT_OK in case no clean WEAK_OK/STRONG_OK is found.
        best_suspect_resp: Any = None
        best_suspect_attempt: Optional[Attempt] = None
        # A7: track whether the budget was cut mid-grid (→ untried_routes).
        _budget_cut = False
        for hit in hits[:3]:  # top 3 candidates
            if attempts_used >= max_attempts:
                _budget_cut = True
                break
            profile_id = hit.profile_id
            profile_used = profile_id
            profile = load_profile(profile_id, profiles=profiles)
            # Patch queue #7: opt-in fan-out for `unknown_challenge`.
            # Only this profile is widened — recognised WAFs already
            # carry tuned grids and shouldn't be silently bloated.
            if (profile_id == "unknown_challenge"
                    and _expand_unknown_challenge_active(user_hint)):
                profile = _expand_unknown_challenge_grid(profile)
                # NOTE: this runs BEFORE the `device_class == "mobile"`
                # override below, which also appends `mobile_subdomain`
                # to `transform_order`. The expander's idempotent
                # `if extra not in transforms` guard means the override
                # is a safe no-op when the axis is already present.

            tls_groups: list[list[str]] = profile.get("tls_impersonate_candidates") or [["safari", "chrome"]]
            tls_flat: list[str] = [t for group in tls_groups for t in group]
            avoid = set((profile.get("tls_impersonate_avoid") or []))
            tls_flat = [t for t in tls_flat if t not in avoid]

            referer_order = profile.get("referer_strategies") or ["self_root"]
            transform_order = profile.get("url_transform_order") or ["original"]

            # device_class override
            if device_class == "mobile":
                tls_flat = [t for t in tls_flat if "ios" in t or "android" in t] or tls_flat
                if "mobile_subdomain" not in transform_order:
                    transform_order = transform_order + ["mobile_subdomain"]
            elif device_class == "desktop":
                tls_flat = [t for t in tls_flat if "ios" not in t and "android" not in t] or tls_flat

            # ADAPT-2: grid-front promotion — M3 extracted to _promote_transform_first().
            transform_order = _promote_transform_first(transform_order, user_hint)

            known_bad_sizes = profile.get("known_bad_sizes") or None

            # Axis order: ref (outermost) × tls (middle) × transform
            # (innermost). The transform axis swaps fastest so a host
            # whose actual discriminator is e.g. `mobile_subdomain` does
            # NOT pay a full (tls × referer) sweep on `original` before
            # ever trying the mobile transform. With the previous
            # transform-outer order, original burned 6×3=18 attempts
            # before the next transform was considered (patch queue #4 —
            # UPSTREAM.md). Referer goes outermost because it's the
            # shortest list (~3 items) and the cheapest to rotate.
            transformed = list(iter_transformed(url, transform_order))
            # P27 grid adaptation state (scoped per profile attempt):
            #   * `tls_reject_families` — impersonate families whose TLS
            #     fingerprint was refused; siblings are skipped (the reject
            #     is fingerprint-level, not URL-level, so retrying them wastes
            #     attempts).
            #   * `adaptive_timeout` — bumped once on the first transport
            #     timeout so a genuinely slow host gets more headroom on
            #     subsequent attempts (capped so it can't grow unbounded).
            tls_reject_families: set[str] = set()
            adaptive_timeout = timeout
            _TIMEOUT_BUMP_CAP = timeout * 2
            # `done` sentinel cleanly short-circuits all three loops when
            # the attempts budget runs out; bare `break` would only exit
            # the innermost loop and the outer loops would re-enter and
            # re-break |tls|·|ref| times.
            done = False
            for ref in referer_order:
                if done:
                    break
                for tls in tls_flat:
                    if done:
                        break
                    # P27: skip a whole family once its TLS fingerprint was
                    # refused — the reject is impersonate-level, identical
                    # across referer/transform, so its siblings can't fare
                    # better.
                    if _impersonate_family(tls) in tls_reject_families:
                        continue
                    for t_name, t_url in transformed:
                        if attempts_used >= max_attempts:
                            done = True
                            _budget_cut = True
                            break
                        # Skip exact duplicate of probe.
                        if (t_name == "original" and tls == base_impersonate
                                and ref == (user_hint.get("referer_strategy") or "self_root")):
                            continue
                        att, resp = _run_attempt(
                            t_url,
                            transform_name=t_name,
                            impersonate=tls,
                            referer_name=ref,
                            success_selectors=success_selectors,
                            known_bad_sizes=known_bad_sizes,
                            timeout=adaptive_timeout,
                            phase="grid",
                            session=session,
                            url_check=url_check,
                            ip_check=ip_check,
                        )
                        trace.append(att)
                        attempts_used += 1
                        # P27: adapt the grid to classified transport errors.
                        att_err = att.error or ""
                        if att_err.startswith(_TLS_REJECTED_PREFIX):
                            tls_reject_families.add(_impersonate_family(tls))
                            # Stop trying further transforms with this same
                            # rejected impersonate — the `for tls` guard skips
                            # its siblings; bail the transform loop now.
                            break
                        elif att_err.startswith(_TIMEOUT_PREFIX):
                            adaptive_timeout = min(adaptive_timeout * 2, _TIMEOUT_BUMP_CAP)
                        if resp is not None:
                            last_resp, last_attempt = resp, att
                            # P21: remember the transform URL that produced the
                            # best curl response so the Playwright fallback
                            # retries it (not the bare original) and inherits
                            # the curl session cookies.
                            winning_url = t_url
                            if att.verdict in _TERMINAL_VERDICTS:
                                # Terminating attempt: skip the politeness jitter
                                # since no further request will be issued
                                # (patch queue #6 — UPSTREAM.md).
                                return _build_result(resp, att, trace, profile_used=profile_id)
                            # ADAPT-7: terminal URL-level verdict → short-circuit.
                            if att.verdict in TERMINAL_NONSUCCESS:
                                summary = _format_summary(trace, profile_id)
                                return FetchResult(
                                    ok=False,
                                    content=getattr(resp, "text", ""),
                                    final_url=getattr(resp, "url", url),
                                    verdict=att.verdict,
                                    profile_used=profile_id,
                                    trace=trace,
                                    summary=summary,
                                    stop_reason="terminal_status",
                                    grid_exhausted=False,
                                )
                            # A6: track best SUSPECT_OK (non-terminal; grid continues).
                            if att.verdict == Verdict.SUSPECT_OK.value:
                                best_suspect_resp = resp
                                best_suspect_attempt = att
                        # Jitter: politeness + IP-reputation guard before the
                        # NEXT attempt. Reached only when continuing the grid
                        # (resp is None, or verdict is CHALLENGE/UNKNOWN).
                        # Tunable via INSANE_JITTER_MS_MIN / INSANE_JITTER_MS_MAX.
                        _jmin = _env_int("INSANE_JITTER_MS_MIN", 150, min_value=0)
                        _jmax = _env_int("INSANE_JITTER_MS_MAX", 400, min_value=0)
                        time.sleep(random.uniform(_jmin/1000.0, _jmax/1000.0))

        # -------- Phase 3: Playwright fallback (profile-driven order) -----------
        if enable_playwright:
            try:
                from .executor import run_playwright_fallback  # lazy import
                # Honour profile's `fallback_when_challenge` list — iterate the
                # caller-declared order instead of capability-inferred single pick.
                fb_profile = load_profile(profile_used or "unknown_challenge", profiles=profiles)
                fb_order = fb_profile.get("fallback_when_challenge") or ["playwright_real_chrome"]
                pw_attempt = None
                pw_content = ""
                # P21: hand the curl session cookies (e.g. a partial clearance)
                # to Chrome so the browser doesn't restart the challenge from
                # zero, and retry the *winning* transform URL rather than the
                # bare original. Cookie harvest is best-effort and value-safe
                # (the executor never logs values).
                handoff_cookies = _session_cookies(session)
                for fb_name in fb_order:
                    if fb_name == "curl_grid_exhaust":
                        # Already performed in Phase 2; nothing more to do here.
                        continue
                    pw_attempt, pw_content = run_playwright_fallback(
                        winning_url,
                        profile_id=profile_used or "unknown_challenge",
                        success_selectors=success_selectors,
                        device_class=device_class,
                        force_executor=fb_name,
                        cookies=handoff_cookies or None,
                    )
                    trace.append(pw_attempt)
                    if pw_attempt.verdict in _TERMINAL_VERDICTS:
                        # ADAPT-1: reverse cookie bridge — load clearance cookies
                        # harvested from Chrome back into the curl Session so the
                        # `finally` block's _save_cookie_jar persists them to disk.
                        # Next curl invocation will replay them without re-solving.
                        # SECURITY: values are never logged; SSRF guards are not
                        # bypassed (cookies don't change URL routing).
                        # Cross-host bleed prevention (M-SEC): ctx.cookies() may
                        # include third-party cookies whose registrable domain differs
                        # from the fetch target. We filter at the SET site — only
                        # cookies whose registrable domain matches `jar_domain` (or
                        # whose domain is empty/host-only, meaning they belong to the
                        # current host) are loaded into the session. The subsequent
                        # _save_cookie_jar call writes only session cookies that pass
                        # the same domain filter (see _session_cookies jar_domain arg).
                        _bridge_cookies = getattr(pw_attempt, "captured_cookies", None)
                        if _bridge_cookies and session is not None and jar_domain is not None:
                            try:
                                from .url_transforms import _registrable_domain as _rd
                            except ImportError:
                                _rd = None
                            for _bc in _bridge_cookies:
                                _bc_name = _bc.get("name")
                                if not _bc_name:
                                    continue
                                # M-SEC: domain-filter — skip cookies that belong to
                                # a DIFFERENT registrable domain. An empty/missing
                                # domain means host-only (belongs to current host) —
                                # keep those. Only drop when domain resolves to a
                                # different registrable domain.
                                _bc_dom = (_bc.get("domain") or "").lstrip(".")
                                if _bc_dom and _rd is not None:
                                    _bc_reg = _rd(_bc_dom) or _bc_dom
                                    if _bc_reg != jar_domain:
                                        continue  # foreign domain — discard
                                try:
                                    session.cookies.set(
                                        _bc_name,
                                        _bc.get("value", ""),
                                        domain=_bc.get("domain") or "",
                                        path=_bc.get("path") or "/",
                                    )
                                except Exception:
                                    pass
                        return FetchResult(
                            ok=True,
                            content=pw_content,
                            final_url=pw_attempt.url,
                            verdict=pw_attempt.verdict,
                            profile_used=profile_used,
                            trace=trace,
                            summary=f"Playwright fallback succeeded via {fb_name}",
                        )
                # Synthesize a placeholder if no iteration ran (empty list).
                if pw_attempt is None:
                    pw_attempt = Attempt(
                        phase="fallback",
                        executor="none",
                        url=url,
                        url_transform="original",
                        impersonate=None,
                        referer="",
                        verdict=Verdict.UNKNOWN.value,
                        error="profile has empty fallback_when_challenge",
                    )
                    trace.append(pw_attempt)
            except ImportError:
                trace.append(Attempt(
                    phase="fallback",
                    executor="playwright",
                    url=url,
                    url_transform="original",
                    impersonate=None,
                    referer="",
                    verdict=Verdict.UNKNOWN.value,
                    error="executor module not available",
                ))
            except Exception as e:
                trace.append(Attempt(
                    phase="fallback",
                    executor="playwright",
                    url=url,
                    url_transform="original",
                    impersonate=None,
                    referer="",
                    verdict=Verdict.UNKNOWN.value,
                    error=f"{type(e).__name__}:{str(e)[:200]}",
                ))

        # -------- Give up, return best we have ----------------------------------
        # A6: if we found a SUSPECT_OK and nothing better, return it as best-effort.
        # The grid kept trying but found no clean WEAK_OK/STRONG_OK — SUSPECT_OK is
        # the best outcome available (uncertain but 200+parseable). ok=False because
        # SUSPECT_OK is not a trust token; callers should treat it as uncertain.
        if best_suspect_attempt is not None and best_suspect_resp is not None:
            # Use the suspect attempt only if it's better than what we have.
            # "Better" here means we have a parseable response, not just UNKNOWN/CHALLENGE.
            _final_verdict = best_suspect_attempt.verdict
            _final_content = getattr(best_suspect_resp, "text", "") or ""
            _final_url = getattr(best_suspect_resp, "url", url)
        else:
            _final_verdict = last_attempt.verdict if last_attempt else Verdict.UNKNOWN.value
            _final_content = getattr(last_resp, "text", "") if last_resp is not None else ""
            _final_url = getattr(last_resp, "url", url) if last_resp is not None else url

        # A7: determine stop_reason and grid_exhausted.
        _last_verdict = last_attempt.verdict if last_attempt else ""
        if _last_verdict == Verdict.RATE_LIMITED.value:
            _stop_reason = "rate_limited"
            _grid_exhausted = False
        elif _budget_cut:
            _stop_reason = "budget"
            _grid_exhausted = False
        else:
            _stop_reason = "exhausted"
            _grid_exhausted = True

        # A7: must_invoke_playwright_mcp — True when the last challenge is a
        # gated page the curl grid structurally cannot solve (challenge verdict).
        _must_pw_mcp = (
            _final_verdict == Verdict.CHALLENGE.value
            or _final_verdict == Verdict.SUSPECT_OK.value
        )

        summary = _format_summary(trace, profile_used)
        return FetchResult(
            ok=False,
            content=_final_content,
            final_url=_final_url,
            verdict=_final_verdict,
            profile_used=profile_used,
            trace=trace,
            summary=summary,
            untried_routes=[],  # stub: full per-combo tracking deferred to a later wave
            must_invoke_playwright_mcp=_must_pw_mcp,
            grid_exhausted=_grid_exhausted,
            stop_reason=_stop_reason,
        )
    finally:
        # P21: persist the (possibly newly-earned) clearance jar before the
        # session is torn down, so the next CLI invocation re-sends it. No-op
        # unless INSANE_COOKIE_JAR_DIR is set. Runs on every exit path
        # (success return inside try still passes through finally).
        if jar_domain is not None:
            # M-SEC: pass jar_domain so _session_cookies drops foreign-domain
            # cookies before writing. Defense-in-depth layer 2.
            _save_cookie_jar(session, url, jar_domain=jar_domain)
        # A2: only close the session when we created it. When a caller-supplied
        # session is in use (pool=ON), the pool owns the lifecycle.
        if _session_owned and session is not None:
            try:
                session.close()
            except Exception:
                pass


def _build_result(resp, attempt: Attempt, trace: list[Attempt], profile_used: Optional[str]) -> FetchResult:
    return FetchResult(
        ok=True,
        content=getattr(resp, "text", "") or "",
        final_url=str(getattr(resp, "url", attempt.url)),
        verdict=attempt.verdict,
        profile_used=profile_used,
        trace=trace,
        summary=f"{attempt.executor} {attempt.impersonate} + {attempt.url_transform} + referer:{attempt.referer} → {attempt.verdict}",
    )


# WAF profiles known to typically gate HTML but leave internal JSON APIs
# (relatively) open. When these are detected and curl challenges pile up,
# we surface R7 hint in the summary so the caller (or Claude) can branch
# to an API-first route without waiting for full grid exhaustion.
_R7_ELIGIBLE_PROFILES = frozenset({
    "akamai_bot_manager",
    "cloudflare_turnstile",
    "datadome_probable",
    "perimeterx_human",
    "f5_big_ip",
    "aws_waf",
    # Wave 1 review sync (2026-06-11): these three profiles are needs_real_tls_stack
    # and were added to the SKILL.md R7 list in P8; syncing the code constant here.
    "imperva_incapsula",
    "kasada",
    "sucuri_cloudproxy",
})

R7_HINT = (
    "💡 R7 API-first 권장: WAF가 HTML 경로를 차단 중. "
    "Playwright MCP 사용 → browser_navigate → browser_network_requests "
    "→ `/api/`·`/graphql`·`\\.json` 필터로 내부 엔드포인트 탐지 → "
    "해당 URL을 `python3 -m engine <API_URL>`로 재호출. 대부분 API 레이어는 "
    "WAF 방어가 얕아 curl_cffi만으로 수집됨."
)


def _format_summary(trace: list[Attempt], profile: Optional[str]) -> str:
    n = len(trace)
    verdicts = [a.verdict for a in trace]
    challenge_count = sum(1 for v in verdicts if v == Verdict.CHALLENGE.value)
    grid_tried = sum(1 for a in trace if getattr(a, "phase", None) == "grid")
    grid_info = f" (grid {grid_tried}/{n})" if grid_tried else ""
    base = (
        f"failed after {n} attempts{grid_info}; profile={profile}; "
        f"verdicts={','.join(v for v in verdicts[:5])}" + ("..." if n > 5 else "")
    )
    if profile in _R7_ELIGIBLE_PROFILES and challenge_count >= 3:
        return base + "\n" + R7_HINT
    return base
