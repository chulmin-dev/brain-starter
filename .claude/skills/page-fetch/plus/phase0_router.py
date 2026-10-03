"""Phase 0 — official public-API router for the plus layer.

Ported from engine/phase0.py (upstream insane-search) and wired into the
plus fetch flow. The SSRF pre-flight from plus._ssrf replaces the bare
curl_cffi direct call so every Phase-0 hop goes through the same guard
chain as the main grid.

Contract:
    route(url, *, timeout) -> Optional[dict]
      None  → url is not a recognised Phase-0 platform; caller runs the
               generic grid as usual.
      dict  → recognised platform. Keys: platform, ok, route, content,
               final_url, attempts. Even on ok=False the caller falls
               through to the grid; attempts is recorded so failure is
               never silent.

Each attempt dict: {route, platform, ok, status, bytes, note}.

NOTE: This is the ONLY plus/ module allowed to name platform hosts.
All host literals carry # NOTE-BIAS-OK because bias_check's EXPLICIT_ALLOW
list covers only engine/; this file is in plus/ and must annotate per-line.
"""
from __future__ import annotations

import math
import re
import subprocess
import time
from typing import Optional
from urllib.parse import urljoin, urlsplit

# Module-top import: a wrong symbol name fails loudly at import time,
# not silently per-fetch inside a swallowing except-clause (H2 / C1 fix).
from ._ssrf import _ssrf_guard  # raises SSRFBlockedError on SSRF-prone URLs


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

# Network errors that are expected in production (timeout, connection reset,
# TLS failure, etc.).  ImportError / AttributeError / NameError are
# programming errors — they must NOT be caught here so they fail loudly.
_NETWORK_ERRORS: tuple[type[BaseException], ...] = (OSError, ValueError)

try:
    from curl_cffi.requests.exceptions import RequestException as _CurlException
    _NETWORK_ERRORS = (*_NETWORK_ERRORS, _CurlException)
except ImportError:
    pass


_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 10


def _ssrf_guarded_get(url: str, *, timeout: int = 15):
    """GET a Phase-0 route with SSRF validation before every redirect hop.

    Redirects are followed manually so an external endpoint cannot pivot into
    localhost, a private network, or cloud metadata before the guard sees the
    destination. One deadline covers the whole chain; it is not reset per hop.
    """
    from curl_cffi import requests as r  # lazy: let ImportError propagate loud

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,ko;q=0.8",
    }
    current_url = url
    deadline = time.monotonic() + timeout

    for redirect_count in range(_MAX_REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("phase0 redirect deadline exceeded")

        _ssrf_guard(current_url)
        response = r.get(
            current_url,
            impersonate="safari",  # type: ignore[arg-type]
            timeout=max(1, math.ceil(remaining)),
            headers=headers,
            allow_redirects=False,
        )
        if response.status_code not in _REDIRECT_CODES:
            return response

        response_headers = {
            str(key).lower(): value
            for key, value in dict(getattr(response, "headers", {}) or {}).items()
        }
        location = response_headers.get("location")
        if not location:
            return response
        if redirect_count >= _MAX_REDIRECTS:
            raise OSError(f"phase0 redirect limit exceeded: {_MAX_REDIRECTS}")

        current_url = urljoin(current_url, str(location))

    raise OSError(f"phase0 redirect limit exceeded: {_MAX_REDIRECTS}")


def _host(url: str) -> str:
    h = (urlsplit(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _attempt(platform: str, route: str, ok: bool, status: int, body: str, note: str = "") -> dict:
    return {"platform": platform, "route": route, "ok": ok, "status": status,
            "bytes": len(body or ""), "note": note}


# ---------------------------------------------------------------------------
# Platform detectors
# ---------------------------------------------------------------------------

def _detect(url: str) -> Optional[str]:
    h = _host(url)
    if not h:
        return None
    # Exact + suffix checks — substring matches on host would misdetect
    # spoofed domains (M1 fix). Use == or endswith(".{tld}") exclusively.
    if h == "reddit.com" or h.endswith(".reddit.com") or h == "redd.it":  # NOTE-BIAS-OK
        return "reddit"
    if h in ("x.com", "twitter.com") or h.endswith(".x.com") or h.endswith(".twitter.com"):  # NOTE-BIAS-OK
        return "x"
    if h == "youtube.com" or h.endswith(".youtube.com") or h == "youtu.be":  # NOTE-BIAS-OK
        return "youtube"
    return None


# ---------------------------------------------------------------------------
# Reddit
# ---------------------------------------------------------------------------

def _reddit(url: str, timeout: int) -> dict:
    attempts: list[dict] = []
    base = url.split("?", 1)[0].rstrip("/")
    # Build .rss / .json from path (works for /r/<sub> and post URLs).
    rss_url = base + ("/.rss" if "/comments/" not in base else ".rss")  # NOTE-BIAS-OK
    json_url = base + ("/.json" if "/comments/" not in base else ".json")  # NOTE-BIAS-OK

    # Route 1: RSS — preferred; no JSON-API gate, but IP-reputation WAF can
    # still 403 from flagged/rate-limited egress IPs (flaky, not guaranteed).
    try:
        x = _ssrf_guarded_get(rss_url, timeout=timeout)
        ok = x.status_code == 200 and ("<rss" in x.text or "<feed" in x.text)
        attempts.append(_attempt("reddit", "rss", ok, x.status_code, x.text,
                                 "feed" if ok else f"status={x.status_code}"))
        if ok:
            return {"platform": "reddit", "ok": True, "route": "rss",
                    "content": x.text, "final_url": rss_url, "attempts": attempts}
    except _NETWORK_ERRORS as e:
        attempts.append(_attempt("reddit", "rss", False, 0, "", f"{type(e).__name__}"))
    # Programming errors (ImportError, AttributeError, NameError, …) propagate.

    # Route 2: JSON via curl_cffi — WAF-gated; 403 common; try cheap.
    try:
        x = _ssrf_guarded_get(json_url, timeout=timeout)
        ok = x.status_code == 200 and x.text.lstrip().startswith(("{", "["))
        attempts.append(_attempt("reddit", "json", ok, x.status_code, x.text,
                                 "json" if ok else f"status={x.status_code}"))
        if ok:
            return {"platform": "reddit", "ok": True, "route": "json",
                    "content": x.text, "final_url": json_url, "attempts": attempts}
    except _NETWORK_ERRORS as e:
        attempts.append(_attempt("reddit", "json", False, 0, "", f"{type(e).__name__}"))

    return {"platform": "reddit", "ok": False, "route": None, "content": "",
            "final_url": url, "attempts": attempts}


# ---------------------------------------------------------------------------
# X / Twitter
# ---------------------------------------------------------------------------

_TWEET_ID_RE = re.compile(r"/status(?:es)?/(\d+)")


def _x(url: str, timeout: int) -> dict:
    attempts: list[dict] = []
    m = _TWEET_ID_RE.search(url)

    if m:  # single tweet → CDN Syndication tweet-result (primary), oEmbed (fallback)
        tid = m.group(1)
        try:
            tweet_url = f"https://cdn.syndication.twimg.com/tweet-result?id={tid}&token=a"  # NOTE-BIAS-OK
            x = _ssrf_guarded_get(tweet_url, timeout=timeout)
            d = x.json() if x.status_code == 200 else {}
            ok = bool(d.get("text"))
            attempts.append(_attempt("x", "tweet-result", ok, x.status_code, x.text,
                                     "has-text" if ok else f"status={x.status_code}"))
            if ok:
                return {"platform": "x", "ok": True, "route": "tweet-result",
                        "content": x.text, "final_url": url, "attempts": attempts}
        except _NETWORK_ERRORS as e:
            attempts.append(_attempt("x", "tweet-result", False, 0, "", f"{type(e).__name__}"))

        try:
            ourl = f"https://publish.twitter.com/oembed?url=https://twitter.com/i/status/{tid}&omit_script=1"  # NOTE-BIAS-OK
            x = _ssrf_guarded_get(ourl, timeout=timeout)
            d = x.json() if x.status_code == 200 else {}
            ok = bool(d.get("html"))
            attempts.append(_attempt("x", "oembed", ok, x.status_code, x.text,
                                     "has-html" if ok else f"status={x.status_code}"))
            if ok:
                return {"platform": "x", "ok": True, "route": "oembed",
                        "content": x.text, "final_url": ourl, "attempts": attempts}
        except _NETWORK_ERRORS as e:
            attempts.append(_attempt("x", "oembed", False, 0, "", f"{type(e).__name__}"))

    else:  # profile timeline → syndication (rate-limit-prone; retry once)
        handle = urlsplit(url).path.strip("/").split("/")[0]
        _reserved = {"i", "search", "home", "explore", "messages", "notifications",
                     "settings", "hashtag"}
        if handle and handle.lower() not in _reserved:
            surl = f"https://syndication.twitter.com/srv/timeline-profile/screen-name/{handle}"  # NOTE-BIAS-OK
            for attempt_no in range(2):
                try:
                    x = _ssrf_guarded_get(surl, timeout=timeout)
                    ok = x.status_code == 200 and "__NEXT_DATA__" in x.text
                    attempts.append(_attempt(
                        "x", f"syndication-timeline#{attempt_no + 1}", ok,
                        x.status_code, x.text,
                        "timeline" if ok else f"status={x.status_code}",
                    ))
                    if ok:
                        return {"platform": "x", "ok": True, "route": "syndication-timeline",
                                "content": x.text, "final_url": surl, "attempts": attempts}
                except _NETWORK_ERRORS as e:
                    attempts.append(_attempt(
                        "x", f"syndication-timeline#{attempt_no + 1}", False, 0, "",
                        f"{type(e).__name__}",
                    ))

    return {"platform": "x", "ok": False, "route": None, "content": "",
            "final_url": url, "attempts": attempts}


# ---------------------------------------------------------------------------
# YouTube
# ---------------------------------------------------------------------------

def _youtube(url: str, timeout: int) -> dict:
    attempts: list[dict] = []
    try:
        p = subprocess.run(
            ["yt-dlp", "--dump-json", "--skip-download", url],
            capture_output=True, text=True, timeout=max(timeout, 60),
        )
        ok = p.returncode == 0 and p.stdout.strip().startswith("{")
        note = "json" if ok else (p.stderr or "").strip()[:80]
        attempts.append(_attempt("youtube", "yt-dlp", ok, 200 if ok else 0, p.stdout, note))
        if ok:
            return {"platform": "youtube", "ok": True, "route": "yt-dlp",
                    "content": p.stdout, "final_url": url, "attempts": attempts}
    except FileNotFoundError:
        attempts.append(_attempt("youtube", "yt-dlp", False, 0, "", "yt-dlp not installed"))
    except subprocess.TimeoutExpired as e:
        attempts.append(_attempt("youtube", "yt-dlp", False, 0, "", f"{type(e).__name__}"))

    return {"platform": "youtube", "ok": False, "route": None, "content": "",
            "final_url": url, "attempts": attempts}


_ROUTERS = {"reddit": _reddit, "x": _x, "youtube": _youtube}


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def route(url: str, *, timeout: int = 15) -> Optional[dict]:
    """Try an official Phase-0 route for url.

    Returns None if url is not a recognised platform (caller falls through
    to the generic grid). Returns a result dict — ok=True on success,
    ok=False on failure (caller STILL falls through; attempts are recorded).
    """
    platform = _detect(url)
    if platform is None:
        return None
    return _ROUTERS[platform](url, timeout)
