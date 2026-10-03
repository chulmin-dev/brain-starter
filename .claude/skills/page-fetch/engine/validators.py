"""Generic challenge / success validator.

Four layers (all generic, never site-specific):
  1. Challenge markers (WAF product strings — not site brand names)
  2. Size fingerprints (known bad byte sizes hinted by caller)
  3. Cookie sensor state (e.g. Akamai `_abck=~-1~`)
  4. Caller-supplied success_selectors (strongest positive proof)

Layers 1-3 are "negative proof" (fail fast).
Layer 4 is "positive proof" — without it, HTTP 200 is only a weak success.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:
    from bs4 import BeautifulSoup
except ImportError:  # bs4 is a soft dep: only used when selectors given
    BeautifulSoup = None  # type: ignore


# Markers are WAF-product strings only. Never include site brand / domain.
#
# Phase 12 (2026-05-24): the bare `"captcha"` substring was too generic —
# some e-commerce platforms embed inert `data-useGoogleRecaptcha=""` /
# `data-googleRecaptchaSiteKey=""` attributes on *every* page (the
# integration is dormant but the attribute survives). Lowercased that
# matches "captcha" everywhere, so every page on those platforms
# verdicted as CHALLENGE despite a normal 200 OK / multi-KB body
# (reproduced live and confirmed via the observation log).
# Replaced with widget-class signals that only appear on *rendered*
# challenge pages, plus one user-facing prompt string. reCAPTCHA +
# hCaptcha cover the dominant CAPTCHA providers; user-facing copy
# catches custom challenge pages that don't ship a known widget class.
CHALLENGE_MARKERS: list[str] = [
    "Access Denied",
    "sec-if-cpt-container",
    "Powered and protected by Akamai",
    "Just a moment...",
    "Checking your browser",
    "cf-chl-bypass",
    "Attention Required! | Cloudflare",
    "<title>Bot Challenge</title>",
    "DataDome",
    "Pardon Our Interruption",        # Kasada block page
    "Sucuri WebSite Firewall",        # Sucuri Cloudproxy block page
    "g-recaptcha",  # Google reCAPTCHA v2 visible widget class
    "h-captcha",    # hCaptcha visible widget class
    # Challenge-page copy. Substring fragments deliberately short so we
    # catch "Please complete the CAPTCHA", "complete the captcha below",
    # "Solve the captcha to continue", etc. without re-introducing the
    # bare-`captcha` false-positive: these phrases are imperative-mood
    # user instructions that don't appear inside inert attribute names.
    "complete the captcha",
    "solve the captcha",
    "Please enable JS and disable any ad blocker",
    "The requested URL was rejected",
    "Request unsuccessful. Incapsula",
    # P24 (2026-06-12): new WAF profile body markers (fastly_sigsci / azure_front_door /
    # cloud_armor / ddos_guard / perimeterx _pxAppId).  Mirror from waf_profiles.yaml
    # so the validator (runs before the detector in the pipeline) catches block pages early.
    "Signal Sciences",              # Fastly NGWAF block page
    "pow-button",                   # Fastly NGWAF proof-of-work challenge widget
    "The request was blocked by Cloud Armor",   # Google Cloud Armor explicit block string
    "DDoS-Guard",                   # DDoS-Guard challenge / block page vendor copy
    "_pxAppId",                     # PerimeterX sensor JS variable — set on every protected page
]

# Minimum body size below which we suspect a stub / challenge page.
# Tunable: some legitimate short JSON responses may be smaller, but callers
# that know their response type should pass success_selectors instead.
SMALL_BODY_THRESHOLD = 3000

# Phase 13 (2026-05-24): widget-class markers (`g-recaptcha`, `h-captcha`)
# also appear on legitimate pages that integrate the CAPTCHA provider into
# a contact / signup form. To distinguish a real challenge gate from a
# normal content page with a form, the widget-class markers require the
# body to be small. Real challenge gates ship a widget + a prompt + minimal
# JS — under ~10 KB in observed cases. Normal content pages with a form
# are typically 30 KB+. The shape gate is one-sided: marker matches in a
# small body are still treated as challenge; marker matches in a large
# body are ignored. Other markers (WAF product strings like "Just a moment"
# or "Powered and protected by Akamai") are scope-robust and are not gated.
SHAPE_GATED_MARKERS: frozenset[str] = frozenset({
    "g-recaptcha",
    "h-captcha",
})

_SHAPE_GATE_DEFAULT = 10_000  # bytes (len(text.encode("utf-8")) after A5)


def _shape_gate_max_body() -> int:
    """Phase 13 — threshold (UTF-8 BYTES, matching `SMALL_BODY_THRESHOLD`
    convention after A5) under which widget-class markers count as challenge
    signals. Tunable via env so operators can adjust without a source edit if
    a provider ships an unusually heavy widget page. Invalid / non-positive
    values fall back to `_SHAPE_GATE_DEFAULT`; matches the `_max_body_bytes`
    pattern in `fetch_chain.py`. Read at every `_marker_hits` call so the env
    var honours runtime changes (e.g. test fixtures setting it per-test)."""
    raw = os.environ.get("INSANE_SHAPE_GATE_MAX_BODY", "").strip()
    if not raw:
        return _SHAPE_GATE_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        return _SHAPE_GATE_DEFAULT
    return value if value > 0 else _SHAPE_GATE_DEFAULT


# Module-level alias of the default (bytes after A5) — kept for callers that
# reference the constant directly (tests, documentation). Operators tuning at
# runtime should set `INSANE_SHAPE_GATE_MAX_BODY`; that's what `_marker_hits` reads.
SHAPE_GATE_MAX_BODY = _SHAPE_GATE_DEFAULT


class Verdict(Enum):
    """Three-level classification (Codex suggestion — avoid binary).

    Wave 3 additions:
      SUSPECT_OK     — 200, parseable, but genuinely uncertain content.
                       NON-terminal: the grid keeps trying other combos.
                       Never persisted to winners (not a trust token).
      RATE_LIMITED   — HTTP 429 (transient; grid may retry).
      AUTH_REQUIRED  — HTTP 401 (terminal URL-level; grid short-circuits).
      NOT_FOUND      — HTTP 404/410 (terminal URL-level; grid short-circuits).
    """

    STRONG_OK = "strong_ok"          # passes all layers incl. success_selectors
    WEAK_OK = "weak_ok"              # passes 1-3 but no positive proof available
    SUSPECT_OK = "suspect_ok"        # 200+parseable but genuinely uncertain (non-terminal)
    CHALLENGE = "challenge"          # fails 1-3 (negative proof triggered)
    BLOCKED = "blocked"              # non-200 status (generic 4xx/5xx)
    RATE_LIMITED = "rate_limited"    # HTTP 429 (transient)
    AUTH_REQUIRED = "auth_required"  # HTTP 401 (terminal URL-level)
    NOT_FOUND = "not_found"          # HTTP 404/410 (terminal URL-level)
    UNKNOWN = "unknown"              # exception / malformed response


# ADAPT-7: URL-level terminal outcomes — the grid cannot fix these by
# changing impersonate/referer/transform, so short-circuit immediately.
# 403 and 5xx are NOT here: 403 is the WAF block the grid exists to beat;
# 5xx is a transient server hiccup. Both keep grinding.
TERMINAL_NONSUCCESS: frozenset[str] = frozenset({
    Verdict.AUTH_REQUIRED.value,
    Verdict.NOT_FOUND.value,
})




@dataclass
class ValidationResult:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    matched_selectors: list[str] = field(default_factory=list)
    body_size: int = 0
    status: int = 0

    @property
    def ok(self) -> bool:
        """Kept for ergonomic `if vr.ok:` use — weak_ok counts as ok.
        SUSPECT_OK is NOT ok (non-terminal; grid keeps trying)."""
        return self.verdict in (Verdict.STRONG_OK, Verdict.WEAK_OK)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "reasons": self.reasons,
            "matched_selectors": self.matched_selectors,
            "body_size": self.body_size,
            "status": self.status,
        }


def _marker_hits(body_lower: str, body_size: int) -> list[str]:
    """Return matching markers, applying the Phase 13 shape gate.

    `SHAPE_GATED_MARKERS` only count when `body_size <= _shape_gate_max_body()` —
    they appear on legitimate pages that integrate the captcha widget into
    a contact form, so a large-body match is treated as a normal page, not
    a challenge gate. Other markers are unaffected.
    """
    shape_gate = _shape_gate_max_body()
    hits: list[str] = []
    for m in CHALLENGE_MARKERS:
        if m.lower() not in body_lower:
            continue
        if m in SHAPE_GATED_MARKERS and body_size > shape_gate:
            continue
        hits.append(m)
    return hits


def _abck_unresolved(cookies: dict) -> bool:
    abck = cookies.get("_abck", "")
    return bool(abck) and "~-1~" in abck


def _byte_size(text: str) -> int:
    """Byte-accurate body size (A5, ported from insane-search v0.8.x).

    `len(text)` counts UNICODE CHARACTERS. For CJK content a genuine
    ~4500-byte page is only ~1500 characters, so a char-count `size` falls
    under `SMALL_BODY_THRESHOLD` and the page is falsely flagged `tiny_body`
    CHALLENGE. The `known_bad_sizes` fingerprints are empirically observed
    BYTE sizes (see `validate()` docstring), so measuring in bytes also makes
    the Layer-2 fingerprint comparison semantically correct. We make `size`
    byte-accurate EVERYWHERE (reporting, shape gate, fingerprint, threshold)
    so a single value is honest across all four uses.
    """
    # "ignore" drops lone surrogates (invalid UTF-8 sequences). The under-count
    # is safe-direction: it nudges toward tiny_body (more conservative), never away.
    return len(text.encode("utf-8", "ignore"))


# M2 (2026-06-24): Soft-phrase suppressor for the small-page RESCUE only.
#
# Problem: `_looks_complete_content_page` rescues a complete HTML doc with
# ≥64 visible chars to WEAK_OK. But a marker-LESS JS-challenge interstitial
# (e.g. "Please wait while we verify your browser… Redirecting…") is ALSO a
# complete document with real visible text — and WEAK_OK is TERMINAL (grid
# stops, no browser escalation) and persisted to winners.json cross-session.
#
# These phrases are generic JS-challenge copy that does NOT appear in
# legitimate short content pages. They are NOT in CHALLENGE_MARKERS because
# they are too generic (they could appear in a large FAQ or blog post) — the
# rescue guard is safe ONLY because it runs exclusively for <3 KB bodies where
# any such phrase is highly suspicious. One-sided: they can only block the
# rescue (keeping tiny_body CHALLENGE), never promote anything new to CHALLENGE.
#
# NOTE-BIAS-OK: these are generic WAF/interstitial copy phrases, not site brands.
_SMALL_PAGE_CHALLENGE_PHRASES: frozenset[str] = frozenset({
    "verify your browser",
    "verifying your browser",
    "checking your browser",   # also in CHALLENGE_MARKERS but only for large bodies
    "verifying you are human",
    "please wait",
    "enable javascript",
    "redirecting",
    "one moment",
    "we are checking",
    "just a moment",           # cf. CHALLENGE_MARKERS — belt-and-suspenders for small rescue
})


def _content_type(resp) -> str:
    """Extract Content-Type header value, lowercased. Empty string on failure."""
    try:
        headers = {k.lower(): v for k, v in dict(getattr(resp, "headers", {}) or {}).items()}
        return str(headers.get("content-type", "")).lower()
    except Exception:
        return ""


def _looks_like_json(text: str, ctype: str) -> bool:
    """True when the body appears to be JSON (by Content-Type or first char).

    Priority:
      1. If Content-Type contains 'json' → True (authoritative).
      2. If Content-Type is non-empty but does NOT contain 'json' (e.g.
         text/html, text/plain) → False; the server declared a non-JSON type,
         don't body-sniff and override it.
      3. No Content-Type → fall back to first-character sniff ('{' or '[').
         Note: 'null' / bare scalars are not sniffed here; they require an
         explicit JSON Content-Type to be routed through the JSON gate.
    """
    if "json" in ctype:
        return True
    if ctype:
        # Non-JSON Content-Type present — respect it, skip body sniff.
        return False
    s = text.lstrip()[:1]
    return s in ("{", "[")


def _json_ok(text: str):
    """True if text parses as non-empty JSON, False if parses-but-empty,
    None if not parseable. Returns Optional[bool]."""
    try:
        obj = json.loads(text)
    except Exception:
        return None
    if obj in (None, {}, [], ""):
        return False
    return True


# W3.1 (2026-06-24): JSON verdict refinement — distinguish legit API responses
# from JSON-wrapped challenge envelopes.
#
# Floor: body must be at least this many bytes for WEAK_OK promotion.
# Blocks pathologically tiny multi-key envelopes like '{"a":1,"b":2}' (13 B)
# while allowing minimal but realistic API shapes such as
# '{"status":"ok","data":[1,2,3],"count":3}' (47 B). Single-key bodies are
# already excluded by the len(obj) < 2 check regardless of size.
_JSON_WEAK_OK_MIN_BYTES = 32

# Error-shaped KEY names at the top level that indicate a JSON WAF/error
# envelope, NOT real application data.
#
# Caution: DO NOT add `status`, `reason`, `ts`, `ref`, `code` — these are
# ubiquitous in LEGIT APIs ({"status":"ok","data":[...]}, {"code":200,"result":...})
# and would cause over-demotion (the exact problem W3.1 was introduced to fix).
# Only add keys that are EXCLUSIVELY error-signal at the top level.
_JSON_ERROR_KEYS: frozenset[str] = frozenset({
    "error", "errors", "blocked", "captcha", "challenge",
    "message", "detail", "forbidden", "unauthorized",
    "denied", "rejected",          # M1: block-signal key names (not status/reason)
})

# Block-signal VALUE tokens — caught by the whole-object blob scan (M2).
# These tokens appear in VALUES of WAF envelopes regardless of key name,
# catching {"status":"blocked"}, {"result":"blocked"}, {"action":"deny"}.
#
# Chosen to be tight: tokens that block-pages use but legit data payloads
# don't. "blocked" as a value is rarely legitimate data; "ok" or "success"
# are never added here — that would break {"status":"ok"} APIs.
# NOTE-BIAS-OK: these are generic WAF/block-page value strings, not site brands.
_JSON_BLOCK_VALUE_TOKENS: frozenset[str] = frozenset({
    '"blocked"',
    '"access denied"',
    '"deny"',
    '"captcha"',
    '"challenge"',
    '"bot detected"',
    '"forbidden"',
})


def _json_is_substantial(text: str, body_size: int) -> bool:
    """Return True when a non-empty parseable JSON body looks like real API data.

    W3.1 + M1/M2 classification rules (all must hold for WEAK_OK promotion):
      1. Body size >= _JSON_WEAK_OK_MIN_BYTES (tiny payloads stay SUSPECT_OK).
      2. Either a dict with >= 2 keys, or a non-empty list.
      3. No top-level key in _JSON_ERROR_KEYS (error/blocked/denied/rejected/…).
      4. (M2) Whole-object blob scan: json.dumps(obj).lower() does NOT contain
         any phrase from _SMALL_PAGE_CHALLENGE_PHRASES OR any token from
         _JSON_BLOCK_VALUE_TOKENS. This covers nested dicts and all array
         elements in one pass — a {"data":{"msg":"verify your browser"}} or
         ["padding","please verify your browser"] is caught here.

    Returns False (stay SUSPECT_OK) when any check fails.

    Caution: DO NOT add "status"/"reason"/"code" to _JSON_ERROR_KEYS — those
    are extremely common in legit APIs. The value-token scan (rule 4) catches
    {"status":"blocked"} without demoting {"status":"ok"}.
    """
    if body_size < _JSON_WEAK_OK_MIN_BYTES:
        return False
    try:
        obj = json.loads(text)
    except Exception:
        return False

    if isinstance(obj, dict):
        if len(obj) < 2:
            # Single-key dict — error-shaped; stay SUSPECT_OK.
            return False
        # Any top-level key matches an error/block name → stay SUSPECT_OK.
        if obj.keys() & _JSON_ERROR_KEYS:
            return False
    elif isinstance(obj, list):
        if len(obj) == 0:
            return False
    else:
        return False

    # M2: stringify the WHOLE parsed object once and scan for both phrase and
    # value-token signals. Covers nested structures and all array elements.
    # json.dumps is deterministic and cheap for the small bodies handled here.
    blob = json.dumps(obj, ensure_ascii=False).lower()
    if any(phrase in blob for phrase in _SMALL_PAGE_CHALLENGE_PHRASES):
        return False
    if any(token in blob for token in _JSON_BLOCK_VALUE_TOKENS):
        return False
    return True


def _looks_complete_content_page(text: str, lowered: str) -> bool:
    """True when a SMALL body is still a real (short) page, not a challenge stub.

    A3 (ported from insane-search v0.8.x `validators.py:159-171`). A genuine
    page is a COMPLETE HTML document (closes `</html>`/`</body>`) that carries
    meaningful visible text — e.g. example.com at ~600B, or a short Korean
    post. A WAF interstitial that slipped past the marker checks is typically
    script-only, empty, or an incomplete fragment.

    M2 guard: even a complete document with ≥64 visible chars is NOT rescued if
    its visible text contains a soft JS-challenge phrase from
    `_SMALL_PAGE_CHALLENGE_PHRASES`. Those phrases only appear in interstitials
    at this small body size — real short content pages don't say "please wait"
    or "verify your browser". The guard is ONE-SIDED: it can only block the
    rescue (keeps tiny_body CHALLENGE), never promote anything new to CHALLENGE.
    """
    if "</html>" not in lowered and "</body>" not in lowered:
        return False
    visible = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    visible = re.sub(r"(?s)<[^>]+>", " ", visible)
    visible = re.sub(r"\s+", " ", visible).strip()
    if len(visible) < 64:
        return False
    visible_lower = visible.lower()
    if any(phrase in visible_lower for phrase in _SMALL_PAGE_CHALLENGE_PHRASES):
        return False
    return True


def _selector_hits(body: str, selectors: list[str]) -> Optional[list[str]]:
    """Return matched-selector list, or None if BS4 is unavailable.

    Distinguishing None (dependency missing) from [] (nothing matched) lets
    the caller classify as UNKNOWN vs CHALLENGE correctly (Codex review: do
    not let dependency failure masquerade as a WAF outcome).
    """
    if BeautifulSoup is None:
        return None
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return []
    hits: list[str] = []
    for sel in selectors:
        try:
            if soup.select(sel):
                hits.append(sel)
        except Exception:
            continue
    return hits


def validate(
    resp,
    *,
    success_selectors: Optional[list[str]] = None,
    known_bad_sizes: Optional[list[int]] = None,
    size_tolerance: int = 20,
) -> ValidationResult:
    """Validate a `curl_cffi` / `requests` response.

    Parameters
    ----------
    resp
        Response object with `.status_code`, `.text`, and cookie-like access.
    success_selectors
        Caller-supplied CSS selectors. Any match promotes `weak_ok` → `strong_ok`.
        Absence of selectors still allows `weak_ok` (no positive proof, but
        no negative proof either).
    known_bad_sizes
        Byte sizes that have been empirically observed as challenge-page
        fingerprints (caller / profile hint). NOTE: these values decay over
        time — profiles should timestamp or refresh them.
    """
    try:
        status = int(getattr(resp, "status_code", 0) or 0)
        text = getattr(resp, "text", "") or ""
        # A5 (2026, insane-search v0.8.x): size is BYTE length, not char count.
        # CJK pages are ~3x denser in bytes than chars; a char-count size made
        # real ~4500-byte Korean pages fall under SMALL_BODY_THRESHOLD and trip
        # a false tiny_body CHALLENGE. byte size is also the correct unit for the
        # known_bad_sizes fingerprints (Layer 2) and body_size reporting.
        size = _byte_size(text)
    except Exception as e:
        return ValidationResult(verdict=Verdict.UNKNOWN, reasons=[f"parse_error:{e}"])

    r = ValidationResult(verdict=Verdict.UNKNOWN, body_size=size, status=status)

    # ADAPT-7: refined HTTP status semantics (conservative default).
    # 429 → RATE_LIMITED (transient; must NOT strike winners).
    # 401 → AUTH_REQUIRED (terminal URL-level; grid short-circuits).
    # 404/410 → NOT_FOUND (terminal URL-level; grid short-circuits).
    # 403 + 5xx → BLOCKED (keep grinding — 403 is the WAF we exist to beat;
    #   5xx is a transient server hiccup). max_attempts=12 default preserved.
    if status == 0 or status >= 400:
        if status == 429:
            r.verdict = Verdict.RATE_LIMITED
        elif status == 401:
            r.verdict = Verdict.AUTH_REQUIRED
        elif status in (404, 410):
            r.verdict = Verdict.NOT_FOUND
        else:
            r.verdict = Verdict.BLOCKED
        r.reasons.append(f"status={status}")
        return r

    # --- Layer 4 (priority): caller's positive proof evaluated first ---
    # P4 (2026-06-11): success_selectors are evaluated before Layer 1 markers
    # so that a normal page that happens to mention a WAF product name (e.g.
    # "How to fix Access Denied errors") isn't misclassified as a challenge
    # when the caller has already supplied positive structural proof.
    #
    # Verdict cap: marker+selector co-occurrence → WEAK_OK (not STRONG_OK).
    # STRONG_OK is the cache-persistence / winners-learning trust token; we
    # must not award it when a challenge marker is also present, because the
    # selector might be matching a challenge page that coincidentally contains
    # expected DOM (e.g. a login form that appears before the challenge wall).
    #
    # Layer 2 (size fingerprints) is evaluated only when no success_selector
    # matched; a matching caller selector takes precedence (size_fp no longer
    # overrides a positive selector match). Layer 2 follows below and is only
    # reached when this success_selectors block is not entered.
    lowered = text.lower()
    markers = _marker_hits(lowered, size)
    if success_selectors:
        hits = _selector_hits(text, success_selectors)
        if hits is None:
            # BS4 dependency missing — can't evaluate caller's proof.
            # Classify as UNKNOWN (not CHALLENGE) so a WAF outcome isn't faked.
            r.verdict = Verdict.UNKNOWN
            r.reasons.append("bs4_missing")
            return r
        if hits:
            cookies = _extract_cookies(resp)
            r.matched_selectors = hits
            if markers:
                # Positive selector evidence present, but a challenge marker
                # was also found — trust is capped at WEAK_OK.
                r.reasons.extend(f"marker:{m}" for m in markers[:3])
                r.reasons.append("marker_overridden")
                r.verdict = Verdict.WEAK_OK
                return r
            if _abck_unresolved(cookies):
                r.reasons.append("abck_unresolved")
                r.verdict = Verdict.WEAK_OK  # demoted from STRONG_OK
                return r
            r.verdict = Verdict.STRONG_OK
            return r
        # Selectors requested but none matched → challenge regardless of size.
        r.verdict = Verdict.CHALLENGE
        r.reasons.append("no_success_selector")
        return r

    # --- Layer 1: challenge markers (product strings, never site brand) ---
    # Only reached when no success_selectors were supplied (handled above).
    if markers:
        r.verdict = Verdict.CHALLENGE
        r.reasons.extend(f"marker:{m}" for m in markers[:3])
        return r

    # --- Layer 2: size fingerprints (caller hint, tolerant match) ---
    # Fingerprint match is a strong negative signal — override even selectors.
    if known_bad_sizes:
        for bad in known_bad_sizes:
            if abs(size - bad) <= size_tolerance:
                r.verdict = Verdict.CHALLENGE
                r.reasons.append(f"size_fp:{size}~{bad}")
                return r

    # --- Layer 2b: JSON-aware validation (A4 + A6) ---
    # A small JSON API response (e.g. 400-byte `{"data":[...]}`) with no
    # selectors would fall through to the tiny_body heuristic → false CHALLENGE.
    # Ported from upstream validators.py:125-149. Detect JSON BEFORE the
    # size heuristic so the engine's own R7 API-first route is not broken.
    #
    # A6 (Wave 3): unknown-marker JSON → SUSPECT_OK (non-terminal) instead of
    # WEAK_OK. We can confirm the body is non-empty parseable JSON but we have
    # no positive proof it is real application data vs a JSON-wrapped challenge.
    # SUSPECT_OK lets the grid keep trying for a clean WEAK_OK/STRONG_OK.
    ctype = _content_type(resp)
    if _looks_like_json(text, ctype):
        j = _json_ok(text)
        if j is True:
            # Non-empty parseable JSON. W3.1: distinguish legit API responses
            # from JSON-wrapped challenge envelopes.
            #
            # WEAK_OK (soft terminal, earns the trust token): substantial body
            # — multi-key dict with no error keys, or non-empty array — whose
            # values don't trip a soft challenge phrase. A real API response
            # (e.g. GitHub /repos, Reddit .json) terminates here.
            #
            # SUSPECT_OK (non-terminal, grid keeps trying): tiny, single-key,
            # error-shaped, or soft-phrase JSON. Could be a JSON WAF envelope
            # (e.g. {"detail":"verify your browser"}, {"error":"blocked"}).
            # Returned as best-effort only if nothing better is found.
            if _json_is_substantial(text, size):
                r.verdict = Verdict.WEAK_OK
                r.reasons.append("json_ok")
                return r
            r.verdict = Verdict.SUSPECT_OK
            r.reasons.append("json_ok")
            return r
        if j is False:
            # Empty JSON ({}, [], null) — definitely not real content.
            r.verdict = Verdict.CHALLENGE
            r.reasons.append("json_empty")
            return r
        # j is None → not actually JSON (parse failed); fall through to HTML path.

    # No selectors: fall back to size heuristic.
    if size < SMALL_BODY_THRESHOLD:
        # A3 (insane-search v0.8.x): a small body is only WEAK evidence of a
        # challenge stub. A COMPLETE, content-bearing HTML document that just
        # happens to be short (e.g. example.com ~600B, or a short Korean post)
        # is a real page → clean WEAK_OK. Only an incomplete / script-only /
        # empty small body stays a tiny_body CHALLENGE.
        if _looks_complete_content_page(text, lowered):
            r.verdict = Verdict.WEAK_OK
            r.reasons.append(f"small_complete_page:{size}")
            return r
        r.verdict = Verdict.CHALLENGE
        r.reasons.append(f"tiny_body:{size}")
        return r

    # --- Layer 3: cookie sensor state (only when no selectors to decide on) ---
    cookies = _extract_cookies(resp)
    if _abck_unresolved(cookies):
        # A6: abck_unresolved on the selector-less path → SUSPECT_OK.
        # The Akamai sensor cookie is unresolved (~-1~ = challenge not cleared),
        # so we are genuinely unsure whether the body is real content or a
        # soft-challenge response. Non-terminal: grid keeps trying; SUSPECT_OK
        # is returned only if nothing better is found. Previously demoted to
        # WEAK_OK which was terminal — closing M2.
        r.reasons.append("abck_unresolved")
        r.verdict = Verdict.SUSPECT_OK
        return r

    # No positive proof available — weak OK.
    r.verdict = Verdict.WEAK_OK
    return r


def _extract_cookies(resp) -> dict:
    try:
        return {c.name: c.value for c in resp.cookies.jar}
    except Exception:
        try:
            return dict(resp.cookies) if hasattr(resp, "cookies") else {}
        except Exception:
            return {}
