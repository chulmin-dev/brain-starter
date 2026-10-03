"""SSRF guard for the plus value layer.

Split out from `_security.py` (D14) because SSRF logic — pre-flight URL
inspection, DNS resolution, non-standard IPv4 normalization, and the
post-redirect re-check — is the largest single concern in that module and
forms a self-contained chunk.

Public surface (re-exported by `_security.py` for backward compat):
- `SSRFBlockedError` — raised when a URL fails the safety check.
- `_ssrf_guard(url, allow_disable=True)` — pre-flight check.
- `_post_redirect_check(final_url, trace_urls)` — sanitize a completed
  fetch's traversal trail.

Environment overrides:
- `INSANE_DISABLE_SSRF_GUARD=1` — bypass the pre-flight (post-redirect is
  always enforced — once redirect traversal has happened we refuse to be
  overridden out of refusing the content).
- `INSANE_SSRF_STRICT=1` — fail closed on DNS lookup errors (default:
  pass through and let the engine's resolver decide).
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from typing import Iterable, Optional
from urllib.parse import urlsplit


ALLOWED_SCHEMES = frozenset({"http", "https"})


class SSRFBlockedError(ValueError):
    """Raised when a URL fails the SSRF safety check.

    Subclasses ValueError so callers that already catch ValueError keep
    working without changes.
    """


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> Optional[str]:
    """Return a short reason if the IP must be blocked, else None."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    # LOW-1 (2026-06-11): 192.88.99.0/24 (6to4 anycast relay, RFC 7526
    # deprecated) is is_global=True so the catch-all below does NOT catch it.
    # Explicitly block it to honour the P2 proposal's stated coverage.
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("192.88.99.0/24"):
        return "6to4-relay"
    # P2 (2026-06-11): catch-all for non-global addresses not covered by the
    # explicit checks above — e.g. 100.64.0.0/10 (CGNAT / Tailscale), which
    # is_private=False but is_global=False on Python 3.12. This is ADDITIVE
    # after the specific checks (not a replacement) so that 64:ff9b::/96
    # (NAT64 mapping, is_global=True + is_reserved=True) is still caught by
    # the is_reserved branch above rather than silently bypassed.
    # L1 note (security review 2026-06-11): this catch-all also blocks IPv6
    # unique-local (fc00::/7) and Teredo — over-block in the safe direction.
    # A legitimately-routed IPv6 address that Python's stdlib classifies as
    # non-global will be blocked here. See UPSTREAM.md §Known limits.
    if not ip.is_global:
        return "non-global"
    return None


# Non-standard IPv4 forms that `ipaddress.ip_address` rejects but `libcurl`'s
# `inet_aton`-style parser silently accepts (RFC 6943 / RFC 3493 deviation):
#   octal-prefixed (0177.0.0.1 → 127.0.0.1)
#   short-form     (127.1 → 127.0.0.1; 0 → 0.0.0.0)
#   single-integer (2130706433 → 127.0.0.1)
#   hex-prefixed   (0x7f.0.0.1 → 127.0.0.1)
# These are classic SSRF bypass vectors. We use `socket.inet_aton` to ask the
# C library how it would interpret the host, then re-check the result against
# our blocked-range list.
_NUMERIC_HOST = re.compile(r"^[0-9a-fA-FxX.]+$")


def _resolve_non_standard_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """If `host` looks like a numeric IPv4 in any form libcurl accepts but
    `ipaddress.ip_address` rejects, return the canonical IPv4Address; else None.
    """
    if not _NUMERIC_HOST.match(host):
        return None
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    try:
        return ipaddress.IPv4Address(packed)
    except (ValueError, ipaddress.AddressValueError):
        return None


def _ssrf_guard(url: str, *, allow_disable: bool = True) -> None:
    """Block SSRF-prone URLs before the engine ever touches them.

    Checks: scheme ∈ {http,https}; host literal IP not in blocked ranges;
    every DNS-resolved IP (A/AAAA) not in blocked ranges.

    Raises `SSRFBlockedError` on failure. Pass `allow_disable=False` to
    ignore the `INSANE_DISABLE_SSRF_GUARD` env override (used by
    `_post_redirect_check` — once redirect-traversal has happened we
    refuse to be overridden out of refusing the content).
    """
    if allow_disable and os.environ.get("INSANE_DISABLE_SSRF_GUARD") == "1":
        return

    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise SSRFBlockedError(
            f"non-http(s) scheme not allowed: {parts.scheme!r} in {url!r}"
        )
    host = parts.hostname
    if not host:
        raise SSRFBlockedError(f"missing hostname in {url!r}")

    # IP literal: short-circuit DNS.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        reason = _is_blocked_ip(ip)
        if reason:
            raise SSRFBlockedError(f"blocked IP literal {host!r} ({reason})")
        return

    # Non-standard IPv4 (octal/decimal/short-form/hex) — `ipaddress` rejected
    # it but libcurl will still interpret these. Resolve via `inet_aton` and
    # check the canonical form against the blocked ranges. Catches the
    # `http://0177.0.0.1/` style of SSRF bypass that the dotted-quad check  # NOTE-BIAS-OK: octal IP SSRF example in security comment
    # alone misses.
    weird_ip = _resolve_non_standard_ipv4(host)
    if weird_ip is not None:
        reason = _is_blocked_ip(weird_ip)
        if reason:
            raise SSRFBlockedError(
                f"blocked non-standard IPv4 {host!r} → {weird_ip} ({reason})"
            )
        return

    # Hostname → resolve and check every returned address.
    try:
        infos = socket.getaddrinfo(host, parts.port or None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        # Default: don't fail closed on lookup error — the engine's own
        # resolver (incl. DoH) may yet succeed. `INSANE_SSRF_STRICT=1`
        # tightens this for callers who want a hard pre-flight.
        if os.environ.get("INSANE_SSRF_STRICT") == "1":
            raise SSRFBlockedError(f"DNS lookup failed for {host!r}: {e}") from e
        return

    for info in infos:
        addr = info[4][0]
        try:
            resolved = ipaddress.ip_address(addr)
        except ValueError:
            continue
        reason = _is_blocked_ip(resolved)
        if reason:
            raise SSRFBlockedError(
                f"host {host!r} resolves to blocked IP {addr} ({reason})"
            )


def _ip_literal_check(url: str, ip: str) -> None:
    """Validate a *pre-resolved* IP literal against the blocked ranges (C8).

    The engine's IP-pinning path resolves each hop's host exactly once, then
    asks this callback to vet the resolved address *before* it pins that same
    IP into libcurl via `CURLOPT_RESOLVE`. Because the verified IP and the
    connected IP are now identical, the classic DNS-rebinding TOCTOU window
    (guard resolves IP-A, libcurl independently re-resolves to IP-B) is closed.

    `url` is accepted for parity with the `url_check(url)` seam and for error
    messages; the security decision is made purely on `ip`. Raises
    `SSRFBlockedError` on a blocked address. Unparseable / empty `ip` is a
    no-op (the caller falls back to libcurl's own resolution, which the
    per-hop `url_check` + post-redirect sweep still guard).
    """
    if not ip:
        return
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        # Not an IP literal — nothing to vet here. The url_check seam and
        # post-redirect sweep remain the defence for this hop.
        return
    reason = _is_blocked_ip(parsed)
    if reason:
        raise SSRFBlockedError(
            f"host in {url!r} resolved to blocked IP {ip} ({reason})"
        )


def _post_redirect_check(final_url: str, trace_urls: Iterable[str] = ()) -> None:
    """Verify final_url and every trace URL after the fetch has completed.

    `engine.fetch_chain` now drives redirects manually with per-hop
    `url_check` (Step 3 patch #2), so curl-driven hops are blocked before
    they fire. This post-redirect sweep is the defence-in-depth net for
    paths that the per-hop check cannot see: Playwright fallback results,
    meta-refresh / JS `location.href` redirects served in a 200-OK body,
    and the engine-stamped final URL on any code path that bypasses
    `url_check`.
    """
    seen: set[str] = set()
    candidates: list[str] = []
    if final_url:
        candidates.append(final_url)
    for u in trace_urls:
        if u and u not in seen:
            seen.add(u)
            candidates.append(u)
    for url in candidates:
        try:
            _ssrf_guard(url, allow_disable=False)
        except SSRFBlockedError as e:
            raise SSRFBlockedError(f"post-redirect: {e}") from None
