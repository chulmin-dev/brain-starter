"""DNS-over-HTTPS support for page-fetch.

Some networks block plain DNS (outbound UDP port 53) while leaving HTTPS
(port 443) open. On such a network every domain fetch fails at name
resolution — curl hangs in `getaddrinfo` until it times out.

This module routes DNS through DoH by setting libcurl's `CURLOPT_DOH_URL`
on the curl_cffi sessions the engine uses, so name resolution travels over
HTTPS instead. The `engine/` package is never touched: curl_cffi is patched
at runtime, entirely from the `plus/` layer.
"""
from __future__ import annotations

import functools
import os
import socket
import sys
import threading

# Cloudflare's DoH endpoint. It is reached by IP, so it needs no DNS itself.
_DEFAULT_DOH_URL = "https://1.1.1.1/dns-query"  # NOTE-BIAS-OK: DoH infrastructure IP — not a target site

# Phase 2 hardening (consensus C6): well-known, reputable DoH endpoints we
# accept without ack. An attacker-set `INSANE_DOH_URL` outside this set would
# otherwise route every domain lookup through a MITM resolver. Hosts are
# IP-only — a hostname endpoint would itself need the DNS that DoH is meant
# to bypass.
_DOH_ALLOWLIST = frozenset({
    "https://1.1.1.1/dns-query",          # NOTE-BIAS-OK: DoH infrastructure IP — Cloudflare primary
    "https://1.0.0.1/dns-query",          # NOTE-BIAS-OK: DoH infrastructure IP — Cloudflare secondary
    "https://8.8.8.8/dns-query",          # NOTE-BIAS-OK: DoH infrastructure IP — Google primary
    "https://8.8.4.4/dns-query",          # NOTE-BIAS-OK: DoH infrastructure IP — Google secondary
    "https://9.9.9.9/dns-query",          # NOTE-BIAS-OK: DoH infrastructure IP — Quad9 primary
    "https://149.112.112.112/dns-query",  # NOTE-BIAS-OK: DoH infrastructure IP — Quad9 secondary
})

_patched = False
_orig_request = None


def doh_url() -> str:
    """The DoH endpoint to use (INSANE_DOH_URL env override, else Cloudflare).

    On a DNS-blocked network the endpoint must be IP-addressed — the default
    `https://1.1.1.1/dns-query` is. A hostname-based URL would itself need the  # NOTE-BIAS-OK: DoH IP in docstring
    very DNS that is blocked; use e.g. `https://8.8.8.8/dns-query` instead.  # NOTE-BIAS-OK: DoH IP in docstring

    Phase 2 guard: an `INSANE_DOH_URL` outside the well-known DoH allowlist
    falls back to the default (with a stderr warning) unless `INSANE_DOH_ACK=1`
    is set — protects against env-injection MITM (consensus C6).
    """
    env = (os.environ.get("INSANE_DOH_URL") or "").strip()
    if not env:
        return _DEFAULT_DOH_URL
    if env in _DOH_ALLOWLIST:
        return env
    if os.environ.get("INSANE_DOH_ACK") == "1":
        print(
            f"[plus] DoH override outside allowlist accepted via "
            f"INSANE_DOH_ACK=1: {env}",
            file=sys.stderr,
        )
        return env
    print(
        f"[plus] warning: INSANE_DOH_URL={env!r} outside allowlist "
        f"({sorted(_DOH_ALLOWLIST)[0]} etc.); falling back to default "
        f"{_DEFAULT_DOH_URL}. Set INSANE_DOH_ACK=1 to override.",
        file=sys.stderr,
    )
    return _DEFAULT_DOH_URL


def enable() -> None:
    """Patch curl_cffi so every session resolves DNS over HTTPS.

    Idempotent. Wraps `Session.request` to set `CURLOPT_DOH_URL` before each
    request — this covers the module-level `curl_cffi.requests.get()` that the
    engine's probe uses, since that path also ends in `Session.request`.

    Best-effort: if curl_cffi is unavailable it returns quietly rather than
    raising — a fetch must never crash because DoH could not be set up.
    """
    global _patched, _orig_request
    if _patched:
        return
    try:
        from curl_cffi import CurlOpt
        from curl_cffi import requests as cffi_requests
    except ImportError:
        return  # curl_cffi not installed — fall back to plain DNS

    url_bytes = doh_url().encode("utf-8")
    _orig_request = cffi_requests.Session.request

    @functools.wraps(_orig_request)
    def _request_with_doh(self, *args, **kwargs):
        try:
            self.curl.setopt(CurlOpt.DOH_URL, url_bytes)
        except Exception:
            pass  # DoH setup must never break a fetch — fall back to plain DNS
        return _orig_request(self, *args, **kwargs)

    cffi_requests.Session.request = _request_with_doh
    _patched = True


def system_dns_works(host: str = "example.com", timeout: float = 3.0) -> bool:
    """Best-effort probe: can the system resolver resolve `host` quickly?

    `getaddrinfo()` ignores socket timeouts, so the probe runs in a daemon
    thread and is judged failed if it has not finished within `timeout`
    seconds (the daemon thread is reaped when the process exits).
    """
    state = {"ok": False}

    def _probe() -> None:
        try:
            socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            state["ok"] = True
        except Exception:
            state["ok"] = False

    t = threading.Thread(target=_probe, daemon=True)
    t.start()
    t.join(timeout)
    # If getaddrinfo hung, the thread is intentionally abandoned; the daemon
    # flag ensures it cannot block process exit.
    return state["ok"]


def setup(mode: str) -> str:
    """Apply DoH according to `mode` and return a short status label.

    mode:
      "on"   — force DoH.
      "off"  — never use DoH.
      "auto" — use DoH only when plain DNS looks blocked. The INSANE_DOH env
               var (on/off/1/0) forces the auto decision; without it, a quick
               system-resolver probe decides.
    """
    if mode == "on":
        enable()
        return f"doh=on ({doh_url()})"
    if mode == "off":
        return "doh=off"

    # auto
    env = (os.environ.get("INSANE_DOH") or "").strip().lower()
    if env in ("1", "on", "true", "yes"):
        enable()
        return f"doh=on (env, {doh_url()})"
    if env in ("0", "off", "false", "no"):
        return "doh=off (env)"
    if system_dns_works():
        return "doh=off (system DNS ok)"
    enable()
    print(
        "[plus] system DNS unreachable — routing DNS over HTTPS (DoH)",
        file=sys.stderr,
    )
    return f"doh=on (auto: system DNS failed, {doh_url()})"
