"""Connect-IP pinning — DNS-rebinding TOCTOU closure (C8 / P39r).

The shipped per-hop `url_check` (P28/C1) re-resolves a host inside the SSRF
guard, but libcurl then resolves *again* when it connects — a rotating-DNS
attacker can hand a public IP to the guard and an internal IP to libcurl's
`connect()`, a microsecond rebinding window (UPSTREAM.md #1). C8/P39r closes it
by resolving each hop's host exactly ONCE, vetting that IP via `ip_check`, and
pinning the SAME IP into libcurl via `CURLOPT_RESOLVE` so the verified IP and
the connected IP are identical.

These tests pin the closure offline (no network) by:
  * faking `curl_cffi.requests` with a scripted Session whose `.curl.setopt`
    records every `CurlOpt.RESOLVE` pin,
  * faking `curl_cffi.const.CurlOpt` so the engine's `from curl_cffi.const
    import CurlOpt` resolves,
  * stubbing `engine.fetch_chain.socket.getaddrinfo` so the resolved IP is
    deterministic (and can be made to "rebind").

Assertions:
  1. The resolved-and-vetted IP is the exact IP pinned into libcurl
     (verify-IP == pin-IP — the TOCTOU is closed by construction).
  2. A blocked resolved IP is rejected at `ip_check` *before* any GET fires
     (rebinding to an internal IP can't reach `connect()`).
  3. `INSANE_DISABLE_IP_PIN=1` skips pinning (CDN/anycast opt-out) while the
     fetch still completes (url_check guard remains).
  4. An IP-literal host issues no RESOLVE pin (nothing to rebind).
  5. The plus-side `_ip_literal_check` callback renders the SSRF verdict on a
     pre-resolved IP (loopback blocked, public allowed).

Mock strategy mirrors `test_engine_redirect_check.py`.
"""
from __future__ import annotations

import importlib
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))


# A stable RESOLVE int so the fake CurlOpt matches the real one (10203). The
# engine only uses identity/equality of `CurlOpt.RESOLVE`, so any sentinel that
# round-trips through `setopt` works; we use the real value for realism.
_RESOLVE_OPT = 10203


class _FakeCurlOpt:
    RESOLVE = _RESOLVE_OPT


class _FakeResponse:
    """Minimal duck-typed response; `.url` is mutable for the engine stamp."""

    def __init__(self, *, status_code: int, text: str, url: str,
                 headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers or {}
        self.content = text.encode("utf-8", errors="replace")


class _FakeCurlHandle:
    """Captures setopt(CurlOpt.RESOLVE, [...]) calls. Mirrors curl_cffi's
    per-perform RESOLVE auto-clear by exposing the cumulative call log; tests
    assert on the pin entries, not residual slist state."""

    def __init__(self):
        self.setopt_calls: list[tuple] = []

    def setopt(self, option, value):
        self.setopt_calls.append((option, value))

    @property
    def resolve_pins(self) -> list[str]:
        out: list[str] = []
        for option, value in self.setopt_calls:
            if option == _RESOLVE_OPT:
                # value is a list like ["host:port:ip"]
                out.extend(value)
        return out


class _ScriptedSession:
    """Session whose .get() returns a queue of pre-built responses and whose
    `.curl` handle records RESOLVE pins."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []
        self.closed = False
        self.curl = _FakeCurlHandle()

    def get(self, url, *, impersonate=None, headers=None, timeout=None,
            allow_redirects=True, **_extra):
        # Snapshot the RESOLVE pins active at the moment of THIS GET so we can
        # assert per-hop pinning even though the handle log is cumulative.
        self.calls.append({
            "url": url,
            "impersonate": impersonate,
            "allow_redirects": allow_redirects,
            "pins_so_far": list(self.curl.resolve_pins),
        })
        if not self._responses:
            raise AssertionError(
                f"_ScriptedSession ran out at call #{len(self.calls)} url={url!r}"
            )
        nxt = self._responses.pop(0)
        if not nxt.url:
            nxt.url = url
        return nxt

    def close(self):
        self.closed = True


_LAST_SESSION: _ScriptedSession | None = None


def _install_fake_curl_cffi(responses):
    """Insert a fake curl_cffi tree (requests + const) backed by `responses`."""
    global _LAST_SESSION

    fake_requests = types.ModuleType("curl_cffi.requests")

    def _session_factory():
        global _LAST_SESSION
        _LAST_SESSION = _ScriptedSession(responses)
        return _LAST_SESSION

    def _module_level_get(*_args, **_kwargs):  # pragma: no cover
        raise AssertionError("cffi_requests.get() should not run — Session path in use")

    fake_requests.Session = _session_factory  # type: ignore[attr-defined]
    fake_requests.get = _module_level_get  # type: ignore[attr-defined]

    fake_const = types.ModuleType("curl_cffi.const")
    fake_const.CurlOpt = _FakeCurlOpt  # type: ignore[attr-defined]

    fake_pkg = types.ModuleType("curl_cffi")
    fake_pkg.requests = fake_requests  # type: ignore[attr-defined]
    fake_pkg.const = fake_const  # type: ignore[attr-defined]

    sys.modules["curl_cffi"] = fake_pkg
    sys.modules["curl_cffi.requests"] = fake_requests
    sys.modules["curl_cffi.const"] = fake_const
    return fake_pkg


def _reload_fetch_chain():
    for name in list(sys.modules):
        if name == "engine.fetch_chain" or name.startswith("engine.fetch_chain."):
            del sys.modules[name]
    fc = importlib.import_module("engine.fetch_chain")
    import engine as _engine_root
    _engine_root.fetch_chain = fc
    return fc


def _fake_getaddrinfo_returning(ip: str):
    """Return a getaddrinfo stub that always resolves to `ip` (port-agnostic)."""
    def _stub(host, port, *args, **kwargs):
        return [(2, 1, 6, "", (ip, port or 0))]
    return _stub


class _IpPinTestBase(unittest.TestCase):
    RESPONSES: list = []

    def setUp(self):
        from plus.tests._engine_fake_helper import install_fake_curl_cffi_isolation
        install_fake_curl_cffi_isolation(self)
        _install_fake_curl_cffi(self.RESPONSES)
        self.fetch_chain = _reload_fetch_chain()
        # Ensure the opt-out env never leaks in from the outer process.
        self._env = mock.patch.dict(os.environ, {}, clear=False)
        self._env.start()
        os.environ.pop("INSANE_DISABLE_IP_PIN", None)
        self.addCleanup(self._env.stop)


# ---------------------------------------------------------------------------
# 1. Verify-IP == pin-IP: the resolved/vetted IP is exactly what gets pinned
# ---------------------------------------------------------------------------

class TestVerifiedIpIsPinned(_IpPinTestBase):
    RESPONSES = [
        _FakeResponse(
            status_code=200,
            text="<html><body>" + ("ok " * 1500) + "</body></html>",
            url="https://example.com/page",
        ),
    ]

    def test_resolved_ip_is_pinned_into_libcurl(self):
        vetted: list[tuple[str, str]] = []

        def _ip_check(url, ip):
            vetted.append((url, ip))

        with mock.patch("engine.fetch_chain.socket.getaddrinfo",
                        _fake_getaddrinfo_returning("93.184.216.34")):
            self.fetch_chain.fetch(
                "https://example.com/page",
                success_selectors=None,
                timeout=1,
                max_attempts=1,
                enable_playwright=False,
                url_check=lambda _u: None,
                ip_check=_ip_check,
            )
        self.assertIsNotNone(_LAST_SESSION)
        # ip_check was asked to vet the resolved IP.
        self.assertIn(("https://example.com/page", "93.184.216.34"), vetted)
        # The SAME IP was pinned into libcurl via CURLOPT_RESOLVE.
        self.assertIn("example.com:443:93.184.216.34",
                      _LAST_SESSION.curl.resolve_pins)
        # And the pin was active *before* the GET fired (closing the window).
        self.assertEqual(len(_LAST_SESSION.calls), 1)
        self.assertIn("example.com:443:93.184.216.34",
                      _LAST_SESSION.calls[0]["pins_so_far"])


# ---------------------------------------------------------------------------
# 2. Rebinding to a blocked IP is rejected at ip_check before any GET
# ---------------------------------------------------------------------------

class TestRebindingBlockedIpRejected(_IpPinTestBase):
    # No response queued: if the engine ever issues a GET the session raises.
    RESPONSES = []

    def test_internal_resolved_ip_blocked_no_get(self):
        from plus._ssrf import _ip_literal_check  # real plus-side IP vetter

        # Host resolves to AWS metadata IP — the rebinding payload.
        with mock.patch("engine.fetch_chain.socket.getaddrinfo",
                        _fake_getaddrinfo_returning("169.254.169.254")):
            result = self.fetch_chain.fetch(
                "https://rebind.example/lure",
                success_selectors=None,
                timeout=1,
                max_attempts=1,
                enable_playwright=False,
                url_check=lambda _u: None,   # url_check passes; ip_check must catch
                ip_check=_ip_literal_check,
            )
        # No GET went out — the internal IP never reached connect().
        self.assertEqual(len(_LAST_SESSION.calls), 0,
                         "blocked IP must be rejected before any GET")
        # The probe attempt carries the url_check_rejected marker (ip_check
        # rejections share that error surface) and the fetch failed.
        self.assertTrue(len(result.trace) >= 1)
        probe = result.trace[0]
        self.assertEqual(probe.verdict, "unknown")
        self.assertIsNotNone(probe.error)
        self.assertIn("url_check_rejected", probe.error)
        self.assertFalse(result.ok)
        # No RESOLVE pin was applied for the blocked IP.
        self.assertEqual(_LAST_SESSION.curl.resolve_pins, [])


# ---------------------------------------------------------------------------
# 3. INSANE_DISABLE_IP_PIN=1 opt-out: no pin, fetch still completes
# ---------------------------------------------------------------------------

class TestOptOutDisablesPin(_IpPinTestBase):
    RESPONSES = [
        _FakeResponse(
            status_code=200,
            text="<html><body>" + ("ok " * 1500) + "</body></html>",
            url="https://example.com/cdn",
        ),
    ]

    def test_disable_env_skips_pin_but_fetch_runs(self):
        vetted: list = []

        with mock.patch.dict(os.environ, {"INSANE_DISABLE_IP_PIN": "1"}, clear=False):
            with mock.patch("engine.fetch_chain.socket.getaddrinfo",
                            _fake_getaddrinfo_returning("93.184.216.34")):
                result = self.fetch_chain.fetch(
                    "https://example.com/cdn",
                    success_selectors=None,
                    timeout=1,
                    max_attempts=1,
                    enable_playwright=False,
                    url_check=lambda _u: None,
                    ip_check=lambda _u, _ip: vetted.append(_ip),
                )
        # GET still fired and succeeded — opt-out doesn't break fetching.
        self.assertEqual(len(_LAST_SESSION.calls), 1)
        self.assertTrue(result.ok)
        # No RESOLVE pin and no ip_check call: the whole pin path was skipped.
        self.assertEqual(_LAST_SESSION.curl.resolve_pins, [])
        self.assertEqual(vetted, [])


# ---------------------------------------------------------------------------
# 4. IP-literal host: nothing to rebind, no pin issued
# ---------------------------------------------------------------------------

class TestIpLiteralHostNotPinned(_IpPinTestBase):
    RESPONSES = [
        _FakeResponse(
            status_code=200,
            text="<html><body>" + ("ok " * 1500) + "</body></html>",
            url="https://93.184.216.34/page",
        ),
    ]

    def test_literal_host_skips_resolve(self):
        getaddr_calls: list = []

        def _spy_getaddrinfo(host, port, *a, **k):
            getaddr_calls.append(host)
            return [(2, 1, 6, "", (host, port or 0))]

        with mock.patch("engine.fetch_chain.socket.getaddrinfo", _spy_getaddrinfo):
            self.fetch_chain.fetch(
                "https://93.184.216.34/page",
                success_selectors=None,
                timeout=1,
                max_attempts=1,
                enable_playwright=False,
                url_check=lambda _u: None,
                ip_check=lambda _u, _ip: None,
            )
        # A literal host needs no resolution and no RESOLVE pin.
        self.assertEqual(_LAST_SESSION.curl.resolve_pins, [])
        self.assertEqual(getaddr_calls, [],
                         "IP-literal host must not be resolved for pinning")


# ---------------------------------------------------------------------------
# 5. plus-side _ip_literal_check verdict on a pre-resolved IP
# ---------------------------------------------------------------------------

class TestIpLiteralCheckVerdict(unittest.TestCase):
    """`_ip_literal_check(url, ip)` renders the SSRF verdict on an IP literal
    that the engine already resolved — no re-resolution inside the check."""

    def test_loopback_ip_blocked(self):
        from plus._ssrf import _ip_literal_check, SSRFBlockedError
        with self.assertRaises(SSRFBlockedError) as cm:
            _ip_literal_check("https://attacker.test/", "127.0.0.1")
        self.assertIn("loopback", str(cm.exception))

    def test_link_local_metadata_ip_blocked(self):
        from plus._ssrf import _ip_literal_check, SSRFBlockedError
        with self.assertRaises(SSRFBlockedError) as cm:
            _ip_literal_check("https://attacker.test/", "169.254.169.254")
        self.assertIn("link-local", str(cm.exception))

    def test_public_ip_allowed(self):
        from plus._ssrf import _ip_literal_check
        # Must not raise — a global address is the whole point of fetching.
        _ip_literal_check("https://example.com/", "93.184.216.34")

    def test_empty_ip_is_noop(self):
        from plus._ssrf import _ip_literal_check
        # Empty / unresolved IP → no verdict (caller falls back to libcurl,
        # still guarded by url_check + post-redirect sweep).
        _ip_literal_check("https://example.com/", "")

    def test_non_ip_string_is_noop(self):
        from plus._ssrf import _ip_literal_check
        # A non-literal (shouldn't happen, but be defensive) is a no-op, not a
        # crash — the url_check seam remains the guard for that hop.
        _ip_literal_check("https://example.com/", "not-an-ip")


# ---------------------------------------------------------------------------
# 6. Per-hop re-pin across a redirect (each hop's host gets its own pin)
# ---------------------------------------------------------------------------

class TestPerHopRepin(_IpPinTestBase):
    RESPONSES = [
        _FakeResponse(
            status_code=302,
            text="",
            url="https://example.com/start",
            headers={"Location": "https://example.org/landing"},
        ),
        _FakeResponse(
            status_code=200,
            text="<html><body>" + ("ok " * 1500) + "</body></html>",
            url="https://example.org/landing",
        ),
    ]

    def test_each_hop_pins_its_own_host(self):
        # Map host → IP so the two hops resolve to distinct addresses.
        host_ip = {"example.com": "93.184.216.34", "example.org": "198.51.100.7"}

        def _mapped_getaddrinfo(host, port, *a, **k):
            return [(2, 1, 6, "", (host_ip[host], port or 0))]

        with mock.patch("engine.fetch_chain.socket.getaddrinfo", _mapped_getaddrinfo):
            self.fetch_chain.fetch(
                "https://example.com/start",
                success_selectors=None,
                timeout=1,
                max_attempts=1,
                enable_playwright=False,
                url_check=lambda _u: None,
                ip_check=lambda _u, _ip: None,
            )
        self.assertEqual(len(_LAST_SESSION.calls), 2)
        # Hop 1: example.com pinned before the first GET.
        self.assertIn("example.com:443:93.184.216.34",
                      _LAST_SESSION.calls[0]["pins_so_far"])
        # Hop 2: example.org pinned before the redirect GET.
        self.assertIn("example.org:443:198.51.100.7",
                      _LAST_SESSION.calls[1]["pins_so_far"])


if __name__ == "__main__":
    unittest.main()
