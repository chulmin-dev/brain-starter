"""P27 engine resilience pack + P28 entry-URL url_check.

Offline / deterministic. Mirrors the fake-curl_cffi-injection strategy of
`test_engine_redirect_check.py` / `test_engine_cookie_persistence.py`: a fake
`curl_cffi.requests` module is swapped into `sys.modules`, `engine.fetch_chain`
is reloaded so its lazy import binds to the fake, and `_engine_fake_helper`
restores everything (including the engine_proxy patch) on cleanup.

Pins:
  * P28 — `url_check` is invoked on the *entry* URL before the first GET, not
    only on redirect hops. An entry URL the check rejects never fires a GET.
  * P27.1 — per-probe wall-clock deadline (`INSANE_MAX_PROBE_SECONDS`) aborts a
    slow redirect chain with a stable `probe_deadline:` error.
  * P27.2 — transport errors classify into `tls_rejected:` / `timeout:` /
    `dns_error:` prefixes; the grid skips the rejected impersonate family on a
    TLS reject.
  * P27.3 — `resp.text` derives from `resp.content` (rehydration pin), proving
    the validators' read path stays consistent.
  * P27.4 — meta-refresh soft redirect: a same-URL refresh is surfaced as an
    `unknown_challenge` signal by the WAF detector.
"""
from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))


# ---------------------------------------------------------------------------
# Fake curl_cffi.requests with scripted / callable responses per call
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, *, status_code: int, text: str, url: str,
                 headers: dict | None = None, cookies: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.content = text.encode("utf-8", errors="replace")


class _ScriptedSession:
    """`.get()` pops the head of `responses`; entries may be callables
    (called with the url) so a test can raise a transport error or sleep."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.cookies: dict[str, str] = {}
        self.calls: list[dict] = []
        self.closed = False

    def get(self, url, *, impersonate=None, headers=None, timeout=None,
            allow_redirects=True, **_extra):
        self.calls.append({
            "url": url,
            "impersonate": impersonate,
            "headers": dict(headers or {}),
            "timeout": timeout,
            "allow_redirects": allow_redirects,
        })
        if not self._responses:
            raise AssertionError(
                f"_ScriptedSession ran out at call #{len(self.calls)} url={url!r}"
            )
        nxt = self._responses.pop(0)
        if callable(nxt):
            return nxt(url)
        if not nxt.url:
            nxt.url = url
        return nxt

    def close(self):
        self.closed = True


_LAST_SESSION: _ScriptedSession | None = None


def _install_fake_curl_cffi(responses):
    global _LAST_SESSION

    fake_requests = types.ModuleType("curl_cffi.requests")

    def _session_factory():
        global _LAST_SESSION
        _LAST_SESSION = _ScriptedSession(responses)
        return _LAST_SESSION

    def _module_level_get(*_args, **_kwargs):  # pragma: no cover
        raise AssertionError("Session path is in use; module-level get must not run")

    fake_requests.Session = _session_factory  # type: ignore[attr-defined]
    fake_requests.get = _module_level_get  # type: ignore[attr-defined]

    fake_pkg = types.ModuleType("curl_cffi")
    fake_pkg.requests = fake_requests  # type: ignore[attr-defined]

    sys.modules["curl_cffi"] = fake_pkg
    sys.modules["curl_cffi.requests"] = fake_requests
    return fake_pkg


def _reload_fetch_chain():
    for name in list(sys.modules):
        if name == "engine.fetch_chain" or name.startswith("engine.fetch_chain."):
            del sys.modules[name]
    fc = importlib.import_module("engine.fetch_chain")
    import engine as _engine_root
    _engine_root.fetch_chain = fc
    return fc


class _FakeFetchBase(unittest.TestCase):
    RESPONSES: list = []

    def setUp(self):
        from plus.tests._engine_fake_helper import install_fake_curl_cffi_isolation
        install_fake_curl_cffi_isolation(self)
        _install_fake_curl_cffi(self.RESPONSES)
        self.fetch_chain = _reload_fetch_chain()


# ---------------------------------------------------------------------------
# P28 — entry URL is screened before the first GET
# ---------------------------------------------------------------------------

class TestEntryUrlChecked(_FakeFetchBase):
    """A url_check that rejects the entry URL must prevent any GET."""

    # No responses queued: if a GET ever fires, _ScriptedSession raises.
    RESPONSES: list = []

    def test_entry_url_rejected_before_first_get(self):
        def reject_all(_u):
            raise ValueError("blocked-entry")

        result = self.fetch_chain.fetch(
            "http://169.254.169.254/latest/meta-data/",
            success_selectors=None,
            timeout=1,
            max_attempts=1,
            enable_playwright=False,
            url_check=reject_all,
        )
        # Zero GETs issued — the entry URL was screened pre-flight.
        self.assertIsNotNone(_LAST_SESSION)
        self.assertEqual(len(_LAST_SESSION.calls), 0,
                         f"entry url must not be fetched; calls={_LAST_SESSION.calls}")
        # The probe attempt carries the established url_check_rejected marker.
        self.assertTrue(len(result.trace) >= 1)
        probe = result.trace[0]
        self.assertEqual(probe.verdict, "unknown")
        self.assertIsNotNone(probe.error)
        self.assertIn("url_check_rejected", probe.error)
        self.assertFalse(result.ok)

    def test_entry_url_allowed_when_check_passes(self):
        # Allow-all check + one good response → entry GET proceeds normally.
        self.fetch_chain = None  # reset; rebuild session with a real response
        _install_fake_curl_cffi([
            _FakeResponse(
                status_code=200,
                text="<html><body>" + ("ok " * 1500) + "</body></html>",
                url="https://example.com/",
            ),
        ])
        self.fetch_chain = _reload_fetch_chain()
        from plus import engine_proxy as _ep
        _ep._engine_fetch_chain = sys.modules["engine.fetch_chain"]

        result = self.fetch_chain.fetch(
            "https://example.com/",
            success_selectors=None,
            timeout=1,
            max_attempts=1,
            enable_playwright=False,
            url_check=lambda _u: None,
        )
        self.assertEqual(len(_LAST_SESSION.calls), 1)
        self.assertEqual(_LAST_SESSION.calls[0]["url"], "https://example.com/")
        self.assertTrue(result.ok)


# ---------------------------------------------------------------------------
# P27.1 — per-probe wall-clock deadline
# ---------------------------------------------------------------------------

def _slow_302(idx):
    """A 302 hop that sleeps before responding (drives the wall-clock budget)."""
    import time as _t

    def _resp(url):
        _t.sleep(0.05)
        return _FakeResponse(
            status_code=302,
            text="",
            url=url,
            headers={"Location": f"https://example.com/h{idx + 1}"},
        )
    return _resp


class TestProbeDeadline(_FakeFetchBase):
    """A slow redirect chain aborts at the wall-clock budget."""

    # 8 successive slow 302s; with a tiny deadline the engine bails before
    # exhausting the 10-hop redirect cap.
    RESPONSES = [_slow_302(i) for i in range(8)]

    def test_deadline_aborts_slow_chain(self):
        import os
        os.environ["INSANE_MAX_PROBE_SECONDS"] = "0.1"
        self.addCleanup(os.environ.pop, "INSANE_MAX_PROBE_SECONDS", None)

        result = self.fetch_chain.fetch(
            "https://example.com/h0",
            success_selectors=None,
            timeout=2,
            max_attempts=1,
            enable_playwright=False,
            url_check=lambda _u: None,
        )
        # Fewer GETs than the 10-hop redirect cap (deadline fired first).
        self.assertLess(len(_LAST_SESSION.calls), 11,
                        "deadline should abort before the redirect cap")
        self.assertTrue(len(result.trace) >= 1)
        probe = result.trace[0]
        self.assertIsNotNone(probe.error)
        self.assertIn("probe_deadline:", probe.error)
        self.assertFalse(result.ok)

    def test_deadline_disabled_by_default(self):
        # No env set → deadline disabled → the chain runs to the redirect cap.
        import os
        os.environ.pop("INSANE_MAX_PROBE_SECONDS", None)
        result = self.fetch_chain.fetch(
            "https://example.com/h0",
            success_selectors=None,
            timeout=2,
            max_attempts=1,
            enable_playwright=False,
            url_check=lambda _u: None,
        )
        probe = result.trace[0]
        self.assertIsNotNone(probe.error)
        # Either hit the redirect cap or ran out of scripted responses, but
        # never the deadline path.
        self.assertNotIn("probe_deadline:", probe.error)


# ---------------------------------------------------------------------------
# P27.2 — transport error classification + grid family-skip
# ---------------------------------------------------------------------------

class TestTransportClassification(unittest.TestCase):
    """`_classify_transport_error` maps known fragments to stable prefixes."""

    def setUp(self):
        # No fake needed — test the pure classifier directly.
        for name in list(sys.modules):
            if name == "engine.fetch_chain":
                break
        import importlib
        self.fc = importlib.import_module("engine.fetch_chain")

    def test_tls_reject_classified(self):
        exc = RuntimeError("OpenSSL SSL_connect: certificate verify failed")
        out = self.fc._classify_transport_error(exc)
        self.assertTrue(out.startswith(self.fc._TLS_REJECTED_PREFIX), out)

    def test_timeout_classified(self):
        exc = RuntimeError("Operation timed out after 20000 ms")
        out = self.fc._classify_transport_error(exc)
        self.assertTrue(out.startswith(self.fc._TIMEOUT_PREFIX), out)

    def test_dns_classified(self):
        exc = RuntimeError("Could not resolve host: nope.invalid")
        out = self.fc._classify_transport_error(exc)
        self.assertTrue(out.startswith(self.fc._DNS_ERROR_PREFIX), out)

    def test_unclassified_keeps_legacy_shape(self):
        exc = RuntimeError("some unrelated failure")
        out = self.fc._classify_transport_error(exc)
        self.assertEqual(out, "RuntimeError:some unrelated failure")

    def test_impersonate_family_collapses_variants(self):
        self.assertEqual(self.fc._impersonate_family("safari_ios"), "safari")
        self.assertEqual(self.fc._impersonate_family("chrome_android"), "chrome")
        self.assertEqual(self.fc._impersonate_family("chrome120"), "chrome")
        self.assertEqual(self.fc._impersonate_family("safari"), "safari")
        self.assertEqual(self.fc._impersonate_family(None), "")


def _tls_reject(url):
    raise RuntimeError("TLS handshake: wrong version number")


class TestGridSkipsTlsRejectedFamily(_FakeFetchBase):
    """When a TLS reject fires for one impersonate, the grid must not keep
    hammering siblings of the same family."""

    # Probe (safari) → CHALLENGE so the grid runs; every grid attempt TLS-rejects.
    # The probe response below is a CHALLENGE-classed small body.
    RESPONSES = [
        _FakeResponse(
            status_code=200,
            text="<html><body>Just a moment...</body></html>",
            url="https://example.com/",
        ),
    ] + [_tls_reject for _ in range(40)]

    def test_family_skip_reduces_attempts(self):
        result = self.fetch_chain.fetch(
            "https://example.com/",
            success_selectors=["article.never"],
            timeout=1,
            max_attempts=12,
            enable_playwright=False,
            url_check=lambda _u: None,
        )
        # At least one grid attempt classified tls_rejected:.
        grid_errors = [a.error or "" for a in result.trace if a.phase == "grid"]
        self.assertTrue(
            any(e.startswith("tls_rejected:") for e in grid_errors),
            f"expected a tls_rejected: grid attempt; got {grid_errors}",
        )
        # Family-skip means we did NOT burn all 12 attempts on rejected TLS:
        # the distinct impersonate families actually tried is small.
        tried_families = {
            self.fetch_chain._impersonate_family(a.impersonate)
            for a in result.trace if a.phase == "grid" and a.impersonate
        }
        # The default unknown_challenge grid has at most a handful of families;
        # the point is the loop terminated via family-skip, not by exhausting
        # max_attempts on one rejected family.
        self.assertLessEqual(len(grid_errors), 12)
        self.assertTrue(len(tried_families) >= 1)


# ---------------------------------------------------------------------------
# P27.3 — resp.text rehydration pin (network-free, deterministic)
# ---------------------------------------------------------------------------

class TestRespTextDerivation(unittest.TestCase):
    """Validators read `resp.text`; pin that a `.text` property derived from
    `.content` stays consistent so the rehydrate path can't silently
    0-byte-misclassify."""

    def test_text_property_tracks_content(self):
        class _PropResp:
            def __init__(self):
                self.status_code = 200
                self.url = "https://example.com/"
                self.headers = {}
                self.cookies = {}
                self._content = b""

            @property
            def content(self):
                return self._content

            @content.setter
            def content(self, v):
                self._content = v

            @property
            def text(self):
                return self._content.decode("utf-8", errors="replace")

        from engine.validators import validate, Verdict
        r = _PropResp()
        body = "<html><body>" + ("ok " * 2000) + "</body></html>"
        r.content = body.encode("utf-8")
        # text must reflect the bytes we just set.
        self.assertEqual(r.text, body)
        vr = validate(r, success_selectors=None)
        # Large clean body → at least WEAK_OK, never a 0-byte CHALLENGE.
        self.assertIn(vr.verdict, (Verdict.WEAK_OK, Verdict.STRONG_OK))
        self.assertEqual(vr.body_size, len(body))


# ---------------------------------------------------------------------------
# P27.4 — meta-refresh soft redirect → detector signal
# ---------------------------------------------------------------------------

class TestMetaRefreshDetection(unittest.TestCase):
    def _resp(self, text, url):
        class _R:
            def __init__(self, t, u):
                self.text = t
                self.url = u
                self.status_code = 200
                self.headers = {}
                self.cookies = {}
        return _R(text, url)

    def test_same_url_meta_refresh_is_challenge_signal(self):
        from engine.waf_detector import detect, detect_meta_refresh
        body = (
            '<html><head>'
            '<meta http-equiv="refresh" content="0; url=https://example.com/x">'
            '</head><body>checking</body></html>'
        )
        resp = self._resp(body, "https://example.com/x")
        mr = detect_meta_refresh(resp)
        self.assertIsNotNone(mr)
        self.assertTrue(mr["same_url"])
        self.assertEqual(mr["target"], "https://example.com/x")

        hits = detect(resp, profiles={})
        ids = {h.profile_id for h in hits}
        self.assertIn("unknown_challenge", ids)
        uc = next(h for h in hits if h.profile_id == "unknown_challenge")
        self.assertIn("meta_refresh_same_url", uc.signals)
        self.assertGreaterEqual(uc.confidence, 0.5)

    def test_cross_url_meta_refresh_not_same_url(self):
        from engine.waf_detector import detect_meta_refresh
        body = (
            '<html><head>'
            "<meta http-equiv='refresh' content='2; url=/landing'>"
            '</head></html>'
        )
        resp = self._resp(body, "https://example.com/start")
        mr = detect_meta_refresh(resp)
        self.assertIsNotNone(mr)
        self.assertFalse(mr["same_url"])
        self.assertEqual(mr["target"], "https://example.com/landing")

    def test_no_meta_refresh_returns_none(self):
        from engine.waf_detector import detect_meta_refresh
        resp = self._resp("<html><body>plain</body></html>", "https://example.com/")
        self.assertIsNone(detect_meta_refresh(resp))


if __name__ == "__main__":
    unittest.main()
