"""Phase 1 guard tests for the plus value layer.

Covers:
- SSRF pre-flight (blocked IP literals, blocked DNS-resolved hosts, non-http schemes)
- SSRF post-redirect (final_url + trace URLs)
- Cloudflare fallback executor coercion
- Per-domain Playwright profileDir
- pip-install env-injection guard (PIP_INDEX_URL etc.)
- monkey-patch install / uninstall idempotency
- upstream signature-drift warning

All tests live in `plus/` and run against the live `engine/` (no network).
"""
from __future__ import annotations

import os
import sys
import unittest
import warnings
from pathlib import Path
from unittest import mock

# Ensure the skill root is on sys.path so `import plus` works when tests are
# invoked directly (e.g. `node .claude/skills/page-fetch/python-runtime.cjs -m unittest plus.tests.test_engine_proxy`).
_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

from plus import engine_proxy
from plus._security import (
    SSRFBlockedError,
    _per_domain_profile_dir,
    _post_redirect_check,
    _sanitize_for_log,
    _ssrf_guard,
    wrap_external_content,
)


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

class TestSSRFGuard(unittest.TestCase):
    """SSRF pre-flight refuses unsafe URLs before they leave the host."""

    def test_loopback_ipv4_blocked(self):
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://127.0.0.1:6379/")
        self.assertIn("loopback", str(cm.exception))

    def test_loopback_ipv6_blocked(self):
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://[::1]/")
        self.assertIn("loopback", str(cm.exception))

    def test_link_local_blocked(self):
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://169.254.169.254/latest/meta-data/")
        self.assertIn("link-local", str(cm.exception))

    def test_private_blocked(self):
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://10.0.0.1/admin")
        self.assertIn("private", str(cm.exception))

    def test_file_scheme_blocked(self):
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("file:///etc/passwd")
        self.assertIn("scheme", str(cm.exception))

    def test_ftp_scheme_blocked(self):
        with self.assertRaises(SSRFBlockedError):
            _ssrf_guard("ftp://example.com/file")

    def test_missing_host_blocked(self):
        with self.assertRaises(SSRFBlockedError):
            _ssrf_guard("http:///path")

    def test_public_host_allowed(self):
        # Should not raise — this is the entire fork's job.
        # Stub getaddrinfo so the test is deterministic and offline.
        fake_infos = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with mock.patch("plus._ssrf.socket.getaddrinfo", return_value=fake_infos):
            _ssrf_guard("https://example.com/")

    def test_non_standard_ipv4_octal_blocked(self):
        # 0177.0.0.1 → libcurl interprets as 127.0.0.1 (loopback) but
        # ipaddress.ip_address rejects it. Pre-flight must still catch.
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://0177.0.0.1/")
        self.assertIn("non-standard IPv4", str(cm.exception))
        self.assertIn("loopback", str(cm.exception))

    def test_non_standard_ipv4_single_integer_blocked(self):
        # 2130706433 → 127.0.0.1
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://2130706433/")
        self.assertIn("loopback", str(cm.exception))

    def test_non_standard_ipv4_hex_blocked(self):
        # 0x7f.0.0.1 → 127.0.0.1
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://0x7f.0.0.1/")
        self.assertIn("loopback", str(cm.exception))

    def test_non_standard_ipv4_short_form_zero_blocked(self):
        # `0` → 0.0.0.0 (unspecified, libcurl maps to localhost-ish)
        with self.assertRaises(SSRFBlockedError):
            _ssrf_guard("http://0/")

    def test_dns_resolves_to_loopback_blocked(self):
        # Simulate a hostname whose DNS resolves to 127.0.0.1 (DNS rebinding
        # surface). We mock getaddrinfo to control the resolved IP.
        fake_infos = [(2, 1, 6, "", ("127.0.0.1", 80))]
        # `socket` lives in plus._ssrf since the D14 split (follow-up 2026-05-24).
        with mock.patch("plus._ssrf.socket.getaddrinfo", return_value=fake_infos):
            with self.assertRaises(SSRFBlockedError) as cm:
                _ssrf_guard("http://attacker.test/")
        self.assertIn("loopback", str(cm.exception))

    def test_disable_env_bypasses(self):
        with mock.patch.dict(os.environ, {"INSANE_DISABLE_SSRF_GUARD": "1"}):
            # Should NOT raise even on loopback.
            _ssrf_guard("http://127.0.0.1/")

    def test_disable_env_ignored_for_post_check(self):
        # Post-redirect check must refuse to be disabled.
        with mock.patch.dict(os.environ, {"INSANE_DISABLE_SSRF_GUARD": "1"}):
            with self.assertRaises(SSRFBlockedError):
                _post_redirect_check("http://127.0.0.1/")


# ---------------------------------------------------------------------------
# Per-domain Playwright profileDir
# ---------------------------------------------------------------------------

class TestProfileDir(unittest.TestCase):
    """Each domain gets its own profileDir under ~/.cache/insane-fetch/pw/."""

    def test_same_host_same_dir(self):
        a = _per_domain_profile_dir("https://example.com/foo")
        b = _per_domain_profile_dir("https://example.com/bar?q=1")
        self.assertEqual(a, b, "Same host must reuse profileDir")

    def test_different_hosts_different_dirs(self):
        a = _per_domain_profile_dir("https://a.example/")
        b = _per_domain_profile_dir("https://b.example/")
        self.assertNotEqual(a, b)

    def test_dir_exists_and_is_dir(self):
        p = Path(_per_domain_profile_dir("https://test-host.example/"))
        self.assertTrue(p.is_dir())

    def test_dir_is_under_user_cache(self):
        p = Path(_per_domain_profile_dir("https://test-host2.example/"))
        cache_root = Path.home() / ".cache" / "insane-fetch" / "pw"
        self.assertTrue(str(p).startswith(str(cache_root)))

    @unittest.skipIf(sys.platform == "win32", "POSIX permission modes do not apply on Windows")
    def test_dir_mode_is_private(self):
        p = Path(_per_domain_profile_dir("https://mode-test.example/"))
        # st_mode & 0o777 should be 0o700 — group/other have no access.
        mode = p.stat().st_mode & 0o777
        self.assertEqual(mode, 0o700, f"profileDir mode {oct(mode)} != 0o700")


# ---------------------------------------------------------------------------
# Monkey-patch install/uninstall
# ---------------------------------------------------------------------------

class TestMonkeyPatch(unittest.TestCase):
    """install() / uninstall() are idempotent and reversible."""

    def test_install_is_idempotent(self):
        engine_proxy.install()
        engine_proxy.install()  # second call must not raise / re-patch
        self.assertTrue(engine_proxy.is_installed())

    def test_uninstall_restores_original(self):
        engine_proxy.install()
        from engine import fetch_chain
        self.assertIs(fetch_chain.fetch, engine_proxy._proxy_fetch)
        engine_proxy.uninstall()
        self.assertIs(fetch_chain.fetch, engine_proxy._ORIGINAL_FETCH)
        self.assertFalse(engine_proxy.is_installed())
        # Restore for following tests.
        engine_proxy.install()

    def test_signature_drift_warns(self):
        # Inspect _check_signature against a stub missing expected params.
        def stub(a, b):
            pass

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            engine_proxy._check_signature(stub, {"a", "b", "c", "d"}, "stub")
        self.assertTrue(
            any("dropped expected parameters" in str(w.message) for w in caught),
            "Expected a RuntimeWarning about missing parameters",
        )


# ---------------------------------------------------------------------------
# pip-install env-injection guard
# ---------------------------------------------------------------------------

class TestPipInstallGuard(unittest.TestCase):
    """_ensure_dependencies refuses pip-install when index env vars are set."""

    def _force_missing(self):
        """Patch _IMPORT_TO_PIP so _ensure_dependencies sees something missing."""
        from plus import __main__ as plus_main
        return mock.patch.dict(
            plus_main._IMPORT_TO_PIP,
            {"_phase1_test_missing": "_phase1_test_pkg"},
        )

    def test_refuses_when_pip_index_url_set(self):
        from plus import __main__ as plus_main
        captured: list = []
        with self._force_missing(), \
             mock.patch.dict(os.environ, {"PIP_INDEX_URL": "http://evil.example/"}, clear=False), \
             mock.patch.object(plus_main.subprocess, "run") as fake_run, \
             mock.patch("sys.stderr") as fake_stderr:
            fake_stderr.write.side_effect = lambda s: captured.append(s)
            plus_main._ensure_dependencies()
        fake_run.assert_not_called()
        joined = "".join(captured)
        self.assertIn("refusing auto-install", joined)
        self.assertIn("PIP_INDEX_URL", joined)

    def test_ack_env_bypasses(self):
        from plus import __main__ as plus_main
        with self._force_missing(), \
             mock.patch.dict(os.environ, {
                 "PIP_INDEX_URL": "http://evil.example/",
                 "INSANE_AUTO_INSTALL_ACK": "1",
             }, clear=False), \
             mock.patch.object(plus_main.subprocess, "run") as fake_run:
            plus_main._ensure_dependencies()
        # subprocess.run *was* called — guard bypassed. But the index URL we
        # forwarded must still be pinned to PyPI (the second positional arg
        # array contains --index-url https://pypi.org/simple).
        self.assertTrue(fake_run.called)
        args = fake_run.call_args.args[0]
        self.assertIn("--index-url", args)
        idx = args.index("--index-url")
        self.assertEqual(args[idx + 1], "https://pypi.org/simple")

    def test_no_auto_install_env_blocks(self):
        from plus import __main__ as plus_main
        with self._force_missing(), \
             mock.patch.dict(os.environ, {"INSANE_NO_AUTO_INSTALL": "1"}, clear=False), \
             mock.patch.object(plus_main.subprocess, "run") as fake_run:
            plus_main._ensure_dependencies()
        fake_run.assert_not_called()


# ---------------------------------------------------------------------------
# Log sanitization + sentinel wrap
# ---------------------------------------------------------------------------

class TestLogSanitization(unittest.TestCase):

    def test_strip_newlines_and_control_chars(self):
        out = _sanitize_for_log("evil\nhost\x00here\rmore", max_len=256)
        self.assertNotIn("\n", out)
        self.assertNotIn("\r", out)
        self.assertNotIn("\x00", out)

    def test_length_cap(self):
        out = _sanitize_for_log("a" * 1000, max_len=64)
        self.assertLessEqual(len(out), 64)
        self.assertTrue(out.endswith("..."))

    def test_wrap_external_content_sentinel(self):
        wrapped = wrap_external_content("malicious body\n", url="https://example.com/foo")
        self.assertTrue(wrapped.startswith("[external_data:url=example.com]"))
        self.assertTrue(wrapped.rstrip().endswith("[/external_data]"))


# ---------------------------------------------------------------------------
# Phase 2 — DoH allowlist + proxy env + search cap + crawl budget
# ---------------------------------------------------------------------------

class TestDoHAllowlist(unittest.TestCase):
    """`INSANE_DOH_URL` outside allowlist falls back to default unless ack."""

    def test_default_endpoint_when_env_unset(self):
        from plus import doh
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INSANE_DOH_URL", None)
            self.assertEqual(doh.doh_url(), doh._DEFAULT_DOH_URL)

    def test_allowlisted_endpoint_accepted(self):
        from plus import doh
        with mock.patch.dict(os.environ, {"INSANE_DOH_URL": "https://8.8.8.8/dns-query"}, clear=False):
            self.assertEqual(doh.doh_url(), "https://8.8.8.8/dns-query")

    def test_non_allowlisted_falls_back(self):
        from plus import doh
        with mock.patch.dict(os.environ, {"INSANE_DOH_URL": "https://evil.example/dns-query"}, clear=False):
            os.environ.pop("INSANE_DOH_ACK", None)
            with mock.patch("sys.stderr"):
                self.assertEqual(doh.doh_url(), doh._DEFAULT_DOH_URL)

    def test_ack_bypasses_allowlist(self):
        from plus import doh
        with mock.patch.dict(os.environ, {
            "INSANE_DOH_URL": "https://corp-doh.internal/dns-query",
            "INSANE_DOH_ACK": "1",
        }, clear=False):
            with mock.patch("sys.stderr"):
                self.assertEqual(doh.doh_url(), "https://corp-doh.internal/dns-query")


class TestProxyEnvDetection(unittest.TestCase):
    """`_check_proxy_env` warns when proxy/CA vars are set; ack silences."""

    def test_no_env_no_warning(self):
        from plus._security import _check_proxy_env
        # Wipe every proxy env var first.
        wipe = {v: "" for v in (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "http_proxy", "https_proxy", "all_proxy",
            "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE",
            "SSL_CERT_DIR",
        )}
        with mock.patch.dict(os.environ, wipe, clear=False):
            for k in list(wipe):
                os.environ.pop(k, None)
            self.assertEqual(_check_proxy_env(), [])

    def test_http_proxy_set_warns(self):
        from plus._security import _check_proxy_env, _proxy_warning_state
        # D3 follow-up (2026-05-24): the warning is now once-per-process.
        # Reset the flag so this test observes a fresh warning regardless
        # of what earlier code paths may have emitted.
        _proxy_warning_state["emitted"] = False
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://evil.example:8080/"}, clear=False):
            os.environ.pop("INSANE_PROXY_ACK", None)
            with mock.patch("sys.stderr") as fake:
                buf: list[str] = []
                fake.write.side_effect = lambda s: buf.append(s)
                hits = _check_proxy_env()
            self.assertIn("HTTP_PROXY", hits)
            self.assertTrue(any("MITM" in s for s in buf))

    def test_ack_silences(self):
        from plus._security import _check_proxy_env
        with mock.patch.dict(os.environ, {
            "HTTPS_PROXY": "http://corp-proxy:8080/",
            "INSANE_PROXY_ACK": "1",
        }, clear=False):
            self.assertEqual(_check_proxy_env(), [])


class TestSearchEngineFetchCap(unittest.TestCase):
    """search._safe_fetch caps engine calls to keep within future timeout."""

    def test_safe_fetch_caps_attempts_and_timeout(self):
        from plus import search
        captured: dict = {}

        def fake_engine_fetch(url, *, timeout, max_attempts, **kwargs):
            captured["timeout"] = timeout
            captured["max_attempts"] = max_attempts

            class _R:
                ok = True
                verdict = "weak_ok"
                content = "<html/>"
            return _R()

        with mock.patch.object(search, "engine_fetch", side_effect=fake_engine_fetch):
            search._safe_fetch("https://example.com/", timeout=60)
        self.assertLessEqual(captured["timeout"], search._SEARCH_MAX_TIMEOUT_S)
        self.assertEqual(captured["max_attempts"], search._SEARCH_MAX_ATTEMPTS)


class TestCrawlBudget(unittest.TestCase):
    """sitemap discovery is bounded by INSANE_CRAWL_MAX_SECONDS + child cap."""

    def test_module_budget_constants(self):
        from plus import crawl
        self.assertGreater(crawl._MAX_CRAWL_SECONDS, 0)
        self.assertGreater(crawl._MAX_CHILD_SITEMAPS, 0)

    def test_int_env_helper(self):
        from plus.crawl import _int_env
        with mock.patch.dict(os.environ, {"BUDGET_TEST": "42"}, clear=False):
            self.assertEqual(_int_env("BUDGET_TEST", 99), 42)
        with mock.patch.dict(os.environ, {"BUDGET_TEST": "-5"}, clear=False):
            self.assertEqual(_int_env("BUDGET_TEST", 99), 99)
        with mock.patch.dict(os.environ, {"BUDGET_TEST": "not-an-int"}, clear=False):
            self.assertEqual(_int_env("BUDGET_TEST", 99), 99)


# ---------------------------------------------------------------------------
# Phase 3 — winners cache + cache guards + blocked-terms + outbound SSRF +
#           selector DoS guard
# ---------------------------------------------------------------------------

class TestWinnersCache(unittest.TestCase):
    """host-keyed winning combo memory: record then get_hint round-trip."""

    def setUp(self):
        from plus import winners
        self.winners = winners
        # Redirect storage to a temp file so production winners.json stays clean.
        import tempfile
        self._tmp = tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".json",
        )
        self._tmp.close()
        self._orig_path = winners._WINNERS_PATH
        winners._WINNERS_PATH = Path(self._tmp.name)

    def tearDown(self):
        self.winners._WINNERS_PATH = self._orig_path
        Path(self._tmp.name).unlink(missing_ok=True)

    def test_get_hint_returns_none_for_unknown_host(self):
        self.assertIsNone(self.winners.get_hint("https://nowhere.example/"))

    def test_record_then_get_round_trip(self):
        # Fake result.trace with a STRONG_OK curl_cffi attempt.
        from engine.fetch_chain import Attempt, FetchResult
        att = Attempt(
            phase="probe", executor="curl_cffi",
            url="https://round-trip.example/",
            url_transform="original", impersonate="safari",
            referer="self_root", verdict="strong_ok",
        )
        result = FetchResult(
            ok=True, content="<html/>", final_url=att.url,
            verdict="strong_ok", profile_used="cloudflare_turnstile",
            trace=[att],
        )
        self.winners.record(att.url, result)
        hint = self.winners.get_hint(att.url)
        self.assertEqual(hint, {
            "impersonate_first": "safari",
            "referer_strategy": "self_root",
        })

    def test_disable_env_silences(self):
        with mock.patch.dict(os.environ, {"INSANE_DISABLE_WINNERS": "1"}, clear=False):
            self.assertIsNone(self.winners.get_hint("https://example.com/"))

    def test_playwright_attempt_not_recorded(self):
        # Playwright fallback attempt has impersonate=None — nothing actionable.
        from engine.fetch_chain import Attempt, FetchResult
        att = Attempt(
            phase="fallback", executor="playwright_real_chrome",
            url="https://pw-only.example/",
            url_transform="original", impersonate=None,
            referer="", verdict="strong_ok",
        )
        result = FetchResult(
            ok=True, content="", final_url=att.url,
            verdict="strong_ok", profile_used="unknown_challenge",
            trace=[att],
        )
        self.winners.record(att.url, result)
        self.assertIsNone(self.winners.get_hint(att.url))


class TestCacheGuards(unittest.TestCase):
    """cache.put refuses weak_ok; key includes selectors; writes are atomic."""

    def setUp(self):
        import tempfile
        from plus import cache
        self.cache = cache
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache.CACHE_DIR
        cache.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        import shutil
        self.cache.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_weak_ok_not_stored(self):
        self.cache.put(
            "https://example.com/", "auto", "raw",
            "weak_ok", "body",
        )
        self.assertIsNone(self.cache.get("https://example.com/", "auto", "raw"))

    def test_strong_ok_stored(self):
        self.cache.put(
            "https://example.com/", "auto", "raw",
            "strong_ok", "body-content",
        )
        self.assertEqual(
            self.cache.get("https://example.com/", "auto", "raw"),
            "body-content",
        )

    def test_selectors_change_key(self):
        self.cache.put(
            "https://example.com/", "auto", "raw",
            "strong_ok", "with-selector-body",
            selectors=["article"],
        )
        # No-selector lookup is a different key — must miss.
        self.assertIsNone(self.cache.get("https://example.com/", "auto", "raw"))
        # Same selectors hit.
        self.assertEqual(
            self.cache.get("https://example.com/", "auto", "raw", selectors=["article"]),
            "with-selector-body",
        )

    def test_atomic_write_no_tmp_file_remains(self):
        self.cache.put(
            "https://example.com/", "auto", "raw",
            "strong_ok", "body",
        )
        leftover = list(Path(self._tmpdir).glob("*.tmp*"))
        self.assertEqual(leftover, [])


class TestBlockedTermsGuard(unittest.TestCase):
    """search() refuses blocked terms; non-blocked passes."""

    def setUp(self):
        # Direct the guard at a fixture file.
        import tempfile
        self._tmp = tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt",
        )
        self._tmp.write("forbidden\n# comment line\nspecial-case\n")
        self._tmp.close()
        os.environ["INSANE_BLOCKED_TERMS_FILE"] = self._tmp.name
        # Bust the mtime cache.
        from plus import _security
        _security._blocked_cache.update({"path": None, "mtime": 0.0, "terms": ()})

    def tearDown(self):
        os.environ.pop("INSANE_BLOCKED_TERMS_FILE", None)
        Path(self._tmp.name).unlink(missing_ok=True)

    def test_matched_term_blocked(self):
        from plus._security import _check_blocked_query
        self.assertEqual(_check_blocked_query("contains FORBIDDEN word"), "forbidden")

    def test_unblocked_passes(self):
        from plus._security import _check_blocked_query
        self.assertIsNone(_check_blocked_query("nothing to see here"))

    def test_search_raises_BlockedQueryError(self):
        from plus import search
        from plus._security import BlockedQueryError
        with self.assertRaises(BlockedQueryError):
            search.search("query about forbidden things", ["hn"], 1, 5)

    def test_disable_env_silences(self):
        from plus._security import _check_blocked_query, _blocked_cache
        with mock.patch.dict(os.environ, {"INSANE_DISABLE_BLOCKED_TERMS": "1"}, clear=False):
            _blocked_cache.update({"path": None, "mtime": 0.0, "terms": ()})
            self.assertIsNone(_check_blocked_query("contains forbidden"))


class TestOutboundSSRFGuard(unittest.TestCase):
    """search-result URLs must clear SSRF before being surfaced."""

    def test_public_url_safe(self):
        from plus.search import _outbound_url_safe
        fake_infos = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with mock.patch("plus._ssrf.socket.getaddrinfo", return_value=fake_infos):
            self.assertTrue(_outbound_url_safe("https://example.com/result"))

    def test_internal_ip_unsafe(self):
        from plus.search import _outbound_url_safe
        self.assertFalse(_outbound_url_safe("http://127.0.0.1/admin"))
        self.assertFalse(_outbound_url_safe("http://169.254.169.254/"))

    def test_octal_ip_unsafe(self):
        from plus.search import _outbound_url_safe
        # Non-standard IPv4 form — Phase 1 follow-up #1 catches this.
        self.assertFalse(_outbound_url_safe("http://0177.0.0.1/"))


class TestSelectorGuard(unittest.TestCase):
    """`--selector` argparse type rejects oversize / control-char selectors."""

    def test_normal_selector_passes(self):
        from plus.__main__ import _safe_selector
        self.assertEqual(_safe_selector("article"), "article")
        self.assertEqual(_safe_selector("div.content > p"), "div.content > p")

    def test_oversize_rejected(self):
        import argparse
        from plus.__main__ import _safe_selector, _MAX_SELECTOR_LEN
        long = "a" * (_MAX_SELECTOR_LEN + 1)
        with self.assertRaises(argparse.ArgumentTypeError):
            _safe_selector(long)

    def test_control_char_rejected(self):
        import argparse
        from plus.__main__ import _safe_selector
        with self.assertRaises(argparse.ArgumentTypeError):
            _safe_selector("article\x00bad")


# ---------------------------------------------------------------------------
# Code-reviewer follow-up fixes (2026-05-24): D3/D7/D15 contract pins.
# ---------------------------------------------------------------------------

class TestProxyEnvIdempotency(unittest.TestCase):
    """D3: `_check_proxy_env` emits the stderr warning at most once per process."""

    def test_warning_emitted_only_once(self):
        from plus._security import _check_proxy_env, _proxy_warning_state
        _proxy_warning_state["emitted"] = False
        with mock.patch.dict(
            os.environ, {"HTTP_PROXY": "http://evil.example:8080/"}, clear=False
        ):
            os.environ.pop("INSANE_PROXY_ACK", None)
            with mock.patch("sys.stderr") as fake:
                buf: list[str] = []
                fake.write.side_effect = lambda s: buf.append(s)
                _check_proxy_env()
                _check_proxy_env()
                _check_proxy_env()
        # Multiple calls but only one MITM line should have hit stderr.
        mitm_lines = [s for s in buf if "MITM" in s]
        self.assertEqual(len(mitm_lines), 1)


class TestBlockedQueryErrorClass(unittest.TestCase):
    """D7: `BlockedQueryError` no longer subclasses ValueError."""

    def test_not_a_value_error(self):
        from plus._security import BlockedQueryError
        # ValueError-catching code paths must NOT silently swallow a
        # security-policy refusal. SSRFBlockedError stays a ValueError
        # subclass for back-compat, but BlockedQueryError is a distinct
        # exception class — policy decisions need explicit handling.
        self.assertFalse(issubclass(BlockedQueryError, ValueError))
        # And it's still an Exception so generic `except Exception:` works.
        self.assertTrue(issubclass(BlockedQueryError, Exception))


class TestAtomicWriteHelper(unittest.TestCase):
    """D15: `atomic_write_text` is the single helper used by cache/winners."""

    def test_writes_and_replaces(self):
        import tempfile
        from plus._atomic import atomic_write_text
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "out.json"
            atomic_write_text(target, '{"a": 1}')
            self.assertEqual(target.read_text(encoding="utf-8"), '{"a": 1}')
            atomic_write_text(target, '{"a": 2}')
            self.assertEqual(target.read_text(encoding="utf-8"), '{"a": 2}')

    def test_no_tmp_left_behind_on_success(self):
        import tempfile
        from plus._atomic import atomic_write_text
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "out.json"
            atomic_write_text(target, "x")
            # No `out.json.tmp.*` artifact should remain.
            siblings = list(target.parent.glob("out.json.tmp.*"))
            self.assertEqual(siblings, [])


class TestExclusiveLock(unittest.TestCase):
    """D12 / #20: `exclusive_lock` serializes read-modify-write blocks."""

    def test_lock_creates_and_releases(self):
        import tempfile
        from plus._atomic import exclusive_lock
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "data.json"
            with exclusive_lock(target):
                # While held, the lock file exists on disk.
                self.assertTrue((target.parent / "data.json.lock").exists())
            # Released — the lock file remains (it is reused) but is unlocked.
            # A second acquisition must succeed without deadlock.
            with exclusive_lock(target):
                pass


# ---------------------------------------------------------------------------
# P2 (2026-06-11): CGNAT / non-global catch-all
# ---------------------------------------------------------------------------

class TestSSRFCGNAT(unittest.TestCase):
    """P2: 100.64.0.0/10 (CGNAT/Tailscale) must be blocked by _ssrf_guard."""

    def test_cgnat_tailscale_blocked(self):
        """100.64.0.1 — first address of CGNAT range — must be blocked."""
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://100.64.0.1/")
        self.assertIn("non-global", str(cm.exception))

    def test_cgnat_upper_range_blocked(self):
        """100.127.255.255 — last address of CGNAT range."""
        with self.assertRaises(SSRFBlockedError):
            _ssrf_guard("http://100.127.255.255/")

    def test_6to4_relay_blocked(self):
        """192.88.99.1 (6to4 anycast relay, RFC 7526 deprecated) must be blocked.
        This address is is_global=True so the non-global catch-all misses it;
        LOW-1 (2026-06-11) adds an explicit network check."""
        with self.assertRaises(SSRFBlockedError) as cm:
            _ssrf_guard("http://192.88.99.1/")
        self.assertIn("6to4-relay", str(cm.exception))

    def test_public_domain_still_allowed(self):
        """Public domain must pass — catch-all must not block global addresses."""
        # This calls the real guard; example.com resolves globally.
        # We stub getaddrinfo so the test is deterministic and offline.
        fake_infos = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with mock.patch("plus._ssrf.socket.getaddrinfo", return_value=fake_infos):
            _ssrf_guard("https://example.com/")  # must not raise


# ---------------------------------------------------------------------------
# P10 (2026-06-11): url_check composition + winners warning
# ---------------------------------------------------------------------------

class TestUrlCheckComposition(unittest.TestCase):
    """P10: caller url_check is composed with _ssrf_guard, not replaced."""

    def test_ssrf_guard_runs_even_with_caller_url_check(self):
        """SSRF guard fires even when caller passes a custom url_check."""
        from plus import engine_proxy as _ep
        from plus._security import SSRFBlockedError as _SB
        _ep.install()

        called_urls: list = []

        def _caller_check(u: str) -> None:
            called_urls.append(u)

        def _fake_fetch(url, **kwargs):
            # Simulate the engine calling url_check on a redirect to loopback.
            check = kwargs.get("url_check")
            if check:
                try:
                    check("http://127.0.0.1/")
                except _SB:
                    raise  # propagate so the test can verify
            return mock.MagicMock(ok=True, content="body", trace=[], final_url=url,
                                   verdict="weak_ok", profile_used=None, summary="")

        fake_infos = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with mock.patch("plus._ssrf.socket.getaddrinfo", return_value=fake_infos):
            with mock.patch.object(_ep, "_ORIGINAL_FETCH", side_effect=_fake_fetch):
                with self.assertRaises(SSRFBlockedError):
                    _ep._proxy_fetch("https://example.com/", url_check=_caller_check)

    def test_caller_check_is_also_invoked(self):
        """Caller's url_check still runs alongside _ssrf_guard."""
        from plus import engine_proxy as _ep
        _ep.install()

        caller_called: list = []

        def _caller_check(u: str) -> None:
            caller_called.append(u)

        def _fake_fetch(url, **kwargs):
            check = kwargs.get("url_check")
            if check:
                check("https://safe.example.com/")
            return mock.MagicMock(ok=True, content="body", trace=[], final_url=url,
                                   verdict="weak_ok", profile_used=None, summary="")

        fake_infos = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with mock.patch("plus._ssrf.socket.getaddrinfo", return_value=fake_infos):
            with mock.patch.object(_ep, "_ORIGINAL_FETCH", side_effect=_fake_fetch):
                _ep._proxy_fetch("https://example.com/", url_check=_caller_check)

        self.assertIn("https://safe.example.com/", caller_called)


class TestWinnersWarning(unittest.TestCase):
    """P10: winners failure emits stderr warning, once per process."""

    def setUp(self):
        from plus import engine_proxy as _ep
        # Reset the once-per-process flag before each test.
        _ep._winners_warned["emitted"] = False

    def test_winners_failure_prints_warning(self):
        from plus import engine_proxy as _ep
        _ep.install()

        def _boom_fetch(url, **kwargs):
            return mock.MagicMock(ok=True, content="body", trace=[], final_url=url,
                                   verdict="weak_ok", profile_used=None, summary="")

        import io
        buf = io.StringIO()
        fake_infos = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with mock.patch("plus._ssrf.socket.getaddrinfo", return_value=fake_infos):
            with mock.patch.object(_ep, "_ORIGINAL_FETCH", side_effect=_boom_fetch):
                with mock.patch("plus.engine_proxy.sys.stderr", buf):
                    # Simulate winners.get_hint raising
                    with mock.patch("plus.winners.get_hint", side_effect=OSError("disk full")):
                        _ep._proxy_fetch("https://example.com/")

        output = buf.getvalue()
        self.assertIn("[plus] warning", output)
        self.assertIn("winners cache unavailable", output)

    def test_winners_warning_emitted_only_once(self):
        """Second failure after first must not produce another line."""
        from plus import engine_proxy as _ep
        _ep.install()

        def _boom_fetch(url, **kwargs):
            return mock.MagicMock(ok=True, content="body", trace=[], final_url=url,
                                   verdict="weak_ok", profile_used=None, summary="")

        import io
        buf = io.StringIO()
        fake_infos = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with mock.patch("plus._ssrf.socket.getaddrinfo", return_value=fake_infos):
            with mock.patch.object(_ep, "_ORIGINAL_FETCH", side_effect=_boom_fetch):
                with mock.patch("plus.engine_proxy.sys.stderr", buf):
                    with mock.patch("plus.winners.get_hint", side_effect=OSError("disk full")):
                        _ep._proxy_fetch("https://a.example.com/")
                        _ep._proxy_fetch("https://b.example.com/")

        lines = [l for l in buf.getvalue().splitlines() if "[plus] warning" in l]
        self.assertEqual(len(lines), 1, "Warning must appear exactly once")


if __name__ == "__main__":
    unittest.main()
