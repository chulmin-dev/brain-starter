"""Engine-local unit tests (patch queue #9 — `UPSTREAM.md`).

Until this file, the only engine-level tests were the manual-run
`test_smoke.py` set, several of which hit live sites. Post-patch
confidence depended on `engine/bias_check.py` plus the downstream
`plus/tests/` suite. The cost: an engine-side regression (e.g. someone
removing a parameter from `fetch_chain.fetch` or renaming a
capability key in `executor._pick_executor`) would only surface via
`plus.engine_proxy._check_signature` at *plus* import time. Useful, but
distant from the change.

This module pins engine contracts directly, no network, pytest-discoverable:

  - `executor._pick_executor` decision table (9 cases × device_class).
  - `fetch_chain.fetch` and `executor.run_playwright_fallback` keyword
    parameter surface (kept in sync with
    `plus.engine_proxy._EXPECTED_FETCH_PARAMS` /
    `_EXPECTED_FALLBACK_PARAMS`).
  - `fetch_chain._TERMINAL_VERDICTS` membership invariants
    (Phase 5 / patch #6).
  - `fetch_chain.Attempt.to_dict()` shape stability.

Anything that changes engine APIs should fail *here* first, then in
plus, in roughly that order.
"""
from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path

# Allow running directly via `python3 engine/tests/test_engine_unit.py`
# in addition to pytest discovery.
_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))


# ---------------------------------------------------------------------------
# executor._pick_executor — decision table
# ---------------------------------------------------------------------------

class PickExecutorDecisionTable(unittest.TestCase):
    """Pin the full capability × device_class matrix.

    Each row encodes one decision branch in `_pick_executor`. If the
    decision logic changes, this table fails first and tells the
    maintainer exactly which branch shifted.
    """

    def setUp(self) -> None:
        from engine.executor import _pick_executor  # noqa: WPS433
        self.pick = _pick_executor

    # ---- device_class="mobile" branch ----

    def test_mobile_with_real_tls_picks_playwright_mobile_chrome(self) -> None:
        self.assertEqual(
            self.pick(["needs_real_tls_stack", "needs_js_exec"], "mobile"),
            "playwright_mobile_chrome",
        )

    def test_mobile_without_real_tls_picks_playwright_mcp_mobile(self) -> None:
        self.assertEqual(
            self.pick(["needs_js_exec"], "mobile"),
            "playwright_mcp_mobile",
        )

    def test_mobile_with_empty_caps_picks_playwright_mcp_mobile(self) -> None:
        self.assertEqual(self.pick([], "mobile"), "playwright_mcp_mobile")

    # ---- needs_mobile_context capability overrides desktop device_class ----

    def test_mobile_context_cap_with_real_tls_overrides_desktop(self) -> None:
        self.assertEqual(
            self.pick(
                ["needs_mobile_context", "needs_real_tls_stack"], "desktop",
            ),
            "playwright_mobile_chrome",
        )

    def test_mobile_context_cap_without_real_tls_overrides_desktop(self) -> None:
        self.assertEqual(
            self.pick(["needs_mobile_context"], "desktop"),
            "playwright_mcp_mobile",
        )

    # ---- desktop branch ----

    def test_desktop_real_tls_plus_js_picks_real_chrome(self) -> None:
        self.assertEqual(
            self.pick(["needs_real_tls_stack", "needs_js_exec"], "desktop"),
            "playwright_real_chrome",
        )

    def test_desktop_js_exec_only_picks_playwright_mcp(self) -> None:
        self.assertEqual(
            self.pick(["needs_js_exec"], "desktop"),
            "playwright_mcp",
        )

    def test_desktop_real_tls_only_picks_real_chrome(self) -> None:
        self.assertEqual(
            self.pick(["needs_real_tls_stack"], "desktop"),
            "playwright_real_chrome",
        )

    def test_desktop_empty_caps_falls_back_to_real_chrome(self) -> None:
        # The code's stated "safest general fallback".
        self.assertEqual(self.pick([], "desktop"), "playwright_real_chrome")

    # ---- defensive null-input ----

    def test_none_caps_is_treated_as_empty(self) -> None:
        # `_pick_executor` does `set(capabilities or [])`; None must not raise.
        self.assertEqual(
            self.pick(None, "desktop"),  # type: ignore[arg-type]
            "playwright_real_chrome",
        )


# ---------------------------------------------------------------------------
# fetch_chain.fetch + executor.run_playwright_fallback — signature pinning
# ---------------------------------------------------------------------------

class EngineSignatureContracts(unittest.TestCase):
    """Mirror of `plus.engine_proxy._EXPECTED_*_PARAMS` at the engine layer.

    The plus-side check emits a RuntimeWarning if a parameter goes missing.
    These tests assert the same invariant at the engine layer so a
    regression fails *before* the plus side has a chance to import.

    When intentionally renaming/removing a parameter:
      1. update plus/engine_proxy.py `_EXPECTED_*_PARAMS`,
      2. update this test,
      3. update any caller (notably `plus/`).
    """

    @staticmethod
    def _new_required_params(sig: inspect.Signature, expected: set[str]) -> set[str]:
        """Return params present in `sig` but absent from `expected` AND
        with no default — i.e. would break callers that pass only `expected`.
        `*args`/`**kwargs` are skipped (they are forwarders, not requirements).
        """
        out: set[str] = set()
        for name, p in sig.parameters.items():
            if name in expected:
                continue
            if p.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ):
                continue
            if p.default is inspect.Parameter.empty:
                out.add(name)
        return out

    def test_fetch_chain_fetch_has_expected_kwargs(self) -> None:
        from engine.fetch_chain import fetch
        sig = inspect.signature(fetch)
        params = set(sig.parameters)
        expected = {
            "url",                 # positional
            "success_selectors",
            "device_class",
            "user_hint",
            "timeout",
            "max_attempts",
            "enable_playwright",
            "url_check",           # added by patch #2 (C1 redirect re-check)
            "ip_check",            # added by C8/P39r (connect-IP pin)
        }
        missing = expected - params
        self.assertEqual(
            missing, set(),
            f"engine.fetch_chain.fetch is missing expected parameters: "
            f"{sorted(missing)}",
        )
        # Symmetric check: a new REQUIRED param the wrapper doesn't forward
        # would silently break `plus._proxy_fetch(url, **kwargs)` callers.
        # Optional params with defaults are fine — engine can grow them freely.
        new_required = self._new_required_params(sig, expected)
        self.assertEqual(
            new_required, set(),
            f"engine.fetch_chain.fetch grew NEW REQUIRED parameter(s): "
            f"{sorted(new_required)}. Update _EXPECTED_FETCH_PARAMS in "
            f"plus/engine_proxy.py AND the `expected` set above; "
            f"plus._proxy_fetch needs to pass them through.",
        )

    def test_run_playwright_fallback_has_expected_kwargs(self) -> None:
        from engine.executor import run_playwright_fallback
        sig = inspect.signature(run_playwright_fallback)
        params = set(sig.parameters)
        expected = {
            "url",
            "profile_id",
            "success_selectors",
            "device_class",
            "timeout",
            "profile_dir",
            "force_executor",
            "cookies",          # added by P21 (curl→Chrome clearance handoff)
            "capture_json",     # added by P32 (opt-in CDP NetworkJournal envelope)
        }
        missing = expected - params
        self.assertEqual(
            missing, set(),
            f"engine.executor.run_playwright_fallback is missing "
            f"parameters: {sorted(missing)}",
        )
        new_required = self._new_required_params(sig, expected)
        self.assertEqual(
            new_required, set(),
            f"engine.executor.run_playwright_fallback grew NEW REQUIRED "
            f"parameter(s): {sorted(new_required)}. Update "
            f"_EXPECTED_FALLBACK_PARAMS in plus/engine_proxy.py AND the "
            f"`expected` set above.",
        )

    def test_fetch_url_check_is_optional(self) -> None:
        """`url_check` is the plus-side SSRF injection seam. Callers that
        don't pass it (e.g. test_smoke.py online tests, third-party
        consumers) must not break. The default must remain `None`."""
        from engine.fetch_chain import fetch
        sig = inspect.signature(fetch)
        self.assertIsNone(sig.parameters["url_check"].default)


# ---------------------------------------------------------------------------
# fetch_chain._TERMINAL_VERDICTS — Phase 5 (patch #6) invariants
# ---------------------------------------------------------------------------

class TerminalVerdictsMembership(unittest.TestCase):
    """The grid loop, the probe, and the Playwright fallback all gate on
    this tuple. Membership drift would silently change which verdicts
    terminate `fetch()`."""

    def test_strong_ok_and_weak_ok_are_terminal(self) -> None:
        from engine.fetch_chain import _TERMINAL_VERDICTS
        from engine.validators import Verdict
        self.assertIn(Verdict.STRONG_OK.value, _TERMINAL_VERDICTS)
        self.assertIn(Verdict.WEAK_OK.value, _TERMINAL_VERDICTS)

    def test_non_ok_verdicts_are_not_terminal(self) -> None:
        """Iterate the full `Verdict` enum so any future value (e.g. an
        eventual `RATE_LIMITED`) is auto-covered. Only STRONG_OK / WEAK_OK
        are allowed to be terminal."""
        from engine.fetch_chain import _TERMINAL_VERDICTS
        from engine.validators import Verdict
        allowed_terminal = {Verdict.STRONG_OK, Verdict.WEAK_OK}
        for v in Verdict:
            if v in allowed_terminal:
                continue
            self.assertNotIn(
                v.value, _TERMINAL_VERDICTS,
                f"{v.name} must NOT terminate the fetch loop",
            )


# ---------------------------------------------------------------------------
# fetch_chain.Attempt — to_dict shape (consumed by trace inspection)
# ---------------------------------------------------------------------------

class AttemptToDictShape(unittest.TestCase):
    """Anything that consumes `result.trace` calls `att.to_dict()`. Pin
    the field set so downstream consumers don't break silently."""

    def test_to_dict_has_required_keys(self) -> None:
        from engine.fetch_chain import Attempt
        att = Attempt(
            phase="probe",
            executor="curl_cffi",
            url="https://example.com/",
            url_transform="original",
            impersonate="safari",
            referer="self_root",
            verdict="strong_ok",
        )
        d = att.to_dict()
        for key in (
            "phase", "executor", "url", "url_transform",
            "impersonate", "referer", "verdict",
        ):
            self.assertIn(
                key, d,
                f"Attempt.to_dict() missing key {key!r}; "
                f"trace consumers may break",
            )


# ---------------------------------------------------------------------------
# url_transforms — PSL-aware `_am_prefix` (patch queue #10)
# ---------------------------------------------------------------------------

class UrlTransformsFallbackPSL(unittest.TestCase):
    # NOTE-BIAS-OK: the suffix names below are PSL data examples, not
    # site references.
    """`_am_prefix` must apply to apex hosts under multi-label public
    suffixes (e.g. ISO ccTLD second levels) without `publicsuffix2`
    installed. The old `host.count('.') >= 2` heuristic skipped them.

    This class exercises the stdlib fallback path — i.e. assumes
    `publicsuffix2` is NOT importable. Run as-is in the dev environment
    which has no such dependency.
    """

    def test_publicsuffix2_is_not_installed(self) -> None:
        """Sanity guard: if someone installs publicsuffix2 globally,
        these tests no longer exercise the fallback path — make that
        switch loud."""
        try:
            import publicsuffix2  # type: ignore[import-not-found]  # noqa: F401
        except ImportError:
            return
        self.skipTest(
            "publicsuffix2 is installed in this environment; the "
            "fallback path is not exercised. Move these assertions to a "
            "subprocess test or uninstall to validate the fallback."
        )

    def test_registrable_domain_single_label_tld(self) -> None:
        from engine.url_transforms import _registrable_domain
        self.assertEqual(_registrable_domain("example.com"), "example.com")
        self.assertEqual(_registrable_domain("www.example.com"), "example.com")
        self.assertEqual(_registrable_domain("a.b.example.com"), "example.com")

    def test_registrable_domain_multi_label_cctlds(self) -> None:
        from engine.url_transforms import _registrable_domain
        for host, expected in [
            ("example.co.kr", "example.co.kr"),
            ("www.example.co.kr", "example.co.kr"),
            ("a.example.co.kr", "example.co.kr"),
            ("example.co.uk", "example.co.uk"),
            ("example.com.au", "example.com.au"),
            ("example.ne.jp", "example.ne.jp"),  # NOTE-BIAS-OK: PSL test fixture — generic example under ccTLD second-level
            ("a.b.example.co.jp", "example.co.jp"),
        ]:
            self.assertEqual(_registrable_domain(host), expected, host)

    def test_registrable_domain_is_case_insensitive(self) -> None:
        from engine.url_transforms import _registrable_domain
        self.assertEqual(
            _registrable_domain("EXAMPLE.CO.KR"), "example.co.kr",
        )

    def test_registrable_domain_handles_bare_label(self) -> None:
        from engine.url_transforms import _registrable_domain
        # Single-label hostnames (e.g. `localhost` or a Docker service
        # name) cannot have a registrable domain; the function should
        # return what it was given (lowercased), not crash.
        self.assertEqual(_registrable_domain("just-a-host"), "just-a-host")
        self.assertEqual(_registrable_domain(""), "")

    def test_am_prefix_multi_label_apex_now_applies(self) -> None:
        """The actual regression #10 was about: pre-PSL, this returned
        None and a real transform candidate was silently lost."""
        from engine.url_transforms import _am_prefix
        for url, expected in [
            ("https://example.co.kr/path", "https://m.example.co.kr/path"),
            ("https://example.co.uk/", "https://m.example.co.uk/"),
            ("https://example.com.au/x?y=1", "https://m.example.com.au/x?y=1"),
            ("https://example.ne.jp/", "https://m.example.ne.jp/"),
        ]:
            self.assertEqual(_am_prefix(url), expected, url)

    def test_am_prefix_skips_deeper_subdomains_under_multi_label_tld(self) -> None:
        from engine.url_transforms import _am_prefix
        for url in [
            "https://a.example.co.kr/",
            "https://staging.example.co.uk/",
            "https://api.v2.example.com.au/",
        ]:
            self.assertIsNone(_am_prefix(url), url)

    def test_am_prefix_still_skips_www_and_m_prefixed(self) -> None:
        from engine.url_transforms import _am_prefix
        # `www.` → owned by `mobile_subdomain`; `m.` → already mobile.
        self.assertIsNone(_am_prefix("https://www.example.co.kr/"))
        self.assertIsNone(_am_prefix("https://m.example.co.kr/"))

    def test_am_prefix_single_label_apex_unchanged(self) -> None:
        """Pre-PSL behaviour on plain `.com` apex hosts must be
        preserved exactly."""
        from engine.url_transforms import _am_prefix
        self.assertEqual(
            _am_prefix("https://example.com/"),
            "https://m.example.com/",
        )
        self.assertIsNone(_am_prefix("https://a.example.com/"))

    def test_iter_transformed_emits_multi_label_apex_candidate(self) -> None:
        """End-to-end: a multi-label apex URL through `iter_transformed`
        with `original` + `am_prefix` must now yield BOTH entries."""
        from engine.url_transforms import iter_transformed
        out = iter_transformed(
            "https://example.co.kr/path", ["original", "am_prefix"],
        )
        names = [n for n, _ in out]
        urls = [u for _, u in out]
        self.assertIn("original", names)
        self.assertIn("am_prefix", names)
        self.assertIn("https://example.co.kr/path", urls)
        self.assertIn("https://m.example.co.kr/path", urls)


class UrlTransformsPSLPath(unittest.TestCase):
    """When `publicsuffix2` IS importable, `_registrable_domain` must
    prefer its `get_sld` result over the static fallback. The package is
    optional and not installed by default in this env; inject a fake via
    `sys.modules` so the PSL branch is still exercised.
    """

    def setUp(self) -> None:
        # If real publicsuffix2 happens to be installed, save it so we
        # can restore. We only care about the import seam, not the data.
        self._saved = sys.modules.get("publicsuffix2")

        self.calls: list[str] = []

        def _fake_get_sld(host: str) -> str:
            self.calls.append(host)
            # Make the fake return a sentinel that is NOT what the static
            # fallback would have returned, so the assertion proves the
            # PSL branch ran.
            return f"PSL::{host}"

        import types as _types
        fake_pkg = _types.ModuleType("publicsuffix2")
        fake_pkg.get_sld = _fake_get_sld  # type: ignore[attr-defined]
        sys.modules["publicsuffix2"] = fake_pkg

        def _restore():
            if self._saved is not None:
                sys.modules["publicsuffix2"] = self._saved
            else:
                sys.modules.pop("publicsuffix2", None)

        self.addCleanup(_restore)

    def test_psl_branch_is_used_when_publicsuffix2_importable(self) -> None:
        from engine.url_transforms import _registrable_domain
        result = _registrable_domain("www.example.co.kr")
        self.assertEqual(result, "PSL::www.example.co.kr")
        self.assertEqual(self.calls, ["www.example.co.kr"])

    def test_psl_exception_falls_back_to_static(self) -> None:
        """If `get_sld` raises (publicsuffix2 throws on some malformed
        hosts), the helper must not propagate — it falls back to the
        static path so the grid keeps spinning."""
        called: list[str] = []

        def _raising_get_sld(host: str) -> str:
            called.append(host)
            raise ValueError("malformed host")

        sys.modules["publicsuffix2"].get_sld = _raising_get_sld  # type: ignore[attr-defined]

        from engine.url_transforms import _registrable_domain
        result = _registrable_domain("example.co.kr")  # NOTE-BIAS-OK
        # Static fallback would resolve to the same registrable domain.
        self.assertEqual(result, "example.co.kr")  # NOTE-BIAS-OK
        # Confirm the PSL branch actually ran (would not, if the import
        # were lifted to module scope and cached `None`).
        self.assertEqual(called, ["example.co.kr"])  # NOTE-BIAS-OK

    def test_psl_returns_falsy_falls_back_to_static(self) -> None:
        """publicsuffix2 returns None/'' for some inputs; helper must
        still produce a usable registrable domain."""
        called: list[str] = []

        def _falsy_get_sld(host: str):
            called.append(host)
            return None

        sys.modules["publicsuffix2"].get_sld = _falsy_get_sld  # type: ignore[attr-defined]

        from engine.url_transforms import _registrable_domain
        self.assertEqual(_registrable_domain("example.com"), "example.com")
        self.assertEqual(called, ["example.com"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
