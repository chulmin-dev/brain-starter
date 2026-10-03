"""Patch queue #7 — opt-in fan-out for `unknown_challenge` profile.

UPSTREAM.md: when the WAF detector cannot place the response into a
recognised profile (probe fails outright, or hits are too weak), the
fetch chain falls back to `unknown_challenge`, whose default grid is
intentionally small (5 tls × 2 referers × 1 transform = 10 attempts).
Operators who know a host is borderline can opt into a wider grid via:

  - env: `INSANE_PROBE_FAIL_EXPAND=1` (also "true", "yes", "on")
  - user_hint: `{"expand_unknown_challenge": True}`

When active, the helper widens *only* the `unknown_challenge` profile —
recognised WAF profiles are not touched (they already carry tuned
grids). The expansion adds the three `mobile_subdomain` / `am_prefix` /
`drop_www` transforms (the URL-shape axis is the most likely
discriminator for an un-fingerprinted challenge) and a no-referer
attempt. Tls candidates are left alone (already five).

These tests are pure-Python unit tests against the helpers — no
network, no `_run_attempt` mocking. The end-to-end "actually widens the
grid in fetch()" coverage is implicit via the helpers being the only
gate.
"""
from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))


class ExpandActivationTest(unittest.TestCase):
    """`_expand_unknown_challenge_active` truth table."""

    def setUp(self) -> None:
        # Pin env state across all tests in this class.
        self._saved = os.environ.get("INSANE_PROBE_FAIL_EXPAND")
        os.environ.pop("INSANE_PROBE_FAIL_EXPAND", None)
        self.addCleanup(self._restore_env)

        from engine import fetch_chain as fc
        self.fc = fc

    def _restore_env(self) -> None:
        if self._saved is None:
            os.environ.pop("INSANE_PROBE_FAIL_EXPAND", None)
        else:
            os.environ["INSANE_PROBE_FAIL_EXPAND"] = self._saved

    def test_no_flag_returns_false(self) -> None:
        self.assertFalse(self.fc._expand_unknown_challenge_active({}))

    def test_user_hint_true_returns_true(self) -> None:
        self.assertTrue(
            self.fc._expand_unknown_challenge_active(
                {"expand_unknown_challenge": True},
            )
        )

    def test_user_hint_false_returns_false(self) -> None:
        self.assertFalse(
            self.fc._expand_unknown_challenge_active(
                {"expand_unknown_challenge": False},
            )
        )

    def test_env_truthy_values_activate(self) -> None:
        for v in ("1", "true", "TRUE", "Yes", "on", "  on  "):
            os.environ["INSANE_PROBE_FAIL_EXPAND"] = v
            self.assertTrue(
                self.fc._expand_unknown_challenge_active({}),
                f"env value {v!r} should activate",
            )

    def test_env_falsy_values_do_not_activate(self) -> None:
        for v in ("", "0", "false", "no", "off", "maybe"):
            os.environ["INSANE_PROBE_FAIL_EXPAND"] = v
            self.assertFalse(
                self.fc._expand_unknown_challenge_active({}),
                f"env value {v!r} should not activate",
            )

    def test_user_hint_wins_when_env_unset(self) -> None:
        os.environ.pop("INSANE_PROBE_FAIL_EXPAND", None)
        self.assertTrue(
            self.fc._expand_unknown_challenge_active(
                {"expand_unknown_challenge": True},
            )
        )


class ExpandProfileTest(unittest.TestCase):
    """`_expand_unknown_challenge_grid` rewrites only the axes we want."""

    def setUp(self) -> None:
        from engine import fetch_chain as fc
        self.fc = fc

    def test_extra_transforms_appended(self) -> None:
        profile = {
            "url_transform_order": ["original"],
            "referer_strategies": ["self_root"],
            "tls_impersonate_candidates": [["safari"]],
        }
        out = self.fc._expand_unknown_challenge_grid(profile)
        self.assertEqual(
            out["url_transform_order"],
            ["original", "drop_www", "am_prefix", "mobile_subdomain"],
        )

    def test_extra_referer_appended(self) -> None:
        profile = {
            "url_transform_order": ["original"],
            "referer_strategies": ["self_root", "google_search"],
        }
        out = self.fc._expand_unknown_challenge_grid(profile)
        self.assertEqual(
            out["referer_strategies"],
            ["self_root", "google_search", "none"],
        )

    def test_extras_already_present_are_not_duplicated(self) -> None:
        profile = {
            "url_transform_order": ["original", "mobile_subdomain"],
            "referer_strategies": ["self_root", "none"],
        }
        out = self.fc._expand_unknown_challenge_grid(profile)
        # `mobile_subdomain` stays once, `drop_www` + `am_prefix` get
        # appended after it. `none` already present, not duplicated.
        self.assertEqual(
            out["url_transform_order"],
            ["original", "mobile_subdomain", "drop_www", "am_prefix"],
        )
        self.assertEqual(
            out["referer_strategies"],
            ["self_root", "none"],
        )

    def test_tls_candidates_unchanged(self) -> None:
        """Tls axis is intentionally left alone — already 5 candidates.

        Also pins that `tls_impersonate_avoid` (the deny axis some
        profiles use to filter `tls_impersonate_candidates`) is passed
        through unchanged. If a future maintainer ever adds avoid
        entries to `unknown_challenge`, this assertion catches a silent
        bypass.
        """
        profile = {
            "url_transform_order": ["original"],
            "referer_strategies": ["self_root"],
            "tls_impersonate_candidates": [["safari", "chrome"]],
            "tls_impersonate_avoid": ["firefox"],
        }
        out = self.fc._expand_unknown_challenge_grid(profile)
        self.assertEqual(
            out["tls_impersonate_candidates"],
            [["safari", "chrome"]],
        )
        self.assertEqual(out.get("tls_impersonate_avoid"), ["firefox"])

    def test_returns_a_copy_not_in_place_mutation(self) -> None:
        profile = {
            "url_transform_order": ["original"],
            "referer_strategies": ["self_root"],
        }
        out = self.fc._expand_unknown_challenge_grid(profile)
        # Original must not be mutated — recognised profiles are loaded
        # from a shared YAML cache; an in-place mutation would silently
        # widen them too on the next fetch.
        self.assertEqual(profile["url_transform_order"], ["original"])
        self.assertEqual(profile["referer_strategies"], ["self_root"])
        self.assertIsNot(out, profile)

    def test_missing_axis_keys_get_sane_defaults(self) -> None:
        """`load_profile` may omit `url_transform_order` for profiles
        that rely on the engine default — the expander must still
        produce a usable result."""
        out = self.fc._expand_unknown_challenge_grid({})
        self.assertIn("original", out["url_transform_order"])
        for t in ("drop_www", "am_prefix", "mobile_subdomain"):
            self.assertIn(t, out["url_transform_order"])
        self.assertEqual(out["referer_strategies"], ["none"])


class ExpandIsLimitedToUnknownChallengeTest(unittest.TestCase):
    """The fetch loop applies `_expand_unknown_challenge_grid` ONLY when
    `profile_id == "unknown_challenge"`. Use grep-style inspection on
    the source so this contract is pinned at the only call site without
    needing to run the full fetch loop end-to-end."""

    def test_call_site_is_guarded_on_profile_id(self) -> None:
        src = (Path(__file__).resolve().parent.parent.parent
               / "engine" / "fetch_chain.py").read_text()
        # The guard appears literally: profile_id == "unknown_challenge"
        # AND _expand_unknown_challenge_active(user_hint).
        contract_msg = (
            "Patch #7 contract: the unknown_challenge expansion must be "
            "gated on BOTH profile_id == 'unknown_challenge' AND "
            "_expand_unknown_challenge_active(user_hint). If you refactored "
            "the literal into a constant or split the guard across lines, "
            "update this grep test to match."
        )
        self.assertIn(
            'profile_id == "unknown_challenge"', src, msg=contract_msg,
        )
        self.assertIn(
            "_expand_unknown_challenge_active(user_hint)", src,
            msg=contract_msg,
        )
        # And the only invocation of the expander is gated by both.
        gate_idx = src.find('profile_id == "unknown_challenge"')
        call_idx = src.find("_expand_unknown_challenge_grid(profile)")
        self.assertGreater(
            call_idx, gate_idx,
            msg=(
                "Expander call must follow its profile_id guard, not "
                "appear unconditionally elsewhere. " + contract_msg
            ),
        )


class ExpandedGridBudgetFloorTest(unittest.TestCase):
    """The HIGH-severity follow-up from the code-reviewer: when the
    expansion flag is active but `max_attempts` is left at its default
    (12), the grid loop would cap before any of the new transforms /
    no-referer combos got tried. The patch auto-bumps the floor to
    `_EXPANDED_GRID_MAX_ATTEMPTS_FLOOR` so opt-in callers see the
    expansion *do something*. Pin that floor with an end-to-end test.
    """

    def setUp(self) -> None:
        # Save/restore the env so a parallel test that sets it doesn't
        # bleed into this one.
        self._saved_env = os.environ.get("INSANE_PROBE_FAIL_EXPAND")
        os.environ.pop("INSANE_PROBE_FAIL_EXPAND", None)
        self.addCleanup(self._restore_env)

        from plus.tests._engine_fake_helper import (
            install_fake_curl_cffi_isolation,
        )
        install_fake_curl_cffi_isolation(self)

        import types
        fake_requests = types.ModuleType("curl_cffi.requests")

        class _S:
            cookies: dict = {}

            def get(self, *_a, **_k):  # pragma: no cover
                raise AssertionError("Session.get should not be reached")

            def close(self):
                return None

        fake_requests.Session = _S  # type: ignore[attr-defined]
        fake_requests.get = lambda *_a, **_k: None  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("curl_cffi")
        fake_pkg.requests = fake_requests  # type: ignore[attr-defined]
        sys.modules["curl_cffi"] = fake_pkg
        sys.modules["curl_cffi.requests"] = fake_requests

        if "engine.fetch_chain" in sys.modules:
            del sys.modules["engine.fetch_chain"]
        import engine.fetch_chain as fc  # noqa: WPS433
        self.fc = fc

        # No real sleep — keeps the test under a second.
        orig_sleep = self.fc.time.sleep
        self.fc.time.sleep = lambda _s: None
        self.addCleanup(
            lambda: setattr(self.fc.time, "sleep", orig_sleep)
        )

    def _restore_env(self) -> None:
        if self._saved_env is None:
            os.environ.pop("INSANE_PROBE_FAIL_EXPAND", None)
        else:
            os.environ["INSANE_PROBE_FAIL_EXPAND"] = self._saved_env

    def _patch_fixed_profile(self) -> None:
        """Force `detect()` to return `unknown_challenge` so the
        expansion path is the relevant one. `load_profile` returns the
        same shape as the YAML defines for `unknown_challenge`."""
        single_hit = type("H", (), {
            "profile_id": "unknown_challenge",
            "confidence": 0.5,
            "signals": [],
        })()

        def _fake_detect(_resp, *, profiles=None):
            return [single_hit]

        def _fake_load_profile(_pid, *, profiles=None):
            # Five tls candidates to mirror the real `unknown_challenge`
            # YAML — keeps the combo space large enough that a) the 12
            # default caps below the available combo count and b) the
            # floor (40) is also below it, so the two thresholds are
            # distinguishable in the caller-honoured test below.
            return {
                "tls_impersonate_candidates": [
                    ["safari", "chrome", "firefox",
                     "safari_ios", "chrome_android"],
                ],
                "referer_strategies": ["self_root", "google_search"],
            }

        orig_detect = self.fc.detect
        orig_load = self.fc.load_profile
        self.fc.detect = _fake_detect
        self.fc.load_profile = _fake_load_profile
        self.addCleanup(lambda: setattr(self.fc, "detect", orig_detect))
        self.addCleanup(lambda: setattr(self.fc, "load_profile", orig_load))

    def _patch_run_attempt_always_challenge(self) -> list[dict]:
        """Make every attempt return CHALLENGE so the loop runs to its
        attempt budget. Returns the captures list for assertions."""
        from engine.fetch_chain import Attempt
        from engine.validators import Verdict

        captures: list[dict] = []

        def _fake(url, *, transform_name, impersonate, referer_name,
                  success_selectors, known_bad_sizes, timeout, phase,
                  session=None, url_check=None, ip_check=None):
            captures.append({
                "phase": phase,
                "transform": transform_name,
                "impersonate": impersonate,
                "referer": referer_name,
            })

            class _R:
                status_code = 403
                text = "<html>blocked</html>"
                url = "https://www.example.com/"
                headers: dict = {}
                cookies: dict = {}
                content = b"x"

            att = Attempt(
                phase=phase,
                executor="curl_cffi",
                url=url,
                url_transform=transform_name,
                impersonate=impersonate or "",
                referer=referer_name or "",
                verdict=Verdict.CHALLENGE.value,
            )
            return att, _R()

        orig = self.fc._run_attempt
        self.fc._run_attempt = _fake
        self.addCleanup(
            lambda: setattr(self.fc, "_run_attempt", orig)
        )
        return captures

    def test_default_max_attempts_is_honoured_when_flag_off(self) -> None:
        """Sanity: without the flag, default `max_attempts=12` still caps."""
        self._patch_fixed_profile()
        captures = self._patch_run_attempt_always_challenge()

        self.fc.fetch(
            "https://www.example.com/",
            enable_playwright=False,
        )

        # 12 = probe + 11 grid (the loop checks budget before each grid
        # attempt). Exact count tolerated ±1 for the dup-probe skip;
        # what matters is "ceiling 12 not raised".
        self.assertLessEqual(
            len(captures), 13,
            f"Default max_attempts=12 must not auto-bump when expansion "
            f"is OFF; got {len(captures)} attempts",
        )

    def test_flag_via_hint_raises_floor(self) -> None:
        self._patch_fixed_profile()
        captures = self._patch_run_attempt_always_challenge()

        self.fc.fetch(
            "https://www.example.com/",
            user_hint={"expand_unknown_challenge": True},
            enable_playwright=False,
        )

        # Default max_attempts=12 + active flag → floor 40. Loop should
        # produce many more attempts than the default cap.
        self.assertGreater(
            len(captures), 12,
            f"Expansion flag must raise max_attempts above the default "
            f"12; got {len(captures)} (no auto-bump?).",
        )
        self.assertLessEqual(
            len(captures), 41,
            f"Auto-bump should not exceed the floor by much; got "
            f"{len(captures)}",
        )

    def test_flag_via_env_raises_floor(self) -> None:
        os.environ["INSANE_PROBE_FAIL_EXPAND"] = "1"
        self._patch_fixed_profile()
        captures = self._patch_run_attempt_always_challenge()

        self.fc.fetch(
            "https://www.example.com/",
            enable_playwright=False,
        )

        self.assertGreater(
            len(captures), 12,
            f"Env flag must auto-bump; got {len(captures)}",
        )

    def test_caller_supplied_higher_max_attempts_is_honoured(self) -> None:
        """A caller asking for 80 attempts under expansion must not get
        clipped down to the floor — the floor only RAISES, never lowers."""
        self._patch_fixed_profile()
        captures = self._patch_run_attempt_always_challenge()

        self.fc.fetch(
            "https://www.example.com/",
            user_hint={"expand_unknown_challenge": True},
            max_attempts=80,
            enable_playwright=False,
        )

        # 4 transforms × 3 refs × 3 tls = 36 combos for the fake profile
        # (3 tls in the fake, not 5 as in the real YAML). Probe + 36
        # grid = 37, minus 1 dup-skip = 36. Caller-supplied 80 covers it.
        # What matters: count > floor's 40 ceiling, so we know the floor
        # didn't clamp.
        self.assertGreater(
            len(captures), 40,
            f"Caller-supplied max_attempts=80 must be honoured; got "
            f"{len(captures)} (floor accidentally clamped?)",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
