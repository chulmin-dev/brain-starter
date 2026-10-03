"""Patch queue #4 — grid axis order (transform-fast round-robin).

UPSTREAM.md: when the URL transform is the host's actual discriminator
(e.g. `mobile_subdomain` for a mobile-first SSR site), the previous nested
loop `for t in transforms: for tls: for ref:` burned an entire
`tls × referer` sweep (~6 × 3 = 18 attempts) on the original transform
before ever trying the mobile one. After the patch the loop order is
`for ref: for tls: for t:` so the transform axis swaps on every attempt.

Tests pin two invariants:

  1. The transform axis swaps faster than tls and ref across the first
     N attempts of the grid.
  2. A scripted "mobile_subdomain is the winner" scenario terminates in
     `len(transform_order)` grid attempts (one full transform sweep)
     rather than the previous N×slower path.
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

from plus.tests._engine_fake_helper import install_fake_curl_cffi_isolation


# ---------------------------------------------------------------------------
# Inert curl_cffi stub (Session() is built by fetch() but never queried;
# _run_attempt is mocked).
# ---------------------------------------------------------------------------

class _InertSession:
    cookies: dict = {}

    def get(self, *_args, **_kwargs):  # pragma: no cover
        raise AssertionError(
            "InertSession.get() must not be reached — _run_attempt is mocked"
        )

    def close(self):
        return None


def _install_inert_curl_cffi() -> None:
    fake_requests = types.ModuleType("curl_cffi.requests")
    fake_requests.Session = _InertSession  # type: ignore[attr-defined]
    fake_requests.get = lambda *_a, **_k: None  # type: ignore[attr-defined]
    fake_pkg = types.ModuleType("curl_cffi")
    fake_pkg.requests = fake_requests  # type: ignore[attr-defined]
    sys.modules["curl_cffi"] = fake_pkg
    sys.modules["curl_cffi.requests"] = fake_requests


def _reload_fetch_chain():
    if "engine.fetch_chain" in sys.modules:
        del sys.modules["engine.fetch_chain"]
    import engine.fetch_chain as fc  # noqa: WPS433
    return fc


# ---------------------------------------------------------------------------
# Scripted _run_attempt that records every call and yields verdicts in order
# ---------------------------------------------------------------------------

def _make_scripted_run_attempt(verdict_sequence, captures):
    """`captures` is a list the test reads after fetch() returns: each
    entry is a dict snapshot of the (transform_name, impersonate,
    referer_name, phase) tuple at call time.

    `verdict_sequence`: the verdict each attempt should resolve to, in
    order. Empty/short → remaining attempts default to UNKNOWN.
    """
    from engine.fetch_chain import Attempt
    from engine.validators import Verdict

    idx = {"i": 0}

    class _R:
        def __init__(self, url):
            self.status_code = 403
            self.text = "<html>blocked</html>"
            self.url = url
            self.headers: dict = {}
            self.cookies: dict = {}
            self.content = self.text.encode("utf-8")

    def _fake(url, *, transform_name, impersonate, referer_name,
              success_selectors, known_bad_sizes, timeout, phase,
              session=None, url_check=None, ip_check=None):
        i = idx["i"]
        idx["i"] += 1
        captures.append({
            "phase": phase,
            "transform": transform_name,
            "impersonate": impersonate,
            "referer": referer_name,
        })
        verdict = (
            verdict_sequence[i] if i < len(verdict_sequence)
            else Verdict.UNKNOWN.value
        )
        att = Attempt(
            phase=phase,
            executor="curl_cffi",
            url=url,
            url_transform=transform_name,
            impersonate=impersonate or "",
            referer=referer_name or "",
            verdict=verdict,
        )
        return att, _R(url)

    return _fake


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class GridAxisOrderTest(unittest.TestCase):
    """The transform axis must swap fastest. Referer is outermost."""

    def setUp(self) -> None:
        install_fake_curl_cffi_isolation(self)
        _install_inert_curl_cffi()
        self.fc = _reload_fetch_chain()

        # No real sleep — keeps the test under a second.
        orig_sleep = self.fc.time.sleep
        self.fc.time.sleep = lambda _s: None
        self.addCleanup(lambda: setattr(self.fc.time, "sleep", orig_sleep))

        self.captures: list[dict] = []

    def _patch_run_attempt(self, verdicts):
        fake = _make_scripted_run_attempt(verdicts, self.captures)
        orig = self.fc._run_attempt
        self.fc._run_attempt = fake
        self.addCleanup(lambda: setattr(self.fc, "_run_attempt", orig))

    def _patch_profile(self, transform_order, tls_candidates, referer_strategies):
        """Force a known profile shape so the test owns the grid dimensions.

        `load_profile` is the engine's per-profile data accessor. We
        return a dict mirroring the real schema with only the fields the
        grid loop reads.
        """
        forced_profile = {
            "tls_impersonate_candidates": [tls_candidates],
            "referer_strategies": list(referer_strategies),
            "url_transform_order": list(transform_order),
        }

        def _fake_load_profile(_pid, *, profiles=None):
            return forced_profile

        # Also make `detect` return a single hit so phase 2 enters with a
        # known profile_id, avoiding the deeper detection path.
        single_hit = type("H", (), {
            "profile_id": "test_profile",
            "confidence": 0.9,
            "signals": [],
        })()

        def _fake_detect(_resp, *, profiles=None):
            return [single_hit]

        orig_load = self.fc.load_profile
        orig_detect = self.fc.detect
        self.fc.load_profile = _fake_load_profile
        self.fc.detect = _fake_detect
        self.addCleanup(lambda: setattr(self.fc, "load_profile", orig_load))
        self.addCleanup(lambda: setattr(self.fc, "detect", orig_detect))

    def test_transform_axis_swaps_fastest(self) -> None:
        """Across the first |T| grid attempts, every transform appears
        exactly once and tls/ref are constant. Across the next |T|
        attempts, the same — with tls swapped to the next value."""
        from engine.validators import Verdict

        transforms = ["original", "mobile_subdomain", "drop_www"]
        tls = ["safari", "chrome"]
        refs = ["self_root", "google_root"]
        self._patch_profile(transforms, tls, refs)

        # All attempts CHALLENGE → loop runs to max_attempts.
        # Make max_attempts large enough to cover one full ref×tls cycle.
        self._patch_run_attempt(
            [Verdict.CHALLENGE.value] * 30,
        )

        # `impersonate_first` is set to a value NOT in `tls` so the
        # dup-probe-skip combo (`original`, base_impersonate,
        # `self_root`) never collides with any grid row. Otherwise the
        # second tls sweep would drop one row and the "tls constant
        # within a sweep" invariant gets blurred by that single skip.
        result = self.fc.fetch(
            "https://www.example.com/",
            user_hint={"impersonate_first": "edge_not_in_grid"},
            max_attempts=24,
            enable_playwright=False,
        )
        self.assertFalse(result.ok, result.summary)

        # captures[0] is the probe (phase="probe"). The grid starts at [1:].
        grid = [c for c in self.captures if c["phase"] == "grid"]
        self.assertGreaterEqual(
            len(grid), 6,
            f"Need ≥ 2 full transform sweeps to validate the axis order; "
            f"got {len(grid)}: {grid}",
        )

        # First three grid attempts: same (tls, ref), three distinct
        # transforms in `transforms` order.
        first_three_transforms = [g["transform"] for g in grid[:3]]
        first_three_tls = {g["impersonate"] for g in grid[:3]}
        first_three_refs = {g["referer"] for g in grid[:3]}
        self.assertEqual(
            sorted(first_three_transforms), sorted(transforms),
            "First 3 grid attempts must enumerate every transform once.",
        )
        self.assertEqual(
            len(first_three_tls), 1,
            f"tls must be constant across the first transform sweep; "
            f"got {first_three_tls}",
        )
        self.assertEqual(
            len(first_three_refs), 1,
            f"ref must be constant across the first transform sweep; "
            f"got {first_three_refs}",
        )

        # Attempts 4-6: tls swapped, transforms cycle again (same set).
        next_three_transforms = [g["transform"] for g in grid[3:6]]
        next_three_tls = {g["impersonate"] for g in grid[3:6]}
        self.assertEqual(
            sorted(next_three_transforms), sorted(transforms),
            "Second transform sweep must cover the same set.",
        )
        self.assertEqual(
            len(next_three_tls), 1,
            "tls must be constant within each transform sweep.",
        )
        # We assert tls advances between sweeps but deliberately do NOT
        # pin which specific tls comes second — the engine is free to
        # rearrange `tls_flat` derivation later; what matters here is
        # that the axis is rotated, not its concrete order.
        self.assertNotEqual(
            next_three_tls, first_three_tls,
            "tls must advance after a complete transform sweep.",
        )

    def test_transform_winner_short_path_short_circuits_grid(self) -> None:
        """If `mobile_subdomain` is the winning transform, the patched
        loop tries it within the first |T| grid attempts and returns.
        With the OLD (transform-outer) order the engine would have
        burned a whole tls×ref sweep on `original` first."""
        from engine.validators import Verdict

        transforms = ["original", "mobile_subdomain", "drop_www"]
        tls = ["safari", "chrome", "firefox"]
        refs = ["self_root", "google_root", "site_referer"]
        self._patch_profile(transforms, tls, refs)

        # probe = CHALLENGE
        # grid[0] (original, safari, self_root) = CHALLENGE
        # grid[1] (mobile_subdomain, safari, self_root) = STRONG_OK
        self._patch_run_attempt([
            Verdict.CHALLENGE.value,
            Verdict.CHALLENGE.value,
            Verdict.STRONG_OK.value,
        ])

        result = self.fc.fetch(
            "https://www.example.com/",  # www.* so mobile_subdomain + drop_www both apply
            user_hint={"impersonate_first": "chrome"},
            max_attempts=24,
            enable_playwright=False,
        )

        self.assertTrue(result.ok, result.summary)
        self.assertEqual(result.verdict, Verdict.STRONG_OK.value)

        grid = [c for c in self.captures if c["phase"] == "grid"]
        # Must finish within the FIRST transform sweep (|T| = 3).
        self.assertLessEqual(
            len(grid), 3,
            f"Expected the loop to find mobile_subdomain within the first "
            f"transform sweep (≤ 3 grid attempts); got {len(grid)}: "
            f"{[g['transform'] for g in grid]}",
        )
        # The winning attempt must be on `mobile_subdomain`.
        winning = grid[-1]
        self.assertEqual(winning["transform"], "mobile_subdomain")

    def test_probe_dup_is_still_skipped(self) -> None:
        """The dup-probe skip in the grid still fires for the
        (`original`, base_impersonate, default_referer) combo, regardless
        of the new axis order."""
        from engine.validators import Verdict

        transforms = ["original", "mobile_subdomain"]
        tls = ["safari", "chrome"]
        refs = ["self_root", "google_root"]
        self._patch_profile(transforms, tls, refs)

        # All CHALLENGE so the grid runs to its natural end.
        self._patch_run_attempt([Verdict.CHALLENGE.value] * 20)

        # Use the default base_impersonate ("safari" — set by fetch() at
        # line 332) and default referer ("self_root") so the dup-probe
        # row in the grid is exactly (original, safari, self_root).
        self.fc.fetch(
            "https://example.com/",
            max_attempts=24,
            enable_playwright=False,
        )

        grid = [c for c in self.captures if c["phase"] == "grid"]
        dup_combo = {
            "transform": "original",
            "impersonate": "safari",
            "referer": "self_root",
        }
        for g in grid:
            self.assertFalse(
                (g["transform"] == dup_combo["transform"]
                 and g["impersonate"] == dup_combo["impersonate"]
                 and g["referer"] == dup_combo["referer"]),
                f"Probe-duplicate combo should be skipped in the grid; "
                f"found at attempt {grid.index(g) + 1}",
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
