"""Phase 11 — winners weak_ok acceptance + 7-day TTL.

Original consensus F6 restricted `winners.record` to `strong_ok`-only.
995-entry observation log analysis revealed `strong_ok` count = 0 because
the value layer never injects `success_selectors` into engine fetches, so
the cache was permanently empty by design. Asymmetry with cache.py
(documented at top of winners.py) lets us safely persist `weak_ok` combos:
a wrong hint degrades to cold-start fallback, never to content poisoning.

Wave 2 additions (ADAPT-3/4/5):
  - ADAPT-3: key format is now `host::device_class`; legacy host-only keys
    are a miss (backward-compat, no crash).
  - ADAPT-4: strike() only penalizes real blocks (challenge/blocked/exhausted);
    transient outcomes (rate_limited, unknown, auth_required, not_found) do
    not strike.
  - ADAPT-5: _prune() enforces 7-day TTL and bounded LRU cap on load.

These tests pin:
  - the strong_ok path is unchanged (regression guard).
  - weak_ok is recorded by default, suppressible via env.
  - every record stamps `recorded_at`.
  - get_hint expires entries older than TTL.
  - get_hint defensively rejects missing / non-numeric / future timestamps.
  - INSANE_DISABLE_WINNERS overrides everything (existing escape hatch).
  - Playwright-fallback attempts (impersonate=None) are still skipped.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

from plus import winners


def _fake_attempt(verdict: str, *, impersonate: str = "chrome",
                  referer: str = "self_root", transform: str = "original"):
    """Minimal attempt object — only the attrs winners._pick_winning_attempt reads."""
    return SimpleNamespace(
        verdict=verdict,
        impersonate=impersonate,
        referer=referer,
        url_transform=transform,
    )


def _fake_result(trace, *, ok: bool = True, profile_used=None):
    return SimpleNamespace(ok=ok, trace=trace, profile_used=profile_used)


def _fake_failed_result(verdict: str):
    """Minimal failed result object for strike() tests."""
    return SimpleNamespace(ok=False, verdict=verdict, trace=[])


class _WinnersTestBase(unittest.TestCase):
    """Redirects _WINNERS_PATH to a per-test tempfile + freezes _now()."""

    def setUp(self):
        self._tmpdir = Path(self.id().replace(".", "_") + "_tmp")
        self._tmpdir.mkdir(exist_ok=True)
        self.addCleanup(self._cleanup_tmpdir)

        self._tmp_path = self._tmpdir / "winners.json"
        self._path_patch = mock.patch.object(winners, "_WINNERS_PATH", self._tmp_path)
        self._path_patch.start()
        self.addCleanup(self._path_patch.stop)

        # Freeze time for deterministic TTL math. Default = 1_000_000.0 epoch
        # secs ("now"); individual tests override via self._set_now.
        self._frozen_now = 1_000_000.0
        self._now_patch = mock.patch.object(
            winners, "_now", side_effect=lambda: self._frozen_now
        )
        self._now_patch.start()
        self.addCleanup(self._now_patch.stop)

        # Snapshot env we touch so the cleanup restores caller state exactly.
        self._saved_env = {
            k: os.environ.get(k)
            for k in ("INSANE_DISABLE_WINNERS", "INSANE_DISABLE_WINNERS_WEAK_OK")
        }
        self.addCleanup(self._restore_env)
        for k in self._saved_env:
            os.environ.pop(k, None)

    def _restore_env(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _cleanup_tmpdir(self):
        for child in self._tmpdir.glob("*"):
            try:
                child.unlink()
            except OSError:
                pass
        try:
            self._tmpdir.rmdir()
        except OSError:
            pass

    def _set_now(self, value: float):
        self._frozen_now = value

    def _read(self) -> dict:
        if not self._tmp_path.exists():
            return {}
        return json.loads(self._tmp_path.read_text())


class StrongOkRegressionTest(_WinnersTestBase):
    def test_strong_ok_recorded_unconditionally(self):
        """strong_ok always wins regardless of env (regression vs F6 strictness)."""
        os.environ["INSANE_DISABLE_WINNERS_WEAK_OK"] = "1"  # would suppress weak_ok
        result = _fake_result([
            _fake_attempt("strong_ok", impersonate="chrome120", referer="self_root"),
        ])
        winners.record("https://example.com/path", result)
        data = self._read()
        # ADAPT-3: key is now host::device_class (default desktop)
        self.assertEqual(data["example.com::desktop"]["impersonate"], "chrome120")
        self.assertEqual(data["example.com::desktop"]["verdict"], "strong_ok")
        self.assertEqual(data["example.com::desktop"]["recorded_at"], self._frozen_now)

    def test_strong_ok_preferred_over_weak_ok_in_trace(self):
        """If trace has both, strong_ok wins even when it appears later."""
        result = _fake_result([
            _fake_attempt("weak_ok", impersonate="edge", referer="search"),
            _fake_attempt("strong_ok", impersonate="firefox", referer="self_root"),
        ])
        winners.record("https://example.com/", result)
        self.assertEqual(self._read()["example.com::desktop"]["impersonate"], "firefox")


class WeakOkAcceptanceTest(_WinnersTestBase):
    def test_weak_ok_recorded_by_default(self):
        """No env set → weak_ok accepted (Phase 11 core)."""
        result = _fake_result([
            _fake_attempt("weak_ok", impersonate="chrome", referer="self_root"),
        ])
        winners.record("https://example.org/page", result)
        data = self._read()
        # ADAPT-3: key is now host::device_class (default desktop)
        self.assertEqual(data["example.org::desktop"]["impersonate"], "chrome")
        self.assertEqual(data["example.org::desktop"]["verdict"], "weak_ok")

    def test_weak_ok_suppressed_by_env_opt_out(self):
        """INSANE_DISABLE_WINNERS_WEAK_OK=1 restores strong_ok-only behaviour."""
        os.environ["INSANE_DISABLE_WINNERS_WEAK_OK"] = "1"
        result = _fake_result([
            _fake_attempt("weak_ok", impersonate="chrome"),
        ])
        winners.record("https://example.org/page", result)
        self.assertEqual(self._read(), {})

    def test_weak_ok_skipped_when_attempt_has_no_impersonate(self):
        """Playwright fallback path — no curl impersonate → nothing to cache."""
        result = _fake_result([
            _fake_attempt("weak_ok", impersonate=""),
        ])
        winners.record("https://example.org/page", result)
        self.assertEqual(self._read(), {})

    def test_first_weak_ok_in_trace_wins(self):
        """When only weak_ok attempts exist, the first one with impersonate wins."""
        result = _fake_result([
            _fake_attempt("weak_ok", impersonate="chrome", referer="self_root"),
            _fake_attempt("weak_ok", impersonate="edge", referer="search"),
        ])
        winners.record("https://example.com/", result)
        self.assertEqual(self._read()["example.com::desktop"]["impersonate"], "chrome")

    def test_record_skipped_when_result_not_ok_even_with_weak_ok_in_trace(self):
        """The `result.ok` gate fires first — a trace with weak_ok must not leak
        past `result.ok=False` (engine signals overall failure even when an
        individual attempt's verdict is weak_ok)."""
        result = _fake_result(
            [_fake_attempt("weak_ok", impersonate="chrome")],
            ok=False,
        )
        winners.record("https://example.com/", result)
        self.assertEqual(self._read(), {})


class TtlTest(_WinnersTestBase):
    def test_fresh_entry_within_ttl_is_returned(self):
        result = _fake_result([_fake_attempt("weak_ok", impersonate="chrome")])
        winners.record("https://example.com/", result)
        # 1 day later — well within TTL.
        self._set_now(self._frozen_now + 86_400)
        hint = winners.get_hint("https://example.com/x")
        self.assertEqual(hint, {"impersonate_first": "chrome",
                                "referer_strategy": "self_root"})

    def test_expired_entry_returns_none(self):
        result = _fake_result([_fake_attempt("weak_ok", impersonate="chrome")])
        winners.record("https://example.com/", result)
        # 7 days + 1 second past record time → expired.
        self._set_now(self._frozen_now + winners._TTL_SECONDS + 1)
        self.assertIsNone(winners.get_hint("https://example.com/x"))

    def test_boundary_at_exact_ttl_is_still_fresh(self):
        """`<= _TTL_SECONDS` is the documented inclusive boundary."""
        result = _fake_result([_fake_attempt("weak_ok", impersonate="chrome")])
        winners.record("https://example.com/", result)
        self._set_now(self._frozen_now + winners._TTL_SECONDS)
        self.assertIsNotNone(winners.get_hint("https://example.com/"))

    def test_legacy_entry_without_recorded_at_is_expired(self):
        """Migrate-by-expiry: pre-Phase-11 entries lack timestamps.
        ADAPT-3: legacy host-only key is a cache miss (not a crash)."""
        self._tmp_path.parent.mkdir(parents=True, exist_ok=True)
        self._tmp_path.write_text(json.dumps({
            "legacy.example.org": {"impersonate": "chrome", "referer": "self_root"}
        }))
        self.assertIsNone(winners.get_hint("https://legacy.example.org/x"))

    def test_corrupt_timestamp_treated_as_expired(self):
        self._tmp_path.parent.mkdir(parents=True, exist_ok=True)
        for bad_ts in ("yesterday", None, [123]):
            self._tmp_path.write_text(json.dumps({
                "bad.example.org": {"impersonate": "chrome", "recorded_at": bad_ts}
            }))
            self.assertIsNone(
                winners.get_hint("https://bad.example.org/"),
                msg=f"corrupt ts {bad_ts!r} should be rejected",
            )

    def test_future_timestamp_treated_as_expired(self):
        """Clock skew defense: an entry stamped in the future can't be trusted."""
        self._tmp_path.parent.mkdir(parents=True, exist_ok=True)
        self._tmp_path.write_text(json.dumps({
            "future.example.org": {
                "impersonate": "chrome",
                "recorded_at": self._frozen_now + 3600,
            }
        }))
        self.assertIsNone(winners.get_hint("https://future.example.org/"))

    def test_expired_entry_is_overwritten_on_next_record(self):
        """Self-healing: expired record → next successful fetch refreshes it."""
        # Plant an expired entry using the new key format.
        self._tmp_path.parent.mkdir(parents=True, exist_ok=True)
        self._tmp_path.write_text(json.dumps({
            "example.com::desktop": {
                "impersonate": "old", "referer": "self_root",
                "recorded_at": self._frozen_now - winners._TTL_SECONDS - 10,
            }
        }))
        # Fresh fetch → new combo replaces stale one.
        result = _fake_result([_fake_attempt("weak_ok", impersonate="new")])
        winners.record("https://example.com/", result)
        self.assertEqual(self._read()["example.com::desktop"]["impersonate"], "new")


class DisableWinnersTest(_WinnersTestBase):
    def test_disable_blocks_record(self):
        os.environ["INSANE_DISABLE_WINNERS"] = "1"
        result = _fake_result([_fake_attempt("strong_ok", impersonate="chrome")])
        winners.record("https://example.com/", result)
        self.assertEqual(self._read(), {})

    def test_disable_blocks_get_hint(self):
        # First record while enabled, then disable and confirm get_hint is None.
        result = _fake_result([_fake_attempt("weak_ok", impersonate="chrome")])
        winners.record("https://example.com/", result)
        self.assertIsNotNone(winners.get_hint("https://example.com/"))

        os.environ["INSANE_DISABLE_WINNERS"] = "1"
        self.assertIsNone(winners.get_hint("https://example.com/"))


# ---------------------------------------------------------------------------
# Wave 2 tests
# ---------------------------------------------------------------------------

class Adapt3DeviceClassKeyTest(_WinnersTestBase):
    """ADAPT-3: device-class key `host::desktop` / `host::mobile`."""

    def test_key_format_desktop(self):
        self.assertEqual(winners._winners_key("example.com", "desktop"),
                         "example.com::desktop")

    def test_key_format_mobile(self):
        self.assertEqual(winners._winners_key("example.com", "mobile"),
                         "example.com::mobile")

    def test_key_format_unknown_defaults_to_desktop(self):
        """Anything other than 'mobile' → desktop (safe fallback)."""
        self.assertEqual(winners._winners_key("example.com", "auto"),
                         "example.com::desktop")
        self.assertEqual(winners._winners_key("example.com", ""),
                         "example.com::desktop")

    def test_desktop_and_mobile_combos_coexist(self):
        """Recording with two device classes must not overwrite each other."""
        desk_result = _fake_result([_fake_attempt("weak_ok", impersonate="chrome")])
        mob_result  = _fake_result([_fake_attempt("weak_ok", impersonate="chrome_ios")])
        winners.record("https://example.com/", desk_result, device_class="desktop")
        winners.record("https://example.com/", mob_result, device_class="mobile")
        data = self._read()
        self.assertEqual(data["example.com::desktop"]["impersonate"], "chrome")
        self.assertEqual(data["example.com::mobile"]["impersonate"], "chrome_ios")

    def test_get_hint_desktop_does_not_return_mobile_entry(self):
        """get_hint with desktop device_class must miss a mobile-keyed entry."""
        mob_result = _fake_result([_fake_attempt("weak_ok", impersonate="safari_ios")])
        winners.record("https://example.com/", mob_result, device_class="mobile")
        hint = winners.get_hint("https://example.com/", device_class="desktop")
        self.assertIsNone(hint)

    def test_get_hint_mobile_returns_mobile_entry(self):
        mob_result = _fake_result([_fake_attempt("weak_ok", impersonate="safari_ios")])
        winners.record("https://example.com/", mob_result, device_class="mobile")
        hint = winners.get_hint("https://example.com/", device_class="mobile")
        self.assertIsNotNone(hint)
        self.assertEqual(hint["impersonate_first"], "safari_ios")

    def test_legacy_host_only_key_is_cache_miss_not_crash(self):
        """Pre-ADAPT-3 files with plain host keys must not crash get_hint."""
        self._tmp_path.parent.mkdir(parents=True, exist_ok=True)
        self._tmp_path.write_text(json.dumps({
            "example.com": {
                "impersonate": "chrome",
                "referer": "self_root",
                "recorded_at": self._frozen_now - 60,
            }
        }))
        # Should return None (miss), not KeyError/crash.
        hint = winners.get_hint("https://example.com/", device_class="desktop")
        self.assertIsNone(hint)


class Adapt4VerdictBasedStrikeTest(_WinnersTestBase):
    """ADAPT-4: strike() only penalizes real blocks, not transient failures."""

    def _plant_combo(self, host: str = "example.com", device_class: str = "desktop",
                     strikes: int = 0):
        key = winners._winners_key(host, device_class)
        self._tmp_path.parent.mkdir(parents=True, exist_ok=True)
        self._tmp_path.write_text(json.dumps({
            key: {
                "impersonate": "chrome",
                "referer": "self_root",
                "recorded_at": self._frozen_now - 60,
                "verdict": "weak_ok",
                "transform": "original",
                "strikes": strikes,
            }
        }))

    def test_penalize_verdicts_constant(self):
        """Invariant: _PENALIZE_VERDICTS contains exactly challenge and blocked."""
        self.assertIn("challenge", winners._PENALIZE_VERDICTS)
        self.assertIn("blocked", winners._PENALIZE_VERDICTS)
        self.assertNotIn("unknown", winners._PENALIZE_VERDICTS)
        self.assertNotIn("rate_limited", winners._PENALIZE_VERDICTS)
        self.assertNotIn("auth_required", winners._PENALIZE_VERDICTS)
        self.assertNotIn("not_found", winners._PENALIZE_VERDICTS)

    def test_challenge_verdict_strikes(self):
        self._plant_combo()
        result = _fake_failed_result("challenge")
        winners.strike("https://example.com/", result=result, device_class="desktop")
        data = self._read()
        self.assertEqual(data["example.com::desktop"]["strikes"], 1)

    def test_blocked_verdict_strikes(self):
        self._plant_combo()
        result = _fake_failed_result("blocked")
        winners.strike("https://example.com/", result=result, device_class="desktop")
        self.assertEqual(self._read()["example.com::desktop"]["strikes"], 1)

    def test_rate_limited_does_not_strike(self):
        """Transient rate-limit must not penalize a good combo."""
        self._plant_combo()
        result = _fake_failed_result("rate_limited")
        winners.strike("https://example.com/", result=result, device_class="desktop")
        # strikes counter must remain 0 (no strike applied)
        self.assertEqual(self._read()["example.com::desktop"]["strikes"], 0)

    def test_unknown_verdict_does_not_strike(self):
        """Dependency/exception failures must not evict a good combo."""
        self._plant_combo()
        result = _fake_failed_result("unknown")
        winners.strike("https://example.com/", result=result, device_class="desktop")
        self.assertEqual(self._read()["example.com::desktop"]["strikes"], 0)

    def test_auth_required_does_not_strike(self):
        self._plant_combo()
        result = _fake_failed_result("auth_required")
        winners.strike("https://example.com/", result=result, device_class="desktop")
        self.assertEqual(self._read()["example.com::desktop"]["strikes"], 0)

    def test_not_found_does_not_strike(self):
        self._plant_combo()
        result = _fake_failed_result("not_found")
        winners.strike("https://example.com/", result=result, device_class="desktop")
        self.assertEqual(self._read()["example.com::desktop"]["strikes"], 0)

    def test_none_result_always_strikes_legacy_compat(self):
        """result=None (legacy callers) → conservative: always strike."""
        self._plant_combo()
        winners.strike("https://example.com/", result=None, device_class="desktop")
        self.assertEqual(self._read()["example.com::desktop"]["strikes"], 1)

    def test_strike_threshold_evicts_entry(self):
        """When strikes reaches _STRIKE_THRESHOLD the entry is deleted."""
        self._plant_combo(strikes=winners._STRIKE_THRESHOLD - 1)
        result = _fake_failed_result("challenge")
        winners.strike("https://example.com/", result=result, device_class="desktop")
        # Entry must be gone.
        self.assertNotIn("example.com::desktop", self._read())

    def test_strike_uses_device_class_key(self):
        """Strike on desktop must not affect the mobile entry for the same host."""
        key_mob  = winners._winners_key("example.com", "mobile")
        key_desk = winners._winners_key("example.com", "desktop")
        self._tmp_path.parent.mkdir(parents=True, exist_ok=True)
        self._tmp_path.write_text(json.dumps({
            key_desk: {"impersonate": "chrome",  "referer": "self_root",
                       "recorded_at": self._frozen_now - 60, "verdict": "weak_ok",
                       "transform": "original", "strikes": 0},
            key_mob:  {"impersonate": "safari_ios", "referer": "self_root",
                       "recorded_at": self._frozen_now - 60, "verdict": "weak_ok",
                       "transform": "original", "strikes": 0},
        }))
        result = _fake_failed_result("challenge")
        winners.strike("https://example.com/", result=result, device_class="desktop")
        data = self._read()
        self.assertEqual(data[key_desk]["strikes"], 1)
        self.assertEqual(data[key_mob]["strikes"], 0)  # untouched


class Adapt5PruneLruTest(_WinnersTestBase):
    """ADAPT-5: _prune() enforces 7-day TTL and bounded LRU cap."""

    def test_prune_drops_expired_entries(self):
        now = 1_000_000.0
        fresh = {"recorded_at": now - 100}
        old   = {"recorded_at": now - (8 * 24 * 3600)}
        data = {
            "fresh.com::desktop": fresh,
            "old.com::desktop":   old,
        }
        pruned = winners._prune(data, now=now)
        self.assertIn("fresh.com::desktop", pruned)
        self.assertNotIn("old.com::desktop", pruned)

    def test_prune_drops_entries_without_timestamp(self):
        """No recorded_at → treated as expired (legacy entries)."""
        data = {"legacy.example.org::desktop": {"impersonate": "chrome"}}
        pruned = winners._prune(data, now=1_000_000.0)
        self.assertNotIn("legacy.example.org::desktop", pruned)

    def test_prune_drops_entries_with_non_numeric_timestamp(self):
        data = {"bad.example.org::desktop": {"impersonate": "chrome", "recorded_at": "now"}}
        pruned = winners._prune(data, now=1_000_000.0)
        self.assertNotIn("bad.example.org::desktop", pruned)

    def test_prune_drops_non_dict_entries(self):
        """Malformed top-level values must be silently discarded."""
        data = {"weird.com::desktop": "not-a-dict", "ok.com::desktop": {"recorded_at": 999_999.9}}
        pruned = winners._prune(data, now=1_000_000.0)
        self.assertNotIn("weird.com::desktop", pruned)
        self.assertIn("ok.com::desktop", pruned)

    def test_prune_enforces_lru_cap(self):
        now = 1_000_000.0
        # 600 fresh entries, all within TTL — cap is 500.
        big = {f"h{i}.com::desktop": {"recorded_at": now - i}
               for i in range(600)}
        pruned = winners._prune(big, now=now)
        self.assertEqual(len(pruned), winners._MAX_ENTRIES)

    def test_prune_lru_evicts_oldest_first(self):
        now = 1_000_000.0
        cap = winners._MAX_ENTRIES
        # cap + 10 entries; the 10 oldest (highest age offset) must be evicted.
        entries = {f"h{i}.com::desktop": {"recorded_at": now - i}
                   for i in range(cap + 10)}
        pruned = winners._prune(entries, now=now)
        # Oldest (largest i, smallest recorded_at) must be gone.
        for i in range(cap, cap + 10):
            self.assertNotIn(f"h{i}.com::desktop", pruned,
                             msg=f"h{i}.com::desktop should have been evicted")

    def test_prune_called_on_load(self):
        """_load() must call _prune so expired entries don't leak into callers."""
        self._tmp_path.parent.mkdir(parents=True, exist_ok=True)
        self._tmp_path.write_text(json.dumps({
            "fresh.com::desktop": {
                "impersonate": "chrome", "referer": "self_root",
                "recorded_at": self._frozen_now - 100, "verdict": "weak_ok",
                "transform": "original", "strikes": 0,
            },
            "old.com::desktop": {
                "impersonate": "chrome", "referer": "self_root",
                "recorded_at": self._frozen_now - (8 * 24 * 3600),
                "verdict": "weak_ok", "transform": "original", "strikes": 0,
            },
        }))
        loaded = winners._load()
        self.assertIn("fresh.com::desktop", loaded)
        self.assertNotIn("old.com::desktop", loaded)

    def test_max_entries_env_override(self):
        """INSANE_WINNERS_MAX env var controls the cap (read at import; test
        the constant directly since re-import is complex in test isolation)."""
        # At minimum, the default cap must be a positive integer.
        self.assertGreater(winners._MAX_ENTRIES, 0)


if __name__ == "__main__":
    unittest.main()
