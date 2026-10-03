"""P22/P23 persistence layer regression tests.

Covers:
  P22 — observe centralization + winners negative invalidation
    - observe.log() accepts new keyword fields (elapsed_ms, impersonate,
      transform, hint_used) and writes them to the log entry
    - engine_proxy._proxy_fetch emits an observe entry with hint_used=True
      when a winners hint was injected
    - winners.strike() increments the strike counter and deletes the entry
      on reaching _STRIKE_THRESHOLD
    - _proxy_fetch calls winners.strike() when a hint-assisted fetch fails
    - winners.get_hint() now includes url_transform_first for non-"original"
      transforms

  P23 — cache lifecycle
    - cache._canonical_url() strips utm_* / tracking params, sorts query keys,
      drops fragment, lowercases host
    - cache._key() with two URLs differing only by utm_source maps to the
      same digest
    - cache.get() lazily unlinks expired entries
    - cache.put() respects INSANE_CACHE_WEAK_OK (accepts weak_ok when set,
      rejects when unset)
    - cache.prune() removes only expired entries, leaves fresh ones
    - cache.info() returns accurate entry/fresh/expired/size counts
    - plus cache {clear,prune,info} CLI subcommands exit 0

All tests are offline and deterministic (no network; observe/winners/cache dirs
monkeypatched to temp dirs; engine calls faked via the _engine_fake_helper
pattern).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

import plus  # noqa: E402 — triggers engine_proxy.install()
import plus.observe as observe_mod  # noqa: E402
import plus.winners as winners_mod  # noqa: E402
from plus import cache as cache_mod  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_winners(tmpdir: Path) -> Path:
    obs = tmpdir / "observations"
    obs.mkdir(parents=True, exist_ok=True)
    return obs / "winners.json"


def _make_fresh_combo(**overrides) -> dict:
    base = {
        "impersonate": "chrome120",
        "transform": "original",
        "referer": "self_root",
        "verdict": "weak_ok",
        "profile_used": None,
        "recorded_at": time.time(),
        "strikes": 0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# P22 — observe.log() extended fields
# ---------------------------------------------------------------------------

class TestObserveExtendedFields(unittest.TestCase):
    """observe.log() must accept and persist P22 keyword fields."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._obs_dir = self._tmpdir / "observations"
        self._log_path = self._obs_dir / "fetch-log.jsonl"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _log_and_read(self, **kwargs) -> dict:
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path):
            observe_mod.log("https://example.test/", None, "weak_ok", 1, True,
                            **kwargs)
        return json.loads(self._log_path.read_text(encoding="utf-8").strip())

    def test_elapsed_ms_stored(self):
        entry = self._log_and_read(elapsed_ms=312.5)
        self.assertAlmostEqual(entry["elapsed_ms"], 312.5)

    def test_impersonate_stored(self):
        entry = self._log_and_read(impersonate="chrome120")
        self.assertEqual(entry["impersonate"], "chrome120")

    def test_transform_stored(self):
        entry = self._log_and_read(transform="mobile_subdomain")
        self.assertEqual(entry["transform"], "mobile_subdomain")

    def test_hint_used_true_stored(self):
        entry = self._log_and_read(hint_used=True)
        self.assertTrue(entry["hint_used"])

    def test_hint_used_false_default(self):
        entry = self._log_and_read()
        self.assertFalse(entry["hint_used"])

    def test_none_fields_stored_as_null(self):
        entry = self._log_and_read(elapsed_ms=None, impersonate=None, transform=None)
        self.assertIsNone(entry["elapsed_ms"])
        self.assertIsNone(entry["impersonate"])
        self.assertIsNone(entry["transform"])

    def test_impersonate_sanitized(self):
        """Control chars in impersonate must be sanitized (same policy as host)."""
        entry = self._log_and_read(impersonate="chrome\nINJECT")
        stored = entry.get("impersonate", "")
        self.assertNotIn("\n", stored)


# ---------------------------------------------------------------------------
# P22 — winners.strike() negative invalidation
# ---------------------------------------------------------------------------

class TestWinnersStrike(unittest.TestCase):
    """winners.strike() increments counter and deletes entry at threshold."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._winners_path = _tmp_winners(self._tmpdir)
        self._orig_path = winners_mod._WINNERS_PATH
        winners_mod._WINNERS_PATH = self._winners_path

    def tearDown(self):
        winners_mod._WINNERS_PATH = self._orig_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_combo(self, host: str, device_class: str = "desktop", **overrides) -> None:
        # ADAPT-3: key is now host::device_class
        key = winners_mod._winners_key(host, device_class)
        data = {key: _make_fresh_combo(**overrides)}
        self._winners_path.write_text(
            json.dumps(data), encoding="utf-8"
        )

    def _read_data(self) -> dict:
        if not self._winners_path.exists():
            return {}
        return json.loads(self._winners_path.read_text(encoding="utf-8"))

    def test_first_strike_increments_counter(self):
        self._write_combo("example.test", strikes=0)
        winners_mod.strike("https://example.test/page")
        data = self._read_data()
        self.assertIn("example.test::desktop", data)
        self.assertEqual(data["example.test::desktop"]["strikes"], 1)

    def test_second_strike_reaches_threshold_deletes_entry(self):
        """At _STRIKE_THRESHOLD strikes the entry must be deleted."""
        threshold = winners_mod._STRIKE_THRESHOLD  # 2
        self._write_combo("example.test", strikes=threshold - 1)
        winners_mod.strike("https://example.test/page")
        data = self._read_data()
        self.assertNotIn(
            "example.test::desktop", data,
            "Entry must be deleted once strike threshold is reached",
        )

    def test_strike_no_entry_is_noop(self):
        """strike() on a host with no entry must not raise."""
        try:
            winners_mod.strike("https://no-entry.example.test/")
        except Exception as exc:  # noqa: BLE001
            self.fail(f"strike() raised on missing entry: {exc}")

    def test_strike_respects_disabled_env(self):
        """INSANE_DISABLE_WINNERS=1 causes strike() to be a no-op."""
        self._write_combo("example.test", strikes=0)
        with mock.patch.dict(os.environ, {"INSANE_DISABLE_WINNERS": "1"}):
            winners_mod.strike("https://example.test/page")
        data = self._read_data()
        # Entry must be unchanged — strike was skipped.
        self.assertEqual(data["example.test::desktop"]["strikes"], 0)

    def test_strike_is_best_effort_on_corrupt_file(self):
        """strike() must not raise even if winners.json is corrupt."""
        self._winners_path.write_text("not valid json {{", encoding="utf-8")
        try:
            winners_mod.strike("https://example.test/page")
        except Exception as exc:  # noqa: BLE001
            self.fail(f"strike() raised on corrupt file: {exc}")


# ---------------------------------------------------------------------------
# P22 — winners.get_hint() exposes url_transform_first
# ---------------------------------------------------------------------------

class TestWinnersGetHintTransform(unittest.TestCase):
    """get_hint() must include url_transform_first for non-original transforms."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._winners_path = _tmp_winners(self._tmpdir)
        self._orig_path = winners_mod._WINNERS_PATH
        winners_mod._WINNERS_PATH = self._winners_path

    def tearDown(self):
        winners_mod._WINNERS_PATH = self._orig_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_combo(self, host: str, device_class: str = "desktop", **overrides) -> None:
        # ADAPT-3: key is now host::device_class
        key = winners_mod._winners_key(host, device_class)
        data = {key: _make_fresh_combo(**overrides)}
        self._winners_path.write_text(json.dumps(data), encoding="utf-8")

    def test_non_original_transform_included_in_hint(self):
        self._write_combo("example.test", transform="mobile_subdomain")
        hint = winners_mod.get_hint("https://example.test/")
        self.assertIsNotNone(hint)
        self.assertEqual(hint.get("url_transform_first"), "mobile_subdomain")

    def test_original_transform_not_included(self):
        self._write_combo("example.test", transform="original")
        hint = winners_mod.get_hint("https://example.test/")
        self.assertIsNotNone(hint)
        self.assertNotIn(
            "url_transform_first", hint,
            "transform='original' must not produce a url_transform_first hint",
        )

    def test_missing_transform_not_included(self):
        combo = _make_fresh_combo()
        combo.pop("transform", None)
        # ADAPT-3: use device-class key
        key = winners_mod._winners_key("example.test", "desktop")
        data = {key: combo}
        self._winners_path.write_text(json.dumps(data), encoding="utf-8")
        hint = winners_mod.get_hint("https://example.test/")
        # hint may be None (no impersonate either) or dict without transform key
        if hint is not None:
            self.assertNotIn("url_transform_first", hint)

    def test_record_resets_strikes_to_zero(self):
        """winners.record() must write strikes=0 to reset any prior counter."""
        self._write_combo("example.test", strikes=1)

        # Build a minimal fake result with an ok weak_ok trace attempt.
        class _FakeAttempt:
            verdict = "weak_ok"
            impersonate = "chrome120"
            url_transform = "original"
            referer = "self_root"

        class _FakeResult:
            ok = True
            trace = [_FakeAttempt()]
            profile_used = None

        winners_mod.record("https://example.test/", _FakeResult())
        data = json.loads(self._winners_path.read_text(encoding="utf-8"))
        # ADAPT-3: key is now host::device_class (default desktop)
        self.assertEqual(
            data["example.test::desktop"]["strikes"], 0,
            "record() must reset strikes to 0 on a successful fetch",
        )


# ---------------------------------------------------------------------------
# P22 — _proxy_fetch observe centralization + strike on failure
# ---------------------------------------------------------------------------

class TestProxyFetchObserveAndStrike(unittest.TestCase):
    """_proxy_fetch logs via observe and calls strike() on hint-assisted failure."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._obs_dir = self._tmpdir / "observations"
        self._log_path = self._obs_dir / "fetch-log.jsonl"
        self._winners_path = _tmp_winners(self._tmpdir)
        self._orig_winners = winners_mod._WINNERS_PATH
        winners_mod._WINNERS_PATH = self._winners_path

    def tearDown(self):
        winners_mod._WINNERS_PATH = self._orig_winners
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_fake_result(self, ok: bool, verdict: str = "weak_ok"):
        class _Att:
            impersonate = "chrome120"
            url_transform = "original"
            referer = "self_root"

        _Att.verdict = verdict

        class _R:
            trace = [_Att()]
            profile_used = None
            final_url = "https://example.test/"
            content = "body"
            summary = ""

        _R.ok = ok
        _R.verdict = verdict
        return _R()

    def test_observe_log_written_on_successful_fetch(self):
        """_proxy_fetch must write an observe entry even for search/crawl paths."""
        fake_result = self._make_fake_result(ok=True)

        from plus import engine_proxy as ep
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(ep, "_ORIGINAL_FETCH", return_value=fake_result), \
             mock.patch.dict(os.environ, {"INSANE_DISABLE_SSRF_GUARD": "1"}):
            ep._proxy_fetch("https://example.test/")

        self.assertTrue(self._log_path.exists(), "observe log must be written")
        entry = json.loads(self._log_path.read_text(encoding="utf-8").strip())
        self.assertIn("elapsed_ms", entry)
        self.assertIsInstance(entry["elapsed_ms"], float)

    def test_hint_used_true_when_winner_injected(self):
        """hint_used=True must appear in the log when a winners hint was used."""
        # Write a fresh winners entry so get_hint() returns something.
        # ADAPT-3: key must be host::device_class so get_hint() finds it.
        combo = _make_fresh_combo(impersonate="safari17")
        key = winners_mod._winners_key("example.test", "desktop")
        self._winners_path.write_text(
            json.dumps({key: combo}), encoding="utf-8"
        )
        fake_result = self._make_fake_result(ok=True)

        from plus import engine_proxy as ep
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(ep, "_ORIGINAL_FETCH", return_value=fake_result), \
             mock.patch.dict(os.environ, {"INSANE_DISABLE_SSRF_GUARD": "1"}):
            ep._proxy_fetch("https://example.test/")

        entry = json.loads(self._log_path.read_text(encoding="utf-8").strip())
        self.assertTrue(entry["hint_used"], "hint_used must be True when winner injected")

    def test_strike_called_on_hint_failure(self):
        """When a hint is used and the fetch fails, strike() must be called."""
        # ADAPT-3: key must be host::device_class so get_hint() injects the hint.
        combo = _make_fresh_combo(impersonate="chrome120", strikes=0)
        key = winners_mod._winners_key("example.test", "desktop")
        self._winners_path.write_text(
            json.dumps({key: combo}), encoding="utf-8"
        )
        # ADAPT-4: fake_result needs a verdict that triggers a strike.
        fake_result = self._make_fake_result(ok=False, verdict="challenge")

        from plus import engine_proxy as ep
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(ep, "_ORIGINAL_FETCH", return_value=fake_result), \
             mock.patch.dict(os.environ, {"INSANE_DISABLE_SSRF_GUARD": "1"}):
            ep._proxy_fetch("https://example.test/")

        data = json.loads(self._winners_path.read_text(encoding="utf-8"))
        self.assertIn(key, data)
        self.assertEqual(
            data[key]["strikes"], 1,
            "strike counter must be incremented after hint-assisted failure",
        )

    def test_no_strike_without_hint(self):
        """When no hint was used (empty winners), failed fetch must not strike."""
        # No entry in winners — get_hint returns None, _hint_used stays False.
        fake_result = self._make_fake_result(ok=False)

        from plus import engine_proxy as ep
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(ep, "_ORIGINAL_FETCH", return_value=fake_result), \
             mock.patch.dict(os.environ, {"INSANE_DISABLE_SSRF_GUARD": "1"}):
            ep._proxy_fetch("https://example.test/")

        # winners file should not be created at all.
        if self._winners_path.exists():
            data = json.loads(self._winners_path.read_text(encoding="utf-8"))
            self.assertNotIn(
                "example.test::desktop", data,
                "No strike must be written when no hint was used",
            )


# ---------------------------------------------------------------------------
# P23 — cache._canonical_url()
# ---------------------------------------------------------------------------

class TestCacheCanonicalUrl(unittest.TestCase):
    """_canonical_url() normalizes URLs for cache key dedup."""

    def test_utm_params_stripped(self):
        url = "https://example.test/page?utm_source=newsletter&utm_medium=email"
        result = cache_mod._canonical_url(url)
        self.assertNotIn("utm_source", result)
        self.assertNotIn("utm_medium", result)

    def test_non_tracking_params_preserved(self):
        url = "https://example.test/page?q=hello&page=2"
        result = cache_mod._canonical_url(url)
        self.assertIn("q=hello", result)
        self.assertIn("page=2", result)

    def test_tracking_params_stripped_but_real_params_kept(self):
        url = "https://example.test/page?q=hello&utm_source=x&fbclid=abc"
        result = cache_mod._canonical_url(url)
        self.assertIn("q=hello", result)
        self.assertNotIn("utm_source", result)
        self.assertNotIn("fbclid", result)

    def test_query_keys_sorted(self):
        url_a = "https://example.test/page?b=2&a=1"
        url_b = "https://example.test/page?a=1&b=2"
        self.assertEqual(
            cache_mod._canonical_url(url_a),
            cache_mod._canonical_url(url_b),
            "Query key order must not affect canonical form",
        )

    def test_fragment_dropped(self):
        url = "https://example.test/page#section3"
        result = cache_mod._canonical_url(url)
        self.assertNotIn("#", result)
        self.assertNotIn("section3", result)

    def test_host_lowercased(self):
        url = "https://EXAMPLE.TEST/page"
        result = cache_mod._canonical_url(url)
        self.assertIn("example.test", result)
        self.assertNotIn("EXAMPLE.TEST", result)

    def test_trailing_slash_stripped(self):
        url = "https://example.test/path/"
        result = cache_mod._canonical_url(url)
        self.assertTrue(
            result.endswith("/path") or result.endswith("/path?") or
            not result.endswith("/"),
            "Trailing slash on path must be stripped",
        )

    def test_empty_url_returned_as_is(self):
        self.assertEqual(cache_mod._canonical_url(""), "")

    def test_two_utm_variants_same_key(self):
        """URLs differing only in utm params must produce the same cache key."""
        url1 = "https://example.test/article"
        url2 = "https://example.test/article?utm_source=email&utm_campaign=june"
        key1 = cache_mod._key(url1, "auto", "raw")
        key2 = cache_mod._key(url2, "auto", "raw")
        self.assertEqual(key1, key2, "utm-variant URLs must share the same cache key")


# ---------------------------------------------------------------------------
# P23 — cache lazy-unlink of expired entries
# ---------------------------------------------------------------------------

class TestCacheLazyUnlink(unittest.TestCase):
    """get() must unlink expired entries on read."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache_mod.CACHE_DIR
        cache_mod.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        cache_mod.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_expired_entry_is_unlinked(self):
        url = "https://example.test/lazy"
        # Write an entry with a timestamp past the TTL.
        ttl = cache_mod._ttl_seconds()
        entry = {
            "ts": time.time() - ttl - 1,
            "url": url,
            "verdict": "strong_ok",
            "content": "stale",
            "selectors": [],
        }
        path = cache_mod._path_for(url, "auto", "raw")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry), encoding="utf-8")

        result = cache_mod.get(url, "auto", "raw")
        self.assertIsNone(result)
        self.assertFalse(path.exists(), "Expired entry must be unlinked by get()")

    def test_fresh_entry_not_unlinked(self):
        url = "https://example.test/fresh-lazy"
        cache_mod.put(url, "auto", "raw", "strong_ok", "fresh-content")
        path = cache_mod._path_for(url, "auto", "raw")
        result = cache_mod.get(url, "auto", "raw")
        self.assertEqual(result, "fresh-content")
        self.assertTrue(path.exists(), "Fresh entry must NOT be unlinked")


# ---------------------------------------------------------------------------
# P23 — INSANE_CACHE_WEAK_OK opt-in
# ---------------------------------------------------------------------------

class TestCacheWeakOkOptIn(unittest.TestCase):
    """cache.put() must respect INSANE_CACHE_WEAK_OK for weak_ok entries."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache_mod.CACHE_DIR
        cache_mod.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        cache_mod.CACHE_DIR = self._orig_dir
        os.environ.pop("INSANE_CACHE_WEAK_OK", None)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_weak_ok_rejected_by_default(self):
        url = "https://example.test/weak"
        cache_mod.put(url, "auto", "raw", "weak_ok", "weak-content")
        result = cache_mod.get(url, "auto", "raw")
        self.assertIsNone(result, "weak_ok must not be cached without INSANE_CACHE_WEAK_OK=1")

    def test_weak_ok_accepted_with_env(self):
        url = "https://example.test/weak-allowed"
        with mock.patch.dict(os.environ, {"INSANE_CACHE_WEAK_OK": "1"}):
            cache_mod.put(url, "auto", "raw", "weak_ok", "weak-content")
            result = cache_mod.get(url, "auto", "raw")
        self.assertEqual(result, "weak-content",
                         "weak_ok must be cached when INSANE_CACHE_WEAK_OK=1")

    def test_strong_ok_always_accepted(self):
        url = "https://example.test/strong"
        cache_mod.put(url, "auto", "raw", "strong_ok", "strong-content")
        result = cache_mod.get(url, "auto", "raw")
        self.assertEqual(result, "strong-content",
                         "strong_ok must always be cached regardless of env")

    def test_unknown_verdict_always_rejected(self):
        url = "https://example.test/unknown"
        with mock.patch.dict(os.environ, {"INSANE_CACHE_WEAK_OK": "1"}):
            cache_mod.put(url, "auto", "raw", "challenge", "bad-content")
        result = cache_mod.get(url, "auto", "raw")
        self.assertIsNone(result, "Non-ok verdicts must never be cached")


# ---------------------------------------------------------------------------
# P23 — cache.prune()
# ---------------------------------------------------------------------------

class TestCachePrune(unittest.TestCase):
    """prune() removes only expired entries."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache_mod.CACHE_DIR
        cache_mod.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        cache_mod.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_prune_removes_expired_leaves_fresh(self):
        # Write one fresh entry.
        cache_mod.put("https://example.test/fresh", "auto", "raw",
                      "strong_ok", "fresh")
        # Write one expired entry directly.
        url_exp = "https://example.test/expired"
        ttl = cache_mod._ttl_seconds()
        entry = {
            "ts": time.time() - ttl - 1,
            "url": url_exp,
            "verdict": "strong_ok",
            "content": "stale",
            "selectors": [],
        }
        path = cache_mod._path_for(url_exp, "auto", "raw")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry), encoding="utf-8")

        removed = cache_mod.prune()
        self.assertEqual(removed, 1, "prune() must remove exactly the expired entry")
        # Fresh entry must survive.
        self.assertIsNotNone(cache_mod.get("https://example.test/fresh", "auto", "raw"))
        # Expired entry must be gone.
        self.assertFalse(path.exists())

    def test_prune_empty_dir_returns_zero(self):
        count = cache_mod.prune()
        self.assertEqual(count, 0)

    def test_prune_missing_dir_returns_zero(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        count = cache_mod.prune()
        self.assertEqual(count, 0)

    def test_prune_removes_corrupt_entries(self):
        path = cache_mod.CACHE_DIR / "corrupt.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{{{{invalid", encoding="utf-8")
        removed = cache_mod.prune()
        self.assertEqual(removed, 1)
        self.assertFalse(path.exists())


# ---------------------------------------------------------------------------
# P23 — cache.info()
# ---------------------------------------------------------------------------

class TestCacheInfo(unittest.TestCase):
    """info() returns accurate stats."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache_mod.CACHE_DIR
        cache_mod.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        cache_mod.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_empty_dir(self):
        stats = cache_mod.info()
        self.assertEqual(stats["entry_count"], 0)
        self.assertEqual(stats["fresh_count"], 0)
        self.assertEqual(stats["expired_count"], 0)
        self.assertEqual(stats["total_bytes"], 0)

    def test_missing_dir(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        stats = cache_mod.info()
        self.assertEqual(stats["entry_count"], 0)

    def test_counts_fresh_and_expired(self):
        # Write one fresh entry.
        cache_mod.put("https://example.test/a", "auto", "raw", "strong_ok", "a")
        # Write one expired entry.
        url_exp = "https://example.test/b"
        ttl = cache_mod._ttl_seconds()
        entry = {
            "ts": time.time() - ttl - 1,
            "url": url_exp,
            "verdict": "strong_ok",
            "content": "b",
            "selectors": [],
        }
        path = cache_mod._path_for(url_exp, "auto", "raw")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry), encoding="utf-8")

        stats = cache_mod.info()
        self.assertEqual(stats["entry_count"], 2)
        self.assertEqual(stats["fresh_count"], 1)
        self.assertEqual(stats["expired_count"], 1)
        self.assertGreater(stats["total_bytes"], 0)

    def test_cache_dir_in_result(self):
        stats = cache_mod.info()
        self.assertEqual(stats["cache_dir"], str(cache_mod.CACHE_DIR))


# ---------------------------------------------------------------------------
# P23 — plus cache CLI subcommands
# ---------------------------------------------------------------------------

class TestCacheCLI(unittest.TestCase):
    """plus cache {clear,prune,info} must exit 0 and produce output."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache_mod.CACHE_DIR
        cache_mod.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        cache_mod.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run(self, *argv: str) -> tuple[int, str]:
        """Run main() with patched stdout, return (exit_code, stdout_text)."""
        import io
        from plus.__main__ import main
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            code = main(list(argv))
        return code, buf.getvalue()

    def test_cache_clear_exit_0(self):
        cache_mod.put("https://example.test/x", "auto", "raw", "strong_ok", "x")
        code, out = self._run("cache", "clear")
        self.assertEqual(code, 0)
        self.assertIn("removed", out)

    def test_cache_prune_exit_0(self):
        code, out = self._run("cache", "prune")
        self.assertEqual(code, 0)
        self.assertIn("pruned", out)

    def test_cache_info_exit_0(self):
        code, out = self._run("cache", "info")
        self.assertEqual(code, 0)
        self.assertIn("entries", out)

    def test_cache_info_json_flag(self):
        code, out = self._run("cache", "info")
        # Without --json the output is human-readable (contains "entries :")
        self.assertEqual(code, 0)


# ===========================================================================
# P36 (2026-06-12): Simhash mis-record detection + content fingerprint fields.
# NEW classes appended — the P22/P23 classes above are untouched. Offline only.
# ===========================================================================

from plus import _fingerprint as fp_mod  # noqa: E402


class TestFingerprintHelper(unittest.TestCase):
    """plus/_fingerprint.py soft-import helpers behave and never raise."""

    def test_fingerprint_stable_for_same_text(self):
        text = "The quick brown fox jumps over the lazy dog. " * 20
        f1 = fp_mod.content_fingerprint(text)
        f2 = fp_mod.content_fingerprint(text)
        self.assertIsNotNone(f1)
        self.assertEqual(f1, f2)

    def test_fingerprint_empty_is_none(self):
        self.assertIsNone(fp_mod.content_fingerprint(""))
        self.assertIsNone(fp_mod.content_fingerprint(None))

    def test_identical_text_high_similarity(self):
        text = "Astronomy studies stars, galaxies, and the cosmos at large. " * 15
        self.assertGreaterEqual(fp_mod.similar(text, text), 0.9)

    def test_different_text_low_similarity(self):
        a = "Astronomy studies stars, galaxies, and the cosmos. " * 15
        b = "Cooking recipes for pasta, bread, and pastry desserts daily. " * 15
        self.assertLess(fp_mod.similar(a, b), 0.9)

    def test_similar_none_inputs_return_zero(self):
        """A degraded/empty input must yield 0.0 so dedup never over-skips."""
        self.assertEqual(fp_mod.similar(None, "x"), 0.0)
        self.assertEqual(fp_mod.similar("x", None), 0.0)
        self.assertEqual(fp_mod.similar("", ""), 0.0)


class TestObserveFingerprintField(unittest.TestCase):
    """observe.log() must accept and persist the P36 fingerprint field."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._obs_dir = self._tmpdir / "observations"
        self._log_path = self._obs_dir / "fetch-log.jsonl"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _log_and_read(self, **kwargs) -> dict:
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path):
            observe_mod.log("https://example.test/", None, "weak_ok", 1, True,
                            **kwargs)
        return json.loads(self._log_path.read_text(encoding="utf-8").strip())

    def test_fingerprint_stored(self):
        entry = self._log_and_read(fingerprint="abc123def456")
        self.assertEqual(entry["fingerprint"], "abc123def456")

    def test_fingerprint_default_none(self):
        entry = self._log_and_read()
        self.assertIsNone(entry["fingerprint"])

    def test_fingerprint_sanitized(self):
        entry = self._log_and_read(fingerprint="abc\nINJECT")
        self.assertNotIn("\n", entry.get("fingerprint", ""))


class TestWinnersFingerprintRecord(unittest.TestCase):
    """winners.record() persists a content fingerprint and warns on mis-record."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._winners_path = _tmp_winners(self._tmpdir)
        self._orig_path = winners_mod._WINNERS_PATH
        winners_mod._WINNERS_PATH = self._winners_path

    def tearDown(self):
        winners_mod._WINNERS_PATH = self._orig_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_result(self, content: str, impersonate: str = "chrome120",
                     transform: str = "original"):
        class _Att:
            verdict = "weak_ok"

        _Att.impersonate = impersonate
        _Att.url_transform = transform
        _Att.referer = "self_root"

        class _R:
            ok = True
            trace = [_Att()]
            profile_used = None

        _R.content = content
        return _R()

    def _read(self) -> dict:
        return json.loads(self._winners_path.read_text(encoding="utf-8"))

    def test_fingerprint_written(self):
        content = "Substantial article body about widgets and gadgets. " * 30
        winners_mod.record("https://example.test/", self._make_result(content))
        data = self._read()
        # ADAPT-3: key is now host::device_class (default desktop)
        key = winners_mod._winners_key("example.test", "desktop")
        self.assertIn("fingerprint", data[key])
        self.assertIsNotNone(data[key]["fingerprint"])

    def test_mis_record_warns_on_identical_fp_different_combo(self):
        """Same body fingerprint from a different combo emits a P36 warning."""
        content = "Identical block/challenge page echoed back to every probe. " * 30
        # First record with combo A.
        winners_mod.record(
            "https://example.test/",
            self._make_result(content, impersonate="chrome120", transform="original"),
        )
        # Second record: same body, DIFFERENT impersonate → mis-record signal.
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            winners_mod.record(
                "https://example.test/",
                self._make_result(content, impersonate="safari17", transform="original"),
            )
        self.assertIn("mis-record", buf.getvalue().lower())

    def test_no_warn_on_different_content(self):
        """Different content across combos must NOT warn."""
        winners_mod.record(
            "https://example.test/",
            self._make_result("First unique body about astronomy. " * 30,
                              impersonate="chrome120"),
        )
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            winners_mod.record(
                "https://example.test/",
                self._make_result("Second different body about cooking. " * 30,
                                  impersonate="safari17"),
            )
        self.assertNotIn("mis-record", buf.getvalue().lower())

    def test_no_warn_same_combo_repeat(self):
        """Re-recording the same combo+body must not warn (legitimate refresh)."""
        content = "Stable page body re-fetched with the same winning combo. " * 30
        winners_mod.record(
            "https://example.test/",
            self._make_result(content, impersonate="chrome120", transform="original"),
        )
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            winners_mod.record(
                "https://example.test/",
                self._make_result(content, impersonate="chrome120", transform="original"),
            )
        self.assertNotIn("mis-record", buf.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
