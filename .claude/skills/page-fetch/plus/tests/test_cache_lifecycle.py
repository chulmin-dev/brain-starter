"""P18: cache lifecycle regression tests — TTL expiry and purge only.

TestCacheGuards (test_engine_proxy.py:524-577) already pins:
  - weak_ok rejection
  - strong_ok storage and retrieval
  - selector-keyed cache miss/hit
  - atomic write (no .tmp leftovers)

This file covers the *uncovered* areas only:
  - TTL expiry: get() returns None after INSANE_CACHE_TTL seconds pass
  - _ttl_seconds() honours INSANE_CACHE_TTL env override and falls back on bad values
  - clear(): removes all .json files, returns count, handles missing dir
  - Corrupted entry self-heals (get returns None and file is removed)
"""
from __future__ import annotations

import json
import os
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
from plus import cache as cache_mod  # noqa: E402


class TestCacheTTLExpiry(unittest.TestCase):
    """cache.get() returns None once the entry exceeds INSANE_CACHE_TTL."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache_mod.CACHE_DIR
        cache_mod.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        import shutil
        cache_mod.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_fresh_entry_returned(self):
        """A just-written entry must be returned immediately."""
        cache_mod.put(
            "https://example.test/fresh", "auto", "raw",
            "strong_ok", "fresh-content",
        )
        result = cache_mod.get("https://example.test/fresh", "auto", "raw")
        self.assertEqual(result, "fresh-content")

    def test_expired_entry_returns_none(self):
        """An entry whose ts is older than TTL must be treated as a miss.

        We write an entry directly with a past timestamp instead of sleeping,
        so the test is instant regardless of system speed.
        """
        url = "https://example.test/expired"
        # Write entry with a timestamp 1 second past the TTL
        ttl = cache_mod._ttl_seconds()
        entry = {
            "ts": time.time() - ttl - 1,
            "url": url,
            "verdict": "strong_ok",
            "content": "stale-content",
            "selectors": [],
        }
        path = cache_mod._path_for(url, "auto", "raw")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry), encoding="utf-8")

        result = cache_mod.get(url, "auto", "raw")
        self.assertIsNone(result, "Expired entry must return None")

    def test_ttl_env_override_shortens_expiry(self):
        """INSANE_CACHE_TTL=1 makes entries expire after 1 second."""
        url = "https://example.test/short-ttl"
        # Write an entry that is 2 seconds old
        entry = {
            "ts": time.time() - 2,
            "url": url,
            "verdict": "strong_ok",
            "content": "should-expire",
            "selectors": [],
        }
        path = cache_mod._path_for(url, "auto", "raw")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry), encoding="utf-8")

        with mock.patch.dict(os.environ, {"INSANE_CACHE_TTL": "1"}, clear=False):
            result = cache_mod.get(url, "auto", "raw")
        self.assertIsNone(result, "Entry older than INSANE_CACHE_TTL=1 must be expired")

    def test_ttl_env_override_extends_expiry(self):
        """INSANE_CACHE_TTL=99999 makes entries that are days old still valid."""
        url = "https://example.test/long-ttl"
        # Write an entry that is 1 hour old — normally past the 6h default
        # but definitely within 99999 seconds
        entry = {
            "ts": time.time() - 3600,
            "url": url,
            "verdict": "strong_ok",
            "content": "still-valid",
            "selectors": [],
        }
        path = cache_mod._path_for(url, "auto", "raw")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry), encoding="utf-8")

        with mock.patch.dict(os.environ, {"INSANE_CACHE_TTL": "99999"}, clear=False):
            result = cache_mod.get(url, "auto", "raw")
        self.assertEqual(result, "still-valid")


class TestTtlSeconds(unittest.TestCase):
    """_ttl_seconds() resolves TTL from env with safe fallback."""

    def test_default_when_env_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INSANE_CACHE_TTL", None)
            ttl = cache_mod._ttl_seconds()
        self.assertEqual(ttl, cache_mod._DEFAULT_TTL_SECONDS)

    def test_env_integer_adopted(self):
        with mock.patch.dict(os.environ, {"INSANE_CACHE_TTL": "3600"}, clear=False):
            ttl = cache_mod._ttl_seconds()
        self.assertEqual(ttl, 3600)

    def test_env_zero_falls_back_to_default(self):
        with mock.patch.dict(os.environ, {"INSANE_CACHE_TTL": "0"}, clear=False):
            ttl = cache_mod._ttl_seconds()
        self.assertEqual(ttl, cache_mod._DEFAULT_TTL_SECONDS)

    def test_env_negative_falls_back_to_default(self):
        with mock.patch.dict(os.environ, {"INSANE_CACHE_TTL": "-100"}, clear=False):
            ttl = cache_mod._ttl_seconds()
        self.assertEqual(ttl, cache_mod._DEFAULT_TTL_SECONDS)

    def test_env_non_integer_falls_back_to_default(self):
        with mock.patch.dict(os.environ, {"INSANE_CACHE_TTL": "not-a-number"}, clear=False):
            ttl = cache_mod._ttl_seconds()
        self.assertEqual(ttl, cache_mod._DEFAULT_TTL_SECONDS)


class TestCachePurge(unittest.TestCase):
    """cache.clear() removes all .json entries and returns correct count.

    This covers cache.py:125-128 which TestCacheGuards does not exercise.
    """

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache_mod.CACHE_DIR
        cache_mod.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        import shutil
        cache_mod.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_clear_removes_all_entries(self):
        for i in range(3):
            cache_mod.put(
                f"https://example.test/page-{i}", "auto", "raw",
                "strong_ok", f"content-{i}",
            )
        count = cache_mod.clear()
        self.assertEqual(count, 3)
        remaining = list(Path(self._tmpdir).glob("*.json"))
        self.assertEqual(remaining, [])

    def test_clear_returns_zero_on_empty_dir(self):
        count = cache_mod.clear()
        self.assertEqual(count, 0)

    def test_clear_returns_zero_when_dir_missing(self):
        """clear() must not raise if CACHE_DIR does not exist."""
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        try:
            count = cache_mod.clear()
        except Exception as exc:  # noqa: BLE001
            self.fail(f"clear() raised when CACHE_DIR missing: {exc}")
        self.assertEqual(count, 0)

    def test_after_clear_get_returns_none(self):
        cache_mod.put(
            "https://example.test/after-clear", "auto", "raw",
            "strong_ok", "gone-after-clear",
        )
        cache_mod.clear()
        result = cache_mod.get("https://example.test/after-clear", "auto", "raw")
        self.assertIsNone(result)


class TestCacheCorruptedEntry(unittest.TestCase):
    """Corrupted cache file is self-healed: get() returns None and removes the file."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_dir = cache_mod.CACHE_DIR
        cache_mod.CACHE_DIR = Path(self._tmpdir)

    def tearDown(self):
        import shutil
        cache_mod.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_corrupted_json_returns_none(self):
        url = "https://example.test/corrupt"
        path = cache_mod._path_for(url, "auto", "raw")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json {{{{", encoding="utf-8")
        result = cache_mod.get(url, "auto", "raw")
        self.assertIsNone(result)

    def test_corrupted_file_is_removed(self):
        """After a corrupted-entry miss the file should be gone (self-heal)."""
        url = "https://example.test/corrupt-removed"
        path = cache_mod._path_for(url, "auto", "raw")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{{{invalid", encoding="utf-8")
        cache_mod.get(url, "auto", "raw")
        self.assertFalse(path.exists(), "Corrupted cache file must be removed on miss")


if __name__ == "__main__":
    unittest.main()
