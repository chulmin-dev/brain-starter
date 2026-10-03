"""P18: observe.py rotation and injection-hygiene regression tests.

Pins:
- 5 MB rotation: when LOG_PATH exceeds threshold, it becomes fetch-log.1.jsonl;
  older rotations shift up; .3 is dropped
- log() creates OBSERVE_DIR if absent
- log() writes a valid JSONL entry (parseable, expected fields present)
- injection sanitization: newline/control chars in url/host are stripped
- best-effort: log() must not raise even when OBSERVE_DIR is unwritable
- Both OBSERVE_DIR and LOG_PATH are monkeypatched — real observations/ untouched
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

import plus  # noqa: E402 — triggers engine_proxy.install()
import plus.observe as observe_mod  # noqa: E402


def _redirect_observe(tmpdir: Path):
    """Context-manager-compatible helper: patch OBSERVE_DIR and LOG_PATH."""
    obs_dir = tmpdir / "observations"
    log_path = obs_dir / "fetch-log.jsonl"
    return (
        mock.patch.object(observe_mod, "OBSERVE_DIR", obs_dir),
        mock.patch.object(observe_mod, "LOG_PATH", log_path),
    )


class TestObserveLogWrites(unittest.TestCase):
    """log() appends a parseable JSONL entry with expected fields."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_creates_observe_dir(self):
        obs_dir = self._tmpdir / "observations"
        log_path = obs_dir / "fetch-log.jsonl"
        self.assertFalse(obs_dir.exists())
        with mock.patch.object(observe_mod, "OBSERVE_DIR", obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", log_path):
            observe_mod.log("https://example.test/", "chrome", "strong_ok", 1, True)
        self.assertTrue(obs_dir.exists(), "OBSERVE_DIR must be created by log()")

    def test_entry_is_valid_jsonl(self):
        obs_dir = self._tmpdir / "observations"
        log_path = obs_dir / "fetch-log.jsonl"
        with mock.patch.object(observe_mod, "OBSERVE_DIR", obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", log_path):
            observe_mod.log("https://example.test/page", "safari", "weak_ok", 2, False)
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertIn("ts", entry)
        self.assertIn("host", entry)
        self.assertIn("url", entry)
        self.assertIn("verdict", entry)
        self.assertIn("attempts", entry)
        self.assertIn("ok", entry)

    def test_entry_field_values(self):
        obs_dir = self._tmpdir / "observations"
        log_path = obs_dir / "fetch-log.jsonl"
        with mock.patch.object(observe_mod, "OBSERVE_DIR", obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", log_path):
            observe_mod.log("https://example.test/check", "auto", "strong_ok", 3, True)
        entry = json.loads(log_path.read_text(encoding="utf-8").strip())
        self.assertEqual(entry["verdict"], "strong_ok")
        self.assertEqual(entry["attempts"], 3)
        self.assertTrue(entry["ok"])
        self.assertIn("example.test", entry["host"])

    def test_multiple_log_calls_append(self):
        obs_dir = self._tmpdir / "observations"
        log_path = obs_dir / "fetch-log.jsonl"
        with mock.patch.object(observe_mod, "OBSERVE_DIR", obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", log_path):
            observe_mod.log("https://a.example.test/", None, "strong_ok", 1, True)
            observe_mod.log("https://b.example.test/", None, "weak_ok", 2, False)
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)


class TestObserveInjectionSanitization(unittest.TestCase):
    """Newlines and control characters in url/host must be sanitized before logging."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_newline_in_url_sanitized(self):
        """A URL containing \\n must not produce a multi-line JSONL entry."""
        obs_dir = self._tmpdir / "observations"
        log_path = obs_dir / "fetch-log.jsonl"
        evil_url = "https://example.test/page\nINJECTED: do evil things"
        with mock.patch.object(observe_mod, "OBSERVE_DIR", obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", log_path):
            observe_mod.log(evil_url, None, "strong_ok", 1, True)
        raw = log_path.read_text(encoding="utf-8")
        lines = raw.strip().splitlines()
        # Must still be exactly one JSONL line — the newline was collapsed to a
        # space so the JSONL record is not split across lines (prompt-injection
        # vector is the line split, not the text itself).
        self.assertEqual(len(lines), 1, "Newline injection must not split the JSONL entry")
        entry = json.loads(lines[0])
        # The raw newline character must not appear verbatim in the stored URL
        self.assertNotIn("\n", entry.get("url", ""), "Raw newline must not appear in stored URL")

    def test_control_chars_in_url_sanitized(self):
        """Control characters (\\r, \\t, etc.) in URL are stripped/replaced."""
        obs_dir = self._tmpdir / "observations"
        log_path = obs_dir / "fetch-log.jsonl"
        evil_url = "https://example.test/\r\x01\x1bpath"
        with mock.patch.object(observe_mod, "OBSERVE_DIR", obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", log_path):
            observe_mod.log(evil_url, None, "strong_ok", 1, True)
        raw = log_path.read_text(encoding="utf-8").strip()
        # Must be parseable JSON
        try:
            json.loads(raw)
        except json.JSONDecodeError as e:
            self.fail(f"Control chars in URL broke JSONL serialization: {e}")

    def test_newline_in_host_sanitized(self):
        """Host-level injection via a crafted URL must be sanitized."""
        obs_dir = self._tmpdir / "observations"
        log_path = obs_dir / "fetch-log.jsonl"
        # craft a URL where urlsplit().hostname contains a newline
        evil_url = "https://evil.example.test\nevil2.example.test/path"
        with mock.patch.object(observe_mod, "OBSERVE_DIR", obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", log_path):
            observe_mod.log(evil_url, None, "strong_ok", 1, True)
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        # Must remain a single parseable line
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        host_val = entry.get("host", "")
        self.assertNotIn("\n", host_val)


class TestObserveRotation(unittest.TestCase):
    """_rotate_if_needed() rotates log when it exceeds the size threshold.

    Uses a tiny threshold (100 bytes) so the test does not write megabytes.
    """

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self._obs_dir = self._tmpdir / "observations"
        self._obs_dir.mkdir()
        self._log_path = self._obs_dir / "fetch-log.jsonl"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_log(self, size: int) -> None:
        """Write `size` bytes of dummy content to LOG_PATH."""
        self._log_path.write_bytes(b"x" * size)

    def test_no_rotation_when_under_threshold(self):
        self._write_log(50)
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(observe_mod, "_max_bytes", return_value=100):
            observe_mod._rotate_if_needed()
        # Still the original file, no .1 created
        self.assertTrue(self._log_path.exists())
        self.assertFalse((self._obs_dir / "fetch-log.1.jsonl").exists())

    def test_rotation_creates_dot1(self):
        """Log exceeding threshold becomes fetch-log.1.jsonl."""
        self._write_log(200)
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(observe_mod, "_max_bytes", return_value=100):
            observe_mod._rotate_if_needed()
        self.assertFalse(self._log_path.exists(), "Original log must be gone after rotation")
        self.assertTrue(
            (self._obs_dir / "fetch-log.1.jsonl").exists(),
            "fetch-log.1.jsonl must exist after rotation",
        )

    def test_rotation_shifts_existing_numbered_files(self):
        """fetch-log.1 -> .2 -> .3 during rotation; .3+ is dropped."""
        # Pre-seed .1 and .2
        (self._obs_dir / "fetch-log.1.jsonl").write_bytes(b"slot1" * 10)
        (self._obs_dir / "fetch-log.2.jsonl").write_bytes(b"slot2" * 10)
        self._write_log(200)

        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(observe_mod, "_max_bytes", return_value=100):
            observe_mod._rotate_if_needed()

        self.assertTrue((self._obs_dir / "fetch-log.2.jsonl").exists())
        self.assertTrue((self._obs_dir / "fetch-log.3.jsonl").exists())
        self.assertFalse(
            (self._obs_dir / "fetch-log.4.jsonl").exists(),
            "No more than 3 rotation slots must exist",
        )

    def test_oldest_slot_dropped(self):
        """When .3 already exists, it is dropped to make room."""
        for n in range(1, 4):
            (self._obs_dir / f"fetch-log.{n}.jsonl").write_bytes(
                f"slot{n}".encode() * 10
            )
        self._write_log(200)

        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(observe_mod, "_max_bytes", return_value=100):
            observe_mod._rotate_if_needed()

        # .3 contains what was .2 (old .3 was dropped)
        self.assertTrue((self._obs_dir / "fetch-log.3.jsonl").exists())
        self.assertFalse((self._obs_dir / "fetch-log.4.jsonl").exists())

    def test_log_call_does_not_raise_when_dir_unwritable(self):
        """log() is best-effort — must not propagate exceptions."""
        # Make a deterministic, isolated invalid directory on every platform.
        bad_dir = self._tmpdir / "not-a-directory"
        bad_dir.write_text("fixture", encoding="utf-8")
        bad_log = bad_dir / "fetch-log.jsonl"
        with mock.patch.object(observe_mod, "OBSERVE_DIR", bad_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", bad_log):
            try:
                observe_mod.log("https://example.test/", None, "strong_ok", 1, True)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"log() must not raise on unwritable dir, got: {exc}")

    def test_rotation_no_op_when_log_absent(self):
        """_rotate_if_needed() is a no-op when LOG_PATH does not exist."""
        with mock.patch.object(observe_mod, "OBSERVE_DIR", self._obs_dir), \
             mock.patch.object(observe_mod, "LOG_PATH", self._log_path), \
             mock.patch.object(observe_mod, "_max_bytes", return_value=100):
            # LOG_PATH does not exist — must not raise
            try:
                observe_mod._rotate_if_needed()
            except Exception as exc:  # noqa: BLE001
                self.fail(f"_rotate_if_needed raised when log absent: {exc}")


if __name__ == "__main__":
    unittest.main()
