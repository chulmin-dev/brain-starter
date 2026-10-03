"""Tests for P9 — CLI output contract.

Covers:
  - _configure_streams: UTF-8 reconfigure called on stdout/stderr
  - cache-hit path: --json envelope produced (ok/verdict/format/content)
  - cache-hit path: _wrap_for_llm applied on plain output
  - cache-hit vs cache-miss: output format parity (key set matches)
"""
from __future__ import annotations

import io
import json
import sys
import unittest
from unittest.mock import MagicMock, patch

import plus.__main__ as cli_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fetch_args(*, json_flag=False, fmt="raw"):
    args = MagicMock()
    args.url = "https://example.com/"
    args.device = "auto"
    args.fmt = fmt
    args.selectors = None
    args.cache = True
    args.cache_weak = False  # MagicMock attribute is truthy by default; pin to False
    args.json = json_flag
    args.trace = False
    args.timeout = 25
    return args


def _run_cmd_fetch_with_cache_hit(hit_content, json_flag=False, fmt="raw"):
    """Execute _cmd_fetch against a cache hit and return (exit_code, stdout_str)."""
    args = _make_fetch_args(json_flag=json_flag, fmt=fmt)

    fake_cache = MagicMock()
    fake_cache.get.return_value = hit_content

    fake_doh = MagicMock()
    fake_doh.setup.return_value = ""

    fake_observe = MagicMock()

    buf = io.StringIO()
    stderr_buf = io.StringIO()

    # _cmd_fetch does `from . import cache, doh, observe`.
    # `from . import x` resolves via the package object's attribute
    # (sys.modules['plus'].x), NOT via sys.modules['plus.x'].
    # patch.dict(sys.modules) only replaces the dict entry and does NOT update
    # the package object, so fakes are invisible to `from . import`.
    # We inject fakes into both sys.modules AND the package __dict__ directly
    # so that `from . import` picks up the fake regardless of prior import state.
    import plus as _plus_pkg
    fake_extract = MagicMock()
    saved = {k: _plus_pkg.__dict__.get(k) for k in ("cache", "doh", "observe", "extract")}
    try:
        _plus_pkg.__dict__["cache"] = fake_cache
        _plus_pkg.__dict__["doh"] = fake_doh
        _plus_pkg.__dict__["observe"] = fake_observe
        _plus_pkg.__dict__["extract"] = fake_extract
        with patch.dict(sys.modules, {
            "plus.cache": fake_cache,
            "plus.doh": fake_doh,
            "plus.observe": fake_observe,
            "plus.extract": fake_extract,
        }):
            with patch("sys.stdout", buf), patch("sys.stderr", stderr_buf):
                code = cli_mod._cmd_fetch(args)
    finally:
        for k, v in saved.items():
            if v is None:
                _plus_pkg.__dict__.pop(k, None)
            else:
                _plus_pkg.__dict__[k] = v

    return code, buf.getvalue()


# ---------------------------------------------------------------------------
# Tests: _configure_streams
# ---------------------------------------------------------------------------

class TestConfigureStreams(unittest.TestCase):

    def test_reconfigure_called_on_both_streams(self):
        fake_stdout = MagicMock()
        fake_stderr = MagicMock()
        with patch.object(sys, "stdout", fake_stdout):
            with patch.object(sys, "stderr", fake_stderr):
                cli_mod._configure_streams()

        fake_stdout.reconfigure.assert_called_once_with(
            encoding="utf-8", errors="backslashreplace"
        )
        fake_stderr.reconfigure.assert_called_once_with(
            encoding="utf-8", errors="backslashreplace"
        )

    def test_missing_reconfigure_emits_warning_not_silent(self):
        """When reconfigure is absent AND buffer swap fails, a warning goes to stderr."""
        bare_stream = MagicMock(spec=[])  # no reconfigure, no buffer

        captured = io.StringIO()
        with patch.object(sys, "stdout", bare_stream):
            with patch.object(sys, "stderr", captured):
                cli_mod._configure_streams()

        output = captured.getvalue()
        self.assertIn("stdout", output)
        self.assertIn("warning", output.lower())


# ---------------------------------------------------------------------------
# Tests: cache-hit JSON output
# ---------------------------------------------------------------------------

class TestCacheHitJsonOutput(unittest.TestCase):

    def test_cache_hit_json_has_required_fields(self):
        code, out = _run_cmd_fetch_with_cache_hit(
            "<html>cached</html>", json_flag=True, fmt="markdown"
        )
        self.assertEqual(code, 0)
        self.assertTrue(out.strip(), "Expected JSON output, got empty string")
        data = json.loads(out.strip())
        self.assertTrue(data["ok"])
        self.assertEqual(data["verdict"], "cache")
        self.assertEqual(data["content"], "<html>cached</html>")
        self.assertEqual(data["format"], "markdown")
        self.assertEqual(data["attempts"], 0)

    def test_cache_hit_plain_applies_wrap_for_llm(self):
        hit = "<html>cached content</html>"
        wrapped = "[external_data:url=example.com]" + hit + "[/external_data]"

        args = _make_fetch_args(json_flag=False, fmt="raw")
        fake_cache = MagicMock()
        fake_cache.get.return_value = hit
        fake_doh = MagicMock()
        fake_doh.setup.return_value = ""

        buf = io.StringIO()
        fake_observe = MagicMock()
        fake_extract = MagicMock()

        import plus as _plus_pkg
        saved = {k: _plus_pkg.__dict__.get(k) for k in ("cache", "doh", "observe", "extract")}
        try:
            _plus_pkg.__dict__["cache"] = fake_cache
            _plus_pkg.__dict__["doh"] = fake_doh
            _plus_pkg.__dict__["observe"] = fake_observe
            _plus_pkg.__dict__["extract"] = fake_extract
            with patch.dict(sys.modules, {
                "plus.cache": fake_cache,
                "plus.doh": fake_doh,
                "plus.observe": fake_observe,
                "plus.extract": fake_extract,
            }):
                with patch("sys.stdout", buf), patch("sys.stderr", io.StringIO()):
                    with patch.object(cli_mod, "_wrap_for_llm", return_value=wrapped) as mock_wrap:
                        code = cli_mod._cmd_fetch(args)
        finally:
            for k, v in saved.items():
                if v is None:
                    _plus_pkg.__dict__.pop(k, None)
                else:
                    _plus_pkg.__dict__[k] = v

        self.assertEqual(code, 0)
        mock_wrap.assert_called_once_with(hit, "https://example.com/")
        self.assertIn(wrapped, buf.getvalue())

    def test_cache_hit_json_keys_match_miss_envelope(self):
        """JSON envelope keys from a cache hit match those from a cache miss."""
        expected_keys = {"ok", "verdict", "profile_used", "final_url",
                         "format", "attempts", "content"}

        code, out = _run_cmd_fetch_with_cache_hit("body text", json_flag=True)
        self.assertEqual(code, 0)
        data = json.loads(out.strip())
        self.assertEqual(set(data.keys()), expected_keys)

    def test_no_early_return_bypasses_json_flag(self):
        """Cache hit with json=False must not emit JSON-looking output."""
        code, out = _run_cmd_fetch_with_cache_hit("plain body", json_flag=False)
        self.assertEqual(code, 0)
        # Output should not be parseable as JSON (it's raw body text)
        with self.assertRaises((json.JSONDecodeError, ValueError)):
            json.loads(out.strip())


if __name__ == "__main__":
    unittest.main()
