"""Tests for --aggressive / INSANE_AGGRESSIVE opt-in mode.

Verifies four behavioural contracts:
  1. --aggressive flag sets expand_unknown_challenge=True in user_hint,
     raises max_attempts to 60, and passes enable_playwright=True.
  2. INSANE_AGGRESSIVE=1 (and truthy variants) does the same as the flag.
  3. DEFAULT (neither flag nor env) leaves engine_fetch call args IDENTICAL
     to the pre-feature baseline (user_hint=None, max_attempts=12).
  4. SSRF guard and IP-pin guards are NOT disabled in aggressive mode
     (aggressive = more attempts, not fewer safety checks).
"""
from __future__ import annotations

import io
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import plus.__main__ as cli_mod
import plus as _plus_pkg


# ---------------------------------------------------------------------------
# Helper: build a minimal argparse.Namespace that _cmd_fetch accepts
# ---------------------------------------------------------------------------
def _make_args(**overrides):
    import argparse
    defaults = dict(
        url="https://example.com/",
        fmt="raw",
        recall=False,
        precision=False,
        query=None,
        prune=False,
        selectors=None,
        device="auto",
        cache=False,
        cache_weak=False,
        doh="auto",
        timeout=25,
        json=False,
        trace=False,
        no_phase0=True,   # skip phase0 to isolate engine_fetch call
        aggressive=False,
        max_attempts=None,  # M1: default None → 12 in _cmd_fetch
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Core helper: run _cmd_fetch with all I/O and engine dependencies faked.
# Uses the same injection pattern as test_cli_output.py: mutate plus.__dict__
# AND sys.modules so `from . import x` resolves to the fake.
# Returns the kwargs dict that engine_fetch was called with.
# ---------------------------------------------------------------------------
def _run_cmd_fetch_capture_engine_call(args, env_patch=None):
    """Run _cmd_fetch and return engine_fetch's call kwargs.

    engine_patch is a dict of env vars to inject (or None).
    Returns (exit_code, engine_fetch_call_kwargs).
    """
    fake_result = MagicMock()
    fake_result.ok = True
    fake_result.verdict = "strong_ok"
    fake_result.profile_used = "test"
    fake_result.final_url = "https://example.com/"
    fake_result.content = "<html>ok</html>"
    fake_result.trace = []
    fake_result.untried_routes = []
    fake_result.must_invoke_playwright_mcp = False
    fake_result.grid_exhausted = False
    fake_result.stop_reason = None

    fake_engine_fetch = MagicMock(return_value=fake_result)
    fake_engine_module = MagicMock()
    fake_engine_module.fetch = fake_engine_fetch

    fake_doh = MagicMock()
    fake_doh.setup.return_value = "doh=off"

    fake_cache = MagicMock()
    fake_cache.get.return_value = None  # cache miss

    fake_extract_mod = MagicMock()
    fake_extract_mod.extract = MagicMock(return_value="body text")

    # plus.binary_extract: looks_like_binary_doc must return False so the binary path
    # is skipped. _cmd_fetch does `from .binary_extract import looks_like_binary_doc`.
    fake_binary_extract = MagicMock()
    fake_binary_extract.looks_like_binary_doc = lambda url: False

    # Inject into package __dict__ + sys.modules (same pattern as test_cli_output.py).
    # `from . import x` resolves via the *package* attribute (sys.modules['plus'].x),
    # NOT sys.modules['plus.x'], so we must set both.
    saved = {k: _plus_pkg.__dict__.get(k)
             for k in ("cache", "doh", "extract", "binary_extract")}

    buf = io.StringIO()
    stderr_buf = io.StringIO()

    # Remove INSANE_AGGRESSIVE from env if not explicitly set in env_patch
    if env_patch is None:
        os.environ.pop("INSANE_AGGRESSIVE", None)

    env_ctx = patch.dict(os.environ, env_patch or {}, clear=False)

    try:
        _plus_pkg.__dict__["doh"] = fake_doh
        _plus_pkg.__dict__["cache"] = fake_cache
        _plus_pkg.__dict__["extract"] = fake_extract_mod
        _plus_pkg.__dict__["binary_extract"] = fake_binary_extract

        with patch.dict(sys.modules, {
            "plus.doh": fake_doh,
            "plus.cache": fake_cache,
            "plus.extract": fake_extract_mod,
            "plus.binary_extract": fake_binary_extract,
            "engine": fake_engine_module,
        }):
            with env_ctx:
                with patch("sys.stdout", buf), patch("sys.stderr", stderr_buf):
                    exit_code = cli_mod._cmd_fetch(args)

    finally:
        for k, v in saved.items():
            if v is None:
                _plus_pkg.__dict__.pop(k, None)
            else:
                _plus_pkg.__dict__[k] = v

    return exit_code, fake_engine_fetch.call_args


class AggressiveFlagTest(unittest.TestCase):
    """--aggressive flag wires expand_unknown_challenge, max_attempts=60, enable_playwright=True."""

    def test_aggressive_flag_expands_grid(self):
        """--aggressive: expand_unknown_challenge=True in user_hint."""
        args = _make_args(aggressive=True)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertIsNotNone(call_args, "engine_fetch must have been called")
        user_hint = call_args.kwargs.get("user_hint") or {}
        self.assertTrue(
            user_hint.get("expand_unknown_challenge"),
            "expand_unknown_challenge must be True in user_hint in aggressive mode",
        )

    def test_aggressive_flag_raises_max_attempts(self):
        """--aggressive: max_attempts raised to 60."""
        args = _make_args(aggressive=True)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertEqual(
            call_args.kwargs.get("max_attempts"),
            60,
            "max_attempts must be 60 in aggressive mode",
        )

    def test_aggressive_flag_enables_playwright(self):
        """--aggressive: enable_playwright=True."""
        args = _make_args(aggressive=True)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertTrue(
            call_args.kwargs.get("enable_playwright"),
            "enable_playwright must be True in aggressive mode",
        )

    def test_aggressive_honors_higher_caller_max_attempts(self):
        """--aggressive + --max-attempts 100 → captured max_attempts is 100 (floor doesn't lower)."""
        args = _make_args(aggressive=True, max_attempts=100)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertEqual(
            call_args.kwargs.get("max_attempts"),
            100,
            "aggressive floor must NOT lower a caller value of 100",
        )

    def test_aggressive_raises_low_caller_max_attempts(self):
        """--aggressive + --max-attempts 5 → captured max_attempts is 60 (floor raises)."""
        args = _make_args(aggressive=True, max_attempts=5)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertEqual(
            call_args.kwargs.get("max_attempts"),
            60,
            "aggressive floor must raise a caller value of 5 to 60",
        )

    def test_no_aggressive_caller_max_attempts_100(self):
        """no aggressive + --max-attempts 100 → captured max_attempts is 100 (knob works alone)."""
        args = _make_args(aggressive=False, max_attempts=100)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertEqual(
            call_args.kwargs.get("max_attempts"),
            100,
            "--max-attempts knob must work without --aggressive",
        )


class AggressiveEnvTest(unittest.TestCase):
    """INSANE_AGGRESSIVE env var (truthy variants) activates aggressive mode."""

    def _is_aggressive_with_env(self, env_value: str) -> bool:
        import argparse
        args = argparse.Namespace(aggressive=False)
        with patch.dict(os.environ, {"INSANE_AGGRESSIVE": env_value}):
            return cli_mod._is_aggressive(args)

    def test_env_1(self):
        self.assertTrue(self._is_aggressive_with_env("1"))

    def test_env_true(self):
        self.assertTrue(self._is_aggressive_with_env("true"))

    def test_env_yes(self):
        self.assertTrue(self._is_aggressive_with_env("yes"))

    def test_env_on(self):
        self.assertTrue(self._is_aggressive_with_env("on"))

    def test_env_TRUE_uppercase(self):
        self.assertTrue(self._is_aggressive_with_env("TRUE"))

    def test_env_whitespace_tolerant(self):
        self.assertTrue(self._is_aggressive_with_env("  1  "))

    def test_env_0_is_falsy(self):
        self.assertFalse(self._is_aggressive_with_env("0"))

    def test_env_empty_is_falsy(self):
        self.assertFalse(self._is_aggressive_with_env(""))

    def test_env_false_is_falsy(self):
        self.assertFalse(self._is_aggressive_with_env("false"))

    def test_env_activates_expand_hint(self):
        """INSANE_AGGRESSIVE=1 via env also sets expand_unknown_challenge."""
        args = _make_args(aggressive=False)
        _, call_args = _run_cmd_fetch_capture_engine_call(
            args, env_patch={"INSANE_AGGRESSIVE": "1"}
        )
        self.assertIsNotNone(call_args)
        user_hint = call_args.kwargs.get("user_hint") or {}
        self.assertTrue(user_hint.get("expand_unknown_challenge"))

    def test_env_activates_max_attempts_60(self):
        """INSANE_AGGRESSIVE=1 via env raises max_attempts to 60."""
        args = _make_args(aggressive=False)
        _, call_args = _run_cmd_fetch_capture_engine_call(
            args, env_patch={"INSANE_AGGRESSIVE": "1"}
        )
        self.assertEqual(call_args.kwargs.get("max_attempts"), 60)


class DefaultUnchangedTest(unittest.TestCase):
    """Default (no --aggressive, no INSANE_AGGRESSIVE) must leave engine_fetch call UNCHANGED.

    Baseline call contract:
        engine_fetch(url, success_selectors=..., device_class=..., timeout=...,
                     user_hint=None, max_attempts=12, enable_playwright=True)
    """

    def test_default_user_hint_is_none(self):
        """Default: user_hint must be None (empty dict coerced to None by the impl)."""
        args = _make_args(aggressive=False)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertIsNotNone(call_args, "engine_fetch must have been called")
        user_hint = call_args.kwargs.get("user_hint")
        self.assertIsNone(
            user_hint,
            f"Default: user_hint must be None, got {user_hint!r}",
        )

    def test_default_max_attempts_is_12(self):
        """Default: max_attempts must be 12."""
        args = _make_args(aggressive=False)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertEqual(
            call_args.kwargs.get("max_attempts"),
            12,
            "Default: max_attempts must be 12 (unchanged from pre-feature baseline)",
        )

    def test_default_enable_playwright_is_true(self):
        """Default: enable_playwright must be True."""
        args = _make_args(aggressive=False)
        _, call_args = _run_cmd_fetch_capture_engine_call(args)
        self.assertTrue(call_args.kwargs.get("enable_playwright"))


class SafetyInvariantTest(unittest.TestCase):
    """Aggressive mode does NOT disable safety guards."""

    def test_ssrf_guard_still_importable(self):
        """SSRF guard must be importable — not monkey-patched away."""
        from plus._ssrf import _ssrf_guard
        self.assertTrue(callable(_ssrf_guard))

    def test_aggressive_truthy_set_is_exact(self):
        """The truthy set is exactly {1, true, yes, on} — no bypass tokens."""
        self.assertEqual(
            cli_mod._AGGRESSIVE_TRUTHY,
            frozenset({"1", "true", "yes", "on"}),
        )

    def test_aggressive_max_attempts_constant_is_60(self):
        """_AGGRESSIVE_MAX_ATTEMPTS must be exactly 60 (full 4×3×5 Akamai grid)."""
        self.assertEqual(cli_mod._AGGRESSIVE_MAX_ATTEMPTS, 60)

    def test_aggressive_does_not_set_disable_ip_pin(self):
        """Aggressive mode must not set INSANE_DISABLE_IP_PIN."""
        import argparse
        args = argparse.Namespace(aggressive=True)
        os.environ.pop("INSANE_DISABLE_IP_PIN", None)
        _ = cli_mod._is_aggressive(args)
        self.assertNotIn(
            "INSANE_DISABLE_IP_PIN", os.environ,
            "Aggressive mode must not set INSANE_DISABLE_IP_PIN — C8 IP-pin must stay on",
        )

    def test_aggressive_env_const_name(self):
        """_AGGRESSIVE_ENV constant must be exactly 'INSANE_AGGRESSIVE'."""
        self.assertEqual(cli_mod._AGGRESSIVE_ENV, "INSANE_AGGRESSIVE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
