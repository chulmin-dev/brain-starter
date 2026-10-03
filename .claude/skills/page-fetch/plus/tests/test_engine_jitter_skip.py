"""Patch queue #6 — strong_ok / weak_ok skips the terminal politeness jitter.

UPSTREAM.md item #6: when a grid attempt produces STRONG_OK or WEAK_OK,
`fetch()` is about to return. The trailing `time.sleep(jitter)` is wasted
(no next attempt will be issued) and adds 150-400 ms per successful retry
under default `INSANE_JITTER_MS_*`. The fix moves the sleep AFTER the
verdict check so it only runs on the continuing path.

Tests assert behavioural invariants via two seams:
  1. Replace `engine.fetch_chain._run_attempt` with a scripted verdict
     factory (probe + grid sequence). This bypasses real validators / WAF
     detection so verdict is deterministic.
  2. Replace `engine.fetch_chain.time` with a spy that records every
     `sleep()` call. Asserts pin the exact call count and that the value is
     within the configured jitter range.

A `curl_cffi` stub is still required because `fetch()` constructs a
`Session()` at entry (cookie-jar share — patch #5). The stub Session is
inert: its `.get()` is never reached because `_run_attempt` is mocked.
"""
from __future__ import annotations

import os
import sys
import types
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

from plus.tests._engine_fake_helper import install_fake_curl_cffi_isolation


# ---------------------------------------------------------------------------
# Inert curl_cffi stub — Session() is built by fetch() but never queried.
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

    def _module_level_get(*_a, **_k):  # pragma: no cover
        raise AssertionError("module-level get() must not be reached")

    fake_requests.get = _module_level_get  # type: ignore[attr-defined]

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
# Spies
# ---------------------------------------------------------------------------

class _SleepSpy:
    """Drop-in for `time.sleep` that records arguments without sleeping."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _scripted_run_attempt(verdict_sequence):
    """Build a fake `_run_attempt` that yields the given verdicts in order.

    Each call returns `(Attempt, fake_resp)`. fake_resp is a tiny duck-typed
    object that `detect()` will look at after the probe phase to choose
    which WAF profile(s) to iterate through; we feed it a body that
    deterministically falls through to `unknown_challenge` so the grid
    iteration is bounded but reaches the patched site.
    """
    from engine.fetch_chain import Attempt
    from engine.validators import Verdict

    idx = {"i": 0}

    class _R:
        def __init__(self, url):
            self.status_code = 403
            self.text = "<html><body>blocked</body></html>"
            self.url = url
            self.headers = {}
            self.cookies = {}
            self.content = self.text.encode("utf-8")

    def _fake(url, *, transform_name, impersonate, referer_name,
              success_selectors, known_bad_sizes, timeout, phase,
              session=None, url_check=None, ip_check=None):
        i = idx["i"]
        idx["i"] += 1
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
# Test cases
# ---------------------------------------------------------------------------

class TerminalJitterSkipTest(unittest.TestCase):
    """Strong/weak OK on a grid attempt must not pay the politeness jitter."""

    def setUp(self) -> None:
        # Pin jitter env vars so the range assertion in
        # `test_non_terminating_attempt_still_jitters` is decoupled from the
        # current defaults in `fetch_chain.py` and from any developer's
        # exported env. Cleanup restores the prior values.
        self._env_snapshot = {
            k: os.environ.get(k)
            for k in ("INSANE_JITTER_MS_MIN", "INSANE_JITTER_MS_MAX")
        }
        os.environ["INSANE_JITTER_MS_MIN"] = "150"
        os.environ["INSANE_JITTER_MS_MAX"] = "400"
        self.addCleanup(self._restore_env)

        install_fake_curl_cffi_isolation(self)
        _install_inert_curl_cffi()
        self.fc = _reload_fetch_chain()

        # `_SleepSpy` intercepts only `fetch_chain.time.sleep` (the module-
        # bound `time` reference, used at the patched call site). Sleeps
        # inside `_run_attempt` or `curl_cffi` internals are out of scope —
        # in these tests they don't fire because `_run_attempt` is mocked.
        self.sleep_spy = _SleepSpy()
        self._orig_sleep = self.fc.time.sleep
        self.fc.time.sleep = self.sleep_spy
        self.addCleanup(lambda: setattr(self.fc.time, "sleep", self._orig_sleep))

    def _restore_env(self) -> None:
        for k, v in self._env_snapshot.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _patch_run_attempt(self, verdicts):
        fake = _scripted_run_attempt(verdicts)
        orig = self.fc._run_attempt
        self.fc._run_attempt = fake
        self.addCleanup(lambda: setattr(self.fc, "_run_attempt", orig))

    def _fetch(self):
        # `impersonate_first="chrome"` ensures the duplicate-skip in the grid
        # loop (transform=original / impersonate=base / referer=self_root)
        # does not collapse to the same combo as the probe, so the first
        # grid iteration actually runs.
        return self.fc.fetch(
            "https://example.com/",
            user_hint={"impersonate_first": "chrome"},
            max_attempts=5,
            enable_playwright=False,
        )

    def test_strong_ok_in_grid_skips_terminal_jitter(self) -> None:
        from engine.validators import Verdict

        self._patch_run_attempt([
            Verdict.CHALLENGE.value,   # probe: forces phase-2 entry
            Verdict.STRONG_OK.value,   # grid[0]: terminates fetch()
        ])

        result = self._fetch()

        self.assertTrue(result.ok, result.summary)
        self.assertEqual(result.verdict, Verdict.STRONG_OK.value)
        self.assertEqual(
            self.sleep_spy.calls,
            [],
            "STRONG_OK on the first grid attempt must not trigger the "
            "trailing politeness jitter (patch queue #6).",
        )

    def test_weak_ok_in_grid_skips_terminal_jitter(self) -> None:
        from engine.validators import Verdict

        self._patch_run_attempt([
            Verdict.CHALLENGE.value,   # probe
            Verdict.WEAK_OK.value,     # grid[0]: WEAK_OK still returns
        ])

        result = self._fetch()

        self.assertTrue(result.ok, result.summary)
        self.assertEqual(result.verdict, Verdict.WEAK_OK.value)
        self.assertEqual(self.sleep_spy.calls, [])

    def test_non_terminating_attempt_still_jitters(self) -> None:
        """CHALLENGE -> CHALLENGE -> STRONG_OK should sleep exactly once,
        after the non-terminating CHALLENGE in the middle."""
        from engine.validators import Verdict

        self._patch_run_attempt([
            Verdict.CHALLENGE.value,   # probe (no jitter — pre-grid)
            Verdict.CHALLENGE.value,   # grid[0]: non-terminating -> jitter
            Verdict.STRONG_OK.value,   # grid[1]: terminating -> skip jitter
        ])

        result = self._fetch()

        self.assertTrue(result.ok, result.summary)
        self.assertEqual(
            len(self.sleep_spy.calls),
            1,
            f"Expected exactly one jitter sleep between the two grid "
            f"attempts; got {self.sleep_spy.calls}",
        )
        # Default jitter is INSANE_JITTER_MS_MIN=150, MAX=400 → 0.15..0.40 s
        slept = self.sleep_spy.calls[0]
        self.assertGreaterEqual(slept, 0.150)
        self.assertLessEqual(slept, 0.400)

    def test_resp_none_attempt_still_jitters(self) -> None:
        """A `_run_attempt` returning `(att, None)` (transport failure) must
        still jitter before the next iteration — that path is exactly what
        the IP-reputation backoff was designed for."""
        from engine.fetch_chain import Attempt
        from engine.validators import Verdict

        idx = {"i": 0}

        def _fake(url, *, transform_name, impersonate, referer_name,
                  success_selectors, known_bad_sizes, timeout, phase,
                  session=None, url_check=None, ip_check=None):
            i = idx["i"]
            idx["i"] += 1
            att = Attempt(
                phase=phase,
                executor="curl_cffi",
                url=url,
                url_transform=transform_name,
                impersonate=impersonate or "",
                referer=referer_name or "",
                verdict=Verdict.UNKNOWN.value,
                error="transport_failed" if i == 1 else None,
            )
            if i == 0:
                # probe — return a synthetic CHALLENGE response so phase 2
                # is entered.
                class _R:
                    status_code = 403
                    text = "<html>blocked</html>"
                    url = "https://example.com/"
                    headers: dict = {}
                    cookies: dict = {}
                    content = b"<html>blocked</html>"
                att.verdict = Verdict.CHALLENGE.value
                return att, _R()
            if i == 1:
                # grid[0] — transport failure (resp=None). Engine should
                # take the jitter path before the next iteration.
                return att, None
            # grid[1] — strong_ok terminates.
            att.verdict = Verdict.STRONG_OK.value
            class _R2:
                status_code = 200
                text = "<html>ok</html>"
                url = "https://example.com/"
                headers: dict = {}
                cookies: dict = {}
                content = b"<html>ok</html>"
            return att, _R2()

        orig = self.fc._run_attempt
        self.fc._run_attempt = _fake
        self.addCleanup(lambda: setattr(self.fc, "_run_attempt", orig))

        result = self._fetch()

        self.assertTrue(result.ok, result.summary)
        self.assertEqual(
            len(self.sleep_spy.calls),
            1,
            "Transport failure (resp=None) must still trigger one jitter "
            "before the next attempt.",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
