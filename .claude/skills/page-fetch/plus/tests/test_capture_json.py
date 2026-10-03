"""Tests for P32 — opt-in CDP NetworkJournal JSON-capture envelope.

ADAPT-1 update (Wave 4): real_chrome now ALWAYS requests captureCookies=True so
the reverse cookie bridge (Chrome→curl) can persist clearance tokens. This means
the envelope is ALWAYS parsed for real_chrome (not only when capture_json=True).
The contract is now:

  * Default (capture_json=False, real_chrome): stdout is a {html,captured_cookies}
    envelope. The executor unwraps it, validates on the HTML half, populates
    Attempt.captured_cookies; Attempt.captured_json stays None.
  * Default (capture_json=False, non-real_chrome): stdout is raw HTML (mobile
    template is excluded from captureCookies). Unchanged.
  * Capture mode (capture_json=True, real_chrome): envelope is {html,
    captured_json, captured_cookies}; both fields populated on Attempt.
  * Capture mode requested but executor is NOT real_chrome → flag ignored.
  * A malformed/non-JSON stdout degrades to raw-HTML treatment (never fatal).

No network, no node subprocess: the node template itself is covered by
`node --check` in offline checks.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

import engine.executor as executor
from engine.validators import Verdict


# HTML that validates as a clean success (so the default verdict path is
# exercised). Must clear validators.SMALL_BODY_THRESHOLD (3000 bytes) so a
# selector-less validation lands on WEAK_OK (a terminal OK verdict) rather than
# CHALLENGE — this keeps the tests focused on envelope behaviour, not validator
# tuning.
_OK_HTML = (
    "<html><head><title>Article</title></head><body><article>"
    "<h1>Real Content</h1>"
    + "<p>Substantial body paragraph with plenty of words to read. </p>" * 80
    + "</article></body></html>"
)


def _fake_node(stdout: str):
    """Build a _run_node_template stand-in returning (rc=0, stdout, stderr)."""
    def _run(template, args, timeout=90):
        # capture the args the executor built so tests can assert on captureJson
        _run.last_args = args
        return 0, stdout, ""
    _run.last_args = None
    return _run


class TestDefaultContractUnchanged(unittest.TestCase):
    """Default path (capture_json=False) for real_chrome.

    ADAPT-1: real_chrome always requests captureCookies=True, so the executor
    always parses the envelope for real_chrome. The HTML half is unwrapped and
    validated exactly as before; captured_json stays None (only populated when
    capture_json=True is passed explicitly).
    """

    def test_raw_html_stdout_degrades_gracefully(self):
        # If stdout is not JSON (e.g. template ran without captureCookies support),
        # the executor falls back to treating it as raw HTML — never fatal.
        fake = _fake_node(_OK_HTML)
        with mock.patch.object(executor, "_run_node_template", fake), \
             mock.patch.object(executor, "_chrome_channel_available", return_value=True):
            att, html = executor.run_playwright_fallback(
                "https://example.com/a",
                profile_id="unknown_challenge",
                force_executor="playwright_real_chrome",
            )
        # Malformed envelope → raw HTML fallback; validation still runs.
        self.assertEqual(html, _OK_HTML)
        self.assertIsNone(att.captured_json)
        self.assertEqual(att.verdict, Verdict.WEAK_OK.value)
        # No captureJson flag was sent (only captureCookies is always set).
        self.assertNotIn("captureJson", fake.last_args)
        # captureCookies IS set for real_chrome (ADAPT-1).
        self.assertTrue(fake.last_args.get("captureCookies"))

    def test_envelope_parsed_without_capture_json_flag(self):
        # ADAPT-1: real_chrome always uses captureCookies, so the envelope IS
        # parsed even when capture_json=False. html is unwrapped; captured_json
        # stays None (not populated without the explicit capture_json=True flag).
        envelope = json.dumps({"html": _OK_HTML, "captured_cookies": []})
        fake = _fake_node(envelope)
        with mock.patch.object(executor, "_run_node_template", fake), \
             mock.patch.object(executor, "_chrome_channel_available", return_value=True):
            att, html = executor.run_playwright_fallback(
                "https://example.com/a",
                profile_id="unknown_challenge",
                force_executor="playwright_real_chrome",
            )
        # Envelope was parsed: html is unwrapped (not the raw JSON string).
        self.assertEqual(html, _OK_HTML)
        # captured_json stays None — only populated with capture_json=True.
        self.assertIsNone(att.captured_json)
        self.assertEqual(att.verdict, Verdict.WEAK_OK.value)


class TestCaptureModeUnwrapsEnvelope(unittest.TestCase):
    """capture_json=True → unwrap {html, captured_json}, validate on html."""

    def test_envelope_unwrapped_and_json_stashed(self):
        captured = [
            {"url": "https://example.com/api/items",
             "status": 200, "body": '{"items":[1,2,3]}'},
        ]
        envelope = json.dumps({"html": _OK_HTML, "captured_json": captured})
        fake = _fake_node(envelope)
        with mock.patch.object(executor, "_run_node_template", fake), \
             mock.patch.object(executor, "_chrome_channel_available", return_value=True):
            att, html = executor.run_playwright_fallback(
                "https://example.com/a",
                profile_id="unknown_challenge",
                force_executor="playwright_real_chrome",
                capture_json=True,
            )
        # Validation ran on the HTML half (verdict gates unchanged).
        self.assertEqual(html, _OK_HTML)
        self.assertEqual(att.verdict, Verdict.WEAK_OK.value)
        # Captured XHR/fetch JSON bodies surfaced on the Attempt.
        self.assertEqual(att.captured_json, captured)
        # captureJson flag WAS sent to the real_chrome template.
        self.assertTrue(fake.last_args.get("captureJson"))

    def test_capture_flag_ignored_for_non_real_chrome(self):
        # Mobile template doesn't support the envelope; flag must be dropped and
        # stdout treated as raw HTML.
        fake = _fake_node(_OK_HTML)
        with mock.patch.object(executor, "_run_node_template", fake), \
             mock.patch.object(executor, "_chrome_channel_available", return_value=True):
            att, html = executor.run_playwright_fallback(
                "https://example.com/a",
                profile_id="unknown_challenge",
                force_executor="playwright_mobile_chrome",
                capture_json=True,
            )
        self.assertEqual(html, _OK_HTML)
        self.assertIsNone(att.captured_json)
        self.assertNotIn("captureJson", fake.last_args)

    def test_malformed_envelope_degrades_to_raw_html(self):
        # capture mode requested but stdout isn't valid JSON → treat as raw HTML
        # rather than failing the attempt.
        fake = _fake_node(_OK_HTML)  # not a JSON envelope
        with mock.patch.object(executor, "_run_node_template", fake), \
             mock.patch.object(executor, "_chrome_channel_available", return_value=True):
            att, html = executor.run_playwright_fallback(
                "https://example.com/a",
                profile_id="unknown_challenge",
                force_executor="playwright_real_chrome",
                capture_json=True,
            )
        self.assertEqual(html, _OK_HTML)
        self.assertEqual(att.verdict, Verdict.WEAK_OK.value)
        # Envelope was requested but absent → captured_json stays None.
        self.assertIsNone(att.captured_json)


class TestCapturedJsonInTraceShape(unittest.TestCase):
    """Attempt.to_dict() carries captured_json (None by default)."""

    def test_to_dict_includes_captured_json_key(self):
        from engine.fetch_chain import Attempt
        att = Attempt(
            phase="fallback", executor="playwright_real_chrome",
            url="https://example.com/", url_transform="original",
            impersonate=None, referer="",
        )
        d = att.to_dict()
        self.assertIn("captured_json", d)
        self.assertIsNone(d["captured_json"])


if __name__ == "__main__":
    unittest.main()
