"""Wave 2 A4 + W3.1 — JSON-aware validation in engine/validators.py.

Pins:
  - A substantial JSON response (multi-key dict, ≥64 bytes, no error keys,
    no soft-challenge phrases in values) → WEAK_OK / json_ok reason.  [W3.1]
  - A tiny / single-key / error-shaped JSON → SUSPECT_OK (non-terminal). [W3.1]
  - A non-empty array (≥64 bytes) → WEAK_OK. [W3.1]
  - Soft-phrase suppressor fires on JSON values (same guard as M2). [W3.1]
  - An empty JSON object/array/null → CHALLENGE / json_empty reason.
  - A non-JSON body that starts with '{' but is broken → falls through to
    normal HTML path (tiny_body or shape-gate, depending on size).
  - Content-Type sniffing takes precedence over body sniffing.
  - A non-JSON Content-Type prevents the JSON path even if body looks JSON-ish.
  - JSON path fires BEFORE the small-body threshold so a tiny valid JSON API
    response is not mislabelled CHALLENGE.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

from engine import validators as v


def _resp(body: str, *, status: int = 200, ctype: str = "") -> SimpleNamespace:
    headers = {"content-type": ctype} if ctype else {}
    return SimpleNamespace(
        text=body,
        status_code=status,
        cookies=SimpleNamespace(jar=[]),
        headers=headers,
    )


class JsonAwareValidationTest(unittest.TestCase):
    """A4 + A6: JSON-aware validator — happy path → SUSPECT_OK (non-terminal).

    Wave 3 (A6) update: non-empty parseable JSON without success_selectors
    is now SUSPECT_OK (not WEAK_OK). Without positive proof we cannot confirm
    the body is real data vs a JSON-wrapped challenge. SUSPECT_OK lets the
    grid keep trying; it is returned only if nothing better is found.
    """

    def test_valid_json_object_with_data_is_suspect_ok(self):
        r = v.validate(_resp('{"items": [1, 2, 3]}'))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)
        self.assertIn("json_ok", r.reasons)

    def test_valid_json_array_with_elements_is_suspect_ok(self):
        r = v.validate(_resp('[{"id": 1}, {"id": 2}]'))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)
        self.assertIn("json_ok", r.reasons)

    def test_valid_json_with_content_type_header_is_suspect_ok(self):
        r = v.validate(_resp('{"status": "ok"}', ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)
        self.assertIn("json_ok", r.reasons)

    def test_valid_json_with_vendor_content_type_is_suspect_ok(self):
        r = v.validate(_resp('{"x": 1}', ctype="application/vnd.api+json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)
        self.assertIn("json_ok", r.reasons)

    def test_valid_json_fires_before_small_body_threshold(self):
        """A tiny but valid JSON API response must not be labelled CHALLENGE
        by the small-body path — JSON gate fires first (A4), returns SUSPECT_OK (A6)."""
        small_json = '{"ok": true}'
        r = v.validate(_resp(small_json, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)
        self.assertIn("json_ok", r.reasons)


class JsonEmptyTest(unittest.TestCase):
    """A4: empty JSON structures → CHALLENGE / json_empty."""

    def test_empty_object_is_challenge(self):
        r = v.validate(_resp("{}"))
        self.assertEqual(r.verdict, v.Verdict.CHALLENGE)
        self.assertIn("json_empty", r.reasons)

    def test_empty_array_is_challenge(self):
        r = v.validate(_resp("[]"))
        self.assertEqual(r.verdict, v.Verdict.CHALLENGE)
        self.assertIn("json_empty", r.reasons)

    def test_null_json_with_ct_is_challenge(self):
        """null with an explicit JSON Content-Type → empty JSON → CHALLENGE."""
        r = v.validate(_resp("null", ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.CHALLENGE)
        self.assertIn("json_empty", r.reasons)

    def test_null_without_ct_falls_through_to_html_path(self):
        """null without a Content-Type is not body-sniffed as JSON (starts with 'n'),
        so it falls through to the normal HTML path and is CHALLENGE via tiny_body."""
        r = v.validate(_resp("null"))
        self.assertEqual(r.verdict, v.Verdict.CHALLENGE)
        self.assertNotIn("json_empty", r.reasons)  # reached via tiny_body, not json gate

    def test_empty_object_with_ct_header_is_challenge(self):
        r = v.validate(_resp("{}", ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.CHALLENGE)
        self.assertIn("json_empty", r.reasons)


class JsonFallThroughTest(unittest.TestCase):
    """A4: bodies that are not actually JSON fall through to HTML path."""

    def test_malformed_json_falls_through(self):
        """'{broken' is not valid JSON → not flagged json_empty; falls through."""
        r = v.validate(_resp("{broken"))
        self.assertNotIn("json_ok", r.reasons)
        self.assertNotIn("json_empty", r.reasons)

    def test_html_body_not_intercepted_by_json_gate(self):
        html = "<html><body>Hello world</body></html>"
        r = v.validate(_resp(html))
        self.assertNotIn("json_ok", r.reasons)
        self.assertNotIn("json_empty", r.reasons)

    def test_plain_text_not_intercepted(self):
        r = v.validate(_resp("Hello, world!", ctype="text/plain"))
        self.assertNotIn("json_ok", r.reasons)
        self.assertNotIn("json_empty", r.reasons)

    def test_non_json_content_type_blocks_sniff(self):
        """An explicit text/html Content-Type prevents body sniff even if body
        happens to start with '{'."""
        r = v.validate(_resp('{"data": 1}', ctype="text/html"))
        # Should NOT be intercepted by JSON gate; falls through to HTML path.
        self.assertNotIn("json_ok", r.reasons)
        self.assertNotIn("json_empty", r.reasons)


# ---------------------------------------------------------------------------
# W3.1 — JSON verdict refinement: substantial → WEAK_OK, error-shaped → SUSPECT_OK
# ---------------------------------------------------------------------------

def _substantial_obj(n_keys: int = 5, value_len: int = 20) -> str:
    """Build a JSON object big enough to clear _JSON_WEAK_OK_MIN_BYTES (64 B)."""
    obj = {f"key_{i}": "x" * value_len for i in range(n_keys)}
    return __import__("json").dumps(obj)


def _substantial_array(n_items: int = 3) -> str:
    """Build a JSON array big enough to clear _JSON_WEAK_OK_MIN_BYTES."""
    arr = [{"id": i, "name": f"item_{i}", "value": "data"} for i in range(n_items)]
    return __import__("json").dumps(arr)


class W31SubstantialJsonWeakOkTest(unittest.TestCase):
    """W3.1: substantial multi-key object or non-empty array → WEAK_OK."""

    def test_multi_key_object_substantial_is_weak_ok(self):
        """5-key object >= 64 bytes with no error keys → WEAK_OK."""
        body = _substantial_obj()
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.WEAK_OK)
        self.assertIn("json_ok", r.reasons)

    def test_non_empty_array_substantial_is_weak_ok(self):
        """Non-empty array >= 64 bytes → WEAK_OK."""
        body = _substantial_array()
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.WEAK_OK)
        self.assertIn("json_ok", r.reasons)

    def test_github_api_shaped_object_is_weak_ok(self):
        """Realistic GitHub-API shaped multi-key object → WEAK_OK (live repro fix)."""
        import json
        body = json.dumps({
            "id": 1203403049,
            "name": "insane-search",
            "full_name": "fivetaku/insane-search",
            "private": False,
            "description": "Auto-bypass for blocked websites",
            "forks_count": 12,
            "stargazers_count": 42,
        })
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.WEAK_OK)
        self.assertIn("json_ok", r.reasons)

    def test_weak_ok_not_strong_ok(self):
        """Substantial JSON earns the soft token (WEAK_OK), not full trust (STRONG_OK)."""
        body = _substantial_obj()
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertNotEqual(r.verdict, v.Verdict.STRONG_OK)

    def test_suspect_ok_still_not_winner(self):
        """Existing SUSPECT_OK cases (tiny single-key) are still not recorded
        to winners — this is unchanged by W3.1."""
        small_single = '{"ok": true}'
        r = v.validate(_resp(small_single, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)


class W31ErrorShapedJsonSuspectOkTest(unittest.TestCase):
    """W3.1: error-shaped / tiny / single-key JSON stays SUSPECT_OK."""

    def test_single_key_error_dict_is_suspect_ok(self):
        """{"error": "blocked"} — single error key → SUSPECT_OK."""
        r = v.validate(_resp('{"error": "blocked"}', ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)
        self.assertIn("json_ok", r.reasons)

    def test_single_key_message_dict_is_suspect_ok(self):
        """{"message": "..."} — single-key message pattern → SUSPECT_OK."""
        r = v.validate(_resp('{"message": "Rate limit exceeded"}',
                             ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_multi_key_with_error_key_is_suspect_ok(self):
        """Multi-key dict containing 'error' top-level key → SUSPECT_OK."""
        import json
        body = json.dumps({"error": "blocked", "code": 403,
                           "detail": "WAF", "ts": 1234567890})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_soft_phrase_in_values_is_suspect_ok(self):
        """{"detail": "please verify you are human"} trips the soft-phrase guard
        — must stay SUSPECT_OK even though it has multiple keys."""
        import json
        body = json.dumps({
            "detail": "please verify you are human",
            "status": 403,
            "timestamp": "2026-06-24T00:00:00Z",
            "path": "/api/data",
        })
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK,
                         "soft-phrase in JSON values must block WEAK_OK promotion")

    def test_verify_browser_phrase_in_values_is_suspect_ok(self):
        """{"detail": "verify your browser"} — classic Cloudflare JSON envelope."""
        import json
        body = json.dumps({
            "detail": "verify your browser",
            "redirect": "https://challenge.example.com/",
            "ray_id": "abc123",
        })
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_tiny_multi_key_below_floor_is_suspect_ok(self):
        """Multi-key dict but below the 64-byte size floor → SUSPECT_OK."""
        # {"a":1,"b":2} = 13 bytes — well below floor.
        r = v.validate(_resp('{"a":1,"b":2}', ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_empty_object_stays_challenge(self):
        """W3.1 does not change the empty-JSON CHALLENGE verdict."""
        r = v.validate(_resp("{}", ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.CHALLENGE)
        self.assertIn("json_empty", r.reasons)


class W31SoftPhraseGuardTest(unittest.TestCase):
    """W3.1: _SMALL_PAGE_CHALLENGE_PHRASES suppressor applied to JSON values."""

    def _multi_key_body(self, **extra) -> str:
        """Build a substantial multi-key body, optionally with extra keys."""
        import json
        base = {f"field_{i}": f"legitimate_value_{i}" * 3 for i in range(4)}
        base.update(extra)
        return json.dumps(base)

    def test_clean_values_become_weak_ok(self):
        """No soft phrases in values → WEAK_OK (baseline for the guard tests)."""
        body = self._multi_key_body()
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.WEAK_OK)

    def test_please_wait_phrase_blocks_promotion(self):
        body = self._multi_key_body(status="please wait while we process")
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_redirecting_phrase_blocks_promotion(self):
        body = self._multi_key_body(msg="redirecting to verification page")
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_one_moment_phrase_blocks_promotion(self):
        body = self._multi_key_body(info="one moment please")
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)


# ---------------------------------------------------------------------------
# M2 — whole-object blob scan: nested phrases + later array elements
# ---------------------------------------------------------------------------

class M2NestedPhraseGuardTest(unittest.TestCase):
    """M2: whole-object json.dumps blob scan catches phrases in nested dicts
    and non-first array elements (the old first-element-only sampling gap)."""

    def test_nested_dict_phrase_stays_suspect_ok(self):
        """{"data":{"msg":"verify your browser"},...} — nested phrase caught."""
        import json
        body = json.dumps({"data": {"msg": "verify your browser"},
                           "ok": False, "ts": 1234567890})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK,
                         "nested phrase must block WEAK_OK (M2)")

    def test_second_array_element_phrase_stays_suspect_ok(self):
        """["padding","please verify your browser"] — 2nd element caught."""
        import json
        body = json.dumps(["legit padding element here",
                           "please verify your browser"])
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK,
                         "phrase in non-first array element must block WEAK_OK (M2)")

    def test_deeply_nested_phrase_stays_suspect_ok(self):
        """Phrase two levels deep is still caught by blob scan."""
        import json
        body = json.dumps({"wrapper": {"inner": {"text": "just a moment"}},
                           "id": 1, "ts": 1234567890})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_clean_nested_dict_is_weak_ok(self):
        """Clean nested values must not be over-demoted by M2."""
        import json
        body = json.dumps({"data": {"id": 1, "name": "item"},
                           "page": 1, "total": 42})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.WEAK_OK,
                         "clean nested dict must NOT be demoted (no over-demotion)")


# ---------------------------------------------------------------------------
# M1 — block-value tokens + no-over-demotion regression pins
# ---------------------------------------------------------------------------

class M1BlockValueTokenTest(unittest.TestCase):
    """M1: block-signal VALUE tokens catch WAF envelopes regardless of key name,
    without demoting legit {"status":"ok"} APIs (no-over-demotion guard)."""

    def test_result_blocked_value_is_suspect_ok(self):
        """{"result":"blocked","kind":"deny","ref":"x"} — value token."""
        import json
        body = json.dumps({"result": "blocked", "kind": "deny", "ref": "x"})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_status_blocked_value_is_suspect_ok(self):
        """{"status":"blocked",...} — "blocked" value token fires."""
        import json
        body = json.dumps({"status": "blocked", "code": 403,
                           "ts": 1234567890, "msg": "WAF"})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_denied_key_is_suspect_ok(self):
        """{"denied":true,...} — denied is an error key (M1 key-set addition)."""
        import json
        body = json.dumps({"denied": True, "reason": "bot", "ts": 1234567890})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_rejected_key_is_suspect_ok(self):
        """{"rejected":true,...} — rejected is an error key."""
        import json
        body = json.dumps({"rejected": True, "reason": "rate_limit",
                           "retry_after": 60})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    def test_action_deny_value_is_suspect_ok(self):
        """{"action":"deny",...} — "deny" block-value token."""
        import json
        body = json.dumps({"action": "deny", "rule": "bot_filter",
                           "ts": 1234567890})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.SUSPECT_OK)

    # --- no-over-demotion regression pins (MUST stay WEAK_OK) ---

    def test_status_ok_multi_key_stays_weak_ok(self):
        """{"status":"ok","data":[1,2,3],"count":3} MUST stay WEAK_OK.
        "status" is NOT in _JSON_ERROR_KEYS — adding it would break real APIs."""
        import json
        body = json.dumps({"status": "ok", "data": [1, 2, 3], "count": 3})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.WEAK_OK,
                         '{"status":"ok"} must NOT be demoted — over-demotion guard')

    def test_results_array_multi_key_stays_weak_ok(self):
        """{"results":[...],"page":1,"total":10} MUST stay WEAK_OK."""
        import json
        body = json.dumps({"results": [{"id": 1}], "page": 1, "total": 10})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.WEAK_OK,
                         "results-array envelope must NOT be demoted")

    def test_status_success_stays_weak_ok(self):
        """{"status":"success",...} — "success" is not a block-value token."""
        import json
        body = json.dumps({"status": "success", "items": ["a", "b", "c"],
                           "count": 5})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, v.Verdict.WEAK_OK)


if __name__ == "__main__":
    unittest.main()
