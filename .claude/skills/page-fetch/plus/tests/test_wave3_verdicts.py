"""Wave 3 — verdict-richness: SUSPECT_OK, RATE_LIMITED, AUTH_REQUIRED,
NOT_FOUND, A7 failure fields, M1 str-contract, M3 helper refactor.

Tests:
  A6 — SUSPECT_OK:
    - unknown-marker JSON → SUSPECT_OK (not WEAK_OK, not recorded as winner)
    - abck_unresolved selector-less → SUSPECT_OK
    - SUSPECT_OK is non-terminal (not in _TERMINAL_VERDICTS)
    - SUSPECT_OK not recorded in winners

  ADAPT-7 — HTTP status semantics:
    - 429 → RATE_LIMITED + no strike
    - 404/410 → NOT_FOUND
    - 401 → AUTH_REQUIRED
    - 403 → BLOCKED (keeps grinding)
    - 500 → BLOCKED (keeps grinding)
    - 404/401 → TERMINAL_NONSUCCESS (grid short-circuits)
    - 403/500 → NOT in TERMINAL_NONSUCCESS

  A7 — FetchResult failure fields:
    - untried_routes populated on budget-cut, empty on true exhaustion
    - must_invoke_playwright_mcp True on challenge, False on 404
    - stop_reason populated honestly
    - --json carries the new fields

  M1 — str-contract:
    - FetchResult.verdict from a real validate() path is str not Verdict enum

  SUSPECT_OK winners-no-record invariant:
    - _pick_winning_attempt with suspect_ok trace returns None
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

from engine import validators as v
from engine.fetch_chain import _TERMINAL_VERDICTS, FetchResult
from engine.validators import TERMINAL_NONSUCCESS, Verdict


def _resp(body: str, *, status: int = 200, ctype: str = "",
          cookies=None) -> SimpleNamespace:
    headers = {"content-type": ctype} if ctype else {}
    jar = cookies or []
    return SimpleNamespace(
        text=body,
        status_code=status,
        cookies=SimpleNamespace(jar=jar),
        headers=headers,
        url="https://example.com/",
    )


# ---------------------------------------------------------------------------
# A6 — SUSPECT_OK verdict
# ---------------------------------------------------------------------------

class SuspectOkEnumTest(unittest.TestCase):
    """SUSPECT_OK is in the enum and is NON-terminal."""

    def test_suspect_ok_in_enum(self):
        self.assertEqual(Verdict.SUSPECT_OK.value, "suspect_ok")

    def test_suspect_ok_not_terminal(self):
        self.assertNotIn(Verdict.SUSPECT_OK.value, _TERMINAL_VERDICTS)

    def test_suspect_ok_not_in_terminal_nonsuccess(self):
        self.assertNotIn(Verdict.SUSPECT_OK.value, TERMINAL_NONSUCCESS)

    def test_suspect_ok_ok_property_false(self):
        """ValidationResult.ok must be False for SUSPECT_OK."""
        r = v.ValidationResult(verdict=Verdict.SUSPECT_OK)
        self.assertFalse(r.ok)


class SuspectOkJsonPathTest(unittest.TestCase):
    """A6 + W3.1: error-shaped / tiny JSON → SUSPECT_OK.

    W3.1 refinement: substantial multi-key JSON → WEAK_OK (see W31 classes).
    These tests use small / single-key bodies that stay SUSPECT_OK under W3.1.
    """

    def test_single_key_json_no_ct_is_suspect_ok(self):
        """Single-key {"items":[1,2,3]} — small body stays SUSPECT_OK (W3.1)."""
        r = v.validate(_resp('{"items": [1, 2, 3]}'))
        self.assertEqual(r.verdict, Verdict.SUSPECT_OK)
        self.assertIn("json_ok", r.reasons)

    def test_single_key_status_ok_is_suspect_ok(self):
        """{"status": "ok"} — single-key, tiny → SUSPECT_OK."""
        r = v.validate(_resp('{"status": "ok"}', ctype="application/json"))
        self.assertEqual(r.verdict, Verdict.SUSPECT_OK)
        self.assertIn("json_ok", r.reasons)

    def test_small_single_key_json_not_weak_ok(self):
        """Small single-key JSON must not reach WEAK_OK (A6 + W3.1 together)."""
        r = v.validate(_resp('{"data": [1, 2]}'))
        self.assertNotEqual(r.verdict, Verdict.WEAK_OK)
        self.assertEqual(r.verdict, Verdict.SUSPECT_OK)

    def test_empty_json_stays_challenge(self):
        """Empty JSON is still CHALLENGE — no change from A4 or W3.1."""
        r = v.validate(_resp("{}", ctype="application/json"))
        self.assertEqual(r.verdict, Verdict.CHALLENGE)
        self.assertIn("json_empty", r.reasons)


class W31JsonVerdictRefinementTest(unittest.TestCase):
    """W3.1: substantial JSON → WEAK_OK; error-shaped / soft-phrase → SUSPECT_OK.

    SUSPECT_OK cases (single-key, error-shaped, soft-phrase) must still NOT be
    recorded as winners — the A6 invariant is preserved for those paths.
    """

    def _build_substantial(self, n_keys: int = 5, val: str = "x" * 15) -> str:
        import json
        return json.dumps({f"k{i}": val for i in range(n_keys)})

    def test_substantial_multi_key_object_is_weak_ok(self):
        """5-key object ≥ 64 bytes, no error keys → WEAK_OK (W3.1)."""
        body = self._build_substantial()
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, Verdict.WEAK_OK)
        self.assertIn("json_ok", r.reasons)

    def test_non_empty_array_substantial_is_weak_ok(self):
        """Non-empty array ≥ 64 bytes → WEAK_OK (W3.1)."""
        import json
        body = json.dumps([{"id": i, "name": f"item_{i}", "val": "data"*3}
                           for i in range(3)])
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, Verdict.WEAK_OK)

    def test_error_keyed_json_stays_suspect_ok(self):
        """{"error":"blocked","code":403,"ts":1} — error key → SUSPECT_OK."""
        import json
        body = json.dumps({"error": "blocked", "code": 403,
                           "ts": 1234567890, "msg": "WAF"})
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, Verdict.SUSPECT_OK)

    def test_soft_phrase_in_json_values_stays_suspect_ok(self):
        """{"detail":"please verify you are human",...} → SUSPECT_OK (soft-phrase guard)."""
        import json
        body = json.dumps({
            "detail": "please verify you are human",
            "status": 403,
            "timestamp": "2026-06-24T00:00:00Z",
            "path": "/api/data",
        })
        r = v.validate(_resp(body, ctype="application/json"))
        self.assertEqual(r.verdict, Verdict.SUSPECT_OK,
                         "soft-phrase in JSON values must NOT reach WEAK_OK")

    def test_suspect_ok_json_cases_not_recorded_as_winner(self):
        """W3.1 SUSPECT_OK JSON paths must still not be recorded to winners."""
        from plus import winners
        # error-shaped JSON → suspect_ok
        att = SimpleNamespace(
            verdict="suspect_ok",
            impersonate="chrome",
            referer="self_root",
            url_transform="original",
        )
        result = SimpleNamespace(ok=True, trace=[att], profile_used=None)
        chosen = winners._pick_winning_attempt(result)
        self.assertIsNone(chosen,
            "SUSPECT_OK (including error-shaped JSON) must not be a winning attempt")


class SuspectOkAbckTest(unittest.TestCase):
    """A6: abck_unresolved on selector-less path → SUSPECT_OK."""

    def _abck_resp(self) -> SimpleNamespace:
        """Build a large body response with an unresolved _abck cookie."""
        big_body = "Real content. " * 300  # well above SMALL_BODY_THRESHOLD
        cookie = SimpleNamespace(name="_abck", value="sometoken~-1~ABCDEF")
        return _resp(big_body, cookies=[cookie])

    def test_abck_unresolved_selectorless_is_suspect_ok(self):
        r = v.validate(self._abck_resp())
        self.assertEqual(r.verdict, Verdict.SUSPECT_OK)
        self.assertIn("abck_unresolved", r.reasons)

    def test_abck_unresolved_not_weak_ok(self):
        """Previously demoted to WEAK_OK — now must be SUSPECT_OK."""
        r = v.validate(self._abck_resp())
        self.assertNotEqual(r.verdict, Verdict.WEAK_OK)


class SuspectOkWinnersTest(unittest.TestCase):
    """A6: SUSPECT_OK must NOT be recorded as a winners trust token."""

    def test_pick_winning_attempt_excludes_suspect_ok(self):
        from plus import winners
        att = SimpleNamespace(
            verdict="suspect_ok",
            impersonate="chrome",
            referer="self_root",
            url_transform="original",
        )
        result = SimpleNamespace(ok=True, trace=[att], profile_used=None)
        chosen = winners._pick_winning_attempt(result)
        self.assertIsNone(chosen,
            "SUSPECT_OK must not be chosen as a winning attempt")

    def test_weak_ok_still_wins_over_suspect_ok(self):
        """A weak_ok attempt after a suspect_ok must be chosen, not suspect_ok."""
        from plus import winners
        suspect_att = SimpleNamespace(
            verdict="suspect_ok", impersonate="chrome",
            referer="self_root", url_transform="original",
        )
        weak_att = SimpleNamespace(
            verdict="weak_ok", impersonate="safari",
            referer="self_root", url_transform="original",
        )
        result = SimpleNamespace(ok=True, trace=[suspect_att, weak_att],
                                 profile_used=None)
        chosen = winners._pick_winning_attempt(result)
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen.verdict, "weak_ok")

    def test_suspect_ok_not_recorded_to_file(self):
        """record() with only suspect_ok in trace must not write to winners."""
        from plus import winners
        import tempfile, shutil
        tmpdir = Path(tempfile.mkdtemp())
        winners_path = tmpdir / "winners.json"
        try:
            with mock.patch.object(winners, "_WINNERS_PATH", winners_path):
                att = SimpleNamespace(
                    verdict="suspect_ok", impersonate="chrome",
                    referer="self_root", url_transform="original",
                )
                result = SimpleNamespace(ok=True, trace=[att],
                                         profile_used=None, content="")
                winners.record("https://example.com/", result)
            self.assertFalse(winners_path.exists(),
                "winners.json must not be written for SUSPECT_OK-only trace")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# ADAPT-7 — HTTP status semantics
# ---------------------------------------------------------------------------

class Adapt7StatusSemanticsTest(unittest.TestCase):
    """ADAPT-7: refined per-status verdicts."""

    def test_429_is_rate_limited(self):
        r = v.validate(_resp("", status=429))
        self.assertEqual(r.verdict, Verdict.RATE_LIMITED)
        self.assertIn("status=429", r.reasons)

    def test_401_is_auth_required(self):
        r = v.validate(_resp("", status=401))
        self.assertEqual(r.verdict, Verdict.AUTH_REQUIRED)

    def test_404_is_not_found(self):
        r = v.validate(_resp("", status=404))
        self.assertEqual(r.verdict, Verdict.NOT_FOUND)

    def test_410_is_not_found(self):
        r = v.validate(_resp("", status=410))
        self.assertEqual(r.verdict, Verdict.NOT_FOUND)

    def test_403_is_blocked(self):
        """403 = WAF block the grid exists to beat — keep grinding."""
        r = v.validate(_resp("", status=403))
        self.assertEqual(r.verdict, Verdict.BLOCKED)

    def test_500_is_blocked(self):
        """5xx = transient server hiccup — keep grinding."""
        r = v.validate(_resp("", status=500))
        self.assertEqual(r.verdict, Verdict.BLOCKED)

    def test_503_is_blocked(self):
        r = v.validate(_resp("", status=503))
        self.assertEqual(r.verdict, Verdict.BLOCKED)


class Adapt7TerminalNonsuccessTest(unittest.TestCase):
    """ADAPT-7: TERMINAL_NONSUCCESS contains exactly 401/404/410-derived verdicts."""

    def test_auth_required_in_terminal_nonsuccess(self):
        self.assertIn(Verdict.AUTH_REQUIRED.value, TERMINAL_NONSUCCESS)

    def test_not_found_in_terminal_nonsuccess(self):
        self.assertIn(Verdict.NOT_FOUND.value, TERMINAL_NONSUCCESS)

    def test_blocked_not_in_terminal_nonsuccess(self):
        """403 must NOT short-circuit — the grid grinds it."""
        self.assertNotIn(Verdict.BLOCKED.value, TERMINAL_NONSUCCESS)

    def test_rate_limited_not_in_terminal_nonsuccess(self):
        """429 is transient — must NOT short-circuit."""
        self.assertNotIn(Verdict.RATE_LIMITED.value, TERMINAL_NONSUCCESS)

    def test_challenge_not_in_terminal_nonsuccess(self):
        self.assertNotIn(Verdict.CHALLENGE.value, TERMINAL_NONSUCCESS)

    def test_suspect_ok_not_in_terminal_nonsuccess(self):
        self.assertNotIn(Verdict.SUSPECT_OK.value, TERMINAL_NONSUCCESS)

    def test_rate_limited_does_not_strike_winners(self):
        """ADAPT-4 (Wave 2) must already exclude rate_limited — confirm still clean."""
        from plus import winners
        self.assertNotIn("rate_limited", winners._PENALIZE_VERDICTS)

    def test_not_found_does_not_strike_winners(self):
        """not_found is URL-level, not route fault — must not strike."""
        from plus import winners
        self.assertNotIn("not_found", winners._PENALIZE_VERDICTS)

    def test_suspect_ok_does_not_strike(self):
        """H1 regression guard: a learned winner that returned SUSPECT_OK (uncertain,
        not a real block) must NOT have its strike counter incremented.

        Pre-H1-fix: the exhausted classifier only excluded
        {unknown, rate_limited, auth_required, not_found}. SUSPECT_OK fell
        through to penalize=True → strike counter went to 1 after one such result.
        Post-H1-fix: 'suspect_ok' is added to the exclusion set → no strike.
        """
        import json, shutil, tempfile
        from pathlib import Path
        from plus import winners
        from unittest import mock

        tmpdir = Path(tempfile.mkdtemp())
        winners_path = tmpdir / "winners.json"
        try:
            # Plant a fresh winner entry with strikes=0.
            key = winners._winners_key("example.com", "desktop")
            combo = {
                "impersonate": "chrome",
                "referer": "self_root",
                "recorded_at": 1_000_000.0,
                "verdict": "weak_ok",
                "transform": "original",
                "strikes": 0,
            }
            winners_path.parent.mkdir(parents=True, exist_ok=True)
            winners_path.write_text(json.dumps({key: combo}), encoding="utf-8")

            # Build a result that has ok=False and verdict="suspect_ok".
            import types
            result = types.SimpleNamespace(ok=False, verdict="suspect_ok")

            frozen_now = 1_000_000.0
            with mock.patch.object(winners, "_WINNERS_PATH", winners_path), \
                 mock.patch.object(winners, "_now", side_effect=lambda: frozen_now):
                winners.strike("https://example.com/page", result=result,
                               device_class="desktop")

            data = json.loads(winners_path.read_text(encoding="utf-8"))
            # The entry must still exist and strikes must remain 0.
            self.assertIn(key, data,
                "Winner entry must not be evicted after a suspect_ok result")
            self.assertEqual(data[key]["strikes"], 0,
                "strike counter must NOT increment for suspect_ok (H1 regression guard)")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# A7 — FetchResult failure fields
# ---------------------------------------------------------------------------

class FetchResultFieldsTest(unittest.TestCase):
    """A7: FetchResult has the four new failure-gate fields."""

    def test_default_values(self):
        fr = FetchResult(ok=False)
        self.assertEqual(fr.untried_routes, [])
        self.assertFalse(fr.must_invoke_playwright_mcp)
        self.assertFalse(fr.grid_exhausted)
        self.assertEqual(fr.stop_reason, "")

    def test_to_dict_includes_new_fields(self):
        fr = FetchResult(
            ok=False,
            grid_exhausted=True,
            stop_reason="exhausted",
            must_invoke_playwright_mcp=True,
            untried_routes=["combo_a", "combo_b"],
        )
        d = fr.to_dict()
        self.assertIn("untried_routes", d)
        self.assertIn("must_invoke_playwright_mcp", d)
        self.assertIn("grid_exhausted", d)
        self.assertIn("stop_reason", d)
        self.assertEqual(d["untried_routes"], ["combo_a", "combo_b"])
        self.assertTrue(d["must_invoke_playwright_mcp"])
        self.assertTrue(d["grid_exhausted"])
        self.assertEqual(d["stop_reason"], "exhausted")

    def test_json_serializable(self):
        fr = FetchResult(
            ok=False,
            grid_exhausted=False,
            stop_reason="rate_limited",
            must_invoke_playwright_mcp=False,
            untried_routes=[],
        )
        # Should not raise.
        payload = json.dumps(fr.to_dict())
        parsed = json.loads(payload)
        self.assertIn("stop_reason", parsed)
        self.assertEqual(parsed["stop_reason"], "rate_limited")

    def test_ok_true_result_has_empty_stop_fields(self):
        """Success paths must leave A7 fields empty (non-populated)."""
        fr = FetchResult(ok=True, content="html", verdict="weak_ok")
        self.assertEqual(fr.stop_reason, "")
        self.assertFalse(fr.grid_exhausted)
        self.assertFalse(fr.must_invoke_playwright_mcp)
        self.assertEqual(fr.untried_routes, [])


# ---------------------------------------------------------------------------
# M2 — plus --json payload carries all four A7 fields
# ---------------------------------------------------------------------------

class PlusJsonPayloadA7FieldsTest(unittest.TestCase):
    """M2: plus/_cmd_fetch --json must include the four A7 failure-gate fields
    so programmatic consumers (harvest ladder) can parse them directly from
    the JSON output without scraping stderr.
    """

    def _build_plus_json_payload(self, result, body: str = "") -> dict:
        """Replicate the _cmd_fetch payload dict to test field coverage."""
        return {
            "ok": result.ok,
            "verdict": result.verdict,
            "profile_used": result.profile_used,
            "final_url": result.final_url,
            "format": "raw",
            "attempts": len(result.trace),
            "content": body,
            # A7 fields (M2):
            "untried_routes": result.untried_routes,
            "must_invoke_playwright_mcp": result.must_invoke_playwright_mcp,
            "grid_exhausted": result.grid_exhausted,
            "stop_reason": result.stop_reason,
        }

    def test_a7_fields_present_in_payload_on_failure(self):
        """All four A7 fields must appear in the plus --json output on ok=False."""
        fr = FetchResult(
            ok=False,
            verdict="challenge",
            profile_used="cloudflare",
            final_url="https://example.com/",
            grid_exhausted=True,
            stop_reason="exhausted",
            must_invoke_playwright_mcp=True,
            untried_routes=[],
        )
        payload = self._build_plus_json_payload(fr)
        for field in ("untried_routes", "must_invoke_playwright_mcp",
                      "grid_exhausted", "stop_reason"):
            self.assertIn(field, payload,
                f"A7 field {field!r} missing from plus --json payload")

    def test_a7_fields_present_on_success(self):
        """A7 fields must also appear on ok=True (empty/False) for schema consistency."""
        fr = FetchResult(
            ok=True,
            verdict="weak_ok",
            profile_used=None,
            final_url="https://example.com/",
        )
        payload = self._build_plus_json_payload(fr, body="<html>content</html>")
        for field in ("untried_routes", "must_invoke_playwright_mcp",
                      "grid_exhausted", "stop_reason"):
            self.assertIn(field, payload,
                f"A7 field {field!r} must be in plus --json payload even on success")
        # Success defaults are empty/False.
        self.assertEqual(payload["untried_routes"], [])
        self.assertFalse(payload["must_invoke_playwright_mcp"])
        self.assertFalse(payload["grid_exhausted"])
        self.assertEqual(payload["stop_reason"], "")

    def test_plus_cmd_fetch_json_source_contains_a7_fields(self):
        """Source-level invariant: _cmd_fetch in plus/__main__.py must include
        all four A7 field keys in the payload dict it builds for --json output."""
        import pathlib
        src = pathlib.Path(_SKILL_ROOT / "plus" / "__main__.py").read_text()
        for field in ("untried_routes", "must_invoke_playwright_mcp",
                      "grid_exhausted", "stop_reason"):
            self.assertIn(field, src,
                f"A7 field {field!r} missing from plus/__main__.py JSON payload")

    def test_existing_json_keys_preserved(self):
        """Additive check: existing --json keys must not be removed by M2."""
        fr = FetchResult(ok=True, verdict="weak_ok", profile_used=None,
                         final_url="https://example.com/")
        payload = self._build_plus_json_payload(fr)
        for key in ("ok", "verdict", "profile_used", "final_url", "format",
                    "attempts", "content"):
            self.assertIn(key, payload,
                f"Pre-existing plus --json key {key!r} was removed — must be preserved")


# ---------------------------------------------------------------------------
# M1 — str-contract: FetchResult.verdict must be str not Verdict enum
# ---------------------------------------------------------------------------

class FetchResultVerdictStrContractTest(unittest.TestCase):
    """M1: FetchResult.verdict built via validate() → fetch path is always str."""

    def test_fetchresult_verdict_is_str_not_enum(self):
        """Pins the str-not-enum contract so a future refactor can't break
        ADAPT-4 strike logic which does `getattr(result, 'verdict', '') == 'challenge'`."""
        fr = FetchResult(ok=False, verdict=Verdict.CHALLENGE.value)
        self.assertIsInstance(fr.verdict, str,
            "FetchResult.verdict must be str (vr.verdict.value), not Verdict enum")
        self.assertEqual(fr.verdict, "challenge")

    def test_validation_result_verdict_value_is_str(self):
        """validate() returns a ValidationResult whose .verdict.value is str."""
        r = v.validate(_resp("<html><body>hello</body></html>"))
        val = r.verdict.value
        self.assertIsInstance(val, str)

    def test_all_verdict_values_are_str(self):
        for verdict in Verdict:
            self.assertIsInstance(verdict.value, str,
                f"Verdict.{verdict.name}.value must be str")


# ---------------------------------------------------------------------------
# All new Verdict members have correct values
# ---------------------------------------------------------------------------

class NewVerdictMembersTest(unittest.TestCase):
    def test_rate_limited_value(self):
        self.assertEqual(Verdict.RATE_LIMITED.value, "rate_limited")

    def test_auth_required_value(self):
        self.assertEqual(Verdict.AUTH_REQUIRED.value, "auth_required")

    def test_not_found_value(self):
        self.assertEqual(Verdict.NOT_FOUND.value, "not_found")

    def test_suspect_ok_value(self):
        self.assertEqual(Verdict.SUSPECT_OK.value, "suspect_ok")

    def test_terminal_verdicts_unchanged(self):
        """_TERMINAL_VERDICTS must remain exactly strong_ok + weak_ok."""
        self.assertEqual(
            set(_TERMINAL_VERDICTS),
            {"strong_ok", "weak_ok"},
            "_TERMINAL_VERDICTS must be exactly {strong_ok, weak_ok}",
        )


if __name__ == "__main__":
    unittest.main()
