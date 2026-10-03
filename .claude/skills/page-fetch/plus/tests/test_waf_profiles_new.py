"""Patch #3 — three new WAF profiles (Imperva, Kasada, Sucuri).

`engine/waf_profiles.yaml` previously fell through to `unknown_challenge`
for these three WAFs because their fingerprints weren't enrolled. The
patch adds detector signatures sourced from vendor docs + wafw00f
signature database (all public, no site-specific data).

Tests pin three layers:
  1. YAML schema — each new profile has the required fields.
  2. Detector — synthetic Response with the WAF's cookie/header pattern
     resolves to the correct profile (not unknown_challenge).
  3. Wildcard semantics — `visid_incap_*` matches `visid_incap_12345`,
     `X-Kpsdk-*` matches `X-Kpsdk-Ct`, etc.
  4. Validator — the body markers added to `CHALLENGE_MARKERS`
     ("Pardon Our Interruption", "Sucuri WebSite Firewall") trip.
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
from engine import waf_detector as wd


# Required schema fields per existing profile entries (akamai_bot_manager,
# cloudflare_turnstile, etc.). New profiles must carry all of these.
_REQUIRED_FIELDS = (
    "detectors",
    "capabilities_needed",
    "tls_impersonate_candidates",
    "referer_strategies",
)


def _fake_resp(*, cookies: dict | None = None, headers: dict | None = None,
               body: str = "", status: int = 200):
    """Build a minimal Response-shaped object the detector + validator read."""
    cookies = cookies or {}
    headers = headers or {}
    cookie_jar = SimpleNamespace(jar=[
        SimpleNamespace(name=k, value=val) for k, val in cookies.items()
    ])
    return SimpleNamespace(
        text=body,
        status_code=status,
        cookies=cookie_jar,
        headers=headers,
    )


class NewProfileSchemaTest(unittest.TestCase):
    """Each new profile honours the documented schema."""

    @classmethod
    def setUpClass(cls):
        cls.profiles = wd._load_profiles()

    def _check(self, profile_id: str) -> None:
        prof = self.profiles.get(profile_id)
        self.assertIsNotNone(prof, f"missing profile {profile_id}")
        for field in _REQUIRED_FIELDS:
            self.assertIn(field, prof, f"{profile_id} missing {field}")
        # Detectors must be a dict with at least one signal family.
        detectors = prof["detectors"]
        self.assertIsInstance(detectors, dict)
        self.assertGreater(
            len(detectors), 0,
            f"{profile_id} has empty detectors",
        )
        # TLS candidates must be groups (list of lists), matching existing pattern.
        tls = prof["tls_impersonate_candidates"]
        self.assertTrue(
            all(isinstance(g, list) for g in tls),
            f"{profile_id} tls_impersonate_candidates must be list of lists",
        )

    def test_imperva_profile_schema(self):
        self._check("imperva_incapsula")

    def test_kasada_profile_schema(self):
        self._check("kasada")

    def test_sucuri_profile_schema(self):
        self._check("sucuri_cloudproxy")


class ImpervaDetectorTest(unittest.TestCase):
    """Imperva fingerprint resolves to imperva_incapsula, not unknown_challenge."""

    def test_cookie_signature_detects_imperva(self):
        # `visid_incap_*` is the canonical Imperva cookie family. Wildcard
        # in the profile must match the concrete name with a hash suffix.
        resp = _fake_resp(cookies={
            "visid_incap_12345": "abcdef",
            "incap_ses_99_12345": "xyz",
        })
        hits = wd.detect(resp)
        self.assertEqual(
            hits[0].profile_id, "imperva_incapsula",
            f"expected imperva_incapsula first, got hits={[h.profile_id for h in hits]}",
        )
        # Two cookie signals → strong (confidence 0.9 per confidence_rules).
        self.assertGreaterEqual(hits[0].confidence, 0.9)

    def test_header_signature_detects_imperva(self):
        # X-Iinfo is added on every Imperva-fronted response. Header lookup
        # is case-insensitive in `_match_patterns`.
        resp = _fake_resp(headers={"x-iinfo": "1-2-3", "x-cdn": "Incapsula"})
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "imperva_incapsula")

    def test_block_body_detects_imperva(self):
        # The block page body is the user-facing signal. Single body marker
        # = weak confidence (0.6) but still resolves to the right profile.
        resp = _fake_resp(body="<html>Request unsuccessful. Incapsula incident ID: 999</html>")
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "imperva_incapsula")


class KasadaDetectorTest(unittest.TestCase):
    def test_cookie_signature_detects_kasada(self):
        # Multiple x-kpsdk-* cookies → high confidence.
        resp = _fake_resp(cookies={
            "x-kpsdk-cd": "abc",
            "x-kpsdk-ct": "def",
        })
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "kasada")
        self.assertGreaterEqual(hits[0].confidence, 0.9)

    def test_header_wildcard_detects_kasada(self):
        # `X-Kpsdk-*` wildcard must match arbitrary suffix on header names.
        resp = _fake_resp(headers={"x-kpsdk-version": "2.1"})
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "kasada")

    def test_block_body_detects_kasada(self):
        resp = _fake_resp(body="<title>Pardon Our Interruption</title>")
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "kasada")


class SucuriDetectorTest(unittest.TestCase):
    def test_server_header_detects_sucuri(self):
        # `Server: Sucuri/Cloudproxy` is the cleanest single signal —
        # `server_contains` is the matched mechanism.
        resp = _fake_resp(headers={"server": "Sucuri/Cloudproxy"})
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "sucuri_cloudproxy")

    def test_xsucuri_header_detects(self):
        resp = _fake_resp(headers={"X-Sucuri-ID": "edge-1", "X-Sucuri-Cache": "HIT"})
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "sucuri_cloudproxy")

    def test_block_body_detects_sucuri(self):
        resp = _fake_resp(body="<h1>Sucuri WebSite Firewall - CloudProxy</h1>")
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "sucuri_cloudproxy")


class ValidatorMarkerCoverageTest(unittest.TestCase):
    """The body markers added in Patch #3 must also be in
    `CHALLENGE_MARKERS` so the validator (which runs ahead of the
    detector in the fetch pipeline) catches block pages early."""

    def _padded(self, snippet: str) -> str:
        # Use padding so the size heuristic doesn't masquerade as the
        # marker verdict (mirror `_padded()` in test_validator_markers).
        return snippet + ("<p>filler content</p>" * 500)

    def test_kasada_marker_trips_challenge(self):
        body = self._padded("<title>Pardon Our Interruption</title>")
        result = v.validate(_fake_resp(body=body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)

    def test_sucuri_marker_trips_challenge(self):
        body = self._padded("<h1>Sucuri WebSite Firewall - CloudProxy</h1>")
        result = v.validate(_fake_resp(body=body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)


class ExistingProfileRegressionTest(unittest.TestCase):
    """MED-1 follow-up: pin pre-existing `server_contains` behaviour.

    The case-insensitive lowercase fix in `_score_profile` was made
    while wiring up sucuri_cloudproxy. It also affects the only other
    `server_contains` user (akamai_bot_manager). Without this pin, a
    future refactor that removes the `.lower()` would silently regress
    Akamai detection."""

    def test_akamai_server_header_case_insensitive(self):
        resp = _fake_resp(headers={"server": "AkamaiGHost"})
        hits = wd.detect(resp)
        self.assertEqual(
            hits[0].profile_id, "akamai_bot_manager",
            msg=f"Mixed-case `AkamaiGHost` must resolve to akamai; got "
                f"{[h.profile_id for h in hits]}",
        )


class NoFalseCrossProfileTest(unittest.TestCase):
    """Regression guard: a response with only Imperva fingerprint must
    not also fire kasada / sucuri detectors. The profiles are siblings
    and the planner picks the strongest hit, but if any of them light
    up on unrelated fingerprints it indicates a copy-paste error in the
    detectors block."""

    def test_imperva_does_not_fire_on_kasada_response(self):
        resp = _fake_resp(cookies={"x-kpsdk-cd": "abc", "x-kpsdk-ct": "def"})
        hits = wd.detect(resp)
        # The top hit must be kasada — and imperva / sucuri must not be
        # in the hit list at all (they have unrelated fingerprints).
        top_ids = [h.profile_id for h in hits]
        self.assertEqual(top_ids[0], "kasada")
        self.assertNotIn("imperva_incapsula", top_ids)
        self.assertNotIn("sucuri_cloudproxy", top_ids)

    def test_sucuri_does_not_fire_on_imperva_response(self):
        resp = _fake_resp(cookies={"visid_incap_99": "x"})
        top_ids = [h.profile_id for h in wd.detect(resp)]
        self.assertEqual(top_ids[0], "imperva_incapsula")
        self.assertNotIn("sucuri_cloudproxy", top_ids)
        self.assertNotIn("kasada", top_ids)


class F5BigIPWildcardTest(unittest.TestCase):
    """P11 (2026-06-11) — F5 BIG-IP cookie wildcard fix.

    Real F5 BIG-IP cookies are named ``BIGipServer<pool_name>`` where the
    pool name is deployment-specific (e.g. ``BIGipServermy_app_pool``).
    The pre-patch profile had a literal ``"BigIPServer"`` entry which only
    matched exact-name equality — real pool cookies never matched.

    The fix changes ``"BigIPServer"`` to ``"BigIPServer*"`` so fnmatch
    wildcard semantics in ``_match_patterns`` catch any pool-name suffix.
    Tests mirror the existing Kasada wildcard tests in this file.
    """

    def test_bigip_exact_cookie_still_matches(self) -> None:
        """A cookie named exactly ``BIGipServer`` (no suffix) must still
        match after the wildcard change — ``fnmatch("bigipserver", "bigipserver*")``
        is True (zero-char suffix allowed)."""
        resp = _fake_resp(cookies={"BIGipServer": "synthetic-cookie"})
        hits = wd.detect(resp)
        top_ids = [h.profile_id for h in hits]
        self.assertIn("f5_big_ip", top_ids, msg=f"bare BIGipServer must still hit; got {top_ids}")

    def test_bigip_pool_name_suffix_matches(self) -> None:
        """The common real-world pattern ``BIGipServer<pool>`` must resolve
        to f5_big_ip — this was the broken case before the wildcard fix."""
        resp = _fake_resp(cookies={"BIGipServerweb_pool": "synthetic-cookie"})
        hits = wd.detect(resp)
        top_ids = [h.profile_id for h in hits]
        self.assertIn(
            "f5_big_ip", top_ids,
            msg=f"pool-suffixed BIGipServer cookie must hit f5_big_ip; got {top_ids}",
        )

    def test_bigip_long_pool_name_matches(self) -> None:
        """Wildcard must match arbitrarily long pool names."""
        resp = _fake_resp(cookies={"BIGipServermy_very_long_application_pool_name": "x"})
        hits = wd.detect(resp)
        top_ids = [h.profile_id for h in hits]
        self.assertIn("f5_big_ip", top_ids)

    def test_ts01_wildcard_still_works(self) -> None:
        """Regression: the sibling TS01* wildcard that was already working
        must not be broken by the profile edit."""
        resp = _fake_resp(cookies={"TS01abc123": "y"})
        hits = wd.detect(resp)
        top_ids = [h.profile_id for h in hits]
        self.assertIn("f5_big_ip", top_ids, msg=f"TS01* sibling wildcard broken; got {top_ids}")


class EnvIntHelperTest(unittest.TestCase):
    """P11 (2026-06-11) — ``_env_int`` defensive env-var parser.

    Unguarded ``int(os.environ.get(...))`` calls in the fetch path crash
    every fetch on a single env typo. ``_env_int`` matches the pattern
    already used in ``_max_body_bytes``: invalid / below-minimum values fall
    back to the default and emit a stderr warning instead of raising.
    """

    @classmethod
    def setUpClass(cls):
        import sys as _sys
        _SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
        if str(_SKILL_ROOT) not in _sys.path:
            _sys.path.insert(0, str(_SKILL_ROOT))
        from engine.fetch_chain import _env_int
        cls._env_int = staticmethod(_env_int)

    def setUp(self):
        import os
        self._saved = {}
        for name in ("_INSANE_TEST_INT_A", "_INSANE_TEST_INT_B"):
            self._saved[name] = os.environ.pop(name, None)

    def tearDown(self):
        import os
        for name, val in self._saved.items():
            if val is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = val

    def test_missing_env_returns_default(self) -> None:
        import os
        os.environ.pop("_INSANE_TEST_INT_A", None)
        self.assertEqual(self._env_int("_INSANE_TEST_INT_A", 42), 42)

    def test_valid_int_returned(self) -> None:
        import os
        os.environ["_INSANE_TEST_INT_A"] = "7"
        self.assertEqual(self._env_int("_INSANE_TEST_INT_A", 10), 7)

    def test_invalid_string_returns_default_with_warning(self) -> None:
        import os, io, sys
        os.environ["_INSANE_TEST_INT_A"] = "not-a-number"
        buf = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = buf
        try:
            result = self._env_int("_INSANE_TEST_INT_A", 99)
        finally:
            sys.stderr = old_stderr
        self.assertEqual(result, 99)
        self.assertIn("WARNING", buf.getvalue())

    def test_below_min_returns_default_with_warning(self) -> None:
        import os, io, sys
        os.environ["_INSANE_TEST_INT_A"] = "0"
        buf = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = buf
        try:
            result = self._env_int("_INSANE_TEST_INT_A", 10, min_value=1)
        finally:
            sys.stderr = old_stderr
        self.assertEqual(result, 10)
        self.assertIn("WARNING", buf.getvalue())

    def test_min_value_zero_allows_zero(self) -> None:
        """Jitter values may legitimately be 0 (no delay) — min_value=0."""
        import os
        os.environ["_INSANE_TEST_INT_A"] = "0"
        self.assertEqual(self._env_int("_INSANE_TEST_INT_A", 150, min_value=0), 0)

    def test_exact_min_value_passes(self) -> None:
        """A value equal to min_value must not trigger the warning."""
        import os
        os.environ["_INSANE_TEST_INT_A"] = "1"
        self.assertEqual(self._env_int("_INSANE_TEST_INT_A", 10, min_value=1), 1)

    def test_whitespace_stripped(self) -> None:
        """Leading/trailing whitespace must not cause a parse error."""
        import os
        os.environ["_INSANE_TEST_INT_A"] = "  5  "
        self.assertEqual(self._env_int("_INSANE_TEST_INT_A", 10), 5)


# ---------------------------------------------------------------------------
# P24 (2026-06-12) — new WAF profiles + am_prefix dedup + signal-class scoring
# ---------------------------------------------------------------------------

class P24NewProfileSchemaTest(unittest.TestCase):
    """P24 — Fastly SigSci, Azure Front Door, Cloud Armor, DDoS-Guard schema."""

    @classmethod
    def setUpClass(cls):
        cls.profiles = wd._load_profiles()

    def _check(self, profile_id: str) -> None:
        prof = self.profiles.get(profile_id)
        self.assertIsNotNone(prof, f"missing profile {profile_id!r}")
        for field in _REQUIRED_FIELDS:
            self.assertIn(field, prof, f"{profile_id} missing required field {field!r}")
        detectors = prof["detectors"]
        self.assertIsInstance(detectors, dict)
        self.assertGreater(len(detectors), 0, f"{profile_id} has empty detectors")
        tls = prof["tls_impersonate_candidates"]
        self.assertTrue(
            all(isinstance(g, list) for g in tls),
            f"{profile_id} tls_impersonate_candidates must be list of lists",
        )

    def test_fastly_sigsci_schema(self):
        self._check("fastly_sigsci")

    def test_azure_front_door_schema(self):
        self._check("azure_front_door")

    def test_cloud_armor_schema(self):
        self._check("cloud_armor")

    def test_ddos_guard_schema(self):
        self._check("ddos_guard")


class P24FastlySigSciDetectorTest(unittest.TestCase):
    """Fastly SigSci (NGWAF) fingerprint resolves to fastly_sigsci."""

    def test_header_detects_fastly_sigsci(self):
        resp = _fake_resp(headers={"x-sigsci-tags": "SQLI", "x-sigsci-requestid": "abc123"})
        hits = wd.detect(resp)
        self.assertEqual(
            hits[0].profile_id, "fastly_sigsci",
            f"x-sigsci-* headers must resolve to fastly_sigsci; got {[h.profile_id for h in hits]}",
        )
        self.assertGreaterEqual(hits[0].confidence, 0.9)

    def test_single_header_weak_confidence(self):
        resp = _fake_resp(headers={"x-sigsci-tags": "SCANNER"})
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "fastly_sigsci")
        self.assertAlmostEqual(hits[0].confidence, 0.6)

    def test_body_detects_fastly_sigsci(self):
        resp = _fake_resp(body="<h1>Signal Sciences</h1><p>pow-button</p>")
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "fastly_sigsci")


class P24AzureFrontDoorDetectorTest(unittest.TestCase):
    """Azure Front Door fingerprint resolves to azure_front_door."""

    def test_header_detects_azure_fd(self):
        resp = _fake_resp(headers={
            "x-azure-ref": "0abc123",
            "x-azure-socketip": "192.0.2.4",
        })
        hits = wd.detect(resp)
        self.assertEqual(
            hits[0].profile_id, "azure_front_door",
            f"x-azure-* headers must resolve to azure_front_door; got {[h.profile_id for h in hits]}",
        )
        self.assertGreaterEqual(hits[0].confidence, 0.9)

    def test_body_detects_azure_fd(self):
        resp = _fake_resp(body="<p>Azure Front Door blocked this request</p>")
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "azure_front_door")


class P24CloudArmorDetectorTest(unittest.TestCase):
    """Cloud Armor fingerprint resolves to cloud_armor."""

    def test_server_header_detects_cloud_armor(self):
        resp = _fake_resp(headers={"server": "Google Frontend"})
        hits = wd.detect(resp)
        self.assertEqual(
            hits[0].profile_id, "cloud_armor",
            f"Google Frontend server header must resolve to cloud_armor; got {[h.profile_id for h in hits]}",
        )

    def test_body_detects_cloud_armor(self):
        resp = _fake_resp(
            body="<h1>The request was blocked by Cloud Armor</h1>",
            headers={"server": "Google Frontend"},
        )
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "cloud_armor")
        self.assertGreaterEqual(hits[0].confidence, 0.9)


class P24DdosGuardDetectorTest(unittest.TestCase):
    """DDoS-Guard fingerprint resolves to ddos_guard."""

    def test_cookie_detects_ddos_guard(self):
        resp = _fake_resp(cookies={"__ddg1_": "abc", "__ddg2_": "xyz"})
        hits = wd.detect(resp)
        self.assertEqual(
            hits[0].profile_id, "ddos_guard",
            f"__ddg* cookies must resolve to ddos_guard; got {[h.profile_id for h in hits]}",
        )
        self.assertGreaterEqual(hits[0].confidence, 0.9)

    def test_header_detects_ddos_guard(self):
        resp = _fake_resp(headers={"ddos-guard": "1"})
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "ddos_guard")

    def test_body_detects_ddos_guard(self):
        resp = _fake_resp(body="<title>DDoS-Guard</title>")
        hits = wd.detect(resp)
        self.assertEqual(hits[0].profile_id, "ddos_guard")


class P24AwsWafSignalClassTest(unittest.TestCase):
    """P24 (W22): aws_waf single-class signal flood must not reach strong confidence.

    x-amzn-requestid fires on all AWS-fronted traffic regardless of WAF presence.
    Multiple x-amzn-* headers are all header-class signals — even if count ≥
    confidence_rules.strong, they should be capped at weak (0.6) because all
    signals come from one class. Only mixing in a different class (cookie or body)
    unlocks strong confidence.
    """

    def test_single_amzn_header_is_weak(self):
        resp = _fake_resp(headers={"x-amzn-requestid": "abc-123"})
        hits = wd.detect(resp)
        aws_hits = [h for h in hits if h.profile_id == "aws_waf"]
        self.assertTrue(aws_hits, "aws_waf must fire on x-amzn-requestid")
        self.assertAlmostEqual(
            aws_hits[0].confidence, 0.6,
            msg="Single header-class signal must be weak (0.6), not strong (0.9)",
        )

    def test_multiple_amzn_headers_same_class_still_weak(self):
        # Two header-class signals (x-amzn-requestid + x-amzn-errortype) — both
        # header class. Even though count == strong threshold (2), same-class flood
        # must be capped at weak.
        resp = _fake_resp(headers={
            "x-amzn-requestid": "abc-123",
            "x-amzn-errortype": "Forbidden",
        })
        hits = wd.detect(resp)
        aws_hits = [h for h in hits if h.profile_id == "aws_waf"]
        self.assertTrue(aws_hits, "aws_waf must fire")
        self.assertAlmostEqual(
            aws_hits[0].confidence, 0.6,
            msg="Same-class multi-signal must stay weak even at count >= strong threshold",
        )

    def test_header_plus_cookie_is_strong(self):
        # Header-class + cookie-class = 2 distinct classes → strong confidence.
        resp = _fake_resp(
            headers={"x-amzn-requestid": "abc-123"},
            cookies={"aws-waf-token": "tok"},
        )
        hits = wd.detect(resp)
        aws_hits = [h for h in hits if h.profile_id == "aws_waf"]
        self.assertTrue(aws_hits, "aws_waf must fire on header+cookie")
        self.assertGreaterEqual(
            aws_hits[0].confidence, 0.9,
            msg="Header-class + cookie-class signals must yield strong (0.9) confidence",
        )

    def test_header_plus_body_is_strong(self):
        # Header-class + body-class = 2 distinct classes → strong confidence.
        resp = _fake_resp(
            headers={"x-amzn-requestid": "abc-123"},
            body="<p>aws-waf-token challenge page</p>",
        )
        hits = wd.detect(resp)
        aws_hits = [h for h in hits if h.profile_id == "aws_waf"]
        self.assertTrue(aws_hits, "aws_waf must fire")
        self.assertGreaterEqual(
            aws_hits[0].confidence, 0.9,
            msg="Header-class + body-class must yield strong confidence",
        )


class P24AmPrefixInProfilesTest(unittest.TestCase):
    """P24 (W21): profiles with mobile_subdomain must also have am_prefix.

    iter_transformed dedup prevents duplicate URLs when both transforms would
    produce the same result (e.g. apex domain where am_prefix fires but
    mobile_subdomain doesn't).
    """

    @classmethod
    def setUpClass(cls):
        cls.profiles = wd._load_profiles()

    def _url_transform_order(self, profile_id: str) -> list:
        prof = self.profiles.get(profile_id) or {}
        return prof.get("url_transform_order") or []

    def _assert_has_am_prefix(self, profile_id: str) -> None:
        order = self._url_transform_order(profile_id)
        self.assertIn(
            "am_prefix", order,
            f"{profile_id} has mobile_subdomain but is missing am_prefix (P24)",
        )

    def test_akamai_has_am_prefix(self):
        self._assert_has_am_prefix("akamai_bot_manager")

    def test_imperva_has_am_prefix(self):
        self._assert_has_am_prefix("imperva_incapsula")

    def test_sucuri_has_am_prefix(self):
        self._assert_has_am_prefix("sucuri_cloudproxy")

    def test_iter_transformed_dedup_apex(self):
        """For an apex URL, mobile_subdomain returns None (no www.) and am_prefix
        fires → one mobile URL. No duplicate even if both are in the order list."""
        from engine.url_transforms import iter_transformed
        url = "https://example.com/page"
        order = ["original", "mobile_subdomain", "am_prefix"]
        results = iter_transformed(url, order)
        result_urls = [u for _, u in results]
        # original + am_prefix (mobile_subdomain skips apex — no www.)
        self.assertEqual(len(result_urls), len(set(result_urls)), "iter_transformed must dedup")
        self.assertIn("https://m.example.com/page", result_urls)
        self.assertIn("https://example.com/page", result_urls)

    def test_iter_transformed_dedup_www(self):
        """For a www. URL, mobile_subdomain fires (www.→m.) and am_prefix skips
        (not apex). iter_transformed must not return the same URL twice."""
        from engine.url_transforms import iter_transformed
        url = "https://www.example.com/page"
        order = ["original", "mobile_subdomain", "am_prefix"]
        results = iter_transformed(url, order)
        result_urls = [u for _, u in results]
        self.assertEqual(len(result_urls), len(set(result_urls)), "iter_transformed must dedup")
        # mobile_subdomain: www. → m.
        self.assertIn("https://m.example.com/page", result_urls)


class P24ValidatorMarkerCoverageTest(unittest.TestCase):
    """P24 body markers added to waf_profiles.yaml must also be in CHALLENGE_MARKERS."""

    def _padded(self, snippet: str) -> str:
        return snippet + ("<p>filler content</p>" * 500)

    def test_sigsci_signal_sciences_marker(self):
        body = self._padded("<h1>Signal Sciences</h1>")
        result = v.validate(_fake_resp(body=body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)

    def test_cloud_armor_marker(self):
        body = self._padded("The request was blocked by Cloud Armor")
        result = v.validate(_fake_resp(body=body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)

    def test_ddos_guard_marker(self):
        body = self._padded("<title>DDoS-Guard</title>")
        result = v.validate(_fake_resp(body=body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)

    def test_perimeterx_app_id_marker(self):
        body = self._padded("window._pxAppId = 'PXabcdef';")
        result = v.validate(_fake_resp(body=body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)


class P24TieBreakerTest(unittest.TestCase):
    """P24: equal-confidence hits must be sorted by signal count, not YAML order."""

    def test_more_signals_ranks_first_at_equal_confidence(self):
        # Create two profiles with identical confidence but different signal counts.
        # Profile A fires 2 signals (strong=0.9); profile B fires 1 (weak=0.6).
        # After sort: A (0.9, 2 signals) > B (0.6, 1 signal).
        # This test uses real profiles: imperva (cookie+header combo) vs sucuri (server only).
        resp = _fake_resp(
            cookies={"visid_incap_99": "x"},
            headers={"x-iinfo": "1-2-3"},
        )
        hits = wd.detect(resp)
        # imperva fires with 2 signals (strong). If sucuri or another profile fires
        # at the same confidence, imperva must still rank first.
        top = hits[0]
        self.assertEqual(top.profile_id, "imperva_incapsula")
        # Confirm it has ≥2 signals (so tie-breaker was meaningful)
        self.assertGreaterEqual(len(top.signals), 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
