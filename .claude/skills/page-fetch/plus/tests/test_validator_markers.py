"""Phase 12 — CHALLENGE_MARKERS precision regression guard.

The bare `"captcha"` substring in `engine/validators.py` was too generic.
sixshop e-commerce HTML ships inert `data-useGoogleRecaptcha=""` /
`data-googleRecaptchaSiteKey=""` attributes on every page (the reCAPTCHA
integration is dormant — empty values, no widget rendered), so every
synthetic fetch verdicted as CHALLENGE despite a normal 200 OK / 73 KB body.

The fix replaces `"captcha"` with three more precise markers:
  - `"g-recaptcha"` — Google reCAPTCHA v2 visible widget class
  - `"h-captcha"` — hCaptcha visible widget class
  - `"Please complete the CAPTCHA"` — common user-facing prompt

Tests pin both directions:
  - Inert recaptcha attributes (sixshop pattern) must NOT trip CHALLENGE.
  - Real widget classes / prompt strings MUST trip CHALLENGE.
  - Pre-existing markers (Cloudflare, Akamai, DataDome) still trip.
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


def _fake_resp(body: str, status: int = 200, cookies: dict | None = None):
    """Minimal Response mock matching `validate()`'s attribute reads."""
    return SimpleNamespace(
        text=body,
        status_code=status,
        cookies=SimpleNamespace(jar=[]) if cookies is None else SimpleNamespace(
            jar=[SimpleNamespace(name=k, value=val) for k, val in cookies.items()]
        ),
    )


# Synthetic inert reCAPTCHA attributes (no production page content).
# (lowercased forms of these substrings would have matched the old
# bare `"captcha"` marker; the new markers must NOT trip on them).
INERT_RECAPTCHA = """
<div data-storeId=""
     data-brandId=""
     data-returnUrl=""
     data-useGoogleRecaptcha=""
     data-googleRecaptchaSiteKey=""
     data-googleRecaptchaHeightDesktop=""
     data-googleRecaptchaHeightMobile="">
</div>
"""


class CaptchaMarkerPrecisionTest(unittest.TestCase):
    """Phase 12 — captcha marker no longer trips on inert HTML attributes."""

    def _padded(self, snippet: str) -> str:
        """Pad past SMALL_BODY_THRESHOLD so the size-heuristic doesn't
        masquerade as the verdict we're testing."""
        return snippet + ("<p>filler</p>" * 500)

    def test_inert_recaptcha_attributes_do_not_trip_challenge(self) -> None:
        """A synthetic page mentions `recaptcha` only in
        empty `data-*` attributes (integration dormant). Must verdict WEAK_OK,
        not CHALLENGE."""
        body = self._padded(INERT_RECAPTCHA)
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.WEAK_OK,
            msg=f"Inert recaptcha attributes should not trip; got "
                f"reasons={result.reasons}",
        )

    def test_visible_recaptcha_widget_trips_challenge(self) -> None:
        """Real Google reCAPTCHA v2 widget — must still classify as CHALLENGE."""
        body = self._padded('<div class="g-recaptcha" data-sitekey="abc"></div>')
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)
        self.assertTrue(any("g-recaptcha" in r for r in result.reasons))

    def test_visible_hcaptcha_widget_trips_challenge(self) -> None:
        """hCaptcha widget class — same provider tier as reCAPTCHA."""
        body = self._padded('<div class="h-captcha" data-sitekey="abc"></div>')
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)
        self.assertTrue(any("h-captcha" in r for r in result.reasons))

    def test_user_facing_captcha_prompt_trips_challenge(self) -> None:
        """Custom challenge pages may not ship a known widget class but
        still include user-facing copy — case-insensitive substring.
        MED follow-up: 'complete the captcha' / 'solve the captcha'
        fragments catch all common imperative phrasings."""
        for variant in (
            "Please complete the CAPTCHA",
            "please complete the captcha to continue",
            "PLEASE COMPLETE THE CAPTCHA",
            "Complete the captcha below",
            "Solve the captcha to continue",
            "solve the CAPTCHA shown above",
        ):
            body = self._padded(f"<p>{variant}</p>")
            result = v.validate(_fake_resp(body))
            self.assertEqual(
                result.verdict, v.Verdict.CHALLENGE,
                msg=f"Variant {variant!r} should trip",
            )

    def test_imperative_prompt_fragments_do_not_match_inert_attributes(self) -> None:
        """Regression invariant for the MED follow-up: the new shorter
        fragments must NOT re-introduce the sixshop-style false positive
        the bare-`captcha` marker caused. Imperative-mood verbs
        (complete/solve) cannot legitimately appear inside an HTML
        attribute name like `data-useGoogleRecaptcha=""`."""
        body = self._padded(INERT_RECAPTCHA)
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.verdict, v.Verdict.WEAK_OK)

    def test_bare_word_captcha_alone_does_not_trip(self) -> None:
        """The whole point of Phase 12: 'captcha' as a bare word in any
        unrelated context (blog post, FAQ, attribute name) must NOT
        trigger. This is the regression invariant."""
        for body in (
            "<p>Our checkout uses captcha protection.</p>",  # marketing copy
            "<form data-captcha-key=''></form>",            # inert attribute
            "<!-- captcha integration TBD -->",              # comment
        ):
            result = v.validate(_fake_resp(self._padded(body)))
            self.assertNotEqual(
                result.verdict, v.Verdict.CHALLENGE,
                msg=f"Bare 'captcha' mention in {body!r} should not trip",
            )

    def test_other_existing_markers_unaffected(self) -> None:
        """Regression guard for the rest of CHALLENGE_MARKERS — make sure
        the Phase 12 edit didn't accidentally drop sibling entries."""
        for marker_excerpt, expected_substr in (
            ("<p>Just a moment...</p>", "just a moment"),
            ("<p>Access Denied by firewall</p>", "access denied"),
            ("<title>Bot Challenge</title>", "bot challenge"),
            ("<p>Powered and protected by Akamai</p>", "akamai"),
            ("<p>DataDome blocked you</p>", "datadome"),
        ):
            body = self._padded(marker_excerpt)
            result = v.validate(_fake_resp(body))
            self.assertEqual(
                result.verdict, v.Verdict.CHALLENGE,
                msg=f"Pre-existing marker for {expected_substr!r} should still trip",
            )


class ShapeGatedMarkerTest(unittest.TestCase):
    """Phase 13 — `g-recaptcha` / `h-captcha` widget-class markers only
    trigger on small bodies. Legitimate contact-form pages integrate the
    same widget class but ship a full-content body (≫10 KB); a real
    challenge page is widget + prompt + minimal JS (~few KB).
    """

    # Small payload — under SHAPE_GATE_MAX_BODY. Real challenge pages
    # look like this.
    SMALL_CHALLENGE = (
        '<html><body>'
        '<div class="g-recaptcha" data-sitekey="x"></div>'
        '<p>Please verify.</p>'
        '</body></html>'
    )

    SMALL_HCAPTCHA = (
        '<html><body>'
        '<div class="h-captcha" data-sitekey="x"></div>'
        '<p>Please verify.</p>'
        '</body></html>'
    )

    def _large(self, snippet: str) -> str:
        """Pad past the shape gate (10 KB) so the marker is ignored.
        Realistic content page would be 30 KB+; we use 15 KB for the
        smaller assertion margin."""
        return snippet + ("<p>real content paragraph</p>" * 600)

    def test_widget_class_in_small_body_still_challenges(self) -> None:
        """The real-challenge case must still verdict CHALLENGE — the
        shape gate is one-sided (small body keeps the trigger active)."""
        for body in (self.SMALL_CHALLENGE, self.SMALL_HCAPTCHA):
            result = v.validate(_fake_resp(body))
            self.assertEqual(
                result.verdict, v.Verdict.CHALLENGE,
                msg=f"Small-body widget should still trip; got {result.reasons}",
            )

    def test_widget_class_in_large_body_does_not_challenge(self) -> None:
        """Phase 13 core: a contact page integrating reCAPTCHA / hCaptcha
        with full content body must NOT verdict CHALLENGE."""
        for snippet in (self.SMALL_CHALLENGE, self.SMALL_HCAPTCHA):
            body = self._large(snippet)
            self.assertGreater(
                len(body), v.SHAPE_GATE_MAX_BODY,
                msg="test padding misconfigured",
            )
            result = v.validate(_fake_resp(body))
            self.assertNotEqual(
                result.verdict, v.Verdict.CHALLENGE,
                msg=f"Large-body widget should be ignored; got {result.reasons}",
            )

    def test_shape_gate_boundary_inclusive(self) -> None:
        """At `body_size == SHAPE_GATE_MAX_BODY` (10000) the marker still
        triggers — the gate is `>` not `>=`, deliberately so a body
        sized exactly at the cap is the *last* size that counts as small.
        Verifies the boundary semantics are pinned."""
        # Build a body whose total `len(text)` is exactly SHAPE_GATE_MAX_BODY.
        widget = '<div class="g-recaptcha"></div>'
        padding = "p" * (v.SHAPE_GATE_MAX_BODY - len(widget))
        body = widget + padding
        self.assertEqual(len(body), v.SHAPE_GATE_MAX_BODY)
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)

    def test_shape_gate_does_not_affect_other_markers(self) -> None:
        """Regression invariant: WAF product-string markers must remain
        scope-robust, large-body matches still trip. Only the widget-class
        markers are gated."""
        # Big body with Cloudflare's "Just a moment..." — has to still trip
        # even though body is >10 KB, because Cloudflare's challenge body
        # CAN be larger than the widget-only pattern.
        body = self._large("<title>Just a moment...</title>")
        self.assertGreater(len(body), v.SHAPE_GATE_MAX_BODY)
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)

    def test_prompt_markers_unaffected_by_shape_gate(self) -> None:
        """Imperative-mood prompt markers ('complete the captcha', etc.)
        are not in SHAPE_GATED_MARKERS — large-body match still trips.
        This is intentional: prompt copy doesn't appear in legitimate
        page content the way widget classes do."""
        body = self._large("<p>Please solve the captcha to continue.</p>")
        self.assertGreater(len(body), v.SHAPE_GATE_MAX_BODY)
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)

    def test_env_var_overrides_shape_gate(self) -> None:
        """MED-1 follow-up: `INSANE_SHAPE_GATE_MAX_BODY` is honoured at
        runtime. With the gate raised to 50_000, a 16 KB body containing
        `g-recaptcha` *does* trip (now considered "small enough"). Without
        the env, that same body would be too large and skip the marker.
        Pins both directions and restores env on teardown."""
        import os as _os
        saved = _os.environ.get("INSANE_SHAPE_GATE_MAX_BODY")
        self.addCleanup(
            lambda: _os.environ.pop("INSANE_SHAPE_GATE_MAX_BODY", None)
            if saved is None
            else _os.environ.__setitem__("INSANE_SHAPE_GATE_MAX_BODY", saved)
        )
        body = self._large(self.SMALL_CHALLENGE)  # ~16 KB
        self.assertGreater(len(body), v.SHAPE_GATE_MAX_BODY)

        # Without override: large body suppresses widget marker.
        _os.environ.pop("INSANE_SHAPE_GATE_MAX_BODY", None)
        self.assertNotEqual(v.validate(_fake_resp(body)).verdict, v.Verdict.CHALLENGE)

        # With override raising the gate above the body size: widget trips.
        _os.environ["INSANE_SHAPE_GATE_MAX_BODY"] = "50000"
        self.assertEqual(v.validate(_fake_resp(body)).verdict, v.Verdict.CHALLENGE)

        # Invalid env falls back to default (≈ no-override behaviour).
        _os.environ["INSANE_SHAPE_GATE_MAX_BODY"] = "not-a-number"
        self.assertNotEqual(v.validate(_fake_resp(body)).verdict, v.Verdict.CHALLENGE)

        # Non-positive falls back to default too.
        _os.environ["INSANE_SHAPE_GATE_MAX_BODY"] = "0"
        self.assertNotEqual(v.validate(_fake_resp(body)).verdict, v.Verdict.CHALLENGE)


class SelectorOverridesMarkerTest(unittest.TestCase):
    """P4 (2026-06-11) — success_selectors evaluated before Layer 1 markers.

    A normal page that mentions a WAF product name in explanatory copy (e.g.
    "How to fix Access Denied errors") must not verdict CHALLENGE when the
    caller has supplied a success_selector that matches real page content.

    Two regression directions:
      1. Marker present + selector matches → WEAK_OK (marker_overridden).
         NOT STRONG_OK: the marker prevents full trust promotion.
      2. Blocked page (no selector match) → CHALLENGE (no_success_selector).
    """

    def _padded(self, snippet: str) -> str:
        return snippet + ("<p>content paragraph</p>" * 500)

    def test_selector_rescues_access_denied_marker(self) -> None:
        """Page contains 'Access Denied' in copy but selector matches real
        content — must be WEAK_OK with marker_overridden, not CHALLENGE."""
        body = self._padded(
            "<p>Access Denied errors occur when permissions are missing.</p>"
            '<article class="main-content"><h1>Guide</h1></article>'
        )
        result = v.validate(
            _fake_resp(body),
            success_selectors=["article.main-content"],
        )
        self.assertEqual(
            result.verdict, v.Verdict.WEAK_OK,
            msg=f"selector should rescue marker FP; got reasons={result.reasons}",
        )
        self.assertIn("marker_overridden", result.reasons)
        self.assertIn("article.main-content", result.matched_selectors)

    def test_selector_rescues_datadome_marker(self) -> None:
        """DataDome mentioned in a tracking snippet on a normal page — real
        content selector must rescue it to WEAK_OK."""
        body = self._padded(
            '<script src="https://example.com/dd.js">/* DataDome */</script>'
            '<div id="product-listing"><p>Items here</p></div>'
        )
        result = v.validate(
            _fake_resp(body),
            success_selectors=["#product-listing"],
        )
        self.assertEqual(result.verdict, v.Verdict.WEAK_OK)
        self.assertIn("marker_overridden", result.reasons)

    def test_marker_override_verdict_is_weak_not_strong(self) -> None:
        """STRONG_OK must not be awarded when a challenge marker co-occurs
        with a selector match — cache-persistence trust token must be
        withheld (P4 verification constraint)."""
        body = self._padded(
            "<p>Just a moment...</p>"
            '<section id="content"><p>Real article text.</p></section>'
        )
        result = v.validate(
            _fake_resp(body),
            success_selectors=["#content"],
        )
        self.assertNotEqual(
            result.verdict, v.Verdict.STRONG_OK,
            msg="marker co-occurrence must cap verdict at WEAK_OK, not STRONG_OK",
        )
        self.assertEqual(result.verdict, v.Verdict.WEAK_OK)

    def test_real_blocked_page_still_challenges(self) -> None:
        """A genuine WAF block page contains the marker AND does not match
        the caller's success_selector — must still verdict CHALLENGE."""
        # Minimal challenge page: marker present, no real content structure.
        body = "<html><head><title>Access Denied</title></head><body><p>blocked</p></body></html>"
        result = v.validate(
            _fake_resp(body),
            success_selectors=["article.main-content"],
        )
        self.assertEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"real block page without selector match must stay CHALLENGE; got {result.reasons}",
        )
        self.assertIn("no_success_selector", result.reasons)

    def test_no_selectors_marker_still_challenges(self) -> None:
        """Regression: when no success_selectors are supplied, markers still
        trip CHALLENGE as before (Layer 1 path unchanged)."""
        body = self._padded("<p>Just a moment...</p>")
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)
        self.assertNotIn("marker_overridden", result.reasons)

    def test_matching_selector_takes_precedence_over_size_fp(self) -> None:
        """MEDIUM-3 / LOW-4 (2026-06-11): selector-first semantics — a matching
        success_selector returns STRONG_OK even when known_bad_sizes also matches.

        Pre-patch, size_fp was evaluated before selectors so it could override a
        positive selector match ("Layer 2 overrides selectors").  Post-patch,
        success_selectors are evaluated FIRST; Layer 2 is only reached when no
        selector block was entered (no success_selectors supplied).  A caller
        that passes both a matching selector AND a matching known_bad_size must
        get STRONG_OK (the selector wins), not CHALLENGE (the old size_fp path).
        """
        # Body contains a <p> tag so the selector ["p"] will match.
        body = "<html><body>" + "<p>content</p>" + "x" * 1480 + "</body></html>"
        body_size = len(body)
        result = v.validate(
            _fake_resp(body),
            success_selectors=["p"],          # matches → selector block entered
            known_bad_sizes=[body_size],      # would trigger CHALLENGE in old code
        )
        # Post-patch: selector matched and no challenge marker → STRONG_OK.
        # Layer 2 (size_fp) is never reached because the selector block returns early.
        self.assertEqual(result.verdict, v.Verdict.STRONG_OK)
        self.assertIn("p", (r.split(":")[-1] for r in result.matched_selectors or []))

    def test_unmatched_selector_challenges_regardless_of_size(self) -> None:
        """When selectors are supplied but none match, result is CHALLENGE
        via no_success_selector — size_fp is irrelevant in this path."""
        body = "x" * 1500
        result = v.validate(
            _fake_resp(body),
            success_selectors=["p"],           # will match nothing on "xxx..." body
            known_bad_sizes=[1500],
        )
        # selector finds no match → no_success_selector path → CHALLENGE
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)
        self.assertIn("no_success_selector", result.reasons)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
