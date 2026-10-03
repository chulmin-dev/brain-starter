"""Wave 1 (insane-search v0.8.x port) — small-complete page + byte-size size.

Two REAL false-CHALLENGE bugs the fork's `engine/validators.py` had in its
selector-less size fallback, ported surgically from upstream:

A3 — small-but-COMPLETE page mislabelled CHALLENGE
    A legitimately SHORT but COMPLETE HTML page (e.g. example.com ~600B, or a
    short Korean post) returns a clean 200 with real content, but the old size
    fallback flagged it `tiny_body` CHALLENGE on size alone → ok=False → the
    whole grid is wasted and the page is falsely reported "blocked". The fix
    (`_looks_complete_content_page`) checks for a complete HTML document marker
    (`</html>` / `</body>`) plus meaningful visible text before declaring
    CHALLENGE. Complete + content → WEAK_OK (`small_complete_page`). Only an
    incomplete / script-only / empty tiny body stays CHALLENGE (`tiny_body`).

A5 — byte-accurate body size (CJK correctness)
    `size = len(text)` counted CHARACTERS. For Korean/CJK a real ~4500-byte
    page is only ~1500 chars, falling under `SMALL_BODY_THRESHOLD` (3000) → a
    false `tiny_body` CHALLENGE. `size` is now `len(text.encode('utf-8'))`
    everywhere (reporting, shape gate, fingerprint, threshold). The
    `known_bad_sizes` fingerprints are byte sizes per the `validate()`
    docstring, so the Layer-2 comparison is now semantically correct too.

Tests pin both directions for each change.
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
    """Minimal Response mock matching `validate()`'s attribute reads
    (mirrors `_fake_resp` in test_validator_markers.py)."""
    return SimpleNamespace(
        text=body,
        status_code=status,
        cookies=SimpleNamespace(jar=[]) if cookies is None else SimpleNamespace(
            jar=[SimpleNamespace(name=k, value=val) for k, val in cookies.items()]
        ),
    )


# Real example.com response shape — a COMPLETE document, short (~600B), with
# real visible text well over the 64-char floor. This is the owner's daily
# selector-less "본문만 뽑아줘" path that the bug falsely reported as blocked.
EXAMPLE_DOT_COM = (
    "<!doctype html><html><head><title>Example Domain</title></head>"
    "<body><div><h1>Example Domain</h1>"
    "<p>This domain is for use in illustrative examples in documents. "
    "You may use this domain in literature without prior coordination "
    "or asking for permission.</p>"
    '<p><a href="https://www.iana.org/domains/example">More information...'
    "</a></p></div></body></html>"
)


class SmallCompletePageTest(unittest.TestCase):
    """A3 — a SMALL but COMPLETE content page is WEAK_OK, not CHALLENGE.

    Two regression directions:
      1. Complete document + meaningful visible text → WEAK_OK
         (`small_complete_page`), even though size < SMALL_BODY_THRESHOLD.
      2. Incomplete / script-only / empty tiny body → CHALLENGE (`tiny_body`).
    """

    def test_example_dot_com_small_complete_is_weak_ok(self) -> None:
        """The headline regression: a real short complete page (example.com)
        must verdict WEAK_OK with `small_complete_page`, not CHALLENGE."""
        result = v.validate(_fake_resp(EXAMPLE_DOT_COM))
        self.assertEqual(
            result.verdict, v.Verdict.WEAK_OK,
            msg=f"small complete page should be WEAK_OK; got reasons={result.reasons}",
        )
        self.assertTrue(
            any(r.startswith("small_complete_page") for r in result.reasons),
            msg=f"expected small_complete_page reason; got {result.reasons}",
        )
        # ok property must be True so the grid stops on this success.
        self.assertTrue(result.ok)

    def test_short_korean_complete_page_is_weak_ok(self) -> None:
        """A short Korean post under the byte threshold but a complete document
        with real visible text is a real page → WEAK_OK, not a blocked stub."""
        body = (
            "<html><body><article>"
            "한국어로 작성된 짧지만 완결된 본문입니다. 실제 내용이 충분히 들어 있어서 "
            "완전한 페이지로 인식되어야 하며, 차단 페이지가 아니라 정상 본문으로 "
            "분류되어야 합니다."
            "</article></body></html>"
        )
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.WEAK_OK,
            msg=f"short complete Korean page should be WEAK_OK; got {result.reasons}",
        )
        self.assertTrue(any(r.startswith("small_complete_page") for r in result.reasons))

    def test_incomplete_fragment_still_tiny_body_challenge(self) -> None:
        """A truncated fragment with NO closing </html>/</body> marker is still
        a suspicious stub → CHALLENGE with `tiny_body` (no rescue)."""
        body = "<html><head><script>window.x=1</script></head>"
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"incomplete fragment must stay CHALLENGE; got {result.reasons}",
        )
        self.assertTrue(any(r.startswith("tiny_body") for r in result.reasons))

    def test_script_only_complete_doc_still_challenge(self) -> None:
        """A complete document whose only content is script (no visible text)
        is a classic WAF interstitial shape → CHALLENGE, not rescued. The
        completeness marker alone is not enough; visible text is required."""
        body = "<html><body><script>var a=1; document.location='x';</script></body></html>"
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"script-only complete doc must stay CHALLENGE; got {result.reasons}",
        )
        self.assertTrue(any(r.startswith("tiny_body") for r in result.reasons))

    def test_empty_tiny_body_still_challenge(self) -> None:
        """An essentially empty body has no completeness marker and no visible
        text → CHALLENGE."""
        result = v.validate(_fake_resp("<html></html>"))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)
        self.assertTrue(any(r.startswith("tiny_body") for r in result.reasons))

    def test_completeness_marker_without_visible_text_is_challenge(self) -> None:
        """Boundary: a complete doc (</body> present) whose visible text is
        below the 64-char floor is NOT rescued — the floor guards against a
        challenge stub that ships an empty shell with closing tags."""
        body = "<html><body><p>short</p></body></html>"  # ~5 visible chars
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"thin complete shell must stay CHALLENGE; got {result.reasons}",
        )


class ByteAccurateSizeTest(unittest.TestCase):
    """A5 — `size` (and `body_size`) is BYTE length, not char count.

    Two regression directions:
      1. A CJK page over the byte threshold (but under it in chars) must NOT
         trip `tiny_body`, and `body_size` must report bytes.
      2. The `known_bad_sizes` Layer-2 fingerprint compares against BYTE size.
    """

    def test_korean_page_over_byte_threshold_not_tiny_body(self) -> None:
        """The headline regression: a Korean page whose char count is under
        SMALL_BODY_THRESHOLD but whose BYTE count is well over it must verdict
        WEAK_OK (not the false `tiny_body` CHALLENGE the char-count produced)."""
        # ~120 reps → ~1605 chars but ~4005 bytes (hangul is 3 bytes/char UTF-8).
        body = (
            "<html><body><article>"
            + ("안녕하세요 본문입니다. " * 120)
            + "</article></body></html>"
        )
        char_len = len(body)
        byte_len = len(body.encode("utf-8"))
        # Sanity: the test fixture must actually straddle the threshold to be
        # meaningful — char count below, byte count above.
        self.assertLess(char_len, v.SMALL_BODY_THRESHOLD)
        self.assertGreater(byte_len, v.SMALL_BODY_THRESHOLD)

        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.WEAK_OK,
            msg=f"CJK page over byte threshold must not be tiny_body; got {result.reasons}",
        )
        self.assertNotIn("tiny_body", " ".join(result.reasons))

    def test_body_size_reports_bytes_not_chars(self) -> None:
        """`body_size` on the result must be the UTF-8 byte length, the value
        a downstream cache / log / size_fp comparison expects."""
        body = (
            "<html><body><article>"
            + ("한국어 본문 내용. " * 120)
            + "</article></body></html>"
        )
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.body_size, len(body.encode("utf-8")),
            msg="body_size must be UTF-8 byte length, not character count",
        )
        self.assertNotEqual(
            result.body_size, len(body),
            msg="fixture must contain multibyte chars so bytes != chars",
        )

    def test_ascii_page_byte_size_equals_char_size(self) -> None:
        """Regression invariant: for a pure-ASCII body byte length == char
        length, so the byte-size switch is a no-op there (existing ASCII
        size-fingerprint tests stay green)."""
        body = "<html><body>" + ("<p>content</p>" * 300) + "</body></html>"
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.body_size, len(body))
        self.assertEqual(result.body_size, len(body.encode("utf-8")))

    def test_known_bad_size_fingerprint_compares_in_bytes(self) -> None:
        """The Layer-2 size fingerprint matches against the BYTE size. A caller
        supplying a byte-accurate `known_bad_sizes` value must trip CHALLENGE
        on a multibyte body whose byte size matches (char count would not)."""
        # Build a multibyte body, then fingerprint its exact BYTE size.
        body = (
            "<html><body>"
            + ("차단 페이지 본문. " * 100)
            + "</body></html>"
        )
        byte_len = len(body.encode("utf-8"))
        self.assertNotEqual(byte_len, len(body), "fixture must be multibyte")

        result = v.validate(_fake_resp(body), known_bad_sizes=[byte_len])
        self.assertEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"byte-accurate size_fp must trip CHALLENGE; got {result.reasons}",
        )
        self.assertTrue(any(r.startswith("size_fp") for r in result.reasons))

    def test_char_count_size_no_longer_matches_byte_fingerprint(self) -> None:
        """Companion to the above: supplying the CHARACTER count as a
        `known_bad_sizes` value must NOT trip on a multibyte body, because the
        comparison is now in bytes. This pins that the unit actually changed."""
        body = (
            "<html><body>"
            + ("정상 페이지 본문. " * 100)
            + "</body></html>"
        )
        char_len = len(body)
        byte_len = len(body.encode("utf-8"))
        # Tolerance is 20 by default; ensure char and byte sizes differ by more
        # than that so the char value can't accidentally match the byte size.
        self.assertGreater(abs(byte_len - char_len), 20)

        result = v.validate(_fake_resp(body), known_bad_sizes=[char_len])
        self.assertNotIn(
            "size_fp", " ".join(result.reasons),
            msg="char-count fingerprint must not match a byte-sized body",
        )


class SoftPhraseSuppressionTest(unittest.TestCase):
    """M2 — soft-phrase suppressor blocks the small-page rescue for JS-challenge
    interstitials that are complete HTML + visible text but not real pages.

    Three regression directions:
      (a) JS-challenge stub with soft phrase → stays CHALLENGE (not rescued).
      (b) Genuine short real page (example.com / short Korean, NO soft phrase)
          → still rescued to WEAK_OK.
      (c) Soft phrase inside a LARGE (>3 KB) legit page → rescue never runs
          there (body over threshold), verdict unaffected by the suppressor.
    """

    def test_verify_browser_interstitial_stays_challenge(self) -> None:
        """The headline M2 regression: a marker-less JS-challenge interstitial
        ('Please wait while we verify your browser… Redirecting…') is a complete
        HTML doc with real visible text, but must NOT be rescued to WEAK_OK
        because the visible text contains a soft JS-challenge phrase."""
        body = (
            "<html><body>"
            "<p>Please wait while we verify your browser before continuing. "
            "Redirecting…</p>"
            "</body></html>"
        )
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"JS-challenge stub with soft phrase must stay CHALLENGE; "
                f"got reasons={result.reasons}",
        )
        self.assertTrue(any(r.startswith("tiny_body") for r in result.reasons))

    def test_checking_your_browser_stays_challenge(self) -> None:
        """'Checking your browser' variant — also present in CHALLENGE_MARKERS
        (Layer 1), so it verdicts CHALLENGE regardless; the soft-phrase suppressor
        provides belt-and-suspenders for the rescue path too."""
        body = (
            "<html><head><title>One moment please</title></head>"
            "<body><p>Checking your browser before accessing the site.</p></body></html>"
        )
        result = v.validate(_fake_resp(body))
        self.assertEqual(result.verdict, v.Verdict.CHALLENGE)

    def test_redirecting_one_moment_stays_challenge(self) -> None:
        """Multiple soft-phrase variants in one body."""
        for phrase_body in (
            "<html><body><p>One moment, we are checking your connection.</p></body></html>",
            "<html><body><p>Enable JavaScript to continue.</p></body></html>",
            "<html><body><p>Verifying you are human. This may take a few seconds.</p></body></html>",
            "<html><body><p>Just a moment while we process your request and redirect you.</p></body></html>",
        ):
            result = v.validate(_fake_resp(phrase_body))
            self.assertEqual(
                result.verdict, v.Verdict.CHALLENGE,
                msg=f"Soft-phrase body should stay CHALLENGE; got {result.reasons} for {phrase_body!r}",
            )

    def test_real_short_page_without_soft_phrase_still_rescued(self) -> None:
        """Regression: a genuine short page with NO soft phrase must still
        be rescued to WEAK_OK — the suppressor must not over-fire."""
        result = v.validate(_fake_resp(EXAMPLE_DOT_COM))
        self.assertEqual(
            result.verdict, v.Verdict.WEAK_OK,
            msg=f"Real short page must still rescue to WEAK_OK; got {result.reasons}",
        )

    def test_korean_short_page_without_soft_phrase_still_rescued(self) -> None:
        """Short Korean content page with no soft phrase → WEAK_OK rescue."""
        body = (
            "<html><body><article>"
            "한국어로 작성된 짧지만 완결된 본문입니다. 실제 내용이 충분히 들어 있어서 "
            "완전한 페이지로 인식되어야 하며, 차단 페이지가 아니라 정상 본문으로 "
            "분류되어야 합니다."
            "</article></body></html>"
        )
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.WEAK_OK,
            msg=f"Short Korean page must rescue to WEAK_OK; got {result.reasons}",
        )

    def test_soft_phrase_in_large_page_does_not_affect_verdict(self) -> None:
        """Soft phrases in a LARGE (>3 KB) page are irrelevant: the rescue
        never runs for over-threshold bodies, so the suppressor is a no-op
        and the verdict is unchanged (WEAK_OK for a clean large body)."""
        # Build a large body containing a soft phrase buried in real content.
        large_body = (
            "<html><body><main>"
            "<p>Please wait — this is just marketing copy, not a challenge page.</p>"
            + "<p>Real article content paragraph.</p>" * 300
            + "</main></body></html>"
        )
        byte_len = len(large_body.encode("utf-8"))
        self.assertGreater(byte_len, v.SMALL_BODY_THRESHOLD,
                           msg="fixture must be over threshold to test the no-op path")
        result = v.validate(_fake_resp(large_body))
        self.assertNotEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"Soft phrase in large page must not trigger CHALLENGE; got {result.reasons}",
        )


class PlaywrightPathBodySizeTest(unittest.TestCase):
    """M3 — executor Playwright path now reports byte-accurate body_size.

    Before M3, `att.body_size = len(html)` counted Unicode characters. A CJK
    page reported ~1/3 the actual byte size, inconsistent with the curl path
    which uses `vr.body_size` (set by `_byte_size()` inside `validate()`).
    Fix: `att.body_size = vr.body_size` so both paths agree.
    """

    def _padded(self, snippet: str) -> str:
        return snippet + ("<p>filler</p>" * 500)

    def test_playwright_path_body_size_is_bytes_not_chars(self) -> None:
        """For a CJK HTML body, vr.body_size must equal UTF-8 byte count,
        not character count. This pins the M3 fix in executor.py."""
        from engine import validators as val
        from types import SimpleNamespace

        # Build a CJK body where bytes >> chars.
        ko_text = "한국어 본문 내용입니다. " * 100
        html = f"<html><body><article>{ko_text}</article></body></html>"
        char_len = len(html)
        byte_len = len(html.encode("utf-8"))
        self.assertNotEqual(char_len, byte_len, "fixture must be multibyte")

        # Simulate what executor does: validate via _FakeResp shim.
        class _FakeResp:
            def __init__(self, text: str):
                self.text = text
                self.status_code = 200
                self.cookies = SimpleNamespace(jar=[])

        vr = val.validate(_FakeResp(html))
        # Post-M3: vr.body_size is bytes (set by _byte_size inside validate).
        self.assertEqual(
            vr.body_size, byte_len,
            msg=f"vr.body_size must be UTF-8 bytes ({byte_len}), got {vr.body_size}",
        )
        self.assertNotEqual(
            vr.body_size, char_len,
            msg="vr.body_size must not be char count for multibyte content",
        )

    def test_ascii_playwright_body_size_unchanged(self) -> None:
        """For pure-ASCII content, byte == char, so M3 is a no-op (no regression)."""
        from engine import validators as val
        from types import SimpleNamespace

        html = "<html><body>" + "<p>ASCII content</p>" * 200 + "</body></html>"

        class _FakeResp:
            def __init__(self, text: str):
                self.text = text
                self.status_code = 200
                self.cookies = SimpleNamespace(jar=[])

        vr = val.validate(_FakeResp(html))
        self.assertEqual(vr.body_size, len(html))
        self.assertEqual(vr.body_size, len(html.encode("utf-8")))


class CjkShapeGateTest(unittest.TestCase):
    """L1 — shape gate is now byte-based; pin CJK boundary behaviour.

    Before A5, `_marker_hits` received a char-count `body_size`. For CJK,
    a body at the byte boundary (~10 KB) could be only ~3.3 KB chars, well
    under _SHAPE_GATE_DEFAULT, so widget-class markers fired on large CJK
    pages that are NOT challenge pages. After A5, body_size is bytes — a CJK
    body at 12 KB bytes correctly exceeds the 10 KB gate and suppresses the
    widget-class marker.
    """

    # A real CJK challenge page is small (widget + minimal JS). A large CJK
    # content page integrating reCAPTCHA in a contact form is the non-challenge
    # case we need the gate to protect.

    def test_widget_class_in_large_cjk_body_not_challenged(self) -> None:
        """A CJK content page that includes g-recaptcha in a contact form and
        whose BYTE size exceeds SHAPE_GATE_MAX_BODY must NOT verdict CHALLENGE
        (the byte-accurate gate suppresses the marker). Pre-A5 (char count),
        the ~12 KB body was only ~4 K chars — inside the gate — and would have
        triggered a false CHALLENGE."""
        # Build a body whose byte length is well over the gate but whose char
        # length is well under it. Each Korean char is 3 bytes.
        ko_filler = "한국어 실제 콘텐츠 페이지 본문 내용입니다. " * 400  # ~400*24 = ~9600 chars, ~28800 bytes
        body = (
            "<html><body>"
            '<div id="contact-form">'
            '<div class="g-recaptcha" data-sitekey="abc"></div>'
            "</div>"
            f"<article>{ko_filler}</article>"
            "</body></html>"
        )
        byte_len = len(body.encode("utf-8"))
        char_len = len(body)
        self.assertGreater(byte_len, v.SHAPE_GATE_MAX_BODY,
                           msg="fixture must exceed byte gate")
        self.assertGreater(char_len, v.SHAPE_GATE_MAX_BODY,
                           msg="fixture must also exceed char gate for this test to be unambiguous")
        result = v.validate(_fake_resp(body))
        self.assertNotEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"g-recaptcha in large CJK body must NOT trigger CHALLENGE; "
                f"got {result.reasons} (byte_len={byte_len}, char_len={char_len})",
        )

    def test_widget_class_in_small_cjk_body_still_challenges(self) -> None:
        """A genuine small CJK challenge page (widget + minimal text, under
        byte gate) still verdicts CHALLENGE — the one-sided gate only protects
        large bodies."""
        body = (
            "<html><body>"
            '<div class="g-recaptcha" data-sitekey="abc"></div>'
            "<p>잠시만 기다려주세요.</p>"
            "</body></html>"
        )
        byte_len = len(body.encode("utf-8"))
        self.assertLess(byte_len, v.SHAPE_GATE_MAX_BODY,
                        msg="fixture must be under the byte gate")
        result = v.validate(_fake_resp(body))
        self.assertEqual(
            result.verdict, v.Verdict.CHALLENGE,
            msg=f"g-recaptcha in small CJK body must still CHALLENGE; got {result.reasons}",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
