"""Tests for P35 — non-HTML document extraction path.

Covers:
  * looks_like_binary_doc: extension detection + content-type refinement,
    with HTML always excluded (offline, no deps).
  * fetch_binary: SSRF guard runs before the GET; size cap is enforced.
  * extract_binary: markitdown convert_stream is fed the fetched BYTES, never
    md.convert(url) (which would bypass the SSRF guard) — soft-gated on
    markitdown presence.

The detection tests are dependency-free so they always run; the conversion
tests mock the binary fetch so no network is touched, and are skipped only
when markitdown itself is absent.
"""
from __future__ import annotations

import importlib.util
import io
import unittest
from unittest.mock import patch

from plus import binary_extract
from plus.binary_extract import (
    extract_binary,
    fetch_binary,
    head_content_type,
    looks_like_binary_doc,
)
from plus._ssrf import SSRFBlockedError


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


_HAS_MARKITDOWN = _has("markitdown")
_HAS_CURL = _has("curl_cffi")


class TestDetection(unittest.TestCase):
    """looks_like_binary_doc — pure logic, no network."""

    def test_pdf_extension_detected(self):
        self.assertTrue(looks_like_binary_doc("https://e.example.org/report.pdf"))

    def test_office_extensions_detected(self):
        for ext in (".docx", ".xlsx", ".pptx", ".doc", ".xls", ".epub"):
            self.assertTrue(
                looks_like_binary_doc(f"https://e.example.org/file{ext}"),
                f"{ext} should be detected",
            )

    def test_html_never_detected_by_extension(self):
        self.assertFalse(looks_like_binary_doc("https://e.example.org/page.html"))
        self.assertFalse(looks_like_binary_doc("https://e.example.org/page.htm"))

    def test_no_extension_no_content_type_is_false(self):
        self.assertFalse(looks_like_binary_doc("https://e.example.org/download"))

    def test_query_string_does_not_confuse_extension(self):
        # dot is in the query, not the path → no false positive.
        self.assertFalse(
            looks_like_binary_doc("https://e.example.org/page?file=a.pdf")
        )

    def test_content_type_refines_extensionless_url(self):
        self.assertTrue(
            looks_like_binary_doc(
                "https://e.example.org/download?id=5",
                content_type="application/pdf",
            )
        )

    def test_content_type_html_overrides_to_false(self):
        # Even if a HEAD says html, never route HTML to markitdown.
        self.assertFalse(
            looks_like_binary_doc(
                "https://e.example.org/download",
                content_type="text/html; charset=utf-8",
            )
        )

    def test_office_content_type_family_detected(self):
        self.assertTrue(
            looks_like_binary_doc(
                "https://e.example.org/x",
                content_type=(
                    "application/vnd.openxmlformats-officedocument"
                    ".wordprocessingml.document"
                ),
            )
        )


class TestFetchBinarySSRF(unittest.TestCase):
    """fetch_binary must SSRF-guard before opening any socket."""

    def test_ssrf_block_raised_before_fetch(self):
        # A loopback URL is blocked by the guard; curl must never be reached.
        with patch.object(binary_extract, "_import_markitdown"):
            with self.assertRaises(SSRFBlockedError):
                fetch_binary("http://127.0.0.1/secret.pdf")

    def test_link_local_metadata_endpoint_blocked(self):
        with self.assertRaises(SSRFBlockedError):
            fetch_binary("http://169.254.169.254/latest.pdf")


@unittest.skipUnless(_HAS_CURL, "curl_cffi not installed")
class TestFetchBinaryRedirectSSRF(unittest.TestCase):
    """A redirect to an internal host must be refused per-hop, not followed.

    The S39-1/CR-HIGH gap: before the fix, fetch_binary used
    allow_redirects=True so libcurl followed a 302→169.254.169.254 with no
    per-hop guard. These tests prove the manual loop now re-runs _ssrf_guard on
    each Location.
    """

    @staticmethod
    def _resp(status, location=None, headers=None):
        r = unittest.mock.MagicMock()
        r.status_code = status
        r.headers = dict(headers or {})
        if location is not None:
            r.headers["location"] = location
        return r

    def test_302_to_link_local_metadata_refused(self):
        from curl_cffi import requests as cffi_requests

        def fake_get(url, **kwargs):
            # Public entry URL 302-redirects to the cloud-metadata endpoint.
            if url == "https://evil.test/report.pdf":
                return self._resp(302, "http://169.254.169.254/latest.pdf")
            raise AssertionError(
                f"internal host must NOT be fetched, but GET hit {url!r}"
            )

        with patch.object(cffi_requests, "get", side_effect=fake_get):
            with self.assertRaises(SSRFBlockedError):
                fetch_binary("https://evil.test/report.pdf")

    def test_302_to_private_ip_refused(self):
        from curl_cffi import requests as cffi_requests

        def fake_get(url, **kwargs):
            if url == "https://evil.test/report.pdf":
                return self._resp(302, "http://10.0.0.1/x.pdf")
            raise AssertionError(f"private host fetched: {url!r}")

        with patch.object(cffi_requests, "get", side_effect=fake_get):
            with self.assertRaises(SSRFBlockedError):
                fetch_binary("https://evil.test/report.pdf")

    def test_redirect_to_public_host_followed_and_returned(self):
        # A redirect to another PUBLIC host is allowed and its body returned —
        # proves the guard refuses internal hops without breaking legit ones.
        from curl_cffi import requests as cffi_requests
        payload = b"%PDF-1.7 redirected body"

        def fake_get(url, **kwargs):
            if url == "https://a.test/doc.pdf":
                return self._resp(301, "https://b.test/real.pdf")
            if url == "https://b.test/real.pdf":
                kwargs["content_callback"](payload)
                return self._resp(200)
            raise AssertionError(f"unexpected GET {url!r}")

        with patch.object(cffi_requests, "get", side_effect=fake_get):
            out = fetch_binary("https://a.test/doc.pdf")
        self.assertEqual(out, payload)

    def test_redirect_loop_capped(self):
        from curl_cffi import requests as cffi_requests

        def fake_get(url, **kwargs):
            # Always redirect to a distinct public host → never terminal.
            n = url.count("/")
            return self._resp(302, f"https://host{n}.test/loop.pdf")

        with patch.object(cffi_requests, "get", side_effect=fake_get):
            with self.assertRaises(RuntimeError) as ctx:
                fetch_binary("https://start.test/loop.pdf")
        self.assertIn("redirect", str(ctx.exception).lower())


@unittest.skipUnless(_HAS_CURL, "curl_cffi not installed")
class TestFetchBinaryCap(unittest.TestCase):
    """The streaming byte cap aborts oversized documents."""

    def test_oversized_document_refused(self):
        # Simulate curl_cffi streaming a body larger than the cap into the
        # content_callback, then return as if the transfer completed.
        from curl_cffi import requests as cffi_requests

        def fake_get(url, **kwargs):
            cb = kwargs["content_callback"]
            # 11 MiB in one chunk — past the 10 MiB default cap.
            cb(b"\x00" * (11 * 1024 * 1024))
            return object()

        with patch.object(cffi_requests, "get", side_effect=fake_get):
            with self.assertRaises(RuntimeError) as ctx:
                fetch_binary("https://e.example.org/big.pdf")
        self.assertIn("size cap", str(ctx.exception))

    def test_oversized_aborts_mid_stream(self):
        # Prove the cap RAISES inside the callback (bandwidth abort), not just
        # flags-and-continues. Feed chunks one at a time; the callback must
        # raise on the chunk that crosses the cap so the simulated stream
        # cannot push further bytes (CR-MEDIUM: docstring "aborts mid-stream").
        from curl_cffi import requests as cffi_requests
        import os

        os.environ["INSANE_MAX_BODY_BYTES"] = "100"
        self.addCleanup(os.environ.pop, "INSANE_MAX_BODY_BYTES", None)

        fed = {"chunks": 0}

        def fake_get(url, **kwargs):
            cb = kwargs["content_callback"]
            # Stream 1000 chunks of 10 bytes; the cap is 100 → the 11th chunk
            # crosses it and the callback must raise, halting the stream.
            for _ in range(1000):
                fed["chunks"] += 1
                cb(b"\x00" * 10)  # raises _BinaryBodyTooLarge once over cap
            return object()

        with patch.object(cffi_requests, "get", side_effect=fake_get):
            with self.assertRaises(RuntimeError) as ctx:
                fetch_binary("https://e.example.org/big.pdf")
        self.assertIn("size cap", str(ctx.exception))
        # The loop must have been cut short well before 1000 chunks — proof the
        # transfer aborted mid-stream rather than draining the whole body.
        self.assertLessEqual(fed["chunks"], 12)

    def test_under_cap_returns_bytes(self):
        from curl_cffi import requests as cffi_requests

        payload = b"%PDF-1.7 small body"

        def fake_get(url, **kwargs):
            kwargs["content_callback"](payload)
            return object()

        with patch.object(cffi_requests, "get", side_effect=fake_get):
            out = fetch_binary("https://e.example.org/small.pdf")
        self.assertEqual(out, payload)


class TestExtractBinaryUsesStreamNotUrl(unittest.TestCase):
    """extract_binary must feed markitdown the fetched bytes, never the URL."""

    def test_convert_stream_called_with_fetched_bytes(self):
        fake_md = unittest.mock.MagicMock()
        fake_result = unittest.mock.MagicMock()
        fake_result.text_content = "# Converted PDF\n\nbody text"
        fake_md.convert_stream.return_value = fake_result

        with patch.object(
            binary_extract, "_import_markitdown", return_value=lambda: fake_md
        ), patch.object(
            binary_extract, "fetch_binary", return_value=b"%PDF-1.7 bytes"
        ):
            out = extract_binary("https://e.example.org/doc.pdf", "markdown")

        self.assertEqual(out, "# Converted PDF\n\nbody text")
        # convert_stream was used (SSRF-safe), convert(url) was NOT.
        fake_md.convert_stream.assert_called_once()
        fake_md.convert.assert_not_called()
        stream_arg = fake_md.convert_stream.call_args[0][0]
        self.assertIsInstance(stream_arg, io.BytesIO)

    def test_missing_markitdown_raises_actionable_error(self):
        with patch.object(
            binary_extract, "_import_markitdown",
            side_effect=RuntimeError(binary_extract._MARKITDOWN_HINT),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                extract_binary("https://e.example.org/doc.pdf", "markdown")
        self.assertIn("markitdown", str(ctx.exception))


@unittest.skipUnless(_HAS_MARKITDOWN, "markitdown not installed")
class TestExtractBinaryRealMarkitdown(unittest.TestCase):
    """End-to-end with the real markitdown library (no network)."""

    def test_real_convert_stream_on_minimal_docx(self):
        # Build a tiny valid .docx in memory so markitdown has real bytes.
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(
                "[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxml'
                'formats.org/package/2006/content-types"><Default '
                'Extension="xml" ContentType="application/xml"/></Types>',
            )
            z.writestr(
                "_rels/.rels",
                '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                'openxmlformats.org/package/2006/relationships"><Relationship '
                'Id="rId1" Type="http://schemas.openxmlformats.org/office'
                'Document/2006/relationships/officeDocument" '
                'Target="word/document.xml"/></Relationships>',
            )
            z.writestr(
                "word/document.xml",
                '<?xml version="1.0"?><w:document xmlns:w="http://schemas.'
                'openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                '<w:p><w:r><w:t>Hello binary world</w:t></w:r></w:p>'
                '</w:body></w:document>',
            )
        docx_bytes = buf.getvalue()

        with patch.object(
            binary_extract, "fetch_binary", return_value=docx_bytes
        ):
            out = extract_binary("https://e.example.org/d.docx", "markdown")
        self.assertIn("Hello binary world", out)


if __name__ == "__main__":
    unittest.main()
