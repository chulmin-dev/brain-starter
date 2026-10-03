"""Non-HTML document extraction path for page-fetch (P35).

The engine fetch chain decodes every response body to ``str`` via
``resp.text`` before the plus layer ever sees it, which destroys the raw
bytes of a binary document (PDF / Office / EPUB). So the engine path cannot
carry a PDF — by the time HTML extraction would run, the binary is already a
mojibake string. P35 therefore lives entirely in the plus layer: when the
target URL looks like a binary document, plus does its OWN size-capped,
SSRF-guarded binary fetch and hands the bytes to ``markitdown`` (a soft
dependency) rather than routing through the HTML engine.

Design contract:
  * HTML is NEVER routed here — trafilatura is strictly better for HTML and
    markitdown's HTML path is weaker. ``looks_like_binary_doc`` only matches
    known binary document extensions / content-types.
  * Detection is by URL path extension first; an optional cheap HEAD request
    refines it via the ``Content-Type`` header (the engine never surfaces
    Content-Type to plus, so we sniff it here on demand).
  * The binary GET drives redirects MANUALLY (``allow_redirects=False``,
    mirroring ``engine.fetch_chain._curl_probe``): every hop is re-checked with
    ``_ssrf_guard`` before the next GET, the final URL + the whole redirect
    trail go through ``_post_redirect_check``, and a ``_MAX_REDIRECTS`` ceiling
    caps the chain. A ``.pdf`` URL that 302-redirects to an internal host
    (``169.254.169.254`` etc.) is therefore refused at the hop that targets it,
    not silently followed — the same per-hop protection P28/P39r give the
    engine path. A streaming byte cap (``INSANE_MAX_BODY_BYTES``, default
    10 MiB — the same ceiling the engine enforces) RAISES on overflow so the
    callback aborts the transfer mid-stream, bounding bandwidth as well as
    memory. So a malicious/huge document can neither pivot to an internal host
    nor exhaust memory/bandwidth.
  * markitdown is fed ``convert_stream(BytesIO(data))`` — never
    ``MarkItDown().convert(url)``, which would have markitdown open its own
    socket and bypass the SSRF guard entirely.
  * docling (heavy, GPU-friendly PDF layout model) is intentionally NOT wired
    in — it is documented as an opt-in alternative only (see references).
"""
from __future__ import annotations

import io
import os
from urllib.parse import urljoin, urlsplit

from ._ssrf import _post_redirect_check, _ssrf_guard  # SSRF guards (proxy parity)

# Binary document extensions markitdown can convert. HTML/HTM are deliberately
# absent — they belong to the trafilatura HTML path, never here.
_BINARY_DOC_EXTENSIONS = frozenset({
    ".pdf",
    ".docx", ".doc",
    ".xlsx", ".xls",
    ".pptx", ".ppt",
    ".epub",
    ".odt", ".ods", ".odp",
})

# Content-Type substrings that mark a binary document. Matched case-folded
# against the HEAD Content-Type. ``text/html`` is excluded by construction.
_BINARY_DOC_CONTENT_TYPES = (
    "application/pdf",
    "application/vnd.openxmlformats-officedocument",  # docx/xlsx/pptx family
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/epub+zip",
    "application/vnd.oasis.opendocument",  # odt/ods/odp family
)

_MARKITDOWN_HINT = (
    "markitdown is required for non-HTML document extraction "
    "(--format markdown/text on a PDF/Office/EPUB URL). "
    "Install it with: pip install markitdown[all]"
)

# Reuse the engine's body-cap env + default so plus and engine agree on the
# ceiling (10 MiB). A binary doc larger than this is refused rather than
# buffered — markitdown would load the whole file into memory anyway.
_MAX_BODY_BYTES_ENV = "INSANE_MAX_BODY_BYTES"
_MAX_BODY_BYTES_DEFAULT = 10 * 1024 * 1024

# Redirect handling mirrors the engine: HTTP codes we follow, and a hop ceiling
# (env-overridable, same name the engine uses so an operator's cap applies to
# both paths). Default 10 matches libcurl's own default and the engine's
# `_MAX_REDIRECTS`.
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS_ENV = "INSANE_MAX_REDIRECTS"
_MAX_REDIRECTS_DEFAULT = 10


def _max_body_bytes() -> int:
    raw = os.environ.get(_MAX_BODY_BYTES_ENV, "").strip()
    if not raw:
        return _MAX_BODY_BYTES_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        return _MAX_BODY_BYTES_DEFAULT
    return value if value > 0 else _MAX_BODY_BYTES_DEFAULT


def _max_redirects() -> int:
    raw = os.environ.get(_MAX_REDIRECTS_ENV, "").strip()
    if not raw:
        return _MAX_REDIRECTS_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        return _MAX_REDIRECTS_DEFAULT
    return value if value > 0 else _MAX_REDIRECTS_DEFAULT


class _BinaryBodyTooLarge(Exception):
    """Sentinel raised inside the size-cap callback on overflow.

    curl_cffi's CFFI bridge coerces any callback exception into a libcurl
    transport failure, so this type is only visible to ``fetch_binary``'s own
    ``try/except`` around the GET — it never escapes to the caller. Mirrors the
    engine's ``_BodyCapAbort`` (``engine/fetch_chain.py``) so the streaming cap
    actually ABORTS the transfer mid-stream instead of letting libcurl drain
    the whole body off the socket.
    """


def _import_markitdown():
    """Import markitdown lazily. Raises RuntimeError with a clear hint."""
    try:
        from markitdown import MarkItDown  # noqa: F401
        return MarkItDown
    except ImportError as e:
        raise RuntimeError(_MARKITDOWN_HINT) from e


def _ext_of(url: str) -> str:
    """Lowercased path extension of `url` (including the dot), or ""."""
    path = urlsplit(url).path
    dot = path.rfind(".")
    if dot == -1:
        return ""
    # Guard against a dot that's actually in an earlier path segment.
    slash = path.rfind("/")
    if dot < slash:
        return ""
    return path[dot:].lower()


def looks_like_binary_doc(url: str, content_type: str | None = None) -> bool:
    """True if `url` (or its `content_type`) names a binary document.

    Extension match wins first (cheap, offline). When `content_type` is
    provided (e.g. from a HEAD probe) it is matched against the known binary
    document media types — but ``text/html`` and friends always return False
    by construction (they are never in the binary table).
    """
    if _ext_of(url) in _BINARY_DOC_EXTENSIONS:
        return True
    if content_type:
        ct = content_type.split(";", 1)[0].strip().lower()
        if ct.startswith("text/html") or ct.startswith("application/xhtml"):
            return False
        return any(ct.startswith(b) for b in _BINARY_DOC_CONTENT_TYPES)
    return False


def head_content_type(url: str, timeout: int = 15) -> str | None:
    """Best-effort HEAD probe returning the Content-Type, or None.

    SSRF-guarded. Used to refine extension-less URLs (e.g. a `/download?id=`
    endpoint that serves a PDF). Never raises — a failed probe just means
    "no extra signal", and the caller falls back to extension detection.
    """
    try:
        _ssrf_guard(url)
    except Exception:
        return None
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        return None
    # allow_redirects=False so a HEAD that 30x-redirects to an internal host
    # can't be followed un-guarded (same redirect gap as the GET path). We do
    # not chase HEAD redirects manually — a redirect means "no content-type
    # signal here", which is exactly the best-effort fall-through this probe
    # already promises. A 2xx with no redirect is the only case that yields a
    # Content-Type, and that URL was already pre-flight guarded above.
    try:
        resp = cffi_requests.head(
            url, impersonate="chrome", timeout=timeout,
            allow_redirects=False,
        )
    except Exception:  # noqa: BLE001 — best-effort sniff, never fatal
        return None
    try:
        if getattr(resp, "status_code", 0) in _REDIRECT_CODES:
            return None  # redirected away — treat as "no signal", don't follow
        return resp.headers.get("content-type")
    except Exception:  # noqa: BLE001
        return None


def fetch_binary(url: str, timeout: int = 25) -> bytes:
    """SSRF-guarded, size-capped binary GET. Returns the raw document bytes.

    Redirects are driven MANUALLY (``allow_redirects=False``): every hop's
    target is re-checked with ``_ssrf_guard`` before its GET is issued, the
    chain is capped at ``INSANE_MAX_REDIRECTS`` hops, and the final URL plus
    the full redirect trail are swept by ``_post_redirect_check``. A public
    ``.pdf`` URL that 302-redirects to an internal host is refused at that hop
    — the same per-hop protection the engine's ``_curl_probe`` provides — so
    this path can't be used as an SSRF redirect pivot.

    The byte cap (``INSANE_MAX_BODY_BYTES``, default 10 MiB) is enforced via
    curl_cffi's streaming ``content_callback`` which RAISES on overflow, so an
    oversized document aborts the transfer mid-stream rather than streaming the
    whole body off the socket (bounds bandwidth as well as memory). The cap is
    cumulative across redirect hops.

    Raises ``SSRFBlockedError`` on a blocked URL (pre-flight or any hop),
    ``RuntimeError`` if the response is too large, redirects too many times,
    or curl_cffi is missing.
    """
    _ssrf_guard(url)  # pre-flight: refuse SSRF-prone URLs before the GET

    try:
        from curl_cffi import requests as cffi_requests
    except ImportError as e:
        raise RuntimeError(
            "curl_cffi is required for binary document fetch. "
            "Install it with: pip install curl_cffi"
        ) from e

    cap = _max_body_bytes()
    max_redirects = _max_redirects()
    buf = bytearray()

    def _collect(chunk: bytes) -> None:
        # curl_cffi streams the body here when content_callback is set. We
        # accumulate up to the cap; on overflow we RAISE the sentinel so
        # libcurl coerces it into a transport abort and stops pulling the body
        # off the socket (matching engine _BodyCap). Keep the bytes that fit so
        # the abort path can still report how far it got.
        remaining = cap - len(buf)
        if len(chunk) > remaining:
            if remaining > 0:
                buf.extend(chunk[:remaining])
            raise _BinaryBodyTooLarge()
        buf.extend(chunk)

    # Manual redirect loop, mirroring engine.fetch_chain._curl_probe: each hop
    # is SSRF-guarded before its GET, and we never let libcurl auto-follow.
    current_url = url
    trace: list[str] = [current_url]
    hops = 0
    while True:
        try:
            resp = cffi_requests.get(
                current_url, impersonate="chrome", timeout=timeout,
                allow_redirects=False, content_callback=_collect,
            )
        except _BinaryBodyTooLarge:
            raise RuntimeError(
                f"binary document exceeds size cap ({cap} bytes); refusing. "
                f"Raise it with INSANE_MAX_BODY_BYTES if this is expected."
            ) from None
        except Exception as e:  # noqa: BLE001 — surface as a clean RuntimeError
            # The CFFI bridge collapses our sentinel into a generic transport
            # error in some curl_cffi builds; re-detect the cap trip by the
            # buffer being exactly full so the size message still wins.
            if len(buf) >= cap:
                raise RuntimeError(
                    f"binary document exceeds size cap ({cap} bytes); refusing. "
                    f"Raise it with INSANE_MAX_BODY_BYTES if this is expected."
                ) from None
            raise RuntimeError(
                f"binary fetch failed: {type(e).__name__}: {e}"
            ) from e

        status = getattr(resp, "status_code", 0)
        location = None
        if status in _REDIRECT_CODES:
            headers = getattr(resp, "headers", None)
            if headers is not None:
                location = headers.get("Location") or headers.get("location")
        if not location:
            break  # terminal response — bytes (if any) are in `buf`.

        hops += 1
        if hops > max_redirects:
            raise RuntimeError(
                f"binary fetch exceeded max redirects ({max_redirects})"
            )
        next_url = urljoin(current_url, location)
        _ssrf_guard(next_url)  # per-hop re-check — closes the redirect SSRF gap
        current_url = next_url
        trace.append(current_url)
        # A redirect hop discards the prior (empty) body; reset so the cap is
        # measured against the final response body, not redirect noise.
        buf.clear()

    # Defence-in-depth: re-sweep the final URL + the whole redirect trail even
    # though every hop was already guarded (covers any guard the per-hop check
    # could not see, mirroring the engine's always-on post-redirect sweep).
    _post_redirect_check(current_url, trace)

    if not buf:
        raise RuntimeError("binary fetch returned no content")
    return bytes(buf)


def extract_binary(url: str, fmt: str, timeout: int = 25) -> str:
    """Fetch a binary document and convert it to text/markdown via markitdown.

    `fmt` is one of the text-bearing formats ("raw"/"markdown"/"text"). All of
    them yield markitdown's text conversion — markitdown emits Markdown-ish
    text, which is the most useful representation of a PDF/Office file; "raw"
    has no meaningful binary analogue so it also returns the converted text.
    """
    MarkItDown = _import_markitdown()
    data = fetch_binary(url, timeout=timeout)
    md = MarkItDown()
    # convert_stream on the bytes we already fetched — NEVER md.convert(url),
    # which would have markitdown open its own (un-guarded) socket.
    result = md.convert_stream(io.BytesIO(data))
    text = getattr(result, "text_content", None)
    if text is None:
        text = str(result)
    return text
