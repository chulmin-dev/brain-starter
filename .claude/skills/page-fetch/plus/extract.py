"""Output pipeline for page-fetch.

`extract(html, fmt, url, ...)` turns raw fetched HTML into the format the caller
asked for: raw HTML, Markdown, plain text, a metadata JSON blob, or a
pruned/query-filtered "fit" variant.

trafilatura is a soft dependency: it is imported lazily so a missing install
produces a clear, actionable error only when a format that needs it is used.
The same holds for the optional metadata enrichers (htmldate, extruct) and the
content-filter module (bs4-only): each is imported at point of use so the
`raw` format never triggers an install of anything (lazy-import design, P14).
"""
from __future__ import annotations

import json
import re
import sys

_TRAFILATURA_HINT = (
    "trafilatura is required for --format markdown/text/fit_markdown/fit_text. "
    "Install it with: pip install trafilatura"
)


def _import_trafilatura():
    """Import trafilatura lazily. Raises RuntimeError with a clear hint."""
    try:
        import trafilatura  # noqa: F401
        return trafilatura
    except ImportError as e:
        raise RuntimeError(_TRAFILATURA_HINT) from e


def _import_bs4():
    """Import BeautifulSoup lazily. Raises RuntimeError with a clear hint."""
    try:
        from bs4 import BeautifulSoup  # noqa: F401
        return BeautifulSoup
    except ImportError as e:
        raise RuntimeError(
            "beautifulsoup4 is required for --format metadata and as the "
            "text fallback. Install it with: pip install beautifulsoup4"
        ) from e


def _import_htmldate():
    """Import htmldate lazily. Returns the module or None if unavailable.

    htmldate ships as a hard dependency of trafilatura, so it is normally
    present whenever trafilatura is. We still guard the import and surface a
    clear stderr notice on absence (no silent skip) so a stripped-down install
    is diagnosable rather than mysteriously missing publish dates.
    """
    try:
        import htmldate  # noqa: F401
        return htmldate
    except ImportError:
        print(
            "[plus] note: htmldate not installed; publish-date extraction "
            "skipped. Install it with: pip install htmldate",
            file=sys.stderr,
        )
        return None


def _import_extruct():
    """Import extruct lazily. Returns the module or None if unavailable.

    extruct is an optional enricher (Microdata / Dublin Core / lenient JSON-LD).
    Absence is expected on bare installs, so we return None and let the caller
    fall back to the bs4 metadata path — but we record that extruct was absent
    in the output (no silent default: the metadata blob carries an explicit
    `extruct_available` flag).
    """
    try:
        import extruct  # noqa: F401
        return extruct
    except ImportError:
        return None


def _bs4_text_fallback(html: str) -> str:
    """Plain-text fallback when trafilatura yields nothing.

    Tries trafilatura.baseline() first (structure-preserving rescue ladder)
    before the bare bs4 get_text dump, which mixes in nav/footer/cookie chrome.
    """
    trafilatura = _import_trafilatura()
    try:
        # baseline() returns (lxml_element, text, text_length).
        _, baseline_text, baseline_len = trafilatura.baseline(html)
    except Exception:  # noqa: BLE001 — baseline is best-effort rescue
        baseline_text, baseline_len = "", 0
    if baseline_len and baseline_text.strip():
        return baseline_text

    BeautifulSoup = _import_bs4()
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return soup.get_text(separator="\n", strip=True)


# Normalized metadata keys we surface from trafilatura's Document.as_dict().
# author/date/description/sitename/license/tags are the high-value fields the
# bs4 raw-tag path cannot produce reliably.
_NORMALIZED_META_KEYS = (
    "author", "date", "description", "sitename", "title",
    "license", "tags", "categories", "hostname", "image", "pagetype",
)


def _normalized_metadata(html: str, url: str) -> dict | None:
    """trafilatura bare_extraction normalized metadata, or None on failure.

    Single parse pass via bare_extraction(with_metadata=True). Returns the
    normalized field subset; None if trafilatura cannot build a Document (the
    caller keeps the bs4 raw path either way — the two are complementary).
    """
    trafilatura = _import_trafilatura()
    try:
        doc = trafilatura.bare_extraction(
            html, with_metadata=True, url=url or None,
        )
    except Exception:  # noqa: BLE001 — best-effort enrichment
        return None
    if doc is None:
        return None
    try:
        d = doc.as_dict()
    except AttributeError:
        # Older/newer trafilatura returning a dict directly.
        d = doc if isinstance(doc, dict) else None
    if not isinstance(d, dict):
        return None
    return {k: d.get(k) for k in _NORMALIZED_META_KEYS if d.get(k)}


# Leading line/block comments some CMSs emit before JSON-LD. `//` comments are
# stripped per-line (no DOTALL — must not swallow the JSON body); HTML comments
# are stripped as a leading block.
_JSONLD_LINE_COMMENT_RE = re.compile(r"^\s*//.*$", re.MULTILINE)
_JSONLD_HTML_COMMENT_RE = re.compile(r"^\s*<!--.*?-->", re.DOTALL)


def _strip_jsonld_comments(raw: str) -> str:
    """Remove leading // line comments and a leading HTML comment block."""
    out = _JSONLD_HTML_COMMENT_RE.sub("", raw)
    out = _JSONLD_LINE_COMMENT_RE.sub("", out)
    return out.strip()


def _parse_jsonld_lenient(raw: str):
    """Parse one JSON-LD script block leniently.

    1. strict=False json.loads (control chars allowed)
    2. on failure, strip leading // / HTML comments and retry
    Returns the parsed object, or a `_parse_error` stub only if both fail —
    this rescues the leading-comment / control-char cases the old strict
    parser flagged as errors.
    """
    try:
        return json.loads(raw, strict=False)
    except (json.JSONDecodeError, ValueError):
        pass
    stripped = _strip_jsonld_comments(raw)
    if stripped and stripped != raw.strip():
        try:
            return json.loads(stripped, strict=False)
        except (json.JSONDecodeError, ValueError):
            pass
    return {
        "_parse_error": True,
        "_raw": raw[:500],
        "_raw_length": len(raw),  # flags truncation when > 500
    }


def _extract_metadata(html: str, url: str = "") -> dict:
    """Parse OGP, Twitter Card, and JSON-LD metadata into a plain dict.

    Layers, all merged (complementary, none replaces another):
      * bs4 raw tags: OGP (og:*), Twitter Card (twitter:*), JSON-LD, <title>.
        Twitter Card especially is bs4-only — extruct's OpenGraph extractor
        reads property= attrs and misses name=twitter:*.
      * trafilatura bare_extraction → `normalized` key (author/date/description/
        sitename/license/tags), with htmldate publish date when present.
      * extruct (soft) → `microdata`/`dublincore`/`extruct_jsonld` keys with
        uniform=True; rdfa omitted from the explicit `syntaxes` allowlist (OFF).
    """
    BeautifulSoup = _import_bs4()
    soup = BeautifulSoup(html, "html.parser")

    ogp: dict[str, str] = {}
    twitter: dict[str, str] = {}
    for meta in soup.find_all("meta"):
        prop = meta.get("property") or ""
        name = meta.get("name") or ""
        content = meta.get("content")
        if content is None:
            continue
        if prop.startswith("og:"):
            ogp[prop] = content
        elif name.startswith("twitter:"):
            twitter[name] = content

    jsonld: list = []
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        raw = script.string or script.get_text() or ""
        raw = raw.strip()
        if not raw:
            continue
        jsonld.append(_parse_jsonld_lenient(raw))

    title_tag = soup.find("title")
    result: dict = {
        "title": title_tag.get_text(strip=True) if title_tag else None,
        "ogp": ogp,
        "twitter": twitter,
        "jsonld": jsonld,
    }

    # --- trafilatura normalized metadata (complementary to raw bs4 above) ---
    normalized = _normalized_metadata(html, url)
    if normalized is not None:
        result["normalized"] = normalized
        # htmldate publish date — only fill if trafilatura didn't already.
        if not normalized.get("date"):
            htmldate = _import_htmldate()
            if htmldate is not None:
                try:
                    found = htmldate.find_date(
                        html, extensive_search=True,
                        url=url or None,
                    )
                except Exception:  # noqa: BLE001 — best-effort date probe
                    found = None
                if found:
                    normalized["date"] = found

    # --- extruct soft-dep: Microdata / Dublin Core / lenient JSON-LD ---
    extruct = _import_extruct()
    result["extruct_available"] = extruct is not None
    if extruct is not None:
        try:
            data = extruct.extract(
                html,
                base_url=url or None,
                # CR-L5: rdfa is deliberately omitted from `syntaxes` (it's noisy
                # and rarely present); listing only the three we want makes the
                # "rdfa OFF" intent explicit in code, not reliant on the extruct
                # default for an unlisted syntax.
                syntaxes=["microdata", "json-ld", "dublincore"],
                uniform=True,
                errors="ignore",
            )
        except Exception:  # noqa: BLE001 — soft enricher, never fatal
            data = None
        if isinstance(data, dict):
            if data.get("microdata"):
                result["microdata"] = data["microdata"]
            if data.get("dublincore"):
                result["dublincore"] = data["dublincore"]
            if data.get("json-ld"):
                result["extruct_jsonld"] = data["json-ld"]

    return result


def _trafilatura_extract(
    trafilatura, html: str, url: str, output_format: str,
    favor_recall: bool, favor_precision: bool,
):
    """Single trafilatura.extract call with recall/precision knobs threaded."""
    return trafilatura.extract(
        html,
        output_format=output_format,
        url=url or None,
        favor_recall=favor_recall,
        favor_precision=favor_precision,
    )


def extract(
    html: str,
    fmt: str,
    url: str = "",
    *,
    favor_recall: bool = False,
    favor_precision: bool = False,
    query: str | None = None,
    prune_threshold: float | None = None,
) -> str:
    """Post-process fetched HTML into the requested output format.

    Parameters
    ----------
    html : str
        Raw HTML returned by the engine fetch chain.
    fmt : str
        One of "raw", "markdown", "text", "metadata", "fit_markdown",
        "fit_text".
    url : str
        Final URL of the document; passed to trafilatura for link resolution
        and to the metadata enrichers for date/base-URL resolution.
    favor_recall, favor_precision : bool
        trafilatura extraction-mode knobs (P14). Mutually exclusive — the CLI
        enforces that; passing both here lets recall win in trafilatura.
    query : str | None
        When set, BM25-filter the extracted/pruned text to query-relevant
        blocks (P29 --query).
    prune_threshold : float | None
        Pruning threshold for the fit_* formats (P29 --prune). None uses the
        module default.

    Returns
    -------
    str
        The formatted output. For "metadata" this is a JSON string.
    """
    if fmt == "raw":
        return html

    if fmt == "metadata":
        return json.dumps(
            _extract_metadata(html, url=url), ensure_ascii=False, indent=2,
        )

    if fmt in ("fit_markdown", "fit_text"):
        from .content_filter import prune_html
        kwargs = {} if prune_threshold is None else {"threshold": prune_threshold}
        pruned = prune_html(html, **kwargs)
        inner_fmt = "markdown" if fmt == "fit_markdown" else "text"
        body = _markdown_or_text(
            pruned, inner_fmt, url, favor_recall, favor_precision,
        )
        return _apply_query(body, html, query)

    if fmt in ("markdown", "text"):
        body = _markdown_or_text(
            html, fmt, url, favor_recall, favor_precision,
        )
        return _apply_query(body, html, query)

    raise ValueError(f"unknown format: {fmt!r}")


def _markdown_or_text(
    html: str, fmt: str, url: str,
    favor_recall: bool, favor_precision: bool,
) -> str:
    """Run trafilatura for markdown/text, with baseline+bs4 rescue."""
    trafilatura = _import_trafilatura()
    output_format = "markdown" if fmt == "markdown" else "txt"
    out = _trafilatura_extract(
        trafilatura, html, url, output_format, favor_recall, favor_precision,
    )
    if out is None or not out.strip():
        print(
            "[plus] warning: trafilatura extraction returned nothing; "
            "falling back to baseline rescue then bs4 get_text()",
            file=sys.stderr,
        )
        return _bs4_text_fallback(html)
    return out


def _apply_query(body: str, html: str, query: str | None) -> str:
    """BM25-filter the body to query-relevant blocks when --query is set.

    The filter runs on the original HTML (block structure is needed for
    scoring) and returns relevant text blocks; when no query is set the body
    passes through unchanged.
    """
    if not query:
        return body
    from .content_filter import bm25_filter
    return bm25_filter(html, query)
