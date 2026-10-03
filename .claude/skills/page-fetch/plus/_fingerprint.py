"""Content fingerprinting helpers for page-fetch (P36).

Two jobs, both built on trafilatura's Simhash (no new dependency —
trafilatura 2.x is already the extraction engine):

  1. Mis-record detection — `content_fingerprint(text)` returns a stable short
     digest of a fetched body. Recorded in winners/observe so that when two
     *different* probe methods (impersonate combos, transforms, fallbacks)
     return byte-identical bodies for a host, the operator can detect that the
     "success" is actually the same challenge / block page being echoed back
     (the verdict gates passed on a stub, not on real content).

  2. Crawl de-dup — `similar(a, b) >= 0.9` lets the crawl --fetch loop skip a
     page whose content is near-identical to one already collected (paginated
     boilerplate, mirrored pages), saving LLM-input tokens.

trafilatura.deduplication is an *internal* module whose import path changed at
2.0 (`trafilatura.hashing` → `trafilatura.deduplication`), so the import is
soft — the helpers degrade to None / 0.0 with a one-time stderr note rather
than crashing a fetch, mirroring extract.py's lazy-soft-import posture.

Provenance: Simhash / content_fingerprint are from trafilatura (Apache-2.0,
adbar/trafilatura). We import them directly; nothing is vendored.
"""
from __future__ import annotations

import sys
from typing import Optional

# Resolved lazily on first use; None means "not available" after a failed
# import (we don't retry every call — a one-time note is enough).
_DEDUP = None  # module handle once imported
_IMPORT_TRIED = False
_IMPORT_OK = False


def _load_dedup():
    """Import trafilatura.deduplication once; cache success/failure.

    Returns the module or None. A failure is reported once on stderr then
    silently treated as "fingerprinting unavailable" for the process lifetime.
    """
    global _DEDUP, _IMPORT_TRIED, _IMPORT_OK
    if _IMPORT_TRIED:
        return _DEDUP if _IMPORT_OK else None
    _IMPORT_TRIED = True
    try:
        from trafilatura import deduplication as _d  # type: ignore
        _DEDUP = _d
        _IMPORT_OK = True
    except Exception as e:  # noqa: BLE001 — any import failure → soft-off
        print(
            f"[plus] note: content fingerprinting unavailable "
            f"({type(e).__name__}: {e}); P36 dedup/mis-record checks are off.",
            file=sys.stderr,
        )
        _DEDUP = None
        _IMPORT_OK = False
    return _DEDUP


def content_fingerprint(text: Optional[str]) -> Optional[str]:
    """Return a stable short fingerprint of `text`, or None when unavailable.

    Empty/None text → None (no fingerprint for an empty body). Any internal
    failure → None (best-effort — never raises into the fetch path).
    """
    if not text:
        return None
    dedup = _load_dedup()
    if dedup is None:
        return None
    try:
        return dedup.content_fingerprint(text)
    except Exception:  # noqa: BLE001 — fingerprinting is best-effort
        return None


def _simhash_value(text: Optional[str]):
    """Build a Simhash for `text`, or None on unavailability/failure."""
    if not text:
        return None
    dedup = _load_dedup()
    if dedup is None:
        return None
    try:
        return dedup.Simhash(text)
    except Exception:  # noqa: BLE001
        return None


def similar(a: Optional[str], b: Optional[str]) -> float:
    """Return the Simhash similarity of two texts in [0.0, 1.0].

    Returns 0.0 when either text is empty or fingerprinting is unavailable —
    a conservative default so de-dup never *over*-skips on a degraded import
    (0.0 < 0.9 threshold → never skipped).
    """
    sa = _simhash_value(a)
    sb = _simhash_value(b)
    if sa is None or sb is None:
        return 0.0
    try:
        return float(sa.similarity(sb))
    except Exception:  # noqa: BLE001
        return 0.0
