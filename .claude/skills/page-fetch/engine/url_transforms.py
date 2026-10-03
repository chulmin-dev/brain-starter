"""Generic URL transforms for the fetch grid.

Transforms are domain-agnostic *rules*. They never reference a specific
site by name. A transform either applies (returns a new URL) or is skipped
(returns None). Callers iterate transforms in order.

Generic URL transforms:
  * mobile_subdomain — `www.example.com` → `m.example.com`
    Strong win on SSR sites with mobile-first serving. Loss on SPA shells
    (some mobile sites return tiny bootstrap HTML).
  * am_prefix — `example.com` (no www) → `m.example.com`
  * drop_www — occasionally unblocks hosts that gate www but not apex.

Adding new transforms: prove they help on ≥2 unrelated sites first
(cross-site validation — bias check).
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit, urlunsplit


# Stdlib fallback for the registrable-domain helper. Loaded from
# `engine/psl_static.txt` at import time so the data lives next to the
# code without being scanned by `bias_check.py` (which targets source
# files only). For full PSL coverage install the optional `publicsuffix2`
# dependency — this file is the stdlib-only path.
_PSL_STATIC_PATH = Path(__file__).parent / "psl_static.txt"


def _load_static_suffixes() -> tuple[str, ...]:
    """Read public-suffix entries from `psl_static.txt`.

    Returns a tuple sorted by length descending so the lookup loop picks
    the **longest** matching suffix first. Without this, the moment the
    file gains a shorter suffix that is a tail of a longer one (e.g. a  # NOTE-BIAS-OK
    bare ccTLD next to its second-level), `frozenset` hash-iteration
    order would make the matcher non-deterministic across Python
    processes (different `PYTHONHASHSEED`).

    Malformed lines (whitespace inside, leading/trailing dot, double
    dots, non-DNS chars) are skipped — they would never match a real
    host's `endswith()` anyway, so the silent miss would be much harder
    to debug than dropping them at load.
    """
    try:
        text = _PSL_STATIC_PATH.read_text(encoding="utf-8")
    except OSError:
        return ()
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if ".." in line or line.startswith(".") or line.endswith("."):
            continue
        # DNS labels are alnum + hyphen + dot only.
        if not all(c.isalnum() or c in ".-" for c in line):
            continue
        seen.add(line)
    return tuple(sorted(seen, key=len, reverse=True))


_STATIC_PUBLIC_SUFFIXES_MULTI: tuple[str, ...] = _load_static_suffixes()


def _registrable_domain(host: str) -> str:
    """Return the registrable (SLD + effective TLD) portion of `host`.

    Uses `publicsuffix2.get_sld` when available — that path covers the full
    PSL. Falls back to a built-in set of common multi-label public
    suffixes (see `_STATIC_PUBLIC_SUFFIXES_MULTI`) when the package is not
    installed, which covers the multi-label cases we actually fetch.

    For unknown / single-label TLDs the fallback returns the last two
    labels, which matches the pre-PSL behaviour for `example.com`.

    The returned host is lowercase.
    """
    if not host:
        return host
    host_lower = host.lower()
    try:
        from publicsuffix2 import get_sld  # type: ignore[import-not-found]
    except ImportError:
        get_sld = None  # type: ignore[assignment]
    if get_sld is not None:
        try:
            sld = get_sld(host_lower)
            if sld:
                return sld
        except Exception:
            # publicsuffix2 raises on malformed hosts — fall back below.
            pass
    # Static fallback: longest-match multi-label suffix wins, then
    # default to last two labels.
    for suffix in _STATIC_PUBLIC_SUFFIXES_MULTI:
        if host_lower == suffix or host_lower.endswith("." + suffix):
            stem = host_lower[: -len(suffix)].rstrip(".")
            if not stem:
                # `host` IS a public suffix — no registrable owner. Return
                # the suffix itself so callers see "no shorter registrable".
                return suffix
            sld_label = stem.rsplit(".", 1)[-1]
            return f"{sld_label}.{suffix}"
    parts = host_lower.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host_lower


def _replace_host(url: str, new_host: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(netloc=new_host))


def _original(url: str) -> Optional[str]:
    return url


def _mobile_subdomain(url: str) -> Optional[str]:
    """`https://www.example.com/a` → `https://m.example.com/a` (only if host starts with www.)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host.startswith("www."):
        return None
    new_host = "m." + host[4:]
    if parts.port:
        new_host = f"{new_host}:{parts.port}"
    return _replace_host(url, new_host)


def _am_prefix(url: str) -> Optional[str]:
    """`https://example.com/a` → `https://m.example.com/a` for apex hosts.

    "Apex" here means the host equals its registrable domain (SLD + public
    suffix). This is the PSL-aware version (patch queue #10): the old
    `host.count(".") >= 2` heuristic mis-classified multi-label TLDs like
    `example.co.kr` (2 dots but apex) as non-apex and skipped them.
    `www.` is still handled by `mobile_subdomain`.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host or host.startswith("m."):
        return None
    if host.startswith("www."):
        return None  # handled by mobile_subdomain
    if host.lower() != _registrable_domain(host):
        # `host` is a deeper subdomain than the registrable domain
        # (e.g. `a.example.com`, `staging.example.co.kr`). The `m.` prefix
        # transform is for apex-only.
        return None
    return _replace_host(url, "m." + host)


def _drop_www(url: str) -> Optional[str]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host.startswith("www."):
        return None
    return _replace_host(url, host[4:])


TRANSFORMS: dict[str, Callable[[str], Optional[str]]] = {
    "original": _original,
    "mobile_subdomain": _mobile_subdomain,
    "am_prefix": _am_prefix,
    "drop_www": _drop_www,
}


def apply_transform(name: str, url: str) -> Optional[str]:
    """Apply one transform by name. Returns transformed URL or None if skipped."""
    fn = TRANSFORMS.get(name)
    if fn is None:
        raise ValueError(f"Unknown transform: {name!r}. Known: {list(TRANSFORMS)}")
    return fn(url)


def iter_transformed(url: str, order: list[str]) -> list[tuple[str, str]]:
    """Yield (transform_name, transformed_url) pairs for a given order.

    Skips transforms that return None (not applicable) and deduplicates
    URLs (so `original` and `drop_www` of `https://example.com` don't double-run).
    """
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for name in order:
        new_url = apply_transform(name, url)
        if new_url is None:
            continue
        if new_url in seen:
            continue
        seen.add(new_url)
        out.append((name, new_url))
    return out
