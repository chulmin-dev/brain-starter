#!/usr/bin/env python3
"""CLI entrypoint for page-fetch — the managed value layer.

Usage:
    python3 -m plus fetch URL [--format raw|markdown|metadata|text]
                              [--selector CSS] [--device auto|desktop|mobile]
                              [--cache] [--timeout N] [--json] [--trace]
    python3 -m plus crawl URL [--mode auto|sitemap|rss|paginate] ...
    python3 -m plus search QUERY [--sources hn,reddit,bluesky,arxiv,naver,ddg]
                                 [--limit N] [--doh auto|on|off]
                                 [--timeout N] [--json]

Backward-compat shorthand: if the first argument starts with http:// or
https://, it is treated as `fetch URL`, so `python3 -m plus URL` also works.

Exit codes (same contract as engine/__main__.py):
    0   ok    (strong_ok or weak_ok)
    1   fail  (ok=False — all attempts failed)
    2   CLI arg error / fatal error
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

# import-name -> pip-name. Single source of truth so the two never drift.
_IMPORT_TO_PIP = {
    "trafilatura": "trafilatura",
    "curl_cffi": "curl_cffi",
    "bs4": "beautifulsoup4",
    "yaml": "pyyaml",
}

# Format-only deps: import-names that are needed *only* by certain output
# formats, so a bare `raw` fetch (or the engine-only path, fmt=None) must not
# auto-install them. Everything else in _IMPORT_TO_PIP (curl_cffi, pyyaml — the
# engine fetch stack) is always considered. This restores the lazy-import
# design: the previous _ensure_dependencies installed all four modules
# unconditionally, defeating the lazy importers in extract.py (P14).
_FORMAT_ONLY_DEPS = frozenset({"trafilatura", "bs4"})

# fmt -> the format-only import-names that fmt actually needs. A fmt absent
# from this map (or fmt=None) needs none of the format-only deps.
_FMT_NEEDS = {
    "raw": frozenset(),
    "metadata": frozenset({"bs4"}),
    "markdown": frozenset({"trafilatura", "bs4"}),
    "text": frozenset({"trafilatura", "bs4"}),
    "fit_markdown": frozenset({"trafilatura", "bs4"}),
    "fit_text": frozenset({"trafilatura", "bs4"}),
}

# Phase 1 hardening (consensus C3): pip index env vars that, if set, may
# redirect installs to an attacker-controlled mirror. We refuse to honor
# them without explicit ack and always pin --index-url to PyPI.
_PINNED_PIP_INDEX = "https://pypi.org/simple"  # NOTE-BIAS-OK: supply-chain guard — pinned to official PyPI index
_PIP_INDEX_ENV_VARS = ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_MIRROR_URL")
_AUTO_INSTALL_ACK_ENV = "INSANE_AUTO_INSTALL_ACK"
_NO_AUTO_INSTALL_ENV = "INSANE_NO_AUTO_INSTALL"


def _ensure_dependencies(fmt: str | None = None) -> None:
    """Auto-install missing runtime dependencies — hardened in Phase 1.

    trafilatura is new to this fork; the rest are inherited from the engine.
    A failed auto-install is non-fatal here — the lazy importers in extract.py
    raise clear, actionable errors at the point of use.

    Format-scoped (P14): only the deps the chosen output format actually needs
    are considered. `raw` (and the engine-only paths, fmt=None) install only
    curl_cffi + pyyaml — never trafilatura — restoring the lazy-import design
    the extract.py importers were written for. extruct/htmldate stay fully soft
    (never auto-installed; surfaced at point of use).

    Phase 1 guards:
      - INSANE_NO_AUTO_INSTALL=1 → never auto-install, print manual command.
      - PIP_INDEX_URL / PIP_EXTRA_INDEX_URL / PIP_MIRROR_URL set without
        INSANE_AUTO_INSTALL_ACK=1 → refuse (env-injection vector).
      - Otherwise install with `--index-url https://pypi.org/simple  # NOTE-BIAS-OK: official PyPI
        --no-cache-dir` to bypass user-configured indexes and any cached
        malicious artifacts.
    """
    # Format-only deps the chosen fmt actually needs (none for raw / fmt=None).
    fmt_needs = _FMT_NEEDS.get(fmt or "raw", frozenset())

    # Scan _IMPORT_TO_PIP (single source of truth for pip names), skipping a
    # format-only dep when the chosen format doesn't need it. Non-format deps
    # (engine fetch stack + any injected entry) are always checked.
    missing = []
    for mod in _IMPORT_TO_PIP:
        if mod in _FORMAT_ONLY_DEPS and mod not in fmt_needs:
            continue
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if not missing:
        return

    to_install = [_IMPORT_TO_PIP[mod] for mod in missing]

    if os.environ.get(_NO_AUTO_INSTALL_ENV) == "1":
        print(
            f"[plus] auto-install disabled ({_NO_AUTO_INSTALL_ENV}=1).\n"
            f"[plus] install manually: "
            f"pip install --index-url {_PINNED_PIP_INDEX} {' '.join(to_install)}",
            file=sys.stderr,
        )
        return

    suspect_env = [v for v in _PIP_INDEX_ENV_VARS if os.environ.get(v)]
    ack = os.environ.get(_AUTO_INSTALL_ACK_ENV) == "1"
    if suspect_env and not ack:
        print(
            f"[plus] refusing auto-install: pip index env vars set "
            f"({', '.join(suspect_env)}). They could redirect installs to an "
            f"attacker-controlled mirror.\n"
            f"[plus] either unset those vars, set "
            f"{_AUTO_INSTALL_ACK_ENV}=1 to bypass, or install manually:\n"
            f"[plus]   pip install --index-url {_PINNED_PIP_INDEX} "
            f"{' '.join(to_install)}",
            file=sys.stderr,
        )
        return

    print(
        f"[plus] installing missing dependencies via PyPI: {', '.join(to_install)}",
        file=sys.stderr,
    )
    try:
        subprocess.run(
            [
                sys.executable, "-m", "pip", "install", "-q",
                "--index-url", _PINNED_PIP_INDEX,
                "--no-cache-dir",
                *to_install,
            ],
            check=True,
        )
    except (subprocess.CalledProcessError, OSError) as e:
        print(
            f"[plus] warning: automatic dependency install failed ({e}).\n"
            f"[plus] install manually: "
            f"pip install --index-url {_PINNED_PIP_INDEX} {' '.join(to_install)}",
            file=sys.stderr,
        )


_AGGRESSIVE_ENV = "INSANE_AGGRESSIVE"
_AGGRESSIVE_TRUTHY = frozenset({"1", "true", "yes", "on"})
_AGGRESSIVE_MAX_ATTEMPTS = 60  # full 4×3×5 Akamai grid


def _is_aggressive(args: "argparse.Namespace") -> bool:
    """Return True if --aggressive flag or INSANE_AGGRESSIVE env is set."""
    if getattr(args, "aggressive", False):
        return True
    return os.environ.get(_AGGRESSIVE_ENV, "").strip().lower() in _AGGRESSIVE_TRUTHY


_MAX_SELECTOR_LEN = 200


def _safe_selector(s: str) -> str:
    """argparse type validator for `--selector` — bounds length and rejects
    control characters.

    BS4's CSS selector engine doesn't have a wall-clock cap, so a maliciously
    nested `:has(...)` or deeply-quantified selector against a large DOM can
    burn minutes of CPU (consensus F8). 200 chars is more than any legitimate
    selector needs; control chars are never legitimate.
    """
    if not isinstance(s, str):
        raise argparse.ArgumentTypeError("selector must be a string")
    if len(s) > _MAX_SELECTOR_LEN:
        raise argparse.ArgumentTypeError(
            f"selector too long: {len(s)} chars (max {_MAX_SELECTOR_LEN})"
        )
    if any(ord(c) < 0x20 for c in s):
        raise argparse.ArgumentTypeError("selector contains control characters")
    return s


def _wrap_for_llm(body: str, url: str) -> str:
    """Opt-in taint sentinel for LLM-tool callers.

    When `INSANE_LLM_SAFE=1` is set, wrap fetched content in
    `[external_data:url=<host>]…[/external_data]` so the LLM treats it as
    untrusted data, not instructions. Default off — bare CLI output (e.g.
    `plus fetch URL > out.html`) stays intact.
    """
    if os.environ.get("INSANE_LLM_SAFE") != "1":
        return body
    from ._security import wrap_external_content
    return wrap_external_content(body, url=url)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python3 -m plus",
        description="page-fetch — managed fetch over the insane-search engine.",
    )
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    fetch_p = sub.add_parser("fetch", help="Fetch a URL through the engine chain.")
    fetch_p.add_argument("url", help="URL to fetch.")
    fetch_p.add_argument(
        "--format", "-f", dest="fmt",
        choices=("raw", "markdown", "metadata", "text",
                 "fit_markdown", "fit_text"),
        default="raw",
        help="Output format (default raw). fit_markdown/fit_text apply "
             "boilerplate pruning before extraction (see --prune).",
    )
    # P14: trafilatura recall/precision knobs. Mutually exclusive.
    fetch_mode = fetch_p.add_mutually_exclusive_group()
    fetch_mode.add_argument(
        "--recall", action="store_true",
        help="favor_recall: rescue under-extracted bodies (more content, "
             "some noise). Mutually exclusive with --precision.",
    )
    fetch_mode.add_argument(
        "--precision", action="store_true",
        help="favor_precision: drop nav/footer cruft aggressively (cleaner, "
             "may lose content). Mutually exclusive with --recall.",
    )
    # P29: content-filter flags.
    fetch_p.add_argument(
        "--prune", action="store_true",
        help="Apply PruningContentFilter before extraction (implied by "
             "--format fit_markdown/fit_text).",
    )
    fetch_p.add_argument(
        "--query", default=None, metavar="TERMS",
        help="BM25-filter the output to blocks relevant to these query terms "
             "(token reduction). CJK recall is reduced — see content_filter.",
    )
    fetch_p.add_argument(
        "--selector", "-s", action="append", default=None, dest="selectors",
        metavar="CSS", type=_safe_selector,
        help=f"Positive-proof CSS selector. Repeatable. Max "
             f"{_MAX_SELECTOR_LEN} chars, no control chars.",
    )
    fetch_p.add_argument(
        "--device", choices=("auto", "desktop", "mobile"), default="auto",
        help="Device class pin.",
    )
    fetch_p.add_argument(
        "--cache", action="store_true",
        help="Read from / write to the on-disk cache.",
    )
    fetch_p.add_argument(
        "--cache-weak", action="store_true", dest="cache_weak",
        help="P23: also cache WEAK_OK results (default: STRONG_OK only). "
             "Reduces security margin — use only when selectors are absent "
             "and stale/attacker-shaped content is acceptable.",
    )
    fetch_p.add_argument(
        "--doh", choices=("auto", "on", "off"), default="auto",
        help="DNS-over-HTTPS mode. auto (default): use DoH only when plain "
             "DNS looks blocked. on/off: force. Env INSANE_DOH overrides auto.",
    )
    fetch_p.add_argument(
        "--timeout", type=int, default=25,
        help="Per-attempt timeout seconds (default 25).",
    )
    fetch_p.add_argument(
        "--max-attempts", type=int, default=None, dest="max_attempts",
        metavar="N",
        help="Hard upper bound on total attempts across all grid phases (default 12). "
             "With --aggressive, the effective value is max(N, 60) so the floor "
             "is never lowered.",
    )
    fetch_p.add_argument(
        "--json", action="store_true",
        help="Emit a JSON envelope to stdout instead of the formatted body.",
    )
    fetch_p.add_argument(
        "--trace", action="store_true",
        help="Print per-attempt trace to stderr.",
    )
    fetch_p.add_argument(
        "--no-phase0", action="store_true", dest="no_phase0",
        help="Skip Phase-0 official-API routes and go straight to the generic grid.",
    )
    fetch_p.add_argument(
        "--aggressive", action="store_true", dest="aggressive",
        help="Opt-in: expand the grid to ≤60 combos + raise max_attempts to 60 + "
             "ensure playwright fallback. Higher breakthrough on hard WAF sites; "
             "higher IP-ban risk. Do NOT use through the Naver-whitelist EC2 IP. "
             "Env INSANE_AGGRESSIVE=1|true|yes|on also activates this.",
    )

    crawl_p = sub.add_parser(
        "crawl", help="Discover many URLs from a starting point, optionally fetch each."
    )
    crawl_p.add_argument("url", help="Starting URL.")
    crawl_p.add_argument(
        "--mode",
        choices=("auto", "sitemap", "rss", "paginate", "llms", "deep"),
        default="auto",
        help="Discovery mode (default auto: llms.txt, then sitemap, then rss). "
             "llms: P37 llms.txt index only. deep: P34 best-first "
             "link-following crawl (use --query/--depth/--allow/--deny).",
    )
    crawl_p.add_argument(
        "--limit", type=int, default=50,
        help="Cap on discovered items (default 50).",
    )
    # P34: deep-crawl knobs (only used by --mode deep).
    crawl_p.add_argument(
        "--query", default=None, metavar="TERMS",
        help="P34 (deep mode): keywords to rank the link frontier by relevance "
             "(best-first crawl). Space-separated.",
    )
    crawl_p.add_argument(
        "--depth", type=int, default=None, dest="depth",
        help="P34 (deep mode): max link-following depth from the start URL "
             "(default 2). Depth 0 = start URL only.",
    )
    crawl_p.add_argument(
        "--allow", action="append", default=None, metavar="PATTERN",
        help="P34 (deep mode): only follow links matching this regex/substring. "
             "Repeatable (a link must match at least one --allow).",
    )
    crawl_p.add_argument(
        "--deny", action="append", default=None, metavar="PATTERN",
        help="P34 (deep mode): never follow links matching this regex/substring. "
             "Repeatable (deny wins over allow).",
    )
    crawl_p.add_argument(
        "--no-same-domain", action="store_false", dest="same_domain",
        default=True,
        help="P34 (deep mode): allow following links off the start URL's "
             "registrable domain. Default OFF (same-domain only) to bound "
             "fetch volume and avoid cross-domain ban risk.",
    )
    crawl_p.add_argument(
        "--resume", action="store_true",
        help="P34 (deep mode): resume an interrupted crawl of the same scope "
             "from its on-disk checkpoint instead of restarting.",
    )
    crawl_p.add_argument(
        "--fetch", action="store_true",
        help="Also fetch each discovered URL and attach its content.",
    )
    crawl_p.add_argument(
        "--format", "-f", dest="fmt",
        choices=("raw", "markdown", "metadata", "text"), default="raw",
        help="Output format for --fetch content (default raw).",
    )
    crawl_p.add_argument(
        "--max-pages", type=int, default=5, dest="max_pages",
        help="Page cap for --mode paginate (default 5).",
    )
    crawl_p.add_argument(
        "--cache", action="store_true",
        help="P23: read/write each --fetch result through the on-disk cache.",
    )
    crawl_p.add_argument(
        "--cache-weak", action="store_true", dest="cache_weak",
        help="P23: also cache WEAK_OK results for --fetch (implies --cache). "
             "Same security trade-off as `fetch --cache-weak`.",
    )
    crawl_p.add_argument(
        "--doh", choices=("auto", "on", "off"), default="auto",
        help="DNS-over-HTTPS mode (see `fetch --doh`).",
    )
    crawl_p.add_argument(
        "--timeout", type=int, default=25,
        help="Per-fetch timeout seconds (default 25).",
    )
    crawl_p.add_argument(
        "--json", action="store_true",
        help="Emit a JSON envelope to stdout instead of a formatted list.",
    )

    cache_p = sub.add_parser(
        "cache", help="Manage the on-disk fetch cache."
    )
    cache_sub = cache_p.add_subparsers(dest="cache_command", metavar="ACTION")
    cache_sub.add_parser("clear", help="Delete every cache entry.")
    cache_sub.add_parser("prune", help="Delete only expired cache entries.")
    cache_sub.add_parser("info", help="Show cache statistics.")

    search_p = sub.add_parser(
        "search", help="Search one keyword across multiple public sources."
    )
    search_p.add_argument("query", help="Search keyword(s).")
    search_p.add_argument(
        "--sources", default="hn,reddit,bluesky,arxiv,naver,ddg,ddgs",
        help="Comma-separated source list (default: all seven). "
             "Choices: hn, reddit, bluesky, arxiv, naver, ddg, ddgs. "
             "ddgs requires the 'ddgs' package (soft-dep: skipped if absent).",
    )
    search_p.add_argument(
        "--limit", type=int, default=10,
        help="Per-source cap on the number of results (default 10).",
    )
    search_p.add_argument(
        "--max-results", type=int, default=None, dest="max_results",
        metavar="N",
        help="Global cap on total results after merging and dedup (P19). "
             "Default: no cap (all deduplicated hits are returned).",
    )
    search_p.add_argument(
        "--doh", choices=("auto", "on", "off"), default="auto",
        help="DNS-over-HTTPS mode (see `fetch --doh`).",
    )
    search_p.add_argument(
        "--timeout", type=int, default=25,
        help="Per-source fetch timeout seconds (default 25).",
    )
    search_p.add_argument(
        "--json", action="store_true",
        help="Emit a JSON envelope to stdout instead of a formatted list.",
    )
    return p


def _cmd_fetch(args: argparse.Namespace) -> int:
    """Run the managed fetch flow. Returns the process exit code."""
    from . import cache, doh
    from .extract import extract

    url = args.url
    device = args.device
    fmt = args.fmt

    # P14/P29: extraction-mode knobs. recall/precision change the extracted
    # body, --prune/--query change which blocks survive — so all of them must
    # be part of the cache key or a later call with a different mode would be
    # served a stale wrong-mode body. We fold the mode into a `cache_fmt`
    # namespace (fmt is already in the key) rather than widen cache.py's
    # signature.
    favor_recall = getattr(args, "recall", False)
    favor_precision = getattr(args, "precision", False)
    query = getattr(args, "query", None)
    want_prune = getattr(args, "prune", False) or fmt in ("fit_markdown", "fit_text")
    mode_parts = []
    if favor_recall:
        mode_parts.append("recall")
    if favor_precision:
        mode_parts.append("precision")
    if want_prune:
        mode_parts.append("prune")
    if query:
        mode_parts.append(f"q={query}")
    cache_fmt = fmt if not mode_parts else f"{fmt}#{'+'.join(mode_parts)}"

    # P23: --cache-weak is threaded explicitly into cache.put (CR-M1/SEC-L2 fix)
    # rather than mutating os.environ for the process lifetime — so an in-process
    # caller that later runs with cache_weak=False is not silently relaxed by a
    # leaked env value.
    cache_weak = getattr(args, "cache_weak", False)

    # 1) Cache lookup (selectors-keyed; STRONG_OK-only on store by default).
    #    Cache hits join the normal emit path so --json and _wrap_for_llm apply
    #    identically regardless of cache state (P9: W25 contract fix).
    if args.cache:
        hit = cache.get(url, device, cache_fmt, selectors=args.selectors)
        if hit is not None:
            if args.json:
                payload = {
                    "ok": True,
                    "verdict": "cache",
                    "profile_used": "cache",
                    "final_url": url,
                    "format": fmt,
                    "attempts": 0,
                    "content": hit,
                }
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                out = _wrap_for_llm(hit, url)
                print(out, end="" if out.endswith("\n") else "\n")
            print(
                "[plus] ok=True verdict=cache profile=cache (cache hit)",
                file=sys.stderr,
            )
            return 0

    # P35: non-HTML document path. The engine decodes every body to str, which
    # destroys binary bytes — so a PDF/Office/EPUB URL must be fetched by the
    # plus layer directly (SSRF-guarded + size-capped) and converted via
    # markitdown, never routed through the HTML engine. HTML never reaches here.
    from .binary_extract import looks_like_binary_doc
    if looks_like_binary_doc(url):
        return _cmd_fetch_binary(args, url, fmt, cache_fmt, cache_weak)

    # 2) DNS-over-HTTPS — route DNS over HTTPS when plain DNS is blocked.
    doh_status = doh.setup(args.doh)

    # 2b) Phase-0: try official no-auth API routes before the generic grid.
    #     Skipped when --no-phase0 is set. On ok=True, return the content
    #     directly (no engine grid needed). On ok=False (platform recognised
    #     but all routes failed), fall through — grid still runs and attempts
    #     are traced so failure is never silent.
    if not getattr(args, "no_phase0", False):
        try:
            from .phase0_router import route as _p0_route
            _p0 = _p0_route(url, timeout=args.timeout)
        except Exception as _p0_exc:
            _p0 = None
            print(f"[plus] phase0 error: {type(_p0_exc).__name__}: {_p0_exc}",
                  file=sys.stderr)
        if _p0 is not None:
            _p0_platform = _p0.get("platform", "?")
            for _att in _p0.get("attempts", []):
                print(
                    f"[plus] phase0 route={_att.get('route','?')} "
                    f"platform={_p0_platform} "
                    f"ok={_att.get('ok')} "
                    f"status={_att.get('status')} "
                    f"bytes={_att.get('bytes',0)} "
                    f"note={_att.get('note','')}",
                    file=sys.stderr,
                )
            if _p0.get("ok"):
                _p0_content = _p0.get("content", "")
                _p0_final_url = _p0.get("final_url") or url
                try:
                    from .extract import extract as _extract
                    _p0_body = _extract(_p0_content, fmt, url=_p0_final_url,
                                        favor_recall=favor_recall,
                                        favor_precision=favor_precision,
                                        query=query)
                except Exception:
                    _p0_body = _p0_content
                if args.json:
                    payload = {
                        "ok": True,
                        "verdict": "strong_ok",
                        "profile_used": f"phase0:{_p0.get('route','?')}",
                        "final_url": _p0_final_url,
                        "format": fmt,
                        "attempts": len(_p0.get("attempts", [])),
                        "content": _p0_body,
                        "untried_routes": [],
                        "must_invoke_playwright_mcp": False,
                        "grid_exhausted": False,
                        "stop_reason": None,
                    }
                    print(json.dumps(payload, ensure_ascii=False, indent=2))
                else:
                    _p0_out = _wrap_for_llm(_p0_body, _p0_final_url)
                    print(_p0_out, end="" if _p0_out.endswith("\n") else "\n")
                print(
                    f"[plus] ok=True verdict=strong_ok "
                    f"profile=phase0:{_p0.get('route','?')} {doh_status}",
                    file=sys.stderr,
                )
                if args.cache:
                    try:
                        from . import cache as _cache_mod
                        _cache_mod.put(
                            url, device, cache_fmt, "strong_ok", _p0_body,
                            selectors=args.selectors, weak_ok=cache_weak,
                        )
                    except OSError as _ce:
                        print(f"[plus] warning: cache write failed: {_ce}",
                              file=sys.stderr)
                return 0

    # 3) Engine fetch on cache miss.
    from engine import fetch as engine_fetch

    # Aggressive mode: opt-in grid expansion + playwright insurance.
    # Activated by --aggressive flag or INSANE_AGGRESSIVE env (truthy: 1/true/yes/on).
    # SAFETY: expands grid size only — SSRF guard, IP-pin (C8), cookie-jar gating,
    # and all per-hop url_check / blocked-terms guards remain active and are NOT
    # disabled by this flag.
    aggressive = _is_aggressive(args)
    if aggressive:
        print(
            "[plus] AGGRESSIVE: grid expanded (≤60 combos), "
            f"max_attempts={_AGGRESSIVE_MAX_ATTEMPTS}, playwright fallback on "
            "— higher success + higher IP-ban risk",
            file=sys.stderr,
        )
    _engine_user_hint: dict = {}
    # M1: --max-attempts N is now a real CLI arg (default None → 12 baseline).
    # L1: collapsed the redundant belt-and-suspenders getattr/hasattr — just getattr with None.
    _engine_max_attempts = getattr(args, "max_attempts", None)
    if _engine_max_attempts is None:
        _engine_max_attempts = 12
    if aggressive:
        _engine_user_hint["expand_unknown_challenge"] = True
        # Honor the higher of caller's value vs aggressive floor (never lower a caller value).
        _engine_max_attempts = max(_engine_max_attempts, _AGGRESSIVE_MAX_ATTEMPTS)

    try:
        result = engine_fetch(
            url,
            success_selectors=args.selectors,
            device_class=device,
            timeout=args.timeout,
            user_hint=_engine_user_hint if _engine_user_hint else None,
            max_attempts=_engine_max_attempts,
            enable_playwright=True,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[plus] fatal: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    # 4) Trace output (observation logging is centralised in engine_proxy._proxy_fetch
    #    since P22 — it now covers fetch/search/crawl paths automatically).
    if args.trace:
        print("=== trace ===", file=sys.stderr)
        for att in result.trace:
            d = att.to_dict()
            print(
                f"[{d['phase']:<8}] {d['executor']:<18} "
                f"status={d['status']:>4} size={d['body_size']:>8} "
                f"verdict={d['verdict']}",
                file=sys.stderr,
            )
        print(f"=== summary: {result.summary} ===", file=sys.stderr)

    # 5) Output formatting via the extract pipeline.
    #    --prune on a markdown/text format promotes it to the fit_* variant;
    #    fit_* formats already prune. recall/precision/query thread through.
    effective_fmt = fmt
    if want_prune and fmt == "markdown":
        effective_fmt = "fit_markdown"
    elif want_prune and fmt == "text":
        effective_fmt = "fit_text"
    try:
        body = extract(
            result.content, effective_fmt, url=result.final_url or url,
            favor_recall=favor_recall, favor_precision=favor_precision,
            query=query,
        )
    except RuntimeError as e:
        # Soft-dependency / actionable error from extract.py.
        print(f"[plus] error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"[plus] fatal: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    # 6) Cache write — STRONG_OK only (cache.put enforces this internally; the
    #    `result.ok` short-circuit is just to avoid the call for weak_ok).
    #    Keyed by cache_fmt so a different extraction mode never collides.
    if args.cache and result.ok:
        try:
            cache.put(
                url, device, cache_fmt, result.verdict, body,
                selectors=args.selectors, weak_ok=cache_weak,
            )
        except OSError as e:
            print(f"[plus] warning: cache write failed: {e}", file=sys.stderr)

    # 7) Emit output.
    if args.json:
        payload = {
            "ok": result.ok,
            "verdict": result.verdict,
            "profile_used": result.profile_used,
            "final_url": result.final_url,
            "format": fmt,
            "attempts": len(result.trace),
            "content": body,
            # A7: failure-gate fields (always included so harvest ladder can parse them
            # programmatically; empty/False on success paths — intended for harvest
            # ladder consumer, lands in a later wave).
            "untried_routes": result.untried_routes,
            "must_invoke_playwright_mcp": result.must_invoke_playwright_mcp,
            "grid_exhausted": result.grid_exhausted,
            "stop_reason": result.stop_reason,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        out = _wrap_for_llm(body, result.final_url or url)
        print(out, end="" if out.endswith("\n") else "\n")

    print(
        f"[plus] ok={result.ok} verdict={result.verdict} "
        f"profile={result.profile_used} {doh_status}",
        file=sys.stderr,
    )
    # A7: print structured failure block on ok=False (intended for harvest
    # ladder; consumer lands in a later wave).
    if not result.ok:
        untried = len(result.untried_routes)
        print(
            f"⛔ NOT EXHAUSTED: stop_reason={result.stop_reason} "
            f"grid_exhausted={result.grid_exhausted} "
            f"untried_routes={untried} "
            f"must_invoke_playwright_mcp={result.must_invoke_playwright_mcp}",
            file=sys.stderr,
        )
    return 0 if result.ok else 1


def _cmd_fetch_binary(
    args: argparse.Namespace, url: str, fmt: str,
    cache_fmt: str, cache_weak: bool,
) -> int:
    """P35: fetch a non-HTML document (PDF/Office/EPUB) and convert it.

    Routed here from `_cmd_fetch` when `looks_like_binary_doc(url)` is True.
    The cache lookup in `_cmd_fetch` already ran and missed (a hit returns
    there), so this performs the plus-side binary fetch + markitdown convert,
    then joins the same emit/cache contract as the HTML path.
    """
    from .binary_extract import extract_binary

    try:
        body = extract_binary(url, fmt, timeout=args.timeout)
    except RuntimeError as e:
        # Soft-dependency / size-cap / actionable error.
        print(f"[plus] error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 — SSRF block or network failure
        print(f"[plus] fatal: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    # Cache write — binary conversions are treated as STRONG_OK (a successful
    # markitdown convert is a clean terminal result). Keyed by cache_fmt so a
    # later HTML-format call never collides.
    if args.cache:
        from . import cache
        try:
            cache.put(
                url, args.device, cache_fmt, "strong_ok", body,
                selectors=args.selectors, weak_ok=cache_weak,
            )
        except OSError as e:
            print(f"[plus] warning: cache write failed: {e}", file=sys.stderr)

    if args.json:
        payload = {
            "ok": True,
            "verdict": "binary",
            "profile_used": "markitdown",
            "final_url": url,
            "format": fmt,
            "attempts": 0,
            "content": body,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        out = _wrap_for_llm(body, url)
        print(out, end="" if out.endswith("\n") else "\n")

    print(
        "[plus] ok=True verdict=binary profile=markitdown (non-HTML document)",
        file=sys.stderr,
    )
    return 0


def _item_url(item: dict) -> str | None:
    """Pull the fetchable URL out of a crawl item, whatever its mode.

    sitemap items use `loc`, rss items use `link`, paginate items use `url`.
    """
    return item.get("loc") or item.get("link") or item.get("url")


def _cmd_crawl(args: argparse.Namespace) -> int:
    """Run the managed crawl flow. Returns the process exit code."""
    from . import cache as cache_mod, crawl, doh
    from .extract import extract

    # P23: --cache-weak implies --cache; the weak-ok policy is threaded
    # explicitly into cache.put below (CR-M1/SEC-L2 fix) rather than mutating
    # os.environ for the process lifetime.
    crawl_cache = getattr(args, "cache", False)
    crawl_cache_weak = getattr(args, "cache_weak", False)
    if crawl_cache_weak:
        crawl_cache = True

    # 1) DNS-over-HTTPS — crawl fetches go through the engine just like fetch.
    doh_status = doh.setup(args.doh)

    # P34: assemble deep-crawl options from CLI flags (used only by mode=deep).
    deep_opts = {
        "query": (getattr(args, "query", None) or "").split() or None,
        "max_depth": getattr(args, "depth", None),
        "allow": getattr(args, "allow", None),
        "deny": getattr(args, "deny", None),
        "same_domain": getattr(args, "same_domain", True),
        "resume": getattr(args, "resume", False),
    }
    # Drop None depth so crawl.run uses its default.
    if deep_opts["max_depth"] is None:
        deep_opts.pop("max_depth")

    # 2) Discovery.
    try:
        result = crawl.run(
            args.url,
            mode=args.mode,
            limit=args.limit,
            max_pages=args.max_pages,
            timeout=args.timeout,
            deep_opts=deep_opts,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[plus] fatal: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    # P5: extract crawl_delay_s from internal result field, then strip it before
    # JSON output (it is not part of the public crawl envelope contract).
    crawl_delay_s: float | None = result.pop("_crawl_delay_s", None)

    items = result["items"]

    # 3) Optional per-URL fetch — sequential, no concurrency. The discovery
    #    limit already capped `items`, so every discovered URL is fetched.
    #    P5: inter-request delay + 429 one-shot backoff applied here.
    if args.fetch and items:
        import time as _time
        from engine import fetch as engine_fetch
        from . import crawl as _crawl_mod

        # LOW-2 (2026-06-11): per-host backoff dict so a 429 on one host
        # doesn't suppress the backoff for a different host in multi-host
        # crawls. A global cap (_MAX_HOST_BACKOFFS) still limits wall-clock.
        from urllib.parse import urlsplit as _urlsplit
        _HOST_BACKED_OFF: dict[str, bool] = {}
        _MAX_HOST_BACKOFFS = 3

        # P20 (2026-06-12): wall-clock budget for the --fetch loop (W31).
        # Without this a --limit 50 loop with max_attempts=12 could run for
        # 50 × 12 × timeout seconds.  Budget = _MAX_CRAWL_SECONDS from crawl
        # module, matching the discovery-phase budget.
        import time as _time_mod
        _fetch_deadline = _time_mod.monotonic() + _crawl_mod._MAX_CRAWL_SECONDS

        # P36 (2026-06-12): de-dup near-identical bodies (paginated boilerplate,
        # mirrored pages). Each collected body is fingerprinted; a later body
        # whose Simhash similarity to any kept one is >= _DEDUP_THRESHOLD is
        # marked duplicate and not re-emitted/cached, saving LLM-input tokens.
        from . import _fingerprint as _fp
        _DEDUP_THRESHOLD = 0.9
        _kept_bodies: list[str] = []

        for i, item in enumerate(items):
            # P20: check wall-clock budget before each item fetch.
            if _time_mod.monotonic() > _fetch_deadline:
                print(
                    f"[plus] crawl warning: --fetch budget exhausted after "
                    f"{i} item(s) — remaining items skipped",
                    file=sys.stderr,
                )
                break

            # Delay before every fetch except the first.
            if i > 0:
                _crawl_mod._politeness_delay(crawl_delay_s)

            target = _item_url(item)
            if not target:
                item["content"] = None
                item["fetch_ok"] = False
                continue

            # P23: cache lookup before fetching — skips the engine entirely on
            # a fresh hit, respecting the P20 deadline budget.
            if crawl_cache:
                _cached = cache_mod.get(target, "auto", args.fmt)
                if _cached is not None:
                    item["content"] = _cached
                    item["fetch_ok"] = True
                    continue

            try:
                # P20: clamp max_attempts so each item fetch can't burn the
                # engine's full 12-attempt budget (W31).
                fr = engine_fetch(target, timeout=args.timeout,
                                  max_attempts=_crawl_mod._CRAWL_MAX_ATTEMPTS)
            except Exception as e:  # noqa: BLE001
                print(
                    f"[plus] crawl warning: fetch failed for {target}: "
                    f"{type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                item["content"] = None
                item["fetch_ok"] = False
                continue

            # 429 per-host one-shot backoff (global cap: _MAX_HOST_BACKOFFS).
            _host = _urlsplit(target).netloc
            if (
                _crawl_mod._last_status(fr) == 429
                and not _HOST_BACKED_OFF.get(_host)
                and len(_HOST_BACKED_OFF) < _MAX_HOST_BACKOFFS
            ):
                print(
                    f"[plus] crawl warning: 429 rate-limit on {target} — "
                    f"backing off {_crawl_mod._RATE_LIMIT_BACKOFF_S}s",
                    file=sys.stderr,
                )
                _time.sleep(_crawl_mod._RATE_LIMIT_BACKOFF_S)
                _HOST_BACKED_OFF[_host] = True
                try:
                    fr = engine_fetch(target, timeout=args.timeout,
                                      max_attempts=_crawl_mod._CRAWL_MAX_ATTEMPTS)
                except Exception as e:  # noqa: BLE001
                    print(
                        f"[plus] crawl warning: fetch failed for {target} "
                        f"after backoff: {type(e).__name__}: {e}",
                        file=sys.stderr,
                    )
                    item["content"] = None
                    item["fetch_ok"] = False
                    continue

            try:
                body = extract(fr.content, args.fmt, url=fr.final_url or target)
            except Exception as e:  # noqa: BLE001
                print(
                    f"[plus] crawl warning: extract failed for {target}: "
                    f"{type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                body = None
            # P36: skip a body that is a near-duplicate of one already kept.
            # Marked on the item (duplicate_of_kept=True) and content cleared so
            # the LLM turn doesn't re-ingest mirrored boilerplate. Cache write is
            # also skipped — the canonical copy is already cached under its own
            # URL. Threshold 0.9 (Simhash); degraded fingerprint backend yields
            # 0.0 similarity so nothing is ever over-skipped.
            _is_dupe = False
            if body:
                for _kept in _kept_bodies:
                    if _fp.similar(body, _kept) >= _DEDUP_THRESHOLD:
                        _is_dupe = True
                        break
            if _is_dupe:
                item["content"] = None
                item["fetch_ok"] = fr.ok
                item["duplicate_of_kept"] = True
                continue
            if body:
                _kept_bodies.append(body)

            item["content"] = body
            item["fetch_ok"] = fr.ok

            # P23: write successful fetch to cache (STRONG_OK-only unless
            # --cache-weak; P20 deadline already checked above this item).
            if crawl_cache and fr.ok and body:
                try:
                    cache_mod.put(
                        target, "auto", args.fmt, fr.verdict, body,
                        weak_ok=crawl_cache_weak,
                    )
                except OSError as e:
                    print(
                        f"[plus] crawl warning: cache write failed for "
                        f"{target}: {e}",
                        file=sys.stderr,
                    )

    # 4) Output.
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        mode = result["mode"]
        print(f"# crawl mode={mode} source={result['source_url']} "
              f"count={result['count']}")
        for i, item in enumerate(items, 1):
            if mode in ("sitemap", "llms"):
                lastmod = item.get("lastmod")
                suffix = f"  (lastmod {lastmod})" if lastmod else ""
                title = item.get("title")
                title_suffix = f"  [{title}]" if title else ""
                print(f"{i:>3}. {item.get('loc')}{suffix}{title_suffix}")
            elif mode == "deep":
                # P34: deep items carry loc + depth + score.
                depth = item.get("depth")
                score = item.get("score")
                meta = f"  (depth {depth}, score {score})"
                print(f"{i:>3}. {item.get('loc')}{meta}")
            elif mode == "rss":
                title = item.get("title") or "(no title)"
                print(f"{i:>3}. {title}")
                if item.get("link"):
                    print(f"     {item['link']}")
                if item.get("date"):
                    print(f"     {item['date']}")
            else:  # paginate
                print(f"{i:>3}. {item.get('url')}")
            if args.fetch and item.get("content"):
                print(f"     --- content ({len(item['content'])} chars) ---")

    print(
        f"[plus] crawl mode={result['mode']} count={result['count']} "
        f"{doh_status}",
        file=sys.stderr,
    )
    return 0 if result["count"] > 0 else 1


def _cmd_cache(args: argparse.Namespace) -> int:
    """Handle `plus cache {clear,prune,info}`. Returns the process exit code."""
    from . import cache as cache_mod

    action = getattr(args, "cache_command", None)
    if action == "clear":
        count = cache_mod.clear()
        print(f"[plus] cache: removed {count} entr{'y' if count == 1 else 'ies'}")
        return 0
    if action == "prune":
        count = cache_mod.prune()
        print(f"[plus] cache: pruned {count} expired entr{'y' if count == 1 else 'ies'}")
        return 0
    if action == "info":
        stats = cache_mod.info()  # NOTE-BIAS-OK: Python method call, not a domain — regex false positive on .info token
        if args.json if hasattr(args, "json") else False:
            print(json.dumps(stats, ensure_ascii=False, indent=2))
        else:
            print(f"cache_dir   : {stats['cache_dir']}")
            print(f"entries     : {stats['entry_count']} "
                  f"(fresh={stats['fresh_count']}, expired={stats['expired_count']})")
            mb = stats["total_bytes"] / (1024 * 1024)
            print(f"total_size  : {mb:.2f} MB ({stats['total_bytes']} bytes)")
        return 0
    # No sub-action: print help.
    print("Usage: python3 -m plus cache {clear,prune,info}", file=sys.stderr)
    return 2


def _cmd_search(args: argparse.Namespace) -> int:
    """Run the multi-source search flow. Returns the process exit code."""
    from . import doh, search

    # 1) DNS-over-HTTPS — every source fetch goes through the engine.
    doh_status = doh.setup(args.doh)

    # 2) Parse the comma-separated source list (drop blanks, case-fold so
    #    `--sources HN,Reddit` matches the lowercase handler keys).
    requested = [s.strip().lower() for s in args.sources.split(",") if s.strip()]

    # 3) Run the search. search.search() warns on unknown source names and
    #    every source handler is best-effort, so this does not raise.
    try:
        result = search.search(
            args.query,
            sources=requested,
            limit=args.limit,
            timeout=args.timeout,
            max_results=args.max_results,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[plus] fatal: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    # 4) Output.
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"# search query={result['query']!r} "
              f"sources={','.join(result['sources']) or '(none)'} "
              f"count={result['count']}")
        # P19 (2026-06-12): results are now interleaved across sources, not
        # grouped.  Display in merged order with a [source] tag per hit so the
        # source attribution is still visible without re-grouping.
        for i, hit in enumerate(result["results"], 1):
            src = hit.get("source") or "?"
            print(f"\n{i:>3}. [{src}] {hit.get('title') or '(no title)'}")
            print(f"     {hit.get('url')}")
            if hit.get("date"):
                print(f"     {hit['date']}")
            snippet = hit.get("snippet")
            if snippet:
                print(f"     {snippet}")

    print(
        f"[plus] search count={result['count']} "
        f"sources={len(result['sources'])} {doh_status}",
        file=sys.stderr,
    )
    return 0 if result["count"] > 0 else 1


def _configure_streams() -> None:
    """Force UTF-8 on stdout/stderr with backslashreplace error handler.

    Prevents UnicodeEncodeError on CJK content under non-UTF-8 locales (e.g.
    Windows cp949 headless). Uses reconfigure() when available (Python 3.7+
    FileIO); falls back gracefully to a wrapper — but never silently swallows
    the failure.
    """
    for stream_name, stream in (("stdout", sys.stdout), ("stderr", sys.stderr)):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[union-attr]
        except AttributeError:
            # reconfigure() absent on some wrapped/redirected streams (e.g.
            # pytest capsys). Attempt a low-level swap; warn if even that fails.
            import io
            try:
                new = io.TextIOWrapper(
                    stream.buffer,  # type: ignore[union-attr]
                    encoding="utf-8",
                    errors="backslashreplace",
                    line_buffering=stream.line_buffering,  # type: ignore[union-attr]
                )
                if stream_name == "stdout":
                    sys.stdout = new
                else:
                    sys.stderr = new
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[plus] warning: could not reconfigure {stream_name} to UTF-8: {exc}",
                    file=sys.stderr,
                )


def main(argv: list[str] | None = None) -> int:
    _configure_streams()
    raw_argv = list(sys.argv[1:] if argv is None else argv)

    # Backward-compat: a bare URL routes to the `fetch` subcommand.
    if raw_argv and raw_argv[0].startswith(("http://", "https://")):
        raw_argv = ["fetch", *raw_argv]

    parser = build_parser()
    args = parser.parse_args(raw_argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 2

    # Phase 2 (consensus C6 sibling): warn once about proxy/CA env vars that
    # could MITM or swap trust. Non-blocking — legitimate corporate setups
    # rely on these.
    from ._security import _check_proxy_env
    _check_proxy_env()

    # Format-scoped dependency check (P14): a bare `raw` fetch must not pull in
    # trafilatura. crawl/search always extract, so default them to needing the
    # markdown stack via their own fmt; fetch passes its chosen fmt.
    _ensure_dependencies(getattr(args, "fmt", None))

    if args.command == "fetch":
        return _cmd_fetch(args)

    if args.command == "crawl":
        return _cmd_crawl(args)

    if args.command == "search":
        return _cmd_search(args)

    if args.command == "cache":
        return _cmd_cache(args)

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
