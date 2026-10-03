"""page-fetch — managed-fork value layer over the insane-search engine.

`plus/` contains formatting, routing, persistence, and safety integration over
the sibling `engine/` package. The engine started as an upstream v0.4.0 copy
but is now a directly maintained hard fork. Offline tests cover engine/plus
contracts. The dependency remains one-way: plus imports engine,
never the reverse. See `../UPSTREAM.md`.

Surface: a managed `fetch` subcommand with output formatting
(raw/markdown/metadata/text), an on-disk cache, and append-only observation
logging (Stage 1); a `crawl` subcommand for multi-URL discovery (Stage 2); and
a `search` subcommand querying six public sources in parallel (Stage 3).
Stage 4 (site monitoring) ships as a separate skill.

Phase 1+2+3 guards (2026-05-24, consensus v2.3 driven) — SSRF pre-/post-check,
Cloudflare fallback executor coercion, per-domain Playwright profileDir, log
sanitization, pip-install env-injection guard, DoH allowlist, proxy/CA env
warning, blocked-query refusal, cache + winners hardening — are installed
automatically on import via `engine_proxy.install()`. Tests can roll back with
`engine_proxy.uninstall()`. See `engine_proxy.py`, `_security.py`, `_ssrf.py`,
`_atomic.py`.

0.2.1 (2026-05-24) follow-up: D3/D4/D7/D12/D14/D15 code-reviewer cleanups —
proxy warning idempotency, blocked_cache thread-lock, BlockedQueryError
reclassification, winners.json `fcntl.flock`, `_security.py` split into
`_security.py` + `_ssrf.py` + `_atomic.py`, atomic-write helper consolidated.
"""

__all__ = ["__version__"]

__version__ = "0.2.1"

# Install Phase 1 guards over the hard-fork engine on import. Idempotent; safe
# even if downstream code re-imports plus. Done eagerly (not lazily) because
# plus' own submodules later do `from engine import fetch as engine_fetch`
# and need the proxied function — install() patches both `engine.fetch_chain.fetch`
# and the top-level re-export so those callers transparently pick up the proxy.
from . import engine_proxy as _engine_proxy
_engine_proxy.install()
