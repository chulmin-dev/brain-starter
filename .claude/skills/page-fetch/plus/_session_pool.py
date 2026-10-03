"""Process-wide per-host curl_cffi SessionPool (A2).

Default OFF — the pool is only activated when ``INSANE_SESSION_POOL=1`` is
set in the environment.  When OFF the module is imported but every call
returns ``None``, keeping the code path byte-identical to today.

Design invariants (Wave 4 security contract):
  1. The pool is keyed by *host* (``urlsplit(url).hostname``), never by full
     URL, so cookies/connections never bleed across registrable domains.
  2. Every SSRF guard (pre-flight, per-hop url_check, post-redirect) fires as
     before — the pool does not touch the guard machinery, it only recycles the
     curl_cffi ``Session`` object between calls to the same host.
  3. C8 IP-pin (CURLOPT_RESOLVE) is per-``perform()`` — curl_cffi clears the
     RESOLVE slist after each request, so a pooled Session does not defeat the
     pin.  fetch_chain re-pins on every hop as it does today.
  4. The pool holds at most ``INSANE_SESSION_POOL_MAX`` (default 64) sessions.
     Least-recently-used eviction runs at every acquisition to stay bounded.
  5. ``close()`` tears down all sessions cleanly; ``_POOL`` is reset so tests
     can call it without leaking state across test cases.

Public surface:
  ``acquire(url)``  — return a live ``Session`` for the host, or ``None``.
  ``release(url, session)``  — return the session to the pool.
  ``close()``  — close and discard all pooled sessions (atexit + test teardown).
  ``pool_enabled()``  — True iff ``INSANE_SESSION_POOL=1``.
"""
from __future__ import annotations

import atexit
import collections
import os
import threading
from typing import Any, Optional
from urllib.parse import urlsplit

_ENV_FLAG = "INSANE_SESSION_POOL"
_MAX_ENV = "INSANE_SESSION_POOL_MAX"
_DEFAULT_MAX = 64


def pool_enabled() -> bool:
    """Return True iff the pool feature flag is set."""
    return os.environ.get(_ENV_FLAG) == "1"


def _max_entries() -> int:
    raw = os.environ.get(_MAX_ENV, "")
    try:
        v = int(raw)
        return v if v > 0 else _DEFAULT_MAX
    except (ValueError, TypeError):
        return _DEFAULT_MAX


def _host(url: str) -> str:
    """Extract the hostname key from a URL. Falls back to the raw URL on error."""
    try:
        h = urlsplit(url).hostname or ""
        return h.lower()
    except Exception:
        return url


# --- Pool state (module-level, protected by _LOCK) ---

_LOCK = threading.Lock()
# OrderedDict used as an LRU map: key=host, value=list[Session]
# Sessions per host are a LIFO stack (last released = first reused).
_POOL: "collections.OrderedDict[str, list[Any]]" = collections.OrderedDict()


def _evict_to_limit() -> None:
    """Drop oldest host entries until the pool is within the size cap.

    Called while holding _LOCK.  The LRU order is maintained by moving a
    host to the end on every acquire/release (OrderedDict move_to_end).
    Eviction closes sessions best-effort — a failure must not raise.
    """
    cap = _max_entries()
    while len(_POOL) > cap:
        _, sessions = _POOL.popitem(last=False)  # oldest host
        for s in sessions:
            try:
                s.close()
            except Exception:
                pass


def acquire(url: str) -> Optional[Any]:
    """Return a live ``curl_cffi.requests.Session`` for ``url``'s host.

    Returns ``None`` when the pool is disabled, curl_cffi is unavailable, or
    no idle session exists for the host yet (caller creates a fresh one).
    The caller is responsible for calling ``release()`` when done.
    """
    if not pool_enabled():
        return None
    try:
        from curl_cffi import requests as cffi_requests  # noqa: F401
    except ImportError:
        return None

    host = _host(url)
    with _LOCK:
        sessions = _POOL.get(host)
        if sessions:
            session = sessions.pop()
            if not sessions:
                del _POOL[host]
            else:
                _POOL.move_to_end(host)
            return session
    # No idle session — caller will create one and release it back.
    return None


def release(url: str, session: Any) -> None:
    """Return ``session`` to the pool keyed by ``url``'s host.

    No-op when the pool is disabled or ``session`` is ``None``.
    """
    if not pool_enabled() or session is None:
        return
    host = _host(url)
    with _LOCK:
        if host not in _POOL:
            _POOL[host] = []
        _POOL[host].append(session)
        _POOL.move_to_end(host)
        _evict_to_limit()


def close() -> None:
    """Close all pooled sessions and reset the pool.

    Called at process exit (atexit) and in tests for isolation.
    """
    with _LOCK:
        for sessions in _POOL.values():
            for s in sessions:
                try:
                    s.close()
                except Exception:
                    pass
        _POOL.clear()


atexit.register(close)
