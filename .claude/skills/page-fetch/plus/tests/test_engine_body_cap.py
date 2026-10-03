"""Patch queue #8 — streaming body-size cap for curl-impersonate.

UPSTREAM.md: `curl-impersonate's stdout is read fully into memory before
verdict check; large pages (>50MB) can OOM. Stream and gate on size.`

curl_cffi 0.15.0's `content_callback` is invoked per chunk; raising
from it aborts the transfer (libcurl error 23 = "Failure writing output
to destination"). `engine/fetch_chain.py` now passes a fresh `_BodyCap`
to every GET — including each redirect hop — and translates the abort
into a stable `body_too_large:<total>><limit>` error string via the
`_BodyTooLarge` sentinel.

Tests cover three layers:

  1. `_max_body_bytes()` env-var parsing (default / override / invalid).
  2. `_BodyCap` chunk-accumulation behaviour and abort semantics.
  3. `_curl_probe` end-to-end: a fake session that calls
     `content_callback` mimics libcurl's chunked write path, so the
     cap path is exercised without network.
"""
from __future__ import annotations

import importlib
import os
import sys
import types
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))


# ---------------------------------------------------------------------------
# `_max_body_bytes` env parsing
# ---------------------------------------------------------------------------

class MaxBodyBytesEnvTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = os.environ.get("INSANE_MAX_BODY_BYTES")
        os.environ.pop("INSANE_MAX_BODY_BYTES", None)
        self.addCleanup(self._restore)
        from engine import fetch_chain as fc
        self.fc = fc

    def _restore(self) -> None:
        if self._saved is None:
            os.environ.pop("INSANE_MAX_BODY_BYTES", None)
        else:
            os.environ["INSANE_MAX_BODY_BYTES"] = self._saved

    def test_default_is_ten_mebibytes(self) -> None:
        self.assertEqual(self.fc._max_body_bytes(), 10 * 1024 * 1024)

    def test_env_override_positive_int(self) -> None:
        os.environ["INSANE_MAX_BODY_BYTES"] = "12345"
        self.assertEqual(self.fc._max_body_bytes(), 12345)

    def test_env_invalid_falls_back_to_default(self) -> None:
        os.environ["INSANE_MAX_BODY_BYTES"] = "not-a-number"
        self.assertEqual(self.fc._max_body_bytes(), 10 * 1024 * 1024)

    def test_env_zero_or_negative_falls_back_to_default(self) -> None:
        for bad in ("0", "-1", "-9999"):
            os.environ["INSANE_MAX_BODY_BYTES"] = bad
            self.assertEqual(
                self.fc._max_body_bytes(),
                10 * 1024 * 1024,
                f"value {bad!r} should fall back to default",
            )

    def test_env_whitespace_tolerated(self) -> None:
        os.environ["INSANE_MAX_BODY_BYTES"] = "  4096  "
        self.assertEqual(self.fc._max_body_bytes(), 4096)


# ---------------------------------------------------------------------------
# `_BodyCap` chunk accumulator
# ---------------------------------------------------------------------------

class BodyCapBehaviourTest(unittest.TestCase):
    def setUp(self) -> None:
        from engine import fetch_chain as fc
        self.fc = fc

    def test_under_limit_accumulates(self) -> None:
        cap = self.fc._BodyCap(100)
        cap(b"x" * 30)
        cap(b"y" * 40)
        self.assertEqual(cap.total, 70)
        self.assertFalse(cap.exceeded)

    def test_at_limit_does_not_raise(self) -> None:
        cap = self.fc._BodyCap(100)
        cap(b"x" * 100)
        self.assertEqual(cap.total, 100)
        self.assertFalse(cap.exceeded)

    def test_over_limit_raises_and_marks(self) -> None:
        cap = self.fc._BodyCap(100)
        cap(b"x" * 80)
        self.assertFalse(cap.exceeded)
        # `_BodyCapAbort` is a `RuntimeError` subclass; pin the exact
        # type so a future change to a plain `RuntimeError` (or anything
        # else broader) is caught.
        with self.assertRaises(self.fc._BodyCapAbort):
            cap(b"y" * 30)  # total would be 110 > 100
        self.assertTrue(cap.exceeded)
        self.assertEqual(cap.total, 110)

    # Phase 10.1 — body rehydration ----------------------------------------

    def test_chunks_accumulated_under_limit(self) -> None:
        """Phase 10.1: chunks must be preserved so `_do_get` can rehydrate
        `resp.content` after curl_cffi diverts the body to the callback."""
        cap = self.fc._BodyCap(100)
        cap(b"<html>")
        cap(b"hello")
        cap(b"</html>")
        self.assertEqual(b"".join(cap.chunks), b"<html>hello</html>")

    def test_chunks_dropped_on_overflow(self) -> None:
        """When the cap trips, the offending chunk is discarded — the
        caller is about to raise `_BodyTooLarge` and never reads `chunks`.
        Accumulated chunks before the trip are still in the list because
        the trip happens mid-call, but the *over-limit* chunk is not."""
        cap = self.fc._BodyCap(20)
        cap(b"x" * 10)  # accepted
        with self.assertRaises(self.fc._BodyCapAbort):
            cap(b"y" * 15)  # would exceed → not appended
        self.assertEqual(cap.chunks, [b"x" * 10])
        self.assertTrue(cap.exceeded)


# ---------------------------------------------------------------------------
# `_curl_probe` end-to-end with a fake session
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Mock curl_cffi Response. `text` is a `@property` derived from
    `content` so the Phase 10.1 rehydrate path can be validated end-to-end:
    setting `.content` automatically updates `.text`, matching real
    curl_cffi semantics. A flat attribute would silently mask the bug
    the fix exists for (HIGH-1 follow-up, reviewer caught)."""

    def __init__(self, body: bytes, status: int = 200, url: str = ""):
        self.status_code = status
        self.url = url
        self.headers: dict = {}
        self.cookies: dict = {}
        self.content = body

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


class _ChunkedSession:
    """Session whose `.get()` simulates libcurl's per-chunk write loop:
    splits the body into `chunk_size`-sized pieces and feeds each to
    `content_callback`. If the callback raises, we mirror libcurl's
    behaviour and surface a transport exception.

    Caveat (mock-fidelity gap): real libcurl chunks are TCP-frame-sized
    (~1460 bytes) and may include zero-length tail writes; this mock
    uses fixed-size chunks and stops at body end. The unit-level
    semantics (per-chunk callback, abort on exception) match production.
    """

    def __init__(self, body: bytes, chunk_size: int = 64,
                 status: int = 200, headers: dict | None = None,
                 location: str | None = None):
        self.body = body
        self.chunk_size = chunk_size
        self.status = status
        self.fixed_headers = headers or {}
        if location is not None:
            self.fixed_headers.setdefault("Location", location)
        self.calls: list[dict] = []
        # Optional sequence of (status, location, body) for multi-hop
        # tests. Set via `queue_response(...)` before each subsequent
        # `.get()` call. Empty deque → use the default (self.body etc.).
        self._queue: list[tuple] = []

    def queue_response(self, *, status: int, location: str | None,
                       body: bytes) -> None:
        self._queue.append((status, location, body))

    def get(self, url, *, impersonate=None, headers=None, timeout=None,
            allow_redirects=False, content_callback=None, **_extra):
        self.calls.append({"url": url, "impersonate": impersonate})
        if self._queue:
            status, location, body = self._queue.pop(0)
            resp_headers = (
                {"Location": location} if location else {}
            )
        else:
            status = self.status
            body = self.body
            resp_headers = dict(self.fixed_headers)
        if content_callback is not None:
            for start in range(0, len(body), self.chunk_size):
                chunk = body[start:start + self.chunk_size]
                try:
                    content_callback(chunk)
                except Exception as e:
                    # Mirror curl_cffi: real production raises
                    # `curl_cffi.requests.exceptions.RequestException`
                    # (libcurl error 23). The mock raises plain
                    # `RuntimeError` to avoid the hard import; the
                    # producer's broad `except Exception` covers both
                    # and `cap.exceeded` is the canonical signal.
                    raise RuntimeError(
                        f"libcurl_mock: write aborted at {start + len(chunk)} bytes"
                    ) from e
        r = _FakeResponse(body, status=status, url=url)
        r.headers = resp_headers
        return r

    def close(self):
        return None


def _install_fake_curl_cffi(session: _ChunkedSession) -> None:
    fake_requests = types.ModuleType("curl_cffi.requests")
    fake_requests.Session = lambda: session  # type: ignore[attr-defined]

    def _module_level_get(url, **kwargs):
        return session.get(url, **kwargs)

    fake_requests.get = _module_level_get  # type: ignore[attr-defined]
    fake_pkg = types.ModuleType("curl_cffi")
    fake_pkg.requests = fake_requests  # type: ignore[attr-defined]
    sys.modules["curl_cffi"] = fake_pkg
    sys.modules["curl_cffi.requests"] = fake_requests


class CurlProbeBodyCapTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_env = os.environ.get("INSANE_MAX_BODY_BYTES")
        os.environ.pop("INSANE_MAX_BODY_BYTES", None)
        self.addCleanup(self._restore_env)

        from plus.tests._engine_fake_helper import (
            install_fake_curl_cffi_isolation,
        )
        install_fake_curl_cffi_isolation(self)

    def _restore_env(self) -> None:
        if self._saved_env is None:
            os.environ.pop("INSANE_MAX_BODY_BYTES", None)
        else:
            os.environ["INSANE_MAX_BODY_BYTES"] = self._saved_env

    def _reload_with_session(self, session: _ChunkedSession):
        _install_fake_curl_cffi(session)
        if "engine.fetch_chain" in sys.modules:
            del sys.modules["engine.fetch_chain"]
        import engine.fetch_chain as fc  # noqa: WPS433
        return fc

    def test_under_cap_returns_response_intact(self) -> None:
        body = b"<html>" + b"x" * 1024 + b"</html>"
        sess = _ChunkedSession(body, chunk_size=128)
        fc = self._reload_with_session(sess)

        resp, err = fc._curl_probe(
            "https://example.com/",
            impersonate="safari",
            referer="",
            timeout=5,
            session=sess,
        )

        self.assertIsNone(err)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.content, body)

    def test_over_cap_returns_body_too_large_error(self) -> None:
        # 5 KB body, 1 KB cap.
        body = b"x" * 5000
        os.environ["INSANE_MAX_BODY_BYTES"] = "1000"
        sess = _ChunkedSession(body, chunk_size=256)
        fc = self._reload_with_session(sess)

        resp, err = fc._curl_probe(
            "https://example.com/",
            impersonate="safari",
            referer="",
            timeout=5,
            session=sess,
        )

        self.assertIsNone(resp)
        self.assertIsNotNone(err)
        # Use the producer-side constant so a rename can't drift away
        # from the test silently.
        self.assertTrue(
            err.startswith(fc._BODY_TOO_LARGE_PREFIX),
            f"Expected stable cap error prefix "
            f"{fc._BODY_TOO_LARGE_PREFIX!r}; got {err!r}",
        )
        # Total reported is the first chunk that crossed the cap.
        # With chunk_size=256 and cap=1000, the 4th chunk lands us at
        # 1024 bytes — first overflow.
        self.assertIn(">1000", err)

    def test_cumulative_cap_across_redirect_hops(self) -> None:
        """Patch-queue #8 follow-up (Medium): a 10-hop redirect chain
        each delivering 60% of the cap would absorb 600% total without
        the cumulative tracker. Pin that the cap is enforced across
        hops, not just per-hop."""
        # Cap = 1000 bytes. Hop 1 returns a 600-byte 302; hop 2 returns
        # an 800-byte 200. Per-hop check passes (600 ≤ 1000, 800 ≤ 1000)
        # but cumulative 1400 > 1000 → must trip.
        os.environ["INSANE_MAX_BODY_BYTES"] = "1000"

        sess = _ChunkedSession(b"", chunk_size=128)  # placeholder body
        sess.queue_response(status=302, location="/next",
                            body=b"x" * 600)
        sess.queue_response(status=200, location=None, body=b"y" * 800)
        fc = self._reload_with_session(sess)

        resp, err = fc._curl_probe(
            "https://example.com/", impersonate="safari", referer="",
            timeout=5, session=sess,
        )

        self.assertIsNone(resp)
        self.assertIsNotNone(err)
        self.assertTrue(
            err.startswith(fc._BODY_TOO_LARGE_PREFIX),
            f"Cumulative redirect bytes must trip the cap; got {err!r}",
        )
        # Two hops issued before the trip.
        self.assertEqual(
            len(sess.calls), 2,
            f"Expected 2 GETs (hop1=302 then hop2 trips cap); got "
            f"{len(sess.calls)}",
        )
        # Error message carries the cumulative byte count.
        self.assertIn(">1000", err)

    def test_cumulative_within_cap_across_hops_still_succeeds(self) -> None:
        """Mirror of the cumulative case: total stays under cap → OK."""
        os.environ["INSANE_MAX_BODY_BYTES"] = "10000"
        sess = _ChunkedSession(b"", chunk_size=128)
        sess.queue_response(status=302, location="/next",
                            body=b"a" * 400)
        sess.queue_response(status=200, location=None, body=b"b" * 400)
        fc = self._reload_with_session(sess)

        resp, err = fc._curl_probe(
            "https://example.com/", impersonate="safari", referer="",
            timeout=5, session=sess,
        )

        self.assertIsNone(err)
        self.assertIsNotNone(resp)
        self.assertEqual(len(sess.calls), 2)

    def test_cap_is_exactly_the_limit_does_not_trip(self) -> None:
        # Boundary: total bytes == cap (not >). Must succeed.
        body = b"y" * 1024
        os.environ["INSANE_MAX_BODY_BYTES"] = "1024"
        sess = _ChunkedSession(body, chunk_size=512)
        fc = self._reload_with_session(sess)

        resp, err = fc._curl_probe(
            "https://example.com/",
            impersonate="safari",
            referer="",
            timeout=5,
            session=sess,
        )

        self.assertIsNone(err)
        self.assertEqual(resp.content, body)

    def test_callback_is_passed_to_session_get(self) -> None:
        body = b"<html>ok</html>"
        sess = _ChunkedSession(body, chunk_size=64)
        # Subclass the session to record `content_callback` separately.
        seen_callbacks: list = []
        orig_get = sess.get

        def _spy_get(url, **kwargs):
            seen_callbacks.append(kwargs.get("content_callback"))
            return orig_get(url, **kwargs)

        sess.get = _spy_get  # type: ignore[assignment]
        fc = self._reload_with_session(sess)

        fc._curl_probe(
            "https://example.com/",
            impersonate="safari",
            referer="",
            timeout=5,
            session=sess,
        )

        self.assertEqual(len(seen_callbacks), 1)
        self.assertIsNotNone(seen_callbacks[0])
        # Two-tier assertion: callable() proves wire-up regardless of
        # type; isinstance() pins identity so a future wrap (logging
        # decorator, etc.) is a deliberate choice rather than silent.
        self.assertTrue(callable(seen_callbacks[0]))
        self.assertIsInstance(
            seen_callbacks[0], fc._BodyCap,
            msg="Pins concrete callback type; relax to `callable` only "
                "if a wrapper is intentional.",
        )


# ---------------------------------------------------------------------------
# Phase 10.1 — `_curl_probe` rehydrates resp.content from cap.chunks
# ---------------------------------------------------------------------------

class _DivertingFakeSession(_ChunkedSession):
    """Mimics curl_cffi 0.15.0 with `content_callback`: the body is
    streamed to the callback and **`resp.content` is left empty** —
    the regression Phase 10.1 fixes. When no callback is supplied,
    behaves identically to the parent.
    """

    def get(self, url, *, content_callback=None, **kwargs):
        resp = super().get(url, content_callback=content_callback, **kwargs)
        if content_callback is not None:
            # Simulate curl_cffi 0.15.0: callback drained the body, so
            # resp's own buffer is empty even though the network bytes
            # are accounted for in the cap. `text` is a property derived
            # from `content`, so setting content="" also empties text —
            # which is exactly what real curl_cffi does.
            resp.content = b""
        return resp


class CurlProbeBodyRehydrateTest(unittest.TestCase):
    """Regression guard for the Phase 10 silent data-loss bug: when
    curl_cffi diverts the body into `content_callback`, `_curl_probe`
    must rehydrate `resp.content` from the captured chunks so downstream
    validators see the real body size.

    Without this guard, a synthetic 73KB 200 OK page at example.org/catalog
    was reported as `size=0 verdict=challenge` across every grid attempt.
    """

    def setUp(self) -> None:
        self._saved_env = os.environ.get("INSANE_MAX_BODY_BYTES")
        os.environ.pop("INSANE_MAX_BODY_BYTES", None)
        self.addCleanup(self._restore_env)

        from plus.tests._engine_fake_helper import (
            install_fake_curl_cffi_isolation,
        )
        install_fake_curl_cffi_isolation(self)

    def _restore_env(self) -> None:
        if self._saved_env is None:
            os.environ.pop("INSANE_MAX_BODY_BYTES", None)
        else:
            os.environ["INSANE_MAX_BODY_BYTES"] = self._saved_env

    def _reload_with_session(self, session):
        _install_fake_curl_cffi(session)
        if "engine.fetch_chain" in sys.modules:
            del sys.modules["engine.fetch_chain"]
        import engine.fetch_chain as fc  # noqa: WPS433
        return fc

    def test_empty_resp_content_is_rehydrated_from_chunks(self) -> None:
        """The streamed-body regression: 200 OK with 73KB body via callback,
        but `resp.content` empty. After fix, content == streamed body
        AND `resp.text` reflects it — `text` is the attribute validators
        actually consume, so this asserts the end-to-end fix path
        (HIGH-1 follow-up)."""
        body = b"<!DOCTYPE html><html>" + b"x" * 1000 + b"</html>"
        sess = _DivertingFakeSession(body, chunk_size=64)
        fc = self._reload_with_session(sess)

        resp, err = fc._curl_probe(
            "https://example.com/",
            impersonate="chrome",
            referer="",
            timeout=5,
            session=sess,
        )
        self.assertIsNone(err)
        self.assertEqual(resp.content, body)
        # Pin the property-derivation chain: validators read `.text`
        # (`validators.py:136`), not `.content`. A future mock divergence
        # that broke this derivation would slip past `.content` assertion.
        self.assertEqual(resp.text, body.decode("utf-8"))

    def test_prepopulated_content_is_not_clobbered(self) -> None:
        """Future-proofing: if a curl_cffi version (or test double) does
        populate `resp.content` alongside the callback, the rehydrate
        path must not overwrite it. The fix uses `if not resp.content`."""
        body = b"<html>real</html>"
        sess = _ChunkedSession(body, chunk_size=64)  # leaves resp.content populated
        fc = self._reload_with_session(sess)

        resp, err = fc._curl_probe(
            "https://example.com/",
            impersonate="chrome",
            referer="",
            timeout=5,
            session=sess,
        )
        self.assertIsNone(err)
        self.assertEqual(resp.content, body)

    def test_rehydrate_survives_redirect_chain(self) -> None:
        """The chunks accumulator is per `_BodyCap`, recreated per hop.
        Make sure the final resp (last hop) is the one that gets
        rehydrated, not an earlier 302 body."""
        final_body = b"<html>final destination 73kb-equivalent</html>"
        sess = _DivertingFakeSession(
            b"first-hop-ignored", chunk_size=64,
            status=302, location="https://example.com/final",
        )
        sess.queue_response(status=200, location=None, body=final_body)
        fc = self._reload_with_session(sess)

        resp, err = fc._curl_probe(
            "https://example.com/",
            impersonate="chrome",
            referer="",
            timeout=5,
            session=sess,
        )
        self.assertIsNone(err)
        self.assertEqual(resp.content, final_body)
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
