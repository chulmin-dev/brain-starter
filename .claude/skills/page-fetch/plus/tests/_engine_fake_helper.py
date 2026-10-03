"""Shared isolation helper for engine.fetch_chain fake-injection tests.

Tests that swap a fake `curl_cffi` into `sys.modules` and reload
`engine.fetch_chain` must restore exactly what they touched, even if
setUp raises midway through. Using `unittest.addCleanup` instead of
`tearDown` is the safe pattern: cleanups registered before the raising
mutation still execute (tearDown does not run when setUp raises).

`install_fake_curl_cffi_isolation(testcase)` snapshots the relevant
modules and registers cleanups in the order the test must reverse them.
The test then performs its own fake-install and `_reload_fetch_chain`.
"""
from __future__ import annotations

import sys
import unittest


def install_fake_curl_cffi_isolation(testcase: unittest.TestCase) -> None:
    """Snapshot sys.modules + engine_proxy state and register cleanups.

    `addCleanup` runs cleanups in LIFO order. We want the final order to be:
        (1) restore sys.modules (so engine.fetch_chain is the real module)
        (2) reinstall engine_proxy onto that real module
    so cleanups are registered in the OPPOSITE order below.
    """
    saved_curl_cffi = {
        k: sys.modules.get(k) for k in ("curl_cffi", "curl_cffi.requests")
    }
    saved_fetch_chain = sys.modules.get("engine.fetch_chain")

    from plus import engine_proxy as _ep

    def _reinstall_engine_proxy():
        if "engine.fetch_chain" in sys.modules:
            _ep._engine_fetch_chain = sys.modules["engine.fetch_chain"]
        _ep.install()

    def _restore_sys_modules():
        for k, v in saved_curl_cffi.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
        if saved_fetch_chain is not None:
            sys.modules["engine.fetch_chain"] = saved_fetch_chain
            import engine as _engine_root
            _engine_root.fetch_chain = saved_fetch_chain
        else:
            sys.modules.pop("engine.fetch_chain", None)

    # LIFO: register reinstall FIRST so it runs LAST (after sys.modules restored).
    testcase.addCleanup(_reinstall_engine_proxy)
    testcase.addCleanup(_restore_sys_modules)

    _ep.uninstall()
