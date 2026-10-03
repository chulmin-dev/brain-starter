#!/usr/bin/env node
/**
 * Generic Playwright fetcher — real Chrome channel (not bundled Chromium).
 *
 * Usage (driven by engine/executor.py):
 *   echo '{"url":"...", "profileDir":"/tmp/.p", "waitSelector":"article"}' | node playwright_real_chrome.js
 *
 * Outputs page HTML to stdout on success; errors to stderr with non-zero exit.
 *
 * NO-SITE-NAME RULE: this file must never branch on specific hostnames.
 * All site specifics come from the JSON input (url, waitSelector).
 *
 * STEALTH MODEL: this template prefers `patchright` (a drop-in Playwright fork
 * that closes CDP-level leaks — Runtime.enable / Console.enable / navigator.webdriver
 * — at the library layer). When patchright is present we deliberately inject NO
 * manual stealth JS: any addInitScript/exposeFunction is itself a fresh detection
 * signature that *defeats* patchright. When patchright is absent we degrade to plain
 * playwright (still channel:chrome) and emit a one-line stderr notice.
 *
 * Dependencies (install once on target machine):
 *   npm i -g patchright playwright    # patchright pinned lockstep with playwright
 *   npx patchright install chrome     # or: npx playwright install chrome
 */
// Chromium flags and staged-load waiting include Scrapling-derived pieces.
// BSD-3-Clause notice: ../../LICENSE (Copyright 2024, Karim shoair).

// STEALTH_ARGS / IGNORE_DEFAULT_ARGS: generic Chromium hardening flags. These are
// site-agnostic (No-Site-Name Rule) and complement patchright's library-level
// patches. HARMFUL_ARGS (e.g. --enable-automation, --disable-extensions,
// --disable-component-update) are intentionally NOT included — they are themselves
// bot-detection signals. --enable-automation is injected by Playwright defaults, so
// it is suppressed via ignoreDefaultArgs instead.
const STEALTH_ARGS = [
  '--disable-blink-features=AutomationControlled',
  '--disable-features=AudioServiceOutOfProcess,IsolateOrigins,site-per-process',
  '--no-first-run',
  '--no-default-browser-check',
  '--no-service-autorun',
  '--password-store=basic',
  '--use-mock-keychain',
  '--force-color-profile=srgb',
  '--font-render-hinting=none',
  '--disable-back-forward-cache',
];
// Default args Playwright injects that leak automation. Suppress, do not re-add.
const IGNORE_DEFAULT_ARGS = ['--enable-automation'];

const fs = require('fs');
const path = require('path');

// A1 (insane-search v0.8.x): drain stdout fully before exiting. An abrupt
// `process.exit(0)` can truncate a large HTML / JSON envelope because it does
// not wait for pending stdout I/O to flush to the OS (Node docs). Await this
// write, set `process.exitCode`, and let the event loop drain naturally instead.
function writeStdoutAsync(payload) {
  return new Promise((resolve, reject) => {
    process.stdout.write(payload, (err) => (err ? reject(err) : resolve()));
  });
}

async function readStdinJson() {
  return await new Promise((resolve, reject) => {
    let data = '';
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch (e) { reject(e); }
    });
    process.stdin.on('error', reject);
  });
}

/**
 * launchPersistentContext can fail with "ProcessSingleton ... SingletonLock"
 * if a previous run left a stale lock in the profile dir (crash / SIGKILL).
 * Clear the lock files once and let the caller retry the launch.
 */
function clearSingletonLocks(profileDir) {
  if (!profileDir) return;
  for (const name of ['SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
    try { fs.rmSync(path.join(profileDir, name), { force: true }); } catch (_e) {}
  }
}

/**
 * Staged load wait: 'load' first, then best-effort 'networkidle'. Replaces the
 * old fixed waitForTimeout magic numbers — fast sites finish fast, slow/XHR-heavy
 * sites stay stable. networkidle is wrapped because some SPAs keep analytics/XHR
 * open indefinitely and would otherwise hang to the nav timeout.
 */
async function stagedWait(page, navTimeout) {
  try { await page.waitForLoadState('load', { timeout: navTimeout }); } catch (_e) {}
  try {
    await page.waitForLoadState('networkidle', { timeout: Math.min(navTimeout, 8000) });
  } catch (_e) {}
}

/**
 * P32 CDP NetworkJournal: passively collect application/json XHR/fetch bodies.
 *
 * Attaches a `page.on('response')` listener (PASSIVE — we never call page.route,
 * which is an active interception that is itself a detection signature AND
 * disables the HTTP cache). Because this only listens, it is compatible with
 * patchright's no-injection stealth contract: it uses the CDP Network domain,
 * not injected JS.
 *
 * Filters: content-type application/json + resourceType xhr|fetch. Budgets:
 * per-response cap (skip a single huge JSON) and a cumulative cap (stop
 * collecting once the envelope would blow past the body ceiling). response.body()
 * is wrapped in try/catch because it throws on evicted / redirect / streamed
 * responses — those are skipped, never fatal.
 *
 * Returns an array the caller drains after navigation; `attach` wires the
 * listener and must be called BEFORE the first navigation.
 */
function makeJsonJournal(perResponseCap, cumulativeCap) {
  const captured = [];
  let total = 0;
  let stopped = false;

  function attach(page) {
    page.on('response', async (resp) => {
      if (stopped) return;
      try {
        const req = resp.request();
        const rtype = req.resourceType();
        if (rtype !== 'xhr' && rtype !== 'fetch') return;
        const ct = (resp.headers()['content-type'] || '').toLowerCase();
        if (!ct.includes('application/json')) return;

        let body;
        try {
          body = await resp.body();
        } catch (_e) {
          // evicted / redirect (3xx) / streamed response — no body available.
          return;
        }
        if (!body || body.length === 0) return;
        if (body.length > perResponseCap) return;     // one giant JSON — skip
        if (total + body.length > cumulativeCap) {     // envelope budget hit
          stopped = true;
          return;
        }
        total += body.length;
        captured.push({
          url: resp.url(),
          status: resp.status(),
          body: body.toString('utf-8'),
        });
      } catch (_e) {
        // listener must never throw into Playwright's event loop
      }
    });
  }

  return { attach, drain: () => captured };
}

/** Scroll to the bottom in steps so lazy-loaded / infinite-scroll content renders. */
async function scrollToEnd(page) {
  try {
    await page.evaluate(async () => {
      await new Promise((resolve) => {
        let total = 0;
        const step = 600;
        const timer = setInterval(() => {
          const before = document.scrollingElement ? document.scrollingElement.scrollHeight : 0;
          window.scrollBy(0, step);
          total += step;
          if (total >= before || total > 50000) { clearInterval(timer); resolve(); }
        }, 120);
      });
    });
    await page.waitForTimeout(400);
  } catch (_e) {
    // best-effort; some pages block scripted scroll
  }
}

async function main() {
  const args = await readStdinJson();
  const url = args.url;
  if (!url) { process.stderr.write('missing url\n'); process.exit(2); }

  const profileDir = args.profileDir || '/tmp/.insane_pw_profile';
  const waitSelector = args.waitSelector || null;
  const timeoutMs = args.timeout || 60000;
  const headless = args.headless ?? false;     // Akamai/etc detect headless
  // 4.2: viewport:null tells patchright/playwright NOT to override the real
  // Chrome default window geometry. A fixed 1920×1080 is itself a fingerprint
  // signal (identical across all invocations). null lets the profile's saved
  // window size pass through, which varies naturally per persistent context.
  // Callers may still pass args.viewport to force a specific size (e.g. tests).
  const viewport = "viewport" in args ? args.viewport : null;
  // P21: cookies handed over from the curl session (e.g. a partial clearance).
  // Replayed via context.addCookies so the browser doesn't restart the
  // challenge from scratch. Best-effort — malformed entries are skipped and
  // never abort the run. Values are not logged.
  const handoffCookies = Array.isArray(args.cookies) ? args.cookies : [];
  // P32: opt-in CDP NetworkJournal. Default OFF → stdout stays raw HTML (the
  // documented template contract executor.py validates via _FakeResp). When
  // captureJson is true, stdout becomes a {html, captured_json} JSON envelope
  // and executor.py reassembles it (only when it set the flag).
  const captureJson = args.captureJson === true;
  // Byte budgets for the JSON journal (defaults align with the 10MB engine
  // body cap; per-response stays well under so one XHR can't dominate).
  const jsonPerResponseCap = args.jsonPerResponseCap || 2 * 1024 * 1024;
  const jsonCumulativeCap = args.jsonCumulativeCap || 8 * 1024 * 1024;
  // ADAPT-1: reverse cookie bridge (Chrome→curl). When true, context.cookies()
  // is harvested after page load and emitted in the envelope so executor.py can
  // bridge clearance tokens back to the curl session jar. Cookie VALUES are
  // never logged by the Python layer (output-0 policy); they transit stdout
  // only within the process-local pipe and are stored 0600 on disk.
  const captureCookies = args.captureCookies === true;

  let chromium;
  let engineName = 'patchright';
  try {
    ({ chromium } = require('patchright'));
  } catch (_e1) {
    // patchright not installed — degrade to plain playwright (no CDP-level
    // stealth, but channel:chrome + STEALTH_ARGS still apply). One-line notice
    // keeps the capability-matched dispatch philosophy: visible, never silent.
    engineName = 'playwright';
    process.stderr.write('[insane-fetch] patchright unavailable; falling back to plain playwright (reduced stealth)\n');
    try {
      ({ chromium } = require('playwright'));
    } catch (_e2) {
      process.stderr.write('neither patchright nor playwright is installed\n');
      process.exit(1);
    }
  }

  const launchOpts = {
    channel: 'chrome',          // real Chrome, not bundled Chromium
    headless,
    viewport,
    args: STEALTH_ARGS,
    ignoreDefaultArgs: IGNORE_DEFAULT_ARGS,
  };

  let ctx;
  try {
    try {
      ctx = await chromium.launchPersistentContext(profileDir, launchOpts);
    } catch (e) {
      // Stale SingletonLock from a crashed prior run — clear once and retry.
      if (/Singleton|ProcessSingleton/i.test(e.message || '')) {
        clearSingletonLocks(profileDir);
        ctx = await chromium.launchPersistentContext(profileDir, launchOpts);
      } else {
        throw e;
      }
    }
    // P21: replay curl-side cookies before the first navigation so a clearance
    // token is already present when the page loads.
    if (handoffCookies.length) {
      try { await ctx.addCookies(handoffCookies); } catch (_e) {
        process.stderr.write('[insane-fetch] cookie handoff skipped (addCookies rejected)\n');
      }
    }

    const page = await ctx.newPage();
    const navTimeout = Math.min(timeoutMs, 90000);

    // P32: wire the passive JSON journal BEFORE any navigation so XHR/fetch
    // responses fired during warmup + main load are captured. No-op on stdout
    // unless captureJson was requested.
    const journal = captureJson
      ? makeJsonJournal(jsonPerResponseCap, jsonCumulativeCap)
      : null;
    if (journal) journal.attach(page);

    // Warmup hop: visit the site root first so Akamai-style bot managers
    // can run their JS sensor and set a resolved session cookie. Direct
    // landing on a search/deep URL is the classic first-hit rejection pattern.
    try {
      const urlObj = new URL(url);
      const rootUrl = `${urlObj.protocol}//${urlObj.host}/`;
      if (rootUrl !== url) {
        await page.goto(rootUrl, { waitUntil: 'domcontentloaded', timeout: navTimeout });
        await stagedWait(page, navTimeout);
      }
    } catch (_e) {
      // warmup is best-effort; continue even if it hiccups
    }

    // Main page — DOM loaded then stage through load/networkidle.
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: navTimeout });
    await stagedWait(page, navTimeout);

    if (waitSelector) {
      try {
        await page.waitForSelector(waitSelector, { timeout: Math.min(timeoutMs, 20000) });
      } catch (_e) {
        // Selector still missing — try one hard reload in case the first hit
        // landed on a challenge page and the sensor has just cleared.
        try {
          await page.reload({ waitUntil: 'domcontentloaded', timeout: navTimeout });
          await stagedWait(page, navTimeout);
          try {
            await page.waitForSelector(waitSelector, { timeout: 10000 });
          } catch (_e2) {
            // Still no luck — caller validates HTML anyway.
          }
        } catch (_e3) {
          // reload failed — proceed with whatever we have
        }
      }
    }

    // Trigger lazy/infinite content before capture.
    await scrollToEnd(page);

    const html = await page.content();
    // ADAPT-1: harvest browser cookies for the reverse bridge (Chrome→curl).
    // context.cookies() returns all cookies in the persistent context — only
    // name/value/domain/path are forwarded; sameSite/httpOnly/secure are
    // intentionally stripped so the struct stays {name,value,domain,path}.
    // Values transit the process-local stdout pipe only; the Python layer
    // enforces output-0 (never logs values). Best-effort: failure → empty list.
    let capturedCookies = [];
    if (captureCookies) {
      try {
        const raw = await ctx.cookies();
        capturedCookies = raw.map((c) => ({
          name: c.name || '',
          value: c.value || '',
          domain: c.domain || '',
          path: c.path || '/',
        }));
      } catch (_e) {
        // cookie harvest failure must not abort the fetch
      }
    }
    if (journal || captureCookies) {
      // P32 / ADAPT-1 envelope: {html, captured_json?, captured_cookies?}.
      // Emitted when either captureJson or captureCookies was requested; the
      // default raw-HTML stdout contract is untouched when both are false.
      const envelope = { html };
      if (journal) envelope.captured_json = journal.drain();
      if (captureCookies) envelope.captured_cookies = capturedCookies;
      await writeStdoutAsync(JSON.stringify(envelope));
    } else {
      await writeStdoutAsync(html);
    }
    process.exitCode = 0;            // flush fully above before any exit (A1)
    return;                         // let finally close ctx, then exit naturally
  } catch (e) {
    process.stderr.write(`${e.name || 'Error'}: ${e.message || e}\n`);
    process.exitCode = 1;
    return;
  } finally {
    try { if (ctx) await ctx.close(); } catch (_e) {}
  }
}

main();
