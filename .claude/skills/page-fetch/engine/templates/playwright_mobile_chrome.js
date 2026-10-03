#!/usr/bin/env node
/**
 * Generic Playwright mobile fetcher — real Chrome + device emulation.
 *
 * Usage:
 *   echo '{"url":"...", "device":"iPhone 13 Pro"}' | node playwright_mobile_chrome.js
 *
 * Device name must match playwright `devices[...]` keys (Pixel 7, iPhone 13 Pro,
 * iPad Pro 11, etc.). When in doubt, omit `device` — default is iPhone 13 Pro.
 *
 * NO-SITE-NAME RULE: same as playwright_real_chrome.js — no hostname branches.
 *
 * STEALTH MODEL: prefers `patchright` (drop-in Playwright fork closing CDP-level
 * leaks) and injects NO manual stealth JS; degrades to plain playwright with a
 * one-line stderr notice when patchright is absent. See playwright_real_chrome.js.
 */
// Chromium flags and staged-load waiting include Scrapling-derived pieces.
// BSD-3-Clause notice: ../../LICENSE (Copyright 2024, Karim shoair).

// Generic Chromium hardening flags (site-agnostic, No-Site-Name Rule). HARMFUL_ARGS
// (e.g. --enable-automation) are excluded; --enable-automation is suppressed via
// ignoreDefaultArgs because Playwright injects it by default.
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
const IGNORE_DEFAULT_ARGS = ['--enable-automation'];

const fs = require('fs');
const path = require('path');

// A1 (insane-search v0.8.x): drain stdout fully before exiting. An abrupt
// `process.exit(0)` can truncate a large HTML payload because it does not wait
// for pending stdout I/O to flush to the OS (Node docs). Await this write, set
// `process.exitCode`, and let the event loop drain naturally instead.
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

function clearSingletonLocks(profileDir) {
  if (!profileDir) return;
  for (const name of ['SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
    try { fs.rmSync(path.join(profileDir, name), { force: true }); } catch (_e) {}
  }
}

async function stagedWait(page, navTimeout) {
  try { await page.waitForLoadState('load', { timeout: navTimeout }); } catch (_e) {}
  try {
    await page.waitForLoadState('networkidle', { timeout: Math.min(navTimeout, 8000) });
  } catch (_e) {}
}

async function main() {
  const args = await readStdinJson();
  const url = args.url;
  if (!url) { process.stderr.write('missing url\n'); process.exit(2); }

  const profileDir = args.profileDir || '/tmp/.insane_pw_mobile_profile';
  const deviceName = args.device || 'iPhone 13 Pro';
  const waitSelector = args.waitSelector || null;
  const timeoutMs = args.timeout || 60000;
  const headless = args.headless ?? false;
  // P21: curl→Chrome cookie handoff (see playwright_real_chrome.js). Best-effort.
  const handoffCookies = Array.isArray(args.cookies) ? args.cookies : [];

  let chromium, devices;
  try {
    ({ chromium, devices } = require('patchright'));
  } catch (_e1) {
    process.stderr.write('[insane-fetch] patchright unavailable; falling back to plain playwright (reduced stealth)\n');
    try {
      ({ chromium, devices } = require('playwright'));
    } catch (_e2) {
      process.stderr.write('neither patchright nor playwright is installed\n');
      process.exit(1);
    }
  }

  const dev = devices[deviceName];
  if (!dev) {
    process.stderr.write(`unknown device: ${deviceName}\n`);
    process.exit(2);
  }

  const launchOpts = {
    channel: 'chrome',
    headless,
    args: STEALTH_ARGS,
    ignoreDefaultArgs: IGNORE_DEFAULT_ARGS,
    ...dev,
  };

  let ctx;
  try {
    try {
      ctx = await chromium.launchPersistentContext(profileDir, launchOpts);
    } catch (e) {
      if (/Singleton|ProcessSingleton/i.test(e.message || '')) {
        clearSingletonLocks(profileDir);
        ctx = await chromium.launchPersistentContext(profileDir, launchOpts);
      } else {
        throw e;
      }
    }
    if (handoffCookies.length) {
      try { await ctx.addCookies(handoffCookies); } catch (_e) {
        process.stderr.write('[insane-fetch] cookie handoff skipped (addCookies rejected)\n');
      }
    }
    const page = await ctx.newPage();
    const navTimeout = Math.min(timeoutMs, 90000);
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: navTimeout });
    await stagedWait(page, navTimeout);

    if (waitSelector) {
      try {
        await page.waitForSelector(waitSelector, { timeout: Math.min(timeoutMs, 20000) });
      } catch (_e) {}
    }

    const html = await page.content();
    await writeStdoutAsync(html);   // flush fully before any exit (A1)
    process.exitCode = 0;
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
