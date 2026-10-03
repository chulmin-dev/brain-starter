// ladder.mjs — bounded fetch and honest terminal results; no browser tier.
import { fetchEngine } from './engines.mjs';

// "unrendered" is RARE: most pages' data lives in raw HTML (problem is usually PARSING, not
// rendering). True client-rendered SPAs return a thin pre-hydration shell. So: a SUBSTANTIAL raw
// page is "ok" even if a shell marker appears somewhere in it (markers false-fire inside big
// hydrated pages — large catalogs can contain markers without being empty shells). Shell markers
// only matter when the page is ALSO small.
const SUBSTANTIAL_BYTES = 8000;   // raw HTML this big almost always carries the real content
const THIN_BYTES = 1500;          // below this on raw HTML → suspect a JS shell
const SHELL_MARKERS = /(<div id="root"><\/div>|<div id="app"><\/div>|please enable javascript|window\.__INITIAL_STATE__\s*=\s*\{\}\s*[<;]|<div id="__next"><\/div>|<div id="__nuxt"><\/div>|ng-version|data-server-rendered)/i;
// Negative markers: a 200-page that is actually a login wall / maintenance / soft-error. Without
// success_selectors page-fetch returns weak_ok for ANY 200 page, so a big login page is
// byte-indistinguishable from real content — classify would say 'ok' (false success). When these
// fire, demote to 'suspect' so the caller verifies instead of trusting it (critical for unattended
// crawl). (review HIGH, 2026-06-14)
//
// CRITICAL precision lesson (rereview, 2026-06-14): markers must be WALL-SHAPED, not bare content
// words. Bare `maintenance`/`temporarily unavailable`/`점검 중` over-fire on real catalogs
// ("maintenance kit for sale", "점검 중인 일부 항목 외 정상 판매") → false negative (drops real
// data). And `로그인 필요` must NOT match its negation "로그인 필요 없음". Every alternation below
// is anchored to a structural tag, a title/heading, or a full wall phrase.
const NEGATIVE_MARKERS = new RegExp([
  '<input[^>]+type=["\']?password',                              // a password field = login form
  '<title>[^<]*(로그인|login|sign[ -]?in)[^<]*</title>',          // login in the page title
  '로그인\\s*(이|가)?\\s*(필요|해\\s*주세요|하세요)(?!\\s*없)',     // "login required" — but NOT "필요 없음"
  '로그인\\s*후\\s*이용',                                          // "available after login"
  'please (log[ -]?in|sign[ -]?in) to (continue|view|access)',
  '시스템\\s*점검',                                                // "system maintenance" (KR wall)
  '점검\\s*중입니다',                                              // "...is under maintenance" (full phrase)
  '서비스\\s*(점검|이용)\\s*(중입니다|불가)',
  '(현재\\s*)?(서비스\\s*)?접속이\\s*불가',                         // naver-style interstitial
  '(under|down for|scheduled)\\s+maintenance',                    // wall-shaped EN maintenance
  'service\\s+(is\\s+)?(currently\\s+)?unavailable',              // wall-shaped (not bare "unavailable")
  'temporarily\\s+(down|offline|closed)',                         // not bare "temporarily unavailable"
  'access\\s+denied',
].join('|'), 'i');

export function classify(fetchResult) {
  // A7-aware failure path: use grid-state fields instead of verdict-only proxy.
  // Applied BEFORE the success-content logic so the grid tells us WHY it stopped.
  //
  // CRITICAL: mustInvokeMcp is NOT used here for the blocked decision.
  // Empirically proven (Naver): headless Chrome is WEAKER than curl_cffi for
  // fingerprint blocks. The grid-state (gridExhausted + verdict) decides, not
  // page-fetch's generic MCP signal. mustInvokeMcp is surfaced in trail only.
  const stopReason = fetchResult.stopReason || null;
  const gridExhausted = fetchResult.gridExhausted || false;

  if (stopReason === 'rate_limited') return 'rate_limited';   // 429 transient — NOT a fingerprint block
  if (stopReason === 'terminal_status') return 'failed';      // 404/410/auth — dead URL, no browser can fix

  // Grid-exhausted + challenge/suspect_ok → confirmed fingerprint block.
  // Replaces the old verdict-only proxy `verdict==='challenge'→blocked`.
  const v = (fetchResult.verdict || '').toLowerCase();
  if (gridExhausted && (v === 'challenge' || v === 'suspect_ok')) return 'blocked';

  // A cut budget does not prove that the grid was exhausted.
  if (stopReason === 'budget' && !gridExhausted) return 'budget_cut';

  // Legacy: bare challenge verdict without A7 fields (e.g. old page-fetch, or
  // gridExhausted=false with challenge) → treat as blocked (conservative).
  // L3: gate on !ok so a pathological ok:true+verdict:'challenge' page isn't discarded.
  if (!fetchResult.ok && v === 'challenge') return 'blocked';

  // Preserve generic engine failures separately from terminal URL failures.
  if (!fetchResult.ok || fetchResult.code !== 0) return 'fetch_error';
  const c = fetchResult.content || '';
  if (NEGATIVE_MARKERS.test(c)) return 'suspect';                   // login/maintenance/soft-error wall
  if (fetchResult.bytes >= SUBSTANTIAL_BYTES) return 'ok';          // big page, no neg marker → we got it
  if (fetchResult.bytes < THIN_BYTES) return 'unrendered';          // tiny → likely a shell
  return SHELL_MARKERS.test(c) ? 'unrendered' : 'ok';              // mid-size: shell marker tiebreaker
}

// strip credentials + query (tokens/magic-links) before logging (output-0 policy)
function safeUrl(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}${u.pathname}${u.search ? '?…' : ''}`; }
  catch { return String(url).split('?')[0]; }
}

// Fetch once, then report what this installed skill can and cannot do.
export async function ladder(url, { interactive = false, aggressive = false, log = () => {} } = {}) {
  const trail = [];

  // tier 1 — page-fetch. Fetch RAW: it's the ground truth for "did we get the page" and is
  // where structured data (product grids, preloaded JSON) actually lives. Markdown extraction is
  // lossy on catalogs and caused false "unrendered" verdicts.
  log(`[harvest] tier1 fetch (raw): ${safeUrl(url)}`);
  const f = await fetchEngine(url, { format: 'raw', aggressive });
  trail.push({ tier: 'fetch', verdict: f.verdict, bytes: f.bytes, ok: f.ok });
  const klass = classify(f);


  return finishFetch(f, klass, trail, interactive);
}

export function finishFetch(f, klass = classify(f), trail = [], interactive = false) {
  const common = { tier_used: 'fetch', verdict: f.verdict, trail };
  if (klass === 'blocked') {
    return { ...common, status: 'blocked', content: '',
      report: 'The fetch was blocked. Open the page yourself; this skill does not bypass access controls.' };
  }
  if (klass === 'failed' || klass === 'fetch_error') {
    return { ...common, status: 'failed', content: '',
      report: 'The fetch failed. Check the URL or open the page yourself.' };
  }
  if (klass === 'rate_limited') {
    return { ...common, status: 'rate_limited', content: '',
      report: 'HTTP 429: respect the rate limit and try later.' };
  }
  if (klass === 'budget_cut') {
    return { ...common, status: 'budget-exhausted', content: '',
      report: 'The fetch budget ended before all routes were tried. Open the page yourself.' };
  }
  if (klass === 'suspect') {
    return { ...common, status: 'suspect', content: f.content, bytes: f.bytes,
      report: 'The response looks like a login or maintenance wall, not the requested content. Open the page yourself.' };
  }
  if (interactive || klass === 'unrendered') {
    return { ...common, status: 'render-unavailable', content: f.content, bytes: f.bytes,
      report: 'JavaScript rendering or interaction is unavailable in harvest. Open the page yourself and provide the public text if needed.' };
  }
  return { ...common, status: 'ok', content: f.content, bytes: f.bytes };
}
