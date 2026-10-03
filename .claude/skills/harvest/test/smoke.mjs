// smoke.mjs — offline regression for harvest's pure logic (no network).
// The ladder DECISION logic (blocked vs unrendered vs ok) + format/dedup are the parts that must
// never silently regress. Exit 0 = all pass.
import { classify, finishFetch } from '../ladder.mjs';
import { normalizeCrawl } from '../crawl.mjs';
import { render, dedup, toCSV, toMarkdown, toJSON } from '../format.mjs';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };

console.log('CLASSIFY (the ladder discriminator):');
ok(classify({ verdict: 'challenge' }) === 'blocked', 'challenge (no A7 fields) → blocked (legacy path)');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 441014, content: 'big <div id="app"></div> window.__INITIAL...' }) === 'ok',
   '441KB page with shell marker → ok (markers ignored on big pages)');
ok(classify({ verdict: 'strong_ok', ok: true, code: 0, bytes: 20000, content: 'x' }) === 'ok', '20KB substantial → ok');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 900, content: '<div id="root"></div>' }) === 'unrendered', 'small SPA shell → unrendered');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 300, content: 'short' }) === 'unrendered', 'tiny (<1500B) → unrendered');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 3000, content: 'normal content no shell markers here' }) === 'ok', 'mid-size, no shell marker → ok');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 3000, content: 'please enable javascript' }) === 'unrendered', 'mid-size + shell marker → unrendered');
ok(classify({ ok: false, code: 1, verdict: 'fail' }) === 'fetch_error', 'generic engine failure (no terminal_status) → fetch_error (escalates to render)');

console.log('A7 FAILURE-GATE CLASSIFY (grid-state fields, not verdict-only proxy):');
// rate_limited: 429 transient — must NOT be classified as blocked or failed
ok(classify({ verdict: 'suspect_ok', ok: false, code: 1, stopReason: 'rate_limited', gridExhausted: false, untriedRoutes: 8, mustInvokeMcp: false }) === 'rate_limited',
   'stopReason=rate_limited → rate_limited (transient 429, not fingerprint block)');
// terminal_status: 404/410/auth URL-level — must be 'failed', not 'blocked'
ok(classify({ verdict: 'not_found', ok: false, code: 1, stopReason: 'terminal_status', gridExhausted: false, untriedRoutes: 0, mustInvokeMcp: false }) === 'failed',
   'stopReason=terminal_status → failed (URL-level 404/auth, not WAF)');
// grid_exhausted + challenge → confirmed fingerprint block
ok(classify({ verdict: 'challenge', ok: false, code: 1, stopReason: 'exhausted', gridExhausted: true, untriedRoutes: 0, mustInvokeMcp: true }) === 'blocked',
   'gridExhausted=true + verdict=challenge → blocked (fingerprint confirmed)');
// grid_exhausted + suspect_ok → also confirmed block (not just challenge)
ok(classify({ verdict: 'suspect_ok', ok: false, code: 1, stopReason: 'exhausted', gridExhausted: true, untriedRoutes: 0, mustInvokeMcp: false }) === 'blocked',
   'gridExhausted=true + verdict=suspect_ok → blocked (grid exhausted = confirmed block)');
// budget cut + grid NOT exhausted → budget_cut (escalate to render, not give up)
ok(classify({ verdict: 'challenge', ok: false, code: 1, stopReason: 'budget', gridExhausted: false, untriedRoutes: 5, mustInvokeMcp: false }) === 'budget_cut',
   'stopReason=budget + gridExhausted=false → budget_cut (escalate to render, not blocked)');
// mustInvokeMcp=true does NOT flip blocked into browser-escalate — classify stays 'blocked'
ok(classify({ verdict: 'challenge', ok: false, code: 1, stopReason: 'exhausted', gridExhausted: true, untriedRoutes: 0, mustInvokeMcp: true }) === 'blocked',
   'mustInvokeMcp=true does NOT change blocked → still blocked (headless is weaker, proven on Naver)');
// M pin: terminal_status → 'failed', NOT 'blocked'; ladder() must short-circuit before renderEngine
ok(classify({ verdict: 'not_found', ok: false, code: 1, stopReason: 'terminal_status', gridExhausted: false, untriedRoutes: 0, mustInvokeMcp: false }) === 'failed',
   'M-pin: terminal_status → failed (URL-level dead end; renderEngine must NOT be called)');
// M pin: generic code≠0 (no stopReason, no terminal_status) → 'fetch_error', NOT 'failed'; reaches render
ok(classify({ verdict: 'fail', ok: false, code: 1, stopReason: null, gridExhausted: false, untriedRoutes: 0, mustInvokeMcp: false }) === 'fetch_error',
   'M-pin: generic code≠0 (no terminal_status) → fetch_error (escalates to tier-2 render; NOT url-level dead end)');

console.log('FALSE-SUCCESS GUARD (review HIGH — login/maintenance must NOT be ok):');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 25000, content: '<title>로그인</title> <input name=pw type="password">' }) === 'suspect', '25KB login wall → suspect (not ok)');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 12000, content: '...시스템 점검중입니다...' }) === 'suspect', 'maintenance page → suspect (not ok)');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 12000, content: '현재 서비스 접속이 불가합니다' }) === 'suspect', 'naver interstitial text → suspect');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 50000, content: '정상 상품 카탈로그 Example Widget 100' }) === 'ok', 'real catalog (no neg marker) → ok');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 12000, content: '<div id="__next"></div>' }) === 'ok', 'big Next.js shell w/o neg marker stays ok (mid path needs <8KB; documented gap)');

console.log('NEGATIVE-MARKER PRECISION (rereview HIGH — must NOT over-fire on real catalogs):');
// these are real-content strings that the bare-word markers wrongly flagged; must stay ok
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 50000, content: 'maintenance kit for sale — example grip 100' }) === 'ok', '"maintenance kit for sale" → ok (not suspect)');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 50000, content: 'this size temporarily unavailable, others in stock' }) === 'ok', '"temporarily unavailable, others in stock" → ok');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 50000, content: '현재 점검 중인 일부 항목 외 전 상품 정상 판매' }) === 'ok', 'KR "점검 중인 일부 항목 외 정상 판매" → ok');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 50000, content: '로그인 필요 없는 무료 카탈로그 — 바로 구매' }) === 'ok', 'KR negation "로그인 필요 없" → ok (not suspect)');
// and the genuine walls still fire
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 50000, content: 'site is down for maintenance, back soon' }) === 'suspect', 'real "down for maintenance" → suspect');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 50000, content: '서비스 점검 중입니다. 잠시 후 이용해 주세요' }) === 'suspect', 'real "점검 중입니다" → suspect');
ok(classify({ verdict: 'weak_ok', ok: true, code: 0, bytes: 50000, content: '로그인이 필요합니다' }) === 'suspect', 'real "로그인이 필요합니다" → suspect');

console.log('CRAWL PARSE (review CRITICAL — must read page-fetch {items} shape):');
ok(normalizeCrawl({ mode: 'paginate', source_url: 'x', count: 3, items: [{ url: '/a' }, { url: '/b' }, { url: '/a' }] }).count === 2, 'items[] parsed + deduped: 3→2 (was 0 = the critical bug)');
ok(normalizeCrawl({ count: 3, items: [] }).status === 'partial', 'upstream count>0 but 0 resolved → partial (no false ok)');
ok(normalizeCrawl({ count: 0, items: [] }).status === 'ok', 'genuinely empty → ok');
ok(normalizeCrawl({ items: [{ loc: '/x' }] }).records[0].url === '/x', 'normalizes loc→url');
ok(normalizeCrawl([{ url: '/a' }]).count === 1, 'tolerates bare array shape');
ok(normalizeCrawl({ count: 3, items: [null, { url: '/a' }, undefined, { loc: '/b' }, 42] }).count === 2, 'null/non-object items filtered (no Object.keys crash)');
ok(normalizeCrawl({ items: 'oops' }).count === 0, 'malformed non-array items → count 0 (no crash)');
ok(normalizeCrawl({ items: 5 }).status === 'ok' && normalizeCrawl({ items: 5 }).count === 0, 'malformed numeric items → empty, not throw');

console.log('FORMAT + DEDUP:');
const recs = [{ url: '/a', name: 'X', price: 100 }, { url: '/a', name: 'X', price: 100 }, { url: '/b', name: 'Y', price: 200 }];
const d = dedup(recs, 'url');
ok(d.length === 2, 'dedup by url: 3 → 2 (first kept)');
ok(dedup([{ a: 1 }, { a: 1 }]).length === 1, 'dedup no url-field falls back to stringify');
ok(/^url,name,price/.test(toCSV(d)), 'CSV header from union of keys');
ok(toCSV([{ a: 'x,y' }]).includes('"x,y"'), 'CSV quotes cells with commas');
ok(/\| url \| name \| price \|/.test(toMarkdown(d)), 'Markdown table header');
ok(JSON.parse(toJSON(d)).length === 2, 'JSON round-trips');
ok(render(d, 'csv').startsWith('url,name,price'), 'render dispatches csv');
ok(render(d, 'md').includes('|'), 'render dispatches md');
ok(Array.isArray(JSON.parse(render(d, 'json'))), 'render dispatches json');
ok(toMarkdown([]).includes('no records'), 'empty records → graceful md');
ok(toCSV([{ a: '=SUM(A1:A9)' }]).includes("'=SUM"), 'CSV formula-injection guard (= cell → prefix quote)');

console.log('TERMINAL RESULTS (no installed browser assumed):');
const fetched = { verdict: 'weak_ok', ok: true, code: 0, bytes: 900, content: '<div id="root"></div>' };
ok(finishFetch(fetched).status === 'render-unavailable', 'JS-only shell → honest terminal rendering limitation');
ok(finishFetch({ ...fetched, bytes: 20000, content: 'public page' }, undefined, [], true).status === 'render-unavailable',
   'explicit interaction cannot become false success even with a substantial fetch');
ok(finishFetch({ ...fetched, content: '<input type="password">', bytes: 20000 }).status === 'suspect',
   'login wall remains suspect, not a rendering promise');
ok(finishFetch({ ...fetched, ok: false, code: 1, stopReason: 'budget' }).status === 'budget-exhausted',
   'cut budget is neither a confirmed block nor a browser handoff');
ok(finishFetch({ ...fetched, ok: false, code: 1, verdict: 'fail' }).status === 'failed',
   'failed engine is an honest failure, not missing content success');
ok(finishFetch({ ...fetched, bytes: 20000, content: 'public page' }).content === 'public page',
   'successful raw fetch preserves requested content');


console.log(`\nharvest smoke: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
