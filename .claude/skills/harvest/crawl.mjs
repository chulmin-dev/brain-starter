// crawl.mjs — multi-page crawl (absorbs scan.py's crawl/pagination/dedup). Delegates the actual
// fetching to page-fetch's `crawl` subcommand (sitemap/rss/paginate), then dedups + formats.
// No site-specific code, no Google/Sheets (output is structured data only).
import { spawn } from 'child_process';
import { PAGE_FETCH, PAGE_FETCH_PYTHON, PAGE_FETCH_PYTHON_ARGS } from './engines.mjs';
import { dedup } from './format.mjs';

function run(cmd, args, { cwd, timeoutMs = 180000 } = {}) {
  return new Promise((resolve) => {
    let out = '', err = '';
    const child = spawn(cmd, args, { cwd, env: { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' } });
    const timer = setTimeout(() => { try { child.kill('SIGTERM'); } catch {} resolve({ code: -1, out, err: err + '\n[timeout]' }); }, timeoutMs);
    child.stdout.on('data', d => out += d);
    child.stderr.on('data', d => err += d);
    child.on('close', code => { clearTimeout(timer); resolve({ code, out, err }); });
    child.on('error', e => { clearTimeout(timer); resolve({ code: -1, out, err: String(e.message || e) }); });
  });
}

// harvest crawl <url> --mode auto|sitemap|rss|paginate --max-pages N --fetch --format ...
// page-fetch crawl emits discovered URLs (and content with --fetch). We parse its --json output.
export async function crawl(url, { mode = 'auto', maxPages = 20, fetch = false, format = 'markdown', timeoutMs = 240000 } = {}) {
  const args = ['-m', 'plus', 'crawl', url, '--mode', mode, '--max-pages', String(maxPages), '--json'];
  if (fetch) { args.push('--fetch', '--format', format); }
  const res = await run(PAGE_FETCH_PYTHON, [...PAGE_FETCH_PYTHON_ARGS, ...args], { cwd: PAGE_FETCH, timeoutMs });
  let parsed = null;
  try { parsed = JSON.parse(res.out); } catch { /* fall through */ }

  if (!parsed) {
    return { status: res.code === 0 ? 'partial' : 'failed', records: [], mode,
             raw: res.out.slice(0, 2000), stderrTail: res.err.split('\n').filter(Boolean).slice(-3).join(' | ') };
  }
  return normalizeCrawl(parsed, mode);
}

// Pure, offline-testable. page-fetch crawl --json emits {mode, source_url, count, items:[{url,...}]}
// (verified 2026-06-14). Be tolerant of legacy/array shapes, normalize the url field, dedup, and —
// critically — NEVER report 'ok' when upstream found pages but we resolved zero (that was the
// silent-data-loss bug). 'partial' surfaces the mismatch instead of lying.
export function normalizeCrawl(parsed, mode = 'auto') {
  let records = Array.isArray(parsed)
    ? parsed
    : (parsed.items || parsed.pages || parsed.results || parsed.urls || []);
  if (!Array.isArray(records)) records = [];   // malformed {items:'x'|5} → empty, not a crash
  if (records.length && typeof records[0] === 'string') records = records.map(u => ({ url: u }));
  // drop null/non-object entries (corrupt/hand-crafted JSON) before formatters Object.keys() them
  records = records.filter(r => r && typeof r === 'object');
  // normalize the url field across shapes (url / loc / link)
  records = records.map(r => (r.url ? r : { ...r, url: r.loc || r.link || r.href || undefined }));
  records = dedup(records, 'url');
  const upstreamCount = (parsed && typeof parsed.count === 'number') ? parsed.count : null;
  const lost = upstreamCount != null && upstreamCount > 0 && records.length === 0;
  return {
    status: lost ? 'partial' : 'ok',
    count: records.length,
    upstream_count: upstreamCount,
    records,
    mode,
    ...(lost ? { warning: `upstream found ${upstreamCount} but harvest resolved 0 — JSON shape mismatch (check items key)` } : {}),
  };
}
