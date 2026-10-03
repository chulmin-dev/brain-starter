#!/usr/bin/env node
// harvest.mjs — bounded fetch/crawl facade over page-fetch.
import fs from 'fs';
import path from 'path';
import { fetchEngine } from './engines.mjs';
import { ladder } from './ladder.mjs';
import { crawl } from './crawl.mjs';
import { render as fmt, dedup } from './format.mjs';

const argv = process.argv.slice(2);
let cmd = argv[0];
const KNOWN = new Set(['auto', 'fetch', 'crawl', 'help']);
let url;
if (!cmd) { usage(); process.exit(2); }
if (KNOWN.has(cmd)) { url = positional(1); } else { url = cmd; cmd = 'auto'; }  // bare URL → auto

function positional(n) { const out = []; for (let i = 1; i < argv.length; i++) { if (argv[i].startsWith('--')) { if (argv[i+1] && !argv[i+1].startsWith('--')) i++; continue; } out.push(argv[i]); } return out[n - 1]; }
function flag(name) { const i = argv.indexOf(`--${name}`); if (i < 0) return undefined; const v = argv[i+1]; return (v && !v.startsWith('--')) ? v : true; }
function usage() {
  console.error('usage: harvest <url> | harvest <fetch|crawl|auto> <url> [opts]\n' +
    '  --format json|csv|md  --max-pages N  --mode auto|sitemap|rss|paginate  --fetch  --interactive  --out <file>');
}

function writeOut(content, outFlag) {
  if (!outFlag) { console.log(content); return; }
  const p = path.resolve(String(outFlag));
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content, 'utf8');
  console.error(`[harvest] wrote → ${p} (${Buffer.byteLength(content, 'utf8')} bytes)`);
}

async function main() {
  if (cmd === 'help') { usage(); return 0; }
  if (!url) { usage(); return 2; }
  const format = flag('format') || 'markdown';
  const out = flag('out');
  // --aggressive: pass through to page-fetch (expands curl grid ≤60 combos, max_attempts=60).
  // Default OFF — automated pipelines must never inherit this flag.
  const aggressive = !!flag('aggressive');

  if (cmd === 'fetch') {
    const r = await fetchEngine(url, { format, aggressive });
    writeOut(r.content || '', out);
    console.error(`[harvest] tier=fetch verdict=${r.verdict} bytes=${r.bytes} ok=${r.ok}`);
    return r.ok ? 0 : 1;
  }
  if (cmd === 'crawl') {
    const r = await crawl(url, { mode: flag('mode') || 'auto', maxPages: Number(flag('max-pages') || 20), fetch: !!flag('fetch'), format });
    const body = (format === 'json') ? JSON.stringify(r, null, 2) : fmt(r.records || [], format, { title: `crawl ${url}` });
    writeOut(body, out);
    console.error(`[harvest] tier=crawl status=${r.status} count=${r.count ?? 0} mode=${r.mode || ''}`);
    return r.status === 'ok' ? 0 : 1;
  }
  // auto — never dump huge raw content to stdout (protects context). Write to a run dir, print
  // envelope + path + a small preview. Caller reads the file as needed.
  const res = await ladder(url, { interactive: !!flag('interactive'), aggressive, log: (m) => console.error(m) });
  const envelope = { status: res.status, tier_used: res.tier_used, verdict: res.verdict, bytes: res.bytes, trail: res.trail, report: res.report };
  const content = res.content || '';
  let contentPath = out ? path.resolve(String(out)) : null;
  if (!contentPath && content) {
    let host = 'page'; try { host = new URL(url).hostname; } catch {}
    const run = path.join(process.cwd(), '.cache/brain/harvest', `${host || 'page'}-${Date.now()}`);
    fs.mkdirSync(run, { recursive: true });
    contentPath = path.join(run, 'content.html');
  }
  if (contentPath && content) { fs.mkdirSync(path.dirname(contentPath), { recursive: true }); fs.writeFileSync(contentPath, content, 'utf8'); }
  envelope.content_path = contentPath;
  envelope.preview = content ? content.replace(/\s+/g, ' ').slice(0, 300) : '';
  console.log(JSON.stringify(envelope, null, 2));
  // exit: 0 ok | 3 render unavailable | 4 suspect | 5 rate limited | 1 failure/budget.
  if (res.status === 'ok') return 0;
  if (res.status === 'render-unavailable') return 3;
  if (res.status === 'suspect') return 4;
  if (res.status === 'rate_limited') return 5;
  return 1;
}

main().then(c => process.exit(c)).catch(e => { console.error('harvest error:', e.stack || e); process.exit(1); });
