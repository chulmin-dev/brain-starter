// engines.mjs — subprocess wrapper around the sibling page-fetch engine.
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'node:module';

const SKILL_DIR = path.dirname(fileURLToPath(import.meta.url));
export const PAGE_FETCH = process.env.PAGE_FETCH_DIR || path.resolve(SKILL_DIR, '../page-fetch');
const { resolvePython } = createRequire(import.meta.url)(path.resolve(SKILL_DIR, '../page-fetch/python-runtime.cjs'));
const python = resolvePython(PAGE_FETCH);
export const PAGE_FETCH_PYTHON = python?.command || null;
export const PAGE_FETCH_PYTHON_ARGS = python?.args || [];

function run(cmd, args, { cwd, timeoutMs = 90000, input } = {}) {
  if (!cmd) return Promise.resolve({ code: -1, out: '', err: 'Python 3.10+ not found; install it and the page-fetch local-venv dependencies.', timedOut: false });
  return new Promise((resolve) => {
    let out = '', err = '', done = false;
    let child;
    try { child = spawn(cmd, args, { cwd, env: { ...process.env, INSANE_NO_AUTO_INSTALL: '1', INSANE_AGGRESSIVE: '0', PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' } }); }
    catch (e) { resolve({ code: -1, out: '', err: String(e.message || e), timedOut: false }); return; }
    const timer = setTimeout(() => { done = true; try { child.kill('SIGTERM'); } catch {} resolve({ code: -1, out, err: err + '\n[timeout]', timedOut: true }); }, timeoutMs);
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { err += d; });
    child.on('error', e => { if (done) return; done = true; clearTimeout(timer); resolve({ code: -1, out, err: String(e.message || e), timedOut: false }); });
    child.on('close', code => { if (done) return; done = true; clearTimeout(timer); resolve({ code, out, err, timedOut: false }); });
    if (input != null) { try { child.stdin.write(input); child.stdin.end(); } catch {} }
  });
}

// ---- page-fetch (Python) ---------------------------------------------------
// Returns { ok, verdict, content, bytes, raw, stopReason, gridExhausted, untriedRoutes, mustInvokeMcp }.
// page-fetch's --json envelope carries verdict + meta; without --json we get raw content.
// A7 failure-gate fields are parsed from the stderr ⛔ block on ok=False:
//   ⛔ NOT EXHAUSTED: stop_reason=budget grid_exhausted=False untried_routes=0 must_invoke_playwright_mcp=True
export async function fetchEngine(url, { format = 'markdown', device = 'auto', timeoutMs = 90000, aggressive = false } = {}) {
  // First: content in the requested format.
  // aggressive=true passes --aggressive to page-fetch: expands curl grid to ≤60 combos,
  // raises max_attempts to 60, ensures playwright fallback. Default OFF — never inherit by accident.
  const fetchArgs = ['-m', 'plus', 'fetch', url, '--format', format, '--device', device];
  if (aggressive) fetchArgs.push('--aggressive');
  const contentRes = await run(PAGE_FETCH_PYTHON, [...PAGE_FETCH_PYTHON_ARGS, ...fetchArgs],
    { cwd: PAGE_FETCH, timeoutMs });
  // Second: a JSON envelope for the verdict (cheap; page-fetch prints verdict to stderr too).
  const verdict = parseVerdict(contentRes.err) || (contentRes.code === 0 ? 'weak_ok' : 'fail');
  const content = contentRes.out || '';
  const a7 = parseA7Fields(contentRes.err);
  return {
    engine: 'page-fetch',
    ok: contentRes.code === 0 && content.trim().length > 0,
    verdict,
    content,
    bytes: Buffer.byteLength(content, 'utf8'),
    code: contentRes.code,
    timedOut: contentRes.timedOut,
    stderrTail: contentRes.err.split('\n').filter(Boolean).slice(-3).join(' | '),
    // A7 failure-gate fields (null/false when absent — success path).
    stopReason: a7.stopReason,
    gridExhausted: a7.gridExhausted,
    untriedRoutes: a7.untriedRoutes,
    mustInvokeMcp: a7.mustInvokeMcp,
  };
}

// page-fetch prints e.g. "[plus] ok=True verdict=weak_ok profile=None ..." to stderr.
function parseVerdict(stderr) {
  if (!stderr) return null;
  const m = stderr.match(/verdict=([a-z_]+)/i);
  return m ? m[1].toLowerCase() : null;
}

// Parse A7 failure-gate fields from the page-fetch ⛔ stderr block.
// Block format: "⛔ NOT EXHAUSTED: stop_reason=budget grid_exhausted=False untried_routes=0 must_invoke_playwright_mcp=True"
// Returns null defaults when the block is absent (success path).
function parseA7Fields(stderr) {
  if (!stderr) return { stopReason: null, gridExhausted: false, untriedRoutes: 0, mustInvokeMcp: false };
  // \b anchors prevent substring matches like "x_stop_reason=" firing on these tokens.
  const srM = stderr.match(/\bstop_reason=([a-z_]+)/i);
  const geM = stderr.match(/\bgrid_exhausted=(True|False)/i);
  const urM = stderr.match(/\buntried_routes=(\d+)/);
  const mcpM = stderr.match(/\bmust_invoke_playwright_mcp=(True|False)/i);
  return {
    stopReason: srM ? srM[1].toLowerCase() : null,
    gridExhausted: geM ? geM[1] === 'True' : false,
    untriedRoutes: urM ? parseInt(urM[1], 10) : 0,
    mustInvokeMcp: mcpM ? mcpM[1] === 'True' : false,
  };
}

