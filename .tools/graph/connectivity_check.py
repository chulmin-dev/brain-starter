#!/usr/bin/env python3
"""brain research↔knowledge connectivity checker (detector only — never edits notes).

Canonical metric: Obsidian body-wikilink graph, ROUTER-EXCLUDED BFS reachability to a
wiki knowledge page. A research note is a SATELLITE (ERROR) if it has no router-excluded
path to knowledge — it only hangs off the catalog hub / other research. This is the
invariant the prevention system enforces. Frontmatter links are NOT counted (Obsidian
doesn't render them as graph edges).

RESOLVER OWNERSHIP (RALPLAN §144/§148): this checker no longer carries its own LINK regex,
fuzzy basename resolver or LEAD_RE. The resolved edge/dangling graph AND the representative
candidate IDs come from `link-audit.mjs --json` (which consumes link-core.mjs, the single
SSOT resolver). This module OWNS the BFS reachability metric, the standalone exemption, the
first-seen report/state UX and the SessionStart fast path.

Modes:
  (default)  full scan via link-audit -> stdout report/state summary (NO writes).
  --suggest  full scan -> dry-run connection proposal per satellite. NEVER applies.
  --session  FAST: read cached state json only (no scan). Surface satellites/heartbeat at
             SessionStart. Silent when clean. Always exit 0 (never block a session).

Writes are OPT-IN and transactional. `--write-report/--write-state/--write-log <path>`
(with `--recovery-dir`) commit all three targets as ONE reverse-bundled transaction
(sibling temp + fsync + rename; any single-target failure restores every target). Default
runs (no write flags) touch nothing and do not even create a recovery namespace.

Exit (report/suggest): satellites>0 -> 2, warns(dist>=3)>0 -> 1, clean -> 0. Audit failure -> 3.
stdlib only. Fixing stays semi-auto: reviewed link edits + human/agent review.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path
from collections import defaultdict, deque

TOOLDIR = Path(__file__).resolve().parent
DEFAULT_VAULT = Path(os.environ.get("MY_BRAIN_DIR") or os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2])
DEFAULT_REPORT = TOOLDIR / 'connectivity-report.md'
DEFAULT_STATE = TOOLDIR / 'connectivity-state.json'
DEFAULT_LOG = TOOLDIR / '.daily-last.log'

# Bare 2-base slug space (link-audit / link-core mirror corpus.mjs: wiki notes are `decisions/foo`,
# NOT `wiki/decisions/foo`). Routers/log pages are already excluded from the audit corpus, so the
# router-exclusion below is a defensive invariant more than an active filter.
KNOWLEDGE_DIRS = ('decisions/', 'insights/', 'projects/', 'people/',
                  'companies/', 'deals/', 'legal/', 'resources/')
ROUTERS = {
    'index', 'index-projects', 'index-decisions', 'index-insights',
    'index-entities', 'index-ops', 'index-research', 'log',
    'changelog', 'documents-events',
}
TODAY = date.today().isoformat()

is_knowledge = lambda n: any(n.startswith(d) for d in KNOWLEDGE_DIRS) and n.lower() not in ROUTERS
is_router = lambda n: n.lower() in ROUTERS


class AuditError(Exception):
    pass


class _InjectedFault(Exception):
    pass


def _sha256(b):
    return hashlib.sha256(b).hexdigest()


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------- argv ----------
def parse_args(argv):
    a = {
        'session': False, 'suggest': False,
        'vault': None, 'node': None, 'audit': None,
        'write_report': None, 'write_state': None, 'write_log': None,
        'recovery_dir': None, 'state': None,
    }
    i = 0
    while i < len(argv):
        t = argv[i]
        if t == '--session':
            a['session'] = True
        elif t == '--suggest':
            a['suggest'] = True
        elif t == '--report':
            pass  # default full scan; kept for backwards-compatible invocation
        elif t in ('--vault', '--node', '--audit', '--state',
                   '--write-report', '--write-state', '--write-log', '--recovery-dir'):
            key = t[2:].replace('-', '_')
            i += 1
            a[key] = argv[i] if i < len(argv) else None
        i += 1
    return a


def load_state(state_path):
    p = Path(state_path)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}


def days_since(iso):
    try:
        y, m, d = map(int, iso.split('-'))
        return (date.today() - date(y, m, d)).days
    except Exception:
        return None


# ---------- FAST PATH: session surfacing reads cached state, no scan ----------
def session_surface(state_path):
    st = load_state(state_path)
    sats = st.get('satellites', {})
    out = []
    if sats:
        out.append(f'[brain-connectivity] 🔴 미연결 research(위성) {len(sats)}건 — 이 세션에 지식 페이지로 본문 `## 관련` 연결 또는 명시 defer:')
        for n, seen in list(sats.items())[:8]:
            stale = '  ⚠️STALE' if seen != TODAY else ''
            out.append(f'  - {n} (최초감지 {seen}){stale}')
        if len(sats) > 8:
            out.append(f'  ... 외 {len(sats) - 8}건')
        out.append('  후보: vault에서 `node .claude/skills/page-fetch/python-runtime.cjs .tools/graph/connectivity_check.py --suggest` → reviewed link edits(반자동)')
    if st.get('standalone_count', 0) > 5:
        out.append(f"[brain-connectivity] ⚪ standalone {st['standalone_count']}건 — 연결 회피 남용 점검.")
    lr = st.get('last_run')
    if lr:
        g = days_since(lr)
        if g is not None and g >= 2:
            out.append(f'[brain-connectivity] ⏰ 연결 상태 마지막 갱신 {g}일 전 — 필요하면 connectivity_check.py로 다시 점검하세요(상태 stale 가능).')
    if out:
        print('\n'.join(out))
    sys.exit(0)


# ---------- link-audit subprocess (single resolver SSOT) ----------
def resolve_node(args):
    n = args['node'] or os.environ.get('BRAIN_NODE')
    if n and os.path.isfile(n) and os.access(n, os.X_OK):
        return n
    w = shutil.which('node')
    if w:
        return w
    return n or 'node'


LINKCORE = str(TOOLDIR / 'link-core.mjs')


def _validate_audit(data):
    schema = data.get('schema')
    if not isinstance(schema, int) or schema < 1:
        raise AuditError(f'unexpected schema: {schema!r}')
    # `bodyEdges` (frontmatter-stripped Obsidian graph) is REQUIRED — connectivity BFS uses it, not the
    # full-content `edges`. Refuse rather than silently BFS over frontmatter feeds.
    for k in ('nodes', 'bodyEdges'):
        if not isinstance(data.get(k), list):
            raise AuditError(f'missing/invalid `{k}`')
    for n in data['nodes']:
        if not isinstance(n, dict) or 'slug' not in n or 'source' not in n:
            raise AuditError('node record missing slug/source')
    for e in data['bodyEdges']:
        if not isinstance(e, dict) or 'source' not in e or 'target' not in e:
            raise AuditError('bodyEdges record missing source/target')
    return data


def _run_node(node, args, label):
    if not (os.path.isfile(node) and os.access(node, os.X_OK)):
        raise AuditError(f'node executable not runnable: {node}')
    try:
        proc = subprocess.run([node] + args, capture_output=True, text=True, encoding='utf-8', timeout=120)
    except Exception as e:
        raise AuditError(f'{label} spawn failed: {e}')
    if proc.returncode != 0:
        raise AuditError(f'{label} exit {proc.returncode}: {proc.stderr.strip()[:300]}')
    try:
        return json.loads(proc.stdout)
    except Exception as e:
        raise AuditError(f'{label} JSON parse failed: {e}')


def run_audit(node, audit, vault):
    if not os.path.isfile(audit):
        raise AuditError(f'link-audit not found: {audit}')
    return _validate_audit(_run_node(node, [audit, '--json', '--vault', str(vault)], 'link-audit'))


# link-core-direct provider (RALPLAN ② allows "link-audit 또는 link-core 기반 CLI"): an ephemeral node
# program that consumes link-core.mjs (the SSOT link-audit itself wraps) and emits the same shape,
# including bodyEdges = resolveLinks over frontmatter-stripped content. Used when a landed link-audit
# does not yet expose bodyEdges. `edges` (full content) is emitted too for parity with link-audit.
_LINKCORE_PROG = r'''
import(%s).then(m => {
  const vault = process.argv[1]
  const notes = m.collectNotes(vault)
  const full = m.resolveLinks(notes)
  const getBody = c => { if (c == null) return null; c = c.replace(/\r\n/g, '\n'); const x = c.match(/^---\n[\s\S]*?\n---\n?([\s\S]*)$/); return x ? x[1] : c }
  const body = m.resolveLinks(notes.map(n => ({ ...n, content: getBody(n.content) })))
  const proj = v => { if (v == null) return null; let s = Array.isArray(v) ? String(v[0] ?? '') : String(v); s = s.replace(/[\[\]"']/g, '').split(',')[0].trim(); return s || null }
  const nodes = notes.map(n => { const db = m.dualBinding(n); return { slug: n.slug, source: n.source, readable: n.readable, standalone: !!db.standalone, standaloneReason: db.standaloneReason ?? null, project: n.source === 'research' ? proj(n.fm && n.fm.project) : null } })
  const representatives = notes.filter(m.representativePredicate).map(n => n.slug)
  process.stdout.write(JSON.stringify({ schema: 1, nodes, edges: full.edges, bodyEdges: body.edges, dangling: full.dangling, ambiguous: full.ambiguous, unreadable: full.unreadable, representatives }))
}).catch(e => { console.error(String(e && e.stack || e)); process.exit(1) })
'''


def run_linkcore_direct(node, vault):
    prog = _LINKCORE_PROG % json.dumps(Path(LINKCORE).resolve().as_uri())
    return _validate_audit(_run_node(node, ['-e', prog, str(vault)], 'link-core'))


def get_audit_data(node, args, vault):
    """Prefer an explicitly-configured link-audit (strict: refuse if it fails/lacks bodyEdges — the
    timer's 'subprocess must succeed' contract). With no explicit config, prefer a landed link-audit
    that exposes bodyEdges, else consume link-core directly (same SSOT)."""
    explicit = args['audit'] or os.environ.get('BRAIN_LINK_AUDIT')
    if explicit:
        return run_audit(node, explicit, vault)
    default_audit = str(TOOLDIR / 'link-audit.mjs')
    if os.path.isfile(default_audit):
        try:
            return run_audit(node, default_audit, vault)
        except AuditError as e:
            # landed link-audit lacks bodyEdges / fails validation → fall back to link-core direct.
            print(f'[connectivity] link-audit unusable ({e}) — falling back to link-core-direct',
                  file=sys.stderr)
    return run_linkcore_direct(node, vault)


# ---------- FULL SCAN: consume audit, own BFS/report-state ----------
def scan(data):
    nodes = data['nodes']
    slugs = [n['slug'] for n in nodes]
    research = sorted(n['slug'] for n in nodes if n.get('source') == 'research')
    standalone = {n['slug']: (n.get('standaloneReason') or '(사유 미기재)')
                  for n in nodes if n.get('standalone')}
    proj = {n['slug']: (n.get('project') or '') for n in nodes if n.get('source') == 'research'}
    # representativeNotes = flat predicate-satisfier list (link-audit); 'representatives' is the
    # flat list in the link-core-direct fallback but a clusterKey→[slug] MAP in link-audit — prefer flat.
    reps = set(data.get('representativeNotes') or data.get('representatives') or [])

    # BFS adjacency uses BODY edges only (frontmatter feeds/related do NOT render in Obsidian's graph;
    # link-audit `bodyEdges` = resolveLinks over frontmatter-stripped content — the invariant this
    # detector enforces). `edges` (full content) is the graph-cache set and is intentionally NOT used here.
    adj = defaultdict(set)
    for e in data['bodyEdges']:
        s, t = e['source'], e['target']
        if s == t:
            continue
        adj[s].add(t)
        adj[t].add(s)

    dist = {n: 0 for n in slugs if is_knowledge(n)}
    q = deque(dist)
    while q:
        x = q.popleft()
        if is_router(x):
            continue
        for y in adj[x]:
            if y not in dist:
                dist[y] = dist[x] + 1
                q.append(y)

    sats = [n for n in research if dist.get(n) is None and n not in standalone]
    warns = [n for n in research if dist.get(n) is not None and dist[n] >= 3 and n not in standalone]
    return dict(notes=slugs, research=research, sats=sats, warns=warns, standalone=standalone,
                dist=dist, adj=adj, proj=proj, reps=reps)


def summary_text(s, report_ref):
    L = [f"research {len(s['research'])} | 🔴위성 {len(s['sats'])} | 🟡dist≥3 {len(s['warns'])} | ⚪standalone {len(s['standalone'])}"]
    if len(s['standalone']) > 5:
        L.append(f"  ⚠️ standalone {len(s['standalone'])}건 — 남용 점검(연결 회피로 standalone 남발?)")
    for n in s['sats']:
        L.append(f'  🔴 {n}')
    for n in s['warns']:
        L.append(f"  🟡 {n} (dist {s['dist'][n]})")
    L.append(f'리포트: {report_ref}')
    return '\n'.join(L) + '\n'


def report_text(s, cur):
    L = ['# brain 연결성 리포트 (자동생성 — 수동편집 금지)', '',
         f'- last_run: {TODAY}',
         f"- research 총: {len(s['research'])}  |  🔴 위성(ERROR): {len(s['sats'])}  |  🟡 dist≥3(WARN): {len(s['warns'])}  |  ⚪ standalone 면제: {len(s['standalone'])}",
         '']
    if s['sats']:
        L.append('## 🔴 위성 — 지식 페이지 경로 없음 (연결 필요)')
        for n in s['sats']:
            seen = cur[n]
            L.append(f'- `{n}`  (최초감지 {seen})' + ('  ⚠️STALE' if seen != TODAY else ''))
        L.append('')
    if s['warns']:
        L.append('## 🟡 dist≥3 — 대표편이 지식과 멀다')
        for n in s['warns']:
            L.append(f"- `{n}`  (dist {s['dist'][n]})")
        L.append('')
    if s['standalone']:
        L.append(f"## ⚪ standalone 면제 ({len(s['standalone'])})")
        for n, r in sorted(s['standalone'].items()):
            L.append(f'- `{n}` — {r}')
        L.append('')
    return '\n'.join(L) + '\n'


def state_text(s, cur):
    return json.dumps(
        {'last_run': TODAY, 'satellites': cur, 'standalone_count': len(s['standalone']),
         'warn_count': len(s['warns'])}, ensure_ascii=False, indent=2)


def suggest(s):
    if not s['sats']:
        print('  위성 없음 — 제안할 것 없음.')
        return
    reps = s['reps']  # shared representative candidate IDs (link-core predicate), no local LEAD_RE
    for n in s['sats']:
        cl = '/'.join(n.split('/')[:2]) + '/'
        sibs = [m for m in s['research'] if m.startswith(cl) and m != n]
        a_leads = [m for m in sibs if any(is_knowledge(t) for t in s['adj'][m])]
        lead = None
        if a_leads:
            lead = max(a_leads, key=lambda c: (c in reps, -len(c)))
        elif sibs:
            named = [m for m in sibs if m in reps]
            lead = (named or sibs)[0]
        p = s['proj'].get(n, '')
        kn = []
        if p:
            key = p.lower().replace('-skill', '').split()[0] if p.split() else ''
            kn = [w for w in s['notes'] if is_knowledge(w) and key and key in w.lower()][:3]
        print(f'\n🔴 {n}\n     project={p or "-"}')
        print(f'     → 지식 후보: {", ".join(k.split("/")[-1] for k in kn)}' if kn
              else '     → 지식 후보 없음 (수동 판단 또는 graph: standalone)')
        if lead and lead != n:
            print(f'     → 대표편 경유: {lead.split("/")[-1]}')
    print('\n(제안만 — apply 안 함. 연결은 reviewed link edits + 사람/에이전트 승인)')


# ---------- transactional multi-target writer (RALPLAN §227/§235-246) ----------
def _syncdir(d):
    try:
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _atomic_write(target, data, mode):
    d = os.path.dirname(os.path.abspath(target)) or '.'
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(target) + '.tmp-', dir=d)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode if mode is not None else 0o644)
        os.replace(tmp, target)
        _syncdir(d)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _rollback(applied, ns):
    """Restore every already-committed target. A target is only restored when its current bytes
    still hash to OUR postimage (else a concurrent editor touched it -> recovery-required, never
    clobber their change)."""
    status = 'reverted'
    for t, rec in applied:
        p = t['path']
        try:
            with open(p, 'rb') as f:
                curh = _sha256(f.read())
        except FileNotFoundError:
            curh = None
        if curh != rec['post_sha256']:
            rec['current_sha256'] = curh
            status = 'recovery-required'
            continue
        if rec['existed'] and rec['pre_sha256'] is not None:
            with open(os.path.join(ns, 'preimage.' + t['name']), 'rb') as f:
                pre = f.read()
            _atomic_write(p, pre, rec['pre_mode'])
            rec['current_sha256'] = _sha256(pre)
        elif not rec['existed']:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
            rec['current_sha256'] = None
        else:
            rec['current_sha256'] = curh
            status = 'recovery-required'
    return status


def transaction_write(targets, recovery_base, run_id, command, semantic_counts, fault_target=None,
                      prehash_fault_target=None, rollback_tamper=None):
    """targets: list of {name, path, text}. Reverse bundle is written BEFORE any target is opened."""
    started = _now()
    ns = os.path.join(recovery_base, run_id)
    os.makedirs(ns, mode=0o700, exist_ok=True)
    os.chmod(ns, 0o700)

    recs = []
    for t in targets:
        p = t['path']
        data = t['text'].encode('utf-8')
        existed = os.path.lexists(p)
        is_link = existed and os.path.islink(p)
        pre_symlink = os.readlink(p) if is_link else None
        pre_hash = pre_mode = None
        if existed and not is_link:
            with open(p, 'rb') as f:
                pre = f.read()
            pre_hash = _sha256(pre)
            pre_mode = stat.S_IMODE(os.lstat(p).st_mode)
            _atomic_write(os.path.join(ns, 'preimage.' + t['name']), pre, 0o600)
        recs.append({
            'name': t['name'], 'path': p, 'existed': existed,
            'pre_sha256': pre_hash, 'pre_mode': pre_mode, 'pre_symlink': pre_symlink,
            'post_sha256': _sha256(data), 'post_mode': pre_mode, 'current_sha256': None,
        })

    bundle = {'run_id': run_id, 'targets': [{k: r[k] for k in
              ('name', 'path', 'existed', 'pre_sha256', 'pre_mode', 'pre_symlink')} for r in recs]}
    bundle_text = json.dumps(bundle, ensure_ascii=False, indent=2) + '\n'
    _atomic_write(os.path.join(ns, 'bundle.json'), bundle_text.encode('utf-8'), 0o600)
    bundle_sha = _sha256(bundle_text.encode('utf-8'))
    _syncdir(ns)

    # pre-hash guard (RALPLAN §248c): the bundle recorded each target's preimage state (existence +
    # bytes hash + symlink) at capture time. Re-compare RIGHT BEFORE the first rename; if any target
    # drifted since capture a concurrent editor touched it → abort the WHOLE transaction, replace
    # NOTHING, and emit an aborted receipt (never clobber the external change).
    if prehash_fault_target:  # selftest seam: simulate a concurrent edit landing after capture
        for t in targets:
            if t['name'] == prehash_fault_target:
                with open(t['path'], 'wb') as f:
                    f.write(b'<<external concurrent edit before rename>>\n')
    drift = None
    for rec in recs:
        p = rec['path']
        if not os.path.lexists(p):
            live_existed, live_hash, live_symlink = False, None, None
        elif os.path.islink(p):
            live_existed, live_hash, live_symlink = True, None, os.readlink(p)
        else:
            with open(p, 'rb') as f:
                live_hash = _sha256(f.read())
            live_existed, live_symlink = True, None
        if (live_existed != rec['existed'] or live_hash != rec['pre_sha256']
                or live_symlink != rec['pre_symlink']):
            rec['current_sha256'] = live_hash
            drift = rec['name']
            break

    applied = []
    status = 'applied'
    trigger = None
    if drift is not None:
        status = 'aborted'
        trigger = f'pre-hash-mismatch: {drift}'
    else:
        try:
            for t, rec in zip(targets, recs):
                _atomic_write(t['path'], t['text'].encode('utf-8'), rec['pre_mode'])
                applied.append((t, rec))
                if fault_target == t['name']:
                    raise _InjectedFault(t['name'])
        except Exception as e:
            trigger = 'injected-fault' if isinstance(e, _InjectedFault) else f'write-failure: {e}'
            if rollback_tamper:  # selftest seam: a concurrent editor overwrites an already-applied
                # target between our write and the rollback read → rollback must refuse to clobber.
                for t, rec in applied:
                    if t['name'] == rollback_tamper:
                        with open(t['path'], 'wb') as f:
                            f.write(b'<<external concurrent edit during rollback>>\n')
            status = _rollback(applied, ns)

    if status == 'applied':
        for t, rec in zip(targets, recs):
            try:
                with open(t['path'], 'rb') as f:
                    rec['current_sha256'] = _sha256(f.read())
            except OSError:
                rec['current_sha256'] = None

    receipt = {
        'run_id': run_id, 'writer': 'connectivity', 'owner': 'connectivity_check.py --write-*',
        'command': command, 'tool_fingerprint': _sha256(Path(__file__).read_bytes()),
        'input_manifest_fingerprint': _sha256(b''.join(r['post_sha256'].encode() for r in recs)),
        'recovery_namespace': recovery_base, 'bundle_path': os.path.join(ns, 'bundle.json'),
        'bundle_sha256': bundle_sha, 'targets': recs,
        'status': status, 'rollback_trigger': trigger,
        'started_at': started, 'completed_at': _now(),
        'semantic_counts': semantic_counts,
    }
    _atomic_write(os.path.join(ns, 'receipt.json'),
                  (json.dumps(receipt, ensure_ascii=False, indent=2) + '\n').encode('utf-8'), 0o600)
    return receipt


# ---------- main ----------
def main():
    args = parse_args(sys.argv[1:])
    state_path = args['state'] or str(DEFAULT_STATE)

    if args['session']:
        session_surface(state_path)
        return

    node = resolve_node(args)
    vault = Path(args['vault']).resolve() if args['vault'] else DEFAULT_VAULT

    write_mode = bool(args['write_report'] or args['write_state'] or args['write_log'])

    try:
        data = get_audit_data(node, args, vault)
    except AuditError as e:
        # Never partially write: a resolver failure aborts before any target/namespace is touched.
        print(f'[connectivity] resolver 실패 — 쓰기 0 (state 보존): {e}', file=sys.stderr)
        sys.exit(3)

    s = scan(data)
    code = 2 if s['sats'] else (1 if s['warns'] else 0)

    if args['suggest']:
        print(summary_text(s, 'stdout (—suggest, no write)'), end='')
        suggest(s)
        sys.exit(code)

    if not write_mode:
        # default check: stdout only, zero writes.
        print(summary_text(s, 'stdout only (--write-report/--write-state/--write-log 로 파일 생성)'), end='')
        sys.exit(code)

    # transactional write path
    if not args['recovery_dir']:
        print('[connectivity] --write-* 사용 시 --recovery-dir 필수 (쓰기 0)', file=sys.stderr)
        sys.exit(4)
    wr = args['write_report'] or str(DEFAULT_REPORT)
    ws = args['write_state'] or str(DEFAULT_STATE)
    wl = args['write_log'] or str(DEFAULT_LOG)

    prev = load_state(ws).get('satellites', {})
    cur = {n: prev.get(n, TODAY) for n in s['sats']}
    rep = report_text(s, cur)
    stt = state_text(s, cur)
    log = summary_text(s, wr)

    import uuid
    run_id = os.environ.get('_CONNECTIVITY_RUN_ID') or str(uuid.uuid4())
    fault = os.environ.get('_CONNECTIVITY_FAULT') or None
    prehash_fault = os.environ.get('_CONNECTIVITY_PREHASH_FAULT') or None
    rollback_tamper = os.environ.get('_CONNECTIVITY_ROLLBACK_TAMPER') or None
    command = ('connectivity_check.py --write-report %s --write-state %s --write-log %s '
               '--recovery-dir %s --node %s' % (wr, ws, wl, args['recovery_dir'], node))
    receipt = transaction_write(
        [{'name': 'report', 'path': wr, 'text': rep},
         {'name': 'state', 'path': ws, 'text': stt},
         {'name': 'log', 'path': wl, 'text': log}],
        args['recovery_dir'], run_id, command,
        {'satellites': len(s['sats']), 'warns': len(s['warns']), 'standalone': len(s['standalone'])},
        fault_target=fault, prehash_fault_target=prehash_fault, rollback_tamper=rollback_tamper,
    )
    print(summary_text(s, wr), end='')
    print(f"[connectivity] writer status={receipt['status']} run_id={run_id}", file=sys.stderr)
    if receipt['status'] != 'applied':
        sys.exit(5)
    sys.exit(code)


if __name__ == '__main__':
    main()
