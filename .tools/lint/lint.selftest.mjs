#!/usr/bin/env node
// lint.selftest.mjs — status-enum/source-binding advisory selftest via MY_BRAIN_DIR fixture.
// lint.mjs 를 격리 fixture brain 에 대해 실행하고 경계별 warn 발화/비발화를 검증한다.
// 읽기전용: fixture 는 os.tmpdir() 하위에 생성 후 정리, 실 corpus 미접촉.
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const LINT = path.join(HERE, 'lint.mjs')
let pass = 0, fail = 0
const ok = (name, cond, info = '') => { if (cond) { pass++; console.log(`  ok   ${name}`) } else { fail++; console.error(`  FAIL ${name} ${info}`) } }

function mkdoc(fm, body = 'body\n') { return `---\n${fm}\n---\n${body}` }

// ---- build fixture brain ----
const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-selftest-'))
const W = path.join(ROOT, 'wiki'), R = path.join(ROOT, 'research')
for (const d of ['decisions', 'projects', 'insights', 'worklog']) fs.mkdirSync(path.join(W, d), { recursive: true })
fs.mkdirSync(path.join(R, '.archive'), { recursive: true })
fs.mkdirSync(path.join(R, 'live'), { recursive: true })

// wiki SCHEMA_DIRS cases
fs.writeFileSync(path.join(W, 'decisions/valid-live.md'), mkdoc('title: "a"\ntype: decision\nstatus: active\ncanonical_fields: [status]\nsummary: "s"'))
fs.writeFileSync(path.join(W, 'decisions/valid-terminal.md'), mkdoc('title: "a"\ntype: decision\nstatus: superseded\ncanonical_fields: [status]\nsummary: "s"'))
fs.writeFileSync(path.join(W, 'decisions/unknown.md'), mkdoc('title: "a"\ntype: decision\nstatus: bogus-value\ncanonical_fields: [status]\nsummary: "s"'))
fs.writeFileSync(path.join(W, 'decisions/mixedcase.md'), mkdoc('title: "a"\ntype: decision\nstatus: Active\ncanonical_fields: [status]\nsummary: "s"'))
fs.writeFileSync(path.join(W, 'decisions/freetext.md'), mkdoc('title: "a"\ntype: decision\nstatus: "**Phase 1.5 배포 완료** — 잔여 P1"\ncanonical_fields: [status]\nsummary: "s"'))
fs.writeFileSync(path.join(W, 'decisions/missing-status.md'), mkdoc('title: "a"\ntype: decision\ncanonical_fields: [status]\nsummary: "s"'))
// 타입별 subset (T1.5 P8): union 안이지만 해당 디렉토리 subset 밖 → subset warn / subset 안 → no warn
fs.writeFileSync(path.join(W, 'insights/subset-viol.md'), mkdoc('title: "a"\ntype: insight\nstatus: confirmed\ncanonical_fields: [status]\nsummary: "s"'))
fs.writeFileSync(path.join(W, 'insights/subset-ok.md'), mkdoc('title: "a"\ntype: insight\nstatus: active\ncanonical_fields: [status]\nsummary: "s"'))
fs.writeFileSync(path.join(W, 'projects/subset-viol.md'), mkdoc('title: "a"\ntype: project\nstatus: confirmed\ncanonical_fields: [status]\nsummary: "s"'))
// fenced status in BODY (not frontmatter) — must NOT warn
fs.writeFileSync(path.join(W, 'decisions/fenced.md'), mkdoc('title: "a"\ntype: decision\nstatus: active\ncanonical_fields: [status]\nsummary: "s"', '```yaml\nstatus: bogus-fenced\n```\n'))
// non-schema wiki dir (worklog) — must NOT warn even with bad status
fs.writeFileSync(path.join(W, 'worklog/note.md'), mkdoc('title: "a"\nstatus: whatever-nonschema\nsummary: "s"'))
// index files so drift checks resolve (not asserted here)
for (const f of ['index-entities', 'index-projects', 'index-insights', 'index-decisions', 'index-archive', 'index-ops', 'index-research']) fs.writeFileSync(path.join(W, `${f}.md`), '# idx\n')

// research cases
fs.writeFileSync(path.join(R, 'live/valid.md'), mkdoc('type: research\nkind: report\ndomain: brain\ntopic: x\nproject: [my-brain]\nstatus: closed\nsummary: "s"'))
fs.writeFileSync(path.join(R, 'live/bad.md'), mkdoc('type: research\nkind: report\ndomain: brain\ntopic: x\nproject: [my-brain]\nstatus: in-progress\nsummary: "s"'))
// .archive excluded
fs.writeFileSync(path.join(R, '.archive/old.md'), mkdoc('type: research\nkind: report\ndomain: brain\ntopic: x\nproject: [my-brain]\nstatus: done\nsummary: "s"'))
// name/description manifest snapshot exception (name && !type)
fs.writeFileSync(path.join(R, 'live/manifest.md'), mkdoc('name: some-skill\ndescription: "a tool"\nstatus: weird-manifest-status'))

// Source-binding is consistent across promoted insights and decisions.
const sourceCases = [
  ['insights/conventional-source', '[[research/live/valid]]', false],
  ['insights/missing-source', '', true],
  ['insights/nonlink-source', 'unbound evidence', true],
  ['decisions/conventional-source', '[[research/live/valid]]', false],
  ['decisions/nonlink-source', 'unbound evidence', true],
]
for (const [slug, source] of sourceCases) {
  const type = slug.startsWith('decisions/') ? 'decision' : 'insight'
  fs.writeFileSync(path.join(W, `${slug}.md`), mkdoc(`title: source fixture\ntype: ${type}\nstatus: active\ncanonical_fields: [source]\nsummary: source fixture\ndate: 2026-09-25\nsource: "${source}"`))
}

// ---- run lint ----
let warns = [], sourceWarns = []
try {
  const out = execFileSync('node', [LINT, '--json'], { env: { ...process.env, MY_BRAIN_DIR: ROOT, BRAIN_KPI_OFF: '1' }, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
  const warnings = JSON.parse(out).warnings
  warns = warnings.filter(w => w.cat === 'status-enum')
  sourceWarns = warnings.filter(w => w.cat === 'source-binding')
} catch (e) { console.error('lint run failed:', e.message); fail++ }

const has = slug => warns.some(w => w.msg.includes(slug))

console.log('== status-enum advisory (W-c) ==')
ok('valid live (active) no warn', !has('decisions/valid-live'))
ok('valid terminal (superseded) no warn', !has('decisions/valid-terminal'))
ok('unknown value warns', has('decisions/unknown'))
ok('mixed-case (Active) warns', has('decisions/mixedcase'))
ok('free-text prose warns', has('decisions/freetext'))
ok('missing status NOT status-enum (owned by frontmatter, no dup)', !has('decisions/missing-status'))
ok('fenced body status: NOT warned (only real frontmatter)', !has('decisions/fenced'))
ok('non-schema wiki dir (worklog) not warned', !has('worklog/note'))
ok('insights subset violation (confirmed, union 안) warns', has('insights/subset-viol'))
ok('insights subset valid (active) no warn', !has('insights/subset-ok'))
ok('projects subset violation (confirmed) warns', has('projects/subset-viol'))
ok('subset warn fp distinct (:status-subset)', warns.some(w => w.fp && w.fp.endsWith('insights/subset-viol:status-subset')))
ok('research valid (closed) no warn', !has('research/live/valid'))
ok('research non-standard (in-progress) warns', has('research/live/bad'))
ok('research .archive excluded', !has('.archive/old'))
ok('research name/description manifest exception', !has('live/manifest'))
ok('exactly 6 status-enum warns (unknown+mixedcase+freetext wiki + research bad + subset 2)', warns.length === 6, `got ${warns.length}: ${warns.map(w => w.msg.split(':')[0]).join(',')}`)

console.log('== source-binding advisory ==')
for (const [slug, , expected] of sourceCases) {
  ok(`${slug}: ${expected ? 'warn' : 'accepted syntax'}`, sourceWarns.some(w => w.msg.startsWith(`${slug}:`)) === expected)
}

// cleanup
fs.rmSync(ROOT, { recursive: true, force: true })
console.log(`\n=== lint advisory selftest: ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
