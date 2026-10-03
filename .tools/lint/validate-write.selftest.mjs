#!/usr/bin/env node
// Standalone behavior tests for the write-time validator and Claude hook bridge.
// All notes and hook fixtures live in a disposable temp vault.
//
// exit 1 on any failure.
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { validateFile, classifyTarget } from './validate-write.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const NODE = process.execPath
const VALIDATOR = path.join(HERE, 'validate-write.mjs')
const HOOK = path.resolve(HERE, '../../.hooks/validate-write.py')
const PYTHON_RUNTIME = path.resolve(HERE, '../../.hooks/python-runtime.cjs')

let pass = 0, fail = 0
const check = (name, cond, detail = '') => {
  if (cond) { pass++; console.log(`  PASS ${name}`) }
  else { fail++; console.log(`  FAIL ${name}${detail ? ' — ' + detail : ''}`) }
}

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'validate-write-selftest-'))
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }) } catch {} })

// ---------------------------------------------------------------- temp vault ----
const VAULT = path.join(TMP, 'vault')
const AX = { type: 'research', kind: 'report', domain: 'testing', topic: 'fixtures', project: 'selftest', status: 'active', summary: 'fixture summary' }
function note({ axes = AX, extraFm = [], body = '' } = {}) {
  const fmLines = Object.entries(axes).map(([k, v]) => `${k}: ${v}`).concat(extraFm)
  return `---\n${fmLines.join('\n')}\n---\n\n${body}\n`
}
function w(rel, content) {
  const p = path.join(VAULT, rel)
  fs.mkdirSync(path.dirname(p), { recursive: true })
  fs.writeFileSync(p, content)
  return p
}

// wiki knowledge target + wiki basic-check fixtures
w('wiki/decisions/some-decision.md', note({ axes: { type: 'decision', status: 'active' }, body: '# Some Decision\n\nknowledge page' }))
w('wiki/insights/some-insight.md', note({ axes: { type: 'insight' }, body: '# Insight\n\nok' }))
w('wiki/insights/nofm.md', '# No Frontmatter Wiki\n\nbody without frontmatter\n')
w('wiki/log.md', '# router log — excluded from corpus\n')

// research: root singletons
const KNOW = 'ties into [[decisions/some-decision]]'
w('research/root-summary.md', note({ body: `# 종합\n\n${KNOW}` }))            // rep + knowledge → silent
w('research/rep-noknow-report.md', note({ body: '# Report\n\nno knowledge link here' })) // rep no knowledge → warn
w('research/root-plain.md', note({ axes: AX, body: '# plain root note\n\nbody' }))        // noncandidate → cluster-no-representative
w('research/nofm/no-frontmatter.md', '# Missing Frontmatter\n\nbody, no --- block\n')      // no-frontmatter short-circuit

// research: axis-missing (standalone to silence the cluster warning, isolating axis warnings)
w('research/axistest/partial.md', note({
  axes: { type: 'research', kind: 'analysis', project: 'selftest', status: 'active', summary: 'partial axes' }, // missing domain, topic
  extraFm: ['graph: standalone', 'standalone_reason: fixture for axis check'],
  body: '# partial\n\nbody',
}))

// research: topicX topdir cluster (one representative)
w('research/topicX/topicX-report.md', note({ body: `# Report\n\n${KNOW}` }))               // representative → silent
w('research/topicX/topicX-child.md', note({ body: '# child\n\nunbound child' }))            // subordinate unbound → missing-representative-link
w('research/topicX/topicX-boundchild.md', note({ body: '# child\n\n## 관련\n- [[topicX-report]]' })) // bound → silent
w('research/topicX/nested/deep-child.md', note({ body: '# nested child\n\nbinds up: [[topicX-report]]' })) // nested → root rep → silent

// research: multi cluster (two representatives)
w('research/multi/multi-report.md', note({ body: `# Report\n\n${KNOW}` }))
w('research/multi/multi-summary.md', note({ body: `# Summary\n\n${KNOW}` }))
w('research/multi/multi-child-zero.md', note({ body: '# child\n\nlinks neither candidate' }))       // → cluster-representative-ambiguous
w('research/multi/multi-child-one.md', note({ body: '# child\n\npicks one: [[multi-report]]' }))     // exactly one → silent

// research: standalone-exempt subordinate (topdir cluster, no candidate)
w('research/lonely/solo-note.md', note({
  axes: { type: 'research', kind: 'work-log', domain: 'testing', topic: 'fixtures', project: 'selftest', status: 'active', summary: 'lonely' },
  extraFm: ['graph: standalone', 'standalone_reason: no wiki home for this fixture'],
  body: '# solo\n\nno representative and no wiki home',
}))

// non-target fixtures
w('.tools/lint/inside-excluded.md', note({ body: '# excluded dir' }))
w('insights/misplaced-note.md', note({ body: '# misplaced\n\nknowledge note written at the vault root' })) // (g) → misplaced-note
w('ROOT-README.md', '# root readme — not a knowledge dir, stays skipped\n')
fs.writeFileSync(path.join(VAULT, 'research', 'note.txt'), 'not markdown\n')

// Symlinked view of the vault (production layout: ~/example-vault → /mnt/c/...). The physical-path
// scope tests below write via the PHYSICAL location while the validator/hook see the symlink as the vault
// root, proving a physical file_path is classified in-scope instead of being silently skipped.
const LINK_VAULT = path.join(TMP, 'vault-symlink')
try { fs.rmSync(LINK_VAULT) } catch {}
if (process.platform !== 'win32') fs.symlinkSync(VAULT, LINK_VAULT)
else console.log('  SKIP symlink scope assertions on win32 (POSIX-only)')

const codes = rel => validateFile(path.join(VAULT, rel), { vault: VAULT }).warnings.map(x => x.code).sort()
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b)

console.log('== validator ==')

// 1. frontmatter 없음 — single warning + short-circuit (no axis warnings leak through)
check('no-frontmatter → single warning, short-circuit', eq(codes('research/nofm/no-frontmatter.md'), ['no-frontmatter']),
  JSON.stringify(codes('research/nofm/no-frontmatter.md')))

// 2. axis 누락 (isolated via standalone)
check('7-axis miss → axis-missing:domain + axis-missing:topic only', eq(codes('research/axistest/partial.md'), ['axis-missing:domain', 'axis-missing:topic']),
  JSON.stringify(codes('research/axistest/partial.md')))

// 3. 대표편 → wiki 지식 본문링크 부재
check('representative missing knowledge link', eq(codes('research/rep-noknow-report.md'), ['representative-missing-knowledge-link']),
  JSON.stringify(codes('research/rep-noknow-report.md')))

// 4. 하위 → 대표편 결박 결손
check('subordinate missing representative link', eq(codes('research/topicX/topicX-child.md'), ['missing-representative-link']),
  JSON.stringify(codes('research/topicX/topicX-child.md')))

// 5. root / nested / multi cluster
check('root singleton noncandidate → cluster-no-representative', eq(codes('research/root-plain.md'), ['cluster-no-representative']),
  JSON.stringify(codes('research/root-plain.md')))
check('nested child → root representative binding → silent', eq(codes('research/topicX/nested/deep-child.md'), []),
  JSON.stringify(codes('research/topicX/nested/deep-child.md')))
check('multi cluster: subordinate links neither → cluster-representative-ambiguous', eq(codes('research/multi/multi-child-zero.md'), ['cluster-representative-ambiguous']),
  JSON.stringify(codes('research/multi/multi-child-zero.md')))
check('multi cluster: subordinate links exactly one → silent', eq(codes('research/multi/multi-child-one.md'), []),
  JSON.stringify(codes('research/multi/multi-child-one.md')))
check('topdir representative with knowledge link → silent', eq(codes('research/topicX/topicX-report.md'), []),
  JSON.stringify(codes('research/topicX/topicX-report.md')))
check('subordinate bound to representative → silent', eq(codes('research/topicX/topicX-boundchild.md'), []),
  JSON.stringify(codes('research/topicX/topicX-boundchild.md')))

// 6. standalone 면제
check('standalone subordinate exempt → silent', eq(codes('research/lonely/solo-note.md'), []),
  JSON.stringify(codes('research/lonely/solo-note.md')))

// 7. 정상 침묵
check('root representative + knowledge link → silent', eq(codes('research/root-summary.md'), []),
  JSON.stringify(codes('research/root-summary.md')))

// wiki basic-only
check('wiki with frontmatter → silent (basic check only)', eq(codes('wiki/insights/some-insight.md'), []),
  JSON.stringify(codes('wiki/insights/some-insight.md')))
check('wiki without frontmatter → no-frontmatter', eq(codes('wiki/insights/nofm.md'), ['no-frontmatter']),
  JSON.stringify(codes('wiki/insights/nofm.md')))

// 8. 비대상 침묵
check('excluded dir (.tools) → skipped silent', eq(codes('.tools/lint/inside-excluded.md'), []) && validateFile(path.join(VAULT, '.tools/lint/inside-excluded.md'), { vault: VAULT }).skipped)
check('non-.md → skipped silent', validateFile(path.join(VAULT, 'research/note.txt'), { vault: VAULT }).skipped)
check('wiki/log.md (WIKI_EXCLUDE) → skipped silent', validateFile(path.join(VAULT, 'wiki/log.md'), { vault: VAULT }).skipped)
check('path outside vault → skipped silent', validateFile('/etc/hostname.md', { vault: VAULT }).skipped)
check('root knowledge-dir .md → misplaced-note (2026-07-12 incident class)', eq(codes('insights/misplaced-note.md'), ['misplaced-note:wiki/insights/misplaced-note']),
  JSON.stringify(codes('insights/misplaced-note.md')))
check('non-knowledge root .md → skipped silent', validateFile(path.join(VAULT, 'ROOT-README.md'), { vault: VAULT }).skipped)

// physical-path (symlinked vault) — file_path is the PHYSICAL location while the vault is reached via a
// symlink. A lexical path.relative would emit a '..'-prefixed rel and silently skip; classifyTarget
// realpaths both sides (Architect MEDIUM1) so the write is classified in-scope and still warns.
if (process.platform !== 'win32') {
  const physChild = path.join(VAULT, 'research/topicX/topicX-child.md')   // physical file_path
  const cls = classifyTarget(physChild, LINK_VAULT)                        // vault reached via symlink
  check('physical-path target classified (not silently skipped)', !cls.skip && cls.source === 'research', JSON.stringify(cls))
  const physCodes = validateFile(physChild, { vault: LINK_VAULT }).warnings.map(x => x.code).sort()
  check('physical-path write still emits cluster warning', eq(physCodes, ['missing-representative-link']), JSON.stringify(physCodes))
  // symmetric: logical file_path (through the symlink) + physical vault → also classified in-scope
  check('logical-path (through symlink) target classified', !classifyTarget(path.join(LINK_VAULT, 'research/topicX/topicX-child.md'), VAULT).skip)
}

// warn 후 target bytes unchanged (validator is strictly read-only)
{
  const p = path.join(VAULT, 'research/topicX/topicX-child.md')
  const before = fs.readFileSync(p)
  spawnSync(NODE, [VALIDATOR, p], { env: { ...process.env, MY_BRAIN_DIR: VAULT } })
  check('warn leaves target bytes unchanged', Buffer.compare(before, fs.readFileSync(p)) === 0)
}

// 9. 내부오류 → exit 0 침묵 (never blocks a write)
{
  const p = path.join(VAULT, 'research/topicX/topicX-child.md')
  const r = spawnSync(NODE, [VALIDATOR, p], { env: { ...process.env, MY_BRAIN_DIR: VAULT, _VALIDATE_FORCE_ERROR: '1' }, encoding: 'utf8' })
  check('internal error → exit 0', r.status === 0, `status=${r.status}`)
  check('internal error → silent stderr', (r.stderr || '') === '', JSON.stringify(r.stderr))
}

// CLI warn path exit code
{
  const p = path.join(VAULT, 'research/topicX/topicX-child.md')
  const r = spawnSync(NODE, [VALIDATOR, p], { env: { ...process.env, MY_BRAIN_DIR: VAULT }, encoding: 'utf8' })
  check('CLI warn → exit 1 + code on stderr', r.status === 1 && r.stderr.includes('missing-representative-link'), `status=${r.status} err=${r.stderr}`)
}


// Exercise the real bridge with local copies of its Node dependencies.
fs.mkdirSync(path.join(VAULT, '.tools/lint'), { recursive: true })
fs.mkdirSync(path.join(VAULT, '.tools/graph'), { recursive: true })
fs.copyFileSync(VALIDATOR, path.join(VAULT, '.tools/lint/validate-write.mjs'))
for (const file of ['link-core.mjs', 'note-io.mjs']) {
  fs.copyFileSync(path.resolve(HERE, '../graph', file), path.join(VAULT, '.tools/graph', file))
}
fs.copyFileSync(path.resolve(HERE, '../vault-path.mjs'), path.join(VAULT, '.tools/vault-path.mjs'))
function runHook(fileArg) {
  const input = JSON.stringify({ tool_input: { file_path: fileArg } })
  return spawnSync(NODE, [PYTHON_RUNTIME, HOOK], { input, env: { ...process.env, MY_BRAIN_DIR: VAULT }, encoding: 'utf8' })
}
{
  const warnRun = runHook(path.join(VAULT, 'research/topicX/topicX-child.md'))
  const output = JSON.parse(warnRun.stdout).hookSpecificOutput
  check('hook warning → PostToolUse additionalContext, exit 0',
    warnRun.status === 0 && output.hookEventName === 'PostToolUse' && output.additionalContext.includes('missing-representative-link'))
  const cleanRun = runHook(path.join(VAULT, 'research/topicX/topicX-report.md'))
  check('hook e2e: clean target → exit 0 silent', cleanRun.status === 0 && cleanRun.stderr === '', `status=${cleanRun.status} err=${JSON.stringify(cleanRun.stderr)}`)
  const skipRun = runHook(path.join(VAULT, 'research/note.txt'))
  check('hook e2e: non-target → exit 0 silent (pre-node)', skipRun.status === 0 && skipRun.stderr === '', `status=${skipRun.status}`)
}

// hook e2e via a symlinked vault + PHYSICAL file_path — exercises the shell realpath -m scope gate
// (Architect MEDIUM1): MY_BRAIN_DIR is the symlink, file_path is the physical location. A lexical
// "$VAULT"/* prefix compare would silently exit 0; realpath -m keeps the write in-scope so node runs.
if (process.platform !== 'win32') {
  const physChild = path.join(VAULT, 'research/topicX/topicX-child.md')       // physical file_path
  const r = spawnSync(NODE, [PYTHON_RUNTIME, HOOK], { input: JSON.stringify({ tool_input: { file_path: physChild } }), env: { ...process.env, MY_BRAIN_DIR: LINK_VAULT }, encoding: 'utf8' })
  check('hook e2e: physical-path write via symlinked vault → advisory warning', r.status === 0 && JSON.parse(r.stdout).hookSpecificOutput.additionalContext.includes('missing-representative-link'))
}


// ---------------------------------------------------------------- verdict ----
console.log(`\nvalidate-write.selftest: ${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
