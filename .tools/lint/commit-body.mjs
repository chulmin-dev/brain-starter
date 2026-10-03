#!/usr/bin/env node
// commit-body.mjs — Lore 5필드 구조화 본문 read-only 리포터 (R3 ADAPT).
//
// 계약(불변):
//   - **항상 exit 0**. 정상/위반/git 오류 전부. 오류는 `report-error=...` 한 줄로 표면화한다.
//   - `lint.mjs` import 0, 게이트 플래그 배선 0, 훅/크론 등록 0 → 호출자가 없으므로 게이트 2중화가 구조적으로 불가.
//   - 소스 무수정. git 읽기만.
//
// 측정 계약(C-3): 분모는 알려진 자동 커밋을 제외한 모든 커밋이다. human과 미등록 automation을
// 구별하지 않는다(제목만으로 작성 주체를 판별할 수 없다는 한계를 감수). 비공인 접두는 warning만 낸다.
//
// usage: node commit-body.mjs [--since=YYYY-MM-DD]

import { execFileSync } from 'node:child_process'

// Opt-in autocommit and optional Obsidian Git backups do not require a manual rationale.
const EXEMPT = [
  /^auto\(brain\)/,
  /^vault backup:/,
]
// 공인 수동 접두 (대상 판정 술어가 아니라 표기 관례 — 비공인은 warning만)
const SANCTIONED = [/^claude:/, /^brain:/, /^lint\([^)]+\):/, /^revert:/]

const LABELS = ['Constraint', 'Rejected', 'Not-tested', 'Directive', 'Reversibility']
const REVERSIBILITY = new Set(['clean', 'migration-needed', 'irreversible'])
const RECORD_SEP = '\u001e'

export function parseCommitMessage(text) {
  const lines = String(text ?? '').split(/\r?\n/)
  const subject = lines[0] || ''
  const found = {}
  for (const l of LABELS) found[l] = []
  for (const line of lines.slice(1)) {
    const m = line.match(/^([A-Za-z][A-Za-z-]*):\s*(.*)$/)
    if (m && LABELS.includes(m[1])) found[m[1]].push(m[2].trim())
  }
  const exempt = EXEMPT.some(re => re.test(subject))
  const sanctioned = SANCTIONED.some(re => re.test(subject))
  const missing = LABELS.filter(l => found[l].length === 0)
  const badRejected = found.Rejected.filter(v => {
    const i = v.indexOf('|')
    return i < 0 || !v.slice(0, i).trim() || !v.slice(i + 1).trim()
  })
  const rev = found.Reversibility
  const badReversibility = rev.length !== 1 || !REVERSIBILITY.has(rev[0])
  const complete = !exempt && missing.length === 0 && badRejected.length === 0 && !badReversibility
  return { subject, exempt, sanctioned, found, missing, badRejected, badReversibility, complete }
}

function main() {
  const sinceArg = process.argv.find(a => a.startsWith('--since='))
  const since = sinceArg ? sinceArg.slice('--since='.length) : null
  let raw
  try {
    const args = ['log', `--format=%B${RECORD_SEP}`, '--no-merges']
    if (since) args.push(`--since=${since}`)
    raw = execFileSync('git', args, { encoding: 'utf8', maxBuffer: 32 << 20 })
  } catch (e) {
    console.log(`report-error=${(e && e.message ? e.message : String(e)).split('\n')[0]}`)
    return
  }
  const msgs = raw.split(RECORD_SEP).map(s => s.replace(/^\r?\n/, '')).filter(s => s.trim())
  let eligible = 0, complete = 0, exempt = 0
  const gaps = []
  for (const m of msgs) {
    const r = parseCommitMessage(m)
    if (r.exempt) { exempt++; continue }
    eligible++
    if (r.complete) { complete++; continue }
    const why = []
    if (r.missing.length) why.push('missing=' + r.missing.join(','))
    if (r.badRejected.length) why.push('bad-rejected=' + r.badRejected.length)
    if (r.badReversibility) why.push('bad-reversibility')
    if (!r.sanctioned) why.push('unsanctioned-subject')
    gaps.push(`  ${r.subject.slice(0, 72)} — ${why.join(' ')}`)
  }
  const rate = eligible ? `${((complete / eligible) * 100).toFixed(1)}%` : 'N/A'
  console.log(`eligible=${eligible} complete=${complete} rate=${rate} exempt=${exempt}`)
  for (const g of gaps) console.log(g)
}

// CLI로 직접 실행될 때만 동작. import 시에는 순수 API만 노출한다.
if (process.argv[1] && process.argv[1].endsWith('commit-body.mjs')) {
  try { main() } catch (e) {
    console.log(`report-error=${(e && e.message ? e.message : String(e)).split('\n')[0]}`)
  }
}
