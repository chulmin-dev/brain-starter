#!/usr/bin/env node
// commit-body.selftest.mjs — 순수 인메모리 픽스처(git I/O 0, writes 0).
// 12 checks: 네 공인 수동 접두 complete / 네 자동 면제 / missing / invalid Rejected /
//            invalid Reversibility / prose·unknown label.
// 13-15 (2026-07-26 QA 보강, red-team F6-N01): missing 단독 검출 — check 09는 라벨 4개를
//            동시에 누락시켜 badReversibility가 missing 조건을 마스킹했고, 그 결과 complete
//            판정에서 missing을 제거한 뮤턴트가 생존했다(미달 커밋을 complete로 세는 회귀 무검출).
//            13은 Reversibility 정상 + 라벨 1개만 누락으로 그 경로를 단독 고정한다.
import { parseCommitMessage } from './commit-body.mjs'

let pass = 0, fail = 0
function check(name, cond, detail) {
  if (cond) { pass++; console.log('  PASS ' + name) }
  else { fail++; console.log('  FAIL ' + name + (detail ? ' — ' + detail : '')) }
}

const body = [
  '',
  'Constraint: 게이트를 이중화하지 않는다',
  'Rejected: 훅 강제 | 저장정지 위험',
  'Not-tested: 맥 자동커밋 레인',
  'Directive: 30일 뒤 재측정한다',
  'Reversibility: clean',
].join('\n')

// 01-04 공인 수동 접두 4종 complete
for (const [i, subj] of [['01', 'claude: x'], ['02', 'brain: x'], ['03', 'lint(broken-link): x'], ['04', 'revert: x']]) {
  const r = parseCommitMessage(subj + '\n' + body)
  check(`${i} sanctioned prefix complete (${subj.split(':')[0]})`, r.complete && !r.exempt && r.sanctioned)
}

// Known automation exemptions.
for (const [i, subj] of [['05', 'auto(brain): wiki/log.md'], ['07', 'vault backup: 2026-07-26']]) {
  const r = parseCommitMessage(subj + '\nno body')
  check(`${i} exempt automation lane`, r.exempt === true && r.complete === false)
}

// 09 missing labels
{
  const r = parseCommitMessage('brain: x\n\nConstraint: only one')
  check('09 missing labels detected', !r.complete && r.missing.length === 4 && r.missing.includes('Reversibility'))
}

// 10 invalid Rejected (파이프 없음 / 한쪽 공란)
{
  const r1 = parseCommitMessage('brain: x\n\nConstraint: c\nRejected: 파이프 없음\nNot-tested: n\nDirective: d\nReversibility: clean')
  const r2 = parseCommitMessage('brain: x\n\nConstraint: c\nRejected: alt |\nNot-tested: n\nDirective: d\nReversibility: clean')
  check('10 invalid Rejected detected', !r1.complete && r1.badRejected.length === 1 && !r2.complete && r2.badRejected.length === 1)
}

// 11 invalid Reversibility (정본 밖 / 두 줄)
{
  const bad = parseCommitMessage('brain: x\n\nConstraint: c\nRejected: a | b\nNot-tested: n\nDirective: d\nReversibility: difficult')
  const dup = parseCommitMessage('brain: x\n\nConstraint: c\nRejected: a | b\nNot-tested: n\nDirective: d\nReversibility: clean\nReversibility: clean')
  check('11 invalid Reversibility detected', !bad.complete && bad.badReversibility && !dup.complete && dup.badReversibility)
}

// 12 prose·unknown label은 필드로 세지 않는다 (Confidence/Scope-risk 금지 포함)
{
  const r = parseCommitMessage('brain: x\n\n산문 문단으로 제약을 서술했다.\nConfidence: high\nScope-risk: narrow\nConstraint: c\nRejected: a | b\nNot-tested: n\nDirective: d\nReversibility: clean')
  const unsanctioned = parseCommitMessage('feat: x\n' + body)
  check('12 prose/unknown labels ignored, unsanctioned flagged',
    r.complete && !('Confidence' in r.found) && unsanctioned.complete && unsanctioned.sanctioned === false)
}

// 13 missing 단독 검출 — Reversibility 정상이고 라벨 하나만 빠진 경우에도 complete=false여야 한다.
//    (F6-N01: 이 케이스가 없으면 complete 판정에서 missing 조건을 제거해도 selftest가 통과한다)
{
  const one = parseCommitMessage('brain: x\n\nConstraint: c\nRejected: a | b\nDirective: d\nReversibility: clean')
  check('13 single missing label detected (Reversibility valid)',
    !one.complete && one.missing.length === 1 && one.missing[0] === 'Not-tested' && one.badReversibility === false)
}

// 14 제목줄의 라벨 형태는 본문 필드로 세지 않는다
{
  const r = parseCommitMessage('Constraint: 제목처럼 보이는 첫 줄\n\nRejected: a | b\nNot-tested: n\nDirective: d\nReversibility: clean')
  check('14 subject-line label is not counted as a body field',
    r.found.Constraint.length === 0 && !r.complete && r.missing.includes('Constraint'))
}

// 15 면제 판정은 complete보다 우선한다 — 자동 레인은 5필드를 갖춰도 eligible이 아니다
{
  const r = parseCommitMessage('auto(brain): wiki/log.md\n' + body)
  check('15 exempt wins over complete-shaped body', r.exempt === true && r.complete === false)
}

console.log(`commit-body.selftest: ${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
