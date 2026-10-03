#!/usr/bin/env node
// revisit-until.selftest.mjs — 순수 인메모리 픽스처(vault I/O 0, writes 0).
// Uses the shared check/summary/fail-exit selftest convention.
// 계약: `[]` red stub에서 02·04·13·16·17만 pass → 5 passed / 12 failed, exit 1. green은 17/0.
import { parseRevisitUntil } from './revisit-until.mjs'

let pass = 0, fail = 0
function check(name, cond, detail) {
  if (cond) { pass++; console.log('  PASS ' + name) }
  else { fail++; console.log('  FAIL ' + name + (detail ? ' — ' + detail : '')) }
}
const count = (v, today, kind) => parseRevisitUntil(v, today).filter(i => i.kind === kind).length
const expired = (v, today) => count(v, today, 'expired')
const invalid = (v, today) => count(v, today, 'invalid')

// 01 expired YYYY-MM — [until:2026-01] at 2026-07-26 → expired 1
check('01 expired YYYY-MM', expired('cond [until:2026-01]', '2026-07-26') === 1)

// 02 future YYYY-MM — [until:2027-12] → 0
check('02 future YYYY-MM', parseRevisitUntil('cond [until:2027-12]', '2026-07-26').length === 0)

// 03 malformed one-digit month → invalid 1
check('03 malformed one-digit month', invalid('cond [until:2026-1]', '2026-07-26') === 1)

// 04 legacy free text ignored by helper → 0
check('04 legacy free text ignored by helper',
  parseRevisitUntil('2026-09-30 bizgoal 순증가치 재판정 시 / skill-deploy check exit 3', '2026-07-26').length === 0)

// 05 YYYY-MM-DD valid through named day — 당일 0, 익일 expired 1
check('05 YYYY-MM-DD valid through named day',
  parseRevisitUntil('cond [until:2026-07-26]', '2026-07-26').length === 0 &&
  expired('cond [until:2026-07-26]', '2026-07-27') === 1)

// 06 nonexistent calendar day invalid — 2026-02-31
check('06 nonexistent calendar day invalid', invalid('cond [until:2026-02-31]', '2026-07-26') === 1)

// 07 invalid month — 2026-13
check('07 invalid month', invalid('cond [until:2026-13]', '2026-07-26') === 1)

// 08 month-end and next-month boundary — [until:2026-07] at 07-31 → 0, 08-01 → expired 1
check('08 month-end and next-month boundary',
  parseRevisitUntil('cond [until:2026-07]', '2026-07-31').length === 0 &&
  expired('cond [until:2026-07]', '2026-08-01') === 1)

// 09 leap month-end boundary — [until:2028-02] at 2028-02-29 → 0, 2028-03-01 → expired 1
check('09 leap month-end boundary',
  parseRevisitUntil('cond [until:2028-02]', '2028-02-29').length === 0 &&
  expired('cond [until:2028-02]', '2028-03-01') === 1)

// 10 mixed expired and future tokens → expired 1 only
check('10 mixed expired and future tokens',
  expired('a [until:2026-01] b [until:2027-12]', '2026-07-26') === 1 &&
  invalid('a [until:2026-01] b [until:2027-12]', '2026-07-26') === 0)

// 11 duplicate expired tokens preserve cardinality → expired 2
check('11 duplicate expired tokens preserve cardinality',
  expired('a [until:2026-01] b [until:2026-01]', '2026-07-26') === 2)

// 12 case variants are invalid → invalid 2
check('12 case variants are invalid', invalid('a [UNTIL:2026-01] b [Until:2027-12]', '2026-07-26') === 2)

// 13 legacy text coexists with future token — helper issue 0
check('13 legacy text coexists with future token',
  parseRevisitUntil('bare 2020-01-01 조건 [until:2027-12]', '2026-07-26').length === 0)

// 14 malformed suffix is invalid — [until:2026-01x]
check('14 malformed suffix is invalid', invalid('cond [until:2026-01x]', '2026-07-26') === 1)

// 15 unclosed candidate is invalid — [until:2026-01 (닫힘 없음)
check('15 unclosed candidate is invalid', invalid('cond [until:2026-01 없음', '2026-07-26') === 1)

// 16 absent and empty values → 0
check('16 absent and empty values',
  parseRevisitUntil('', '2026-07-26').length === 0 &&
  parseRevisitUntil(undefined, '2026-07-26').length === 0 &&
  parseRevisitUntil('조건 또는 날짜', '2026-07-26').length === 0)

// 17 canonical template comment stays valid — CLAUDE.md 템플릿 주석의 예시 토큰이 invalid를 만들지 않는다
check('17 canonical template comment stays valid',
  parseRevisitUntil('조건 또는 날짜   # optional — 만료 기계판독이 필요하면 끝에 [until:2027-07] 형식 토큰 추가(YYYY-MM=해당 월 말)', '2026-07-26').length === 0)

// 18 스캔 상한 가드 (QA F5) — 4KB 초과 입력은 백트래킹 없이 즉시 0을 반환한다.
{
  const huge = '[until:x '.repeat(40000)   // ~360KB, 닫힘 누락 = O(n^2) 유발형
  const t0 = Date.now()
  const n = parseRevisitUntil(huge, '2026-07-26').length
  const ms = Date.now() - t0
  check('18 scan limit guards oversized value', n === 0 && ms < 50, `n=${n} ms=${ms}`)
}

// 19 상한 이하 정상 입력은 가드에 걸리지 않는다
check('19 under-limit value still scanned',
  parseRevisitUntil('x'.repeat(4000) + ' [until:2026-01]', '2026-07-26').filter(i => i.kind === 'expired').length === 1)

console.log(`revisit-until.selftest: ${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
