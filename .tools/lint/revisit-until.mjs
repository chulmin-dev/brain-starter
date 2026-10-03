#!/usr/bin/env node
// revisit-until.mjs — decisions frontmatter `revisit_trigger`의 선택적 `[until:YYYY-MM[-DD]]` 토큰 판독.
// 순수 helper: fs/process/현재시각 직접 접근 0. 호출자가 today를 주입한다.
//
// 계보: Lore 프로토콜(arXiv 2603.15566) `Directive: ... [until:...]` 자기소멸 지시의 이식분(R9).
// 상류 staleness-detector.ts:125-149 / parseUntilDate:230-240 대응. 기존 자유문자열과 공존하며,
// 토큰이 있는 문서는 이 검사가 담당하고 lint.mjs §5 legacy bare-date 검사는 skip한다(precedence).
//
// 정본 계약:
//   - 유효 토큰: lowercase `until`, 무공백, 두 자리 월/일. day 부재 = 해당 월 말까지 유효.
//   - day 존재 = 그 날짜 당일까지 유효. `today > boundary`에서 expired.
//   - UTC 재구성 결과가 원값과 다르면 invalid (`[until:2026-02-31]`).
//   - 여러 후보는 입력 순서대로 issue 하나씩, duplicate 보존.

// 유효 토큰 판정식(anchored). 후보는 아래 CANDIDATE_RE로 넓게 잡고 이 식으로 확정한다.
const VALID_ANCHORED = /^\[until:(\d{4})-(0[1-9]|1[0-2])(?:-(0[1-9]|[12]\d|3[01]))?\]$/
// 후보: case-insensitive 시도와 닫힘 누락까지 포착한다(닫히지 않은 경우 줄 끝/공백 경계까지).
const CANDIDATE_RE = /\[until:[^\]\r\n]*\]|\[until:[^\s\]\r\n]*/gi
// 스캔 상한(F5 ReDoS 방어). frontmatter 한 줄 값의 현실 상한을 크게 웃도는 값.
const SCAN_LIMIT = 4096

/** YYYY-MM-DD 문자열로 UTC 경계일을 만든다. 재구성 불일치 시 null. */
function boundaryOf(y, m, d) {
  const year = Number(y), month = Number(m)
  if (d === undefined) {
    // day 부재 = 해당 월 말일
    const last = new Date(Date.UTC(year, month, 0))
    if (last.getUTCFullYear() !== year || last.getUTCMonth() + 1 !== month) return null
    return last.toISOString().slice(0, 10)
  }
  const day = Number(d)
  const dt = new Date(Date.UTC(year, month - 1, day))
  if (dt.getUTCFullYear() !== year || dt.getUTCMonth() + 1 !== month || dt.getUTCDate() !== day) return null
  return dt.toISOString().slice(0, 10)
}

/**
 * @param {string} value  revisit_trigger 원문
 * @param {string} today  'YYYY-MM-DD'
 * @param {string} [slug] 메시지 접두(호출자 문맥). 생략 시 접두 없음 — 순수성 유지.
 * @returns {{kind:'expired'|'invalid', token:string, boundary?:string, message:string}[]}
 */
export function parseRevisitUntil(value, today, slug) {
  const at = slug ? slug + ' ' : ''
  const issues = []
  if (typeof value !== 'string' || value === '') return issues
  // CANDIDATE_RE는 닫힘 누락 입력에서 O(n^2) 백트래킹이 가능하다(QA F5: 180KB에서 2.4s).
  // revisit_trigger는 frontmatter 한 줄이라 현실 상한이 수백 바이트다. 4KB 초과는 스캔하지 않는다.
  if (value.length > SCAN_LIMIT) return issues
  const candidates = value.match(CANDIDATE_RE)
  if (!candidates) return issues
  for (const raw of candidates) {
    const m = VALID_ANCHORED.exec(raw)
    if (!m) {
      issues.push({ kind: 'invalid', token: raw, message: `${at}revisit_trigger 토큰 ${raw} 형식 오류 ([until:YYYY-MM] 또는 [until:YYYY-MM-DD])` })
      continue
    }
    const boundary = boundaryOf(m[1], m[2], m[3])
    if (boundary === null) {
      issues.push({ kind: 'invalid', token: raw, message: `${at}revisit_trigger 토큰 ${raw} 형식 오류 (존재하지 않는 날짜)` })
      continue
    }
    if (today > boundary) {
      issues.push({ kind: 'expired', token: raw, boundary, message: `${at}revisit_trigger ${raw} 만료 (경계 ${boundary} 경과) — 재검토 필요` })
    }
  }
  return issues
}
