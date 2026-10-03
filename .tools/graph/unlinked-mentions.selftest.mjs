#!/usr/bin/env node
// unlinked-mentions.selftest.mjs — pure in-memory fixtures (no vault I/O, no writes).
// Covers the T2 plan tech-4 acceptance cases:
//   ① plain-text mention of an existing title → hit
//   ② aliases match → hit
//   ③ inside [[...]] / fenced code / frontmatter → NO hit
//   ④ partial word (no boundary) → NO hit
//   ⑤ longest-title-first (overlap yields ONE hit for the longer title)
// plus: self-mention skip, ambiguity (2+ targets, never auto-picked), determinism (double run
// byte-identical). exit 0 iff all pass.
import { buildDictionary, scan, mergeRanges, excludedRanges, titlePattern, protectedLines } from './unlinked-mentions.mjs'

let pass = 0, fail = 0
function check(name, cond, detail) {
  if (cond) { pass++; console.log('  PASS ' + name) }
  else { fail++; console.log('  FAIL ' + name + (detail ? ' — ' + detail : '')) }
}

// ---- fixture corpus (dictionary sources; content only matters for the scanned page) ----
const D = (slug, source, fm, content = '') => ({ slug, source, content, fm })
const corpus = [
  D('projects/meta-ads', 'wiki', { title: 'Meta Ads' }),
  D('projects/meta', 'wiki', { title: 'Meta' }),
  D('insights/payment-failure', 'wiki', { title: '결제 실패 패턴', aliases: ['PG 실패'] }),
  D('research/topic/dup-title', 'research', { title: 'Duplicate Name' }),
  D('decisions/dup-title-2', 'wiki', { title: 'Duplicate Name' }),
  D('people/self-page', 'wiki', { title: 'Self Page' }),
  D('worklog/2026-06', 'wiki', { title: '2026-06' }),
  D('research/topic2/report', 'research', { title: '고유한 리포트 제목' }),
]

const scanned = D('notes/scratch', 'wiki', { title: 'scratch' }, `---
title: scratch
summary: frontmatter은 Meta Ads를 언급해도 비히트여야 한다
---
# scratch

Meta Ads 캠페인 예산을 검토했다.
PG 실패 사례를 정리했다.
이미 [[Meta Ads]] 로 링크된 언급은 제외된다.
\`\`\`
코드블록 안의 Meta Ads 는 제외된다.
\`\`\`
인라인 코드 \`Meta Ads\` 도 제외된다.
Metadata 는 부분단어라 제외된다.
Duplicate Name 언급은 모호 후보 2개를 보고한다.
선결제 실패 패턴들은 합성어 내부라 비히트다.
결제 실패 패턴 단독 언급은 히트다.
~~~
물결 fence 안 Meta Ads 도 제외된다.
~~~
`)

const selfDoc = D('people/self-page', 'wiki', { title: 'Self Page' }, `---
title: Self Page
---
Self Page 자기 자신 언급은 스킵된다.
하지만 Meta Ads 언급은 잡힌다.
`)

const docs = [...corpus, scanned]
const dict = buildDictionary(docs)

// ---- unit: helpers ----
check('mergeRanges merges overlaps', JSON.stringify(mergeRanges([[5, 9], [0, 3], [2, 6]])) === '[[0,9]]')
check('excludedRanges covers wikilink+code+url', (() => {
  const r = excludedRanges('a [[x]] b `c` d https://e.com f')
  return r.length === 3
})())
check('titlePattern is whitespace-flexible', titlePattern('Meta Ads').test('Meta\t Ads'))

// ---- dictionary ----
check('dict longest-first', dict[0].term.length >= dict[dict.length - 1].term.length)
check('dict alias present', dict.some(e => e.term === 'PG 실패' && e.targets.includes('insights/payment-failure')))
check('dict slug-basename present', dict.some(e => e.term === 'meta-ads'))
check('dict ambiguous term keeps both targets',
  dict.some(e => e.term === 'Duplicate Name' && e.targets.length === 2))
check('noise guard: date-like term excluded', !dict.some(e => e.term === '2026-06'))
check('noise guard: research basename excluded, title kept', (() => {
  const dictAll = buildDictionary(docs, { allBasenames: true })
  return !dict.some(e => e.term === 'report')
    && dict.some(e => e.term === '고유한 리포트 제목')
    && dictAll.some(e => e.term === 'report') && dictAll.some(e => e.term === '2026-06')
})())

// ---- scan: acceptance cases ----
const rep = scan([scanned], dict)
const hits = rep.hits
const on = line => hits.filter(h => h.line === line)

check('① plain-text title mention → hit', hits.some(h => h.term === 'Meta Ads' && h.match === 'Meta Ads' && h.targets.includes('projects/meta-ads')))
check('② alias mention → hit', hits.some(h => h.term === 'PG 실패' && h.targets.includes('insights/payment-failure')))
check('③a [[wikilink]] internal → no hit', !on(9).length, JSON.stringify(on(9)))
check('③b fenced code → no hit', !on(11).length, JSON.stringify(on(11)))
check('③c inline code → no hit', !on(13).length, JSON.stringify(on(13)))
check('③d frontmatter → no hit', !on(2).length && !on(3).length, JSON.stringify(hits.filter(h => h.line <= 4)))
check('④ partial word (Metadata) → no hit', !on(14).some(h => h.term === 'Meta'), JSON.stringify(on(14)))
check('⑤ longest-first: "Meta Ads" once, no nested "Meta"', (() => {
  const l = on(7)
  return l.length === 1 && l[0].term === 'Meta Ads'
})(), JSON.stringify(on(7)))
check('ambiguity: 2 targets reported, both visible', (() => {
  const h = hits.find(h => h.term === 'Duplicate Name')
  return h && h.targets.length === 2 && h.suggested.includes('[[research/topic/dup-title]]') && h.suggested.includes('[[decisions/dup-title-2]]')
})())
check('④b 한글 합성어 내부 → no hit (Unicode 경계)', !on(16).length, JSON.stringify(on(16)))
check('①b 한글 title 단독 언급 → hit', on(17).some(h => h.term === '결제 실패 패턴'), JSON.stringify(on(17)))
check('③e ~~~ fence → no hit', !on(19).length, JSON.stringify(on(19)))
check('fence pairing: ``` inside ~~~ stays protected', (() => {
  const p = protectedLines('~~~\n```\ncontent\n~~~\nafter')
  return p.has(0) && p.has(1) && p.has(2) && p.has(3) && !p.has(4)
})())

// ---- self-mention skip ----
const selfRep = scan([selfDoc], dict)
check('self-mention skipped', !selfRep.hits.some(h => h.term === 'Self Page'), JSON.stringify(selfRep.hits))
check('non-self hit on same page kept', selfRep.hits.some(h => h.term === 'Meta Ads'))

// ---- determinism: double run byte-identical ----
const a = JSON.stringify(scan([scanned, selfDoc], buildDictionary(docs)))
const b = JSON.stringify(scan([scanned, selfDoc], buildDictionary(docs)))
check('determinism: double run byte-identical', a === b)

console.log(`unlinked-mentions.selftest: ${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
