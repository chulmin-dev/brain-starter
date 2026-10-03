#!/usr/bin/env node
// grep-rank.selftest — standalone, ZERO network / model / vault reads. Locks the W1.1a FLAT
// field-projection contract of grepRank (grep-rank.mjs) + deriveFields (corpus.mjs):
//   (a) distinct/total are computed over the 5-field projection (title/aliases/tags/summary/body) and
//       are concatenation-equivalent (fields joined by a separator; no token spans a field boundary),
//   (b) the comparator (distinct desc, total desc, slug asc) is a deterministic total order,
//   (c) options.exactTerms still augments the match set (router exact-guard) — leg parity preserved,
//   (d) aliases are aggregated into distinct/total (an alias-only match scores; deriveFields threads it).
import { grepRank, tokenize, FIELDS } from './grep-rank.mjs'
import { deriveFields, parseFrontmatter } from './corpus.mjs'

let pass = 0, fail = 0
const ok = (name, cond, info = '') => { if (cond) { pass++; console.log(`  PASS ${name}`) } else { fail++; console.error(`  FAIL ${name} ${info}`) } }
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b)

// reference scorer: naive whole-projection scan (fields joined by \n) — the "결합 동치" oracle.
function refScore(doc, terms) {
  const proj = FIELDS.map(f => {
    const v = doc[f]
    return (Array.isArray(v) ? v.join('\n') : v == null ? '' : String(v)).toLowerCase()
  }).join('\n')
  let distinct = 0, total = 0
  for (const t of terms) {
    let c = 0, i = proj.indexOf(t)
    while (i !== -1) { c++; i = proj.indexOf(t, i + t.length) }
    if (c > 0) { distinct++; total += c }
  }
  return { distinct, total }
}

// ---------------------------------------------------------- (a) 5-field distinct/total ----
console.log('== (a) 5-field distinct/total + concatenation-equivalence ==')
{
  const doc = { slug: 'd1', title: 'alpha beta', aliases: ['gamma'], tags: ['delta'], summary: 'epsilon', body: 'zeta alpha' }
  const q = 'alpha beta gamma delta epsilon zeta'
  const s = grepRank([doc], q, 10)
  ok('doc scored', s.length === 1 && s[0].slug === 'd1')
  ok('distinct=6 (one token per field, alpha in two)', s[0].distinct === 6, `${s[0].distinct}`)
  ok('total=7 (alpha twice: title+body)', s[0].total === 7, `${s[0].total}`)
  ok('fieldHits.alpha=[title,body]', eq(s[0].fieldHits.alpha, ['title', 'body']), JSON.stringify(s[0].fieldHits.alpha))
  ok('fieldHits.gamma=[aliases]', eq(s[0].fieldHits.gamma, ['aliases']))
  ok('fieldHits.delta=[tags]', eq(s[0].fieldHits.delta, ['tags']))
  ok('fieldHits.epsilon=[summary]', eq(s[0].fieldHits.epsilon, ['summary']))
  // concatenation-equivalence: grepRank == naive whole-projection scan for the same terms
  const r = refScore(doc, tokenize(q))
  ok('projection-equivalent distinct', r.distinct === s[0].distinct, `ref=${r.distinct} got=${s[0].distinct}`)
  ok('projection-equivalent total', r.total === s[0].total, `ref=${r.total} got=${s[0].total}`)

  // no cross-field false positive: 'oob' would match a naive 'foo'+'bar' concat but not fields joined
  // by a separator. grepRank scores fields independently → must NOT match.
  const boundary = grepRank([{ slug: 'b', title: 'foo', body: 'bar' }], 'oob', 10)
  ok('no cross-field boundary match', boundary.length === 0, JSON.stringify(boundary))
}

// ---------------------------------------------------------------- (b) comparator order ----
console.log('== (b) comparator total-order determinism + tie-break ==')
{
  const docs = [
    { slug: 'zzz', title: 'foo' },            // distinct 1, total 1
    { slug: 'aaa', title: 'foo' },            // distinct 1, total 1
    { slug: 'mmm', title: 'foo bar' },        // distinct 2, total 2
    { slug: 'nnn', title: 'foo foo foo' },    // distinct 1, total 3
  ]
  const run1 = grepRank(docs, 'foo bar', 10)
  const run2 = grepRank(docs, 'foo bar', 10)
  ok('two runs byte-identical', eq(run1, run2))
  ok('distinct desc then total desc then slug asc', eq(run1.map(s => s.slug), ['mmm', 'nnn', 'aaa', 'zzz']), JSON.stringify(run1.map(s => s.slug)))
  // input order must not leak into output (feed reversed → same sorted order)
  const rev = grepRank([...docs].reverse(), 'foo bar', 10)
  ok('input-order independent', eq(rev.map(s => s.slug), ['mmm', 'nnn', 'aaa', 'zzz']))
  ok('limit slices after sort', grepRank(docs, 'foo bar', 2).map(s => s.slug).join(',') === 'mmm,nnn')
}

// -------------------------------------------------------------- (c) exactTerms regression ----
console.log('== (c) exactTerms path (router exact-guard) regression guard ==')
{
  const docs = [{ slug: 'q1', title: 'irrelevant', body: 'the exact phrase lives deep here' }]
  const none = grepRank(docs, 'zznomatch', 10)
  ok('no query-token match → empty (ab-bench parity: no options)', none.length === 0)
  const withExact = grepRank(docs, 'zznomatch', 10, { exactTerms: ['exact phrase'] })
  ok('exactTerm surfaces otherwise-missed doc', withExact.length === 1 && withExact[0].slug === 'q1', JSON.stringify(withExact))
  ok('exactTerm counted (distinct=1,total=1)', withExact[0].distinct === 1 && withExact[0].total === 1)
  ok('exactTerm fieldHits=[body]', eq(withExact[0].fieldHits['exact phrase'], ['body']))
  // short exact terms (<2 chars) are filtered
  ok('short exactTerm filtered', grepRank(docs, 'zznomatch', 10, { exactTerms: ['x'] }).length === 0)
  // exactTerm equal to a query token must not double-count (Set dedup)
  const dup = grepRank([{ slug: 'q2', body: 'exact exact' }], 'exact', 10, { exactTerms: ['exact'] })
  ok('exactTerm dedup with query token', dup[0].distinct === 1 && dup[0].total === 2, JSON.stringify(dup[0]))
}

// ---------------------------------------------------------------------- (d) aliases scored ----
console.log('== (d) aliases aggregated into distinct/total (alias-only match scores) ==')
{
  // alias-only match: token appears ONLY in the aliases field
  const docs = [
    { slug: 'entity', title: 'zzz', aliases: ['Example Corporation'], tags: [], summary: '', body: 'nothing relevant here' },
    { slug: 'noise', title: 'zzz', aliases: [], tags: [], summary: '', body: 'unrelated body' },
  ]
  const s = grepRank(docs, 'Example Corporation', 10)
  ok('alias-only doc scored, control dropped', s.length === 1 && s[0].slug === 'entity', JSON.stringify(s.map(x => x.slug)))
  ok('alias tokens aggregate distinct=2', s[0].distinct === 2, `${s[0].distinct}`)
  ok('alias match tagged fieldHits=[aliases]', eq(s[0].fieldHits.example, ['aliases']) && eq(s[0].fieldHits.corporation, ['aliases']))

  // end-to-end: raw frontmatter → deriveFields → grepRank (proves aliases thread through the contract)
  const raw = '---\ntitle: "Example Corp"\naliases: ["Example Corporation", "예시 회사"]\ntags: [entertech]\nsummary: "a unicorn"\n---\n\nBody text about robots and IP only.\n'
  const doc = { slug: 'companies/example', source: 'wiki', content: raw, fm: parseFrontmatter(raw) }
  const f = deriveFields(doc)
  const ko = grepRank([{ slug: doc.slug, ...f }], '예시 회사', 10)
  ok('KO alias query hits via aliases field', ko.length === 1 && ko[0].slug === 'companies/example' && ko[0].distinct === 2, JSON.stringify(ko))
  const en = grepRank([{ slug: doc.slug, ...f }], 'Example Corporation', 10)
  ok('EN alias query hits (title+aliases)', en.length === 1 && en[0].distinct === 2 && eq(en[0].fieldHits.example, ['title', 'aliases']), JSON.stringify(en[0]?.fieldHits))
}


// ---- W2.1 fieldTier precedence tier (W2.pre-approved ladder 3>2>1>0) ------------------------------
{
  // (a) HARD tier dominates total: alias-match entity (t=2) beats body-heavy note (t=31, example mode)
  const entity = { slug: 'companies/example', title: '예시회사 (Example Corporation)', aliases: ['Example Corporation'], tags: [], summary: '', body: 'short body' }
  const research = { slug: 'research/example-deep', title: 'deep tech analysis', aliases: [], tags: [], summary: '', body: ('example corporation '.repeat(15)) + 'example' }
  const r = grepRank([research, entity], 'Example Corporation', 10)
  ok('W2.1(a) tier beats total (entity #1 over t31 body note)', r[0].slug === 'companies/example' && r[1].slug === 'research/example-deep', JSON.stringify(r.map(x => [x.slug, x.fieldTier, x.total])))
  ok('W2.1(a) tiers assigned 3 vs 0', r[0].fieldTier === 3 && r[1].fieldTier === 0, JSON.stringify(r.map(x => x.fieldTier)))

  // (b) body-only pool: ordering identical to flat comparator (all tier 0)
  const b1 = { slug: 'a/one', title: 'x', aliases: [], tags: [], summary: '', body: 'kimchi kimchi kimchi' }
  const b2 = { slug: 'a/two', title: 'y', aliases: [], tags: [], summary: '', body: 'kimchi' }
  const rb = grepRank([b2, b1], 'kimchi', 10)
  ok('W2.1(b) body-only order = flat (total desc)', rb[0].slug === 'a/one' && rb[0].fieldTier === 0 && rb[1].fieldTier === 0, JSON.stringify(rb))

  // (c) CJK: 示例人物 tokenizes to [] — no match, and exact-phrase rung cannot re-admit via raw substring
  const syntheticPerson = { slug: 'people/syntheticPerson', title: '예시 인물', aliases: ['示例人物'], tags: [], summary: '', body: '# 예시 인물 (示例人物)' }
  const rc = grepRank([syntheticPerson], '示例人物', 10)
  ok('W2.1(c) CJK query stays unmatchable (no raw-substring backdoor)', rc.length === 0, JSON.stringify(rc))

  // (d) exact-phrase rung 3 beats title-token rung 2 (example-ko residual mode)
  const entityKo = { slug: 'companies/example2', title: '예시회사', aliases: ['예시 회사'], tags: [], summary: '', body: '' }
  const titleNote = { slug: 'research/example-note', title: '예시 회사 기술 심층 분석', aliases: [], tags: [], summary: '', body: '예시 회사 예시 회사 예시 회사' }
  const rd = grepRank([titleNote, entityKo], '예시 회사', 10)
  ok('W2.1(d) exact-phrase(3) beats title-token(2) despite total deficit', rd[0].slug === 'companies/example2' && rd[0].fieldTier === 3 && rd[1].fieldTier === 2, JSON.stringify(rd.map(x => [x.slug, x.fieldTier])))

  // (e) exactTerms NEVER raises the tier (contract 3c) — exactTerm hits title, tier stays body-only
  const et = { slug: 'p/one', title: 'SECRET_TOKEN config', aliases: [], tags: [], summary: '', body: 'deploy notes here' }
  const re1 = grepRank([et], 'deploy notes', 10, { exactTerms: ['secret_token'] })
  ok('W2.1(e) exactTerms excluded from tier (title hit via exactTerm, tier=0)', re1.length === 1 && re1[0].fieldTier === 0, JSON.stringify(re1[0]))
  ok('W2.1(e) exactTerm still counted in distinct/total', re1[0].distinct === 3, `${re1[0].distinct}`)

  // determinism: two runs identical order
  const rr1 = JSON.stringify(grepRank([research, entity, titleNote, entityKo], 'example', 10).map(x => x.slug))
  const rr2 = JSON.stringify(grepRank([entity, entityKo, titleNote, research], 'example', 10).map(x => x.slug))
  ok('W2.1 determinism: input-order independence with tier key', rr1 === rr2, rr1 + ' vs ' + rr2)
}

console.log(`\ngrep-rank.selftest: ${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
