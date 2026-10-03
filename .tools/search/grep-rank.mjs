// Shared FLAT field-projection grep ranker — SINGLE source of truth for the keyword/grep retrieval
// leg, used by both ab-bench.mjs (regression gate) and brain-search.mjs (router). Input docs now carry
// the deriveFields() 5-field shape {slug, title, aliases, tags, summary, body}; distinct/total are
// computed over the 5-field PROJECTION (title + aliases + tags + summary + body). The projection is
// concatenation-equivalent: each field's text is joined by \n, and a query token never contains
// whitespace (tokenize splits on \s+), so no token can span a field boundary — per-field occurrence
// sum == whole-projection occurrence count. Ranking (W2.1, fieldTier ON): comparator
// (fieldTier desc, distinct desc, total desc, slug asc). fieldTier is a HARD precedence tier derived
// from WHERE the QUERY tokens matched — ladder: 3 alias/title exact-phrase (tokenized-sequence equality
// per alias element/title, NEVER raw substring — C-CJK: 柳瑞穂 tokenizes to [] and stays unmatchable)
// > 2 alias/title token > 1 tags/summary token > 0 body-only (= the W1.1a flat behavior). The tier is
// computed from tokenize(q) ONLY — options.exactTerms NEVER contributes to the tier (router exact-guard
// stays orthogonal; W2.pre contract 3c). fieldHits (term -> [fields matched]) feeds the tier and stays
// on each scored row. options.exactTerms adds caller-supplied exact phrases/identifiers to
// the match set (router exact-guard); ab-bench passes none (leg/router parity is intentional, not a bug).
export const STOP = new Set(['그', '이', '저', '수', '것', '등', 'the', 'a', 'an', 'of', 'to', 'in', 'on', 'for', 'and', 'or', 'is', '어떻게', '무엇', '관련', '대해'])

export function tokenize(q) {
  return [...new Set(
    q.toLowerCase().split(/\s+/)
      .map(t => t.replace(/^[^\w가-힣.]+|[^\w가-힣.]+$/g, ''))                              // trim edge punct, keep internal . _ -
      .map(t => t.replace(/(은|는|이|가|을|를|의|에서|에|으로|로|과|와|도|만|까지|부터|처럼)$/, '')) // strip trailing Korean josa
      .filter(t => t.length >= 2 && !STOP.has(t))
  )]
}

// the 5 projected fields, fixed order. Order is irrelevant to distinct/total (sum is commutative) and
// only fixes the iteration for the internal fieldHits detail.
export const FIELDS = ['title', 'aliases', 'tags', 'summary', 'body']

// per-field lowercased text. Arrays (aliases/tags) join on \n — a separator that can never appear
// inside a query token — so the concatenated projection stays match-count-equivalent to scoring each
// field (and each array element) independently.
function fieldText(v) {
  return (Array.isArray(v) ? v.join('\n') : v == null ? '' : String(v)).toLowerCase()
}

// non-overlapping occurrence count of needle t in haystack hay (t.length >= 2 by construction).
function countOcc(hay, t) {
  let c = 0, idx = hay.indexOf(t)
  while (idx !== -1) { c++; idx = hay.indexOf(t, idx + t.length) }
  return c
}

// ---- W2.1 fieldTier (hard precedence tier; W2.pre-approved ladder) --------------------------------
// 3 = alias/title EXACT-PHRASE: tokenize(q) sequence-equals tokenize(<title>) or tokenize(<one alias
//     element>). Runs over the TOKENIZED text (same keep-class) — never a raw substring, so CJK-only
//     strings (柳瑞穂 → []) cannot re-enter through this rung (W2.pre contract 2).
// 2 = EVERY query token matched in title/aliases. 1 = every token matched in non-body fields.\n// 0 = otherwise (flat behavior). FULL-COVERAGE tiers only — see fieldTierOf gate-fix note.
// Tier uses QUERY tokens only — exactTerms hits are excluded (contract 3c: tier must not depend on the
// router-only exact-guard input).
function exactPhraseEq(qToks, v) {
  const vToks = tokenize(String(v == null ? '' : v))
  return vToks.length > 0 && vToks.length === qToks.length && vToks.every((t, i) => t === qToks[i])
}
// FULL-QUERY-COVERAGE requirement (2026-07-12 gate fix): the tier rises ONLY when EVERY query token
// is matched, and every token's hit set reaches the rung's fields. Without this, a doc sharing ONE
// incidental token with the query in its title out-ranked docs matching ALL tokens in body (the
// snapshot-diff gate caught 9 expected-slug drops incl. 4 misses on the original 32 — any-token
// tiering is provably wrong for multi-token queries). Entity/alias fixtures keep their full win:
// their aliases/title cover the WHOLE query by construction.
function fieldTierOf(qToks, qTokSet, fieldHits, d) {
  if (qToks.length === 0) return 0
  let allMatched = true, allTitleAlias = true, allNonBody = true
  for (const t of qToks) {
    const fs = fieldHits[t]
    if (!fs || fs.length === 0) { allMatched = false; break }
    if (!fs.includes('title') && !fs.includes('aliases')) allTitleAlias = false
    if (!fs.some(f => f !== 'body')) allNonBody = false
  }
  if (!allMatched) return 0
  if (allTitleAlias) {
    const cands = [d.title, ...(Array.isArray(d.aliases) ? d.aliases : d.aliases != null ? [d.aliases] : [])]
    if (cands.some(v => exactPhraseEq(qToks, v))) return 3
    return 2
  }
  return allNonBody ? 1 : 0
}

// docs: [{ slug, title, aliases, tags, summary, body }] (deriveFields shape). Returns scored objects
// [{ slug, distinct, total, fieldHits }] sliced to `limit`, sorted (distinct desc, total desc, slug
// asc). Callers needing slugs only do .map(s => s.slug); grepScoreOf reads .distinct/.total.
export function grepRank(docs, q, limit, options = {}) {
  const toks = tokenize(q)
  const extra = Array.isArray(options.exactTerms)
    ? options.exactTerms.map(t => String(t).toLowerCase()).filter(t => t.length >= 2)
    : []
  const terms = extra.length ? [...new Set([...toks, ...extra])] : toks
  const qTokSet = new Set(toks)
  const scored = []
  for (const d of docs) {
    const proj = {}
    for (const f of FIELDS) proj[f] = fieldText(d[f])
    let distinct = 0, total = 0
    const fieldHits = {} // term -> [fields matched]
    for (const t of terms) {
      let termTotal = 0
      const hitFields = []
      for (const f of FIELDS) { const c = countOcc(proj[f], t); if (c > 0) { termTotal += c; hitFields.push(f) } }
      if (termTotal > 0) { distinct++; total += termTotal; fieldHits[t] = hitFields }
    }
    if (distinct > 0) scored.push({ slug: d.slug, distinct, total, fieldHits, fieldTier: fieldTierOf(toks, qTokSet, fieldHits, d) })
  }
  scored.sort((a, b) => b.fieldTier - a.fieldTier || b.distinct - a.distinct || b.total - a.total || a.slug.localeCompare(b.slug))
  return scored.slice(0, limit)
}
