#!/usr/bin/env node
// link-core.mjs — the SINGLE corpus/metadata/link resolver + shared representative predicate /
// cluster classifier for my-brain (RALPLAN ② §137, §150-172). build-graph.mjs, lint.mjs and the
// operational Python connectivity checker are meant to CONSUME this resolver instead of each
// carrying their own link parser (which historically drifted: fuzzy basename + errors='replace').
//
// Hard rule from the certainty ladder (OSB empirics: fuzzy cutoff 0.84 mis-matched
// "Google Ads" → "Google Docs"): NO fuzzy auto-selection, EVER. A link that resolves to two or
// more notes is reported as `ambiguous`, never silently picked. Uncertainty is reported, not healed.
//
// Slug rule mirrors .tools/search/corpus.mjs (2-base slug): wiki notes → path relative to wiki/
// (bare, e.g. "decisions/foo"); research notes → relative to the vault (e.g. "research/topic/report").
// Pure node stdlib; the only local dependency is note-io.mjs (strict-UTF-8 read).
import fs from 'node:fs'
import path from 'node:path'
import { readExact } from './note-io.mjs'

// ---- constants ------------------------------------------------------------

// Router/log files are not knowledge pages — excluded from the wiki corpus (mirrors corpus.mjs EXCLUDE).
// W4.2(R2) quarterly rotation artifacts (log/·changelog/ YYYY-Qn.md) are log archives too — same shape as lint.mjs NON_PAGE (T1.5 P3).
const WIKI_EXCLUDE = /^(index(-[a-z-]+)?|CHANGELOG|log|documents-events|\d{4}-Q[1-4])\.md$/
// Non-knowledge / non-vault directories never walked (OSB SKIP_DIRS ∪ brain machine-local dirs).
// Any dotfile-prefixed entry is also skipped (mirrors corpus.mjs dotfile guard).
const SKIP_DIRS = new Set(['.git', '.obsidian', '.trash', '.tools', '.cache', 'node_modules', 'raw', 'templates', '_export'])
// Shared representative predicate — operational superset of the stage-2 hook draft: keeps the Python
// LEAD_RE terms incl. the previously-dropped index|brief, and uses the `synthes` prefix (RALPLAN §63/§158).
const LEAD_RE = /(summary|synthes|proposal|final|report|readme|overview|spec|index|brief)/i
// wiki knowledge dirs a representative note is expected to body-link into (mirrors connectivity_check.py).
const KNOWLEDGE_DIRS = ['decisions/', 'insights/', 'projects/', 'people/', 'companies/', 'deals/', 'legal/', 'resources/']
const EM_DASH = '\u2014', EN_DASH = '\u2013'
const WIKILINK_RE = /\[\[([^\]]+)\]\]/g

// ---- small helpers --------------------------------------------------------

const cmpStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0)
const cmpFromTarget = (a, b) => cmpStr(a.from, b.from) || cmpStr(a.target, b.target)

// Lowercase, unify em/en dashes, flatten space/underscore/dash runs — the matching key. Slashes
// are preserved so a path-qualified slug key keeps its structure. Dash/separator normalization is
// applied ONLY here (in lookup keys), never to the verbatim link target we emit.
function normKey(s) {
  return String(s).replace(/[\u2014\u2013]/g, '-').trim().toLowerCase().replace(/[\s_-]+/g, ' ')
}

// Remove fenced + inline code so example wikilinks inside code never count (fixture #82).
function stripCode(text) {
  // P2 root-cause fix: the inline rule must NOT span newlines. It previously read /`[^`]*`/g, so an
  // unpaired backtick (e.g. one inside a frontmatter `summary:`) paired with some later backtick far
  // down the body and deleted EVERYTHING between them — swallowing real wikilinks. `stripCodeLines`
  // below already excluded \n; the two had silently diverged. Live case: topic-backup.md holds 909
  // backticks (odd), and full-content extraction returned ["path"×4] while the body returned the two
  // genuine links — which is exactly how `orphans ⊄ bodyOrphans` was produced.
  return String(text).replace(/```[\s\S]*?```/g, '').replace(/`[^`\n]*`/g, '')
}

// Same, but keep line structure intact so a `## 관련` / `# H1` inside a code block cannot masquerade
// as a real heading (fenced content becomes blank lines; inline code becomes equal-width spaces).
function stripCodeLines(text) {
  return String(text)
    .replace(/```[\s\S]*?```/g, m => m.replace(/[^\n]/g, ''))
    .replace(/`[^`\n]*`/g, m => ' '.repeat(m.length))
}

function getBody(content) {
  if (content == null) return ''
  content = content.replace(/\r\n/g, '\n')
  const m = content.match(/^---\n[\s\S]*?\n---\n?([\s\S]*)$/)
  return m ? m[1] : content
}

function firstH1(content) {
  if (content == null) return null
  const m = stripCodeLines(getBody(content)).match(/^#[ \t]+(.+?)[ \t]*$/m)
  return m ? m[1] : null
}

// Reduce a raw wikilink body to a target: drop alias (|), heading (#) and block (^) anchors, trailing
// backslash and a literal `.md`. Keeps the full path AND the last path component. NEVER uses Path.stem
// (which would eat the tail of a dotted title like "v1.2"); only a literal trailing ".md" is stripped.
function linkParts(raw) {
  let t = String(raw).split('|')[0].split('#')[0].split('^')[0].trim().replace(/\\+$/, '')
  if (t.endsWith('.md')) t = t.slice(0, -3)
  const slash = t.lastIndexOf('/')
  return { verbatim: slash === -1 ? t : t.slice(slash + 1), full: t, hasPath: slash !== -1 }
}

function fmList(v) {
  if (v == null) return []
  if (Array.isArray(v)) return v.filter(x => typeof x === 'string' && x.trim() !== '')
  if (typeof v === 'string') return v.trim() === '' ? [] : [v]
  return []
}

function isKnowledgeSlug(slug) {
  return KNOWLEDGE_DIRS.some(d => slug.startsWith(d))
}

// graph: standalone + NON-EMPTY standalone_reason → the explicit binding-warning exemption (§158).
// Empty/absent reason is NOT exempt.
function graphStandalone(fm) {
  const g = fm && fm.graph
  const gv = Array.isArray(g) ? g.join(' ') : (g == null ? '' : String(g))
  if (!/^standalone/i.test(gv.trim())) return null
  let reason = fm && fm.standalone_reason
  if (Array.isArray(reason)) reason = reason.join(' ')
  reason = (reason == null ? '' : String(reason)).trim()
  return reason ? reason : null
}

// ---- frontmatter ----------------------------------------------------------

function unquote(x) {
  x = String(x).trim()
  if ((x.startsWith('"') && x.endsWith('"')) || (x.startsWith("'") && x.endsWith("'"))) x = x.slice(1, -1)
  return x
}

// Split a scalar on top-level commas only: commas inside quotes or inside [ ] / [[ ]] bracket depth
// do NOT split (RALPLAN §152).
function splitTopComma(s) {
  const out = []
  let cur = '', depth = 0, q = null
  for (const c of String(s)) {
    if (q) { cur += c; if (c === q) q = null; continue }
    if (c === '"' || c === "'") { q = c; cur += c; continue }
    if (c === '[') { depth++; cur += c; continue }
    if (c === ']') { depth = Math.max(0, depth - 1); cur += c; continue }
    if (c === ',' && depth === 0) { out.push(cur); cur = ''; continue }
    cur += c
  }
  out.push(cur)
  return out.map(x => x.trim()).filter(x => x !== '')
}

// Robust frontmatter parser: scalar / inline-list [a,b] / block-list (- item) / quoted / wikilink
// values. Wikilink-valued fields keep their [[...]] wrapper verbatim (dualBinding strips it later);
// a lone `[[a]]` stays a scalar string, `[[a]], [[b]]` becomes a list.
export function parseFrontmatterFull(content) {
  const fm = {}
  if (typeof content !== 'string') return fm
  content = content.replace(/\r\n/g, '\n')
  const m = content.match(/^---\n([\s\S]*?)\n---/)
  if (!m) return fm
  const lines = m[1].split('\n')
  for (let i = 0; i < lines.length; i++) {
    const kv = lines[i].match(/^([A-Za-z_][A-Za-z0-9_]*):[ \t]*(.*)$/)
    if (!kv) continue
    const key = kv[1]
    const rest = kv[2]
    if (rest.trim() === '') {
      // possible block list on the following indented "- item" lines
      const items = []
      let j = i + 1
      while (j < lines.length && /^[ \t]*-[ \t]+\S/.test(lines[j])) {
        items.push(unquote(lines[j].replace(/^[ \t]*-[ \t]+/, '')))
        j++
      }
      if (items.length) { fm[key] = items; i = j - 1 } else fm[key] = ''
      continue
    }
    const t = rest.trim()
    if (t.startsWith('[[')) {
      // wikilink value(s): split only on top-level commas (outside brackets)
      const parts = splitTopComma(t)
      fm[key] = parts.length > 1 ? parts.map(unquote) : unquote(t)
    } else if (t.startsWith('[') && t.endsWith(']')) {
      const inner = t.slice(1, -1)
      fm[key] = inner.trim() === '' ? [] : splitTopComma(inner).map(unquote)
    } else {
      fm[key] = unquote(t)
    }
  }
  return fm
}

// ---- corpus collection ----------------------------------------------------

function* walkMd(dir) {
  let ents
  try { ents = fs.readdirSync(dir, { withFileTypes: true }) } catch { return }
  ents.sort((a, b) => cmpStr(a.name, b.name)) // deterministic order (golden stability)
  for (const e of ents) {
    if (e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue
    const full = path.join(dir, e.name)
    if (e.isDirectory()) yield* walkMd(full)
    else if (e.name.endsWith('.md')) yield full
  }
}

// Recursively collect notes under vaultDir/{wiki,research}, mirroring corpus.mjs slug rules.
// content is strict UTF-8 (readExact); a file that is not valid UTF-8 yields content:null and
// readable:false (it is a graph node but cannot be scanned/rewritten — the "unreadable" signal).
export function collectNotes(vaultDir) {
  const base = path.resolve(vaultDir)
  const notes = []
  const WIKI = path.join(base, 'wiki')
  const RESEARCH = path.join(base, 'research')
  for (const file of walkMd(WIKI)) {
    if (WIKI_EXCLUDE.test(path.basename(file))) continue
    const content = readExact(file)?.replace(/\r\n/g, '\n') ?? null
    const slug = path.relative(WIKI, file).split(path.sep).join('/').replace(/\.md$/, '')
    notes.push({ slug, source: 'wiki', file, content, fm: content == null ? {} : parseFrontmatterFull(content), readable: content != null })
  }
  for (const file of walkMd(RESEARCH)) {
    const content = readExact(file)?.replace(/\r\n/g, '\n') ?? null
    const slug = 'research/' + path.relative(RESEARCH, file).split(path.sep).join('/').replace(/\.md$/, '')
    notes.push({ slug, source: 'research', file, content, fm: content == null ? {} : parseFrontmatterFull(content), readable: content != null })
  }
  notes.sort((a, b) => cmpStr(a.slug, b.slug))
  return notes
}

// ---- link extraction + resolution -----------------------------------------

// Body wikilink targets, VERBATIM last path component (.md stripped, dotted titles + dashes preserved),
// code stripped first, deduped in first-seen order. Dash/separator normalization is a lookup-key
// concern only and is intentionally NOT applied here.
export function extractLinks(content) {
  const out = [], seen = new Set()
  const clean = stripCode(content == null ? '' : content)
  let m; WIKILINK_RE.lastIndex = 0
  while ((m = WIKILINK_RE.exec(clean))) {
    const { verbatim } = linkParts(m[1])
    if (verbatim && !seen.has(verbatim)) { seen.add(verbatim); out.push(verbatim) }
  }
  return out
}

function buildIndex(notes) {
  const byExactStem = new Map(), byExactAlias = new Map()
  const byNormStem = new Map(), byNormAlias = new Map(), byNormSlug = new Map()
  const pushArr = (map, k, n) => { const a = map.get(k); if (a) a.push(n); else map.set(k, [n]) }
  const pushSet = (map, k, n) => { const s = map.get(k); if (s) s.add(n); else map.set(k, new Set([n])) }
  for (const n of notes) {
    const stem = n.slug.split('/').pop()
    pushArr(byExactStem, stem, n)
    pushSet(byNormStem, normKey(stem), n)
    pushSet(byNormSlug, normKey(n.slug), n)
    for (const a of fmList(n.fm && n.fm.aliases)) {
      pushArr(byExactAlias, a, n)
      pushSet(byNormAlias, normKey(a), n)
    }
  }
  return { byExactStem, byExactAlias, byNormStem, byNormAlias, byNormSlug }
}

function uniqNotes(list) {
  const seen = new Set(), out = []
  for (const n of list) { if (!seen.has(n.slug)) { seen.add(n.slug); out.push(n) } }
  return out
}

// Resolution ladder (NO fuzzy): exact stem/alias (verbatim) → slug-normalized unique (path-qualified,
// most specific) → normalized stem/alias unique → otherwise ambiguous (2+) or dangling (0).
function resolveOne(verbatim, full, hasPath, idx) {
  const exact = uniqNotes([...(idx.byExactStem.get(verbatim) || []), ...(idx.byExactAlias.get(verbatim) || [])])
  if (exact.length === 1) return { kind: 'edge', note: exact[0] }
  if (hasPath) {
    const sl = [...(idx.byNormSlug.get(normKey(full)) || [])]
    if (sl.length === 1) return { kind: 'edge', note: sl[0] }
    if (sl.length >= 2) return { kind: 'ambiguous', candidates: sl }
  }
  const nk = normKey(verbatim)
  const norm = uniqNotes([...(idx.byNormStem.get(nk) || []), ...(idx.byNormAlias.get(nk) || [])])
  if (norm.length === 1) return { kind: 'edge', note: norm[0] }
  if (norm.length >= 2) return { kind: 'ambiguous', candidates: norm }
  if (exact.length >= 2) return { kind: 'ambiguous', candidates: exact }
  return { kind: 'dangling' }
}

// Resolve every readable note's body wikilinks against the note universe.
// → { edges[], dangling[], ambiguous[], unreadable[] } (all sorted; no self-loops; edges deduped).
export function resolveLinks(notes) {
  const idx = buildIndex(notes)
  const edgeSet = new Set(), dangling = [], ambiguous = []
  for (const n of notes) {
    if (n.content == null) continue
    const clean = stripCode(n.content)
    const seen = new Set()
    let m; WIKILINK_RE.lastIndex = 0
    while ((m = WIKILINK_RE.exec(clean))) {
      const { verbatim, full, hasPath } = linkParts(m[1])
      if (!verbatim) continue
      const dk = verbatim + '\u0000' + full
      if (seen.has(dk)) continue
      seen.add(dk)
      const res = resolveOne(verbatim, full, hasPath, idx)
      if (res.kind === 'edge') {
        if (res.note.slug !== n.slug) edgeSet.add(n.slug + '\t' + res.note.slug)
      } else if (res.kind === 'ambiguous') {
        ambiguous.push({ from: n.slug, target: verbatim, candidates: res.candidates.map(x => x.slug).sort(cmpStr) })
      } else {
        dangling.push({ from: n.slug, target: verbatim })
      }
    }
  }
  const edges = [...edgeSet].map(e => { const [source, target] = e.split('\t'); return { source, target } })
    .sort((a, b) => cmpStr(a.source, b.source) || cmpStr(a.target, b.target))
  dangling.sort(cmpFromTarget)
  ambiguous.sort(cmpFromTarget)
  const unreadable = notes.filter(n => n.content == null).map(n => n.slug).sort(cmpStr)
  return { edges, dangling, ambiguous, unreadable }
}

// Resolved out-edges of a single note as a Set of target slugs (used by the cluster classifier).
function resolvedTargets(note, idx) {
  const out = new Set()
  if (note.content == null) return out
  const clean = stripCode(note.content)
  let m; WIKILINK_RE.lastIndex = 0
  while ((m = WIKILINK_RE.exec(clean))) {
    const { verbatim, full, hasPath } = linkParts(m[1])
    if (!verbatim) continue
    const res = resolveOne(verbatim, full, hasPath, idx)
    if (res.kind === 'edge' && res.note.slug !== note.slug) out.add(res.note.slug)
  }
  return out
}

// ---- dual binding (feeds / related / body ## 관련) -------------------------

// Canonical target of a feeds/related/body token: unquote → strip [[ ]] wrapper / |alias / #heading /
// ^block / trailing "\" / literal ".md" → slash-normalize (strip a leading `wiki/`, keep `research/`).
// NEVER Path.stem; dashes are preserved (dash normalization is a comparison-key concern only).
function canonicalTarget(raw) {
  let t = unquote(raw)
  t = t.replace(/^\[\[+/, '').replace(/\]\]+$/, '').split('|')[0].split('#')[0].split('^')[0].trim().replace(/\\+$/, '')
  if (t.endsWith('.md')) t = t.slice(0, -3)
  t = t.trim()
  if (t.startsWith('wiki/')) t = t.slice(5)
  return t.trim()
}

// Comparison key for dual-binding sets: lowercase, dashes unified, separators flattened, slashes kept.
function dualKey(s) {
  return String(s).replace(/[\u2014\u2013]/g, '-').trim().toLowerCase().replace(/[ \t_-]+/g, '-')
}

function canonSet(rawList) {
  const seen = new Set(), out = []
  for (const r of rawList) {
    const c = canonicalTarget(r)
    if (!c) continue
    const k = dualKey(c)
    if (seen.has(k)) continue
    seen.add(k); out.push(c)
  }
  out.sort(cmpStr)
  return out
}

// Body `## 관련` (or `## 관련 (...)`) section targets: from that exact H2 up to the next H2, code removed.
function bodyRelatedTargets(content) {
  if (content == null) return []
  const lines = stripCodeLines(getBody(content)).split('\n')
  let start = -1
  for (let i = 0; i < lines.length; i++) {
    if (/^##[ \t]+관련([ \t]*\([^\n]*\))?[ \t]*$/.test(lines[i])) { start = i + 1; break }
  }
  if (start === -1) return []
  let end = lines.length
  for (let i = start; i < lines.length; i++) { if (/^##[ \t]/.test(lines[i])) { end = i; break } }
  const region = lines.slice(start, end).join('\n')
  const out = []
  let m; WIKILINK_RE.lastIndex = 0
  while ((m = WIKILINK_RE.exec(region))) { const c = canonicalTarget(m[1]); if (c) out.push(c) }
  return out
}

// P1: canonical UNDIRECTED edge set. A wikilink graph is undirected in meaning, but `resolveLinks`
// emits one record per written direction — so `A→B` and `B→A` are two records for ONE relation.
// Canonicalizing puts the codepoint-lower slug in `source`, which collapses reciprocal pairs.
//
// Deliberately NOT applied (upstream does both; both are wrong here):
//   - LCC cut          — would delete the P2 islands we are trying to surface.
//   - `_normalize_name` uppercase/unescape — slug case is the resolver's contract, not ours.
// Resolved slugs are passed through verbatim; only ORDER within a pair changes.
//
// Pipeline: validate {source,target} → drop self-loops → lo/hi place → dedup pair → sort asc.
// Pure: never mutates `edges` and never writes derived values back to any cache.
export function canonicalUndirectedEdges(edges) {
  const seen = new Set(), out = []
  for (const e of edges || []) {
    if (!e || typeof e.source !== 'string' || typeof e.target !== 'string') continue
    if (!e.source || !e.target || e.source === e.target) continue
    const [source, target] = e.source <= e.target ? [e.source, e.target] : [e.target, e.source]
    const key = `${source}\u0000${target}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ source, target })
  }
  return out.sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : 0) ||
                            (a.target < b.target ? -1 : a.target > b.target ? 1 : 0))
}

// P2: connectivity components over the BODY-undirected graph.
//
// Why bodyEdges and not edges: frontmatter `feeds`/`related` do not render in Obsidian's graph, so
// full-content edges would report a connectivity the user cannot see (the satellite-invariant).
//
// Component IDs are content-addressed — `sha256:` + SHA-256 over the codepoint-sorted member list
// joined by '\n' with a trailing '\n'. That makes an ID stable across runs and machines and
// independent of iteration order, so a component keeps its identity as long as its membership does.
//
// Total order is (size desc, first member asc, full member list lexicographic). Member lists are
// disjoint by construction, so the third key is only ever reached on an exact size+first-member tie
// and always decides — the order is therefore total, never arbitrary.
export function connectivityComponents(bodyEdges, cryptoImpl) {
  const canon = canonicalUndirectedEdges(bodyEdges)
  const adj = new Map()
  const touch = a => { if (!adj.has(a)) adj.set(a, new Set()); return adj.get(a) }
  for (const e of canon) { touch(e.source).add(e.target); touch(e.target).add(e.source) }

  const cmpCp = (a, b) => (a < b ? -1 : a > b ? 1 : 0)
  const seen = new Set(), groups = []
  for (const start of [...adj.keys()].sort(cmpCp)) {
    if (seen.has(start)) continue
    const stack = [start], members = []
    seen.add(start)
    while (stack.length) {
      const v = stack.pop()
      members.push(v)
      for (const w of adj.get(v) || []) if (!seen.has(w)) { seen.add(w); stack.push(w) }
    }
    groups.push(members.sort(cmpCp))
  }
  groups.sort((x, y) => y.length - x.length || cmpCp(x[0], y[0]) || cmpCp(x.join('\n'), y.join('\n')))

  const idOf = m => 'sha256:' + cryptoImpl.createHash('sha256').update(m.join('\n') + '\n', 'utf8').digest('hex')
  const withId = groups.map(m => ({ id: idOf(m), size: m.length, members: m }))
  return {
    edgeBasis: 'bodyEdges',
    linkedNodeCount: adj.size,
    componentCount: withId.length,
    lcc: withId[0] || { id: null, size: 0, members: [] },
    islands: withId.slice(1),
    strandedNodeCount: withId.slice(1).reduce((s, c) => s + c.size, 0),
  }
}
// Dual binding of a research note. feeds = knowledge targets research supplies; related = general
// relation mirror that MUST also appear in body `## 관련` when non-empty. Diffs (dualKey compared):
//   missing    = related targets absent from body (the binding warning),
//   bodyOnly   = body targets neither declared in related nor feeds,
//   unresolved = feeds targets absent from body (declared knowledge that renders no graph edge).
// graph: standalone (+reason) is still observed but flagged so callers exempt the binding warning.
export function dualBinding(note) {
  const fm = note.fm || {}
  const feeds = canonSet(fmList(fm.feeds))
  const related = canonSet(fmList(fm.related))
  const bodyRelated = canonSet(bodyRelatedTargets(note.content))
  const bk = new Set(bodyRelated.map(dualKey)), rk = new Set(related.map(dualKey)), fk = new Set(feeds.map(dualKey))
  const missing = related.filter(t => !bk.has(dualKey(t))).sort(cmpStr)
  const bodyOnly = bodyRelated.filter(t => !rk.has(dualKey(t)) && !fk.has(dualKey(t))).sort(cmpStr)
  const unresolved = feeds.filter(t => !bk.has(dualKey(t))).sort(cmpStr)
  const standaloneReason = graphStandalone(fm)
  return {
    feeds, related, bodyRelated, missing, bodyOnly, unresolved,
    counts: { feeds: feeds.length, related: related.length, bodyRelated: bodyRelated.length, missing: missing.length, bodyOnly: bodyOnly.length, unresolved: unresolved.length },
    standalone: standaloneReason != null,
    standaloneReason,
  }
}

// ---- representative predicate + cluster classifier ------------------------

// Shared representative predicate: basename matches LEAD_RE, or the title/first-H1 contains 종합|결론.
export function representativePredicate(note) {
  const stem = note.slug.split('/').pop()
  if (LEAD_RE.test(stem)) return true
  const title = note.fm && note.fm.title
  if (typeof title === 'string' && /종합|결론/.test(title)) return true
  const h1 = firstH1(note.content)
  return !!(h1 && /종합|결론/.test(h1))
}

// Cluster key of a research note (filename removed from the research-relative path):
//   research/<topdir>/<file>            → key research/<topdir>,        parentRel research/<topdir>
//   research/<topdir>/<nested…>/<file>  → key research/<topdir> (first dir), parentRel = immediate parent
//   research/<file>                     → singleton key research/@root/<basename> (no sibling guessing)
// Non-research notes have no cluster.
export function clusterOf(note) {
  const slug = note.slug
  if (!slug.startsWith('research/')) return { clusterKey: null, parentRel: null }
  const parts = slug.split('/') // ['research', ...]
  if (parts.length === 2) return { clusterKey: `research/@root/${parts[1]}`, parentRel: 'research' }
  return { clusterKey: `research/${parts[1]}`, parentRel: parts.slice(0, -1).join('/') }
}

// Classify a note within its cluster (§166-171). NEVER auto-selects a representative.
// classification: 'representative' (note itself is a candidate) | 'subordinate' | 'not-applicable'.
// warning: null | representative-missing-knowledge-link | missing-representative-link
//        | cluster-no-representative | cluster-representative-ambiguous.
export function classifyCluster(note, notes) {
  const { clusterKey, parentRel } = clusterOf(note)
  const standaloneReason = graphStandalone(note.fm || {})
  const standalone = standaloneReason != null
  if (clusterKey == null) {
    return { clusterKey: null, parentRel: null, classification: 'not-applicable', candidates: [], warning: null, standalone }
  }
  const candidates = notes.filter(n => clusterOf(n).clusterKey === clusterKey && representativePredicate(n)).map(n => n.slug).sort(cmpStr)
  const idx = buildIndex(notes)
  const targets = resolvedTargets(note, idx)
  const base = { clusterKey, parentRel, candidates }

  if (candidates.includes(note.slug)) {
    // this note IS a representative → check for a resolved wiki-knowledge body link
    const hasKnowledge = [...targets].some(isKnowledgeSlug)
    return {
      ...base,
      classification: 'representative',
      warning: hasKnowledge || standalone ? null : 'representative-missing-knowledge-link',
      clusterAmbiguous: candidates.length >= 2, // multiplicity of candidates is a separate cluster-level fact
      standalone,
    }
  }
  // subordinate note
  if (candidates.length === 0) {
    return { ...base, classification: 'subordinate', warning: standalone ? null : 'cluster-no-representative', standalone }
  }
  if (candidates.length === 1) {
    const bound = targets.has(candidates[0])
    return { ...base, classification: 'subordinate', warning: bound || standalone ? null : 'missing-representative-link', boundRepresentative: bound ? candidates[0] : null, standalone }
  }
  // 2+ candidates: respect an explicit single binding; 0 or 2+ resolved links → ambiguous (no auto-select)
  const linked = candidates.filter(c => targets.has(c))
  if (linked.length === 1) {
    return { ...base, classification: 'subordinate', warning: null, boundRepresentative: linked[0], standalone }
  }
  return { ...base, classification: 'subordinate', warning: standalone ? null : 'cluster-representative-ambiguous', boundRepresentative: null, standalone }
}
