#!/usr/bin/env node
// unlinked-mentions.mjs — plain-text mentions of existing page titles/aliases inside wiki/ bodies,
// reported as [[slug]] upgrade candidates. READ-ONLY advisory CLI: never writes the vault; the
// promotion itself is an LLM/user decision (link-core doctrine — uncertainty is reported, not healed).
//
// Port of MarcoPorcellato/matryca-plumber@9a71121 src/graph/unlinked_mentions.py:
//   longest-first title dictionary (_page_titles_from_graph), per-line excluded ranges with merge
//   (_excluded_ranges/_merge_ranges), word-boundary + whitespace-flexible title pattern
//   (_title_pattern (?<![\w#/])…(?![\w#/]) IGNORECASE), consumed[] overlap suppression, caps
//   (max_hits_per_file 80 / total 2000).
// Adaptations (T2 plan tech 4, ADOPT):
//   - dictionary = corpus.mjs deriveFields title+aliases (G7 wiring) + slug basename, over the FULL
//     corpus (wiki+research), each term mapped to its target slug(s). 2+ targets → reported as
//     ambiguous with ALL targets — NEVER auto-picked (link-core NO-fuzzy hard rule).
//   - scan corpus = wiki/ only via corpus.mjs walkDocs (corpus EXCLUDE is byte-identical to
//     link-core WIKI_EXCLUDE; reused through the exported corpus.mjs copy → zero existing-file edits).
//   - protected lines = frontmatter block + ``` fenced code (source used its global fence scanner);
//     per-line excluded ranges = [[wikilinks]] / `inline code` / URLs. Logseq-only exclusions
//     (((uuid)) block refs, {{macros}}) are dropped — no such syntax in this vault.
//   - self-mentions (term resolving only to the scanned page itself) are skipped.
//   - per title we take ALL non-overlapping matches longest-first instead of the source pos-sweep
//     (whose pos=m.end() jump could skip an earlier shorter-title match); longest-wins-on-overlap
//     semantics are preserved via the consumed[] map.
//   - maxTitles defaults to the source hard cap 5000 (source default 500 would truncate this
//     corpus' ~1.5k-term dictionary; longest-first cap would silently drop all short titles).
//
// usage:
//   node .tools/graph/unlinked-mentions.mjs [--json] [--max-titles N] [--max-hits-per-file N]
// text output:  wiki/<file>.md:<line> · <매치 문구> → 승급 후보 [[slug]]
// exit 0 always (advisory; not a gate).
import { walkDocs, deriveFields } from '../search/corpus.mjs'

const TOTAL_CAP = 2000

// ---- dictionary ------------------------------------------------------------

// docs: iterable of {slug, source, content, fm}. Returns [{term, targets:[slug…]}] sorted
// longest-first (ties: codepoint asc) — deterministic. Terms deduped case-insensitively.
export function buildDictionary(docs, { maxTitles = 5000, allBasenames = false } = {}) {
  // Noise guards (adaptation — live-vault empiric: without them the report hits the 2000 cap on
  // date fragments and research artifact filenames alone):
  //   1. date-shaped terms (any source: title/alias/basename) are never dictionary entries —
  //      "2026-06" in prose is a date, not a mention. A page whose TITLE is itself date-shaped
  //      (worklog months) is thus deliberately unreachable by this scanner.
  //   2. slug-basename terms are added for WIKI docs only — research artifact basenames are
  //      boilerplate (report/spec/INDEX/HANDOFF/…, e.g. `report` alone → 23-way ambiguous);
  //      research pages stay reachable via their fm.title. Disable both via allBasenames:true
  //      (CLI --all-basenames) for source-faithful behavior.
  const byKey = new Map() // lower(term) → {term, targets:Set}
  const add = (term, slug) => {
    const t = String(term ?? '').trim()
    if (!t) return
    const key = t.toLowerCase()
    let e = byKey.get(key)
    if (!e) { e = { term: t, targets: new Set() }; byKey.set(key, e) }
    e.targets.add(slug)
  }
  const dateLike = t => /^\d{4}([-\u2013]\d{2}([-\u2013]\d{2})?|[-\u2013]Q[1-4])$/.test(t)
  for (const doc of docs) {
    const f = deriveFields(doc)
    if (allBasenames || !dateLike(f.title)) add(f.title, doc.slug)
    for (const a of f.aliases) { if (allBasenames || !dateLike(a)) add(a, doc.slug) }
    const base = doc.slug.split('/').pop()
    if (allBasenames || (doc.source === 'wiki' && !dateLike(base))) add(base, doc.slug)
  }
  const out = [...byKey.values()].map(e => ({ term: e.term, targets: [...e.targets].sort() }))
  out.sort((a, b) => b.term.length - a.term.length || (a.term < b.term ? -1 : a.term > b.term ? 1 : 0))
  return out.slice(0, Math.max(1, Math.min(maxTitles, 5000)))
}

// ---- range helpers (faithful port) ----------------------------------------

export function mergeRanges(ranges) {
  if (!ranges.length) return []
  const s = [...ranges].sort((a, b) => a[0] - b[0] || a[1] - b[1])
  const out = [s[0]]
  for (const [a, b] of s.slice(1)) {
    const last = out[out.length - 1]
    if (a <= last[1]) last[1] = Math.max(last[1], b)
    else out.push([a, b])
  }
  return out
}

export function excludedRanges(line) {
  const ex = []
  for (const re of [/\[\[[^\]]+\]\]/g, /`[^`]*`/g, /https?:\/\/[^\s)>\]]+/g]) {
    for (const m of line.matchAll(re)) ex.push([m.index, m.index + m[0].length])
  }
  return mergeRanges(ex)
}

const inRanges = (idx, ranges) => ranges.some(([a, b]) => a <= idx && idx < b)

// ---- title pattern (whitespace-flexible; UNICODE word boundary) ------------
// Python's `\w` is Unicode by default, so the source pattern `(?<![\w#/])…(?![\w#/])` treats
// Hangul as word characters (no match inside 미결제금 for title 결제). JS `\w` is ASCII-only —
// a literal port would false-hit inside Korean compounds (critic R1). \p{L}\p{N} + u flag
// restores the source's actual semantics. Consequence (source-faithful): particle-suffixed
// mentions (패턴을) do NOT match — same as the Python original.

const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const B = '\\p{L}\\p{N}_#/'

export function titlePattern(term) {
  const parts = term.trim().split(/\s+/).filter(Boolean)
  const inner = parts.map(escRe).join('\\s+')
  return new RegExp(`(?<![${B}])${inner}(?![${B}])`, 'giu')
}

// ---- protected lines: frontmatter + fenced code (0-based line indices) -----

export function protectedLines(content) {
  const lines = String(content).split('\n').map(l => l.replace(/\r$/, '')) // CRLF-safe
  const prot = new Set()
  let i = 0
  if (lines[0] === '---') {
    prot.add(0)
    for (i = 1; i < lines.length; i++) { prot.add(i); if (lines[i] === '---') { i++; break } }
  }
  // CommonMark-style fence pairing (critic R2): a fence closes only on the SAME character with
  // length >= the opener's; other fence-ish lines inside are content (and protected anyway).
  let fence = null // {ch, len} while inside a fence
  for (; i < lines.length; i++) {
    const m = lines[i].match(/^\s*(`{3,}|~{3,})/)
    if (m) {
      prot.add(i)
      if (!fence) fence = { ch: m[1][0], len: m[1].length }
      else if (m[1][0] === fence.ch && m[1].length >= fence.len) fence = null
      continue
    }
    if (fence) prot.add(i)
  }
  return prot
}

// ---- scan ------------------------------------------------------------------

// dict entries get a lazily-built {re, first} matcher; `first` = lowercased first token used as a
// cheap includes() prefilter so we do not run ~1.5k regexes on every line.
function compileDict(dict) {
  return dict.map(e => ({
    ...e,
    re: titlePattern(e.term),
    first: e.term.trim().split(/\s+/)[0].toLowerCase(),
  }))
}

// Scan one doc. Returns hits [{file, line, column, term, match, context, targets, suggested}].
export function scanDoc(doc, compiledDict, { maxHitsPerFile = 80 } = {}) {
  const file = `wiki/${doc.slug}.md`
  const lines = String(doc.content).split('\n')
  const prot = protectedLines(doc.content)
  const hits = []
  for (let li = 0; li < lines.length && hits.length < maxHitsPerFile; li++) {
    if (prot.has(li)) continue
    const line = lines[li]
    if (!line.trim()) continue
    const lower = line.toLowerCase()
    const excl = excludedRanges(line)
    const consumed = new Array(line.length).fill(false)
    const lineHits = []
    for (const entry of compiledDict) {
      if (!lower.includes(entry.first)) continue
      const targets = entry.targets.filter(t => t !== doc.slug)
      if (!targets.length) continue // self-mention only
      entry.re.lastIndex = 0
      for (let m; (m = entry.re.exec(line)); ) {
        const [s, e] = [m.index, m.index + m[0].length]
        if (e === s) { entry.re.lastIndex++; continue }
        let overlap = false
        for (let k = s; k < e; k++) if (consumed[k]) { overlap = true; break }
        if (overlap || inRanges(s, excl) || inRanges(e - 1, excl)) continue
        for (let k = s; k < e; k++) consumed[k] = true
        lineHits.push({
          file, line: li + 1, column: s + 1,
          term: entry.term, match: m[0],
          context: line.trim().slice(0, 240),
          targets,
          suggested: targets.map(t => `[[${t}]]`).join(' | '),
        })
      }
    }
    lineHits.sort((a, b) => a.column - b.column)
    for (const h of lineHits) { if (hits.length >= maxHitsPerFile) break; hits.push(h) }
  }
  return hits
}

// Full scan: docs sorted by slug asc (deterministic), total cap 2000 (source parity).
export function scan(scanDocs, dict, { maxHitsPerFile = 80 } = {}) {
  const compiled = compileDict(dict)
  const sorted = [...scanDocs].sort((a, b) => (a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0))
  const hits = []
  let filesScanned = 0
  for (const doc of sorted) {
    filesScanned++
    for (const h of scanDoc(doc, compiled, { maxHitsPerFile })) {
      if (hits.length >= TOTAL_CAP) break
      hits.push(h)
    }
    if (hits.length >= TOTAL_CAP) break
  }
  return { ok: true, files_scanned: filesScanned, hit_count: hits.length, hits }
}

// ---- CLI -------------------------------------------------------------------

function main() {
  const argv = process.argv.slice(2)
  const json = argv.includes('--json')
  const num = (flag, def) => {
    const i = argv.indexOf(flag)
    if (i === -1 || i + 1 >= argv.length) return def
    const n = Number(argv[i + 1])
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : def
  }
  const maxTitles = num('--max-titles', 5000)
  const maxHitsPerFile = num('--max-hits-per-file', 80)
  const allBasenames = argv.includes('--all-basenames')

  const docs = [...walkDocs()]
  const dict = buildDictionary(docs, { maxTitles, allBasenames })
  const wiki = docs.filter(d => d.source === 'wiki')
  const report = scan(wiki, dict, { maxHitsPerFile })

  if (json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n')
    return
  }
  for (const h of report.hits) {
    const amb = h.targets.length > 1 ? `(모호 ${h.targets.length}) ` : ''
    process.stdout.write(`${h.file}:${h.line} · ${h.match} → 승급 후보 ${amb}${h.suggested}\n`)
  }
  process.stdout.write(`# files_scanned=${report.files_scanned} hits=${report.hit_count}\n`)
}

if (import.meta.url === `file://${process.argv[1]}`) main()
