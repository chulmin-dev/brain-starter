#!/usr/bin/env node
// Grep search over wiki and research, with exact-identifier promotion and metadata filters.
import fs from 'node:fs'
import { walkDocs, collectDocs, deriveFields } from './corpus.mjs'
import { grepRank, tokenize } from './grep-rank.mjs'
const POOL = 50
const ARCHIVED_EQUIV = new Set(['archived', 'closed', 'deprecated', 'superseded']) // closed lowercase set — no substring matching, no date/mtime
const RETRO = /(archive|archived|retrospective|history|old|past)|아카이브|회고|과거|예전|이전/i

function die(code, msg) { if (msg) console.error(msg); process.exit(code) }

// Unexpected internal failures map to exit 5 (distinct from usage 1 / filters 2 / corpus 3).
const fatal = e => { try { console.error('internal error: ' + (e?.stack || e?.message || e)) } catch {}; process.exit(5) }
process.on('uncaughtException', fatal)
process.on('unhandledRejection', fatal)

// ---- arg parsing ----
const VALUE_FLAGS = new Set(['type', 'status', 'tag', 'limit', 'source'])
function parseArgs(argv) {
  const flags = {}, pos = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split(/=(.*)/s)
      if (v !== undefined) flags[k] = v                                                                  // --key=value
      else if (VALUE_FLAGS.has(k) && i + 1 < argv.length && !argv[i + 1].startsWith('--')) flags[k] = argv[++i] // --key value
      else flags[k] = true                                                                              // boolean flag
    } else pos.push(a)
  }
  return { flags, pos }
}
const csv = v => (typeof v === 'string' ? v.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : [])

const { flags, pos } = parseArgs(process.argv.slice(2))
const USAGE = 'usage: brain-search "<query>" [--type=a,b] [--status=a,b] [--tag=a,b] [--source=wiki,research] [--limit=N] [--include-archive] [--explain]'
if (flags.help || flags.h) { console.log(USAGE); process.exit(0) }

let query = pos.join(' ').trim()
if (!query) {
  try { if (!process.stdin.isTTY) query = fs.readFileSync(0, 'utf-8').trim() } catch {}
}
if (query.length > 8192) query = query.slice(0, 8192) // defensive cap (detectors run on the query string)
if (!query) die(1, 'usage: brain-search "<query>" [flags]  (empty query)')

const limit = (() => {
  if (flags.limit === undefined) return 10
  if (!/^\d+$/.test(String(flags.limit))) die(1, '--limit must be an integer 1-50')
  const n = parseInt(flags.limit, 10)
  if (n < 1 || n > 50) die(1, '--limit must be an integer 1-50')
  return n
})()
const typeF = csv(flags.type), statusF = csv(flags.status), tagF = csv(flags.tag), sourceF = [...new Set(csv(flags.source))]
if (flags.source !== undefined && sourceF.length === 0) die(1, '--source must be a comma-separated subset of wiki,research')
if (sourceF.length && sourceF.some(v => !['wiki', 'research'].includes(v))) die(1, '--source must be a comma-separated subset of wiki,research')
if (flags.expand !== undefined || flags['no-expand']) die(1, 'unknown search option; ' + USAGE)
const explain = !!flags.explain
const retroHit = RETRO.test(query)
const includeArchive = !!flags['include-archive'] || statusF.includes('archived') || retroHit
const archiveReason = flags['include-archive'] ? 'flag' : statusF.includes('archived') ? 'status-filter' : retroHit ? 'retrospective-query' : null

// ---- corpus + metadata (single walk) ----
let meta
try { meta = collectDocs() } catch (e) { die(3, 'corpus unreadable: ' + e.message) }
const metaMap = new Map(meta.map(d => [d.slug, d]))

// ---- frontmatter + archive filters -> allowed slug set ----
const norm = s => String(s || '').toLowerCase()
function passFilters(d) {
  if (!includeArchive && norm(d.status) === 'archived') return false
  if (typeF.length && !typeF.includes(norm(d.type))) return false
  if (statusF.length && !statusF.includes(norm(d.status))) return false
  if (tagF.length) { const t = (d.tags || []).map(norm); if (!tagF.some(x => t.includes(x))) return false }
  if (sourceF.length && !sourceF.includes(norm(d.source))) return false
  return true
}
const allowed = new Set(meta.filter(passFilters).map(d => d.slug))
if (allowed.size === 0) {
  emit('filtered-empty', [], 2, { filters_excluded_all: meta.length > 0 })
}

// ---- raw docs for grep (filtered, lowercased) ----
let rawDocs
try { rawDocs = [...walkDocs()] } catch (e) { die(3, 'corpus walk failed: ' + e.message) }
// Preserve full raw text so identifiers beyond the body preview remain searchable.
const grepDocs = rawDocs.filter(d => allowed.has(d.slug)).map(d => ({ slug: d.slug, text: d.content.toLowerCase(), ...deriveFields(d) }))

// ---- detectors ----
const strongDetectors = [
  ['strong:quoted', /("([^"\\]|\\.){2,}"|'([^'\\]|\\.){2,}'|`([^`\\]|\\.){2,}`)/],
  ['strong:UPPER_SNAKE', /\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/],
  ['strong:separator_identifier', /\b[A-Za-z_$][A-Za-z0-9_$]*(?:[_$][A-Za-z0-9_$]+)+\b/],
  ['strong:path_or_file', /(^|\s)(~|\.|\.\.|\/)?([A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+(\.[A-Za-z0-9]+)?(?=\s|$)/],
  ['strong:path_or_file', /\b[A-Za-z0-9_.-]+\.(md|mjs|js|ts|tsx|py|sh|json|ya?ml|html|css|sql|env|toml|lock|txt)\b/i],
  ['strong:infra_identifier', /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/],
  ['strong:infra_identifier', /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/],
  ['strong:infra_identifier', /\b(?:i|sg|subnet|ami|vpc|vol|rtb|eipalloc|nat)-[0-9a-f]{8,17}\b/i]
]
const strongReasons = [...new Set(strongDetectors.filter(([, re]) => re.test(query)).map(([reason]) => reason))]

// Quoted substrings are matched as whole phrases.
const exactTerms = [...query.matchAll(/"([^"\\]+)"|'([^'\\]+)'|`([^`\\]+)`/g)].map(m => m[1] || m[2] || m[3]).filter(Boolean)

// Exact identifiers are promoted before the bounded grep result pool.
const strongTerms = (() => {
  const out = []
  for (const [, re] of strongDetectors) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g')
    for (const m of query.matchAll(g)) { const t = m[0].trim().toLowerCase(); if (t.length >= 2) out.push(t) }
  }
  for (const t of exactTerms) { const x = t.toLowerCase(); if (x.length >= 2) out.push(x) }
  return [...new Set(out)]
})()
function exactIdentifierHits(terms) {
  if (!terms.length) return []
  const hits = []
  for (const d of grepDocs) {
    let matched = 0, total = 0
    for (const t of terms) { let c = 0, idx = d.text.indexOf(t); while (idx !== -1) { c++; idx = d.text.indexOf(t, idx + t.length) } if (c > 0) { matched++; total += c } }
    if (matched > 0) hits.push({ slug: d.slug, matched, total })
  }
  hits.sort((a, b) => b.matched - a.matched || b.total - a.total || a.slug.localeCompare(b.slug))
  return hits
}

if (process.env.BRAIN_SEARCH__FAULT === '1') throw new Error('fault-injection (selftest only)')
// ---- grep leg ----
const grepScored = grepRank(grepDocs, query, POOL, exactTerms.length ? { exactTerms } : {})
const grepScoreOf = g => +(g.distinct + Math.min(g.total, 999) / 1000).toFixed(4)

// ---- metadata keyword candidates (collectDocs metadata, not markdown-table parsing) ----

const qToks = tokenize(query)
const kwMap = new Map()
if (qToks.length) {
  for (const d of meta) {
    if (!allowed.has(d.slug)) continue
    const hay = norm(`${d.slug} ${d.title} ${(d.tags || []).join(' ')} ${d.type} ${d.status} ${d.summary}`)
    let c = 0; for (const t of qToks) if (hay.includes(t)) c++
    if (c > 0) kwMap.set(d.slug, c)
  }
}
const kwSorted = [...kwMap.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(e => e[0])

// ---- result builder ----
function mk(slug, via, score) {
  const m = metaMap.get(slug) || {}
  return { slug, source: m.source || '', title: m.title || slug, summary: (m.summary || '').slice(0, 120), tags: m.tags || [], score: typeof score === 'number' ? score : null, via }
}

// freshness demote helper: stable partition (relative order preserved inside each bucket) of a
// candidate list into live > archived-equivalent by frontmatter status (empty/undefined = live).
// Never adds a status field to result entries — fixed result key order is contractual.
function freshnessPartition(list) {
  const live = [], demoted = []
  for (const e of list) (ARCHIVED_EQUIV.has(norm(metaMap.get(e.slug)?.status)) ? demoted : live).push(e)
  return { list: live.concat(demoted), demoted: demoted.map(e => e.slug) }
}

// ---- ordering ----
const mode = strongReasons.length ? 'strong-exact' : 'grep'
const order = [], seen = new Set()
const push = (slug, via, score) => { if (!seen.has(slug)) { seen.add(slug); order.push(mk(slug, via, score)) } }
const replaceOrder = list => {
  order.length = 0
  seen.clear()
  for (const row of list) { if (!seen.has(row.slug)) { seen.add(row.slug); order.push(row) } }
}

if (strongReasons.length) {
  for (const g of exactIdentifierHits(strongTerms)) push(g.slug, 'grep', +(g.matched + Math.min(g.total, 999) / 1000).toFixed(4))
}
for (const g of grepScored) push(g.slug, 'grep', grepScoreOf(g))
for (const slug of kwSorted) push(slug, 'keyword', null)

// Freshness stable-partitions the complete primary order. Strong-exact remains exempt.
let freshnessDemoted = []
if (includeArchive && mode !== 'strong-exact') {
  const p = freshnessPartition(order)
  replaceOrder(p.list)
  freshnessDemoted = p.demoted
}

const results = order.slice(0, limit)
emit(mode, results, 0, {
  detectors: { strong: strongReasons },
  exact_terms: exactTerms,
  archive_reason: archiveReason,
  leg_counts: { grep: grepScored.length, keyword: kwMap.size },
  freshness_demoted: freshnessDemoted,
})

// ---- output ----
function emit(mode, results, exitCode, explainData) {
  const filters = sourceF.length
    ? { type: typeF, status: statusF, tag: tagF, source: sourceF, include_archive: !!flags['include-archive'], effective_include_archive: includeArchive }
    : { type: typeF, status: statusF, tag: tagF, include_archive: !!flags['include-archive'], effective_include_archive: includeArchive }
  const out = {
    schema_version: 1,
    query,
    limit,
    filters,
    route: {
      mode,
      reason: mode === 'strong-exact' ? strongReasons : mode === 'filtered-empty'
        ? [meta.length === 0 && !typeF.length && !statusF.length && !tagF.length && !sourceF.length ? 'empty-corpus' : 'filters-exclude-all']
        : ['none'],
      legs: { grep: mode === 'filtered-empty' ? 'skipped' : 'ok' }
    },
    results
  }
  if (explain && explainData) out.explain = explainData
  process.stdout.write(JSON.stringify(out, null, 2) + '\n')
  process.exit(exitCode)
}

