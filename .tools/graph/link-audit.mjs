#!/usr/bin/env node
// link-audit.mjs — the ONE audit surface over link-core (RALPLAN ② §138). It is the canonical
// (정본) owner of orphan/dangling and emits the node/edge/metadata JSON that the operational Python
// connectivity checker CONSUMES instead of carrying its own resolver.
//
// Default = `--json` to stdout, ZERO writes (no cache, no recovery namespace) — a pure observation
// surface (plan §186 default-command matrix row `link-audit --json`).
//
//   node link-audit.mjs --vault <dir>   # audit JSON to stdout (default, zero-write)
//
// Schema (frozen v1, coordinated with connectivity_check.py consumer):
//   schema:1
//   nodes:[{slug, source, readable, standalone, standaloneReason, project}]   (research metadata only)
//   edges:[{source,target}]                                                   (resolveLinks verbatim)
//   dangling:[{from,target}] + danglingDistinct:[{target,occurrences,froms[]}]
//   sourceBindings:[{from,target,path}]  (rule-11 raw/ provenance links split OUT of dangling)
//   ambiguous:[{from,target,candidates[]}]
//   unreadable:[slug]
//   orphans:[slug]  degree:{slug:{in,out}}  topHubs:[{slug,degree,in,out}]
//   dualBinding:{missing[],bodyOnly[],unresolved[],counts}
//   clusters:{classifications, warnings, representatives:{clusterKey:[slug]}}
//   representatives:{clusterKey:[slug]}   (per-cluster candidate map; suggest "대표편 경유")
//   representativeNotes:[slug]            (flat representativePredicate satisfiers)
//   counts:{...}
//
// Slugs are 2-base bare: wiki `decisions/foo` (no `wiki/`), research `research/topic/report`.
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import {
  collectNotes, resolveLinks, dualBinding, representativePredicate, classifyCluster,
  canonicalUndirectedEdges, connectivityComponents,
} from './link-core.mjs'
import { VAULT_ROOT } from '../vault-path.mjs'

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0)
const cmpFromTarget = (a, b) => cmp(a.from, b.from) || cmp(a.target, b.target)

// First `project` frontmatter token, brackets/quotes/alias stripped → canonical string | null.
function firstProject(fm) {
  let v = fm && fm.project
  if (Array.isArray(v)) v = v[0]
  if (typeof v !== 'string') return null
  let t = v.trim().replace(/^["']|["']$/g, '').replace(/^\[\[+/, '').replace(/\]\]+$/, '').split('|')[0].trim()
  return t || null
}

// Rule 11 (source-binding provenance) — CLAUDE.md §11. The vault's raw/ tree (session transcripts,
// meeting captures) is DELIBERATELY excluded from the link-core corpus (SKIP_DIRS), so a body wikilink
// like [[raw/sessions/session-source]] — a source binding to raw/sessions/<target>.md that
// PHYSICALLY EXISTS on disk — resolves to `dangling` even though nothing is broken. It is a source
// pointer, not a dead link. We re-derive the on-disk truth with a direct fs probe (the corpus never
// walks raw/) and split these OUT of dangling so triage never mis-judges them. Live incident (Wave 4):
// 13 such rule-11 links were flagged DELETE by the triage LLM; the lead rejected them by hand.
// Returns the vault-relative raw/ path on a hit (raw/sessions|meetings/<t>.md, raw/<t>.md, raw/<t>),
// else null. `target` is the verbatim last-path-component that resolveLinks reports as dangling.
export function sourceBindingPath(target, vaultDir) {
  if (!vaultDir) return null
  const t = String(target).trim()
  if (!t || t.includes('/') || t.includes('\\') || t.includes('..')) return null // last-component only
  const raw = path.join(path.resolve(vaultDir), 'raw')
  for (const rel of [`sessions/${t}.md`, `meetings/${t}.md`, `${t}.md`, t]) {
    const full = path.join(raw, rel)
    if (full !== raw && !full.startsWith(raw + path.sep)) continue // never escape raw/
    try { if (fs.statSync(full).isFile()) return path.join('raw', rel) } catch {}
  }
  return null
}

export function buildAudit(notes, opts = {}) {
  const vaultDir = opts.vaultDir || null
  const { edges, dangling: rawDangling, ambiguous, unreadable } = resolveLinks(notes)
  // Rule-11 split (see sourceBindingPath): pull raw/ provenance pointers that PHYSICALLY resolve out of
  // dangling BEFORE any distinct/count/downstream (triage/report) consumer sees them. Only when a
  // vaultDir is supplied (CLI passes it); without it the audit is a pure resolveLinks passthrough so
  // every existing caller (and the golden fixtures) keep byte-identical output.
  const sourceBindings = []
  const dangling = []
  for (const d of rawDangling) {
    const rel = vaultDir ? sourceBindingPath(d.target, vaultDir) : null
    if (rel) sourceBindings.push({ from: d.from, target: d.target, path: rel })
    else dangling.push(d)
  }
  sourceBindings.sort((a, b) => cmpFromTarget(a, b) || cmp(a.path, b.path))
  const sourceBindingsDistinct = [...new Set(sourceBindings.map(b => b.target))].length
  // bodyEdges — resolveLinks over frontmatter-stripped copies. Connectivity BFS
  // consumes THIS set (frontmatter feeds/related do not render in Obsidian's
  // graph — the satellite-invariant); `edges` (full content) stays the
  // graph-cache set. Mirrors connectivity_check.py's link-core-direct fallback.
  const stripFm = c => { if (c == null) return null; c = c.replace(/\r\n/g, '\n'); const m = c.match(/^---\n[\s\S]*?\n---\n?([\s\S]*)$/); return m ? m[1] : c }
  const { edges: bodyEdges } = resolveLinks(notes.map(n => ({ ...n, content: stripFm(n.content) })))

  // degree / orphans / hubs -------------------------------------------------
  const degree = {}
  for (const n of notes) degree[n.slug] = { in: 0, out: 0 }
  for (const e of edges) { if (degree[e.source]) degree[e.source].out++; if (degree[e.target]) degree[e.target].in++ }
  const orphans = notes.filter(n => degree[n.slug].in === 0 && degree[n.slug].out === 0).map(n => n.slug).sort(cmp)

  // P2: body-basis orphan views. `orphans` above is FULL-edge degree (frontmatter feeds/related
  // included); `bodyOrphans` is what Obsidian's graph actually renders. The two answer different
  // questions and the contract binds them: orphans ⊆ bodyOrphans.
  const bodyDegree = {}
  for (const n of notes) bodyDegree[n.slug] = 0
  for (const e of bodyEdges) {
    if (e.source === e.target) continue
    if (bodyDegree[e.source] !== undefined) bodyDegree[e.source]++
    if (bodyDegree[e.target] !== undefined) bodyDegree[e.target]++
  }
  const bodyOrphans = notes.filter(n => bodyDegree[n.slug] === 0).map(n => n.slug).sort(cmp)
  // Isolated in the body graph yet bound through frontmatter only — invisible in Obsidian.
  const frontmatterOnlyBound = bodyOrphans.filter(x => !orphans.includes(x))
  // Producer-side invariant. A full-degree-0 note cannot carry a body edge; if it does, an upstream
  // extractor is miscounting (this is exactly how the stripCode newline-spanning bug surfaced).
  const invariantViolations = orphans.filter(o => !bodyOrphans.includes(o))
  if (invariantViolations.length) {
    throw new Error(`link-audit invariant violated: orphans ⊄ bodyOrphans (${invariantViolations.length}): ${invariantViolations.slice(0, 5).join(', ')}`)
  }
  const topHubs = Object.entries(degree)
    .map(([slug, d]) => ({ slug, degree: d.in + d.out, in: d.in, out: d.out }))
    .filter(x => x.degree > 0)
    .sort((a, b) => b.degree - a.degree || cmp(a.slug, b.slug))
    .slice(0, 15)

  // dangling distinct -------------------------------------------------------
  const distMap = new Map()
  for (const d of dangling) {
    const e = distMap.get(d.target) || { target: d.target, occurrences: 0, froms: [] }
    e.occurrences++; e.froms.push(d.from); distMap.set(d.target, e)
  }
  const danglingDistinct = [...distMap.values()]
    .map(e => ({ target: e.target, occurrences: e.occurrences, froms: [...new Set(e.froms)].sort(cmp) }))
    .sort((a, b) => cmp(a.target, b.target))

  // nodes (+ research metadata for the Python consumer) ---------------------
  const nodes = notes.map(n => {
    const base = { slug: n.slug, source: n.source, readable: n.readable, standalone: false, standaloneReason: null, project: null }
    if (n.source === 'research') {
      const db = dualBinding(n)
      base.standalone = db.standalone
      base.standaloneReason = db.standaloneReason
      base.project = firstProject(n.fm)
    }
    return base
  })

  // dual-binding aggregate --------------------------------------------------
  const db = { missing: [], bodyOnly: [], unresolved: [] }
  for (const n of notes) {
    if (n.source !== 'research') continue
    const d = dualBinding(n)
    for (const t of d.missing) db.missing.push({ from: n.slug, target: t })
    for (const t of d.bodyOnly) db.bodyOnly.push({ from: n.slug, target: t })
    for (const t of d.unresolved) db.unresolved.push({ from: n.slug, target: t })
  }
  db.missing.sort(cmpFromTarget); db.bodyOnly.sort(cmpFromTarget); db.unresolved.sort(cmpFromTarget)
  db.counts = { missing: db.missing.length, bodyOnly: db.bodyOnly.length, unresolved: db.unresolved.length }

  // clusters + representatives ---------------------------------------------
  const classifications = { representative: 0, subordinate: 0, 'not-applicable': 0 }
  const warnings = {}
  const clusterMap = new Map()
  for (const n of notes) {
    if (n.source !== 'research') continue
    const cc = classifyCluster(n, notes)
    classifications[cc.classification] = (classifications[cc.classification] || 0) + 1
    if (cc.warning) warnings[cc.warning] = (warnings[cc.warning] || 0) + 1
    if (cc.clusterKey && !clusterMap.has(cc.clusterKey)) clusterMap.set(cc.clusterKey, cc.candidates.slice().sort(cmp))
  }
  const representatives = {}
  for (const k of [...clusterMap.keys()].sort(cmp)) representatives[k] = clusterMap.get(k)
  const representativeNotes = notes.filter(n => n.source === 'research' && representativePredicate(n)).map(n => n.slug).sort(cmp)

  const counts = {
    nodes: nodes.length,
    readable: nodes.filter(n => n.readable).length,
    unreadable: unreadable.length,
    edges: edges.length,
    danglingOccurrences: dangling.length,
    sourceBindings: sourceBindings.length,
    sourceBindingsDistinct,
    danglingDistinct: danglingDistinct.length,
    ambiguous: ambiguous.length,
    orphans: orphans.length,
    dualBinding: db.counts,
    clusters: { classifications, warnings },
  }

  return {
    schema: 1,
    counts,
    nodes,
    edges,
    bodyEdges,
    dangling,
    sourceBindings,
    danglingDistinct,
    ambiguous,
    unreadable,
    orphans,
    degree,
    topHubs,
    dualBinding: db,
    clusters: { classifications, warnings, representatives },
    representatives,
    representativeNotes,
    // P1: canonical UNDIRECTED views. Additive and OPTIONAL — every pre-existing field above
    // (edges/bodyEdges/degree/orphans/counts.edges) keeps its exact prior bytes, so existing
    // consumers are untouched. Names carry full/body because the two bases answer different
    // questions: `edges` includes frontmatter feeds/related, `bodyEdges` is what Obsidian renders.
    canonicalFullEdges: canonicalUndirectedEdges(edges),
    canonicalBodyEdges: canonicalUndirectedEdges(bodyEdges),
    // P2: body-basis connectivity. `isolatedNodeCount` is carried on the components object so a
    // consumer reading only that object still sees the isolated count without re-deriving it.
    bodyOrphans,
    frontmatterOnlyBound,
    components: { ...connectivityComponents(bodyEdges, crypto), isolatedNodeCount: bodyOrphans.length },
  }
}

// ---- CLI -------------------------------------------------------------------

function main() {
  const argv = process.argv.slice(2)
  let vault = VAULT_ROOT
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--vault') vault = argv[++i]
    // --json is the default and only output mode; accepted as a no-op for explicitness.
  }
  const notes = collectNotes(vault)
  process.stdout.write(JSON.stringify(buildAudit(notes, { vaultDir: vault }), null, 2) + '\n')
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
