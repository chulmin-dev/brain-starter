#!/usr/bin/env node
import { VAULT_ROOT } from '../vault-path.mjs'
// validate-write.mjs — write-time 7-axis / representative-cluster validator (RALPLAN ③ §174-182, §302-308).
//
// Consumed as a PostToolUse (Write|Edit|MultiEdit) validator: given ONE file path, it emits fixed
// warning CODES to stderr and exits 1 (warn), or stays silent and exits 0. It NEVER blocks or
// rewrites the target — warn-not-block. The write it observes has already been committed by the tool.
//
// SSOT: the representative predicate, cluster classification and frontmatter parsing all come from
// link-core.mjs (the single resolver). This module adds ONLY (1) the write-time scope gate + fixed
// warning codes and (2) a cluster-scoped corpus loader so a single-file check does not need a
// full-vault collectNotes (perf target: target p95 <= 1s). Because the predicate/cluster codes are
// re-exported from link-core, the operational superset stays in lock-step automatically.
//
// Checks (research notes unless noted):
//   (a) scope: only .md inside the vault; raw/templates/_export/.obsidian/.git/.trash/.tools/.cache/
//       node_modules and any dotdir are skipped SILENTLY; wiki index/CHANGELOG/log/documents-events too.
//   (b) missing frontmatter → a SINGLE `no-frontmatter` warning, then short-circuit.
//   (c) research: the 7 required axes (type/kind/domain/topic/project/status/summary) → `axis-missing:<field>`.
//   (d) representative → wiki-knowledge body link, subordinate → representative binding: the verbatim
//       link-core classifyCluster warning code (representative-missing-knowledge-link /
//       missing-representative-link / cluster-no-representative / cluster-representative-ambiguous).
//   (e) `graph: standalone` + non-empty `standalone_reason` exempts (d) — handled inside classifyCluster.
//   (f) wiki notes get the basic frontmatter-presence check only.
//   (g) misplaced knowledge dir: a vault-ROOT <knowledge-dir>/... .md (e.g. insights/x.md instead of
//       wiki/insights/x.md) → a SINGLE `misplaced-note:wiki/<rel>` warning, then short-circuit
//       (mislocated-write incident class; content checks are pointless in a wrong tree).
//
// warn-not-block: an internal fault is swallowed to a SILENT exit 0 on purpose (contract §182/§305) —
// a validator must never disrupt a successful write. Set BRAIN_VALIDATE_DEBUG=1 to surface the fault
// on stderr while still exiting 0.
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { fileURLToPath } from 'node:url'
import { readExact } from '../graph/note-io.mjs'
import { parseFrontmatterFull, representativePredicate, clusterOf, classifyCluster } from '../graph/link-core.mjs'

// Directory-skip constants mirror link-core (SKIP_DIRS / WIKI_EXCLUDE / KNOWLEDGE_DIRS) which are not
// exported there. Kept literally in sync so the write-time corpus view matches the resolver's.
const SKIP_DIRS = new Set(['.git', '.obsidian', '.trash', '.tools', '.cache', 'node_modules', 'raw', 'templates', '_export'])
const WIKI_EXCLUDE = /^(index(-[a-z-]+)?|CHANGELOG|log|documents-events)\.md$/
const KNOWLEDGE_DIRS = ['decisions', 'insights', 'projects', 'people', 'companies', 'deals', 'legal', 'resources']
const AXES = ['type', 'kind', 'domain', 'topic', 'project', 'status', 'summary']

function vaultRoot() {
  return path.resolve(VAULT_ROOT)
}

const relSlashes = rel => rel.split(path.sep).join('/')

// Mirror link-core.collectNotes' note shape so classifyCluster's internal buildIndex / resolvedTargets
// see identical objects. content is strict UTF-8 (readExact); non-UTF-8 → content:null, readable:false.
function makeNote(file, slug, source) {
  const content = readExact(file)?.replace(/\r\n/g, '\n') ?? null
  return { slug, source, file, content, fm: content == null ? {} : parseFrontmatterFull(content), readable: content != null }
}

// Deterministic recursive .md walk that skips dotfiles + SKIP_DIRS (mirrors link-core.walkMd).
function* walkMd(dir) {
  let ents
  try { ents = fs.readdirSync(dir, { withFileTypes: true }) } catch { return }
  ents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  for (const e of ents) {
    if (e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue
    const full = path.join(dir, e.name)
    if (e.isDirectory()) yield* walkMd(full)
    else if (e.name.endsWith('.md')) yield full
  }
}

// Classify the written path: { skip:true } when out of scope, else { source, slug }.
export function classifyTarget(absFile, vault) {
  if (!absFile.endsWith('.md')) return { skip: true }
  // Canonicalize both sides so a physical-path write (e.g. /mnt/c/.../my-brain/... reached via a
  // ${MY_BRAIN_DIR} symlink) resolves inside the vault instead of being silently skipped by a
  // lexical path.relative producing a '..'-prefixed rel (Architect MEDIUM1). realpathSync throws on a
  // non-existent leaf → fall back to the lexical absolute path so genuinely out-of-vault inputs skip.
  const canon = p => { try { return fs.realpathSync(p) } catch { return path.resolve(p) } }
  const rel = path.relative(canon(vault), canon(absFile))
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return { skip: true } // outside the vault
  const segs = rel.split(path.sep)
  for (let i = 0; i < segs.length - 1; i++) {
    if (segs[i].startsWith('.') || SKIP_DIRS.has(segs[i])) return { skip: true } // excluded / dot directory
  }
  const base = segs[segs.length - 1]
  if (segs[0] === 'wiki') {
    if (WIKI_EXCLUDE.test(base)) return { skip: true }
    return { source: 'wiki', slug: segs.slice(1).join('/').replace(/\.md$/, '') }
  }
  if (segs[0] === 'research') {
    return { source: 'research', slug: 'research/' + segs.slice(1).join('/').replace(/\.md$/, '') }
  }
  if (segs.length >= 2 && KNOWLEDGE_DIRS.includes(segs[0])) {
    // (g) knowledge dir mirrored at the vault root — the canonical home is wiki/<same path>.
    return { source: 'misplaced', slug: relSlashes(rel).replace(/\.md$/, ''), expected: 'wiki/' + relSlashes(rel).replace(/\.md$/, '') }
  }
  return { skip: true } // any other vault .md outside wiki/ and research/ is not a knowledge note
}

// Minimal corpus needed to reproduce classifyCluster's output for ONE research note WITHOUT a full
// collectNotes: the note's cluster directory (candidates + subordinate→representative resolution) plus
// — only when the note itself is a representative candidate — the wiki knowledge dirs (so its body
// knowledge link can resolve). A subordinate never needs the wiki corpus. Returns null for non-research.
export function clusterScopeNotes(vault, targetNote) {
  const { clusterKey } = clusterOf(targetNote)
  if (clusterKey == null) return null
  const bySlug = new Map()
  const add = n => { if (n && n.slug && !bySlug.has(n.slug)) bySlug.set(n.slug, n) }
  const RESEARCH = path.join(vault, 'research')
  if (clusterKey.startsWith('research/@root/')) {
    // root singleton: no sibling guessing — only this file shares the cluster key (§163/§168).
    add(targetNote)
  } else {
    // topdir cluster research/<topdir>: every descendant shares the key (§166). Scan just that subtree.
    const topdir = clusterKey.slice('research/'.length)
    for (const file of walkMd(path.join(RESEARCH, topdir))) {
      const slug = 'research/' + relSlashes(path.relative(RESEARCH, file)).replace(/\.md$/, '')
      add(makeNote(file, slug, 'research'))
    }
  }
  bySlug.set(targetNote.slug, targetNote) // force the just-written target's fresh content to be authoritative
  if (representativePredicate(targetNote)) {
    const WIKI = path.join(vault, 'wiki')
    for (const kd of KNOWLEDGE_DIRS) {
      for (const file of walkMd(path.join(WIKI, kd))) {
        if (WIKI_EXCLUDE.test(path.basename(file))) continue
        const slug = relSlashes(path.relative(WIKI, file)).replace(/\.md$/, '')
        add(makeNote(file, slug, 'wiki'))
      }
    }
  }
  return [...bySlug.values()]
}

// Validate one file. Returns { warnings: [{slug, code}], skipped }. Never throws for expected inputs;
// the internal-error seam (_VALIDATE_FORCE_ERROR) exists only to exercise the CLI's swallow path.
export function validateFile(absFile, opts = {}) {
  if (process.env._VALIDATE_FORCE_ERROR) throw new Error('forced internal error (selftest seam)')
  const vault = opts.vault ? path.resolve(opts.vault) : vaultRoot()
  const abs = path.resolve(absFile)
  const t = classifyTarget(abs, vault)
  if (t.skip) return { warnings: [], skipped: true }
  if (t.source === 'misplaced') {
    // (g) wrong tree entirely — one placement warning, no content checks.
    return { warnings: [{ slug: t.slug, code: `misplaced-note:${t.expected}` }], skipped: false }
  }

  const content = readExact(abs)?.replace(/\r\n/g, '\n') ?? null
  if (content == null) return { warnings: [], skipped: true } // missing / non-UTF-8 → nothing to validate

  const slug = t.slug
  const warnings = []

  // (b) frontmatter presence — single warning + short-circuit (same delimiter regex as parseFrontmatterFull)
  if (!/^---\n[\s\S]*?\n---/.test(content)) {
    warnings.push({ slug, code: 'no-frontmatter' })
    return { warnings, skipped: false }
  }

  const fm = parseFrontmatterFull(content)

  // (f) wiki: basic frontmatter-presence check only.
  if (t.source === 'wiki') return { warnings, skipped: false }

  // (c) research: the 7 required axes.
  for (const ax of AXES) {
    const v = fm[ax]
    const missing = v == null || (typeof v === 'string' && v.trim() === '') || (Array.isArray(v) && v.length === 0)
    if (missing) warnings.push({ slug, code: `axis-missing:${ax}` })
  }

  // (d)/(e) representative & subordinate binding via link-core (standalone exemption handled internally).
  const targetNote = { slug, source: 'research', file: abs, content, fm, readable: true }
  const notes = clusterScopeNotes(vault, targetNote)
  if (notes) {
    const res = classifyCluster(targetNote, notes)
    if (res && res.warning) warnings.push({ slug, code: res.warning })
  }
  return { warnings, skipped: false }
}

// Realpath-compare both sides so a symlinked invocation (e.g. ${MY_BRAIN_DIR} → /mnt/c/...) still
// detects direct execution; a plain argv[1]/import.meta.url compare silently no-ops under symlinks.
function isMain() {
  try { return process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)) } catch { return false }
}

if (isMain()) {
  let code = 0
  try {
    const file = process.argv[2]
    if (file) {
      const { warnings } = validateFile(file)
      if (warnings.length) {
        for (const w of warnings) process.stderr.write(`[brain-validate-write] ${w.slug}: ${w.code}\n`)
        code = 1
      }
    }
  } catch (e) {
    // warn-not-block: a validator fault must NEVER disrupt the (already committed) write → silent exit 0.
    if (process.env.BRAIN_VALIDATE_DEBUG) process.stderr.write(`[brain-validate-write] internal-error: ${e && e.message}\n`)
    code = 0
  }
  process.exit(code)
}
