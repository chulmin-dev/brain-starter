#!/usr/bin/env node
import { VAULT_ROOT } from '../vault-path.mjs'
// build-graph.mjs — wiki+research Obsidian link graph, now a link-core CONSUMER (RALPLAN ② §142).
//
// SSOT: node/edge set + resolution come from link-core.mjs (collectNotes + resolveLinks). No local
// parser. Behaviour:
//   default            → emit the graph JSON to STDOUT, write NOTHING (zero-write default).
//   --write-cache      → additionally persist .cache/wiki-graph.json through a reverse-bundled safe
//                        writer (recovery namespace ~/.cache/my-brain/graph-cache-recovery/<run_id>).
//
// The persisted schema { builtAt, nodes:[{id,title,type,status}], edges:[{source,target}] } is
// preserved verbatim for query-graph.mjs and other graph consumers.
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'
import { collectNotes, resolveLinks } from './link-core.mjs'

const HOME = os.homedir()

function parseArgs(argv) {
  const a = { writeCache: false, vault: null, cachePath: null, recoveryDir: null }
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i]
    if (t === '--write-cache') a.writeCache = true
    else if (t === '--vault') a.vault = argv[++i]
    else if (t === '--cache-path') a.cachePath = argv[++i]
    else if (t === '--recovery-dir') a.recoveryDir = argv[++i]
  }
  return a
}

const args = parseArgs(process.argv.slice(2))
const VAULT = args.vault || VAULT_ROOT
const GRAPH_FILE = args.cachePath || path.join(VAULT, '.cache/wiki-graph.json')
const RECOVERY_BASE = args.recoveryDir || path.join(HOME, '.cache/my-brain/graph-cache-recovery')

// coerce a frontmatter scalar (which parseFrontmatterFull may hand back as a list) to a plain string.
const str = v => (v == null ? '' : Array.isArray(v) ? String(v[0] ?? '') : String(v))
const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex')

function syncDir(dir) {
  try { const fd = fs.openSync(dir, 'r'); try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) } } catch {}
}

// atomic sibling-temp write preserving an explicit mode (mirrors note-io writeExact semantics).
function atomicWrite(target, data, mode) {
  const dir = path.dirname(target)
  fs.mkdirSync(dir, { recursive: true })
  const tmp = path.join(dir, `.${path.basename(target)}.tmp-${process.pid}-${crypto.randomBytes(6).toString('hex')}`)
  const fd = fs.openSync(tmp, 'wx', mode == null ? 0o644 : mode)
  try { fs.writeSync(fd, data, 0, data.length, 0); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
  if (mode != null) { try { fs.chmodSync(tmp, mode) } catch {} }
  try { fs.renameSync(tmp, target) } catch (e) { try { fs.unlinkSync(tmp) } catch {} ; throw e }
  syncDir(dir)
}

// Reverse-bundled single-target cache writer (RALPLAN §227/§235-246). The preimage bundle is written
// BEFORE the target is opened/truncated; on any post-rename fault the target is restored atomically,
// but only when the current bytes still hash to our postimage (else concurrent edit → recovery-required).
function writeCache(target, text, { runId, recoveryBase, nodeCount, edgeCount, command }) {
  const data = Buffer.from(text, 'utf-8')
  const postHash = sha256(data)
  const startedAt = new Date().toISOString()
  const ns = path.join(recoveryBase, runId)
  fs.mkdirSync(ns, { recursive: true, mode: 0o700 })
  try { fs.chmodSync(ns, 0o700) } catch {}

  // 1. preimage bundle first ------------------------------------------------
  let existed = false, preMode = null, preSymlink = null, preHash = null
  let st = null
  try { st = fs.lstatSync(target) } catch {}
  if (st) {
    existed = true
    if (st.isSymbolicLink()) {
      preSymlink = fs.readlinkSync(target)
    } else {
      const pre = fs.readFileSync(target)
      preHash = sha256(pre)
      preMode = st.mode & 0o777
      atomicWrite(path.join(ns, 'preimage'), pre, 0o600)
    }
  }
  const bundle = { run_id: runId, target, existed, pre_sha256: preHash, pre_mode: preMode, pre_symlink: preSymlink }
  const bundleText = JSON.stringify(bundle, null, 2) + '\n'
  atomicWrite(path.join(ns, 'bundle.json'), Buffer.from(bundleText, 'utf-8'), 0o600)
  const bundleSha = sha256(Buffer.from(bundleText, 'utf-8'))
  syncDir(ns)

  // 2. pre-hash guard + write temp+fsync+rename --------------------------------
  let status = 'applied', rollbackTrigger = null
  // pre-hash guard (plan §248c): the bundled preimage must still be live at rename time. If a
  // concurrent editor touched the target since capture → abort, write NOTHING, never clobber it.
  if (process.env._GRAPH_PREHASH_FAULT) { // selftest seam: inject a concurrent edit after capture
    try { atomicWrite(target, Buffer.from('<<external concurrent edit before rename>>\n', 'utf-8'), preMode) } catch {}
  }
  let liveExisted = false, liveHash = null, liveSymlink = null
  try {
    const lst = fs.lstatSync(target)
    liveExisted = true
    if (lst.isSymbolicLink()) liveSymlink = fs.readlinkSync(target)
    else liveHash = sha256(fs.readFileSync(target))
  } catch {}
  const drifted = liveExisted !== existed || liveHash !== preHash || liveSymlink !== preSymlink
  if (drifted) {
    status = 'aborted'; rollbackTrigger = 'pre-hash-mismatch'
  } else {
    atomicWrite(target, data, preMode)

    // fault seam (selftest only): force the rollback path after the target is in place.
    const fault = process.env._GRAPH_FAULT
    if (fault) {
      rollbackTrigger = 'injected-fault'
      // `tamper` simulates a concurrent external edit landing on our postimage before rollback reads
      // it → restore must refuse (recovery-required), never clobber the external change.
      if (fault === 'tamper') { try { atomicWrite(target, Buffer.from('<<external concurrent edit during rollback>>\n', 'utf-8'), preMode) } catch {} }
      let cur = null
      try { cur = fs.readFileSync(target) } catch {}
      if (cur != null && sha256(cur) === postHash) {
        if (existed && preHash != null) { atomicWrite(target, fs.readFileSync(path.join(ns, 'preimage')), preMode); status = 'reverted' }
        else if (!existed) { try { fs.unlinkSync(target); syncDir(path.dirname(target)) } catch {} ; status = 'reverted' }
        else status = 'recovery-required'
      } else status = 'recovery-required'
    }
  }

  const curHash = (() => { try { return sha256(fs.readFileSync(target)) } catch { return null } })()
  const receipt = {
    run_id: runId, writer: 'build-graph', owner: 'build-graph.mjs --write-cache', command,
    tool_fingerprint: sha256(fs.readFileSync(new URL(import.meta.url))),
    input_manifest_fingerprint: postHash,
    recovery_namespace: recoveryBase, bundle_path: path.join(ns, 'bundle.json'), bundle_sha256: bundleSha,
    targets: [{
      path: target, existed,
      pre_sha256: preHash, pre_mode: preMode, pre_symlink: preSymlink,
      post_sha256: postHash, post_mode: preMode, current_sha256: curHash,
    }],
    status, rollback_trigger: rollbackTrigger,
    started_at: startedAt, completed_at: new Date().toISOString(),
    semantic_counts: { nodes: nodeCount, edges: edgeCount },
  }
  atomicWrite(path.join(ns, 'receipt.json'), Buffer.from(JSON.stringify(receipt, null, 2) + '\n', 'utf-8'), 0o600)
  return receipt
}

// ---- build -----------------------------------------------------------------
const notes = collectNotes(VAULT)
const { edges } = resolveLinks(notes)
const nodes = notes.map(n => ({
  id: n.slug,
  title: str(n.fm && n.fm.title) || n.slug,
  type: str(n.fm && n.fm.type),
  status: str(n.fm && n.fm.status),
}))
const graph = { builtAt: new Date().toISOString(), nodes, edges }
const out = JSON.stringify(graph)

// default output is stdout JSON only.
process.stdout.write(out + '\n')

if (args.writeCache) {
  const runId = crypto.randomUUID()
  const receipt = writeCache(GRAPH_FILE, out + '\n', {
    runId, recoveryBase: RECOVERY_BASE, nodeCount: nodes.length, edgeCount: edges.length,
    command: 'build-graph.mjs --write-cache',
  })
  process.stderr.write(`graph: ${nodes.length} nodes, ${edges.length} edges (wiki+research) -> ${GRAPH_FILE} [${receipt.status}]\n`)
  if (receipt.status !== 'applied') process.exit(1)
} else {
  process.stderr.write(`graph: ${nodes.length} nodes, ${edges.length} edges (wiki+research) — stdout only; pass --write-cache to persist ${GRAPH_FILE}\n`)
}
