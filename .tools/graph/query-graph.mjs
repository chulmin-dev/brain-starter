import { VAULT_ROOT } from '../vault-path.mjs'
﻿import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import Graph from 'graphology'
import { canonicalUndirectedEdges } from './link-core.mjs'

const BRAIN = VAULT_ROOT
const GRAPH_FILE = path.join(BRAIN, '.cache/wiki-graph.json')

// 허브 제외 목록 — worklog 월별 허브는 하드코딩 대신 wiki/worklog/ 실디렉토리 동적 열거 (T1.5 P11, T1 A3: 신규 월마다 목록이 낡는 문제 해소)
const WORKLOG_DIR = path.join(BRAIN, 'wiki/worklog')
const worklogHubs = fs.existsSync(WORKLOG_DIR)
  ? fs.readdirSync(WORKLOG_DIR).filter(f => /^\d{4}-(0[1-9]|1[0-2])\.md$/.test(f)).map(f => 'worklog/' + f.replace(/\.md$/, ''))
  : []
const DEFAULT_HUB_EXCLUDE = ['index', 'CHANGELOG', 'log', 'documents-events', ...worklogHubs]
const args = { mermaid: false, exclude: null, noExclude: false }
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a === '--seed') args.seed = process.argv[++i]
  else if (a === '--keyword') args.keyword = process.argv[++i]
  else if (a === '--hops') args.hops = parseInt(process.argv[++i])
  else if (a === '--max') args.max = parseInt(process.argv[++i])
  else if (a === '--mermaid') args.mermaid = true
  else if (a === '--exclude') args.exclude = process.argv[++i].split(',').map(s => s.trim())
  else if (a === '--no-exclude') args.noExclude = true
}
const excludeSet = new Set(args.noExclude ? [] : (args.exclude || DEFAULT_HUB_EXCLUDE))
const HOPS = args.hops ?? 2
const MAX = args.max ?? 25

const data = JSON.parse(fs.readFileSync(GRAPH_FILE, 'utf-8'))
// P1: a wikilink graph is undirected in meaning. This used to build `type:'directed'` and feed it
// raw `data.edges`, so a reciprocally-linked pair (A→B AND B→A) counted as TWO edges and rendered
// twice. canonicalUndirectedEdges collapses each pair to one lo/hi record; the cache file itself is
// never rewritten (read-only derivation — `data` stays exactly as loaded).
const g = new Graph({ type: 'undirected' })
for (const n of data.nodes) g.addNode(n.id, n)
for (const e of canonicalUndirectedEdges(data.edges)) { try { g.addEdge(e.source, e.target) } catch {} }

let seeds = []
if (args.seed) {
  if (g.hasNode(args.seed)) seeds = [args.seed]
} else if (args.keyword) {
  const q = args.keyword.toLowerCase()
  seeds = g.nodes().filter(n => !excludeSet.has(n) && (n.toLowerCase().includes(q) || (g.getNodeAttribute(n, 'title') || '').toLowerCase().includes(q)))
}
if (!seeds.length) { console.error('no seed found'); process.exit(1) }

const visited = new Set(seeds)
let frontier = [...seeds]
for (let h = 0; h < HOPS && visited.size < MAX; h++) {
  const next = []
  for (const node of frontier) {
    for (const neighbor of g.neighbors(node)) {
      if (excludeSet.has(neighbor)) continue
      if (!visited.has(neighbor) && visited.size < MAX) { visited.add(neighbor); next.push(neighbor) }
    }
  }
  frontier = next
  if (!next.length) break
}

const subNodes = [...visited]
const subEdges = []
for (const e of g.edges()) {
  const s = g.source(e), t = g.target(e)
  if (visited.has(s) && visited.has(t)) subEdges.push({ source: s, target: t })
}

if (args.mermaid) {
  console.log('```mermaid')
  console.log('graph LR')
  const nodeId = {}
  subNodes.forEach((n, i) => {
    nodeId[n] = `n${i}`
    const title = (g.getNodeAttribute(n, 'title') || n).slice(0, 30)
    const status = g.getNodeAttribute(n, 'status') || ''
    const label = status ? `${title}<br/>${status}` : title
    const shape = seeds.includes(n) ? `([${label}])` : `[${label}]`
    console.log(`  ${nodeId[n]}${shape}`)
  })
  for (const e of subEdges) {
    console.log(`  ${nodeId[e.source]} --> ${nodeId[e.target]}`)
  }
  console.log('```')
} else {
  console.log(JSON.stringify({ seeds, nodeCount: subNodes.length, edgeCount: subEdges.length, nodes: subNodes.slice(0, 15), edges: subEdges.slice(0, 30) }, null, 2))
}
