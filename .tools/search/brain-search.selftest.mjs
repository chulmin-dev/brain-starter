#!/usr/bin/env node
// Real router with synthetic notes; never reads a personal vault or downloads a model.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { validateFile } from '../lint/validate-write.mjs'

const vault = fs.mkdtempSync(path.join(os.tmpdir(), 'brain-starter-search-'))
const cli = path.resolve(import.meta.dirname, 'brain-search.mjs')
const note = (slug, status, text) => {
  const file = path.join(vault, 'wiki', slug + '.md')
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, `---\ntitle: ${slug}\ntype: insight\nstatus: ${status}\nsummary: synthetic routing note\n---\n${text}\n`)
}
const run = (query, flags = []) => {
  const result = spawnSync(process.execPath, [cli, query, '--json', '--explain', ...flags], {
    cwd: os.tmpdir(), encoding: 'utf8', env: { PATH: process.env.PATH, HOME: vault, MY_BRAIN_DIR: vault }
  })
  return { status: result.status, data: JSON.parse(result.stdout), stderr: result.stderr }
}
try {
  let empty = run('nothing')
  assert.equal(empty.status, 2)
  assert.deepEqual(empty.data.route.reason, ['empty-corpus'])
  assert.deepEqual(run('nothing', ['--type=project']).data.route.reason, ['filters-exclude-all'])
  note('insights/current', 'active', 'orchard harvest automation')
  note('insights/old', 'archived', 'orchard orchard orchard harvest legacy')
  note('insights/identifier', 'active', 'A body-only identifier: ENGINE_ROUTE_MAP')
  let result = run('orchard')
  assert.equal(result.status, 0)
  assert.equal(result.stderr, '', 'grep search emits no runtime warnings')
  assert.deepEqual(result.data.results.map(row => row.slug), ['insights/current'])
  result = run('ENGINE_ROUTE_MAP', ['--limit=1'])
  assert.equal(result.status, 0)
  assert.equal(result.data.route.mode, 'strong-exact')
  assert.equal(result.data.results[0].slug, 'insights/identifier')
  result = run('orchard', ['--include-archive'])
  assert.equal(result.status, 0)
  assert.deepEqual(result.data.results.map(row => row.slug), ['insights/current', 'insights/old'])
  result = run('orchard', ['--status=archived'])
  assert.equal(result.data.results[0].slug, 'insights/old')
  result = run('orchard', ['--type=nonexistent'])
  assert.equal(result.status, 2)
  assert.equal(result.data.route.mode, 'filtered-empty')
  result = run('zznonmatchingconceptzz')
  assert.equal(result.status, 0, 'a completed search with no matches succeeds')
  assert.deepEqual(result.data.results, [])
  note('insights/late-identifier', 'active', 'padding '.repeat(600) + 'BODY_ONLY_TOKEN')
  result = run('BODY_ONLY_TOKEN', ['--limit=1'])
  assert.equal(result.data.results[0].slug, 'insights/late-identifier', 'full raw search includes text beyond the preview')
  result = run('"orchard harvest"')
  assert.equal(result.data.results[0].slug, 'insights/current', 'quoted phrases preserve exact ordering')
  const crlf = path.join(vault, 'wiki/projects/windows-note.md')
  fs.mkdirSync(path.dirname(crlf), { recursive: true })
  fs.writeFileSync(crlf, '---\r\ntitle: Windows CRLF title\r\ntype: project\r\nstatus: active\r\nsummary: CRLF metadata\r\n---\r\nwindowsnewlines\r\n')
  result = run('windowsnewlines', ['--type=project', '--status=active'])
  assert.equal(result.status, 0)
  assert.equal(result.data.results[0].title, 'Windows CRLF title')
  assert.equal(result.data.results[0].summary, 'CRLF metadata')
  assert.deepEqual(validateFile(crlf, { vault }).warnings, [], 'CRLF frontmatter passes write validation')
  console.log('brain-search synthetic router: routing, empty corpus, and CRLF scenarios passed')
} finally {
  fs.rmSync(vault, { recursive: true, force: true })
}
