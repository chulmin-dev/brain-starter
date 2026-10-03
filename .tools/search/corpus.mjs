#!/usr/bin/env node
import { VAULT_ROOT } from '../vault-path.mjs'
// Shared corpus collector for keyword search and graph tools.
import fs from 'node:fs'
import path from 'node:path'

export const BRAIN = VAULT_ROOT
const WIKI = path.join(BRAIN, 'wiki')
const RESEARCH = path.join(BRAIN, 'research')
// 라우터·로그 제외 — 지식 페이지가 아닌 파일이 검색 top-10을 오염하는 것 방지.
// W4.2(R2) 분기 롤테이션 산출물(log/·changelog/의 YYYY-Qn.md)도 로그 아카이브 — lint.mjs NON_PAGE와 동형 (T1.5 P3).
export const EXCLUDE = /^(index(-[a-z-]+)?|CHANGELOG|log|documents-events|\d{4}-Q[1-4])\.md$/

export function* walkMd(dir) {
  if (!fs.existsSync(dir)) return
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith('.')) continue // dotfile guard (.ultgoal, .cache 등 비지식 디렉토리/파일)
    const full = path.join(dir, e.name)
    if (e.isDirectory()) yield* walkMd(full)
    else if (e.name.endsWith('.md')) yield full
  }
}

export function parseFrontmatter(content) {
  content = content.replace(/\r\n/g, '\n')
  const m = content.match(/^---\n([\s\S]*?)\n---/)
  if (!m) return {}
  const fm = {}
  for (const line of m[1].split('\n')) {
    const kv = line.match(/^([a-zA-Z_]+):\s*(.+)$/)
    if (!kv) continue
    let val = kv[2].trim()
    if (val.startsWith('[') && val.endsWith(']')) val = val.slice(1, -1).split(',').map(s => s.trim().replace(/['"]/g, '')).filter(Boolean)
    else val = val.replace(/^["']|["']$/g, '')
    fm[kv[1]] = val
  }
  return fm
}

export const getBody = content => {
  content = content.replace(/\r\n/g, '\n')
  const m = content.match(/^---\n[\s\S]*?\n---\n([\s\S]*)/)
  // Normalize whitespace before bounding the preview body.
  return (m ? m[1] : content).replace(/\n+/g, ' ').slice(0, 2500)
}

// Project a document into the five searchable fields used by grep-rank.
export function deriveFields(doc) {
  const fm = doc.fm || {}
  const asArr = v => (Array.isArray(v) ? v : v ? [v] : [])
  return {
    title: fm.title || doc.slug,
    aliases: asArr(fm.aliases),
    tags: asArr(fm.tags),
    summary: fm.summary || '',
    body: getBody(doc.content),
  }
}

// Wiki slugs are relative to wiki/; research slugs retain their research/ prefix.
// Graph tools receive full content so links outside the preview remain visible.
export function* walkDocs() {
  for (const full of walkMd(WIKI)) {
    if (EXCLUDE.test(path.basename(full))) continue
    const content = fs.readFileSync(full, 'utf-8').replace(/\r\n/g, '\n')
    yield { slug: path.relative(WIKI, full).split(path.sep).join('/').replace(/\.md$/, ''), source: 'wiki', content, fm: parseFrontmatter(content) }
  }
  for (const full of walkMd(RESEARCH)) {
    const content = fs.readFileSync(full, 'utf-8').replace(/\r\n/g, '\n')
    yield { slug: path.relative(BRAIN, full).split(path.sep).join('/').replace(/\.md$/, ''), source: 'research', content, fm: parseFrontmatter(content) }
  }
}

export function collectDocs() {
  const docs = []
  for (const doc of walkDocs()) {
    const f = deriveFields(doc)
    docs.push({ slug: doc.slug, source: doc.source, title: f.title, aliases: f.aliases, tags: f.tags, summary: f.summary, type: doc.fm.type || '', status: doc.fm.status || '', body: f.body })
  }
  return docs
}
