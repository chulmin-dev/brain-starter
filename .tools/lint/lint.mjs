#!/usr/bin/env node
import { VAULT_ROOT } from '../vault-path.mjs'
// my-brain 무결성 lint — warn-only, 소스 무수정 (읽기전용 철학).
// usage: node lint.mjs [--json]
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { collectNotes, resolveLinks } from '../graph/link-core.mjs'
import { sourceBindingPath } from '../graph/link-audit.mjs'
import { parseRevisitUntil } from './revisit-until.mjs'
import { scanFixtureIntegrity } from './fixture-integrity.mjs'

const BRAIN = VAULT_ROOT
const WIKI = path.join(BRAIN, 'wiki')
const JSON_MODE = process.argv.includes('--json')

const ROW_RE = /^\|\s*\[\[([^\]|#]+)\]\]\s*\|(.*)\|\s*$/
// 라우터·로그 파일 — 카탈로그 등재 의무 없음 + 지식 페이지 아님
// W4.2(R2): 분기 롤테이션 산출물(log/·changelog/의 YYYY-Qn.md)도 non-page — drift-not-indexed 오폭 방지
const NON_PAGE = /^(index(-[a-z-]+)?|CHANGELOG|log|documents-events|\d{4}-Q[1-4])\.md$/
// frontmatter 스키마 검사 대상 디렉토리 (CLAUDE.md Frontmatter 규약 정의 타입만)
const SCHEMA_DIRS = new Set(['people', 'companies', 'deals', 'legal', 'projects', 'decisions', 'insights', 'documents'])
// Advisory status enum mirrors CLAUDE.md's canonical status table.
// exact lowercase union만 검사(mixed-case·자유서술·union 밖 = warn). status 부재는 frontmatter/research-frontmatter 카테고리 소유(중복 금지).
const STATUS_WIKI_UNION = new Set(['active', 'confirmed', 'pending', 'revised', 'negotiating', 'dispute', 'pre-litigation', 'filed', 'mediation', 'judgment', 'precedent', 'paused', 'archived', 'closed', 'deprecated', 'superseded'])
const STATUS_RESEARCH = new Set(['active', 'confirmed', 'closed', 'archived', 'superseded'])
// 타입별 status subset — CLAUDE.md v2.0 §타입별 subset(각 타입 frontmatter 정의가 SSOT)의 기계 표현 (T1.5 P8, T1 A5 recall 갭 해소).
// union 검사와 동일 카테고리(status-enum)·동일 advisory 티어. union 밖이면 union warn만(중복 금지), union 안 + subset 밖이면 subset warn.
const STATUS_WIKI_SUBSET = {
  people: new Set(['active', 'closed', 'archived']),
  companies: new Set(['active', 'negotiating', 'dispute', 'closed', 'archived']),
  deals: new Set(['active', 'negotiating', 'closed', 'archived']),
  legal: new Set(['pre-litigation', 'negotiating', 'filed', 'mediation', 'judgment', 'closed', 'archived', 'precedent']),
  projects: new Set(['active', 'paused', 'closed', 'archived']),
  decisions: new Set(['active', 'confirmed', 'pending', 'revised', 'deprecated', 'superseded', 'archived']),
  insights: new Set(['active', 'archived']),
  documents: new Set(['active', 'archived']),
}
const ROW_MAX_CHARS = 200       // U1b 행 다이어트 목표
const SECTION_MAX_ROWS = 30     // index.md(라우터) 전용 — 서브인덱스는 행 캡 면제 (스펙 v0.2)
const INDEX_MAX_BYTES = 8192    // U1a 슬림 L0 목표
const SUBINDEX_MAX_BYTES = 30000 // 서브인덱스 크기 감시 (행 캡 대체)
const HEADER_MAX_BYTES = 400    // W2 가드

function walkMd(dir, base = dir) {
  const out = []
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name)
    if (e.isDirectory()) out.push(...walkMd(full, base))
    else if (e.name.endsWith('.md')) out.push(path.relative(base, full).split(path.sep).join('/'))
  }
  return out
}

function parseFrontmatter(text) {
  const m = text.match(/^---\r?\n([\s\S]*?)\r?\n---/)
  if (!m) return null
  const fm = {}
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z_]+):\s*(.*)$/)
    if (kv) fm[kv[1]] = kv[2].trim().replace(/^["']|["']$/g, '')
  }
  return fm
}

const warnings = []
// fp = 게이트 fingerprint (W2.2, §3): `카테고리|정규화 식별자`. baseline-frozen 티어만 사용.
// 가변 수치(길이·바이트)는 식별자에서 제외 — 수치 변동으로 fp가 흔들리지 않게.
const warn = (cat, msg, fp) => warnings.push({ cat, msg, fp: fp ? `${cat}|${fp}` : null })

// ---------- 1. index 파일 파싱 ----------
const indexFileNames = fs.readdirSync(WIKI).filter(f => /^index(-[a-z-]+)?\.md$/.test(f))
const indexed = new Map() // slug -> [indexFile,...]
const indexStats = {}
for (const fname of indexFileNames) {
  const text = fs.readFileSync(path.join(WIKI, fname), 'utf-8')
  const bytes = Buffer.byteLength(text, 'utf-8')
  const sections = {}
  let cur = '(no section)'
  let rowOver = 0
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('## ')) { cur = line.slice(3).trim(); continue }
    const m = line.match(ROW_RE)
    if (!m) continue
    const slug = m[1].trim()
    const summary = m[2].trim()
    sections[cur] = (sections[cur] || 0) + 1
    if (!indexed.has(slug)) indexed.set(slug, [])
    indexed.get(slug).push(fname)
    // W4.3: index-archive.md는 dormant 보관소(L0/L1.5 비로딩) — 행 다이어트 규율 목적(로딩 비용) 소멸 → row-length 면제
    if (summary.length > ROW_MAX_CHARS && fname !== 'index-archive.md') {
      rowOver++
      warn('row-length', `${fname} [[${slug}]] 요약 ${summary.length}자 (> ${ROW_MAX_CHARS})`, `${fname}:${slug}`)
    }
    // research-aware resolve: index 행이 research/를 가리키면 BRAIN 루트 기준 (broken-link 검사와 동일 — W1.1 FP 수정)
    const slugFile = slug.startsWith('research/') ? path.join(BRAIN, slug + '.md') : path.join(WIKI, slug + '.md')
    if (!fs.existsSync(slugFile))
      warn('drift-missing-file', `${fname} 행 [[${slug}]] → 파일 없음`)
  }
  for (const [sec, n] of Object.entries(sections))
    if (fname === 'index.md' && n > SECTION_MAX_ROWS)
      warn('section-cap', `${fname} §${sec} ${n}행 (> ${SECTION_MAX_ROWS} 라우터 캡)`)
  if (fname !== 'index.md' && fname !== 'index-archive.md' && bytes > SUBINDEX_MAX_BYTES) // W4.3: 보관소는 크기 감시 면제
    warn('subindex-size', `${fname} ${bytes}B (> ${SUBINDEX_MAX_BYTES}B — dormant 이동 검토)`, fname)
  indexStats[fname] = { bytes, rows: [...Object.values(sections)].reduce((a, b) => a + b, 0), sections, rowOver200: rowOver }
}

// index.md 크기 + W2 헤더
if (indexStats['index.md']) {
  if (indexStats['index.md'].bytes > INDEX_MAX_BYTES)
    warn('l0-size', `index.md ${indexStats['index.md'].bytes}B (> ${INDEX_MAX_BYTES}B 슬림 목표)`)
  const headerLine = fs.readFileSync(path.join(WIKI, 'index.md'), 'utf-8')
    .split(/\r?\n/).find(l => l.startsWith('Last updated:')) || ''
  const hb = Buffer.byteLength(headerLine, 'utf-8')
  indexStats['index.md'].headerBytes = hb // 수용 기준 2 실측 (critic MINOR-4)
  if (hb > HEADER_MAX_BYTES) warn('w2-header', `헤더 ${hb}B (> ${HEADER_MAX_BYTES}B)`)
  if (headerLine.includes('이전:')) warn('w2-header', `헤더에 '이전:' 인라인 history`)
}

// W4.2 파일 캡 30KB (advisory 티어) — 활성 로그 파일 재비대 감시 (롤테이션 아카이브는 대상 아님)
const FILE_CAP_BYTES = 30000
for (const capFile of ['log.md', 'CHANGELOG.md']) {
  const p = path.join(WIKI, capFile)
  if (fs.existsSync(p)) {
    const b = fs.statSync(p).size
    if (b > FILE_CAP_BYTES) warn('file-cap', `${capFile} ${b}B (> ${FILE_CAP_BYTES}B — 분기 롤테이션 필요: wiki/log|changelog/YYYY-Qn.md)`)
  }
}

// ---------- 2. 페이지 스캔 ----------
const allMd = walkMd(WIKI)
const pages = allMd.filter(f => !NON_PAGE.test(path.basename(f)))
const fmMissing = [], canonMissing = []
let archivedInIndex = 0, notIndexed = 0
for (const rel of pages) {
  const slug = rel.replace(/\.md$/, '')
  const text = fs.readFileSync(path.join(WIKI, rel), 'utf-8')
  const fm = parseFrontmatter(text)
  const dir = rel.split('/')[0]
  if (SCHEMA_DIRS.has(dir)) {
    if (!fm) { fmMissing.push(slug); warn('frontmatter', `${slug}: frontmatter 없음`, `${slug}:frontmatter`) }
    else {
      for (const req of ['title', 'type', 'status', 'summary'])
        if (!(req in fm)) { fmMissing.push(slug + ':' + req); warn('frontmatter', `${slug}: ${req} 누락`, `${slug}:${req}`) }
      if (!('canonical_fields' in fm)) { canonMissing.push(slug); warn('canonical', `${slug}: canonical_fields 누락`, slug) }
      if (fm.summary && fm.summary.length > 200) warn('frontmatter', `${slug}: summary ${fm.summary.length}자 (> 200)`, `${slug}:summary-length`)
      const st0 = typeof fm.status === 'string' ? fm.status : ''
      if (st0 && !STATUS_WIKI_UNION.has(st0)) warn('status-enum', `${slug}: status '${st0.slice(0, 30)}' 전역 union 밖 (live12+terminal4)`, `${slug}:status-enum`)
      else if (st0 && STATUS_WIKI_SUBSET[dir] && !STATUS_WIKI_SUBSET[dir].has(st0))
        warn('status-enum', `${slug}: status '${st0.slice(0, 30)}' ${dir} subset 밖 (전역 union 안 — 타입별 subset 위반)`, `${slug}:status-subset`)
    }
  }
  const status = fm?.status || ''
  const inIndex = indexed.has(slug)
  if (['archived', 'closed'].includes(status) && inIndex && status !== 'precedent') {
    archivedInIndex++; warn('drift-archived', `${slug} (status: ${status}) 가 index에 잔존`)
  }
  if (!['archived', 'closed'].includes(status) && !inIndex) {
    notIndexed++; warn('drift-not-indexed', `${slug} (status: ${status || '?'}) 가 어떤 index에도 없음`)
  }
}

// ---------- 3. 깨진 wikilink ----------
// research/ 1급화: wiki→research 링크(허브 등)가 유효 타깃이 되도록 existsCache에 포함 (2026-06-14)
const RESEARCH_DIR = path.join(BRAIN, 'research')
const researchMd = fs.existsSync(RESEARCH_DIR) ? walkMd(RESEARCH_DIR).map(f => 'research/' + f) : []
const existsCache = new Set([...allMd, ...researchMd].map(f => f.replace(/\.md$/, '')))
let brokenLinks = 0
// broken-link now CONSUMES link-core's resolver (SSOT, RALPLAN §143): a wiki link is "broken"
// iff link-core cannot resolve it (dangling) — no separate parser/existsCache heuristic. Scope stays
// wiki-source so the historical fingerprint `<wiki-rel-with-.md>→<verbatim>` format is preserved;
// the verbatim skip rules (raw/, http, 파일명, YYYY placeholders) carry over unchanged.
const lcNotes = collectNotes(BRAIN)
const lcBySlug = new Map(lcNotes.map(n => [n.slug, n]))
// Machine-portability guard (2026-07-26): raw/ is gitignored, so `raw/sessions/*.md` exists only on the
// machine that produced the session. link-core normalizes `[[raw/sessions/X]]` down to its last segment
// (`X`), which slips past the `startsWith('raw/')` skip below, and sourceBindingPath() only rescues it
// when the file is PHYSICALLY present. Net effect before this fix: the very same commit passed the gate
// on the authoring machine and FAILED on every other one (found on the Mac, 10 broken-link fp).
// Fix: treat a raw/-prefixed link as intentional provenance from the SOURCE TEXT, independent of
// whether that machine happens to hold the file. Non-raw dangling links stay enforced as before.
const rawPrefixed = new Set()
for (const n of lcNotes) {
  if (n.source !== 'wiki') continue
  let body = ''
  try { body = fs.readFileSync(path.join(BRAIN, 'wiki', n.slug + '.md'), 'utf8') } catch { continue }
  for (const m of body.matchAll(/\[\[\s*raw\/([^\]|#]+?)\s*(?:[|#][^\]]*)?\]\]/g)) {
    const seg = m[1].split('/').filter(Boolean).pop()
    if (seg) rawPrefixed.add(`${n.slug}\u0000${seg.replace(/\.md$/, '')}`)
  }
}
for (const d of resolveLinks(lcNotes).dangling) {
  const note = lcBySlug.get(d.from)
  if (!note || note.source !== 'wiki') continue
  const target = d.target
  if (!target || target.startsWith('raw/') || target.startsWith('http') || target.includes('파일명') || target.includes('YYYY')) continue
  // rule-11 source-binding: target이 raw/ 아래 실재 파일이면 broken이 아니라 의도적 결박 (link-audit sourceBindings와 동일 기준)
  if (sourceBindingPath(target, BRAIN)) continue
  // ...and the same binding declared as `[[raw/...]]` in the source text, even when this machine lacks the file
  if (rawPrefixed.has(`${d.from}\u0000${target}`)) continue
  const rel = d.from + '.md'
  brokenLinks++; warn('broken-link', `${rel} → [[${target}]]`, `${rel}→${target}`)
}

// ---------- 4. Research frontmatter ----------
const RESEARCH = path.join(BRAIN, 'research')
let researchMissing = 0
if (fs.existsSync(RESEARCH)) {
  for (const rel of walkMd(RESEARCH)) {
    if (rel.startsWith('.archive/')) continue // W3.2a: 종결 리서치 아카이브 — 카탈로그·7축 라벨 의무 제외
    const fm = parseFrontmatter(fs.readFileSync(path.join(RESEARCH, rel), 'utf-8'))
    if (fm && fm.name && !fm.type) continue   // 스킬/툴 매니페스트 스냅샷(name/description) = 정당히 다른 스키마, 예외
    if (!fm) { researchMissing++; warn('research-frontmatter', `research/${rel}: frontmatter 없음 (7축 라벨 필요)`, `research/${rel}:frontmatter`) }
    else for (const req of ['type', 'kind', 'domain', 'status'])
      if (!(req in fm)) { researchMissing++; warn('research-frontmatter', `research/${rel}: ${req} 누락`, `research/${rel}:${req}`) }
    if (fm && typeof fm.status === 'string' && fm.status && !STATUS_RESEARCH.has(fm.status))
      warn('status-enum', `research/${rel}: status '${fm.status.slice(0, 30)}' research subset 밖`, `research/${rel}:status-enum`)
  }
}

// ---------- 5. D6 계보 검사 (W2.1 — advisory 티어, 게이트 무관 warn) ----------
// supersedes 체인: [[..]] 타깃 실재 + 대체된 결정이 여전히 활성 status면 경고
// revisit_trigger 만료: 트리거 문구에 과거 날짜(YYYY-MM-DD)가 있으면 재검토 만료 경고
const DECISIONS_DIR = path.join(WIKI, 'decisions')
if (fs.existsSync(DECISIONS_DIR)) {
  const today = new Date().toISOString().slice(0, 10)
  for (const rel of walkMd(DECISIONS_DIR).map(f => 'decisions/' + f)) {
    const fm = parseFrontmatter(fs.readFileSync(path.join(WIKI, rel), 'utf-8'))
    if (!fm) continue
    const slug = rel.replace(/\.md$/, '')
    if (fm.supersedes) {
      for (const m of fm.supersedes.matchAll(/\[\[([^\]|#\n]+)\]\]/g)) {
        const target = m[1].trim()
        if (!existsCache.has(target)) {
          warn('supersedes', `${slug} → supersedes 타깃 [[${target}]] 파일 없음`)
        } else if (!target.startsWith('research/')) {
          const tfm = parseFrontmatter(fs.readFileSync(path.join(WIKI, target + '.md'), 'utf-8'))
          const tstatus = tfm?.status || ''
          if (!['superseded', 'archived', 'closed', 'deprecated'].includes(tstatus))
            warn('supersedes', `${slug} 가 [[${target}]] 를 대체하는데 타깃 status=${tstatus || '?'} (superseded/archived 아님)`)
        }
      }
    }
    if (fm.revisit_trigger) {
      // R9 precedence(가산): [until:] 토큰이 있으면 신규 revisit-until 검사가 그 문서를 담당하고
      // legacy bare-date 검사는 skip한다. 토큰이 없으면 아래 legacy coverage가 그대로 작동한다.
      // dedupe가 아니라 우선순위다 — token+과거 bare 날짜 문서는 신규만 발화하는 것이 의도된 설계.
      if (!/\[until:/.test(fm.revisit_trigger)) {
      const dm = fm.revisit_trigger.replace(/\[\[[^\]]*\]\]/g, ' ').match(/(\d{4}-\d{2}-\d{2})/)
      if (dm && dm[1] < today) warn('revisit', `${slug} revisit_trigger 날짜 ${dm[1]} 경과 — 재검토 필요`)
      }
      for (const issue of parseRevisitUntil(fm.revisit_trigger, today, slug))
        warn('revisit-until', issue.message)
    }
  }
}

// ---------- 5b. B-H8 재방문 범위 확장 (advisory 티어, 게이트 무관 warn) ----------
// 근거: brain-habit-audit-2026-07-30 §B-H8. 위 5번 블록은 wiki/decisions/ 96편만 순회해서
// live 상태로 30일+ 정지한 노트 163편 중 13편(8%)에만 닿았다. 나머지 150편(92%)은 구조적 미도달.
// 여기서 두 가지를 넓힌다:
//   (1) revisit_trigger 만료 검사를 research/ + wiki/ 전역으로 (기존은 decisions/ 한정)
//   (2) live status인데 30일+ 무커밋이고 [until:] 토큰이 없는 노트를 advisory로 표면화
// 원칙: WARN만. ENFORCE0·FROZEN 어느 집합에도 넣지 않는다 — 대상이 163편이라
//       게이트에 넣으면 즉시 전면 차단된다(감사 §B-H8 "실패 시 동작").
{
  const today = new Date().toISOString().slice(0, 10)
  const TERMINAL = new Set(['archived', 'closed', 'deprecated', 'superseded', 'done', 'complete', 'completed'])
  // 상시 참조 문서는 갱신이 없는 게 정상 → 정체로 보지 않는다(감사 §B-H8 "오탐 비용").
  const ALWAYS_CURRENT = new Set(['person', 'company', 'resource'])
  const STALE_DAYS = 30

  // decisions/ 는 위 5번 블록이 이미 담당 — 중복 발화 방지
  const scan = []
  for (const rel of walkMd(WIKI)) {
    if (rel.startsWith('decisions/')) continue
    scan.push({ abs: path.join(WIKI, rel), slug: rel.replace(/\.md$/, ''), repoRel: 'wiki/' + rel })
  }
  const RESEARCH_ROOT = path.join(BRAIN, 'research')
  if (fs.existsSync(RESEARCH_ROOT))
    for (const rel of walkMd(RESEARCH_ROOT))
      scan.push({ abs: path.join(RESEARCH_ROOT, rel), slug: 'research/' + rel.replace(/\.md$/, ''), repoRel: 'research/' + rel })

  // 마지막 커밋일: git 1회 호출로 전량 수집. 실패·타임아웃이면 (2)만 skip — fail-open.
  const lastCommit = new Map()
  try {
    const { execFileSync } = await import('node:child_process')
    const out = execFileSync('git', ['-c', 'core.quotepath=false', 'log', '--name-only',
      '--format=@@%ad', '--date=short', '--', 'wiki', 'research'],
      { cwd: BRAIN, encoding: 'utf-8', timeout: 10000, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] })
    let cur = null
    for (const line of out.split('\n')) {
      if (line.startsWith('@@')) cur = line.slice(2)
      else if (line.trim() && cur && !lastCommit.has(line)) lastCommit.set(line, cur)
    }
  } catch { /* git 불가 → 정체 검사만 건너뛴다 */ }

  const staleHits = []
  for (const { abs, slug, repoRel } of scan) {
    let fm = null
    try { fm = parseFrontmatter(fs.readFileSync(abs, 'utf-8')) } catch { continue }
    if (!fm) continue

    // (1) 범위 확장 — 기존 5번 블록과 동일한 판정 로직
    if (fm.revisit_trigger) {
      if (!/\[until:/.test(fm.revisit_trigger)) {
        const dm = fm.revisit_trigger.replace(/\[\[[^\]]*\]\]/g, ' ').match(/(\d{4}-\d{2}-\d{2})/)
        if (dm && dm[1] < today) warn('revisit', `${slug} revisit_trigger 날짜 ${dm[1]} 경과 — 재검토 필요`)
      }
      for (const issue of parseRevisitUntil(fm.revisit_trigger, today, slug))
        warn('revisit-until', issue.message)
      continue // 토큰이 있으면 이미 관리 대상 — (2) 대상 아님
    }

    // (2) 정체 표면화 — live status + 30일+ 무커밋 + [until:] 없음
    if (!lastCommit.size) continue
    const status = (fm.status || '').trim()
    if (!status || TERMINAL.has(status)) continue
    if (ALWAYS_CURRENT.has((fm.type || '').trim())) continue
    const last = lastCommit.get(repoRel)
    if (!last) continue
    const age = Math.floor((Date.parse(today) - Date.parse(last)) / 86400000)
    if (age >= STALE_DAYS) staleHits.push({ slug, status, last, age })
  }

  // 163편을 개별 warn으로 쏟으면 advisory가 노이즈가 된다 — 총계 1줄 + 최고령 10편만.
  if (staleHits.length) {
    staleHits.sort((a, b) => b.age - a.age)
    warn('revisit-stale', `live 상태 ${STALE_DAYS}일+ 정지 ${staleHits.length}편 — [until:YYYY-MM] 토큰으로 재방문 시점을 못 박아라`)
    for (const h of staleHits.slice(0, 10))
      warn('revisit-stale', `  ${h.slug} (status=${h.status}, 최종커밋 ${h.last}, ${h.age}일)`)
  }
}

// ---------- 6. D7 trigger-action 검사 (W3.3 — advisory 티어, 게이트 무관 warn) ----------
// v1.3 교훈 저장 강제 규칙: insights는 trigger→action 쌍 형태여야 함. 화살표(→) 부재를 휴리스틱으로 검출.
const INSIGHTS_DIR = path.join(WIKI, 'insights')
if (fs.existsSync(INSIGHTS_DIR)) {
  for (const rel of walkMd(INSIGHTS_DIR).map(f => 'insights/' + f)) {
    const text = fs.readFileSync(path.join(WIKI, rel), 'utf-8')
    const body = text.replace(/^---\r?\n[\s\S]*?\r?\n---/, '')
    if (!body.includes('→'))
      warn('trigger-action', `${rel.replace(/\.md$/, '')}: trigger→action 쌍 부재 의심 (화살표 0회 — v1.3 교훈 저장 형식)`)
  }
}

// ---------- 7. W4 source-binding 검사 (advisory 티어, 게이트 무관 warn) ----------
// New promoted decisions and insights bind source to raw/research evidence via wikilinks.
const SB_CUTOFF = '2026-07-03'
const SB_WIKILINK = /\[\[[^\]]+\]\]/
for (const sub of ['decisions', 'insights']) {
  const sbDir = path.join(WIKI, sub)
  if (!fs.existsSync(sbDir)) continue
  for (const rel of walkMd(sbDir).map(f => sub + '/' + f)) {
    const fm = parseFrontmatter(fs.readFileSync(path.join(WIKI, rel), 'utf-8'))
    if (!fm || !fm.date || !(fm.date > SB_CUTOFF)) continue // date 없거나 컷 이하 = 대상 외(소급분 스킵)
    const src = (fm.source || '').trim()
    // This checks source syntax only; Claude must read the evidence before promotion.
    if (!src || !SB_WIKILINK.test(src))
      warn('source-binding', `${rel.replace(/\.md$/, '')}: 승격 페이지 source 결박 누락/비정상 (규칙 11, 2026-07-03 이후 신규분 한정)`)
  }
}

// ---------- 9. W6 fixture 참조 무결성 (advisory 티어 — 게이트 무관 warn) ----------
// `.tools/` 커밋 fixture 중 어떤 비-fixture 소스도 참조하지 않는 파일(고아)을 읽기전용으로 검출한다.
// 판정 규칙·보수적 면제 조건의 SSOT = fixture-integrity.mjs 헤더 주석.
// **advisory 티어 고정**: 카테고리 'fixture-integrity' 는 ENFORCE0·FROZEN 어디에도 없다 →
// fp 미생성(warn 3번째 인자 없음) + `--gate` 종료코드·lint-baseline.json 바이트 불변.
// 승격(enforce-0/baseline-frozen)은 티어 표 갱신 + 별도 승인 사안이며 여기서 하지 않는다.
// 검출기 자체 실패도 게이트를 흔들지 못하게 try/catch 로 advisory warn 으로 흡수한다.
try {
  for (const f of scanFixtureIntegrity(BRAIN).findings) warn('fixture-integrity', f.message)
} catch (e) { warn('fixture-integrity', `검출기 실행 실패: ${e.message}`) }
// ---------- 출력 + 게이트 (W2.2: Q3 세션 훅 + fingerprint baseline) ----------
const counts = {}
for (const w of warnings) counts[w.cat] = (counts[w.cat] || 0) + 1
const result = { brain: BRAIN, indexFiles: indexStats, totalPages: pages.length, warningCounts: counts, totalWarnings: warnings.length }

// 티어 배정 SSOT = AGENTS.md §Lint 소유권·티어 SSOT — 이 상수는 그 표의 기계 표현
const ENFORCE0 = new Set(['drift-missing-file', 'drift-not-indexed', 'drift-archived', 'section-cap', 'l0-size', 'w2-header'])
// subindex-size는 2026-09-13 advisory로 강등(AGENTS.md 표 비고) — fp가 파일명뿐이라 동결이 성립하지 않아 사실상 enforce-0로 동작했음
const FROZEN = new Set(['frontmatter', 'canonical', 'broken-link', 'research-frontmatter', 'row-length'])
const BASELINE_PATH = path.join(BRAIN, '.tools/lint/lint-baseline.json')
const GATE = process.argv.includes('--gate')
const INIT_BASELINE = process.argv.includes('--init-baseline')
const RATCHET = process.argv.includes('--ratchet')
const frozenFps = new Set(warnings.filter(w => FROZEN.has(w.cat) && w.fp).map(w => w.fp))

if (INIT_BASELINE) {
  if (fs.existsSync(BASELINE_PATH)) { console.error('[gate] baseline 이미 존재 — 무승인 재생성 금지 (baseline migration은 승인된 wave diff 필요)'); process.exit(1) }
  const created = new Date().toISOString().slice(0, 10)
  const reviewBy = new Date(Date.now() + 90 * 86400e3).toISOString().slice(0, 10)
  fs.writeFileSync(BASELINE_PATH, JSON.stringify({
    created, review_by: reviewBy,
    notes: 'W2.2 fingerprint baseline (Q3: 신규만 차단). items=동결 fp(하향 전용 래칫 — --gate --ratchet). review_by 만료 시 advisory warn만 발생 — 운영 마찰 시 1순위 제거 후보. items 상향(추가·재작성)은 승인된 wave diff에 명시된 baseline migration만 허용.',
    items: [...frozenFps].sort()
  }, null, 2) + '\n')
  console.log(`[gate] baseline 생성: items ${frozenFps.size} (동결 fp), review_by ${reviewBy}`)
  process.exit(0)
}

if (GATE) {
  if (!fs.existsSync(BASELINE_PATH)) { console.error('[gate] FAIL: lint-baseline.json 없음 — node lint.mjs --init-baseline 필요'); process.exit(1) }
  const base = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf-8'))
  const items = new Set(base.items)
  const enforceViol = warnings.filter(w => ENFORCE0.has(w.cat))
  const newViol = warnings.filter(w => FROZEN.has(w.cat) && w.fp && !items.has(w.fp))
  const stale = base.items.filter(f => !frozenFps.has(f))
  // W3(2026-07-04) 게이트 신호 표면화: advisory 티어(ENFORCE0·FROZEN 밖) 발화 총계 1줄 — 훅 gate-last 기록용
  const advisoryTotal = warnings.filter(w => !ENFORCE0.has(w.cat) && !FROZEN.has(w.cat)).length
  console.log(`[gate] advisory 총계: ${advisoryTotal}건`)
  if (base.review_by && new Date().toISOString().slice(0, 10) > base.review_by)
    console.log(`[gate] advisory: baseline review_by ${base.review_by} 만료 — 재검토 권장`)
  if (stale.length) console.log(`[gate] 래칫 하향 가능 ${stale.length}건${RATCHET ? ' — 제거 적용' : ' (--gate --ratchet 으로 제거)'}`)
  if (RATCHET && stale.length) {
    base.items = base.items.filter(f => frozenFps.has(f))
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(base, null, 2) + '\n')
  }
  if (enforceViol.length || newViol.length) {
    console.error(`[gate] FAIL — enforce-0 위반 ${enforceViol.length}건 / baseline-frozen 신규 fp ${newViol.length}건`)
    const perCat = {}
    for (const w of newViol) { (perCat[w.cat] ||= []).push(w.fp) }
    for (const w of enforceViol) console.error(`[gate][enforce-0][${w.cat}] ${w.msg}`)
    for (const [c, fps] of Object.entries(perCat)) {
      console.error(`[gate][new-fp] ${c}: +${fps.length}건`)
      for (const f of fps) console.error(`[gate][new-fp]   ${f}`)
    }
    process.exit(1)
  }
  console.log('[gate] PASS — enforce-0 전부 0, baseline-frozen 신규 fp 0')
  process.exit(0)
}

if (JSON_MODE) {
  result.warnings = warnings
  console.log(JSON.stringify(result, null, 2))
} else {
  for (const w of warnings) console.log(`[${w.cat}] ${w.msg}`)
  console.log('---')
  for (const [f, s] of Object.entries(indexStats))
    console.log(`${f}: ${s.bytes}B, ${s.rows}행, 200자 초과 ${s.rowOver200}행`)
  console.log(`pages: ${pages.length} | warnings: ${JSON.stringify(counts)}`)
}
process.exit(0) // warn-only (기존 호출 경로 보존)