#!/usr/bin/env node
import { VAULT_ROOT } from '../vault-path.mjs'
// drift-lint.mjs — READ-ONLY fact-level drift lint for my-brain.
// 소스 무수정(읽기전용 철학, .tools/lint/lint.mjs 와 동일). 이 lint 은 절대 문서를 편집하지 않는다.
// 결정/근거: wiki/insights/brain-drift-fact-level-audit-2026-06-28.md (fact-level 전수 감사)
//          + wiki/insights/brain-search-freshness-axis-2026-06-28.md (freshness 축)
//
// 무엇을 잡나 — 의미분석 0, 기계적·값쌈 신호만(감사 §설계시사 3):
//   Detector-2 (registry, value conflict): confirmed 소스(결정 frontmatter 필드 / 회사 status)와
//     화이트리스트 허브/인덱스 본문의 stale 값 충돌. precision by construction(명시 레지스트리).
//   Detector-3 (supersedes direction): supersedes wikilink 타깃의 date 가 소스보다 *최신* 이면 INVERTED
//     (스키마: supersedes 는 더 *오래된* 문서를 가리켜야 함). prose(비-wikilink) supersedes 는 SKIP.
//   Detector-1 (index catalog row status mismatch): index-*.md 행이 명시한 status 가 링크된 캐논
//     페이지 frontmatter status 와 불일치. + 공급사(type=company·category=supplier) 카탈로그 행의
//     현생산처/후보/방문예정 마커 vs 회사 status(이건 D2-factory 와 겹쳐 default 게이트에서 demote,
//     --raw discovery 에서만 노출).
//
// ── 모드 & exit code ──
//   (default)   : 탐지 → ALLOWLIST 비교. findings==allowlist → exit 0, 불일치 → exit 1(extra/missing 출력).
//   --raw       : discovery-only. 모든 finding(카탈로그 overlap 포함) 나열, 게이트 없음, exit 0.
//   selftest    : 인라인/임시 FIXTURE 만으로 각 detector positive + negative(sibling/feed) 검증.
//   --json      : 구조화 출력(default·raw 둘 다 지원).
//   exit 2      : 예약(미사용).
//   exit 3      : 레지스트리 참조 소스 필드 누락/malformed(FAIL LOUD).
//
// ── ALLOWLIST = known-but-unfixed drift ledger (sibling drift-allowlist.json, maintainable). ──
//   findings(default-gated) must == allowlist → exit 0; extra(new drift) or missing(fixed-but-listed) → exit 1.
//   2026-06-28: ALL 7 original findings RESOLVED → allowlist now []  (clean: drift-lint --json exit 0, 0 findings).
//     * 2 HIGH (example price-hub / production-factory)  — W2 fact-correction + price reconciled-escape.
//     * 3 inverted-supersedes (consensus v1/update/r3→v2) — v2 now supersedes the 3 older; inverted lines removed.
//     * 2 index-status (interview-first 'proposed'→built / ultgoal-skill-design 'pending'→confirmed) — index rows corrected.
//
// ── CAVEATS (precision-first; recall ceiling) ──
//   * exit 0 ≠ "brain is drift-free". = "no DETECTABLE drift in the 3 detector classes within registry/
//     whitelist scope == allowlist". NOT caught: factual/missing-supersedes drift, version-axis drift
//     (e.g. index-projects ultgoal v1.0→v3.0.1), self-consistent-but-stale docs (e.g. stage4 '미커밋').
//   * D1 Class-A reads the first prose `status:` token in an index row; catalog growth could mismatch a
//     target and emit a false positive — bounded by exit-1 triage (operator prunes allowlist or fixes source).
//   * Asymmetric fail-loud: only D2 (registry source) is exit-3; D1/D3 silently skip unresolved targets/
//     dates (intentional recall trade-off — silent skip = recall gap, never a false positive).

import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const BRAIN_DEFAULT = VAULT_ROOT

const ARGV = process.argv.slice(2)
const JSON_MODE = ARGV.includes('--json')
const RAW_MODE = ARGV.includes('--raw')
const SELFTEST = ARGV.includes('selftest')

// .tools/lint/lint.mjs 와 동일 패턴 — index 행, wikilink, 인덱스 파일 글롭, 비-페이지.
const ROW_RE = /^\|\s*\[\[([^\]|#]+)\]\]\s*\|(.*)\|\s*$/
const INDEX_GLOB = /^index(-[a-z-]+)?\.md$/
const NON_PAGE = /^(index(-[a-z-]+)?|CHANGELOG|log|documents-events)\.md$/

// ── allowlist: sibling JSON (maintainable — fixes are data edits, not code edits). missing/parse-fail → [] (clean). ──
const ALLOWLIST_FILE = path.join(import.meta.dirname, 'drift-allowlist.json')
const ALLOWLIST = (() => { try { const v = JSON.parse(fs.readFileSync(ALLOWLIST_FILE, 'utf8')); return Array.isArray(v) ? v : [] } catch { return [] } })()

// Explicit vault-owner fact checks only; content-free template starts empty.
const REGISTRY = []

class RegistrySourceError extends Error {}

// ───────────────────────── 공유 파싱 ─────────────────────────

function walkMd(dir, base = dir) {
  const out = []
  if (!fs.existsSync(dir)) return out
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith('.')) continue // dotfile/dot-dir 가드 (비지식)
    const full = path.join(dir, e.name)
    if (e.isDirectory()) out.push(...walkMd(full, base))
    else if (e.name.endsWith('.md')) out.push(path.relative(base, full).split(path.sep).join('/'))
  }
  return out
}

function rawFrontmatter(text) {
  const m = text.match(/^---\r?\n([\s\S]*?)\r?\n---/)
  return m ? m[1] : ''
}

// 단순 kv frontmatter (lint.mjs 스타일). [[..]] 배열은 의도적으로 다루지 않음 — supersedes/decided_price 는
// 아래 전용 추출기로 raw 블록에서 직접 뽑는다(corpus.mjs parseFrontmatter 가 [[..]] 배열을 mangle 하므로).
function parseFrontmatter(text) {
  const raw = rawFrontmatter(text)
  const fm = {}
  for (const line of raw.split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z_]+):\s*(.*)$/)
    if (kv) fm[kv[1]] = kv[2].trim().replace(/^["']|["']$/g, '')
  }
  return fm
}

function getBody(text) {
  const m = text.match(/^---\r?\n[\s\S]*?\r?\n---\r?\n([\s\S]*)$/)
  return m ? m[1] : text
}

// raw frontmatter 에서 한 키의 값 라인(+이어지는 YAML 들여쓰기/리스트 라인) 수집.
function fmValueBlock(rawFm, key) {
  const lines = rawFm.split(/\r?\n/)
  const idx = lines.findIndex(l => new RegExp('^' + key + ':').test(l))
  if (idx < 0) return null
  let block = lines[idx].replace(new RegExp('^' + key + ':\\s*'), '')
  for (let i = idx + 1; i < lines.length; i++) {
    if (/^\s+\S/.test(lines[i]) || /^-\s/.test(lines[i])) block += '\n' + lines[i]
    else break
  }
  return block
}

// decided_price 등 비-JSON 객체를 tolerant 파싱(unquoted keys). {} 없어도 동작.
function parseTolerantObject(valStr) {
  if (valStr == null) return null
  const out = {}
  let n = 0
  for (const m of valStr.matchAll(/([A-Za-z가-힣][\w가-힣]*)\s*:\s*([0-9][\d,]*)/g)) {
    out[m[1]] = Number(m[2].replace(/,/g, ''))
    n++
  }
  return n > 0 ? out : null
}

function fmtKRW(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',') }

// stale 토큰('58,900' / '58.9k')을 숫자로 정규화 — reconciled-escape 의 live_price 일치 비교용.
function numFromToken(tok) {
  const km = String(tok).match(/^([\d.]+)\s*k$/i)
  if (km) return Math.round(parseFloat(km[1]) * 1000)
  return Number(String(tok).replace(/,/g, ''))
}

// 날짜 해석: frontmatter date → date_range 시작 → basename 의 YYYY-MM-DD → null.
function docDate(doc) {
  const d = doc.fm.date
  if (d && /^\d{4}-\d{2}-\d{2}$/.test(d)) return d
  const dr = doc.rawFm.match(/^date_range:\s*(\d{4}-\d{2}-\d{2})/m)
  if (dr) return dr[1]
  const bn = doc.basename.match(/(\d{4}-\d{2}-\d{2})/)
  return bn ? bn[1] : null
}

// 코퍼스 로드: wiki + research. 각 doc = {abs, slug, basename, isWiki, isIndex, text, fm, rawFm, body}.
function loadCorpus(brainDir) {
  const WIKI = path.join(brainDir, 'wiki')
  const RESEARCH = path.join(brainDir, 'research')
  const docs = []
  for (const rel of walkMd(WIKI)) {
    const abs = path.join(WIKI, rel)
    const text = fs.readFileSync(abs, 'utf8')
    const slug = rel.replace(/\.md$/, '')
    docs.push({ abs, slug, basename: path.basename(slug), isWiki: true, isIndex: INDEX_GLOB.test(path.basename(rel)), text, fm: parseFrontmatter(text), rawFm: rawFrontmatter(text), body: getBody(text) })
  }
  for (const rel of walkMd(RESEARCH)) {
    const abs = path.join(RESEARCH, rel)
    const text = fs.readFileSync(abs, 'utf8')
    const slug = 'research/' + rel.replace(/\.md$/, '')
    docs.push({ abs, slug, basename: path.basename(slug), isWiki: false, isIndex: false, text, fm: parseFrontmatter(text), rawFm: rawFrontmatter(text), body: getBody(text) })
  }
  const bySlug = new Map(), byBasename = new Map()
  for (const d of docs) {
    if (!bySlug.has(d.slug)) bySlug.set(d.slug, d)
    if (!byBasename.has(d.basename)) byBasename.set(d.basename, d)
  }
  return { docs, bySlug, byBasename, brainDir }
}

function resolveRef(corpus, ref) {
  let r = ref.trim().replace(/^\.\//, '')
  r = r.split('|')[0].split('#')[0].trim()
  if (corpus.bySlug.has(r)) return corpus.bySlug.get(r)
  const bn = path.basename(r)
  return corpus.byBasename.get(bn) || null
}

// ───────────────────────── Detector-2 (registry) ─────────────────────────

function detectRegistry(corpus, registry) {
  const findings = []
  for (const entry of registry) {
    if (entry.kind === 'value-conflict') {
      // 소스 필드(decided_price) tolerant 파싱 — 누락/malformed 면 FAIL LOUD.
      const srcAbs = path.join(corpus.brainDir, entry.source.rel)
      if (!fs.existsSync(srcAbs)) throw new RegistrySourceError(`[${entry.id}] source not found: ${entry.source.rel}`)
      const srcRaw = rawFrontmatter(fs.readFileSync(srcAbs, 'utf8'))
      const valStr = fmValueBlock(srcRaw, entry.source.field)
      const parsed = parseTolerantObject(valStr)
      if (!parsed) throw new RegistrySourceError(`[${entry.id}] source field '${entry.source.field}' missing/malformed in ${entry.source.rel}`)
      const currentTokens = Object.values(parsed).map(fmtKRW)
      const hits = []
      for (const t of entry.targets) {
        const tabs = path.join(corpus.brainDir, t)
        const td = corpus.bySlug.get(t.replace(/^wiki\//, '').replace(/\.md$/, ''))
        const body = td ? td.body : (fs.existsSync(tabs) ? getBody(fs.readFileSync(tabs, 'utf8')) : '')
        const found = entry.staleTokens.filter(tok => body.includes(tok))
        if (!found.length) continue
        // 가격 reconciled-escape (W2 2026-06-28): 허브 frontmatter 가 decided_price(tolerant) + 비어있지 않은
        //   pending_application 을 보유하고, (하드닝) 발견된 stale 토큰이 허브 live_price 값과 정확히 일치하면
        //   그 토큰은 '적용대기 라이브가'(구가 아님)로 화해됨 → SKIP. live_price 와 불일치하는 무관 stale
        //   가격은 blanket-accept 하지 않고 여전히 플래그.
        if (entry.reconciledIf) {
          const tRawFm = td ? td.rawFm : (fs.existsSync(tabs) ? rawFrontmatter(fs.readFileSync(tabs, 'utf8')) : '')
          const decidedObj = parseTolerantObject(fmValueBlock(tRawFm, 'decided_price'))
          const pendBlock = fmValueBlock(tRawFm, 'pending_application')
          const hasPending = pendBlock != null && pendBlock.trim() !== ''
          const liveObj = parseTolerantObject(fmValueBlock(tRawFm, 'live_price'))
          const liveNums = liveObj ? new Set(Object.values(liveObj)) : new Set()
          const foundNums = new Set(found.map(numFromToken))
          const liveMatches = !!liveObj && foundNums.size === liveNums.size && [...foundNums].every(n => liveNums.has(n))
          if (decidedObj && hasPending && liveMatches) continue
        }
        hits.push({ target: t, staleFound: found })
      }
      if (hits.length) {
        findings.push({
          id: entry.id, detector: 'D2-registry', severity: entry.severity, default: true,
          doc: hits.map(h => h.target).join(' + '),
          summary: `${entry.label}: 소스 ${entry.source.field}=${currentTokens.join('/')} 인데 허브 본문에 구값 잔존`,
          evidence: { source: entry.source.rel, currentTokens, hits },
        })
      }
    } else if (entry.kind === 'production-source') {
      // 소스 회사 status 읽기 — 누락 시 FAIL LOUD.
      const status = {}
      for (const s of entry.sources) {
        const sAbs = path.join(corpus.brainDir, s.rel)
        if (!fs.existsSync(sAbs)) throw new RegistrySourceError(`[${entry.id}] source not found: ${s.rel}`)
        const v = parseFrontmatter(fs.readFileSync(sAbs, 'utf8'))[s.field]
        if (!v) throw new RegistrySourceError(`[${entry.id}] source field '${s.field}' missing in ${s.rel}`)
        status[s.role] = v.toLowerCase()
      }
      const formerActive = ['active', 'adopted', 'confirmed', '정식'].includes(status['former-current'])
      const nowActive = ['active', 'adopted', 'confirmed', '정식'].includes(status['now-official'])
      const hits = []
      for (const t of entry.targets) {
        const td = corpus.bySlug.get(t.replace(/^wiki\//, '').replace(/\.md$/, ''))
        const body = td ? td.body : (fs.existsSync(path.join(corpus.brainDir, t)) ? getBody(fs.readFileSync(path.join(corpus.brainDir, t), 'utf8')) : '')
        const markers = []
        // former-supplier 가 '현 생산처'라 주장하는데 실제 status 가 active 가 아님 → 충돌.
        if (!formerActive && entry.currentClaim.some(re => re.test(body))) markers.push('현생산처/현공장(실제 discontinued)')
        // current-supplier 이 '후보/방문예정'이라는데 실제 active(정식) → 충돌.
        if (nowActive && entry.candidateClaim.some(re => re.test(body))) markers.push('후보/방문예정(실제 active)')
        if (markers.length) hits.push({ target: t, markers })
      }
      if (hits.length) {
        // dedup: example-project.md + index-entities.md 묶어 ONE grouped finding.
        findings.push({
          id: entry.id, detector: 'D2-registry', severity: entry.severity, default: true,
          doc: hits.map(h => h.target).join(' + '),
          summary: `${entry.label}: former-supplier=${status['former-current']}·current-supplier=${status['now-official']} 인데 옛 생산처 마커 잔존`,
          evidence: { sources: entry.sources.map(s => s.rel), hits },
        })
      }
    }
  }
  return findings
}

// ───────────────────────── Detector-3 (supersedes direction) ─────────────────────────

function detectSupersedes(corpus) {
  const findings = []
  const WIKILINK = /\[\[([^\]]+)\]\]/g
  for (const d of corpus.docs) {
    const block = fmValueBlock(d.rawFm, 'supersedes')
    if (!block) continue
    const refs = [...block.matchAll(WIKILINK)].map(m => m[1])
    if (!refs.length) continue // prose(비-wikilink) supersedes → SKIP
    const srcDate = docDate(d)
    if (!srcDate) continue
    for (const ref of refs) {
      const target = resolveRef(corpus, ref)
      if (!target) continue
      const tgtDate = docDate(target)
      if (!tgtDate) continue
      if (tgtDate > srcDate) {
        // 타깃이 더 *최신* → 역방향(supersedes 는 더 오래된 걸 가리켜야 함).
        findings.push({
          id: `supersedes-inverted-${d.basename}`, detector: 'D3-supersedes', severity: 'MED', default: true,
          doc: d.slug + '.md',
          summary: `supersedes INVERTED: ${d.basename}(${srcDate}) → ${target.basename}(${tgtDate}) — 타깃이 더 최신`,
          evidence: { source: d.slug, sourceDate: srcDate, target: target.slug, targetDate: tgtDate },
        })
      }
    }
  }
  return findings
}

// ───────────────────────── Detector-1 (index catalog row status) ─────────────────────────

function detectIndexStatus(corpus) {
  const findings = []
  const norm = s => String(s || '').trim().toLowerCase()
  for (const d of corpus.docs) {
    if (!d.isIndex) continue
    for (const line of d.text.split(/\r?\n/)) {
      const m = line.match(ROW_RE)
      if (!m) continue
      const slug = m[1].trim()
      const body = m[2]
      const target = resolveRef(corpus, slug)
      if (!target) continue

      // Class A — 행이 명시한 status (status: X / status=X) vs 타깃 frontmatter status.
      const decl = body.match(/status\s*[:=]\s*([A-Za-z]+)/)
      if (decl) {
        const declared = norm(decl[1])
        const actual = norm(target.fm.status)
        if (declared && actual && declared !== actual) {
          findings.push({
            id: `index-status-stale-${target.basename}`, detector: 'D1-index-status', severity: 'MED', default: true,
            doc: `${d.basename}.md → ${target.slug}`,
            summary: `index 행 'status: ${declared}' ≠ 타깃 frontmatter status '${actual}'`,
            evidence: { index: d.basename, slug: target.slug, declared, actual },
          })
        }
      }

      // Class B — 공급사 카탈로그 행의 현생산처/후보 마커 vs 회사 status.
      //   D2-factory 와 겹침 → default:false (--raw discovery 에서만 노출, catalog overlap).
      if (norm(target.fm.type) === 'company' && norm(target.fm.category) === 'supplier') {
        const firstSeg = body.split(/[.。→]/)[0] // 1번째 문장만(교차참조 prose 배제 → primary slug 에 결박)
        const actual = norm(target.fm.status)
        let claim = null
        if (/현\s*생산처|현\s*공장/.test(firstSeg)) claim = 'current-producer'
        else if (/후보|방문\s*예정/.test(firstSeg)) claim = 'candidate'
        if (claim === 'current-producer' && ['discontinued', 'archived', 'inactive', 'out'].includes(actual)) {
          findings.push({ id: `index-catalog-overlap-${target.basename}`, detector: 'D1-index-status', severity: 'LOW', default: false, doc: `${d.basename}.md → ${target.slug}`, summary: `index 행이 '현 생산처' 주장 but 회사 status='${actual}'`, evidence: { index: d.basename, slug: target.slug, claim, actual, overlapsWith: 'example-production-source' } })
        } else if (claim === 'candidate' && ['active', 'adopted', 'confirmed'].includes(actual)) {
          findings.push({ id: `index-catalog-overlap-${target.basename}`, detector: 'D1-index-status', severity: 'LOW', default: false, doc: `${d.basename}.md → ${target.slug}`, summary: `index 행이 '후보/방문예정' 주장 but 회사 status='${actual}'`, evidence: { index: d.basename, slug: target.slug, claim, actual, overlapsWith: 'example-production-source' } })
        }
      }
    }
  }
  return findings
}

// ───────────────────────── orchestration ─────────────────────────

function runDetectors(brainDir, registry) {
  const corpus = loadCorpus(brainDir)
  const findings = [
    ...detectRegistry(corpus, registry),
    ...detectSupersedes(corpus),
    ...detectIndexStatus(corpus),
  ]
  // 안정 정렬: detector → id
  findings.sort((a, b) => (a.detector + a.id).localeCompare(b.detector + b.id))
  return findings
}

function printDefault(findings) {
  const gated = findings.filter(f => f.default)
  const ids = gated.map(f => f.id).sort()
  const allow = [...ALLOWLIST].sort()
  const extra = ids.filter(i => !allow.includes(i))
  const missing = allow.filter(i => !ids.includes(i))
  const ok = extra.length === 0 && missing.length === 0
  const exitCode = ok ? 0 : 1
  if (JSON_MODE) {
    console.log(JSON.stringify({ mode: 'default', brain: BRAIN_DEFAULT, ok, exitCode, findingCount: gated.length, allowlist: allow, findings: gated, extra, missing }, null, 2))
  } else {
    console.log(`drift-lint (default gate) — ${gated.length} gated findings vs ${allow.length} allowlisted`)
    for (const f of gated) console.log(`  [${f.severity}] ${f.id}  (${f.detector})\n        ${f.summary}`)
    if (extra.length) console.log(`\nEXTRA (not in allowlist → drift regression?):\n  ${extra.join('\n  ')}`)
    if (missing.length) console.log(`\nMISSING (allowlisted but not found → fixed? update allowlist):\n  ${missing.join('\n  ')}`)
    console.log(ok ? '\nOK — findings == allowlist (exit 0)' : '\nMISMATCH (exit 1)')
  }
  return exitCode
}

function printRaw(findings) {
  if (JSON_MODE) {
    console.log(JSON.stringify({ mode: 'raw', brain: BRAIN_DEFAULT, findingCount: findings.length, findings }, null, 2))
  } else {
    console.log(`drift-lint (--raw discovery) — ${findings.length} findings (no gate)`)
    for (const f of findings) console.log(`  [${f.severity}] ${f.default ? 'GATE' : 'raw '} ${f.id}  (${f.detector})\n        ${f.summary}`)
  }
  return 0
}

// ───────────────────────── selftest (FIXTURES only) ─────────────────────────

function runSelftest() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-lint-selftest-'))
  const w = (rel, content) => { const p = path.join(tmp, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, content) }
  const fmDoc = (fm, body = '') => `---\n${fm}\n---\n${body}\n`

  // POSITIVE — D2 price: 소스 decided_price + 허브에 stale 토큰.
  w('wiki/decisions/fix-price-source.md', fmDoc('title: "fx price"\ntype: decision\ndate: 2026-03-01\nstatus: adopted\ndecided_price: { Alpha: 100, Beta: 200 }'))
  w('wiki/projects/fix-hub.md', fmDoc('title: "fx hub"\ntype: project\nstatus: active', '라인업: Alpha 999 / Beta 200 (구가 999 잔존)'))
  // POSITIVE — D3 inverted supersedes: 소스(older) → 타깃(newer).
  w('wiki/decisions/fix-old.md', fmDoc('title: "old"\ntype: decision\ndate: 2026-01-01\nstatus: archived\nsupersedes: [[decisions/fix-new]]'))
  w('wiki/decisions/fix-new.md', fmDoc('title: "new"\ntype: decision\ndate: 2026-02-01\nstatus: confirmed'))
  // POSITIVE — D1 index status mismatch: 행 'status: proposed' vs 타깃 built.
  w('wiki/index-fixtures.md', '# fx index\n\n| 페이지 | 요약 |\n|---|---|\n| [[decisions/fix-built]] | 어떤 결정 status: proposed 빌드 대기. |\n')
  w('wiki/decisions/fix-built.md', fmDoc('title: "built one"\ntype: decision\ndate: 2026-03-02\nstatus: built'))
  // NEGATIVE — sibling/experiment-arm 쌍 (near-dup, supersedes/registry/index 무관).
  w('research/fix-exp-2026-03-01/armA.md', fmDoc('title: "arm A"\ntype: research\ndate: 2026-03-01\nstatus: active', '실험 arm A 본문. Alpha 999 우연 등장.'))
  w('research/fix-exp-2026-03-01/armB.md', fmDoc('title: "arm B"\ntype: research\ndate: 2026-03-01\nstatus: active', '실험 arm B 본문(거의 동일). Alpha 999 우연 등장.'))
  // NEGATIVE — decision↔research feed 쌍 (source/feeds 링크지 supersedes 아님).
  w('wiki/decisions/fix-feed-decision.md', fmDoc('title: "feed dec"\ntype: decision\ndate: 2026-03-03\nstatus: confirmed\nsource: [[research/fix-feed-2026-03-03/report]]'))
  w('research/fix-feed-2026-03-03/report.md', fmDoc('title: "feed report"\ntype: research\ndate: 2026-03-03\nstatus: active\nfeeds: [[decisions/fix-feed-decision]]', '리서치 피드 본문.'))
  // NEGATIVE — 공급사 카탈로그 교차참조: primary=정식 공급사(active)인데 본문 후반부에 옛 업체 '후보' 언급.
  w('wiki/index-suppliers.md', '# sup\n\n| 페이지 | 요약 |\n|---|---|\n| [[companies/fix-good]] | 정식 생산처 (현 공장). 이전 [[companies/fix-bad]]는 후보였음 → 방문 예정이었음. |\n')
  w('wiki/companies/fix-good.md', fmDoc('title: "good supplier"\ntype: company\ncategory: supplier\nstatus: active'))
  // W2 reconciled-escape fixtures.
  // NEGATIVE — 허브가 decided_price + pending_application + 일치하는 live_price 보유 → 화해되어 미플래그.
  w('wiki/projects/fix-hub-reconciled.md', fmDoc('title: "fx hub reconciled"\ntype: project\nstatus: active\nlive_price: { Alpha: 999 }\ndecided_price: { Alpha: 100 }\npending_application: "예시 매장 실반영 대기"', '라인업(라이브가): Alpha 999 (현 매장가 — reconciled).'))
  // POSITIVE(하드닝) — decided_price + pending_application 있으나 live_price 가 stale 토큰과 불일치 → 여전히 플래그.
  w('wiki/projects/fix-hub-mismatch.md', fmDoc('title: "fx hub mismatch"\ntype: project\nstatus: active\nlive_price: { Alpha: 777 }\ndecided_price: { Alpha: 100 }\npending_application: "대기"', '라인업: Alpha 999 (무관 stale — live 는 777).'))

  const fixtureRegistry = [
    { id: 'fix-price', kind: 'value-conflict', severity: 'HIGH', label: 'fx', source: { rel: 'wiki/decisions/fix-price-source.md', field: 'decided_price' }, targets: ['wiki/projects/fix-hub.md'], staleTokens: ['999'] },
    { id: 'fix-reconciled', kind: 'value-conflict', severity: 'HIGH', label: 'fx-rec', reconciledIf: { hubField: ['decided_price', 'pending_application'] }, source: { rel: 'wiki/decisions/fix-price-source.md', field: 'decided_price' }, targets: ['wiki/projects/fix-hub-reconciled.md'], staleTokens: ['999'] },
    { id: 'fix-pending-mismatch', kind: 'value-conflict', severity: 'HIGH', label: 'fx-mm', reconciledIf: { hubField: ['decided_price', 'pending_application'] }, source: { rel: 'wiki/decisions/fix-price-source.md', field: 'decided_price' }, targets: ['wiki/projects/fix-hub-mismatch.md'], staleTokens: ['999'] },
  ]

  const findings = runDetectors(tmp, fixtureRegistry)
  const ids = new Set(findings.map(f => f.id))
  const cat = id => findings.find(f => f.id === id)

  const checks = []
  const ck = (name, pass, extra = '') => checks.push({ name, pass, extra })
  // positives
  ck('D2 price flags stale hub', ids.has('fix-price'))
  ck('D2 price reconciled-escape (decided+pending+matching live_price) does NOT flag', !ids.has('fix-reconciled'))
  ck('D2 price hardening: decided+pending but live_price MISMATCH still flags', ids.has('fix-pending-mismatch'))
  ck('D3 inverted supersedes (old→new) flags', ids.has('supersedes-inverted-fix-old'))
  ck('D1 index status (proposed vs built) flags', ids.has('index-status-stale-fix-built'))
  // negatives
  ck('sibling armA/armB does NOT flag', !findings.some(f => /arm[ab]/i.test(JSON.stringify(f.evidence))) && !ids.has('supersedes-inverted-armA') && !ids.has('supersedes-inverted-armB'))
  ck('decision↔research feed pair does NOT flag', ![...ids].some(i => /fix-feed/.test(i)))
  ck('supplier cross-ref (후보 about other) does NOT flag', !ids.has('index-catalog-overlap-fix-good'))
  // D3 must not over-flag: only the one inverted
  ck('D3 yields exactly the seeded inversion', findings.filter(f => f.detector === 'D3-supersedes').length === 1)

  // fail-loud path: malformed decided_price → RegistrySourceError (exit 3 경로).
  let failLoud = false
  try {
    runDetectors(tmp, [{ id: 'fix-bad', kind: 'value-conflict', severity: 'HIGH', label: 'x', source: { rel: 'wiki/decisions/fix-built.md', field: 'decided_price' }, targets: ['wiki/projects/fix-hub.md'], staleTokens: ['1'] }])
  } catch (e) { failLoud = e instanceof RegistrySourceError }
  ck('FAIL LOUD on malformed/missing registry source (exit 3)', failLoud)

  fs.rmSync(tmp, { recursive: true, force: true })

  const allPass = checks.every(c => c.pass)
  if (JSON_MODE) {
    console.log(JSON.stringify({ mode: 'selftest', allPass, checks }, null, 2))
  } else {
    console.log('drift-lint selftest (FIXTURES only)')
    for (const c of checks) console.log(`  ${c.pass ? 'PASS' : 'FAIL'} — ${c.name}${c.extra ? ' :: ' + c.extra : ''}`)
    console.log(allPass ? '\nselftest: ALL PASS (exit 0)' : '\nselftest: FAILURES (exit 1)')
  }
  return allPass ? 0 : 1
}

// ───────────────────────── main ─────────────────────────

function main() {
  if (SELFTEST) return runSelftest()
  let findings
  try {
    findings = runDetectors(BRAIN_DEFAULT, REGISTRY)
  } catch (e) {
    if (e instanceof RegistrySourceError) {
      if (JSON_MODE) console.log(JSON.stringify({ mode: RAW_MODE ? 'raw' : 'default', error: 'registry-source', message: e.message, exitCode: 3 }, null, 2))
      else console.error(`FAIL LOUD (exit 3): ${e.message}`)
      return 3
    }
    throw e
  }
  return RAW_MODE ? printRaw(findings) : printDefault(findings)
}

process.exit(main())
