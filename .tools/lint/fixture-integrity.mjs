#!/usr/bin/env node
// fixture-integrity.mjs — 도구 트리 커밋 fixture 참조 무결성 판독기 (V2 W6).
//
// 티어: **advisory 전용(고정)**. lint.mjs 는 결과를 카테고리 'fixture-integrity' 로 warn 하고
// fingerprint 를 만들지 않는다(fp=null). ENFORCE0·FROZEN 어디에도 등재하지 않는다 —
// 즉 `--gate` 종료코드와 lint-baseline.json 바이트에 어떤 영향도 주지 않는다.
// 티어 승격(enforce-0/baseline-frozen)은 별도 승인 사안이며 이 파일에서 결정하지 않는다.
//
// 정본 계약:
//   - 순수·읽기전용: fs 읽기만 한다. 쓰기/이동/삭제 API 미사용, 네트워크·시계·cwd·env 미접촉
//     (root 는 호출자가 주입). 같은 트리 → 같은 출력.
//   - 결정적: 디렉토리 나열은 이름 정렬 후 순회, 출력 정렬은 code-unit 비교(cmp)만 사용.
//     localeCompare 금지(로케일 의존 = 머신별 출력 흔들림).
//   - 읽기 실패는 조용한 성공이 아니라 advisory finding 으로 표면화한다
//     (kind='read-error'), 스캔 가드(크기·바이너리)에 걸린 소스도 표면화한다(kind='source-unscanned').
//
// fixture 판정: 도구 루트(TOOLS_DIR) 하위에서 경로 세그먼트에 FIXTURE_DIR_NAME 이 있고
// **그 아래**에 있는 파일. 즉 <pkg>/fixtures/case.json, <pkg>/fixtures/corpus/note-a.md 등.
//
// 참조 판정 — 아래 셋 중 하나라도 성립하면 "참조됨"(비-fixture 소스만 참조자로 인정):
//   (1) 직접 경로: 소스의 경로 토큰이 그 fixture 파일 경로로 해석된다.
//   (2) 파일명: 소스 본문에 basename 이 토큰 경계로 등장한다.
//   (3) 디렉토리 소비: 소스가 그 fixture 디렉토리(또는 상위 fixture 디렉토리)를 **디렉토리 토큰**으로
//       지목하고, **같은 파일 안에** 디렉토리 순회 마커(DIR_SCAN_MARKERS/SHELL_SCAN_MARKERS)가 있다.
//       → 그 디렉토리 subtree 전체가 "의도적으로 소비됨"으로 처리된다.
//
// (3)이 필요한 이유: 재귀 소비되는 fixture vault(collectNotes 로 vault 째 스캔)와 디렉토리 소비되는
// eval fixture corpus(loadDocsFromDir 로 디렉토리 째 로드)의 자식 파일들은 개별 파일명이 어떤 소스에도
// 등장하지 않는다. 개별 언급 부재만으로 고아 판정하면 그 두 묶음이 통째로 오탐된다.
//
// (3)은 '어디든 fixtures 라는 낱말이 있으면 전부 면제'가 **아니다**. 보수적 조건 셋이 모두 필요하다:
//   ㄱ. 토큰이 **실재하는 fixture 디렉토리 경로로 해석**되어야 한다. 해석 기준은 소스 자신의 디렉토리
//       (또는 도구 루트)이므로, A 패키지의 'fixtures' 토큰이 B 패키지의 fixture 를 면제할 수 없다.
//       유사 이름(`fixtures-notes/deep`, `my-fixtures/x`)은 해석 결과가 fixture 디렉토리가 아니라 면제 불가.
//   ㄴ. 단일 세그먼트 토큰(`fixtures` 단독)은 **path.join/path.resolve 인자로 등장할 때만** 디렉토리
//       지목으로 인정한다. frontmatter 축 값(`topic: 'fixtures'`)이나 산문 속 낱말이 subtree 를
//       통째로 면제해 버리는 사고를 막는 조건이다(실제 corpus 에 그런 값이 존재한다).
//   ㄷ. 같은 소스에 디렉토리 순회 마커가 있어야 한다(경로만 언급 + 순회 없음 = 면제 불가).
//
// 자기충족 면제 차단(SELF_SOURCE_RELS): 이 검출기 자신과 그 selftest 는 참조 소스로 세지 않는다.
// 규칙 정의를 담은 파일이라 fixture 어휘·예시 경로가 필연적으로 들어가는데, 그것이 실제 배선 없이
// 라이브 subtree 를 면제해 버리면 검출기가 영구히 눈을 감는다. 대가: 이 쌍만 소비하는 fixture 는
// 고아로 보고된다(의도된 방향 — 검출기용 fixture 는 두지 않는다).
//
// 오차 방향(의도): advisory 검출기이므로 **오탐(false positive)보다 미탐(false negative)을 선호**한다.
// 토큰 해석·마커 판정은 휴리스틱이고, 애매하면 "참조됨" 쪽으로 판정한다.

import fs from 'node:fs'
import path from 'node:path'

export const TOOLS_DIR = '.tools'
export const FIXTURE_DIR_NAME = 'fixtures'
// 자기충족 면제 차단 대상(루트상대). 위 헤더 주석 §자기충족 면제 차단 참조.
export const SELF_SOURCE_RELS = [
  `${TOOLS_DIR}/lint/fixture-integrity.mjs`,
  `${TOOLS_DIR}/lint/fixture-integrity.selftest.mjs`,
]

// 스캔 대상 소스 확장자(소문자, 점 없음). 텍스트 소스만 — 바이너리는 애초에 목록 밖이다.
// 확장자 없는 파일은 대상 밖(바이너리 blob 오독 방지) — 현 트리에 해당 파일 없음.
export const SOURCE_EXT = new Set([
  'mjs', 'cjs', 'js', 'jsx', 'ts', 'mts', 'cts', 'tsx',
  'json', 'jsonl', 'md', 'txt', 'tpl',
  'sh', 'bash', 'zsh', 'py', 'rb',
  'yml', 'yaml', 'toml', 'ini', 'cfg', 'conf', 'service', 'timer',
])
const SHELL_EXT = new Set(['sh', 'bash', 'zsh'])

// 디렉토리 순회(= 개별 파일명 없이 디렉토리째 소비) 마커. 명시 allowlist — 의도적으로 좁게 유지한다.
// `recursive: true` 는 mkdir/rm 옵션으로 거의 모든 파일에 등장하므로 **마커가 아니다**(전면 면제 방지).
export const DIR_SCAN_MARKERS = [
  'readdirSync', 'readdir(', 'opendirSync', 'withFileTypes',
  'globSync', 'glob(', 'glob.glob', 'os.walk', 'rglob', 'iterdir', 'listdir',
  'collectNotes', 'loadDocsFromDir', 'collectVaultDocs', // 이 저장소의 디렉토리 소비 API
  'walkMd', 'walkDir', 'walkTree', 'walk(',
]
// 셸 소스(sh/bash/zsh)에만 추가 적용되는 마커 — 산문에서의 오검을 피하려 확장자로 게이트한다.
export const SHELL_SCAN_MARKERS = ['cp -r', 'cp -R', 'rsync', 'find ', 'for f in', 'ls ']

// 생성물·과도기 디렉토리 이름. 여기에 더해 이름이 `.` 로 시작하는 디렉토리는 모두 건너뛴다
// (.cache/.git/.venv 등 — /.gitignore 와 같은 성격의 머신-로컬 산출물).
export const IGNORED_DIR_NAMES = new Set([
  'node_modules', '__pycache__', 'dist', 'build', 'coverage', 'tmp', 'venv',
])
// /.gitignore 가 명시한 도구 트리 하위 생성물(머신-로컬) — 제외해 출력이 머신별로 흔들리지 않게 한다.
export const TRANSIENT_RELS = [
  `${TOOLS_DIR}/state/agent-runs`,
  `${TOOLS_DIR}/graph/connectivity-report.md`,
  `${TOOLS_DIR}/graph/connectivity-state.json`,
]

export const MAX_SOURCE_BYTES = 1024 * 1024 // 이 이상은 스캔하지 않고 finding 으로 표면화

// code-unit 비교(로케일 무관). link-core.mjs 의 cmp 와 동일 정의.
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0)

// path.join(A, 'b', 'c') 처럼 나뉜 인접 문자열 리터럴을 'b/c' 로 접합한다(경로 토큰 복원).
const LITERAL_JOIN_RE = /(['"`])\s*,\s*(['"`])/g
// 한 줄 문자열 리터럴 본문(공백 포함 가능 — 공백 있는 파일명 대비).
const QUOTED_RE = /'([^'\r\n]{1,400})'|"([^"\r\n]{1,400})"|`([^`\r\n]{1,400})`/g
// 인용 없는 경로형 토큰(셸 인자 등): 공백 불허 + 슬래시 1개 이상 필수.
// 구 정규식의 토큰 집합을 그대로 재현하되 선형 스캐너로 읽는다. 정규식은 매 시작점에서 남은
// 문자열을 다시 훑어 slash-free·slash-dense 입력 모두 O(n²) stall을 만들 수 있었다.
const BARE_HEAD_CHARS = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.@~$-')
const BARE_TAIL_CHARS = new Set([...BARE_HEAD_CHARS, '{', '}'])
const barePathsIn = text => {
  const out = []
  let i = 0
  while (i < text.length) {
    while (i < text.length && !BARE_HEAD_CHARS.has(text[i])) i++
    if (i === text.length) break

    const start = i
    while (i < text.length && BARE_HEAD_CHARS.has(text[i])) i++

    let end = -1
    while (i < text.length && text[i] === '/' && i + 1 < text.length && BARE_TAIL_CHARS.has(text[i + 1])) {
      i++
      while (i < text.length && BARE_TAIL_CHARS.has(text[i])) i++
      end = i
    }
    if (end !== -1) out.push(text.slice(start, end))
  }
  return out
}
// 경로 조립 호출의 인자 목록(중첩 괄호 없는 단순형만 — 미탐 방향).
const PATH_CALL_RE = /\b(?:path\.(?:join|resolve)|os\.path\.join)\s*\(([^()\r\n]{0,400})\)/g

const errText = e => (e && e.message ? e.message : String(e))
const extOf = name => {
  const i = name.lastIndexOf('.')
  return i > 0 ? name.slice(i + 1).toLowerCase() : ''
}
const isTransientRel = rel => TRANSIENT_RELS.some(t => rel === t || rel.startsWith(t + '/'))
const isIgnoredDirName = name => name.startsWith('.') || IGNORED_DIR_NAMES.has(name)
const quotedIn = text => {
  const out = []
  for (const m of text.matchAll(QUOTED_RE)) {
    const v = (m[1] ?? m[2] ?? m[3] ?? '').trim()
    if (v) out.push(v)
  }
  return out
}

/**
 * 세그먼트 배열을 도구 루트상대 경로로 정규화한다. `..` 는 스택 pop.
 * 도구 루트 밖으로 벗어나면 null (검사 범위 밖).
 */
function normalizeSegs(segs) {
  const st = []
  for (const s of segs) {
    if (s === '' || s === '.') continue
    if (s === '..') { if (!st.length) return null; st.pop(); continue }
    st.push(s)
  }
  if (st.length < 2 || st[0] !== TOOLS_DIR) return null
  return st.join('/')
}

/**
 * fixture 판정. 파일이면 fixture 세그먼트가 **basename 앞**에 있어야 한다.
 * @param {string} rel 루트상대 경로
 * @param {boolean} [isDir]
 * @returns {string|null} 가장 바깥 fixture 루트의 루트상대 경로
 */
export function fixtureRootOf(rel, isDir = false) {
  const segs = rel.split('/')
  if (segs[0] !== TOOLS_DIR) return null
  const last = isDir ? segs.length : segs.length - 1
  for (let i = 1; i < last; i++) if (segs[i] === FIXTURE_DIR_NAME) return segs.slice(0, i + 1).join('/')
  return null
}

/**
 * 소스 본문에서 경로 토큰 후보(해석 전 원문)를 뽑는다 — 파일 참조 판정용.
 * @returns {string[]} 중복 제거 토큰
 */
export function extractPathTokens(text) {
  if (typeof text !== 'string' || text === '') return []
  const joined = text.replace(LITERAL_JOIN_RE, '/')
  const out = new Set(quotedIn(joined))
  for (const token of barePathsIn(joined)) out.add(token)
  return [...out]
}

/**
 * 디렉토리 지목으로 인정되는 토큰만 뽑는다 — 위 헤더 조건 ㄴ의 구현.
 *   - 다중 세그먼트 토큰(슬래시 포함): 그대로 인정.
 *   - 단일 세그먼트 리터럴: path.join/path.resolve 인자로 등장할 때만 인정.
 * @returns {string[]}
 */
export function extractDirTokens(text) {
  if (typeof text !== 'string' || text === '') return []
  const out = new Set()
  for (const t of extractPathTokens(text)) if (t.includes('/')) out.add(t)
  const joined = text.replace(LITERAL_JOIN_RE, '/')
  for (const m of joined.matchAll(PATH_CALL_RE)) for (const v of quotedIn(m[1])) out.add(v)
  return [...out]
}

/**
 * 토큰을 도구 루트상대 경로 후보로 해석한다.
 *   - 토큰에 도구 루트 세그먼트가 있으면 그 지점부터 루트상대로 확정(절대경로·$VAR 접두 무해).
 *   - 없으면 ① 소스 파일 자신의 디렉토리 기준, ② 도구 루트 기준 두 후보를 낸다.
 * @param {string} token
 * @param {string} srcRel 소스 파일의 루트상대 경로
 * @returns {string[]}
 */
export function resolveToken(token, srcRel) {
  const raw = typeof token === 'string' ? token.trim() : ''
  if (!raw || raw.length > 400 || raw.includes('://')) return []
  const segs = raw.split('/')
  const ti = segs.indexOf(TOOLS_DIR)
  if (ti !== -1) {
    const r = normalizeSegs([TOOLS_DIR, ...segs.slice(ti + 1)])
    return r ? [r] : []
  }
  const out = []
  const a = normalizeSegs([...String(srcRel).split('/').slice(0, -1), ...segs])
  if (a) out.push(a)
  const b = normalizeSegs([TOOLS_DIR, ...segs])
  if (b && b !== a) out.push(b)
  return out
}

// 토큰 경계 판정용 — 이름 문자에 붙어 있으면 다른 식별자의 일부다.
const isNameChar = c => c !== '' && c !== undefined && /[A-Za-z0-9_-]/.test(c)

/**
 * basename 이 텍스트에 "토큰 경계로" 등장하는지. `x-case.json` 안의 `case.json` 은 앞이
 * `-`(이름 문자)라 불일치, `fixtures/case.json` 은 앞이 `/`라 일치.
 * 뒤가 `.`+영숫자(확장자 연장, `case.json.bak`)면 불일치, 문장 끝 마침표는 일치.
 */
export function mentionsName(text, name) {
  if (typeof text !== 'string' || typeof name !== 'string' || name === '') return false
  let i = 0
  while ((i = text.indexOf(name, i)) !== -1) {
    const before = i > 0 ? text[i - 1] : ''
    const j = i + name.length
    const after = j < text.length ? text[j] : ''
    const extLike = after === '.' && /[A-Za-z0-9]/.test(text[j + 1] || '')
    if (!isNameChar(before) && !isNameChar(after) && !extLike) return true
    i += 1
  }
  return false
}

/** 도구 트리를 정렬 순회하며 파일·디렉토리 목록을 모은다(심볼릭 링크 미추적). */
function walkTools(absDir, relDir, ctx) {
  let ents
  try {
    ents = fs.readdirSync(absDir, { withFileTypes: true })
  } catch (e) {
    ctx.errors.push({ rel: relDir, message: `디렉토리 나열 실패: ${errText(e)}` })
    return
  }
  ents.sort((a, b) => cmp(a.name, b.name))
  for (const e of ents) {
    const rel = `${relDir}/${e.name}`
    if (e.isSymbolicLink()) continue // 링크 미추적(순환·머신 의존 회피)
    if (isTransientRel(rel)) continue
    if (e.isDirectory()) {
      if (isIgnoredDirName(e.name)) continue
      ctx.dirs.push(rel)
      walkTools(path.join(absDir, e.name), rel, ctx)
    } else if (e.isFile()) {
      ctx.files.push(rel)
    }
  }
}

/**
 * fixture 참조 무결성 스캔(읽기 전용, 결정적).
 * @param {string} root vault 루트 경로. `<root>/<TOOLS_DIR>` 만 본다.
 * @returns {{root:string, toolsPresent:boolean, fixtureFiles:string[], sourceFiles:string[],
 *            consumedFixtureDirs:{dir:string,consumers:string[]}[],
 *            findings:{kind:string,path:string,message:string}[]}}
 */
export function scanFixtureIntegrity(root) {
  if (typeof root !== 'string' || root === '') throw new TypeError('scanFixtureIntegrity(root): root 문자열 필수')
  const toolsAbs = path.join(root, TOOLS_DIR)
  const findings = []
  const push = (kind, p, message) => findings.push({ kind, path: p, message })
  const sortFindings = () => findings.sort((a, b) => cmp(a.kind, b.kind) || cmp(a.path, b.path) || cmp(a.message, b.message))
  const empty = () => { sortFindings(); return { root, toolsPresent: false, fixtureFiles: [], sourceFiles: [], consumedFixtureDirs: [], findings } }

  let st = null
  try {
    st = fs.statSync(toolsAbs)
  } catch (e) {
    // 부재는 정상(최소 vault) — 그 외 오류는 조용한 성공 금지.
    if (!e || e.code !== 'ENOENT') push('read-error', TOOLS_DIR, `${TOOLS_DIR} 상태 확인 실패: ${errText(e)}`)
    return empty()
  }
  if (!st.isDirectory()) return empty()

  const ctx = { files: [], dirs: [], errors: [] }
  walkTools(toolsAbs, TOOLS_DIR, ctx)
  for (const e of ctx.errors) push('read-error', e.rel, e.message)

  const fixtureFiles = []
  const sourceFiles = []
  for (const rel of ctx.files) {
    if (fixtureRootOf(rel) !== null) { fixtureFiles.push(rel); continue }
    if (SELF_SOURCE_RELS.includes(rel)) continue // 자기충족 면제 차단
    if (SOURCE_EXT.has(extOf(path.basename(rel)))) sourceFiles.push(rel)
  }
  const fixtureDirs = new Set(ctx.dirs.filter(d => fixtureRootOf(d, true) !== null))

  // ---- 소스 1회 통독: 경로 토큰 해석 + 순회 마커 판정 ----
  const referencedPaths = new Set()     // (1) 직접 경로로 지목된 fixture 파일
  const consumers = new Map()           // (3) fixture 디렉토리 -> 소비 소스 목록
  const scannedSources = []             // (2) basename 검사용 { rel, text }
  for (const rel of sourceFiles) {
    const abs = path.join(root, rel)
    // 소스당 fs 호출 1회(readFileSync)만 쓴다 — stat+read 2회는 게이트 경로에서 체감되는 비용이다.
    // 크기 가드는 읽은 뒤 판정하고, 읽기 자체가 실패하면(권한·과대 파일) advisory finding 으로 나간다.
    let buf = null
    try {
      buf = fs.readFileSync(abs)
    } catch (e) {
      push('read-error', rel, `소스 읽기 실패: ${errText(e)} — 참조 스캔 생략(고아 판정이 과탐일 수 있음)`)
      continue
    }
    if (buf.length > MAX_SOURCE_BYTES) {
      push('source-unscanned', rel, `${rel} ${buf.length}B > ${MAX_SOURCE_BYTES}B — 참조 스캔 생략(고아 판정이 과탐일 수 있음)`)
      continue
    }
    if (buf.includes(0)) {
      push('source-unscanned', rel, `${rel} NUL 바이트 포함(바이너리 추정) — 참조 스캔 생략`)
      continue
    }
    const text = buf.toString('utf8')
    scannedSources.push({ rel, text })
    // 사전 필터 — 불변식: 소스 파일은 절대 fixture 디렉토리 아래에 없고(fixture 는 소스에서 제외),
    // `..` 정규화는 세그먼트를 제거만 한다. 따라서 해석 결과에 fixture 세그먼트가 나타나려면
    // 토큰 자체가 그 이름을 담고 있어야 한다 → 나머지 토큰은 해석 없이 건너뛴다(미탐 없음).
    for (const token of extractPathTokens(text)) {
      if (!token.includes(FIXTURE_DIR_NAME)) continue
      for (const cand of resolveToken(token, rel)) if (fixtureRootOf(cand) !== null) referencedPaths.add(cand)
    }
    const hasScanMarker = DIR_SCAN_MARKERS.some(m => text.includes(m)) ||
      (SHELL_EXT.has(extOf(path.basename(rel))) && SHELL_SCAN_MARKERS.some(m => text.includes(m)))
    if (!hasScanMarker) continue
    for (const token of extractDirTokens(text)) {
      if (!token.includes(FIXTURE_DIR_NAME)) continue // 위와 같은 불변식
      for (const cand of resolveToken(token, rel)) {
        if (!fixtureDirs.has(cand)) continue
        const list = consumers.get(cand)
        if (list) { if (!list.includes(rel)) list.push(rel) } else consumers.set(cand, [rel])
      }
    }
  }

  // ---- fixture 별 참조 판정 ----
  // 값이 싼 순서: (1) 경로 Set → (3) 조상 디렉토리 소비 → (2) basename 전수 스캔.
  for (const rel of fixtureFiles) {
    if (referencedPaths.has(rel)) continue
    const fxRoot = fixtureRootOf(rel)
    let consumed = false
    for (let dir = rel.slice(0, rel.lastIndexOf('/')); dir.length >= fxRoot.length; dir = dir.slice(0, dir.lastIndexOf('/'))) {
      if (consumers.has(dir)) { consumed = true; break }
      if (dir === fxRoot) break // fixture 루트 위로는 올라가지 않는다
    }
    if (consumed) continue
    if (scannedSources.some(s => mentionsName(s.text, path.basename(rel)))) continue
    push('orphan', rel, `${rel}: ${TOOLS_DIR}/ 비-fixture 소스에서 참조 0건 (경로·파일명 미언급 + 디렉토리 소비자 없음) — 배선 확인 또는 삭제 검토`)
  }

  sortFindings()
  const consumedFixtureDirs = [...consumers.entries()]
    .map(([dir, list]) => ({ dir, consumers: [...list].sort(cmp) }))
    .sort((a, b) => cmp(a.dir, b.dir))
  return {
    root,
    toolsPresent: true,
    fixtureFiles: [...fixtureFiles].sort(cmp),
    sourceFiles: [...sourceFiles].sort(cmp),
    consumedFixtureDirs,
    findings,
  }
}
