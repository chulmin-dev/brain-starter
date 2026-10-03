#!/usr/bin/env node
// note-io.selftest.mjs — selftest for note-io.mjs. Operates ENTIRELY in a fresh os.tmpdir sandbox;
// never reads or writes the live vault. Proves: strict-UTF-8-or-refuse, byte/BOM/CRLF preservation,
// no newline translation, mode preservation, and atomic temp+rename (no temp leftovers).
//
//   node note-io.selftest.mjs        # exit 1 on any failure
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { readExact, writeExact } from './note-io.mjs'

let pass = 0, fail = 0
const log = []
const check = (name, cond, detail) => {
  if (cond) { pass++; log.push('  PASS ' + name) }
  else { fail++; log.push('  FAIL ' + name + (detail ? ' — ' + detail : '')) }
}
const bytesEqual = (a, b) => Buffer.compare(a, b) === 0

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'note-io-selftest-'))
try {
  // 1. strict UTF-8 round-trip with BOM + CRLF preserved, byte-identical
  {
    const original = Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from('line1\r\nline2\n한글\r\n', 'utf-8')])
    const src = path.join(dir, 'bom-crlf.md')
    fs.writeFileSync(src, original)
    const text = readExact(src)
    check('readExact decodes valid UTF-8 (non-null)', text != null)
    check('BOM preserved as U+FEFF in decoded text', text != null && text.charCodeAt(0) === 0xFEFF)
    check('CRLF preserved in decoded text', text != null && text.includes('\r\n'))
    const dst = path.join(dir, 'bom-crlf.out.md')
    writeExact(dst, text)
    check('writeExact round-trips byte-identical (BOM + CRLF)', bytesEqual(fs.readFileSync(dst), original))
  }

  // 2. invalid UTF-8 → readExact returns null (the "do not rewrite" signal)
  {
    const src = path.join(dir, 'invalid.md')
    fs.writeFileSync(src, Buffer.from([0x2D, 0x2D, 0x0A, 0xFF, 0xFE, 0x0A])) // lone 0xFF/0xFE
    check('readExact refuses invalid UTF-8 (null)', readExact(src) === null)
  }

  // 3. no newline translation: mixed \r\n and \n written verbatim
  {
    const text = 'a\r\nb\nc\r\n'
    const dst = path.join(dir, 'nl.md')
    writeExact(dst, text)
    check('writeExact performs NO newline translation', bytesEqual(fs.readFileSync(dst), Buffer.from(text, 'utf-8')))
  }

  // 4. mode preservation across rewrite
  {
    const src = path.join(dir, 'mode.md')
    fs.writeFileSync(src, 'before')
    if (process.platform !== 'win32') fs.chmodSync(src, 0o640)
    writeExact(src, 'after content')
    if (process.platform !== 'win32') check('writeExact preserves file mode (0640)', (fs.statSync(src).mode & 0o777) === 0o640)
    else console.log('  SKIP 0640 mode assertion on win32 (POSIX-only)')
    check('writeExact wrote new content', fs.readFileSync(src, 'utf-8') === 'after content')
  }

  // 5. atomic temp+rename: final content correct, NO temp siblings left behind
  {
    const src = path.join(dir, 'atomic.md')
    writeExact(src, 'v1')
    writeExact(src, 'v2')
    check('writeExact final content correct after overwrite', fs.readFileSync(src, 'utf-8') === 'v2')
    const leftovers = fs.readdirSync(dir).filter(f => f.includes('.tmp-'))
    check('writeExact leaves no temp sibling files', leftovers.length === 0, leftovers.join(','))
  }

  // 6. writeExact on a brand-new path (no prior file → default mode, still atomic)
  {
    const dst = path.join(dir, 'fresh.md')
    writeExact(dst, 'fresh\n')
    check('writeExact creates a new file atomically', fs.existsSync(dst) && fs.readFileSync(dst, 'utf-8') === 'fresh\n')
  }

  // 7. readExact on a missing path → null (never throws)
  check('readExact on missing path → null', readExact(path.join(dir, 'nope.md')) === null)

  // 8. exact-bytes read: trailing-newline-free content survives (no accidental append)
  {
    const src = path.join(dir, 'no-eol.md')
    fs.writeFileSync(src, Buffer.from('no trailing newline', 'utf-8'))
    const t = readExact(src)
    const dst = path.join(dir, 'no-eol.out.md')
    writeExact(dst, t)
    check('no trailing newline preserved (no append)', bytesEqual(fs.readFileSync(dst), Buffer.from('no trailing newline', 'utf-8')))
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true })
}

console.log('note-io.selftest')
console.log(log.join('\n'))
console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
