#!/usr/bin/env node
// note-io.mjs — byte-exact read/write for tools that rewrite vault notes in place.
//
// Shared strict UTF-8 IO for graph tools: bytes/mode/EOL/BOM preservation,
// with temp+fsync+rename on explicit writes.
//
// Why strict: a tool that READS forgivingly (errors="replace") then WRITES BACK saves every
// undecodable byte as a permanent U+FFFD and silently rewrites CRLF↔LF. So the rule is:
//   strict UTF-8 in → byte-exact UTF-8 out; a file we cannot decode losslessly is NEVER rewritten.
// readExact returning null is the explicit "do not rewrite this file" signal.
//
// Pure node stdlib, no deps.
import fs from 'node:fs'
import path from 'node:path'

// Decode the file as STRICT UTF-8, or return null when it is not valid UTF-8.
// A leading BOM (U+FEFF) and CRLF line endings survive verbatim in the returned string and
// round-trip byte-identically through writeExact (ignoreBOM keeps the BOM as a real character;
// TextDecoder performs no newline translation).
export function readExact(p) {
  let buf
  try { buf = fs.readFileSync(p) } catch { return null }
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf)
  } catch {
    return null // invalid UTF-8 → refuse: caller must not rewrite this file
  }
}

// Write text back as UTF-8 bytes with NO newline translation, preserving the original file mode.
// Durability + atomicity: write a sibling temp in the SAME directory, fsync it, then rename over
// the target so a concurrent reader never observes a partial file and no cross-device copy occurs.
export function writeExact(p, text) {
  const abs = path.resolve(p)
  const dir = path.dirname(abs)
  let mode = null
  try { mode = fs.statSync(abs).mode & 0o777 } catch {} // preserve mode when the file exists
  const tmp = path.join(dir, `.${path.basename(abs)}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  const data = Buffer.from(text, 'utf-8')
  const fd = fs.openSync(tmp, 'wx', mode == null ? 0o666 : mode)
  try {
    fs.writeSync(fd, data, 0, data.length, 0)
    fs.fsyncSync(fd)
  } finally {
    fs.closeSync(fd)
  }
  if (mode != null) { try { fs.chmodSync(tmp, mode) } catch {} } // creation mask may alter mode; restore exactly
  try {
    fs.renameSync(tmp, abs)
  } catch (e) {
    try { fs.unlinkSync(tmp) } catch {}
    throw e
  }
}
