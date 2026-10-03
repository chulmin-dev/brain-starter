// format.mjs — structured output: JSON / CSV / Markdown. No Google/Sheets deps (output-only;
// Sheets push is a separate gdrive step by design).

export function toJSON(records) { return JSON.stringify(records, null, 2); }

function csvCell(v) {
  let s = v == null ? '' : String(v);
  // formula-injection guard: a cell starting with = + - @ can execute in Sheets/Excel. Prefix '.
  if (/^[=+\-@]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
export function toCSV(records) {
  if (!records || !records.length) return '';
  const cols = [...records.reduce((set, r) => { Object.keys(r).forEach(k => set.add(k)); return set; }, new Set())];
  const head = cols.map(csvCell).join(',');
  const rows = records.map(r => cols.map(c => csvCell(r[c])).join(','));
  return [head, ...rows].join('\n');
}
export function toMarkdown(records, { title } = {}) {
  if (!records || !records.length) return (title ? `# ${title}\n\n` : '') + '_(no records)_';
  const cols = [...records.reduce((set, r) => { Object.keys(r).forEach(k => set.add(k)); return set; }, new Set())];
  const head = `| ${cols.join(' | ')} |`;
  const sep = `| ${cols.map(() => '---').join(' | ')} |`;
  const rows = records.map(r => `| ${cols.map(c => String(r[c] ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ')).join(' | ')} |`);
  return (title ? `# ${title}\n\n` : '') + [head, sep, ...rows].join('\n');
}

export function render(records, fmt, opts = {}) {
  switch ((fmt || 'json').toLowerCase()) {
    case 'csv': return toCSV(records);
    case 'md': case 'markdown': return toMarkdown(records, opts);
    default: return toJSON(records);
  }
}

// dedup by a key (default: url, else stringified record). Keeps first occurrence.
export function dedup(records, keyField = 'url') {
  const seen = new Set(); const out = [];
  for (const r of records) {
    const k = (r && r[keyField] != null) ? String(r[keyField]) : JSON.stringify(r);
    if (seen.has(k)) continue;
    seen.add(k); out.push(r);
  }
  return out;
}
