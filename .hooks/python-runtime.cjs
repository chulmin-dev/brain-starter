'use strict';
// Python resolution for project hooks and scoped selftests.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function executable(name) {
  const dirs = (process.env.PATH || process.env.Path || '').split(path.delimiter);
  const suffixes = process.platform === 'win32' ? ['', '.exe'] : [''];
  for (const dir of dirs) {
    if (/[/\\]WindowsApps(?:[/\\]|$)/i.test(dir)) continue;
    for (const suffix of suffixes) {
      const file = path.join(dir, name + suffix);
      try {
        if (fs.statSync(file).isFile()) {
          fs.accessSync(file, process.platform === 'win32' ? fs.constants.F_OK : fs.constants.X_OK);
          return file;
        }
      } catch {}
    }
  }
  return null;
}

function resolvePython(skillDir = __dirname, override = process.env.PAGE_FETCH_PYTHON) {
  const candidates = [];
  if (override) candidates.push({ command: override, args: [] });
  else {
    const venv = path.join(skillDir, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
    if (fs.existsSync(venv)) candidates.push({ command: venv, args: [] });
    for (const [name, args] of [['python3', []], ['python', []], ['py', ['-3']]]) {
      const command = executable(name);
      if (command) candidates.push({ command, args });
    }
  }
  for (const candidate of candidates) {
    if (/[/\\]WindowsApps[/\\]/i.test(candidate.command)) continue;
    const probe = spawnSync(candidate.command, [...candidate.args, '-c', 'import sys; print(sys.version_info >= (3, 10))'],
      { encoding: 'utf8', timeout: 3000, windowsHide: true });
    if (probe.status === 0 && probe.stdout.trim() === 'True') return candidate;
  }
  return null;
}
module.exports = { resolvePython, executable };
if (require.main === module) {
  const python = resolvePython();
  if (!python) { console.error('Python 3.10+ not found; install Python from python.org and add it to PATH.'); process.exitCode = 1; }
  else {
    const result = spawnSync(python.command, [...python.args, ...process.argv.slice(2)],
      { stdio: 'inherit', env: { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' }, windowsHide: true });
    process.exitCode = result.status ?? 1;
  }
}
