'use strict';
// Shell-neutral entrypoint: works under Git Bash or PowerShell, never blocks a session.
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const { resolvePython, executable } = require('./python-runtime.cjs');
const root = process.env.CLAUDE_PROJECT_DIR || path.resolve(__dirname, '..');
const hook = process.argv[1]; // settings invokes this module through node -e
const env = { ...process.env, MY_BRAIN_DIR: root, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' };

function emitContext(event, context) {
  if (context) console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: event, additionalContext: context } }));
}

function fallbackOnboarding() {
  if (env.BRAIN_SKIP_ONBOARDING === '1') return '';
  const marker = path.join(root, '.cache/brain/onboarded');
  try {
    if (fs.existsSync(marker)) return '';
    fs.readFileSync(path.join(root, 'ONBOARDING.md'), 'utf8');
    fs.mkdirSync(path.dirname(marker), { recursive: true });
    fs.writeFileSync(marker, 'onboarding requested\n', { flag: 'wx' });
    return '\n## Brain Starter — 첫 실행 안내\nONBOARDING.md를 읽고 한국어로 짧게 인사하고 기능을 설명하세요. ' +
      '“첫 10분 체크리스트를 함께 해볼까요? 이미 끝낸 단계가 있나요?”라고 제안하세요. ' +
      '사용자가 원하면 필요한 단계만 함께 진행하고, 기존 작업을 막거나 승인 없이 선택 기능·의존성을 설치하지 마세요. ' +
      '나중에는 `/onboarding`으로 다시 안내받을 수 있다고 알려주세요.\n';
  } catch { return ''; }
}
try {
  if (hook === 'autocommit') {
    if (env.BRAIN_AUTOCOMMIT === '1') {
      let bash = executable('bash');
      // Use Git Bash rather than an unrelated system shell launcher.
      if (process.platform === 'win32') {
        bash = [process.env.ProgramFiles, process.env['ProgramFiles(x86)'],
          process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs')]
          .filter(Boolean).map(dir => path.join(dir, 'Git/bin/bash.exe')).find(file => fs.existsSync(file)) ||
          (bash && !/[/\\](?:System32|WindowsApps)[/\\]/i.test(bash) ? bash : null);
      }
      if (bash) spawnSync(bash, [path.join(root, '.hooks/autocommit.sh')], { stdio: 'inherit', env, timeout: 110000, windowsHide: true });
      else console.error('[brain] Autocommit skipped: Git Bash is unavailable.');
    }
  } else if (['session-start', 'session-end', 'validate-write'].includes(hook)) {
    // Hooks only require the standard library, not the optional page-fetch venv.
    const python = resolvePython(path.join(root, '.hooks'), null);
    if (hook === 'session-start') {
      const input = fs.readFileSync(0, 'utf8');
      let event;
      try { event = JSON.parse(input); } catch { event = {}; }
      const cwd = path.resolve(event.cwd || root);
      const relative = path.relative(path.resolve(root), cwd);
      if (!relative.startsWith('..') && !path.isAbsolute(relative)) {
        let context = '';
        if (python) {
          const result = spawnSync(python.command, [...python.args, path.join(root, '.hooks/session-start.py')],
            { input, encoding: 'utf8', env, timeout: 15000, windowsHide: true });
          if (result.stderr) process.stderr.write(result.stderr);
          try { context = JSON.parse(result.stdout).hookSpecificOutput.additionalContext; } catch {}
        } else {
          try { context = fs.readFileSync(path.join(root, 'wiki/index.md'), 'utf8'); } catch {}
          context += '\n[brain] Python 3.10+ is unavailable. Install from python.org, add Python to PATH, and restart Claude Desktop. Session capture and write checks are unavailable until then.\n';
          context += fallbackOnboarding();
        }
        if (fs.existsSync(path.join(root, '.git/lint-failed'))) {
          context += '\n[brain] Autocommit held: the previous lint gate failed (.git/lint-failed). Run node .tools/lint/lint.mjs --gate and fix the findings; do not hide them by increasing the baseline.\n';
        }
        emitContext('SessionStart', context);
      }
    } else if (python) {
      spawnSync(python.command, [...python.args, path.join(root, '.hooks', hook + '.py')],
        { stdio: 'inherit', env, timeout: hook === 'validate-write' ? 4500 : 15000, windowsHide: true });
    } else if (hook === 'validate-write') {
      emitContext('PostToolUse', '[brain] Write check skipped: Python 3.10+ is unavailable. Install from python.org and restart Claude Desktop.');
    } else console.error('[brain] Hook skipped: Python 3.10+ is unavailable (install from python.org).');
  }
} catch (error) {
  console.error('[brain] Hook skipped: ' + error.message);
}
// Advisory hooks must return success even if an optional tool or hook fails.
process.exitCode = 0;
