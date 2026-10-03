# Setup

## 1. Windows + Claude Desktop
Install **Claude Desktop**, **Git for Windows**, **Node.js LTS (22.16 or newer)**, **Python 3.12 from python.org**, and **Obsidian**. In Python's installer check **Add python.exe to PATH**; do not use the Microsoft Store Python alias. Restart Claude Desktop after installation so it inherits the new Windows PATH.

Choose GitHub **Use this template → Create a new repository** (prefer private), then clone your repository with Git for Windows, or download and extract its ZIP. Open that folder in Obsidian via **Open folder as vault**. In Claude Desktop choose **Code → Local environment** and select this same native Windows folder. No WSL, standalone Claude CLI, or remote service is needed.

The project loads `CLAUDE.md`, `.claude/settings.json`, `.claude/commands/onboarding.md`, and `.claude/skills/` automatically. The first session offers the Korean [ONBOARDING.md](ONBOARDING.md) checklist; `/onboarding` repeats it. Hooks set the project path automatically. Direct tools resolve their containing clone, so no `export` is necessary.

From PowerShell or Git Bash in the vault:
```text
node --version
python --version
node .tools/lint/lint.mjs --gate
node bin/brain-search "example" --explain
```
Search always prints JSON. An empty vault returns mode `filtered-empty`, reason `empty-corpus`, exit **2**, until your first approved note. This is not a broken installation. Search, lint and graph build/audit need no npm packages.

Only when selecting another vault explicitly is necessary, set `MY_BRAIN_DIR` to its absolute Windows path in Desktop's **Local environment editor (gear icon)**. Use that editor for other optional session variables too. PowerShell profile assignments do not configure Desktop. For terminal-only tools, PowerShell uses `$env:MY_BRAIN_DIR = (Get-Location).Path`; Git Bash uses `export MY_BRAIN_DIR="$(pwd -W)"`. Do not point at somebody else's vault.

Hook commands are shell-neutral Node launchers, usable under Git Bash and PowerShell. Hooks have their own `.hooks/python-runtime.cjs`; optional skills are not hook dependencies. Python resolution tries `python3`, `python`, then `py -3`, ignoring WindowsApps aliases. If Python is missing, SessionStart still gives first-run guidance and tells Claude that capture/write checks are unavailable. Install Python and restart Desktop to enable those hooks. Node is required. SessionStart reads context without changing tracked notes; SessionEnd captures qualifying transcripts in ignored `raw/sessions/`; PostToolUse sends advisory warnings to Claude without undoing completed writes. Never commit raw captures or credentials.

## 2. Daily commands
```text
node bin/brain-search "query" --limit=5 --explain
node .tools/lint/lint.mjs --gate
node .tools/lint/drift-lint.mjs --json
node .tools/graph/link-audit.mjs
node .tools/graph/build-graph.mjs
node .hooks/python-runtime.cjs .tools/graph/connectivity_check.py
node .tools/graph/unlinked-mentions.mjs
```
Search exits: 0 completed search (including no matches); 1 usage; 2 filters/empty corpus; 3 unreadable corpus; 5 internal error. Connectivity can exit 2 for isolated satellites, a finding rather than a crash. Graph commands are read-only unless you explicitly use `node .tools/graph/build-graph.mjs --write-cache`. Drift's fact registry starts empty; index/supersedes detectors still run.

Optional local autocommit: set `BRAIN_AUTOCOMMIT=1` in Desktop's Local environment editor before opening a new session. Git Bash is required for this opt-in hook. It lint-gates and commits only wiki/research, skips pre-staged work and never pushes/pulls. Leave it unset for manual Git operation. A held lint gate writes `.git/lint-failed`, surfaced in the next SessionStart context; fix violations rather than increasing the empty baseline. Configure your own local Git identity. A ZIP has no Git repository, so autocommit remains unavailable until you initialize one.

## 3. Optional graph query
Only graph-cache query requires an npm dependency (`graphology`):
```text
npm install --prefix .tools/graph
node .tools/graph/build-graph.mjs --write-cache
node .tools/graph/query-graph.mjs --keyword example
```
This installs only into this clone. It is not needed for first-run onboarding, search, lint or link audit.

## Included skills
- **prompt-tune:** prompt-only tuning with approval and checkpoint guards; does not execute the supplied task.
- **page-fetch:** requested public-page extraction; an MIT fork of [fivetaku/insane-search](https://github.com/fivetaku/insane-search), with upstream attribution and the retained Scrapling-derived template fragments' BSD-3 notice in `.claude/skills/page-fetch/LICENSE`.
- **harvest:** structured fetch/crawl and JSON/CSV/Markdown output using sibling page-fetch. JavaScript-only pages return `render-unavailable` (exit 3); open those pages yourself instead.

All three are project skills at `.claude/skills/<name>/SKILL.md`; **no global installation is needed**. A personal skill with the same name takes precedence over the project skill, so remove or rename only personal copies you own if they shadow these skills.

Page-fetch retrieval needs **Python 3.10+** and local Python packages. Install only if you want retrieval, from the vault root in PowerShell or Git Bash:
```text
node .claude/skills/page-fetch/python-runtime.cjs -m venv .venv
node .claude/skills/page-fetch/python-runtime.cjs -m pip install --index-url https://pypi.org/simple curl_cffi PyYAML beautifulsoup4 trafilatura publicsuffix2 feedparser
node .claude/skills/page-fetch/python-runtime.cjs -m plus --help
node .claude/skills/harvest/harvest.mjs --help
```
The skill's Python launcher uses the page-fetch directory as its working directory, so `.venv` stays skill-local. Set `INSANE_NO_AUTO_INSTALL=1` in Desktop's Local environment editor to prohibit implicit package installation. No package installation is needed for prompt-tune or harvest's offline helpers. Harvest resolves sibling page-fetch and its venv, then installed Python. Overrides: `PAGE_FETCH_DIR` and `PAGE_FETCH_PYTHON` (an executable path, not a shell command). No browser automation or webpilot is bundled or required.
Runtime observations, winner records and crawl checkpoints are private local state under `~/.cache/brain/page-fetch`, not files in the project skill. Offline tests remain bundled; live coverage/smoke scripts and development sync tooling are not part of the template.

Optional search privacy terms go in your own `~/.config/page-fetch/blocked-terms` (one term per line), or a file selected by `INSANE_BLOCKED_TERMS_FILE`; no personal terms are shipped. Login, CAPTCHA and paywall bypass are not supported.
