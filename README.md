# Brain Starter

A content-free personal knowledge vault for Obsidian and Claude Desktop's Code tab. It ships search, schema/lint gates, read-only link tools and source capture—not personal notes, credentials or session logs.

## Start
1. On Windows install **Claude Desktop**, **Git for Windows**, **Node.js LTS (22.16+)**, **Python 3.12 from python.org** (check **Add python.exe to PATH**), and **Obsidian**.
2. Choose **Use this template → Create a new repository** (prefer private), then clone it or download/extract the ZIP.
3. In Claude Desktop open **Code → Local environment** and select the native Windows vault folder. Restart Desktop after installing tools so it inherits their PATH.
4. Open the same folder as an Obsidian vault. The first Claude session offers [한국어 온보딩](ONBOARDING.md); `/onboarding` repeats it.
5. Project hooks and the three project skills load automatically—no global skill installation or `export` needed. From the vault run `node .tools/lint/lint.mjs --gate` and `node bin/brain-search "your query"`. Empty knowledge returns reason `empty-corpus` (exit 2, not a setup failure). See [SETUP.md](SETUP.md) for optional dependencies.

처음이라면 [한국어 온보딩](ONBOARDING.md)을 읽거나 vault에서 Claude Code를 열고 `/onboarding`으로 첫 10분을 함께 진행하세요.

## Included mechanisms
- **One search entrypoint:** `node bin/brain-search`, full-raw grep, metadata keywords, exact-identifier promotion and terminal-status freshness. No npm/model setup is needed.
- **Canonical statuses:** 12 live + 4 terminal values, per-type subsets, advisory `status-enum` lint.
- **Integrity:** `lint.mjs --gate`, empty fingerprint baseline, write validation, research axes, source binding, catalog/broken-link checks, revisit deadlines and synthetic fixture integrity.
- **Graph:** shared link resolver, body/frontmatter distinction, audit/connectivity and unlinked-mention suggestions. Optional graph-cache query needs graphology.
- **Capture and promotion:** Claude session hooks preserve raw transcripts. When requested, Claude reads pending sessions, proposes supported wiki updates and applies them only with owner approval.
- **Skeleton:** empty catalogs/directories and processed-session ledger. No personal sample pages.

```text
node bin/brain-search public search command (always JSON)
CLAUDE.md, AGENTS.md  generic assistant contracts
.hooks/, .claude/     project-local Claude hooks
.tools/              search, lint, read-only graph tools, processed-session state
wiki/                empty catalog router and knowledge categories
raw/                 private immutable sources; ignored except folder markers
research/            research catalog target; starts empty
.obsidian/           text-only vault settings; plugin binaries not shipped
```

## Included Claude Code skills
- **prompt-tune:** turns a rough multi-step task prompt into a guarded, checkpointed prompt; no dependencies.
- **page-fetch:** recovers and extracts a requested public page; hard fork of [fivetaku/insane-search](https://github.com/fivetaku/insane-search), with its [MIT license](.claude/skills/page-fetch/LICENSE).
- **harvest:** structured multi-page collection using sibling page-fetch; JSON/CSV/Markdown output.

The skills live in `.claude/skills/{prompt-tune,page-fetch,harvest}` and load automatically when this vault is opened in Claude Desktop's Code tab. Personal skills with the same name take precedence; avoid shadowing these project copies. Page-fetch fetch/crawl needs Python packages in its local venv. No browser automation is bundled or required; JavaScript-only pages must be opened by the user. See [SETUP.md](SETUP.md#included-skills).


## Safety and optional dependencies
Search, lint, link audit/build and Claude source capture work on native Windows without npm packages. Only optional graph-cache query needs graphology. [SETUP.md](SETUP.md) explains optional package and skill setup.

Post-write warnings do not undo completed writes. Autocommit is opt-in and local-only (`BRAIN_AUTOCOMMIT=1`), gates wiki/research, and holds when operator-staged work exists. It never pushes. External collection, paid calls, publication and source-to-wiki promotion require explicit authorization.

Not shipped: personal wiki/raw/research content, historical lint exceptions, system-state/locks or personal consent.
This template's code is [MIT licensed](LICENSE). Page-fetch is an MIT fork of fivetaku/insane-search and retains its [own LICENSE](.claude/skills/page-fetch/LICENSE).

