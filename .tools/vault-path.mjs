import path from 'node:path'
import { fileURLToPath } from 'node:url'

// Every tool shares one vault: explicit environment, Claude project, then this clone.
export const VAULT_ROOT = path.resolve(process.env.MY_BRAIN_DIR || process.env.CLAUDE_PROJECT_DIR || path.join(path.dirname(fileURLToPath(import.meta.url)), '..'))
