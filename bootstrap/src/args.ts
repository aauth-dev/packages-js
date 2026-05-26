/** Flags that consume the following token as their value. Everything else is boolean. */
const VALUE_FLAGS = new Set([
  'keystore',
  'algorithm',
  'person-server',
  'agent-provider',
  'agent-id',
  'local',
  'lifetime',
])

export interface ParsedArgs {
  command?: string
  positional: string[]
  flags: Record<string, string | boolean>
  /** `--help` / `-h` (silent alias) or the `help` command. */
  help: boolean
  /** `--version` (silent alias). */
  version: boolean
}

export function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = []
  const flags: Record<string, string | boolean> = {}
  let help = false
  let version = false

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--help' || a === '-h') {
      help = true
    } else if (a === '--version') {
      version = true
    } else if (a.startsWith('--')) {
      const key = a.slice(2)
      if (VALUE_FLAGS.has(key)) {
        flags[key] = argv[++i] ?? ''
      } else {
        flags[key] = true
      }
    } else if (a.startsWith('-') && a.length > 1) {
      // Unknown short flag — long-form only for v1; accept as a boolean so it
      // doesn't get mistaken for a positional.
      flags[a.slice(1)] = true
    } else {
      positional.push(a)
    }
  }

  return { command: positional[0], positional, flags, help, version }
}
