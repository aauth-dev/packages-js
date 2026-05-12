import { readConfig } from '@aauth/local-keys'

/**
 * Printed when `npx @aauth/fetch` is invoked with no URL. Aims to orient new
 * users: what they can call, what shape the flags take, and a pointer back to
 * @aauth/bootstrap if no agent is configured yet.
 */
export function printGettingStarted(): void {
  let configured = false
  try {
    const cfg = readConfig()
    configured = Object.keys(cfg.agents).length > 0
  } catch { /* no config yet */ }

  console.log('@aauth/fetch — AAuth-authenticated HTTP requests')
  console.log('')

  if (!configured) {
    console.log('You don\'t have an agent configured yet.')
    console.log('')
    console.log('Set one up first:')
    console.log('  npx @aauth/bootstrap --ps https://person.hello-beta.net')
    console.log('')
  }

  console.log('Examples:')
  console.log('')
  console.log('  # Call an AAuth-protected resource (handles the full challenge flow):')
  console.log('  npx @aauth/fetch https://whoami.aauth.dev --log')
  console.log('')
  console.log('  # Same, requesting specific scopes:')
  console.log('  npx @aauth/fetch "https://whoami.aauth.dev?scope=openid+profile" --log')
  console.log('')
  console.log('  # R3 (Rich Resource Requests) — authorize for specific operations:')
  console.log('  npx @aauth/fetch --authorize https://notes.aauth.dev/authorize \\')
  console.log('                   --operations listNotes,createNote --log')
  console.log('')
  console.log('  # Just sign and send (no 401 handling):')
  console.log('  npx @aauth/fetch --agent-only https://example.com --log')
  console.log('')
  console.log('Common flags:')
  console.log('  --log              Narrate each protocol step on stderr (JSONL)')
  console.log('  --force-consent    Force the PS to prompt for fresh consent each run')
  console.log('  --authorize        Run the auth flow only; return tokens for reuse')
  console.log('  --operations <ops> Comma-separated operationIds for R3 authorization')
  console.log('  --scope <scope>    Requested scopes (whoami-style resources)')
  console.log('  --help             Full help')
  console.log('')
  console.log('See `npx @aauth/fetch --help` for the complete reference.')
}
