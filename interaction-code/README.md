# @aauth/interaction-code

AAuth interaction code generation and canonicalization, implementing the Crockford base32 format specified in `draft-hardt-oauth-aauth-protocol §2.6`.

## Install

```
npm install @aauth/interaction-code
```

## API

### `generateCode(): string`

Generates an 8-symbol Crockford base32 interaction code (40 bits of entropy) in canonical `XXXX-XXXX` form. The returned value is ready to use as a storage key.

```typescript
import { generateCode } from '@aauth/interaction-code'

const code = generateCode()  // e.g. "A1B2-C3D4"
store.set(code, pendingData)
```

### `canonicalizeCode(input: string): string`

Canonicalizes user-presented input to `XXXX-XXXX` form for storage lookup. Handles:
- Hyphens in any position (stripped, then reinserted at position 4)
- Lowercase input (uppercased)
- Crockford decode aliases: `I`/`L` → `1`, `O` → `0`

```typescript
import { canonicalizeCode } from '@aauth/interaction-code'

// All of these look up the same stored record:
store.get(canonicalizeCode('a1b2c3d4'))    // → 'A1B2-C3D4'
store.get(canonicalizeCode('A1B2-C3D4'))  // → 'A1B2-C3D4'
store.get(canonicalizeCode('a1b2-c3d4'))  // → 'A1B2-C3D4'
```

### `CROCKFORD32: string`

The Crockford base32 alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (omits I, L, O, U).

## Code format

- **Alphabet:** Crockford base32 (32 symbols, no visually ambiguous characters)
- **Entropy:** 40 bits (5 random bytes → 8 × 5-bit symbols)
- **Display:** `XXXX-XXXX` — hyphen at position 4 for human readability only
- **Storage:** `XXXX-XXXX` — canonical form includes hyphen
- **Lookup:** call `canonicalizeCode(userInput)` before comparing
