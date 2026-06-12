# Contributing

Thanks for contributing to `@interop/did-cli`. For a map of the codebase --
entry point, the command-factory pattern, module layout, and the command
surface -- see [ARCHITECTURE.md](ARCHITECTURE.md).

## Refactoring
- Preserve existing comments and formatting

## Code Style

### Naming
- Use `camelCase` for variables, functions, and properties; `PascalCase` for classes
- Avoid single-letter variable names — use descriptive names (e.g. `err` not `e`, `chunk` not `c`)
- Private class methods and properties are prefixed with underscore (e.g. `_generate`)

### Functions
- Prefer named `async function` declarations over arrow functions at module level
- Export functions and classes inline (`export async function ...`, `export class ...`)

### Imports
- Use `node:` prefix for Node.js built-in imports (e.g. `import fs from 'node:fs'`)
- Group imports: Node.js built-ins first, then external packages, then local modules
- Use named imports; avoid default imports where possible

### Parameters
- Pass related arguments as a single options object and destructure in the signature:
  ```js
  export async function exportKey({ publicKey, secretKey }) { ... }
  ```

## JSDoc

Use multi-line `@param options` style, documenting each property on its own line:

```js
/**
 * @param options {object}
 * @param options.methodId {string}
 * @param [options.contentType] {string}   ← square brackets for optional params
 */
```

Do not use the inline `@param {{ prop: type }}` style.
Use `@returns {type}` whenever possible.

## Error Handling

- Use `err` (not `e`) as the catch variable name

## Command Tests

Command tests (`src/commands/*.test.ts`) use `node:test` with
`node:assert/strict` and follow this pattern:

- Capture output by mocking `console.log` / `console.error` into string
  arrays in `beforeEach` (`mock.method(console, 'log', ...)`), and call
  `mock.restoreAll()` in `afterEach`.
- Point storage at temp dirs via env vars: `WALLET_DIR` (wallet collections)
  and `DIDS_DIR` (DID documents), created with `mkdtemp(join(tmpdir(), ...))`.
  Clean up in `afterEach` (or a `finally` block): delete the env var (restore
  the previous value if one was saved) and `rm` the temp dir recursively.
- Invoke commands through their factory:
  `makeXCommand().parseAsync([...args], { from: 'user' })`.
- Assert against the captured log arrays; parse JSON output with
  `JSON.parse(logs.join('\n'))` when needed.
- Run a single test file with:
  `node --test --import tsx --enable-source-maps src/commands/<name>.test.ts`

## Comments

- Use `/** */` JSDoc-style block comments for file, class, and function headers
  (including the one-paragraph "what this file does" header at the top of a
  module).
- Use `//` only for short one- or two-line inline comments.
- Do not put "See CONTRIBUTING.md ..." cross-references inside code comments;
  keep pointers to the spec/docs in the README and this file.
