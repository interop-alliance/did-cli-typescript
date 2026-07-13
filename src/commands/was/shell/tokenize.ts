/**
 * Splits an interactive-shell input line into argv tokens, honoring single
 * quotes, double quotes, and backslash escapes so quoted paths and payloads
 * survive the trip to commander. Kept dependency-free, consistent with the
 * project's no-inquirer / no-chalk stance.
 *
 * Quoting rules mirror a POSIX shell closely enough for path entry: single
 * quotes are literal (no escapes inside), double quotes allow backslash to
 * escape the next character, and a bare backslash escapes the next character.
 * An unterminated quote throws.
 */

/**
 * Tokenizes a shell input line into argv-style tokens.
 *
 * @param line {string}
 * @returns {string[]}
 */
export function tokenizeShellLine(line: string): string[] {
  const tokens: string[] = []
  let current = ''
  let hasToken = false
  let quote: '"' | "'" | undefined

  for (let index = 0; index < line.length; index++) {
    const char = line[index]

    if (quote) {
      if (char === quote) {
        quote = undefined
      } else if (char === '\\' && quote === '"') {
        const next = line[index + 1]
        if (next === undefined) {
          current += char
        } else {
          current += next
          index++
        }
      } else {
        current += char
      }
      continue
    }

    if (char === '"' || char === "'") {
      quote = char
      hasToken = true
      continue
    }

    if (char === '\\') {
      const next = line[index + 1]
      if (next !== undefined) {
        current += next
        index++
      }
      hasToken = true
      continue
    }

    if (char === ' ' || char === '\t') {
      if (hasToken) {
        tokens.push(current)
        current = ''
        hasToken = false
      }
      continue
    }

    current += char
    hasToken = true
  }

  if (quote) {
    throw new Error('Unterminated quote in input.')
  }
  if (hasToken) {
    tokens.push(current)
  }
  return tokens
}
