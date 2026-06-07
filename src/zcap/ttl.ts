/**
 * Time-to-live parsing for delegated capability expiration.
 *
 * `expiresFromTtl` turns a short duration string (e.g. `1y`, `30d`, `24h`) into
 * an absolute expiration `Date` relative to now, used as the default `expires`
 * for `zcap delegate` when an explicit `--expires` ISO date is not given.
 */

/**
 * Supported duration units and their length in milliseconds. Note `m` is
 * minutes (not months) and `y` is treated as 365 days.
 */
const UNIT_MS: Record<string, number> = {
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
  w: 7 * 24 * 60 * 60 * 1000,
  y: 365 * 24 * 60 * 60 * 1000
}

/**
 * Parses a time-to-live duration string into an absolute expiration date.
 *
 * The format is an integer followed by a unit: `s` (seconds), `m` (minutes),
 * `h` (hours), `d` (days), `w` (weeks), or `y` (365 days), e.g. `1y`, `30d`,
 * `24h`, `15m`.
 *
 * @param ttl {string}   The duration string.
 * @returns {Date}   `now + ttl`.
 */
export function expiresFromTtl(ttl: string): Date {
  const match = /^(\d+)([smhdwy])$/.exec(ttl.trim())
  if (!match) {
    throw new Error(
      `Invalid --ttl value "${ttl}". Expected a number followed by a unit ` +
        '(s, m, h, d, w, or y), e.g. 1y, 30d, 24h.'
    )
  }
  const amount = Number(match[1])
  const unitMs = UNIT_MS[match[2]]
  return new Date(Date.now() + amount * unitMs)
}
