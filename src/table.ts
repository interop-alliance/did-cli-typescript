/**
 * Minimal column-aligned table rendering for CLI list/show output.
 *
 * Deliberately hand-rolled (padEnd-based, no dependencies) and deterministic:
 * column widths are computed from the content and optional per-column caps,
 * never from the terminal width, so output is stable for tests and pipes.
 */

export interface Column {
  header: string
  /** Cells longer than this are middle-truncated; undefined = unlimited. */
  maxWidth?: number
}

const ELLIPSIS = '...'

/**
 * Truncate a value to `maxWidth` characters by removing the middle and
 * inserting an ellipsis, keeping both ends -- the informative parts of
 * fingerprints and DIDs.
 *
 * @param options {object}
 * @param options.value {string}
 * @param options.maxWidth {number}
 * @returns {string}
 */
export function truncateMiddle({
  value,
  maxWidth
}: {
  value: string
  maxWidth: number
}): string {
  if (value.length <= maxWidth) {
    return value
  }
  if (maxWidth <= ELLIPSIS.length) {
    return value.slice(0, maxWidth)
  }
  const visible = maxWidth - ELLIPSIS.length
  const headLength = Math.ceil(visible / 2)
  const tailLength = visible - headLength
  return value.slice(0, headLength) + ELLIPSIS + value.slice(-tailLength)
}

/**
 * Render a padEnd-aligned table: a header row, a dash separator, then one
 * line per row. Each column's width is the widest of its header and cells,
 * capped at the column's `maxWidth` (cells beyond the cap are
 * middle-truncated). Cells are joined with two spaces; missing values render
 * as empty cells. Trailing whitespace is trimmed from every line.
 *
 * @param options {object}
 * @param options.columns {Column[]}
 * @param options.rows {string[][]}
 * @returns {string}
 */
export function renderTable({
  columns,
  rows
}: {
  columns: Column[]
  rows: string[][]
}): string {
  const cells = rows.map(row =>
    columns.map((column, columnIndex) => {
      const value = row[columnIndex] ?? ''
      return column.maxWidth
        ? truncateMiddle({ value, maxWidth: column.maxWidth })
        : value
    })
  )
  const widths = columns.map((column, columnIndex) => {
    const widest = Math.max(
      column.header.length,
      ...cells.map(row => row[columnIndex].length)
    )
    return column.maxWidth ? Math.min(widest, column.maxWidth) : widest
  })
  const lines = [
    columns.map((column, columnIndex) =>
      column.header.padEnd(widths[columnIndex])
    ),
    widths.map(width => '-'.repeat(width)),
    ...cells.map(row =>
      row.map((value, columnIndex) => value.padEnd(widths[columnIndex]))
    )
  ]
  return lines.map(line => line.join('  ').trimEnd()).join('\n')
}
