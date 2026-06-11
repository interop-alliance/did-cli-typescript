import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { renderTable, truncateMiddle } from './table.js'

describe('truncateMiddle', () => {
  it('returns the value unchanged when it fits', () => {
    assert.equal(truncateMiddle({ value: 'abc', maxWidth: 3 }), 'abc')
    assert.equal(truncateMiddle({ value: 'abc', maxWidth: 10 }), 'abc')
  })

  it('truncates the middle, keeping both ends', () => {
    assert.equal(
      truncateMiddle({ value: 'abcdefghijklmnop', maxWidth: 11 }),
      'abcd...mnop'
    )
  })

  it('gives the head the extra character on odd splits', () => {
    assert.equal(
      truncateMiddle({ value: 'abcdefghijklmnop', maxWidth: 10 }),
      'abcd...nop'
    )
  })

  it('truncates at the exact boundary', () => {
    const value = 'abcdefghij'
    assert.equal(truncateMiddle({ value, maxWidth: 10 }), value)
    assert.equal(truncateMiddle({ value, maxWidth: 9 }), 'abc...hij')
  })

  it('falls back to a plain slice when maxWidth is tiny', () => {
    assert.equal(truncateMiddle({ value: 'abcdef', maxWidth: 3 }), 'abc')
    assert.equal(truncateMiddle({ value: 'abcdef', maxWidth: 2 }), 'ab')
  })
})

describe('renderTable', () => {
  it('renders a header, separator, and aligned rows', () => {
    const output = renderTable({
      columns: [{ header: 'NAME' }, { header: 'VALUE' }],
      rows: [
        ['a', 'one'],
        ['longer', 'two']
      ]
    })
    assert.equal(
      output,
      ['NAME    VALUE', '------  -----', 'a       one', 'longer  two'].join(
        '\n'
      )
    )
  })

  it('uses the header width when headers are wider than cells', () => {
    const output = renderTable({
      columns: [{ header: 'DESCRIPTION' }],
      rows: [['x']]
    })
    assert.equal(output, ['DESCRIPTION', '-----------', 'x'].join('\n'))
  })

  it('caps column width at maxWidth and middle-truncates cells', () => {
    const output = renderTable({
      columns: [{ header: 'ID', maxWidth: 9 }, { header: 'NOTE' }],
      rows: [['abcdefghijklm', 'ok']]
    })
    assert.equal(
      output,
      ['ID         NOTE', '---------  ----', 'abc...klm  ok'].join('\n')
    )
  })

  it('renders missing and empty values as empty cells', () => {
    const output = renderTable({
      columns: [{ header: 'A' }, { header: 'B' }, { header: 'C' }],
      rows: [['x'], ['y', '', 'z']]
    })
    assert.equal(output, ['A  B  C', '-  -  -', 'x', 'y     z'].join('\n'))
  })

  it('renders only the header and separator when there are no rows', () => {
    const output = renderTable({
      columns: [{ header: 'A' }, { header: 'B' }],
      rows: []
    })
    assert.equal(output, ['A  B', '-  -'].join('\n'))
  })
})
