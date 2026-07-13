/**
 * Unit tests for the shell session cwd math: relative/absolute `cd`, `.`/`..`
 * navigation, a full space URL setting the server origin, depth rejection, and
 * `formatCwd`.
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { resolveCwdChange, formatCwd } from './session.js'

describe('resolveCwdChange', () => {
  it('enters a space from the root', () => {
    assert.deepEqual(resolveCwdChange({ cwd: [], arg: 'demo' }), {
      cwd: ['demo']
    })
  })

  it('joins a relative segment onto the current directory', () => {
    assert.deepEqual(resolveCwdChange({ cwd: ['demo'], arg: 'did' }), {
      cwd: ['demo', 'did']
    })
  })

  it('walks up one level with ".."', () => {
    assert.deepEqual(resolveCwdChange({ cwd: ['demo', 'did'], arg: '..' }), {
      cwd: ['demo']
    })
  })

  it('stays at the root when going up past it', () => {
    assert.deepEqual(resolveCwdChange({ cwd: [], arg: '..' }), { cwd: [] })
  })

  it('stays put on "."', () => {
    assert.deepEqual(resolveCwdChange({ cwd: ['demo', 'did'], arg: '.' }), {
      cwd: ['demo', 'did']
    })
  })

  it('resets to the root on "/"', () => {
    assert.deepEqual(resolveCwdChange({ cwd: ['demo', 'did'], arg: '/' }), {
      cwd: []
    })
  })

  it('resolves an absolute path, ignoring the current directory', () => {
    assert.deepEqual(
      resolveCwdChange({ cwd: ['demo', 'did'], arg: '/other/coll' }),
      { cwd: ['other', 'coll'] }
    )
  })

  it('combines "../" navigation within a single argument', () => {
    assert.deepEqual(
      resolveCwdChange({ cwd: ['demo', 'did'], arg: '../creds' }),
      { cwd: ['demo', 'creds'] }
    )
  })

  it('enters a space from a full space URL and reports its server', () => {
    assert.deepEqual(
      resolveCwdChange({
        cwd: [],
        arg: 'https://was.example/space/abc/coll'
      }),
      { cwd: ['abc', 'coll'], server: 'https://was.example' }
    )
  })

  it('rejects a URL that addresses a resource', () => {
    assert.throws(
      () =>
        resolveCwdChange({
          cwd: [],
          arg: 'https://was.example/space/abc/coll/res'
        }),
      /addresses a resource/
    )
  })

  it('rejects descending past a collection', () => {
    assert.throws(
      () => resolveCwdChange({ cwd: ['demo', 'did'], arg: 'too/deep' }),
      /at most SPACE\/COLLECTION deep/
    )
  })
})

describe('formatCwd', () => {
  it('renders the root as "/"', () => {
    assert.equal(formatCwd([]), '/')
  })

  it('renders a space and collection path', () => {
    assert.equal(formatCwd(['demo', 'did']), '/demo/did')
  })
})
