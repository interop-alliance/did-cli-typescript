/**
 * Unit tests for `reportError`: HTTP status/reason and server-provided problem
 * details are surfaced for `WasError`s, while plain errors keep the bare
 * message and the input-error exit code. Also covers the `runAndExit` reporter
 * seam that keeps the command tree shell-safe.
 */
import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { WasError } from '@interop/was-client'
import { reportError, runAndExit, setRunAndExitReporter } from './shared.js'

describe('reportError', () => {
  let errors: string[]

  beforeEach(() => {
    errors = []
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
  })

  afterEach(() => {
    mock.restoreAll()
  })

  it('appends the HTTP status and reason phrase for a WasError', () => {
    const code = reportError({
      action: 'put the resource',
      err: new WasError('Request error', { status: 415 })
    })
    assert.equal(code, 1)
    assert.equal(
      errors[0],
      'Could not put the resource: Request error ' +
        '(HTTP 415 Unsupported Media Type)'
    )
  })

  it('appends server-provided problem details after the status', () => {
    const code = reportError({
      action: 'create the space',
      err: new WasError('Validation failed', {
        status: 400,
        details: ['name is required']
      })
    })
    assert.equal(code, 1)
    assert.equal(
      errors[0],
      'Could not create the space: Validation failed ' +
        '(HTTP 400 Bad Request; name is required)'
    )
  })

  it('omits the status suffix when a WasError carries no status', () => {
    reportError({
      action: 'put the resource',
      err: new WasError('Server URL is required')
    })
    assert.equal(
      errors[0],
      'Could not put the resource: Server URL is required'
    )
  })

  it('returns the input-error code (2) for a plain Error, unadorned', () => {
    const code = reportError({
      action: 'put the resource',
      err: new Error('bad path')
    })
    assert.equal(code, 2)
    assert.equal(errors[0], 'Could not put the resource: bad path')
  })
})

describe('runAndExit with a reporter installed', () => {
  let exited: number | undefined

  beforeEach(() => {
    exited = undefined
    mock.method(process, 'exit', (code: number) => {
      exited = code
    })
  })

  afterEach(() => {
    setRunAndExitReporter()
    mock.restoreAll()
  })

  it('reports a non-zero code to the reporter instead of exiting', async () => {
    const reported: number[] = []
    setRunAndExitReporter(code => reported.push(code))
    await runAndExit(Promise.resolve(2))
    assert.deepEqual(reported, [2])
    assert.equal(exited, undefined)
  })

  it('reports a zero code to the reporter too', async () => {
    const reported: number[] = []
    setRunAndExitReporter(code => reported.push(code))
    await runAndExit(Promise.resolve(0))
    assert.deepEqual(reported, [0])
    assert.equal(exited, undefined)
  })

  it('restores process.exit behavior once the reporter is cleared', async () => {
    setRunAndExitReporter(() => {})
    setRunAndExitReporter()
    await runAndExit(Promise.resolve(3))
    assert.equal(exited, 3)
  })
})
