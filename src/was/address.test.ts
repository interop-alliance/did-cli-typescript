import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { parseWasAddress, setWasAddressBase } from './address.js'

describe('parseWasAddress', () => {
  describe('handle / bare id form', () => {
    it('parses a bare space reference', () => {
      assert.deepEqual(parseWasAddress('home'), { spaceRef: 'home' })
    })

    it('parses a space/collection path', () => {
      assert.deepEqual(parseWasAddress('home/credentials'), {
        spaceRef: 'home',
        collectionId: 'credentials'
      })
    })

    it('parses a space/collection/resource path', () => {
      assert.deepEqual(parseWasAddress('home/credentials/vc-1'), {
        spaceRef: 'home',
        collectionId: 'credentials',
        resourceId: 'vc-1'
      })
    })

    it('parses a uuid space id', () => {
      assert.deepEqual(
        parseWasAddress('81246131-69a4-45ab-9bff-9c946b59cf2e/photos'),
        {
          spaceRef: '81246131-69a4-45ab-9bff-9c946b59cf2e',
          collectionId: 'photos'
        }
      )
    })

    it('parses a urn space id', () => {
      assert.deepEqual(parseWasAddress('urn:uuid:1234/photos/pic-1'), {
        spaceRef: 'urn:uuid:1234',
        collectionId: 'photos',
        resourceId: 'pic-1'
      })
    })
  })

  describe('full space URL form', () => {
    const spaceUrl =
      'https://was.example/space/81246131-69a4-45ab-9bff-9c946b59cf2e'

    it('parses a bare space URL', () => {
      assert.deepEqual(parseWasAddress(spaceUrl), {
        server: 'https://was.example',
        spaceRef: '81246131-69a4-45ab-9bff-9c946b59cf2e'
      })
    })

    it('parses collection/resource segments inside the URL', () => {
      assert.deepEqual(parseWasAddress(`${spaceUrl}/credentials/vc-1`), {
        server: 'https://was.example',
        spaceRef: '81246131-69a4-45ab-9bff-9c946b59cf2e',
        collectionId: 'credentials',
        resourceId: 'vc-1'
      })
    })

    it('keeps a non-default port in the server origin', () => {
      assert.deepEqual(
        parseWasAddress('http://localhost:8080/space/abc/docs'),
        {
          server: 'http://localhost:8080',
          spaceRef: 'abc',
          collectionId: 'docs'
        }
      )
    })

    it('rejects a URL without a /space/<id> path', () => {
      assert.throws(
        () => parseWasAddress('https://was.example/other/abc'),
        /expected a path of the form/
      )
      assert.throws(
        () => parseWasAddress('https://was.example/space/'),
        /expected a path of the form/
      )
    })

    it('rejects a URL path deeper than collection/resource', () => {
      assert.throws(
        () => parseWasAddress('https://was.example/space/abc/coll/res/extra'),
        /expected at most/
      )
    })
  })

  describe('malformed addresses', () => {
    it('rejects an empty address', () => {
      assert.throws(() => parseWasAddress(''), /empty string/)
    })

    it('rejects an empty space segment', () => {
      assert.throws(() => parseWasAddress('/credentials'), /empty space/)
    })

    it('rejects empty path segments', () => {
      assert.throws(() => parseWasAddress('home//vc-1'), /empty path segment/)
      assert.throws(() => parseWasAddress('home/credentials/'), /empty path/)
    })

    it('rejects paths deeper than space/collection/resource', () => {
      assert.throws(
        () => parseWasAddress('home/credentials/vc-1/extra'),
        /expected at most/
      )
    })
  })

  describe('with a relative-path base (shell cwd)', () => {
    afterEach(() => {
      setWasAddressBase([])
    })

    it('joins a relative path onto the base', () => {
      setWasAddressBase(['demo', 'did'])
      assert.deepEqual(parseWasAddress('did.jsonl'), {
        spaceRef: 'demo',
        collectionId: 'did',
        resourceId: 'did.jsonl'
      })
    })

    it('joins a multi-segment relative path onto a space base', () => {
      setWasAddressBase(['demo'])
      assert.deepEqual(parseWasAddress('did/did.jsonl'), {
        spaceRef: 'demo',
        collectionId: 'did',
        resourceId: 'did.jsonl'
      })
    })

    it('resolves "." to the base itself', () => {
      setWasAddressBase(['demo', 'did'])
      assert.deepEqual(parseWasAddress('.'), {
        spaceRef: 'demo',
        collectionId: 'did'
      })
    })

    it('treats a leading slash as absolute, ignoring the base', () => {
      setWasAddressBase(['demo', 'did'])
      assert.deepEqual(parseWasAddress('/other/coll'), {
        spaceRef: 'other',
        collectionId: 'coll'
      })
    })

    it('leaves a full space URL untouched by the base', () => {
      setWasAddressBase(['demo', 'did'])
      assert.deepEqual(parseWasAddress('https://was.example/space/abc/coll'), {
        server: 'https://was.example',
        spaceRef: 'abc',
        collectionId: 'coll'
      })
    })

    it('rejects a relative path that reaches past the resource depth', () => {
      setWasAddressBase(['demo', 'did'])
      assert.throws(() => parseWasAddress('a/b'), /expected at most/)
    })

    it('restores the exact base-less behavior once cleared', () => {
      setWasAddressBase(['demo', 'did'])
      setWasAddressBase([])
      assert.deepEqual(parseWasAddress('home/credentials'), {
        spaceRef: 'home',
        collectionId: 'credentials'
      })
    })
  })
})
