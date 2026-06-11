/**
 * WAS path parsing: normalizes the single positional address accepted by the
 * `was` commands -- `SPACE[/COLLECTION[/RESOURCE]]` -- into its components.
 *
 * The `SPACE` part takes one of three forms:
 *
 * - a local registry handle (e.g. `home`), resolved later against the local
 *   space registry;
 * - a bare space id (e.g. a server-generated uuid or urn), which needs the
 *   server URL supplied separately;
 * - a full space https URL (e.g. `https://was.example/space/<id>`), which is
 *   self-contained: the server URL is the URL's origin and the space id is
 *   the segment after `/space/`. Collection/resource segments may appear
 *   inside the URL itself or be appended with the same `/<coll>/<res>`
 *   syntax as the other forms.
 *
 * Handles and bare space ids are not distinguished here -- both land in
 * `spaceRef` and are resolved against the registry by the caller. Resource
 * ids containing `/` are not supported by this syntax.
 */

/**
 * The normalized form of a WAS address: the server URL when the address was
 * given as a full space URL, the space reference (handle or space id) as
 * written, and the optional collection/resource ids.
 */
export interface WasAddress {
  /** Server base URL (origin), present only for the full-URL form. */
  server?: string
  /** The space handle or space id, exactly as the user wrote it. */
  spaceRef: string
  collectionId?: string
  resourceId?: string
}

/**
 * Returns the parsed URL when the value is an http(s) URL, undefined
 * otherwise.
 *
 * @param value {string}
 * @returns {URL | undefined}
 */
function tryParseHttpUrl(value: string): URL | undefined {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return undefined
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined
  }
  return url
}

/**
 * Splits the trailing path segments of a WAS address into collection and
 * resource ids, rejecting empty segments and paths deeper than
 * collection/resource.
 *
 * @param options {object}
 * @param options.segments {string[]}
 * @param options.address {string}   The original address, for error messages.
 * @returns {{collectionId?: string, resourceId?: string}}
 */
function parseTailSegments({
  segments,
  address
}: {
  segments: string[]
  address: string
}): { collectionId?: string; resourceId?: string } {
  if (segments.length > 2) {
    throw new Error(
      `Invalid WAS address "${address}": expected at most ` +
        'SPACE/COLLECTION/RESOURCE.'
    )
  }
  if (segments.some(segment => segment === '')) {
    throw new Error(`Invalid WAS address "${address}": empty path segment.`)
  }
  const [collectionId, resourceId] = segments
  return {
    ...(collectionId !== undefined && { collectionId }),
    ...(resourceId !== undefined && { resourceId })
  }
}

/**
 * Parses a WAS address -- `SPACE[/COLLECTION[/RESOURCE]]`, where `SPACE` is a
 * registry handle, a bare space id, or a full space https URL -- into its
 * normalized components. Throws on malformed addresses (empty segments,
 * paths deeper than collection/resource, URLs without a `/space/<id>` path).
 *
 * @param address {string}
 * @returns {WasAddress}
 */
export function parseWasAddress(address: string): WasAddress {
  if (address === '') {
    throw new Error('Invalid WAS address: empty string.')
  }

  const url = tryParseHttpUrl(address)
  if (url) {
    const segments = url.pathname.split('/').filter(Boolean)
    if (segments[0] !== 'space' || !segments[1]) {
      throw new Error(
        `Invalid WAS space URL "${address}": expected a path of the form ` +
          '/space/<space-id>[/<collection>[/<resource>]].'
      )
    }
    const [, spaceRef, ...tail] = segments
    return {
      server: url.origin,
      spaceRef,
      ...parseTailSegments({ segments: tail, address })
    }
  }

  const [spaceRef, ...tail] = address.split('/')
  if (spaceRef === '') {
    throw new Error(`Invalid WAS address "${address}": empty space segment.`)
  }
  return { spaceRef, ...parseTailSegments({ segments: tail, address }) }
}
