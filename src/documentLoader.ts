/**
 * The CLI's single shared JSON-LD document loader, used by every command that
 * resolves DIDs / dereferences DID URLs or loads JSON-LD contexts (DID
 * resolution, VC issue/verify, EDV recipient resolution, zcap signing).
 *
 * Per project convention, DID/JSON-LD resolution always goes through
 * `@interop/security-document-loader`, never a hand-rolled loader. The loader's
 * default resolver only knows did:key and did:web, so the did:webvh driver is
 * registered onto a copy of the defaults -- keeping the did:webvh dependency out
 * of the shared loader package itself. A bare DID resolves to its DID document;
 * a `did#fragment` URL is dereferenced straight to its verification-method node.
 * Works for did:key (offline), did:web, and did:webvh (both fetched). Built once
 * and reused.
 */
import {
  createDefaultDidResolver,
  securityLoader
} from '@interop/security-document-loader'
import { createDidWebvhDriver } from '@interop/did-method-webvh/driver'
import type { DidMethodDriver } from '@interop/did-io'

// The shared DID resolver underlying `documentLoader`. Kept module-private: its
// `@interop/did-io` type is not portably nameable across an export boundary.
const didResolver = createDefaultDidResolver()
// `CachedResolver.use` types its argument as the full generation-capable
// `DidMethodDriver`, but only reads `.method` (and later calls `.get`) for
// resolution; the webvh driver implements just that resolution subset.
didResolver.use(createDidWebvhDriver() as unknown as DidMethodDriver)

/** The shared document loader for all CLI commands. */
export const documentLoader = securityLoader({ didResolver }).build()
