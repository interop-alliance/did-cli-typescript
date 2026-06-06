/**
 * Trusted DID registry configuration for credential verification.
 *
 * Provides the DCC "known registries" list consumed by both
 * @interop/verifier-core (the `registries` option) and
 * @digitalcredentials/issuer-registry-client. `loadKnownRegistries` fetches
 * the canonical remote list at runtime and falls back to a bundled set of
 * `dcc-legacy` entries when the network is unavailable.
 */
import type { EntityIdentityRegistry } from '@interop/verifier-core'

/**
 * Canonical DCC known-did-registries list. An array of EntityIdentityRegistry
 * entries published by the Digital Credentials Consortium.
 */
export const KNOWN_REGISTRIES_URL =
  'https://digitalcredentials.github.io/dcc-known-registries/known-did-registries.json'

/**
 * Legacy DID registry URLs, used as a fallback when KNOWN_REGISTRIES_URL
 * cannot be fetched. Each entry is tagged `type: 'dcc-legacy'` so it satisfies
 * the EntityIdentityRegistry contract consumed by @interop/verifier-core and
 * @digitalcredentials/issuer-registry-client.
 */
export const KnownDidRegistries: EntityIdentityRegistry[] = [
  {
    type: 'dcc-legacy',
    name: 'DCC Pilot Registry',
    url: 'https://digitalcredentials.github.io/issuer-registry/registry.json'
  },
  {
    type: 'dcc-legacy',
    name: 'DCC Sandbox Registry',
    url: 'https://digitalcredentials.github.io/sandbox-registry/registry.json'
  },
  {
    type: 'dcc-legacy',
    name: 'DCC Community Registry',
    url: 'https://digitalcredentials.github.io/community-registry/registry.json'
  },
  {
    type: 'dcc-legacy',
    name: 'DCC Registry',
    url: 'https://digitalcredentials.github.io/dcc-registry/registry.json'
  }
]

/**
 * Fetches the remote DCC known registries list, falling back to the bundled
 * KnownDidRegistries const on any failure (logged to stderr).
 *
 * @returns {Promise<EntityIdentityRegistry[]>}
 */
export async function loadKnownRegistries(): Promise<EntityIdentityRegistry[]> {
  try {
    const response = await fetch(KNOWN_REGISTRIES_URL)
    if (!response.ok) {
      throw new Error(`Registry fetch failed: ${response.status}`)
    }
    return (await response.json()) as EntityIdentityRegistry[]
  } catch (err) {
    console.error('Using fallback KnownDidRegistries:', err)
    return KnownDidRegistries
  }
}
