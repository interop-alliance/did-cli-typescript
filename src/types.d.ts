declare module '@digitalcredentials/ed25519-multikey' {
  interface GenerateOptions {
    id?: string
    controller?: string
    seed?: Uint8Array
  }

  interface ExportedKeyPair {
    id?: string
    [key: string]: unknown
  }

  interface KeyPair {
    publicKeyMultibase: string
    export(options: { publicKey: boolean; secretKey: boolean }): Promise<ExportedKeyPair>
  }

  export function generate(options?: GenerateOptions): Promise<KeyPair>
}
