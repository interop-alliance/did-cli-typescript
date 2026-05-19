declare module '@digitalcredentials/did-method-key' {
  type IDidDocument = import('@digitalcredentials/ssi').IDidDocument
  type IPublicKey = import('@digitalcredentials/ssi').IPublicKey

  interface FromKeyPairResult {
    didDocument: IDidDocument
    keyPairs: Map<string, unknown>
    methodFor: (options: { purpose: string }) => unknown
  }

  class DidKeyDriver {
    use(options: {
      multibaseMultikeyHeader: string
      fromMultibase: (options: { publicKeyMultibase: string }) => Promise<unknown>
    }): void
    fromKeyPair(options: {
      verificationKeyPair: IPublicKey
      keyAgreementKeyPair?: IPublicKey
    }): Promise<FromKeyPairResult>
    get(options: { did?: string; url?: string }): Promise<IDidDocument>
  }

  export function driver(): DidKeyDriver
}

declare module '@digitalcredentials/ed25519-multikey' {
  type IMultikeyPair = import('@digitalcredentials/ssi').IMultikeyPair

  interface GenerateOptions {
    id?: string
    controller?: string
    seed?: Uint8Array
  }

  interface KeyPair {
    publicKeyMultibase: string
    export(options: { publicKey: boolean; secretKey: boolean }): Promise<IMultikeyPair>
  }

  export function generate(options?: GenerateOptions): Promise<KeyPair>
}
