// src/types/crypto-browserify.d.ts
declare module 'crypto-browserify' {
  // Minimal surface the SDK actually uses
  type Enc = 'hex' | 'latin1' | 'base64';
  interface Hash {
    update(data: string | Uint8Array, inputEncoding?: string): Hash;
    digest(encoding?: Enc): string | Uint8Array;
  }
  interface Hmac {
    update(data: string | Uint8Array, inputEncoding?: string): Hmac;
    digest(encoding?: Enc): string | Uint8Array;
  }

  export function createHash(alg: string): Hash;
  export function createHmac(alg: string, key: string | Uint8Array): Hmac;
  export function randomBytes(size: number): Uint8Array;
  export function pbkdf2(
    password: string | Uint8Array,
    salt: string | Uint8Array,
    iterations: number,
    keylen: number,
    digest: string,
    callback: (err: any, derivedKey: Uint8Array) => void
  ): void;
  export function pbkdf2Sync(
    password: string | Uint8Array,
    salt: string | Uint8Array,
    iterations: number,
    keylen: number,
    digest: string
  ): Uint8Array;
}
