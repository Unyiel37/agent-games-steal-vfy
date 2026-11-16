/**
 * Minimal TypeScript declarations for snarkjs and circomlibjs.
 *
 * Neither package ships bundled type definitions, so this file
 * describes the small part of each API this project uses. If a
 * future release ships its own types, this file can be deleted.
 */

declare module "snarkjs" {
  export const groth16: {
    fullProve: (
      input: unknown,
      wasmFile: string,
      zkeyFilePath: string,
    ) => Promise<{ proof: unknown; publicSignals: string[] }>;
    verify: (
      vk: object,
      publicSignals: string[],
      proof: unknown,
    ) => Promise<boolean>;
    exportVerificationKey: (zkeyFilePath: string) => Promise<object>;
  };
}

declare module "circomlibjs" {
  export function buildPoseidon(): Promise<{
    (inputs: unknown[]): unknown;
    F: {
      e: (x: unknown) => unknown;
      toString: (x: unknown) => string;
      /** Field modulus (BN128 base field prime). */
      p: bigint;
    };
  }>;
}
