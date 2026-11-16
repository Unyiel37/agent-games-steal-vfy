/**
 * Groth16 proof generation (snarkjs) for the vfy-policy circuit.
 *
 * Every Steal the VFY move must carry a policy proof: the circuit proves
 * that the chosen action follows the committed strategy for the exact
 * turn in the envelope. The circuit inputs are built by policy.ts
 * (buildPolicyInput) from the turn envelope + the strategy decision.
 *
 * Circuit facts (probed first-hand against the published artifacts):
 *  - Groth16 / BN128 (Circom 2.x), vkHash
 *    0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
 *  - 9 public inputs: matchId, turnNumber, action, amount,
 *    opponentBalance, selfBalance, commitment, salt, circuitVersion
 *  - 1 private input: strategyParams[8] (8 field elements)
 *  - commitment == Poseidon(strategyParams[0..7], salt)
 *    (verified empirically: wrong commitment fails witness generation
 *    at template line 72; Poseidon(params, salt) passes it)
 */

import * as snarkjs from "snarkjs";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildPolicyInput, type PolicyInput } from "./policy.js";

/**
 * Resolve a circuit artifact path: an explicit env var wins; otherwise a
 * cwd-relative path is used when it exists, else the path next to this
 * module (dist/../circuits) — so the agent works whether it is started
 * from the repo root, from elsewhere, or as a serverless function.
 */
function resolveCircuitPath(envVar: string, fallback: string): string {
  const fromEnv = process.env[envVar];
  if (fromEnv) return fromEnv;
  if (existsSync(resolve(fallback))) return fallback;
  return join(dirname(fileURLToPath(import.meta.url)), "..", fallback);
}

const WASM_PATH = resolveCircuitPath(
  "CIRCUIT_WASM_PATH",
  "./circuits/vfy-policy.wasm",
);
const ZKEY_PATH = resolveCircuitPath(
  "CIRCUIT_ZKEY_PATH",
  "./circuits/vfy-policy_final.zkey",
);

export interface GeneratedProof {
  proof: unknown;
  publicSignals: string[];
}

/** Registered verification-key hash for the vfy-policy circuit. */
export const REGISTERED_VK_HASH =
  process.env.REGISTERED_VK_HASH ??
  "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";

/** Circuit version bound into every policy proof. */
export const CIRCUIT_VERSION = process.env.CIRCUIT_VERSION ?? "1";

export async function generatePolicyProof(
  input: PolicyInput,
): Promise<GeneratedProof> {
  const circuitInput = buildPolicyInput(input);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH,
  );
  return { proof, publicSignals: publicSignals.map(String) };
}
