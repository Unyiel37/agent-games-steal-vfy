/**
 * vfy-policy circuit inputs + strategy configuration.
 *
 * Circuit facts (probed first-hand against the published artifacts):
 *  - 9 public inputs: matchId, turnNumber, action, amount,
 *    opponentBalance, selfBalance, commitment, salt, circuitVersion.
 *  - 1 private input: strategyParams[8] (8 field elements).
 *  - commitment == Poseidon(strategyParams[0..7], salt)
 *    (9-input Poseidon, salt LAST — verified empirically: any other
 *    commitment fails witness generation at template line 72).
 *  - strategyParams validity (empirical, template asserts):
 *      params[0] in [1, 10]        (line 90: > 0; line 95: <= 10)
 *      params[1]: <= ~100 → action 2; > ~100..110 → action 1 (line 153:
 *        action 1 requires amount 0). Exact threshold unpinned.
 *      params[2]: if params[2] >= opponentBalance → prescribed move
 *        is HOLD (line 140). No upper range bound found (1000 valid).
 *      params[3] in {0, 1}         (line 98); 1 → always HOLD
 *      params[4..7] must be 0      (lines 75-78)
 *  - Prescribed move (see strategy.ts for the full model):
 *      p3==1 → (0,0); p2>=opp → (0,0); p1>~100 → (1,0); else (2,p0).
 *    Turn number and selfBalance do NOT affect the move.
 *  - The dashboard registration format for the commitment is
 *    {"hash": "0x..."} — a 32-byte hex of the Poseidon output
 *    (numberToHex(BigInt(commitment), { size: 32 })).
 *
 * The Poseidon instance is built once at import time (top-level await).
 */

import { createHash } from "node:crypto";
import { buildPoseidon } from "circomlibjs";
import type { ActionName } from "./strategy.js";

const poseidon = await buildPoseidon();
const F = poseidon.F;

/**
 * Field modulus, taken from the circomlibjs Poseidon instance itself —
 * NEVER hand-typed. A mistyped constant silently mangles every
 * commitment: the first build used a wrong 76-digit value, which
 * reduced the 77-digit Poseidon commitment to a different field
 * element and made every proof fail at template line 72 (the
 * commitment check). With F.p the reduction is the identity for
 * genuine Poseidon outputs (commitment < F.p).
 */
const FIELD_PRIME: bigint = F.p;

export interface StrategyConfig {
  /** 8 private strategy parameters, as decimal strings. */
  params: string[];
  /** Salt bound into the commitment (stable for the whole tournament). */
  salt: string;
  /** Commitment = Poseidon(params[0..7], salt), decimal field element. */
  commitment: string;
}

export interface PolicyInput {
  state: {
    matchId: string;
    turn: number;
    selfBalance: number;
    opponentBalance: number;
    commitment: string;
  };
  decision: { action: ActionName; amount?: number };
  strategy: StrategyConfig;
  /** Commitment to put in the public inputs (defaults to strategy.commitment). */
  commitment?: string;
}

/** Action enum (working hypothesis — verify at the practice turn):
 *  HOLD = 0, FORTIFY = 1, EXTRACT = 2.
 *  Evidence: with params[3]=0, p1<=100, p2<opp the circuit only
 *  accepts (2, params[0]) — an EXTRACT of the cap amount; with
 *  params[3]=1, or p2>=opp, it only accepts (0, 0) — a HOLD; with
 *  p1>~100 it only accepts (1, 0). Action 1's semantics (FORTIFY?)
 *  are unconfirmed — only its circuit behaviour is known. */
export const ACTION_CODE: Record<ActionName, string> = {
  HOLD: "0",
  FORTIFY: "1",
  EXTRACT: "2",
};

function toFieldElement(value: string): string {
  if (/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) {
    return (BigInt(value) % FIELD_PRIME).toString();
  }
  const digest = createHash("sha256").update(value, "utf8").digest("hex");
  return (BigInt(`0x${digest}`) % FIELD_PRIME).toString();
}

/** Poseidon hash of (params[0..7], salt) — the strategy commitment. */
export function computeCommitment(params: string[], salt: string): string {
  const inputs = [...params, salt].map((x) => F.e(x));
  return F.toString(poseidon(inputs));
}

/** 32-byte hex form of a decimal field-element commitment
 * (the dashboard "strategyCommitment" registration format). */
export function commitmentToHex(commitment: string): string {
  const hex = BigInt(commitment).toString(16).padStart(64, "0");
  return `0x${hex}`;
}

/** Parse a commitment from the envelope (hex string or decimal) into
 * a decimal field element for the circuit inputs. */
export function commitmentToField(value: string): string {
  return toFieldElement(value);
}

function parseParams(raw: string | undefined, fallback: string): string[] {
  const parts = (raw ?? fallback).split(",").map((s) => s.trim());
  if (parts.length !== 8) {
    throw new Error(
      `STRATEGY_PARAMS must have exactly 8 comma-separated values, got ${parts.length}`,
    );
  }
  for (const p of parts) {
    if (!/^\d+$/.test(p)) throw new Error(`STRATEGY_PARAMS value not an integer: ${p}`);
  }
  return parts;
}

export function validateParams(params: string[]): void {
  const n = params.map(Number);
  if (!(n[0] >= 1 && n[0] <= 10)) {
    throw new Error(`strategyParams[0] must be in [1, 10], got ${n[0]}`);
  }
  if (n[3] !== 0 && n[3] !== 1) {
    throw new Error(`strategyParams[3] must be 0 or 1, got ${n[3]}`);
  }
  for (let i = 4; i < 8; i++) {
    if (n[i] !== 0) {
      throw new Error(`strategyParams[${i}] must be 0, got ${n[i]}`);
    }
  }
  for (let i = 0; i < 8; i++) {
    if (BigInt(params[i]) >= FIELD_PRIME) {
      throw new Error(`strategyParams[${i}] exceeds the field prime`);
    }
  }
}

export function loadStrategyConfig(): StrategyConfig {
  const params = parseParams(
    process.env.STRATEGY_PARAMS,
    "10,0,0,0,0,0,0,0",
  );
  const salt = process.env.STRATEGY_SALT ?? "999";
  if (!/^\d+$/.test(salt)) throw new Error(`STRATEGY_SALT must be an integer, got ${salt}`);
  validateParams(params);
  return { params, salt, commitment: computeCommitment(params, salt) };
}

/**
 * Build the circuit inputs for a policy proof.
 *
 * The commitment in the public inputs MUST equal the frozen commitment
 * from the turn envelope (the platform checks it against the registered
 * strategy). The caller passes the envelope commitment; this function
 * uses it verbatim (normalised to a field element). The private
 * strategyParams must be the params whose Poseidon hash (with the
 * strategy salt) equals that commitment — otherwise witness
 * generation fails (fail closed upstream: HOLD with no proof).
 */
export function buildPolicyInput(input: PolicyInput): Record<string, unknown> {
  const { state, decision, strategy } = input;
  const commitment = input.commitment ?? state.commitment;
  return {
    matchId: toFieldElement(state.matchId),
    turnNumber: String(state.turn),
    action: ACTION_CODE[decision.action],
    amount: String(decision.action === "EXTRACT" ? (decision.amount ?? 0) : 0),
    opponentBalance: String(state.opponentBalance),
    selfBalance: String(state.selfBalance),
    commitment: commitmentToField(commitment),
    salt: strategy.salt,
    circuitVersion: process.env.CIRCUIT_VERSION ?? "1",
    strategyParams: strategy.params,
  };
}
