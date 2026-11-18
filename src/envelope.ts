/**
 * Turn-envelope parsing for the Steal the VFY agent.
 *
 * Kept in its own module so both the local server (src/server.ts)
 * and the Vercel function (api/agent.js) can share it without
 * importing server.ts (which starts a listener on import).
 *
 * The exact envelope schema is confirmed at the practice turn; this
 * parser tolerates the field-name variants seen in the public docs
 * and skeleton code.
 */
import type { TurnState } from "./strategy.js";

export function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    const n = Number(value.trim());
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function parseTurnEnvelope(
  envelope: Record<string, unknown>,
): TurnState | null {
  const inner =
    (envelope.input as Record<string, unknown> | undefined) ??
    (envelope.gameState as Record<string, unknown> | undefined) ??
    (envelope.state as Record<string, unknown> | undefined) ??
    envelope;
  const matchId =
    asString(inner.matchId) ??
    asString(inner.match_id) ??
    asString(envelope.matchId);
  const turn =
    asNumber(inner.turn) ??
    asNumber(inner.turnNumber) ??
    asNumber(inner.turn_number) ??
    asNumber(envelope.turn);
  const selfBalance =
    asNumber(inner.selfBalance) ??
    asNumber(inner.myBalance) ??
    asNumber(inner.self_balance);
  const opponentBalance =
    asNumber(inner.opponentBalance) ?? asNumber(inner.opponent_balance);
  // The frozen strategy-commitment hash: a hex string, or an object
  // { hash: "0x..." } (the registration format).
  const commitmentRaw =
    inner.commitment ?? inner.strategyCommitment ?? envelope.commitment;
  let commitment: string | undefined;
  if (typeof commitmentRaw === "string") commitment = commitmentRaw;
  else if (
    commitmentRaw &&
    typeof commitmentRaw === "object" &&
    typeof (commitmentRaw as Record<string, unknown>).hash === "string"
  ) {
    commitment = (commitmentRaw as Record<string, string>).hash;
  }
  if (
    matchId === undefined ||
    turn === undefined ||
    selfBalance === undefined ||
    opponentBalance === undefined
  ) {
    return null;
  }
  // Commitment boleh absen (payload practice tidak membawanya); caller memakai commitment registered. String kosong menandai "absen".
  return { matchId, turn, selfBalance, opponentBalance, commitment: commitment ?? "" };
}
