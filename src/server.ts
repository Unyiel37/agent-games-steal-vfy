/**
 * Steal the VFY agent — public HTTPS endpoint for zkVerify Agent Games.
 *
 * Protocol (Steal the VFY):
 *  - POST /agent accepts a signed JSON turn envelope.
 *  - Every inbound request is authenticated first: HMAC-SHA256 over the
 *    RAW request body, compared against the `x-agent-games-signature`
 *    header with the platform-issued secret (AGENT_GAMES_HMAC_SECRET_VFY).
 *    The secret is a FRESH one issued when the Steal agent is registered
 *    in the dashboard — it is NOT the Proof Gatekeeper secret.
 *  - Preflight requests ({ type: "agent-games.preflight.v1" }) are
 *    answered with { ok: true, protocolVersion: "v1" }, signed.
 *  - Turn requests ({ type: "agent-games.steal-the-vfy.v1" }) carry the
 *    game state (both balances, frozen strategy-commitment hash,
 *    deadline). The agent picks a move with the deterministic v1
 *    strategy (see strategy.ts), generates a Groth16 policy proof
 *    (see proof.ts / policy.ts) and answers with
 *    { matchId, turn, action, amount?, policyProof, idempotencyKey },
 *    signed over the raw response body.
 *  - Fail closed: any error, timeout, or uncertainty is a HOLD with NO
 *    proof (never a fake proof, never a guessed action). A missed turn
 *    costs -1; an invalid proof costs -2 — so a valid HOLD beats a
 *    broken EXTRACT.
 *
 * ASSUMPTIONS (to verify at the practice turn — see README / build log):
 *  - Turn envelope type is "agent-games.steal-the-vfy.v1".
 *  - Envelope state fields: matchId, turn (or turnNumber), selfBalance
 *    (or myBalance), opponentBalance, commitment (hex string or
 *    { hash } object).
 *  - Response action is the string name ("HOLD" / "EXTRACT" /
 *    "FORTIFY"); `amount` is omitted entirely for HOLD and FORTIFY.
 *  - `policyProof` is an object { circuitVersion, proof, public_signals }
 *    (per the Build guide, not top-level fields).
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { decideTurn, type ActionName, type TurnState } from "./strategy.js";
import { parseTurnEnvelope, asString } from "./envelope.js";
import { generatePolicyProof, CIRCUIT_VERSION } from "./proof.js";
import {
  commitmentToField,
  loadStrategyConfig,
  type StrategyConfig,
} from "./policy.js";

const PORT = Number(process.env.PORT ?? 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET_VFY;

if (!HMAC_SECRET) {
  console.error(
    "Missing AGENT_GAMES_HMAC_SECRET_VFY. Copy the one-time secret from the Agent Games dashboard (Rotate Secret, Steal the VFY agent) into your environment and restart.",
  );
  process.exit(1);
}

const SECRET = HMAC_SECRET as string;
const STRATEGY: StrategyConfig = loadStrategyConfig();

// Per-match history, used by the strategy to infer the opponent's
// extract pattern from successive balance deltas. In-memory only;
// a restart loses it (the strategy degrades gracefully to stateless).
const matchHistory = new Map<string, TurnState[]>();

// Responses already sent, keyed by idempotency key — a repeated turn
// gets the IDENTICAL response, not a fresh HOLD.
const responseCache = new Map<string, Record<string, unknown>>();

function sign(body: string): string {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}

function verifySignature(rawBody: Buffer, signature: string | undefined): boolean {
  if (!signature) return false;
  const expected = createHmac("sha256", SECRET).update(rawBody).digest();
  let provided: Buffer;
  try {
    provided = Buffer.from(signature, "hex");
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": sign(body),
  });
  res.end(body);
}

/** Send a turn response and cache it under its idempotency key. */
function sendTurn(
  res: ServerResponse,
  idempotencyKey: string,
  payload: Record<string, unknown>,
): void {
  responseCache.set(idempotencyKey, payload);
  sendJson(res, 200, payload);
}

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function holdResponse(matchId: string, turn: number): Record<string, unknown> {
  return {
    matchId,
    turn,
    action: "HOLD" as ActionName,
    policyProof: null,
    idempotencyKey: `${matchId}:${turn}`,
  };
}

async function handleAgent(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const rawBody = await readRawBody(req);
  const signature = req.headers["x-agent-games-signature"];
  if (!verifySignature(rawBody, Array.isArray(signature) ? signature[0] : signature)) {
    sendJson(res, 401, { error: "invalid_signature" });
    return;
  }

  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
  } catch {
    sendJson(res, 400, { error: "invalid_json" });
    return;
  }

  // Preflight handshake — must pass before the platform marks the agent active.
  if (envelope.type === "agent-games.preflight.v1") {
    sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    return;
  }

  if (envelope.type !== "agent-games.steal-the-vfy.v1") {
    sendJson(res, 400, { error: "unknown_envelope_type" });
    return;
  }

  const state = parseTurnEnvelope(envelope);
  if (!state) {
    sendJson(res, 400, { error: "missing_turn_state" });
    return;
  }

  const idempotencyKey = `${state.matchId}:${state.turn}`;

  // A repeated turn gets the identical response (same idempotency key).
  const cached = responseCache.get(idempotencyKey);
  if (cached) {
    sendJson(res, 200, cached);
    return;
  }

  // Deadline check — an expired turn is a HOLD (never a late proof).
  const deadlineAt =
    asString(envelope.deadline_at) ?? asString(envelope.deadlineAt);
  if (deadlineAt && Date.now() > Date.parse(deadlineAt)) {
    sendTurn(res, idempotencyKey, holdResponse(state.matchId, state.turn));
    return;
  }

  // The envelope commitment must equal our registered strategy
  // commitment — otherwise the proof cannot verify (fail closed).
  if (commitmentToField(state.commitment) !== STRATEGY.commitment) {
    console.error(
      `[turn ${state.matchId}:${state.turn}] envelope commitment does not match registered strategy commitment`,
    );
    sendTurn(res, idempotencyKey, holdResponse(state.matchId, state.turn));
    return;
  }

  // Track history for opponent-pattern inference (best effort).
  const history = matchHistory.get(state.matchId) ?? [];
  const decision = decideTurn(state, history, STRATEGY);
  history.push(state);
  matchHistory.set(state.matchId, history.slice(-10));

  // HOLD needs no proof — answer immediately.
  if (decision.action === "HOLD") {
    sendTurn(res, idempotencyKey, holdResponse(state.matchId, state.turn));
    return;
  }

  // Every other move needs a valid policy proof. Any failure is a HOLD.
  try {
    const startedAt = Date.now();
    const generated = await Promise.race([
      generatePolicyProof({
        state,
        decision,
        strategy: STRATEGY,
      }),
      new Promise<never>((_resolve, reject) =>
        setTimeout(() => reject(new Error("proof timeout")), 40_000),
      ),
    ]);
    console.log(
      `[turn ${state.matchId}:${state.turn}] ${decision.action} ${decision.amount ?? ""} proof in ${Date.now() - startedAt}ms`,
    );
    const response: Record<string, unknown> = {
      matchId: state.matchId,
      turn: state.turn,
      action: decision.action,
      policyProof: {
        circuitVersion: CIRCUIT_VERSION,
        proof: generated.proof,
        public_signals: generated.publicSignals,
      },
      idempotencyKey,
    };
    // amount is only meaningful for EXTRACT; omit it for FORTIFY.
    if (decision.action === "EXTRACT") response.amount = decision.amount;
    sendTurn(res, idempotencyKey, response);
  } catch (error) {
    console.error(
      `[turn ${state.matchId}:${state.turn}] proof generation failed:`,
      error,
    );
    sendTurn(res, idempotencyKey, holdResponse(state.matchId, state.turn));
  }
}

export const server = createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: "agent-games-steal-vfy" }));
    return;
  }
  if (req.method === "POST" && req.url === "/agent") {
    handleAgent(req, res).catch((error) => {
      console.error("handler error:", error);
      if (!res.headersSent) sendJson(res, 500, { error: "internal_error" });
    });
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
});

// Only listen when run directly (node dist/server.js). Importing this
// module (e.g. from the Vercel function via envelope.js) must NOT
// start a listener.
const isMain =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  server.listen(PORT, () => {
    console.log(`Steal the VFY agent listening on port ${PORT} (POST /agent)`);
  });
}
