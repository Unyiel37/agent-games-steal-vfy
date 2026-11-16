/**
 * Vercel serverless entry point for the Steal the VFY agent.
 *
 * Same protocol as src/server.ts (POST /agent, HMAC-SHA256 over the raw
 * body, deterministic v1 strategy, Groth16 policy proof for every
 * non-HOLD move, fail closed to HOLD with no proof), packaged as a
 * Vercel Node function. Proof generation is local only: Vercel hobby
 * functions time out at 10s and the platform re-verifies the returned
 * proof itself.
 *
 * Required env vars (Vercel dashboard):
 *   AGENT_GAMES_HMAC_SECRET_VFY — platform-issued secret for the Steal
 *     agent (Rotate Secret; NOT the Proof Gatekeeper secret)
 *   CIRCUIT_WASM_PATH           — e.g. ./circuits/vfy-policy.wasm
 *   CIRCUIT_ZKEY_PATH           — e.g. ./circuits/vfy-policy_final.zkey
 *   REGISTERED_VK_HASH          — 0x6c5650…be047 (vfy-policy)
 *   CIRCUIT_VERSION             — e.g. 1
 *   STRATEGY_PARAMS             — e.g. 10,0,0,0,0,0,0,0
 *   STRATEGY_SALT               — e.g. 999
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { decideTurn } from "../dist/strategy.js";
import { generatePolicyProof, CIRCUIT_VERSION } from "../dist/proof.js";
import { loadStrategyConfig, commitmentToField } from "../dist/policy.js";
import { parseTurnEnvelope, asString } from "../dist/envelope.js";

export const config = {
  api: {
    bodyParser: false,
  },
};

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET_VFY ?? "";
const STRATEGY = loadStrategyConfig();

// Responses already sent, keyed by idempotency key — a repeated turn
// gets the IDENTICAL response, not a fresh HOLD.
const responseCache = new Map();
const matchHistory = new Map();

function sign(body) {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}

function verifySignature(rawBody, signature) {
  if (!signature || !SECRET) return false;
  const expected = createHmac("sha256", SECRET).update(rawBody).digest();
  let provided;
  try {
    provided = Buffer.from(signature, "hex");
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": sign(body),
  });
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function holdResponse(matchId, turn) {
  return {
    matchId,
    turn,
    action: "HOLD",
    policyProof: null,
    idempotencyKey: `${matchId}:${turn}`,
  };
}

/** Send a turn response and cache it under its idempotency key. */
function sendTurn(res, idempotencyKey, payload) {
  responseCache.set(idempotencyKey, payload);
  sendJson(res, 200, payload);
}

export default async function handler(req, res) {
  if (req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: "agent-games-steal-vfy" }));
    return;
  }
  if (req.method !== "POST") {
    sendJson(res, 405, { error: "method_not_allowed" });
    return;
  }
  if (!SECRET) {
    console.error("Missing AGENT_GAMES_HMAC_SECRET_VFY");
    sendJson(res, 500, { error: "server_misconfigured" });
    return;
  }

  const rawBody = await readRawBody(req);
  const signature = req.headers["x-agent-games-signature"];
  if (!verifySignature(rawBody, Array.isArray(signature) ? signature[0] : signature)) {
    sendJson(res, 401, { error: "invalid_signature" });
    return;
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString("utf8"));
  } catch {
    sendJson(res, 400, { error: "invalid_json" });
    return;
  }

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
  const deadlineAt = asString(envelope.deadline_at) ?? asString(envelope.deadlineAt);
  if (deadlineAt && Date.now() > Date.parse(deadlineAt)) {
    sendTurn(res, idempotencyKey, holdResponse(state.matchId, state.turn));
    return;
  }

  if (commitmentToField(state.commitment) !== STRATEGY.commitment) {
    console.error(
      `[turn ${state.matchId}:${state.turn}] envelope commitment does not match registered strategy commitment`,
    );
    sendTurn(res, idempotencyKey, holdResponse(state.matchId, state.turn));
    return;
  }

  const history = matchHistory.get(state.matchId) ?? [];
  const decision = decideTurn(state, history, STRATEGY);
  history.push(state);
  matchHistory.set(state.matchId, history.slice(-10));

  if (decision.action === "HOLD") {
    sendTurn(res, idempotencyKey, holdResponse(state.matchId, state.turn));
    return;
  }

  try {
    const generated = await Promise.race([
      generatePolicyProof({
        state,
        decision,
        strategy: STRATEGY,
      }),
      new Promise((_resolve, reject) =>
        setTimeout(() => reject(new Error("proof timeout")), 8_000),
      ),
    ]);
    const response = {
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
    if (decision.action === "EXTRACT") response.amount = decision.amount;
    sendTurn(res, idempotencyKey, response);
  } catch (error) {
    console.error(`[turn ${state.matchId}:${state.turn}] proof generation failed:`, error);
    sendTurn(res, idempotencyKey, holdResponse(state.matchId, state.turn));
  }
}
