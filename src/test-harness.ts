/**
 * Local test harness for the Steal the VFY agent.
 *
 * Run:  npm run build && npx tsx src/test-harness.ts
 * (from the repo root; uses a DUMMY HMAC secret — never a real one.)
 *
 * Checks:
 *  1. decideTurn: extract-mode params → EXTRACT cap in every state;
 *     hold-mode params (params[3]=1) → HOLD.
 *  2. Policy proof: buildPolicyInput + generatePolicyProof + verify
 *     against the vfy-policy vk, with timing (3 runs).
 *  3. HTTP server (spawned as a child on a test port):
 *     - GET /health → 200
 *     - POST /agent preflight (signed) → { ok: true }
 *     - POST /agent turn (signed, correct commitment) → EXTRACT +
 *       policyProof that verifies + response signature valid
 *     - POST the same turn again → byte-identical cached response
 *     - POST turn with a WRONG commitment → HOLD, no proof
 *     - POST with a bad signature → 401
 *     - POST unsigned → 401
 *     - POST unknown envelope type → 400
 *
 * Exit code 0 = all checks pass.
 */

import { createHmac } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import {
  decideTurn,
  type TurnState,
} from "./strategy.js";
import {
  computeCommitment,
  commitmentToHex,
  loadStrategyConfig,
} from "./policy.js";
import { generatePolicyProof, CIRCUIT_VERSION } from "./proof.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TEST_PORT = 3456;
const TEST_SECRET = "test-secret-dummy-never-use-in-production";
const BASE = `http://127.0.0.1:${TEST_PORT}`;

let passed = 0;
let failed = 0;

function check(label: string, ok: boolean, extra = ""): void {
  if (ok) {
    passed++;
    console.log(`  PASS ${label}${extra}`);
  } else {
    failed++;
    console.log(`  FAIL ${label}${extra}`);
  }
}

function sign(body: string, secret = TEST_SECRET): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

async function postAgent(
  envelope: Record<string, unknown>,
  secret: string | null = TEST_SECRET,
): Promise<{ status: number; body: string; json: Record<string, unknown>; sigOk: boolean }> {
  const body = JSON.stringify(envelope);
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (secret !== null) headers["x-agent-games-signature"] = sign(body, secret);
  const res = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers,
    body,
    // The server's proof race is 40 s; a turn must answer within ~45 s.
    signal: AbortSignal.timeout(55_000),
  });
  const text = await res.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    /* non-JSON body */
  }
  const sig = res.headers.get("x-agent-games-signature") ?? "";
  const expected = createHmac("sha256", TEST_SECRET).update(text).digest("hex");
  return { status: res.status, body: text, json, sigOk: sig === expected };
}

async function waitForHealth(server: ChildProcess, timeoutMs = 10_000): Promise<boolean> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`${BASE}/health`, {
        signal: AbortSignal.timeout(2_000),
      });
      if (res.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function main(): Promise<void> {
  console.log("== 1. decideTurn ==");
  const extractCfg = loadStrategyConfig(); // defaults: 10,0,0,0,0,0,0,0 / salt 999
  const holdCfg = {
    params: ["10", "0", "0", "1", "0", "0", "0", "0"],
    salt: "999",
    commitment: computeCommitment(["10", "0", "0", "1", "0", "0", "0", "0"], "999"),
  };
  const states: TurnState[] = [
    { matchId: "12345", turn: 1, selfBalance: 100, opponentBalance: 100, commitment: extractCfg.commitment },
    { matchId: "12345", turn: 20, selfBalance: 190, opponentBalance: 10, commitment: extractCfg.commitment },
    { matchId: "12345", turn: 10, selfBalance: 10, opponentBalance: 190, commitment: extractCfg.commitment },
  ];
  for (const s of states) {
    const d = decideTurn(s, [], extractCfg);
    check(
      `extract-mode turn=${s.turn} self=${s.selfBalance} opp=${s.opponentBalance} → EXTRACT 10`,
      d.action === "EXTRACT" && d.amount === 10,
    );
    const h = decideTurn(s, [], holdCfg);
    check(`hold-mode turn=${s.turn} → HOLD`, h.action === "HOLD");
  }
  // Circuit rule: p2 >= opponentBalance → HOLD. With default p2=0
  // this is exactly opponentBalance <= 0 (extracting then would fail
  // proof generation at template line 140).
  const oppZero: TurnState = {
    matchId: "12345",
    turn: 5,
    selfBalance: 100,
    opponentBalance: 0,
    commitment: extractCfg.commitment,
  };
  check(
    "extract-mode opp=0 → HOLD (p2>=opp rule)",
    decideTurn(oppZero, [], extractCfg).action === "HOLD",
  );
  // Circuit rule: p1 > ~100 → prescribed move is (1, 0).
  const fortifyCfg = {
    params: ["10", "200", "0", "0", "0", "0", "0", "0"],
    salt: "999",
    commitment: computeCommitment(["10", "200", "0", "0", "0", "0", "0", "0"], "999"),
  };
  check(
    "p1=200 → FORTIFY",
    decideTurn(states[0], [], fortifyCfg).action === "FORTIFY",
  );

  console.log("== 2. policy proof (3 runs, timed) ==");
  const vk = JSON.parse(readFileSync(join(ROOT, "circuits", "vfy-vk.json"), "utf8")) as object;
  const proofTimes: number[] = [];
  for (let i = 1; i <= 3; i++) {
    const state = states[0];
    const t0 = Date.now();
    const generated = await generatePolicyProof({
      state,
      decision: { action: "EXTRACT", amount: 10 },
      strategy: extractCfg,
    });
    const ms = Date.now() - t0;
    proofTimes.push(ms);
    const ok = await snarkjs.groth16.verify(vk, generated.publicSignals, generated.proof);
    check(`proof run ${i} verifies (groth16.verify)`, ok === true, ` — ${ms}ms`);
    check(
      `proof run ${i} public signals = 9`,
      generated.publicSignals.length === 9,
      ` — got ${generated.publicSignals.length}`,
    );
    check(
      `proof run ${i} circuitVersion public signal = ${CIRCUIT_VERSION}`,
      generated.publicSignals[8] === CIRCUIT_VERSION,
    );
  }
  const avg = Math.round(proofTimes.reduce((a, b) => a + b, 0) / proofTimes.length);
  const max = Math.max(...proofTimes);
  console.log(`  proof times: ${proofTimes.join("ms, ")}ms — avg ${avg}ms, max ${max}ms (Vercel hobby limit ~10,000ms)`);

  console.log("== 3. HTTP server ==");
  const server = spawn("node", ["dist/server.js"], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(TEST_PORT),
      AGENT_GAMES_HMAC_SECRET_VFY: TEST_SECRET,
      STRATEGY_PARAMS: "10,0,0,0,0,0,0,0",
      STRATEGY_SALT: "999",
    },
    stdio: "pipe",
  });
  server.stdout?.on("data", (d: Buffer) => process.stdout.write(`  [server] ${d}`));
  server.stderr?.on("data", (d: Buffer) => process.stdout.write(`  [server:err] ${d}`));
  try {
    check("server starts (health within 10s)", await waitForHealth(server));

    const health = await fetch(`${BASE}/health`, {
      signal: AbortSignal.timeout(5_000),
    });
    check("GET /health → 200", health.status === 200);

    const preflight = await postAgent({ type: "agent-games.preflight.v1" });
    check("preflight → 200 { ok: true }", preflight.status === 200 && preflight.json.ok === true);
    check("preflight response signature valid", preflight.sigOk);

    const commitmentHex = commitmentToHex(extractCfg.commitment);
    const turnEnvelope = {
      type: "agent-games.steal-the-vfy.v1",
      matchId: "12345",
      turn: 1,
      selfBalance: 100,
      opponentBalance: 100,
      commitment: commitmentHex,
    };
    const turn1 = await postAgent(turnEnvelope);
    check("turn 1 → 200", turn1.status === 200);
    check("turn 1 action = EXTRACT", turn1.json.action === "EXTRACT");
    check("turn 1 amount = 10", turn1.json.amount === 10);
    check("turn 1 idempotencyKey = 12345:1", turn1.json.idempotencyKey === "12345:1");
    check("turn 1 response signature valid", turn1.sigOk);
    const pp = turn1.json.policyProof as
      | { circuitVersion: string; proof: unknown; public_signals: string[] }
      | null;
    check("turn 1 policyProof present", pp !== null && typeof pp === "object");
    if (pp) {
      check("turn 1 policyProof.circuitVersion = 1", pp.circuitVersion === "1");
      const ok = await snarkjs.groth16.verify(vk, pp.public_signals, pp.proof);
      check("turn 1 policyProof verifies against vk", ok === true);
    }

    const turn1Repeat = await postAgent(turnEnvelope);
    check(
      "repeat turn 1 → byte-identical cached response",
      turn1Repeat.body === turn1.body,
    );

    const wrongCommitment = await postAgent({
      ...turnEnvelope,
      turn: 2,
      commitment: "0x0000000000000000000000000000000000000000000000000000000000000001",
    });
    check("wrong commitment → HOLD", wrongCommitment.json.action === "HOLD");
    check("wrong commitment → no proof", wrongCommitment.json.policyProof === null);

    const badSig = await postAgent(turnEnvelope, "wrong-secret");
    check("bad signature → 401", badSig.status === 401);

    const unsigned = await postAgent(turnEnvelope, null);
    check("unsigned → 401", unsigned.status === 401);

    const unknownType = await postAgent({ type: "agent-games.nope.v1" });
    check("unknown envelope type → 400", unknownType.status === 400);
  } finally {
    server.kill("SIGTERM");
  }

  console.log(`\nRESULT: ${passed} passed, ${failed} failed`);
  // NOTE: snarkjs leaves worker threads (sockets/MessagePorts) behind
  // after fullProve, so the process never exits on its own — exit
  // explicitly. This does not affect the server (long-running) or
  // Vercel (the response is sent when the handler resolves).
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((error) => {
  console.error("harness crashed:", error);
  process.exit(1);
});
