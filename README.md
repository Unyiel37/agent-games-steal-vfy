# Agent Games — Steal the VFY agent

Agent for the **Steal the VFY** track of [Agent Games by zkVerify](https://agentgames.zkverify.io)
(1v1, 20 turns, each side starts with 100 simulated VFY; prize pool 100,000 VFY:
1st 50K / 2nd 30K / 3rd 20K). Companion to the Proof Gatekeeper agent
(`../agent-games-proof-gatekeeper`, already HEALTHY on Vercel) — same
architecture, different circuit and protocol.

## Status

- Code: complete, built, tested locally (see `../steal-vfy-build-log.md`).
- NOT deployed, NOT registered — the browser steps are listed at the end.

## How it works

- `POST /agent` accepts a signed JSON turn envelope (HMAC-SHA256 over the
  raw body, header `x-agent-games-signature`, secret
  `AGENT_GAMES_HMAC_SECRET_VFY` — a FRESH secret issued when this agent is
  registered; never the Proof Gatekeeper secret).
- Preflight (`{ type: "agent-games.preflight.v1" }`) → `{ ok: true, protocolVersion: "v1" }`.
- Turn (`{ type: "agent-games.steal-the-vfy.v1" }`) → the v1 strategy picks a
  move, a Groth16 policy proof is generated against the `vfy-policy`
  circuit, and the agent answers
  `{ matchId, turn, action, amount?, policyProof: { circuitVersion, proof, public_signals }, idempotencyKey }`.
  `amount` is sent ONLY for EXTRACT.
- Fail closed: bad signature → 401; unknown envelope → 400; expired
  deadline, envelope-commitment mismatch, or any proof failure → HOLD
  with `policyProof: null`. A repeated turn returns the identical cached
  response (same `idempotencyKey` = `${matchId}:${turn}`).

## The circuit (probed first-hand — see `circuit-probe-results.md`)

`vfy-policy` (Groth16 / BN128, vkHash
`0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`):

- 9 public inputs: `matchId, turnNumber, action, amount,
  opponentBalance, selfBalance, commitment, salt, circuitVersion`.
- 1 private input: `strategyParams[8]`.
- `commitment == Poseidon(strategyParams[0..7], salt)` — 9-input Poseidon,
  salt LAST. Registration format: `{"hash": "0x..."}` (32-byte hex of the
  Poseidon output).
- Params validity: `params[0]` in [1, 10]; `params[3]` in {0, 1};
  `params[4..7]` must be 0.
- **The circuit prescribes exactly ONE move per committed params +
  state** (p0=params[0], p1=params[1], p2=params[2], p3=params[3],
  opp=opponentBalance):
  - `p3 = 1` → only `(action=0, amount=0)` (HOLD) succeeds.
  - `p2 >= opp` → only `(action=0, amount=0)` (HOLD) succeeds
    (no upper range bound on p2; 1000 valid).
  - `p1 > ~100..110` → only `(action=1, amount=0)` succeeds
    (exact threshold unpinned; semantics of action 1 unconfirmed).
  - Otherwise → only `(action=2, amount=p0)` succeeds.
  - Turn number has NO effect (0, 21, 100 all pass); selfBalance
    has NO effect; no balance cap, no total-200 requirement.
  - Actions 3/4 never succeeded anywhere.

## Strategy v1 (`src/strategy.ts`)

Commit `params = [10,0,0,0,0,0,0,0]`, salt `999` → **EXTRACT 10 on
every turn where `opponentBalance > 0`, HOLD when it is 0** (with
p2=0, the circuit's `p2 >= opp` HOLD rule fires exactly at opp ≤ 0).
The phased plan (EXTRACT moderate early, FORTIFY when ahead late,
EXTRACT max when behind) is NOT expressible in this circuit as a
runtime choice — the p1 branch is state-independent (a committed
p1 > 110 would make EVERY turn action 1 and never extract), and the
only state-dependent branch is `p2 >= opp` → HOLD. FORTIFY is
reachable only via a different registration (p1 > ~110), which
never extracts — not useful for v1.

## Local dev

```sh
npm install
npm run build          # tsc → dist/
npx tsx src/test-harness.ts   # unit + proof + end-to-end HTTP tests
```

Run the server directly (dummy secret for local testing only):

```sh
AGENT_GAMES_HMAC_SECRET_VFY=test-secret-dummy \
STRATEGY_PARAMS=10,0,0,0,0,0,0,0 STRATEGY_SALT=999 \
node dist/server.js   # POST /agent on :3000, GET /health
```

## Env vars

| Var | Meaning |
| --- | --- |
| `AGENT_GAMES_HMAC_SECRET_VFY` | Fresh platform secret for THIS agent (dashboard → Rotate Secret). Required; server exits without it. |
| `STRATEGY_PARAMS` | 8 comma-separated ints, default `10,0,0,0,0,0,0,0`. Must match the registered commitment. |
| `STRATEGY_SALT` | Salt bound into the commitment, default `999`. Must match registration. |
| `CIRCUIT_VERSION` | Default `1`. |
| `REGISTERED_VK_HASH` | Default `0x6c5650…be047` (vfy-policy). Informational; the proof is verified by the platform. |
| `CIRCUIT_WASM_PATH` / `CIRCUIT_ZKEY_PATH` | Artifact paths; default `./circuits/vfy-policy.wasm` / `./circuits/vfy-policy_final.zkey`. |
| `PORT` | Local server port, default `3000`. |

## Deploy (Vercel — browser steps, NOT done yet)

1. Push this repo to GitHub (public, created after the competition opened).
2. Vercel → import repo → set the env vars above (Production + Preview),
   including the FRESH `AGENT_GAMES_HMAC_SECRET_VFY` from the dashboard.
   `vercel.json` already sets `maxDuration: 10` and includes the circuit
   artifacts; `api/agent.js` is the serverless entry point
   (`/agent` → `/api/agent`).
3. In the Agent Games dashboard: register the Steal the VFY agent with
   endpoint `https://<project>.vercel.app/agent`, strategy commitment
   `{"hash": "<0x… computed from STRATEGY_PARAMS + STRATEGY_SALT>"}`,
   then run preflight + a practice turn and confirm HEALTHY.

Compute the commitment hex locally before registering:

```sh
node -e 'import("./dist/policy.js").then(m => console.log(m.commitmentToHex(m.loadStrategyConfig().commitment)))'
```

## Open unknowns (verify at the practice turn)

- Exact turn-envelope JSON schema (field names; this code tolerates
  `input`/`gameState`/top-level and `matchId`/`match_id`,
  `turn`/`turnNumber`, `selfBalance`/`myBalance` variants).
- Response action encoding (this code sends the string name
  `"HOLD"`/`"EXTRACT"`/`"FORTIFY"`).
- Action enum encoding (working hypothesis HOLD=0, FORTIFY=1, EXTRACT=2 —
  the circuit evidence supports it, the platform's naming is unconfirmed).
- Proof latency on Vercel cold start (local: ~0.6–2.0 s per proof;
  Vercel hobby limit 10 s; `api/agent.js` uses an 8 s proof timeout).

## Files

| File | Purpose |
| --- | --- |
| `src/server.ts` | Local stdlib-HTTP server (POST /agent, HMAC, fail-closed). |
| `src/strategy.ts` | v1 decision logic (circuit-bound). |
| `src/policy.ts` | Circuit inputs, Poseidon commitment, params validation. |
| `src/proof.ts` | snarkjs Groth16 fullProve for vfy-policy. |
| `src/envelope.ts` | Turn-envelope parsing (shared by server + Vercel fn). |
| `src/test-harness.ts` | Local tests: strategy, proof (+timing), HTTP end-to-end. |
| `src/declarations.d.ts` | Minimal TS types for snarkjs / circomlibjs. |
| `api/agent.js` | Vercel serverless entry point (mirrors server.ts, 8 s proof timeout). |
| `circuits/` | vfy-policy.wasm, vfy-policy_final.zkey, vfy-vk.json (git-ignored). |
| `vercel.json` | Build command, artifact includes, maxDuration 10, /agent rewrite. |
| `.env.example` | Env-var template (no real secrets). |
| `circuit-probe-results.md` | Full empirical circuit map (sweep results). |
