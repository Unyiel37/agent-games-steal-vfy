/**
 * Steal the VFY — v1 strategy (deterministic, circuit-bound).
 *
 * WHAT THE CIRCUIT PROVES (empirical, against the published
 * vfy-policy artifacts — see build log / circuit-probe-results.md,
 * 121+ trials in the sweep plus the earlier probes):
 *
 * Prescribed move (p0=params[0], p1=params[1], p2=params[2],
 * p3=params[3], opp=opponentBalance):
 *   if p3 == 1:          → (action=0, amount=0)            HOLD
 *   elif p2 >= opp:      → (action=0, amount=0)            HOLD
 *   elif p1 > ~100..110: → (action=1, amount=0)            (FORTIFY?)
 *   else:                → (action=2, amount=p0)           EXTRACT p0
 *
 *  - params[0] in [1, 10] is the extract cap; the amount MUST equal
 *    params[0] (any other amount fails at template line 149).
 *  - params[3] in {0, 1}; params[4..7] must be 0.
 *  - Turn number has NO effect and no bounds (0, 21, 100 all pass);
 *    selfBalance has NO effect (0, 1, 5, 1000 all pass); no balance
 *    cap and no total-200 requirement.
 *  - Action 1 is provable ONLY as (1, 0) and ONLY when p1 is above
 *    the threshold in (100, 110] (exact point unpinned; whether the
 *    threshold is absolute or relative to a balance is untested).
 *  - Action 3/4 never succeeded anywhere.
 *  - CORRECTION vs the first probes: the move is NOT
 *    state-independent — params[2] compares against opponentBalance
 *    (the earlier "turn 20" effect was really opponentBalance=10).
 *
 * CONSEQUENCE — the phased v1 strategy from the original plan
 * (EXTRACT moderate early, FORTIFY when ahead late, EXTRACT max
 * when behind) is NOT expressible in this circuit as a runtime
 * choice: the p1 branch is state-independent (a committed p1 > 110
 * would make EVERY turn action 1 and never extract), and the only
 * state-dependent branch is p2 >= opp → HOLD. A strategy that
 * deviates from the circuit-prescribed move for its committed
 * params scores nothing on that turn.
 *
 * THEREFORE v1 is: commit params [10,0,0,0,0,0,0,0] (max extract
 * cap, p2=0, p1=0) and EXTRACT 10 on every turn where
 * opponentBalance > 0, HOLD when opponentBalance is 0 (with p2=0,
 * p2 >= opp holds exactly when opp <= 0 — extracting then would
 * fail proof generation and fall back to HOLD anyway, so decide
 * HOLD directly and skip the doomed proof).
 *
 * The `history` argument is accepted for interface compatibility
 * and future opponent-pattern work; v1 is intentionally stateless
 * because the circuit is state-independent.
 */

import type { StrategyConfig } from "./policy.js";

export type ActionName = "HOLD" | "FORTIFY" | "EXTRACT";

export interface TurnState {
  matchId: string;
  turn: number;
  selfBalance: number;
  opponentBalance: number;
  commitment: string;
}

export interface Decision {
  action: ActionName;
  /** Amount in VFY. Only meaningful for EXTRACT; omit for HOLD/FORTIFY. */
  amount?: number;
}

/** The extract cap bound into the committed params (params[0]). */
export function extractCap(strategy: StrategyConfig): number {
  return Number(strategy.params[0]);
}

/**
 * Decide the move for one turn — exactly the circuit-prescribed move
 * for the committed params (see header comment).
 *
 * Rules:
 *  - params[3] === 1 → HOLD (the only provable move for those params).
 *  - params[2] >= opponentBalance → HOLD (circuit rule; with the
 *    default p2=0 this is exactly opponentBalance <= 0).
 *  - params[1] > 100 → the circuit prescribes (1, 0); this function
 *    returns FORTIFY in that case so the committed strategy is
 *    honoured (a registration with p1 > 110 would fortify every
 *    turn — v1 does not use it, params[1] = 0).
 *  - params[0] < 1 (impossible after validateParams) → HOLD.
 *  - Otherwise → EXTRACT params[0].
 */
export function decideTurn(
  state: TurnState,
  _history: TurnState[],
  strategy: StrategyConfig,
): Decision {
  const params = strategy.params.map(Number);
  if (params[3] === 1) return { action: "HOLD" };
  if (params[2] >= state.opponentBalance) return { action: "HOLD" };
  if (params[1] > 100) return { action: "FORTIFY" };
  const cap = params[0];
  if (!(cap >= 1)) return { action: "HOLD" };
  return { action: "EXTRACT", amount: cap };
}

/** One-line human-readable description of the committed strategy. */
export function describeStrategy(strategy: StrategyConfig): string {
  const params = strategy.params.map(Number);
  if (params[3] === 1) return `HOLD every turn (params ${strategy.params.join(",")})`;
  if (params[1] > 100) {
    return `FORTIFY every turn (params ${strategy.params.join(",")}, salt ${strategy.salt})`;
  }
  return `EXTRACT ${params[0]} whenever opponentBalance > ${params[2]} (params ${strategy.params.join(",")}, salt ${strategy.salt}); HOLD otherwise`;
}
