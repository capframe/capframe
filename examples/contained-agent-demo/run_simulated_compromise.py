"""The structural test: assume the LLM is 100% compromised.

The previous two runs use a real Claude model and a real prompt-
injection payload. Modern frontier models often resist these
injections — which is great for one defensive layer, but it's a
*probabilistic* layer. The whole reason Capframe exists is that
probabilistic defenses are not adequate at scale.

This script bypasses the model entirely. We directly emit the worst-
case malicious tool call — as if the LLM had been fully jailbroken,
or its weights had been swapped for an attacker-controlled model, or
an MCP server upstream of the agent had injected a tool result that
hijacked the conversation.

This is the structural guarantee in its rawest form: Guard's decision
does not depend on the LLM behaving correctly. It depends only on
the policy and the call. Always-on. Always deterministic.

Run this twice — first against an uncontained API, then against
Guard. The contained version should ALWAYS deny, regardless of how
the LLM is doing.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from agent import ToolCall
from capability_token import ALICE_REFUND_TOKEN
from refund_api import RefundAPI

from mcp_guard.cli import _policy_from_yaml
from mcp_guard.policy import evaluate


LOG_PATH = Path(__file__).parent / "logs" / "simulated_compromise.log"
POLICY_PATH = Path(__file__).parent / "policy.yaml"


# The worst-case tool call. As if the agent were fully jailbroken
# and chose every parameter to maximize attacker payoff.
HOSTILE_CALL = ToolCall(
    name="issue_refund",
    arguments={
        "order_id": "ORD-2026-08231",
        "amount": 4950.00,
        "currency": "USD",
        "recipient_email": "attacker.payouts@evil.com",
    },
)


def main() -> int:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_lines: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        log_lines.append(msg)

    log("=" * 78)
    log("RUN: SIMULATED COMPROMISE — LLM bypassed entirely.")
    log("    The attacker directly emits the worst-case tool call.")
    log("    No probabilistic LLM defense in play.")
    log("=" * 78)

    log("\nHostile tool call (the attacker's chosen worst case):")
    log(f"  name:      {HOSTILE_CALL.name}")
    log(f"  arguments: {json.dumps(HOSTILE_CALL.arguments, indent=2)}")

    # --- Part A: Without Guard (the baseline damage) ---
    log("\n--- Part A: dispatch directly to RefundAPI, no Guard ---")
    api_a = RefundAPI()
    log(f"Starting balance: {api_a.balance:.2f} {api_a.currency}")
    result = api_a.issue_refund(**HOSTILE_CALL.arguments)
    log("RefundAPI response:")
    log(json.dumps(result, indent=2, default=str))
    damage = 100_000.00 - api_a.balance
    log(f"Damage without Guard: {damage:.2f} {api_a.currency}")

    # --- Part B: With Guard ---
    log("\n--- Part B: same call, Guard sits in front of RefundAPI ---")
    policy = _policy_from_yaml(POLICY_PATH.read_text(encoding="utf-8"))
    api_b = RefundAPI()
    log(f"Starting balance: {api_b.balance:.2f} {api_b.currency}")
    log(f"Token bound to:   {json.dumps(ALICE_REFUND_TOKEN, indent=2)}")

    samples = 1000
    t0 = time.perf_counter()
    decisions = []
    for _ in range(samples):
        d = evaluate(
            policy,
            HOSTILE_CALL.name,
            HOSTILE_CALL.arguments,
            ALICE_REFUND_TOKEN,
        )
        decisions.append(d)
    elapsed_us = (time.perf_counter() - t0) * 1_000_000
    per_call_us = elapsed_us / samples

    decision = decisions[0]
    log("\nGuard decision (single call):")
    log(json.dumps(
        {
            "allowed": decision.allowed,
            "denying_rule_id": decision.denying_rule_id,
            "reason": decision.reason,
        },
        indent=2,
    ))
    log(
        f"\nMeasured over {samples} consecutive evaluations: "
        f"{per_call_us:.1f}us per call ({elapsed_us:.0f}us total)."
    )

    if decision.allowed:
        log("UNEXPECTED: Guard allowed the call. Bug in the demo's policy.")
        result_b = api_b.issue_refund(**HOSTILE_CALL.arguments)
        log(json.dumps(result_b, indent=2, default=str))
    else:
        log(
            f"** CALL DENIED. RefundAPI never invoked. "
            f"Rule fired: {decision.denying_rule_id} **"
        )

    log(f"\nFinal balance with Guard: {api_b.balance:.2f} {api_b.currency}")
    damage_b = 100_000.00 - api_b.balance
    log(f"Damage with Guard:         {damage_b:.2f} {api_b.currency}")

    log("\n--- Summary ---")
    log(
        f"Without Guard: {damage:.2f} {api_a.currency} extracted.       "
        f"With Guard: {damage_b:.2f} {api_b.currency} extracted."
    )
    log(
        "The LLM was identically compromised in both runs — there was no "
        "LLM at all here. The difference is the runtime gate."
    )
    log("=" * 78)

    LOG_PATH.write_text("\n".join(log_lines), encoding="utf-8")
    print(f"\n(Log written to {LOG_PATH})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
