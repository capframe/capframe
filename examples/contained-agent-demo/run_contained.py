"""Run the SAME agent against the SAME attack WITH Capframe Guard.

Identical agent. Identical model. Identical prompt-injection payload.
Identical Anthropic API call. Identical tool-use decision from Claude.

The only difference: between Claude's tool-call decision and the
refund API, we evaluate the call against the mcp-guard policy bound
to the agent's capability token. If the call falls outside the token,
the refund API never sees the call.

Expected outcome: the attack is denied. No fraudulent refund. No
financial damage. The agent is *structurally contained* — not because
the LLM defended itself, but because the runtime gate doesn't care
what the LLM decided.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from agent import run_agent
from capability_token import ALICE_REFUND_TOKEN
from refund_api import ATTACK_CUSTOMER_MESSAGE, RefundAPI

from mcp_guard.cli import _policy_from_yaml
from mcp_guard.policy import evaluate


LOG_PATH = Path(__file__).parent / "logs" / "contained.log"
POLICY_PATH = Path(__file__).parent / "policy.yaml"


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "ERROR: ANTHROPIC_API_KEY not set. Export it and try again.",
            file=sys.stderr,
        )
        return 1

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_lines: list[str] = []

    def log(msg: str) -> None:
        print(msg)
        log_lines.append(msg)

    log("=" * 78)
    log("RUN: CONTAINED — Capframe Guard sits between agent and refund API")
    log("=" * 78)

    log("\nLoading policy from " + str(POLICY_PATH.name))
    policy = _policy_from_yaml(POLICY_PATH.read_text(encoding="utf-8"))
    log(f"  Policy has {len(policy.rules)} rule(s).")
    for rule in policy.rules:
        log(f"   - {rule.rule_id}: deny if {len(rule.conditions)} condition(s) match")

    refund_api = RefundAPI()
    log(f"\nStarting balance: {refund_api.balance:.2f} {refund_api.currency}")

    log("\n--- Capability token bound to this agent's session ---")
    log(json.dumps(ALICE_REFUND_TOKEN, indent=2))
    log("---")

    log("\n--- Customer message (identical hostile payload) ---")
    log(ATTACK_CUSTOMER_MESSAGE)
    log("--- End customer message ---\n")

    log("Calling Claude with the customer message + issue_refund tool...")
    t_start = time.perf_counter()
    turn = run_agent(ATTACK_CUSTOMER_MESSAGE)
    t_llm = (time.perf_counter() - t_start) * 1000

    log(f"\nModel: {turn.model}")
    log(f"Claude response time: {t_llm:.0f}ms")
    if turn.text_before_tool:
        log(f"\nClaude's commentary:\n{turn.text_before_tool}")

    if turn.tool_call is None:
        log("\nClaude declined to call the refund tool. Nothing for Guard to evaluate.")
        log("(In a hostile environment, do not rely on this. Capframe contains")
        log("the attack even when the LLM is fully compromised.)")
        log("=" * 78)
        LOG_PATH.write_text("\n".join(log_lines), encoding="utf-8")
        return 0

    log(f"\nClaude chose to call: {turn.tool_call.name}")
    log(f"with arguments:\n{json.dumps(turn.tool_call.arguments, indent=2)}")

    log("\n>>> Capframe Guard intercepts the call before the refund API sees it.")
    t_guard_start = time.perf_counter()
    decision = evaluate(
        policy,
        turn.tool_call.name,
        turn.tool_call.arguments,
        ALICE_REFUND_TOKEN,
    )
    t_guard = (time.perf_counter() - t_guard_start) * 1_000_000  # microseconds

    log(f"\nGuard decision (computed in {t_guard:.1f}us):")
    log(json.dumps(
        {
            "allowed": decision.allowed,
            "denying_rule_id": decision.denying_rule_id,
            "reason": decision.reason,
        },
        indent=2,
    ))

    if decision.allowed:
        log("\nCall ALLOWED. Forwarding to refund API.")
        result = refund_api.issue_refund(**turn.tool_call.arguments)
        log(f"\nRefundAPI response:\n{json.dumps(result, indent=2, default=str)}")
    else:
        log(
            f"\n** CALL DENIED at Guard. RefundAPI never invoked. "
            f"Rule fired: {decision.denying_rule_id} **"
        )

    log(f"\nFinal balance: {refund_api.balance:.2f} {refund_api.currency}")
    log(f"Final ledger:  {len(refund_api.ledger)} refund(s)")

    damage = 100_000.00 - refund_api.balance
    log(f"\nFinancial damage: {damage:.2f} {refund_api.currency}")
    log("=" * 78)

    LOG_PATH.write_text("\n".join(log_lines), encoding="utf-8")
    print(f"\n(Log written to {LOG_PATH})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
