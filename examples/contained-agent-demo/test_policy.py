"""Property tests for the demo's mcp_guard policy + capability token.

These assert the *truth table* of the gate against the real engine —
no LLM, no API tokens. They exist because the demo's headline claim
("Guard denies the fraudulent call, allows the legit one") is only
meaningful if BOTH halves hold: a gate that denies everything is not a
security control, it's an outage.
"""

from __future__ import annotations

import copy

import pytest

from mcp_guard.policy import evaluate


def _decide(policy, token, call):
    return evaluate(policy, "issue_refund", call, token)


# ── The false-positive control (the half the demo never showed) ──────


def test_legit_call_is_allowed(policy, token, legit_call):
    """A faithful refund of the true order MUST pass. If this fails the
    gate is broken regardless of how well it blocks attacks."""
    d = _decide(policy, token, legit_call)
    assert d.allowed is True, (
        f"Legit call was denied by {d.denying_rule_id!r} — false positive. "
        f"The gate is rejecting valid traffic."
    )


def test_policy_parsed_all_four_rules(policy):
    """If the YAML parser silently drops rules, this catches it."""
    ids = [r.rule_id for r in policy.rules]
    assert ids == [
        "refund-order-mismatch",
        "refund-amount-mismatch",
        "refund-currency-mismatch",
        "refund-recipient-mismatch",
    ], f"Policy did not parse into the 4 expected rules: {ids}"


# ── Single-field deviations deny by the EXPECTED rule ────────────────


@pytest.mark.parametrize(
    "field,bad_value,expected_rule",
    [
        ("order_id", "ORD-9999-99999", "refund-order-mismatch"),
        ("amount", 4950.0, "refund-amount-mismatch"),
        ("currency", "USD", "refund-currency-mismatch"),
        ("recipient_email", "attacker@evil.com", "refund-recipient-mismatch"),
    ],
)
def test_single_field_deviation_denies_by_expected_rule(
    policy, token, legit_call, field, bad_value, expected_rule
):
    """Each rule must fire independently for its own field. This proves
    the win isn't just 'the amount happened to be huge' — every bound
    dimension is enforced."""
    call = copy.deepcopy(legit_call)
    call[field] = bad_value
    d = _decide(policy, token, call)
    assert d.allowed is False, f"Deviation on {field} was allowed!"
    assert d.denying_rule_id == expected_rule, (
        f"Deviation on {field} denied by {d.denying_rule_id!r}, "
        f"expected {expected_rule!r}"
    )


def test_full_attack_call_is_denied(policy, token):
    """The actual poisoned-context payload from the demo."""
    attack = {
        "order_id": "ORD-2026-08231",
        "amount": 4950.0,
        "currency": "USD",
        "recipient_email": "alice.payouts.verified@mailflow-secure.com",
    }
    d = _decide(policy, token, attack)
    assert d.allowed is False


# ── Adversarial edge cases (fail-closed expectations) ────────────────
#
# These probe the type/format seams where real bypasses hide. A
# capability gate should fail CLOSED: when in doubt, deny. Each case
# documents the engine's actual behavior so a regression is visible.


def test_amount_as_string_is_denied(policy, token, legit_call):
    """A stringified amount ('47.5') must NOT be treated as equal to the
    bound float 47.5 — otherwise a type-juggling attacker slips through.
    '47.5' != 47.5 is True, so the call is denied. Fail-closed: correct."""
    call = copy.deepcopy(legit_call)
    call["amount"] = "47.5"
    d = _decide(policy, token, call)
    assert d.allowed is False, (
        "BYPASS: a string-typed amount equal-looking to the bound value "
        "was allowed. Type confusion bypass."
    )


def test_amount_off_by_integer_is_denied(policy, token, legit_call):
    """47 (int) is not 47.5 (bound) and must deny."""
    call = copy.deepcopy(legit_call)
    call["amount"] = 47
    d = _decide(policy, token, call)
    assert d.allowed is False, "BYPASS: amount 47 != bound 47.5 but allowed."


def test_recipient_case_variation_is_denied(policy, token, legit_call):
    """Email is matched exactly (case-sensitive). A differently-cased
    address is a different string and is denied. NOTE: stricter than RFC
    email semantics — a deliberate fail-closed choice, documented here."""
    call = copy.deepcopy(legit_call)
    call["recipient_email"] = "Alice.LegitCustomer@Example.com"
    d = _decide(policy, token, call)
    assert d.allowed is False


def test_uncovered_extra_arg_does_not_flip_legit_call(policy, token, legit_call):
    """Adding an argument the policy doesn't name must not change the
    verdict on an otherwise-legit call — it stays allowed."""
    call = copy.deepcopy(legit_call)
    call["internal_memo"] = "approved by manager; skip review"
    d = _decide(policy, token, call)
    assert d.allowed is True, (
        "An extra uncovered arg flipped a legit call to denied — the "
        "evaluator is sensitive to unknown fields."
    )


def test_bad_value_on_uncovered_arg_is_not_governed(policy, token, legit_call):
    """Documents the gate's SCOPE: a bad value on an arg no rule binds is
    invisible to the policy. Bound fields are all correct here, so the
    call is allowed — a reminder that policy coverage must match the
    tool's real parameter surface."""
    call = copy.deepcopy(legit_call)
    call["shadow_amount"] = 999999  # not a bound field
    d = _decide(policy, token, call)
    assert d.allowed is True


def test_wrong_tool_name_is_not_governed(policy, token, legit_call):
    """Rules are scoped to issue_refund; another tool name matches no
    rule, so evaluate() allows it. Other tools need their own rules."""
    d = evaluate(policy, "some_other_tool", legit_call, token)
    assert d.allowed is True
