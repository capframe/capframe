"""Shared pytest fixtures for the contained-agent demo test suite.

These tests exercise the REAL mcp_guard policy engine against the REAL
policy.yaml shipped in this demo. They do not call any LLM and cost no
API tokens — they assert properties of the deterministic gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_guard.cli import _policy_from_yaml
from mcp_guard.policy import GeneratedPolicy

from capability_token import ALICE_REFUND_TOKEN
from refund_api import LEGITIMATE_ORDER

POLICY_PATH = Path(__file__).parent / "policy.yaml"


@pytest.fixture(scope="session")
def policy() -> GeneratedPolicy:
    """The actual policy.yaml the demo ships, parsed by the actual
    mcp_guard YAML parser."""
    return _policy_from_yaml(POLICY_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def token() -> dict:
    """The capability token, bound out-of-band from the TRUE order of
    record (not the agent's poisoned context)."""
    return ALICE_REFUND_TOKEN


@pytest.fixture(scope="session")
def legit_call() -> dict:
    """A faithful refund of the real order: the call that MUST be
    allowed. This is the false-positive control."""
    return {
        "order_id": LEGITIMATE_ORDER["order_id"],
        "amount": float(LEGITIMATE_ORDER["total"]),
        "currency": LEGITIMATE_ORDER["currency"],
        "recipient_email": LEGITIMATE_ORDER["customer_email"],
    }
