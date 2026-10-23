"""The capability token bound to the agent for one specific order.

In production, this is produced by `capframe bind` as an ed25519
holder-of-key token. Here we model it as a plain Python dict that
feeds into mcp-guard's `user_context` parameter — same wire shape,
no key-management ceremony for the demo.

The principle: the agent is authorized to refund THIS order, for
THIS amount, in THIS currency, to THIS recipient. Anything else is
outside the bound capability and must be denied at runtime, before
the refund API ever sees the call.
"""

from __future__ import annotations

from typing import Any

from refund_api import LEGITIMATE_ORDER


def mint_token_for_order(order: dict[str, Any]) -> dict[str, Any]:
    """Bind a single-use refund capability to one order.

    The token's claims are bound at issuance time. The LLM never sees
    these values — the operator who invokes the agent chooses which
    order to bind, and the runtime gate enforces the binding. So
    prompt injection cannot relax the binding: the agent has no
    capability to grant itself more authority than the token allows.
    """
    return {
        "bound_order_id": order["order_id"],
        "bound_amount": float(order["total"]),
        "bound_currency": order["currency"],
        "bound_recipient_email": order["customer_email"],
    }


# The token the support operator mints when triaging Alice's ticket.
# Note: nothing the customer puts in their message can change these
# values. The capability is bound out-of-band, by the operator, in
# the gate — never inside the LLM context.
ALICE_REFUND_TOKEN = mint_token_for_order(LEGITIMATE_ORDER)
