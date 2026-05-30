# Capframe demo walkthrough — Find → Bind → Guard

This is the prose-and-fixture version of `examples/demo.tape`. Read it
end-to-end and you've seen the full pipeline; copy-paste the commands
on a machine with the binaries installed and you reproduce it.

If you want a recorded GIF instead, run the VHS tape:

```sh
vhs examples/demo.tape   # produces examples/demo.gif
```

VHS is a charmbracelet tool: https://github.com/charmbracelet/vhs.

## What we're scanning

`examples/shopify-mcp.inventory.json` — a deliberately mixed surface.
A few well-defended tools (`order.list` with bounded `since` /
`limit`), one authority-relevant one (`order.refund` with no monetary
cap), and one nominally-missing-auth tool (`fulfill.send_tracking`).
This is the kind of inventory mcp-recon produces from a real config
via `mcp-recon enumerate`.

## 1. Find — emit findings.v1

```sh
capframe find examples/shopify-mcp.inventory.json --out findings.json --pretty
```

`capframe find` dispatches to `mcp-recon` under the hood. Output is a
[`capframe.findings.v1`](https://capframe.ai/docs/findings-v1) JSON
document:

```sh
jq '.summary' findings.json
```

```json
{
  "total": 3,
  "by_severity": {
    "info": 0,
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 0
  },
  "by_category": {
    "excessive_agency": 1,
    "missing_authz": 1,
    "unconstrained_input": 1
  }
}
```

The interesting ones:

```sh
jq '[.findings[] | {id, severity, category, title}]' findings.json
```

```json
[
  {
    "id": "f-r4-order-refund",
    "severity": "high",
    "category": "excessive_agency",
    "title": "Tool `order.refund` accepts an unbounded money amount"
  },
  {
    "id": "f-r2-fulfill-send-tracking",
    "severity": "high",
    "category": "missing_authz",
    "title": "Tool `fulfill.send_tracking` sends external messages but auth is not required"
  },
  {
    "id": "f-r1-order-refund",
    "severity": "medium",
    "category": "unconstrained_input",
    "title": "Tool `order.refund` accepts unconstrained string input"
  }
]
```

R4 caught the unbounded `amount` parameter — that's the Critical
case to worry about for a refund tool. R2 caught the auth gap. R1
caught the unconstrained `reason` string. All three deterministic, all
three reproducible.

## 2. Bind — capability caveats from the findings

```sh
capframe bind examples/shopify-mcp.inventory.json --out caveats.json --pretty
```

`capframe bind` dispatches to `mcp-recon caveats`, which turns each
authority-relevant finding into an issuance plan capnagent can mint
into a token:

```sh
jq '.plans[] | {tool, recommend, caveats: [.caveats[].dsl]}' caveats.json
```

```json
{
  "tool": "order.refund",
  "recommend": "scope",
  "caveats": [
    "amount <= 100.00",
    "amount >= 0.01",
    "reason.length <= 256"
  ]
}
{
  "tool": "fulfill.send_tracking",
  "recommend": "deny",
  "caveats": []
}
```

The output is intentionally machine-readable: capnagent (Capframe's
**Bind** module) consumes it to mint a macaroon-style capability
token.

```sh
capnagent issue --plan caveats.json --out token.bin
file token.bin
# token.bin: data
stat -c '%s bytes' token.bin
# 412 bytes
```

The token carries the caveats inline. Pass it to the agent runtime;
caveat enforcement is the guard's job.

## 3. Guard — evaluate the token at call time

The same caveats that bound the agent now block calls that exceed
them. A legit refund within bounds is **allowed**:

```sh
capframe guard --token token.bin --tool order.refund --args '{"order_id":"123","amount":47.50}'
```

```
ALLOW order.refund
  amount=47.50 ≤ 100.00 ✓
  amount=47.50 ≥ 0.01 ✓
  reason absent, no length check
```

A call past the cap is **denied** with the exact caveat citation:

```sh
capframe guard --token token.bin --tool order.refund --args '{"order_id":"123","amount":9999.00}'
```

```
DENY order.refund
  amount=9999.00 > 100.00 (caveat: amount <= 100.00, from f-r4-order-refund)
```

Note the citation: the deny carries the originating finding id, so
incident response can map back to "this exact rule caught it." That's
the wire-format compounding — `findings.v1` flows through all three
modules.

## Repro discipline

- **Deterministic.** Same inputs → same outputs every run. Rerun
  the pipeline and the JSON is byte-for-byte identical.
- **No LLM in the decision path.** The classifier is rule code.
  The token verifier is a parser + caveat evaluator.
- **All three modules consume the same schema.** Pass a
  `findings.v1` blob between them; they don't care which one wrote
  it, as long as the schema validates.

## Going further

- [capframe.ai/quickstart](https://capframe.ai/quickstart) — same
  flow as the first 4 steps, in prose, on the public site.
- [capframe.ai/docs/findings-v1](https://capframe.ai/docs/findings-v1)
  — every field of the wire format, with the schema regex patterns.
- [capframe.ai/leaderboard](https://capframe.ai/leaderboard) — the
  same scanner running daily against 72+ real MCP servers.

## Verifying this walkthrough

The fixture in step 0 (`examples/shopify-mcp.inventory.json`) is
real. The commands in steps 1–3 are the public CLI surface of
`capframe`, `mcp-recon`, and `capnagent`. The JSON snippets shown
above are **representative output drawn from real fixture runs**
of mcp-recon's `caveats` command on the shopify inventory. If the
binary surface drifts (flag names, output keys), the walkthrough
will drift with it — patch as needed.
