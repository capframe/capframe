<div align="center">

# Capframe

**Capability-based security for AI agents.**

Find what your agents touch. Bind their authority. Guard every call.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Website](https://capframe.ai) · [Docs](https://capframe.ai/docs) · [Discord](https://capframe.ai/discord)

</div>

---

## What is this?

Capframe is a three-module security platform for AI agents that call tools — typically over MCP (Model Context Protocol), though adapters for other tool-calling interfaces are on the roadmap.

It treats every tool call as a capability check:

1. **Discover** the tool surface and find injection gaps.
2. **Mint** scoped, revocable capability tokens.
3. **Enforce** policy at runtime, on every call.

Each module ships as its own crate and CLI subcommand. Use them standalone, or together as a platform.

## The three modules

| Module    | Subcommand        | Source repo                                                       | Status |
| --------- | ----------------- | ----------------------------------------------------------------- | ------ |
| **Find**  | `capframe find`   | [mcp-recon](https://github.com/euanmcrosson-dotcom/mcp-recon)     | Beta   |
| **Bind**  | `capframe bind`   | [capnagent](https://github.com/euanmcrosson-dotcom/capnagent)     | Beta   |
| **Guard** | `capframe guard`  | [mcp-guard](https://github.com/euanmcrosson-dotcom/mcp-guard)     | Beta   |
| **Report**| `capframe report` | (this repo)                                                       | Alpha  |

## Quick start

```bash
# Install the CLI
curl -fsSL https://capframe.ai/install | sh

# 1. Map your agent's tool surface
capframe find ./my-mcp-server.toml

# 2. Mint a scoped capability token for your agent
capframe bind \
  --agent shopify-bot \
  --tools "order.read, refund.write" \
  --max-refund 50.00 \
  --ttl 24h

# 3. Run the runtime sentry
capframe guard --policy ./policy.toml --addr 127.0.0.1:8783

# 4. Produce an audit-ready compliance report
capframe report --findings ./capframe.findings.json --format html --out ./report.html
```

## How the pieces fit

```
   +-------------+      +-------------+      +-------------+
   |  capframe   |      |  capframe   |      |  capframe   |
   |    find     | ---> |    bind     | ---> |    guard    |
   +-------------+      +-------------+      +-------------+
    Discovery            Authority             Enforcement
    (red team)           (capability tokens)   (runtime gate)
          |                    |                    |
          +-------------+------+----------+---------+
                        v                 v
                  findings.json     policy.toml
                        +---------+-------+
                                  v
                         +----------------+
                         | capframe report|
                         +----------------+
                                  |
                                  v
                       OWASP / NIST / ATLAS
                          audit artifact
```

1. **Find** scans MCP servers and writes a structured findings file.
2. **Bind** issues ed25519 holder-of-key capability tokens scoped to what each agent actually needs.
3. **Guard** evaluates every tool call against the token and policies synthesized from Find's findings — before the call hits the tool.
4. **Report** rolls findings + token grants + Guard logs into an audit-ready document.

## Compliance mapping

Every run produces evidence mapped to:

- **OWASP LLM Top 10** — particularly LLM01 (prompt injection), LLM02 (insecure output), LLM07 (insecure plugin design), LLM08 (excessive agency)
- **NIST AI RMF** — Govern / Map / Measure / Manage
- **MITRE ATLAS** — applicable tactics and techniques per finding

Run `capframe report` after any scan or Guard session to produce HTML or PDF output.

## Architecture

Capframe is a Rust workspace:

```
capframe/
├── crates/
│   ├── capframe-cli/        # the dispatcher binary
│   └── capframe-findings/   # shared findings schema (Rust types)
├── schemas/
│   └── findings.v1.json     # the canonical JSON Schema
└── docs/
```

**Design principles**

- **Local-first.** The CLI runs entirely on your machine. No data leaves your environment unless you opt into the hosted control plane.
- **Deterministic.** Guard's policy evaluation is deterministic and auditable — no LLM in the decision path.
- **Composable.** Use Find without Bind. Use Guard without Find. The modules don't require each other.
- **Rust-native.** Single binary, no runtime, easy to deploy.

## Project status

Capframe is pre-1.0. The three modules are independently usable in beta today; the dispatcher CLI and unified report generator are under active development.

Roadmap highlights:

- [ ] `capframe report` v1 (HTML + PDF, signed)
- [ ] OpenAI function-calling adapter
- [ ] Anthropic tool-use adapter
- [ ] LangGraph integration
- [ ] Hosted control plane (private alpha)
- [ ] SOC 2 Type I for hosted offering

## Community

- **Discord:** [capframe.ai/discord](https://capframe.ai/discord)
- **GitHub Discussions:** [github.com/capframe/capframe/discussions](https://github.com/capframe/capframe/discussions)
- **Security disclosures:** security@capframe.ai

## Design partners

Capframe is taking a small number of design partners in regulated industries (financial services, healthcare, defense) for the v1 release. If you're deploying AI agents in a regulated environment, email [hello@capframe.ai](mailto:hello@capframe.ai).

## Contributing

Contributions welcome. The fastest path is opening an issue describing the use case you want supported — we'll triage and tag good first issues.

## License

MIT. See [LICENSE](LICENSE).

---

<div align="center">
<sub>Find. Bind. Guard.</sub>
</div>
