
<div align="center">

# Capframe — Capability Security for AI Agents

**Built for agentic AI — not just LLMs.**

Capframe is a deterministic security system that helps you control what AI agents can do when they use tools. It discovers risky capabilities, issues scoped permissions through capability tokens, and enforces them at runtime — without putting an LLM in the security decision path.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Website](https://capframe.ai) · [Docs](https://capframe.ai/docs) · [Discord](https://capframe.ai/discord)

</div>

---

## Why Capframe?

 Modern AI agents can take real actions through tools (file systems, APIs, code execution, databases, etc.). Without proper controls, these agents become high-risk systems vulnerable to prompt injection, confused deputy attacks, and unintended or malicious behavior. 
Capframe is a three-module security platform for AI agents that call tools — typically over MCP (Model Context Protocol), that fixes this underlying problem ! 

## Architecture

1. **Find** the tool surface and the injection gaps in it.
2. **Bind** the agent's authority with scoped, revocable capability tokens.
3. **Guard** every call at runtime — deterministic policy, no LLM in the decision path.

The `capframe` binary is a single dispatcher CLI. The three modules ship from their own repos and are resolved at runtime from `PATH`:

| Module | Subcommand | Source repo | Distribution |
|---|---|---|---|
| **Find** | `capframe find` | [mcp-recon](https://github.com/euanmcrosson-dotcom/mcp-recon) | GitHub Releases (native binary) |
| **Bind** | `capframe bind` | [capnagent](https://github.com/euanmcrosson-dotcom/capnagent) | GitHub Releases  |
| **Guard** | `capframe guard` | [mcp-guard](https://github.com/euanmcrosson-dotcom/mcp-guard) | GitHub Releases + PyPI (`mcp-guardrails`) |
| **Report** | `capframe report` | (this repo) | shipped with capframe |

Each module is independently usable. Capframe gives them a shared CLI, a shared findings format ([`findings.v1`](schemas/findings.v1.json)), and a unified audit report.

For a map of this repo's internals — crates, dispatch, the version gate, the wire schema, and the leaderboard pipeline — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).



Components

Component:    role:       language:Repository     
mcp-recon,Tool discovery & risk classification,Rust,GitHub
capnagent,Capability token issuance,Rust,GitHub
mcp-guard,Runtime policy enforcement,Python,GitHub


## Install

```bash
# Install the dispatcher CLI
curl -fsSL https://capframe.ai/install | sh                # Linux / macOS
iwr -useb https://capframe.ai/install.ps1 | iex            # Windows PowerShell

# Then pull the three modules with sha256-verified binaries
capframe install                                            # all three
capframe install find bind guard                            # explicit
capframe install bind --version v0.7.4                      # pin one
```

`capframe install` downloads each module's release archive from its GitHub repo, verifies the `.sha256` sidecar, extracts the binary into `~/.capframe/bin`, and records the pinned version in `~/.capframe/state.json`. Add `~/.capframe/bin` to your `PATH`.

If you'd rather install via Python: `pip install capnagent mcp-guardrails` covers Bind and Guard.

Verify everything is wired:

```bash
capframe doctor
```

`doctor` resolves each module's binary, runs `--version`, and confirms it satisfies capframe's compatibility band (see [version policy](#version-policy)).

## Quick start

```bash
# 1. Map your agent's tool surface
capframe find ./my-mcp-server.toml

# 2. Mint a scoped capability token
capframe bind \
  --agent shopify-bot \
  --tools "order.read, refund.write" \
  --limit max_refund=50.00 \
  --limit region=eu \
  --ttl 24h

# 3. Synthesize / backtest / evaluate policies via mcp-guard
capframe guard synthesize "the agent issued a refund larger than the cap"
capframe guard backtest ./policy.yaml
capframe guard evaluate ./policy.yaml order.refund '{"amount": 50}'

# 4. Produce an audit-ready compliance report
capframe report --findings capframe.findings.json --format html --out report.html
capframe report --findings capframe.findings.json --format pdf  --out report.pdf
```

`--format pdf` requires `weasyprint` or a Chromium/Chrome binary on `PATH`. Capframe auto-detects whichever is present; override with `--pdf-tool weasyprint|chromium|chrome`.

`--limit` is repeatable. It replaces the old `--max-refund` flag with a generic constraint passthrough. Keys must match `[A-Za-z0-9_.]+`. The dispatcher forwards each one as `--limit key=value` to the underlying bind module.

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
                       OWASP / NIST / ATLAS/ CAST
                          audit artifact
```

1. **Find** scans MCP servers and emits a `findings.v1.json` document.
2. **Bind** issues ed25519 holder-of-key capability tokens scoped to what each agent actually needs.
3. **Guard** evaluates every tool call against the token + a policy synthesized from Find's output — deterministic, single-digit microsecond decisions.
4. **Report** rolls findings (and, on the roadmap, token grants + Guard logs) into an HTML / PDF audit document.


CAST — Capframe Agent Security Taxonomy
Capframe introduces CAST (Capframe Agent Security Taxonomy), a set of risk categories specifically designed for tool-using AI agents.
CAST defines 8 core risk categories that go beyond traditional LLM frameworks, including:

Tool Capability Excess
Indirect Injection via Tool Output
Insufficient Capability Scoping
Tool Metadata Poisoning
Capability Boundary Violation
Cross-Tool Propagation
Persistent State Poisoning
Uncontrolled Tool Invocation

→ View full CAST documentation
Each CAST category maps directly to Capframe’s modules, making the taxonomy actionable rather than theoretical.


## Security posture

A security tool that hasn't audited itself is a security claim. Capframe ships under the audit posture we apply to other people's code: every module is versioned, CHANGELOGed, and carries a directed test corpus for the threat class it's designed to detect. We run a hardening pass across the three modules on a quarterly cadence; the 2026-05 pass found and fixed two real defects, both of the same shape — a serialization layer that silently accepts more than the consumer can parse.

- **mcp-guard 0.5.7 — type-confusion fail-open in the policy evaluator.** Positive deny operators (`contains`, `matches`, `starts_with`, `equals`, `in`) returned `False` ("don't deny") the instant the argument was not a plain `str`. A rule that caught the literal value `"x@evil.com"` failed to fire when the same value arrived as `["x@evil.com"]` (list) or `{"to": "x@evil.com"}` (dict). Fixed by recursing positive ops through list/tuple/dict; negative and allow-list ops kept whole-value to avoid opening a different bypass class. Corpus expanded with an explicit type-confusion category (304 → 308 cases; TPR holds at 1.00, FPR unchanged).

- **mcp-recon 0.2.3 — Debug-formatter mismatch on the Find→Bind handoff.** `caveats_v1` embedded tool names into `tool == "…"` / `tool != "…"` predicates via Rust's `Debug` formatter, which emits `\r`, `\0`, and `\u{..}` escapes capnagent's caveat-DSL parser rejects. Any tool name carrying such a character produced a caveat string that failed parsing on the receiving end, silently breaking the handoff — and since the upstream MCP server controls the name, a hostile server could weaponize the gap. Fixed with an explicit DSL-safe serializer; tool names containing un-escapable control characters now fail closed to a `recommend: "deny"` plan instead of emitting unparseable caveats. Tests round-trip every predicate through a vendored equivalent of the consumer's parser (35 → 45 core tests).

- **capnagent 0.7.4** went through the same pass without surfacing a parallel defect. That is not a claim the module is bug-free; it is the honest record of what this review found.

Both defects were located by reading both sides of the relevant boundary, not by fuzzing — fuzzing finds crashes, directed code reading finds silent fail-opens. Both were fixed under TDD with the failing test written first, and the corpus that proved the defect is retained as a regression guard. The pattern they share — a defensive layer being more lenient than the layer it hands off to — is the canonical class for security-tool boundary bugs, and the next pass will look for more of it.

See each module's CHANGELOG for the full record, including what didn't change.

## Compliance mapping

Each finding carries identifiers from:

- **OWASP LLM Top 10** — `LLM01` … `LLM10`
- **NIST AI RMF** — `GOVERN-*` / `MAP-*` / `MEASURE-*` / `MANAGE-*`
- **MITRE ATLAS** — `T####` and `T####.###`

The JSON Schema validates these patterns at the wire level; the example payload in `schemas/findings.example.json` is exercised in CI.

Use Cases

Securing autonomous coding and research agents
Protecting internal enterprise AI agents with tool access
Building compliant AI systems in regulated industries
Sandboxing agent capabilities during development and testing
```

**Design principles**

- **Local-first.** The CLI runs entirely on your machine. No telemetry. No data leaves your environment unless you opt into the hosted control plane.
- **Deterministic.** Guard's policy evaluation is deterministic and auditable — no LLM in the decision path.
- **Composable.** Use Find without Bind. Use Guard without Find. The modules don't require each other.
- **Rust-native dispatcher.** Single binary, no runtime, easy to deploy. The underlying Find/Bind modules ship as native Rust binaries; Guard ships as a PyInstaller-bundled native binary.

## Version policy

Capframe pins each module to a semver range it has verified wire-compatibility with. On every dispatch, capframe runs `<module> --version`, parses the output, and refuses to invoke an incompatible binary. Mismatches print a `capframe install <module>` hint.

| Module | Required range | Pinned via |
|---|---|---|
| mcp-recon (Find)  | `>=0.0.1, <0.1.0` | `modules.rs::Module::version_req` |
| capnagent (Bind)  | `>=0.7.0, <0.8.0` | `modules.rs::Module::version_req` |
| mcp-guard (Guard) | `>=0.5.0, <0.6.0` | `modules.rs::Module::version_req` |

Bump these in lockstep with breaking CLI changes in the underlying modules.

## Project status

Capframe is pre-1.0. The three modules are independently usable today; the dispatcher CLI, sha256-verified installer, version-pinning gate, and HTML/PDF report generator landed at v0.2.


Philosophy
Capframe is built on three core principles:

Deterministic Security — Security decisions must be reproducible and auditable.
Least Privilege — Agents should only receive the capabilities they explicitly need.
Defense in Depth — Combine discovery, authorization, and enforcement.

Roadmap:

- [x] `capframe install` with sha256 verification + version pinning
- [x] `capframe report` HTML (maud-templated) + PDF (weasyprint/chromium dispatch)
- [x] JSON-Schema-conformance test suite for `findings.v1`
- [ ] In-process module dispatch (drop the subprocess hop for find/bind)
- [ ] Native PDF rendering without external tool
- [ ] OpenAI function-calling adapter
- [ ] Anthropic tool-use adapter
- [ ] LangGraph integration
- [ ] Hosted control plane (private alpha)
- [ ] SOC 2 Type I for hosted offering

## Development

```bash
cargo test --workspace          # 17 tests (CLI dispatch, schema conformance, unit)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The CI workflow (`.github/workflows/ci.yml`) runs all of the above on Linux, macOS, and Windows, plus a Python-driven schema validator against `schemas/findings.example.json`.

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
