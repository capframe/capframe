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

1. **Find** the tool surface and the injection gaps in it.
2. **Bind** the agent's authority with scoped, revocable capability tokens.
3. **Guard** every call at runtime — deterministic policy, no LLM in the decision path.

The `capframe` binary is a single dispatcher CLI. The three modules ship from their own repos and are resolved at runtime from `PATH`:

| Module | Subcommand | Source repo | Distribution |
|---|---|---|---|
| **Find** | `capframe find` | [mcp-recon](https://github.com/euanmcrosson-dotcom/mcp-recon) | GitHub Releases (native binary) |
| **Bind** | `capframe bind` | [capnagent](https://github.com/euanmcrosson-dotcom/capnagent) | GitHub Releases + PyPI |
| **Guard** | `capframe guard` | [mcp-guard](https://github.com/euanmcrosson-dotcom/mcp-guard) | GitHub Releases + PyPI (`mcp-guardrails`) |
| **Report** | `capframe report` | (this repo) | shipped with capframe |

Each module is independently usable. Capframe gives them a shared CLI, a shared findings format ([`findings.v1`](schemas/findings.v1.json)), and a unified audit report.

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
                       OWASP / NIST / ATLAS
                          audit artifact
```

1. **Find** scans MCP servers and emits a `findings.v1.json` document.
2. **Bind** issues ed25519 holder-of-key capability tokens scoped to what each agent actually needs.
3. **Guard** evaluates every tool call against the token + a policy synthesized from Find's output — deterministic, single-digit microsecond decisions.
4. **Report** rolls findings (and, on the roadmap, token grants + Guard logs) into an HTML / PDF audit document.

## Compliance mapping

Each finding carries identifiers from:

- **OWASP LLM Top 10** — `LLM01` … `LLM10`
- **NIST AI RMF** — `GOVERN-*` / `MAP-*` / `MEASURE-*` / `MANAGE-*`
- **MITRE ATLAS** — `T####` and `T####.###`

The JSON Schema validates these patterns at the wire level; the example payload in `schemas/findings.example.json` is exercised in CI.

## Architecture

```
capframe/
├── crates/
│   ├── capframe-cli/        # dispatcher binary, install, doctor, report
│   └── capframe-findings/   # findings.v1 shared schema (Rust types + tests)
├── schemas/
│   └── findings.v1.json     # canonical JSON Schema (Draft 2020-12)
└── .github/workflows/       # CI + tagged-release builds for 6 targets
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
