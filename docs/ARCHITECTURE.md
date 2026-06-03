# Capframe — Architecture

Workspace `0.2.1` · ~2,800 LOC Rust · Cargo workspace (resolver 2, edition 2021, `rust-version = 1.78`).

Capframe is a **dispatcher CLI** plus a **shared wire-format crate** and a **leaderboard
aggregator**. The CLI (`capframe`) exposes six subcommands modelling a four-stage pipeline —
**Find → Bind → Guard → Report**. Find/Bind/Guard front three *external* module binaries
(`mcp-recon`, `capnagent`, `mcp-guard`) that live in their own repos and are resolved at runtime
from `PATH` / `~/.capframe/bin`; Report ships in-repo. The `capframe-findings` crate is the JSON
wire contract every module speaks; `capframe-leaderboard` rolls `findings.v2` files into the
public ranking.

> Maintained by hand. If you change dispatch, the wire schema, or the version bands, update this file.

## Architecture at a glance

```
                         ┌──────────────────────────────────────────┐
                         │            capframe-cli (binary)           │
                         │   main.rs → clap → Command enum dispatch   │
                         └───────────────┬────────────────────────────┘
      ┌───────────┬──────────────┬───────┴───────┬──────────────┬────────────┐
   install      doctor          find           bind/guard      report
  download +   resolve(),     in-process       build argv →   findings JSON →
  sha256 →     NO version     mcp-recon-core   modules::       maud HTML / PDF
  ~/.capframe  check          by DEFAULT;      dispatch()     subprocess
   /bin                       --external →                    (weasyprint/
                              subprocess                      chromium/chrome)
                                   │                │
                                   ▼                ▼
                  modules.rs :: resolve_compatible()  ← semver version GATE
                                   │                │
                ┌──────────────────┼────────────────┼──────────────────┐
                ▼                  ▼                                    ▼
          mcp-recon (Find)   capnagent (Bind)                   mcp-guard (Guard)
          >=0.0.1,<0.1.0     >=0.7.0,<0.8.0                     >=0.5.0,<0.6.0
          └──────── external repos, resolved from PATH / ~/.capframe/bin ────────┘

   Shared wire types →  capframe-findings   (findings.v1  ·  findings.v2)
   Public ranking    →  capframe-leaderboard ( *.findings.v2.json → leaderboard.json )
```

## Crates

| Crate | Role |
|---|---|
| `crates/capframe-cli` | Dispatcher binary: `install`, `doctor`, `find`, `bind`, `guard`, `report` |
| `crates/capframe-findings` | Shared `findings.v1` / `findings.v2` wire types + round-trip/schema tests |
| `crates/capframe-leaderboard` | Aggregates `*.findings.v2.json` → `leaderboard.json` |

## Subsystems

### 1. CLI dispatcher core — `capframe-cli/src/main.rs`, `commands/mod.rs`
`Cli` (clap `Parser`, `main.rs:17`) → `Command` enum (`main.rs:26-45`) routed in the `main` match
(`main.rs:51-58`). `init_tracing` (`main.rs:61-74`) sets log level from `-v` / `CAPFRAME_LOG`. Each
subcommand has a `run()` handler.

### 2. Module resolution & version policy — `capframe-cli/src/modules.rs` *(the critical gate)*
`Module` enum (`:6-11`) → `underlying_binary()` (`:15-21`), `version_req()` (`:33-39`). `resolve()`
(`:50-59`) does a `which::which()` PATH lookup with **no** version check; `resolve_compatible()`
(`:62-80`) adds the semver gate via `binary_version()` (`:82-89`) + `parse_version()` (`:92-99`).
`dispatch()` (`:101-112`) is the single entry to every external binary and propagates the child's
exit code. The version bands here are the cross-repo wire-compat enforcement — bump them in lockstep
with breaking CLI changes in the underlying modules.

### 3. Install command — `capframe-cli/src/commands/install.rs`
`install_one` (`:133-196`) resolves a release tag (`resolve_latest_tag`, `:232-245`, unauthenticated
GitHub API), downloads archive + `.sha256` sidecar, verifies (`parse_sha256_line` `:265-278`,
`sha256_file` `:280-296`), extracts via system `tar`, copies into `~/.capframe/bin`, records
`ModuleState`{version, sha256} to `state.json`. `host_triple` (`:204-217`) does OS/arch detection.

### 4. Passthrough commands — `commands/find.rs`, `bind.rs`, `guard.rs`, `doctor.rs`
`find` is **dual-path**: `run_inprocess` (`find.rs:81-101`) calls `mcp_recon_core::classify()` as a
linked library (**default**); `run_external` (`find.rs:67-79`) hits `dispatch()` only under
`--external`. `build_envelope` (`find.rs:103-146`) translates results into `findings.v1` with
OWASP/NIST/ATLAS mappings; `scanner.version` is stamped from `MCP_RECON_CORE_VERSION` (`find.rs:31`,
kept in lockstep with the `mcp-recon-core` tag in `Cargo.toml`). `bind` validates `--limit
key=value` via `parse_limit` (`bind.rs:27-43`). `guard` has a nested `Op` enum
(synthesize/evaluate/backtest). `doctor` calls `resolve()` (no version check).

### 5. Report command — `capframe-cli/src/commands/report.rs`
`run` (`:39`) reads findings JSON → `Format` (Html/Pdf/Json). `render_html` (`:113`) uses **maud**
with embedded CSS, severity cards, tool table, and `mapping_table` (`:263`) for compliance pills.
`render_pdf` (`:59`) writes a temp HTML and shells out to a PDF tool found by `detect_pdf_tool`
(`:95`, order: weasyprint → chromium → chrome) or `--pdf-tool`.

### 6. Findings schema crate (wire contract) — `capframe-findings/src/lib.rs` + `v2.rs`
`SCHEMA_VERSION="capframe.findings.v1"` (`lib.rs:14`). v1 root `Findings` (`lib.rs:16`) has
**optional** `scan_id`; v2 `FindingsV2` (`v2.rs:20`) **requires** `scan_id` and replaces `Target`
with `Server`{handle, kind, `ServerSource` ∈ {registry,http,sandbox,file}}.
`Finding`/`Tool`/`Severity`(5)/`Category`(13)/`SideEffect`(7)/`Mappings` are **byte-identical
v1↔v2**. `from_v1` (`v2.rs:72-99`) migrates, synthesizing a NIL-UUID `scan_id` placeholder if
absent. Tests (`tests/schema.rs`, `schema_v2.rs`) validate both against the JSON Schemas via the
`jsonschema` Draft 2020-12 validator.

### 7. Leaderboard crate — `capframe-leaderboard/src/lib.rs` + `main.rs`
`build` (`lib.rs:133-170`) reads a dir **non-recursively** for `*.findings.v2.json`, `parse_one`
(`:172`) enforces `schema_version=="capframe.findings.v2"`, `score_from_counts` (`:102-108`) =
`100 − (10·crit + 4·high + 2·med + 1·low)`, saturating, clamped `[0,100]` (**Info ignored**), sorts
by score desc then handle asc. Public `Weights` are embedded in the output JSON. Malformed files are
**skipped with a warn**, not fatal; an empty dir *is* an error. CLI:
`capframe-leaderboard build --findings DIR --out JSON [--pretty]`.

### 8. Schemas, CI/release, installers & manifests — `schemas/*.json`, `.github/workflows/*`, `install.sh|ps1`, `Cargo.toml`
Both schemas are Draft 2020-12 with `additionalProperties:false`; v1 validates `owasp_llm` against
`^LLM(0[1-9]|10)$`. `ci.yml` = fmt/clippy/test on ubuntu/macos/windows + a Python `jsonschema` step +
shellcheck. `release.yml` = tag-triggered cross-compile to 6 targets with per-target `.sha256`.
`leaderboard-daily.yml` = 07:00 UTC cron chaining registry → sandbox (Docker) → HTTP producers →
`capframe-leaderboard build` → cross-repo push to `capframe/website` via `LEADERBOARD_PUSH_TOKEN`.
Installers fail-closed on checksum mismatch.

## End-to-end data flow

**Scan → report (local):** `capframe find` → (default) in-process `mcp_recon_core::classify()` →
`build_envelope` emits `capframe.findings.v1` JSON → `capframe report --findings … --format
html|pdf` deserializes v1 → maud HTML, optionally piped through a PDF subprocess.

**Leaderboard (cron):** `mcp-recon producer {registry → sandbox → http}` each emit slug-named
`*.findings.v2.json` into one flat dir (sandbox **overwrites** the registry file for the same handle
— last-write-wins on filename) → `capframe-leaderboard build` scores/sorts → `leaderboard.json` →
pushed to `capframe/website` → Vercel ISR.

**The wire contract is the seam:** v1 is the Find→Bind→Guard→Report format; v2 (richer `Server`
identity, required `scan_id`) is the leaderboard format. `from_v1()` bridges them.

## Invariants

- **Single choke point:** every external-binary call goes through `dispatch()` →
  `resolve_compatible()`; the semver bands in `modules.rs:33-39` enforce cross-repo wire-compat.
- **Fail-closed paths:** sha256 verify in `install.rs` and both installers; PDF tool absence errors
  rather than silently degrading; leaderboard `parse_one` rejects a wrong `schema_version`; schemas
  are strict (`additionalProperties:false`).
- **Truthful scanner metadata:** in-process find stamps `scanner.version = MCP_RECON_CORE_VERSION`.

## Footguns

1. **`find` is in-process by default** — `mcp-recon-core` is linked in (pinned to git tag
   `v0.0.13`); the version gate and any on-PATH `mcp-recon` are bypassed unless you pass
   `--external`.
2. **`doctor` doesn't version-check** — it calls `resolve()`, not `resolve_compatible()`, so it
   reports OK on an incompatible on-PATH binary; the mismatch only surfaces at dispatch.
3. **Install-time vs dispatch-time skew** — `install` verifies sha256 but never checks the version
   band; an incompatible binary installs fine and only fails when used. `--version` accepts any tag
   string unvalidated.
4. **`State::load()` fails *open*** — a corrupted `state.json` silently `unwrap_or_default()`s to
   empty, losing version/sha256 history with no warning. The one spot that bucks the fail-closed
   ethos.
5. **mcp-recon version skew in the cron** — the CLI pins `mcp-recon-core` at tag `v0.0.13`, but
   `leaderboard-daily.yml` builds `mcp-recon` from **master**; the in-process classifier and the
   leaderboard producer can diverge. `MCP_RECON_CORE_VERSION` is a hand-maintained constant that
   must track the Cargo tag.

## Where do I start if I want to…

| Goal | Open |
|---|---|
| Add/modify a CLI flag or subcommand | `capframe-cli/src/main.rs` (`Command` enum) + the relevant `commands/*.rs` handler |
| Change the findings wire schema | `capframe-findings/src/lib.rs` (v1) / `v2.rs` (v2) **and** `schemas/findings.v1.json` / `v2.json` + round-trip tests |
| Bump a module version band | `capframe-cli/src/modules.rs` `version_req()` |
| Touch the leaderboard scoring/sort | `capframe-leaderboard/src/lib.rs` (`score_from_counts`, `build`, `Weights`) |
| Touch the daily cron / push token | `.github/workflows/leaderboard-daily.yml` (smoke-test via `workflow_dispatch` first) |
| Add/adjust a classifier rule (R1–R7) | **not here** — `crates/mcp-recon-core/src/classifier.rs` in the `mcp-recon` repo |
| Change install/verification behavior | `capframe-cli/src/commands/install.rs` + `install.sh` / `install.ps1` |
