# Changelog

All notable changes to the Capframe dispatcher CLI + findings schema land here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org).

The three underlying modules (`mcp-recon`, `capnagent`, `mcp-guard`) keep their
own changelogs in their own repos.

---

## [v0.2.1] — 2026-05-19

### Fixed

- **`capframe guard` actually works now.** v0.2.0 sent `--policy <p>
  --addr <a>` to `mcp-guard`, but `mcp-guard`'s argparse CLI takes one of
  three positional subcommands (`synthesize` / `evaluate` / `backtest`).
  Any user who tried `capframe guard ...` end-to-end hit a dead dispatch.

### Changed

- `capframe guard` now mirrors `mcp-guard` 1:1:
  - `capframe guard synthesize <detail> [--technique-id X] [--kind K]`
  - `capframe guard evaluate <policy> <tool> <args> [--user-context J]`
  - `capframe guard backtest <policy>`
- README + landing-page `Demo` section updated to match.
- Pairs with **mcp-guard v0.5.6**, which adds the `--version` flag
  Capframe's semver gate needs (hardcoded so it works in PyInstaller bundles).

### Tests

- Three new integration tests (Windows + Unix mock dispatch) confirm each
  guard subcommand forwards the right argv. Total test count now **22**
  in capframe + **21** in mcp-recon + smaller suites in the other modules.

---

## [v0.2.0] — 2026-05-19

### Added

- **`capframe install [find|bind|guard]`** — downloads each module from
  its GitHub Releases, verifies the `.sha256` sidecar, extracts into
  `~/.capframe/bin/`, and records the pinned version + hash in
  `~/.capframe/state.json`. State.json doubles as a supply-chain receipt.
- **Semver gating on dispatch** — every `capframe <module> ...`
  invocation first runs `<bin> --version` and matches against
  `Module::version_req`. Mismatches fail fast with a `capframe install
  <module>` hint instead of dispatching and getting a wrong-arg error
  three layers deep.
- **`--limit key=value`** on `capframe bind` — generic, repeatable
  constraint passthrough. Replaces the Shopify-specific
  `--max-refund` flag.
- **Real templated HTML report** via `maud` (severity cards, per-finding
  cards, mappings table, print CSS), plus a `--format pdf` path that
  auto-detects `weasyprint` / `chromium` on `PATH`.
- **JSON Schema conformance test suite** for `findings.v1` (5 tests:
  example validates, Rust roundtrip validates, synthetic minimal
  validates, unknown severity rejected, malformed OWASP ID rejected).
- **Cross-platform integration tests** for the dispatcher — Unix uses
  `#!/bin/sh` mocks, Windows uses `.bat` mocks (via PATHEXT lookup).

### Fixed

- `install.sh` couldn't find the binary inside the release archive's
  `capframe-<ver>-<target>/` subdirectory. Now uses
  `tar --strip-components=1`. (Surfaced by the first Docker smoke
  test; commit `9d7a3c5`.)
- `install.sh` no longer prints a dead `capframe.ai/discord` URL —
  no such redirect exists.

### Changed

- Workspace deps: `dirs`, `maud`, `semver`, `sha2`, `ureq` (+
  `jsonschema`, `assert_cmd`, `predicates`, `tempfile` in dev).
- README rewritten — accurate about the three modules living in
  separate repos, the version-pinning policy, the `capframe install`
  flow, and the PDF tool requirement.

---

## [v0.1.0] — 2026-05-18

### Added

- Initial public release. Dispatcher CLI that resolves the
  Find / Bind / Guard modules via `which::which` on `PATH` and shells
  out to each. `capframe-findings` crate carrying the `findings.v1`
  Rust types matching a public JSON Schema (Draft 2020-12). Static
  marketing site at `capframe.ai`. Cross-compiled to 6 targets
  via the tag-driven release workflow.
- `install.sh` + `install.ps1` with `.sha256` verification.

---

[v0.2.1]: https://github.com/capframe/capframe/releases/tag/v0.2.1
[v0.2.0]: https://github.com/capframe/capframe/releases/tag/v0.2.0
[v0.1.0]: https://github.com/capframe/capframe/releases/tag/v0.1.0
