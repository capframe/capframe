# Contributing to Capframe

Thanks for showing up — security-tool work compounds fastest when
people poke at it from the outside. This file is the short version of
how to get a change in.

## Local setup

```bash
# Clone + cd
git clone https://github.com/capframe/capframe
cd capframe

# Build + test the workspace
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Rust 1.78+ is required (see `Cargo.toml`'s `rust-version`).

For end-to-end testing against the three module binaries (`mcp-recon`,
`capnagent`, `mcp-guard`), install them via:

```bash
cargo run -- install
```

That fetches the latest sha256-verified release of each module into
`~/.capframe/bin/`. Then verify with `cargo run -- doctor`.

The Docker smoke-test image in `../capframe-smoke/Dockerfile` (in the
project's parent directory, not committed in this repo) reproduces a
full clean-machine install flow if you want to validate a change
doesn't break the public install pipeline.

## Test discipline

This project follows **test-driven development**. New behaviour
arrives with a failing test first; the implementation makes it pass.

- Unit tests live alongside the code (`mod tests` blocks).
- Integration tests for the CLI live in
  `crates/capframe-cli/tests/cli.rs` (uses `assert_cmd` +
  cross-platform mock binaries on `PATH`).
- JSON-Schema conformance tests for `findings.v1` live in
  `crates/capframe-findings/tests/schema.rs`.

CI runs all of the above on Linux, macOS, and Windows for every PR
and push to `main`. The `Release` workflow fires on tags matching
`v*` and ships cross-compiled binaries to GitHub Releases.

## Commit style

```
<type>: <short imperative subject>

<longer body explaining *why*, with line wraps around 72 chars.
Hyperlinks to the issue / PR are welcome. The body should answer:
what observable behaviour changed, and why is the new behaviour
better.>

Co-Authored-By: <name> <email>
```

Recent examples worth mirroring:

- `v0.2.1: rewrite capframe guard to match mcp-guard's actual CLI`
- `install: flatten release-archive subdirectory on extract`
- `v0.2.0: install subcommand, version pinning, --limit, real PDF report`

Subject lines are lower-case where the project's history is
lower-case (most recent commits). Avoid `feat:` / `fix:` /
`chore:` prefixes — they don't add value here.

## Branching + PRs

- `main` is the integration branch. Direct push to `main` is
  reserved for maintainers + release-tag commits.
- For changes, open a PR from a feature branch in your fork or a
  topic branch in this repo. PRs should target `main`.
- One logical change per PR. If you're tempted to bundle two
  unrelated changes, split them.

A useful PR description has:

1. **What** changed (one paragraph or a bulleted list).
2. **Why** the change is correct (link to the failing test the
   change makes pass, or the failure mode it prevents).
3. **How** you verified locally
   (`cargo test --workspace`, smoke-test output, etc.).

## Good first issues

If you're looking for somewhere to start, candidates:

- New classifier rules in `mcp-recon-core/src/classifier.rs` —
  see the existing six (R1–R6) for the pattern. Each new rule is
  one function + three tests + an entry in `classify()`.
- Additional `Tool::side_effects` taxonomy entries — the current
  set (read / write / network / filesystem / execute / money /
  irreversible) is intentionally small; we're happy to add
  more if you can justify a missing semantic.
- Additional input formats for `capframe find` — Claude Desktop's
  `claude_desktop_config.json` is the obvious next conversion
  target.

Look in the issue tracker for the `good first issue` label.

## Module repos

Capframe's umbrella is in this repo; the three modules live in
their own repos and ship their own binaries:

- [mcp-recon](https://github.com/euanmcrosson-dotcom/mcp-recon)
  — Find module. Rule-based scanner.
- [capnagent](https://github.com/euanmcrosson-dotcom/capnagent)
  — Bind module. Capability-token engine.
- [mcp-guard](https://github.com/euanmcrosson-dotcom/mcp-guard)
  — Guard module. Deterministic policy evaluator.

Each module repo has its own `CONTRIBUTING.md` (or accepts PRs in
the same spirit). If your change touches the wire format between
modules (`findings.v1.json`), open a PR in this repo first — the
schema lives here and the modules consume it.

## License

By contributing you agree your work is licensed under the MIT
License that covers the rest of this repo (see `LICENSE`).

## Code of conduct

Be kind, be specific, assume good faith. Substantive disagreement is
welcome; personal attacks are not. The maintainers will moderate
when needed.

## Questions

- Security: `security@capframe.ai`
  (see [`SECURITY.md`](SECURITY.md))
- General: open an issue or email `hello@capframe.ai`
