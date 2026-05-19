# Security Policy

If you've found a vulnerability in Capframe — the dispatcher CLI, the
findings schema, or any of the three module repos that the umbrella
installer brings in (`mcp-recon`, `capnagent`, `mcp-guard`) — please
read this document before opening a public issue.

## Reporting

**Email:** `security@capframe.ai`

We aim to acknowledge every report within **72 hours** and to provide
an initial assessment (accepted / out-of-scope / needs-more-info)
within **5 business days**.

If you don't get an acknowledgment in 72 hours, escalate by emailing
`hello@capframe.ai` with the original report attached and `[SECURITY
ESCALATION]` in the subject line.

PGP is not currently set up. If you need an encrypted channel before
disclosure, mention it in your first email and we'll establish one.

## What's in scope

In scope:

- The `capframe` dispatcher binary in this repo
  (`crates/capframe-cli`).
- The `capframe-findings` crate and the `findings.v1` JSON Schema.
- The three module binaries the umbrella installer fetches and
  verifies:
  [`mcp-recon`](https://github.com/euanmcrosson-dotcom/mcp-recon),
  [`capnagent`](https://github.com/euanmcrosson-dotcom/capnagent),
  [`mcp-guard`](https://github.com/euanmcrosson-dotcom/mcp-guard).
- The install scripts (`install.sh`, `install.ps1`) served from
  `capframe.ai/install`.
- The marketing site at `capframe.ai`.

Out of scope:

- The "Pro" tier described on the landing page. It is a waitlist
  signup, not a deployed product.
- Third-party tools `weasyprint` and Chromium that `capframe report
  --format pdf` shells out to.
- Issues in user-supplied policy YAML or findings JSON unless they
  cause memory-safety or denial-of-service problems in capframe
  itself.

## What we treat as security-relevant

- Anything that causes capframe or a module binary to execute
  attacker-controlled code (RCE / arbitrary writes).
- Supply-chain attacks against the install pipeline (e.g., sha256
  validation bypass, redirect manipulation, archive-extraction path
  traversal).
- Auth bypass on the capability-token verifier (`capnagent`) —
  forged tokens, signature-collision tricks, attenuation-rule
  bypasses.
- Indirect-injection paths through findings or report content that
  reach a viewer's browser as executable script.
- TLS/HSTS/CSP misconfiguration on `capframe.ai` that exposes users
  to MITM.

Severity follows the rough CVSS bucketing in the
[OWASP LLM Top 10 — Risk Rating](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
mapped to the `findings.v1` `Severity` enum.

## What we do NOT treat as security-relevant

- Bugs in the heuristic classifier (false-positive findings, missed
  side-effect detections). These are correctness issues; please open
  a regular GitHub issue.
- Cosmetic problems on the website.
- Out-of-date dependencies that we already have a tracking issue
  for. Check the open issues before reporting.

## Disclosure timeline

We follow a **90-day** coordinated disclosure window:

| Day | Step |
|---:|---|
| 0  | Report received, acknowledgment sent within 72 hours. |
| 0–7 | Triage, severity assessment, reproduction. |
| 7–60 | Fix developed, internally reviewed, released as a patch tag (e.g. `v0.2.x`). |
| 60–90 | Coordinated public disclosure window. |
| 90 | Vulnerability is published in the GitHub Security Advisory feed regardless of fix status, unless the reporter agrees to extend. |

If you're sitting on an active exploit and 90 days is too long, say
so explicitly; we'll move faster.

## Recognition

By default we credit reporters in the relevant GitHub Security
Advisory under "Credit." Prefer to stay anonymous? Let us know in
the report.

## Past advisories

None yet — Capframe is pre-1.0. This file is the standing offer.
