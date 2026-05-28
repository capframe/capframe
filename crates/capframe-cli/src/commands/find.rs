//! `capframe find` — discover the tool surface of an MCP server.
//!
//! Defaults to **in-process** dispatch: pulls in `mcp-recon-core` as a
//! library, calls the deterministic classifier directly, and emits the
//! `capframe.findings.v1` envelope. Skipping the subprocess hop trims
//! ~30–100ms of startup (PATH resolution + binary load + clap parse) and
//! removes a flaky integration point — the on-PATH binary no longer needs
//! to exist, match a version range, or speak a stable CLI surface.
//!
//! `--external` falls back to the legacy subprocess path against whichever
//! `mcp-recon` is on PATH. Useful when:
//! - The on-PATH binary is a newer release than the version capframe
//!   compiled against and the user wants the newer rules.
//! - Cross-checking that the in-process output matches the subprocess
//!   output bit-for-bit.

use anyhow::{Context, Result};
use capframe_findings as cff;
use clap::Args as ClapArgs;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

use crate::modules::{dispatch, Module};

/// Version of `mcp-recon-core` we compile against. Keep in lockstep with
/// the `path`/`git`/`version` value in this crate's Cargo.toml. Used as
/// `scanner.version` in the emitted envelope so consumers can see exactly
/// which classifier did the work.
const MCP_RECON_CORE_VERSION: &str = "0.0.12";

#[derive(ClapArgs, Debug)]
#[command(about = "Discover the tool surface of an MCP server")]
pub struct Args {
    /// Path to an mcp-recon.inventory.v1 JSON file to classify.
    pub target: PathBuf,

    /// Write findings to this file (default: ./capframe.findings.json)
    #[arg(short, long, default_value = "capframe.findings.json")]
    pub out: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub format: Format,

    /// Skip the in-process classifier and shell out to the on-PATH
    /// `mcp-recon` binary instead. The on-PATH version must satisfy
    /// `Module::Find::version_req`; mismatches are rejected.
    #[arg(long)]
    pub external: bool,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Pretty,
}

pub fn run(args: Args) -> Result<()> {
    if args.external {
        return run_external(&args);
    }
    run_inprocess(&args)
}

fn run_external(args: &Args) -> Result<()> {
    tracing::info!(target = %args.target.display(), "capframe find (external / subprocess)");
    let mut raw = vec![
        "--target".to_string(),
        args.target.display().to_string(),
        "--out".to_string(),
        args.out.display().to_string(),
    ];
    if args.format == Format::Pretty {
        raw.push("--pretty".into());
    }
    dispatch(Module::Find, &raw)
}

fn run_inprocess(args: &Args) -> Result<()> {
    tracing::info!(target = %args.target.display(), "capframe find (in-process)");
    let body = fs::read_to_string(&args.target)
        .with_context(|| format!("read {}", args.target.display()))?;
    let inv: mcp_recon_core::McpInventory = serde_json::from_str(&body)
        .with_context(|| {
            format!(
                "parse {} as mcp-recon.inventory.v1",
                args.target.display()
            )
        })?;
    let core_findings = mcp_recon_core::classify(&inv);
    let envelope = build_envelope(&inv, &core_findings, &args.target);
    let json = if args.format == Format::Pretty {
        serde_json::to_string_pretty(&envelope)?
    } else {
        serde_json::to_string(&envelope)?
    };
    fs::write(&args.out, json).with_context(|| format!("write {}", args.out.display()))?;
    tracing::debug!(
        path = %args.out.display(),
        findings = envelope.findings.len(),
        "wrote capframe.findings.v1"
    );
    Ok(())
}

fn build_envelope(
    inv: &mcp_recon_core::McpInventory,
    core_findings: &[mcp_recon_core::Finding],
    target_path: &Path,
) -> cff::Findings {
    let findings: Vec<cff::Finding> = core_findings.iter().map(translate_finding).collect();
    let tools: Vec<cff::Tool> = inv
        .servers
        .iter()
        .flat_map(|s| &s.tools)
        .map(translate_tool)
        .collect();
    let by_severity = severity_counts(&findings);
    let total = by_severity.info
        + by_severity.low
        + by_severity.medium
        + by_severity.high
        + by_severity.critical;

    cff::Findings {
        schema_version: cff::SCHEMA_VERSION.to_string(),
        scanned_at: OffsetDateTime::now_utc(),
        scan_id: None,
        scanner: cff::Scanner {
            name: "mcp-recon".to_string(),
            version: MCP_RECON_CORE_VERSION.to_string(),
        },
        target: cff::Target {
            kind: cff::TargetKind::McpServer,
            name: None,
            url: None,
            path: Some(target_path.display().to_string()),
            transport: None,
        },
        tools,
        findings,
        summary: cff::Summary {
            total,
            by_severity,
            by_category: BTreeMap::new(),
            mappings: cff::Mappings::default(),
        },
    }
}

fn translate_finding(f: &mcp_recon_core::Finding) -> cff::Finding {
    cff::Finding {
        id: f.id.clone(),
        severity: translate_severity(f.severity),
        category: translate_category(f.category),
        title: f.title.clone(),
        description: f.description.clone(),
        tool: f.tool.clone(),
        evidence: None,
        remediation: f.remediation.clone(),
        mappings: cff::Mappings {
            owasp_llm: f.mappings.owasp_llm.clone(),
            nist_rmf: f.mappings.nist_rmf.clone(),
            mitre_atlas: f.mappings.mitre_atlas.clone(),
        },
        first_seen: None,
        last_seen: None,
    }
}

fn translate_severity(s: mcp_recon_core::Severity) -> cff::Severity {
    use mcp_recon_core::Severity as M;
    match s {
        M::Info => cff::Severity::Info,
        M::Low => cff::Severity::Low,
        M::Medium => cff::Severity::Medium,
        M::High => cff::Severity::High,
        M::Critical => cff::Severity::Critical,
    }
}

fn translate_category(c: mcp_recon_core::Category) -> cff::Category {
    use mcp_recon_core::Category as M;
    // mcp-recon-core and capframe-findings carry the same 13 categories
    // today. Exhaustive match — the compiler will surface any drift between
    // the two type families the moment one side adds a new variant.
    match c {
        M::IndirectInjection => cff::Category::IndirectInjection,
        M::ExcessiveAgency => cff::Category::ExcessiveAgency,
        M::UnconstrainedInput => cff::Category::UnconstrainedInput,
        M::MissingAuthz => cff::Category::MissingAuthz,
        M::InsecureOutputHandling => cff::Category::InsecureOutputHandling,
        M::SecretExposure => cff::Category::SecretExposure,
        M::ToolNamingConflict => cff::Category::ToolNamingConflict,
        M::Deserialization => cff::Category::Deserialization,
        M::SsrfSurface => cff::Category::SsrfSurface,
        M::FilesystemEgress => cff::Category::FilesystemEgress,
        M::NetworkEgress => cff::Category::NetworkEgress,
        M::UntrustedDependency => cff::Category::UntrustedDependency,
        M::Other => cff::Category::Other,
    }
}

fn translate_tool(t: &mcp_recon_core::Tool) -> cff::Tool {
    cff::Tool {
        name: t.name.clone(),
        description: t.description.clone(),
        parameters: t.parameters.clone(),
        side_effects: t
            .side_effects
            .iter()
            .map(|s| translate_side_effect(*s))
            .collect(),
        auth_required: t.auth_required,
        rate_limited: t.rate_limited,
    }
}

fn translate_side_effect(s: mcp_recon_core::SideEffect) -> cff::SideEffect {
    use mcp_recon_core::SideEffect as M;
    match s {
        M::Read => cff::SideEffect::Read,
        M::Write => cff::SideEffect::Write,
        M::Network => cff::SideEffect::Network,
        M::Filesystem => cff::SideEffect::Filesystem,
        M::Execute => cff::SideEffect::Execute,
        M::Money => cff::SideEffect::Money,
        M::Irreversible => cff::SideEffect::Irreversible,
    }
}

fn severity_counts(findings: &[cff::Finding]) -> cff::SeverityCounts {
    let mut c = cff::SeverityCounts::default();
    for f in findings {
        match f.severity {
            cff::Severity::Info => c.info += 1,
            cff::Severity::Low => c.low += 1,
            cff::Severity::Medium => c.medium += 1,
            cff::Severity::High => c.high += 1,
            cff::Severity::Critical => c.critical += 1,
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv_with_one_tool(name: &str, desc: &str, params: serde_json::Value) -> mcp_recon_core::McpInventory {
        mcp_recon_core::McpInventory {
            schema: mcp_recon_core::INVENTORY_SCHEMA.into(),
            servers: vec![mcp_recon_core::McpServer {
                name: "t".into(),
                transport: Some(mcp_recon_core::Transport::Stdio),
                tools: vec![mcp_recon_core::Tool {
                    name: name.into(),
                    description: Some(desc.into()),
                    parameters: if params.is_null() { None } else { Some(params) },
                    side_effects: vec![],
                    auth_required: Some(true),
                    rate_limited: None,
                }],
            }],
        }
    }

    #[test]
    fn build_envelope_emits_schema_tag_and_scanner_metadata() {
        let inv = inv_with_one_tool("run_shell", "Run a shell command", serde_json::json!(null));
        let findings = mcp_recon_core::classify(&inv);
        let env = build_envelope(&inv, &findings, Path::new("test.json"));
        assert_eq!(env.schema_version, cff::SCHEMA_VERSION);
        assert_eq!(env.scanner.name, "mcp-recon");
        assert_eq!(env.scanner.version, MCP_RECON_CORE_VERSION);
        // R7 should have fired on "run_shell" + "Run a shell command".
        assert!(env.findings.iter().any(|f| f.id.contains("r7")));
        assert_eq!(env.summary.by_severity.critical, 1);
        assert_eq!(env.summary.total, 1);
    }

    #[test]
    fn translator_preserves_severity_category_and_mappings() {
        // Construct a synthetic core finding (all the fields we care about).
        let core = mcp_recon_core::Finding {
            id: "f-r4-test".into(),
            severity: mcp_recon_core::Severity::High,
            category: mcp_recon_core::Category::ExcessiveAgency,
            title: "T".into(),
            description: Some("D".into()),
            tool: Some("t".into()),
            remediation: Some("R".into()),
            mappings: mcp_recon_core::Mappings {
                owasp_llm: vec!["LLM08".into()],
                nist_rmf: vec!["MANAGE-2.2".into()],
                mitre_atlas: vec!["T0051".into()],
            },
        };
        let out = translate_finding(&core);
        assert_eq!(out.id, "f-r4-test");
        assert!(matches!(out.severity, cff::Severity::High));
        assert!(matches!(out.category, cff::Category::ExcessiveAgency));
        assert_eq!(out.mappings.owasp_llm, vec!["LLM08"]);
        assert_eq!(out.mappings.nist_rmf, vec!["MANAGE-2.2"]);
        assert_eq!(out.mappings.mitre_atlas, vec!["T0051"]);
        assert!(out.evidence.is_none());
        assert!(out.first_seen.is_none());
        assert!(out.last_seen.is_none());
    }
}
