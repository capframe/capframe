//! Capframe findings v2 — ecosystem-aware wire format.
//!
//! Replaces v1's thin `target` with a rich `server` identity (handle,
//! repo_url, source) so findings can be aggregated across thousands of
//! MCP servers for the public leaderboard at capframe.ai/leaderboard.
//!
//! See `schemas/findings.v2.json` for the canonical schema. Items inside
//! `findings[]` reuse v1's [`Finding`](crate::Finding) type byte-for-byte —
//! the rule engine emits these without modification.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;

use crate::{Finding, Mappings, Scanner, SeverityCounts, TargetKind, Tool, Transport};

pub const SCHEMA_VERSION_V2: &str = "capframe.findings.v2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsV2 {
    pub schema_version: String,
    pub scan_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub scanned_at: OffsetDateTime,
    pub scanner: Scanner,
    pub server: Server,
    #[serde(default)]
    pub tools: Vec<Tool>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    pub summary: SummaryV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub handle: String,
    pub kind: TargetKind,
    pub source: ServerSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerSource {
    Registry,
    Http,
    Sandbox,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryV2 {
    pub total: u32,
    pub by_severity: SeverityCounts,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub by_category: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "Mappings::is_empty")]
    pub mappings: Mappings,
}

/// Migrate a v1 [`Findings`](crate::Findings) document to v2 by promoting
/// `target` to `server` and synthesizing a handle from available identity.
///
/// `source` must be supplied by the caller — v1 had no notion of how an
/// inventory was produced. `scan_id` is preserved if v1 had one; otherwise
/// a deterministic placeholder is generated.
pub fn from_v1(v1: crate::Findings, source: ServerSource, handle: String) -> FindingsV2 {
    let server = Server {
        handle,
        kind: v1.target.kind,
        source,
        repo_url: v1.target.url.clone(),
        name: v1.target.name.clone(),
        transport: v1.target.transport,
    };
    let summary = SummaryV2 {
        total: v1.summary.total,
        by_severity: v1.summary.by_severity.clone(),
        by_category: v1.summary.by_category.clone(),
        mappings: v1.summary.mappings.clone(),
    };
    FindingsV2 {
        schema_version: SCHEMA_VERSION_V2.to_string(),
        scan_id: v1
            .scan_id
            .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string()),
        scanned_at: v1.scanned_at,
        scanner: v1.scanner,
        server,
        tools: v1.tools,
        findings: v1.findings,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Severity, Target, TargetKind, SCHEMA_VERSION};

    #[test]
    fn round_trips_example_payload() {
        let example = include_str!("../../../schemas/findings.v2.example.json");
        let parsed: FindingsV2 = serde_json::from_str(example).expect("parse example");
        assert_eq!(parsed.schema_version, SCHEMA_VERSION_V2);
        assert_eq!(
            parsed.server.handle,
            "npm:@modelcontextprotocol/server-everything@0.1.0"
        );
        assert_eq!(parsed.server.source, ServerSource::Registry);
        let back = serde_json::to_string(&parsed).expect("reserialize");
        let reparsed: FindingsV2 = serde_json::from_str(&back).expect("re-parse");
        assert_eq!(reparsed.summary.total, parsed.summary.total);
        assert_eq!(reparsed.scan_id, parsed.scan_id);
    }

    #[test]
    fn migrate_v1_preserves_findings_and_summary() {
        let v1_str = include_str!("../../../schemas/findings.example.json");
        let v1: crate::Findings = serde_json::from_str(v1_str).expect("parse v1");
        assert_eq!(v1.schema_version, SCHEMA_VERSION);

        let v2 = from_v1(
            v1.clone(),
            ServerSource::File,
            "file:shopify-mcp@local".to_string(),
        );

        assert_eq!(v2.schema_version, SCHEMA_VERSION_V2);
        assert_eq!(v2.server.handle, "file:shopify-mcp@local");
        assert_eq!(v2.server.source, ServerSource::File);
        assert_eq!(v2.server.name.as_deref(), Some("shopify-mcp"));
        assert_eq!(v2.findings.len(), v1.findings.len());
        assert_eq!(v2.summary.total, v1.summary.total);
        // The Finding items themselves are unchanged — same severity, same id.
        assert_eq!(v2.findings[0].id, v1.findings[0].id);
        assert!(matches!(v2.findings[0].severity, Severity::High));
    }

    #[test]
    fn synthesizes_scan_id_when_v1_has_none() {
        let v1 = crate::Findings {
            schema_version: SCHEMA_VERSION.to_string(),
            scanned_at: OffsetDateTime::now_utc(),
            scan_id: None,
            scanner: Scanner {
                name: "test".to_string(),
                version: "0.0.0".to_string(),
            },
            target: Target {
                kind: TargetKind::McpServer,
                name: None,
                url: None,
                path: None,
                transport: None,
            },
            tools: vec![],
            findings: vec![],
            summary: crate::Summary {
                total: 0,
                by_severity: SeverityCounts::default(),
                by_category: BTreeMap::new(),
                mappings: Mappings::default(),
            },
        };

        let v2 = from_v1(v1, ServerSource::Registry, "npm:test@0.0.0".to_string());

        assert_eq!(v2.scan_id, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn server_source_serializes_as_snake_case() {
        let s = serde_json::to_string(&ServerSource::Sandbox).unwrap();
        assert_eq!(s, "\"sandbox\"");
        let parsed: ServerSource = serde_json::from_str("\"http\"").unwrap();
        assert_eq!(parsed, ServerSource::Http);
    }
}
