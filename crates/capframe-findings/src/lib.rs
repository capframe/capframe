//! Capframe findings v1 — wire format shared by all modules.
//! See `schemas/findings.v1.json` for the canonical schema.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;

pub const SCHEMA_VERSION: &str = "capframe.findings.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Findings {
    pub schema_version: String,
    #[serde(with = "time::serde::rfc3339")]
    pub scanned_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<String>,
    pub scanner: Scanner,
    pub target: Target,
    #[serde(default)]
    pub tools: Vec<Tool>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scanner {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    McpServer,
    OpenaiFunction,
    AnthropicTool,
    LanggraphNode,
    Custom,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Stdio,
    Http,
    Sse,
    Websocket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<SideEffect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limited: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    Read,
    Write,
    Network,
    Filesystem,
    Execute,
    Money,
    Irreversible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Mappings::is_empty")]
    pub mappings: Mappings,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub first_seen: Option<OffsetDateTime>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub last_seen: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    IndirectInjection,
    ExcessiveAgency,
    UnconstrainedInput,
    MissingAuthz,
    InsecureOutputHandling,
    SecretExposure,
    ToolNamingConflict,
    Deserialization,
    SsrfSurface,
    FilesystemEgress,
    NetworkEgress,
    UntrustedDependency,
    Other,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Mappings {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp_llm: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nist_rmf: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_atlas: Vec<String>,
}

impl Mappings {
    pub fn is_empty(&self) -> bool {
        self.owasp_llm.is_empty() && self.nist_rmf.is_empty() && self.mitre_atlas.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total: u32,
    pub by_severity: SeverityCounts,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub by_category: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "Mappings::is_empty")]
    pub mappings: Mappings,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SeverityCounts {
    #[serde(default)]
    pub info: u32,
    #[serde(default)]
    pub low: u32,
    #[serde(default)]
    pub medium: u32,
    #[serde(default)]
    pub high: u32,
    #[serde(default)]
    pub critical: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_example_payload() {
        let example = include_str!("../../../schemas/findings.example.json");
        let parsed: Findings = serde_json::from_str(example).expect("parse example");
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        let back = serde_json::to_string(&parsed).expect("reserialize");
        let reparsed: Findings = serde_json::from_str(&back).expect("re-parse");
        assert_eq!(reparsed.summary.total, parsed.summary.total);
    }
}
