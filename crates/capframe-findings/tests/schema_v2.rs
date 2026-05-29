use capframe_findings::v2::{FindingsV2, Server, ServerSource, SummaryV2, SCHEMA_VERSION_V2};
use capframe_findings::{Mappings, Scanner, SeverityCounts, TargetKind};
use jsonschema::JSONSchema;
use time::OffsetDateTime;

const SCHEMA: &str = include_str!("../../../schemas/findings.v2.json");
const EXAMPLE: &str = include_str!("../../../schemas/findings.v2.example.json");

fn schema() -> JSONSchema {
    let v: serde_json::Value = serde_json::from_str(SCHEMA).expect("v2 schema is valid json");
    JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&v)
        .expect("v2 schema compiles")
}

fn assert_valid(s: &JSONSchema, doc: &serde_json::Value, context: &str) {
    if let Err(errors) = s.validate(doc) {
        let msgs: Vec<String> = errors
            .map(|e| format!("  - {} @ {}", e, e.instance_path))
            .collect();
        panic!("{context} failed v2 validation:\n{}", msgs.join("\n"));
    }
}

#[test]
fn v2_example_payload_validates() {
    let s = schema();
    let example: serde_json::Value =
        serde_json::from_str(EXAMPLE).expect("v2 example is valid json");
    assert_valid(&s, &example, "schemas/findings.v2.example.json");
}

#[test]
fn v2_rust_serialization_validates() {
    let parsed: FindingsV2 = serde_json::from_str(EXAMPLE).expect("parse v2 example");
    let reserialized = serde_json::to_value(&parsed).expect("reserialize v2");
    assert_valid(&schema(), &reserialized, "Rust-roundtripped v2 example");
}

#[test]
fn v2_minimal_synthetic_validates() {
    let minimal = FindingsV2 {
        schema_version: SCHEMA_VERSION_V2.into(),
        scan_id: "00000000-0000-0000-0000-000000000001".into(),
        scanned_at: OffsetDateTime::now_utc(),
        scanner: Scanner {
            name: "capframe-test".into(),
            version: "0.1.0".into(),
        },
        server: Server {
            handle: "npm:test@0.0.0".into(),
            kind: TargetKind::McpServer,
            source: ServerSource::Registry,
            repo_url: None,
            name: None,
            transport: None,
        },
        tools: vec![],
        findings: vec![],
        summary: SummaryV2 {
            total: 0,
            by_severity: SeverityCounts::default(),
            by_category: Default::default(),
            mappings: Mappings::default(),
        },
    };
    let v = serde_json::to_value(&minimal).expect("serialize minimal v2");
    assert_valid(&schema(), &v, "synthetic minimal v2");
}

#[test]
fn v2_schema_rejects_unknown_source() {
    let mut example: serde_json::Value = serde_json::from_str(EXAMPLE).expect("parse v2 example");
    example["server"]["source"] = serde_json::Value::String("smoke-signal".into());
    let s = schema();
    assert!(
        s.validate(&example).is_err(),
        "schema must reject unknown server.source values"
    );
}

#[test]
fn v2_schema_requires_handle() {
    let mut example: serde_json::Value = serde_json::from_str(EXAMPLE).expect("parse v2 example");
    let server = example["server"].as_object_mut().unwrap();
    server.remove("handle");
    let s = schema();
    assert!(
        s.validate(&example).is_err(),
        "schema must reject server without handle"
    );
}

#[test]
fn v2_schema_requires_scan_id() {
    let mut example: serde_json::Value = serde_json::from_str(EXAMPLE).expect("parse v2 example");
    example.as_object_mut().unwrap().remove("scan_id");
    let s = schema();
    assert!(
        s.validate(&example).is_err(),
        "schema must reject v2 document without scan_id (required in v2; was optional in v1)"
    );
}

#[test]
fn v2_schema_rejects_v1_version_string() {
    let mut example: serde_json::Value = serde_json::from_str(EXAMPLE).expect("parse v2 example");
    example["schema_version"] = serde_json::Value::String("capframe.findings.v1".into());
    let s = schema();
    assert!(
        s.validate(&example).is_err(),
        "v2 schema must reject v1's schema_version const"
    );
}
