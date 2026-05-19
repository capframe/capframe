use capframe_findings::{
    Findings, Mappings, Scanner, SeverityCounts, Summary, Target, TargetKind, SCHEMA_VERSION,
};
use jsonschema::JSONSchema;
use time::OffsetDateTime;

const SCHEMA: &str = include_str!("../../../schemas/findings.v1.json");
const EXAMPLE: &str = include_str!("../../../schemas/findings.example.json");

fn schema() -> JSONSchema {
    let v: serde_json::Value = serde_json::from_str(SCHEMA).expect("schema is valid json");
    JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&v)
        .expect("schema compiles")
}

fn assert_valid(s: &JSONSchema, doc: &serde_json::Value, context: &str) {
    if let Err(errors) = s.validate(doc) {
        let msgs: Vec<String> = errors
            .map(|e| format!("  - {} @ {}", e, e.instance_path))
            .collect();
        panic!("{context} failed validation:\n{}", msgs.join("\n"));
    }
}

#[test]
fn example_payload_validates() {
    let s = schema();
    let example: serde_json::Value =
        serde_json::from_str(EXAMPLE).expect("example is valid json");
    assert_valid(&s, &example, "schemas/findings.example.json");
}

#[test]
fn rust_serialization_validates() {
    let parsed: Findings =
        serde_json::from_str(EXAMPLE).expect("parse example into Rust types");
    let reserialized = serde_json::to_value(&parsed).expect("reserialize Rust types");
    assert_valid(&schema(), &reserialized, "Rust-roundtripped example");
}

#[test]
fn minimal_synthetic_findings_validates() {
    let minimal = Findings {
        schema_version: SCHEMA_VERSION.into(),
        scanned_at: OffsetDateTime::now_utc(),
        scan_id: None,
        scanner: Scanner {
            name: "capframe-test".into(),
            version: "0.1.0".into(),
        },
        target: Target {
            kind: TargetKind::McpServer,
            name: Some("test-target".into()),
            url: None,
            path: None,
            transport: None,
        },
        tools: vec![],
        findings: vec![],
        summary: Summary {
            total: 0,
            by_severity: SeverityCounts::default(),
            by_category: Default::default(),
            mappings: Mappings::default(),
        },
    };
    let v = serde_json::to_value(&minimal).expect("serialize minimal");
    assert_valid(&schema(), &v, "synthetic minimal Findings");
}

#[test]
fn schema_rejects_unknown_severity() {
    let mut example: serde_json::Value =
        serde_json::from_str(EXAMPLE).expect("parse example");
    example["findings"][0]["severity"] = serde_json::Value::String("apocalyptic".into());
    let s = schema();
    assert!(
        s.validate(&example).is_err(),
        "schema must reject unknown severity values"
    );
}

#[test]
fn schema_rejects_malformed_owasp_id() {
    let mut example: serde_json::Value =
        serde_json::from_str(EXAMPLE).expect("parse example");
    example["findings"][0]["mappings"]["owasp_llm"] =
        serde_json::Value::Array(vec![serde_json::Value::String("LLM99".into())]);
    let s = schema();
    assert!(
        s.validate(&example).is_err(),
        "owasp_llm pattern must reject LLM99 (out of range)"
    );
}
