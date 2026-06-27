use capframe_leaderboard::{build, to_json, LEADERBOARD_SCHEMA_VERSION, SCORE_MAX};
use std::fs;
use tempfile::TempDir;
use time::OffsetDateTime;

fn seed_fixtures() -> TempDir {
    let dir = TempDir::new().unwrap();
    for name in ["good", "risky", "mid"] {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(format!("{name}.findings.v2.json"));
        let dst = dir.path().join(format!("{name}.findings.v2.json"));
        fs::copy(&src, &dst).expect("copy fixture");
    }
    // a non-findings file that should be ignored
    fs::write(dir.path().join("README.md"), "ignore me").unwrap();
    dir
}

#[test]
fn builds_leaderboard_sorted_by_score_desc() {
    let dir = seed_fixtures();
    let board = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap();
    assert_eq!(board.schema_version, LEADERBOARD_SCHEMA_VERSION);
    assert_eq!(board.total_scanned, 3);
    assert_eq!(board.rows.len(), 3);
    // good = 100, mid = 100 - (4+2) = 94, risky = 100 - (10+2) = 88
    assert_eq!(board.rows[0].score, SCORE_MAX);
    assert_eq!(board.rows[0].handle, "npm:@safe/good-server@1.0.0");
    assert_eq!(board.rows[1].score, 94);
    assert_eq!(board.rows[1].handle, "pypi:mid-server@0.5.0");
    assert_eq!(board.rows[2].score, 88);
    assert_eq!(board.rows[2].handle, "npm:@risky/exec-server@2.0.0");
}

#[test]
fn rows_carry_identity_through() {
    let dir = seed_fixtures();
    let board = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap();
    let risky = board
        .rows
        .iter()
        .find(|r| r.handle == "npm:@risky/exec-server@2.0.0")
        .unwrap();
    assert_eq!(risky.name.as_deref(), Some("exec-server"));
    assert_eq!(
        risky.repo_url.as_deref(),
        Some("https://github.com/risky/exec-server")
    );
    assert_eq!(risky.counts.critical, 1);
    assert_eq!(risky.counts.medium, 1);
    // tool_count flows from the v2 doc's tools[] length
    assert_eq!(risky.tool_count, 3);
    // findings array carries through end-to-end for the detail view
    assert_eq!(risky.findings.len(), 2);
    let ids: Vec<&str> = risky.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"f-r7-exec"));
    assert!(ids.contains(&"f-r6-fetch"));
    let mid = board
        .rows
        .iter()
        .find(|r| r.handle == "pypi:mid-server@0.5.0")
        .unwrap();
    assert_eq!(mid.tool_count, 2);
    let good = board
        .rows
        .iter()
        .find(|r| r.handle == "npm:@safe/good-server@1.0.0")
        .unwrap();
    assert_eq!(good.tool_count, 0);
}

#[test]
fn ties_break_by_handle_ascending() {
    let dir = TempDir::new().unwrap();
    for (slug, handle) in [
        ("alpha", "npm:alpha@1.0.0"),
        ("beta", "npm:beta@1.0.0"),
        ("gamma", "npm:gamma@1.0.0"),
    ] {
        let doc = format!(
            r#"{{
                "schema_version":"capframe.findings.v2",
                "scan_id":"00000000-0000-0000-0000-000000000000",
                "scanned_at":"2026-05-29T18:00:00Z",
                "scanner":{{"name":"x","version":"0.0.0"}},
                "server":{{"handle":"{handle}","kind":"mcp_server","source":"registry"}},
                "findings":[],
                "summary":{{"total":0,"by_severity":{{"info":0,"low":0,"medium":0,"high":0,"critical":0}}}}
            }}"#,
        );
        fs::write(dir.path().join(format!("{slug}.findings.v2.json")), doc).unwrap();
    }
    let board = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap();
    assert_eq!(board.rows[0].handle, "npm:alpha@1.0.0");
    assert_eq!(board.rows[1].handle, "npm:beta@1.0.0");
    assert_eq!(board.rows[2].handle, "npm:gamma@1.0.0");
}

#[test]
fn malformed_file_does_not_abort_build() {
    let dir = seed_fixtures();
    fs::write(dir.path().join("bad.findings.v2.json"), "{ not json").unwrap();
    let board = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap();
    // The 3 fixtures still land; the bad one is skipped with a tracing warn.
    assert_eq!(board.total_scanned, 3);
}

#[test]
fn empty_dir_errors_with_helpful_message() {
    let dir = TempDir::new().unwrap();
    let err = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap_err();
    assert!(err.to_string().contains("no *.findings.v2.json"));
}

#[test]
fn all_malformed_dir_errors_instead_of_publishing_empty() {
    // A run where EVERY input file fails to parse must error, not return a
    // successful empty board that would silently wipe the published leaderboard.
    let dir = TempDir::new().unwrap();
    for slug in ["a", "b", "c"] {
        fs::write(
            dir.path().join(format!("{slug}.findings.v2.json")),
            "{ not json",
        )
        .unwrap();
    }
    let err = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("parseable") && msg.contains('3'),
        "error should report that all 3 files were skipped as malformed, got: {msg}"
    );
}

#[test]
fn score_comes_from_findings_not_self_reported_summary() {
    // A producer that declares a clean summary while shipping a Critical in
    // findings[] must NOT score 100. The score is derived from the actual
    // findings the detail view renders, so the board can't be gamed by a lying
    // summary counter.
    let dir = TempDir::new().unwrap();
    let body = r#"{
        "schema_version":"capframe.findings.v2",
        "scan_id":"00000000-0000-0000-0000-000000000000",
        "scanned_at":"2026-05-29T18:00:00Z",
        "scanner":{"name":"x","version":"0.0.0"},
        "server":{"handle":"npm:@liar/server@1.0.0","kind":"mcp_server","source":"registry"},
        "findings":[{"id":"f1","severity":"critical","category":"excessive_agency","title":"t"}],
        "summary":{"total":0,"by_severity":{"info":0,"low":0,"medium":0,"high":0,"critical":0}}
    }"#;
    fs::write(dir.path().join("liar.findings.v2.json"), body).unwrap();

    let board = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap();
    let row = &board.rows[0];
    assert_eq!(
        row.score, 90,
        "one critical -> 90 regardless of the declared summary"
    );
    assert_eq!(
        row.counts.critical, 1,
        "row counts must reflect findings[], not the lie"
    );
}

#[test]
fn duplicate_handles_collapse_to_newest_scan() {
    // Two distinct files resolving to the SAME handle (e.g. a stale registry
    // slug + a fresh sandbox slug) must produce ONE row, not two. The newer
    // scan wins so the board reflects the latest grade.
    let dir = TempDir::new().unwrap();
    let doc = |slug: &str, scanned_at: &str, source: &str, findings: &str, sev: &str| {
        let body = format!(
            r#"{{
                "schema_version":"capframe.findings.v2",
                "scan_id":"00000000-0000-0000-0000-000000000000",
                "scanned_at":"{scanned_at}",
                "scanner":{{"name":"x","version":"0.0.0"}},
                "server":{{"handle":"npm:@dup/server@1.0.0","kind":"mcp_server","source":"{source}"}},
                "findings":{findings},
                "summary":{{"total":0,"by_severity":{sev}}}
            }}"#,
        );
        fs::write(dir.path().join(format!("{slug}.findings.v2.json")), body).unwrap();
    };
    // older registry scan: one critical -> score 90
    doc(
        "registry-slug",
        "2026-05-29T18:00:00Z",
        "registry",
        r#"[{"id":"f1","severity":"critical","category":"excessive_agency","title":"t"}]"#,
        r#"{"info":0,"low":0,"medium":0,"high":0,"critical":1}"#,
    );
    // newer sandbox scan: clean -> score 100
    doc(
        "sandbox-slug",
        "2026-05-30T18:00:00Z",
        "sandbox",
        "[]",
        r#"{"info":0,"low":0,"medium":0,"high":0,"critical":0}"#,
    );

    let board = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap();
    assert_eq!(
        board.total_scanned, 1,
        "duplicate handle must collapse to one row"
    );
    let row = &board.rows[0];
    assert_eq!(row.handle, "npm:@dup/server@1.0.0");
    assert_eq!(row.score, SCORE_MAX, "newer (sandbox) scan should win");
    assert_eq!(row.counts.critical, 0);
}

#[test]
fn duplicate_package_different_versions_collapse_to_newest() {
    // The real-world case the leaderboard hit: the registry corpus pins a
    // package at one version (a shallow static scan) while the sandbox corpus
    // pins the SAME package at a newer version (a deep live scan). Those handles
    // differ only in the trailing `@<version>`, so a handle-keyed dedup leaves
    // two contradicting rows on the board (e.g. firecrawl-mcp@3.20.1 at 94 next
    // to firecrawl-mcp@3.20.2 at 0). They must collapse to ONE row keyed on the
    // version-independent package identity, with the newer/richer scan winning.
    let dir = TempDir::new().unwrap();
    let doc = |slug: &str, handle: &str, scanned_at: &str, source: &str, findings: &str| {
        let body = format!(
            r#"{{
                "schema_version":"capframe.findings.v2",
                "scan_id":"00000000-0000-0000-0000-000000000000",
                "scanned_at":"{scanned_at}",
                "scanner":{{"name":"x","version":"0.0.0"}},
                "server":{{"handle":"{handle}","kind":"mcp_server","source":"{source}"}},
                "findings":{findings},
                "summary":{{"total":0,"by_severity":{{"info":0,"low":0,"medium":0,"high":0,"critical":0}}}}
            }}"#,
        );
        fs::write(dir.path().join(format!("{slug}.findings.v2.json")), body).unwrap();
    };
    // older registry scan of 3.20.1: one critical -> score 90
    doc(
        "registry-slug",
        "npm:firecrawl-mcp@3.20.1",
        "2026-06-27T09:21:24Z",
        "registry",
        r#"[{"id":"f1","severity":"critical","category":"excessive_agency","title":"t"}]"#,
    );
    // newer sandbox scan of 3.20.2: clean -> score 100
    doc(
        "sandbox-slug",
        "npm:firecrawl-mcp@3.20.2",
        "2026-06-27T09:23:58Z",
        "sandbox",
        "[]",
    );

    let board = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap();
    assert_eq!(
        board.total_scanned, 1,
        "same package at two versions must collapse to one row"
    );
    let row = &board.rows[0];
    assert_eq!(
        row.handle, "npm:firecrawl-mcp@3.20.2",
        "the newer sandbox scan's handle (and version) should be the surviving row"
    );
    assert_eq!(row.score, SCORE_MAX, "newer (sandbox) scan should win");
}

#[test]
fn non_regular_findings_entry_is_counted_not_silently_dropped() {
    // A *directory* (or symlink) named like a findings file must be counted as
    // skipped and surfaced, not silently dropped so the dir looks empty.
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("sneaky.findings.v2.json")).unwrap();
    let err = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap_err();
    assert!(
        err.to_string().contains("skipped"),
        "a present-but-skipped entry must be distinguished from an empty dir, got: {err}"
    );
}

#[test]
fn to_json_roundtrips_via_serde() {
    let dir = seed_fixtures();
    let board = build(dir.path(), OffsetDateTime::UNIX_EPOCH).unwrap();
    let body = to_json(&board, true).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["schema_version"], "capframe.leaderboard.v1");
    assert!(parsed["rows"].is_array());
    assert_eq!(parsed["weights"]["critical"], 10);
}
