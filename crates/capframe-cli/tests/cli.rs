use assert_cmd::Command;
use predicates::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

fn capframe() -> Command {
    Command::cargo_bin("capframe").expect("build capframe bin")
}

/// Write a mock module binary that prints `version_output` on `--version`
/// and otherwise dumps its argv (space-separated) into `argv_log`.
///
/// On Unix: writes a `#!/bin/sh` script and chmods 0o755.
/// On Windows: writes a `.bat` file. `which::which` resolves `.bat`
/// via PATHEXT, and `Command::new(...)` invokes batch files through
/// the OS loader (Rust 1.77.2+).
fn write_mock_module(dir: &Path, name: &str, version_output: &str, argv_log: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        let script = format!(
            "#!/bin/sh
if [ \"$1\" = \"--version\" ]; then echo '{ver}'; exit 0; fi
printf '%s ' \"$@\" > '{log}'
",
            ver = version_output,
            log = argv_log.display()
        );
        let mut f = File::create(&path).unwrap();
        f.write_all(script.as_bytes()).unwrap();
        drop(f);
        fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
        path
    }
    #[cfg(windows)]
    {
        let path = dir.join(format!("{name}.bat"));
        let script = format!(
            "@echo off\r\nif \"%~1\"==\"--version\" (\r\n    echo {ver}\r\n    exit /b 0\r\n)\r\necho %*> \"{log}\"\r\nexit /b 0\r\n",
            ver = version_output,
            log = argv_log.display()
        );
        let mut f = File::create(&path).unwrap();
        f.write_all(script.as_bytes()).unwrap();
        drop(f);
        path
    }
}

#[test]
fn version_prints() {
    capframe()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("capframe"));
}

#[test]
fn top_level_help_lists_install_subcommand() {
    capframe()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("install"))
        .stdout(predicate::str::contains("doctor"));
}

#[test]
fn bind_help_documents_limit_flag() {
    capframe()
        .args(["bind", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--limit"))
        .stdout(predicate::str::contains("key=value"));
}

#[test]
fn install_help_includes_module_values() {
    capframe()
        .args(["install", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("find"))
        .stdout(predicate::str::contains("bind"))
        .stdout(predicate::str::contains("guard"));
}

#[test]
fn doctor_reports_modules_missing_on_empty_path() {
    capframe()
        .env_clear()
        .env("PATH", "")
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("module not found"));
}

#[test]
fn doctor_flags_out_of_band_module_version() {
    // doctor must actually run `--version` and check the compat band, not just
    // report OK because the binary resolves on PATH. mcp-recon requires
    // >=0.0.1,<0.1.0 — a 9.9.9 binary must be shown as incompatible (with its
    // version), but doctor still exits success (it reports, it doesn't fail).
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    let _mock = write_mock_module(dir.path(), "mcp-recon", "mcp-recon 9.9.9", &argv_log);

    capframe()
        .env("PATH", dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("9.9.9"))
        .stdout(predicate::str::contains("requires"));
}

#[test]
fn doctor_reports_version_for_compatible_module() {
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    let _mock = write_mock_module(dir.path(), "mcp-recon", "mcp-recon 0.0.12", &argv_log);

    capframe()
        .env("PATH", dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.0.12"))
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn bind_passes_limits_through_to_module() {
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    let _mock = write_mock_module(dir.path(), "capnagent", "capnagent 0.7.5", &argv_log);

    capframe()
        .env("PATH", dir.path())
        .args([
            "bind",
            "--agent",
            "shopify-bot",
            "--tools",
            "order.read,refund.write",
            "--limit",
            "max_refund=50",
            "--limit",
            "region=eu",
            "--ttl",
            "24h",
        ])
        .assert()
        .success();

    let argv = fs::read_to_string(&argv_log).expect("mock wrote argv");
    assert!(argv.contains("--agent"), "got: {argv}");
    assert!(argv.contains("shopify-bot"), "got: {argv}");
    assert!(argv.contains("--tools"), "got: {argv}");
    assert!(argv.contains("order.read,refund.write"), "got: {argv}");
    assert!(argv.contains("--limit"), "got: {argv}");
    assert!(argv.contains("max_refund=50"), "got: {argv}");
    assert!(argv.contains("region=eu"), "got: {argv}");
    assert!(argv.contains("--ttl"), "got: {argv}");
    assert!(argv.contains("24h"), "got: {argv}");
}

#[test]
fn guard_backtest_dispatches_to_mcp_guard_backtest() {
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    let _mock = write_mock_module(dir.path(), "mcp-guard", "mcp-guard 0.5.5", &argv_log);

    capframe()
        .env("PATH", dir.path())
        .args(["guard", "backtest", "/tmp/policy.yaml"])
        .assert()
        .success();

    let argv = fs::read_to_string(&argv_log).expect("mock wrote argv");
    assert!(argv.contains("backtest"), "got: {argv}");
    assert!(argv.contains("policy.yaml"), "got: {argv}");
    // Must NOT pass the old --policy / --addr flag shape:
    assert!(
        !argv.contains("--policy"),
        "old --policy flag leaked: {argv}"
    );
    assert!(!argv.contains("--addr"), "old --addr flag leaked: {argv}");
}

#[test]
fn guard_synthesize_dispatches_to_mcp_guard_synthesize() {
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    let _mock = write_mock_module(dir.path(), "mcp-guard", "mcp-guard 0.5.5", &argv_log);

    capframe()
        .env("PATH", dir.path())
        .args([
            "guard",
            "synthesize",
            "the tool deleted my prod db",
            "--technique-id",
            "T0051",
        ])
        .assert()
        .success();

    let argv = fs::read_to_string(&argv_log).expect("mock wrote argv");
    assert!(argv.contains("synthesize"), "got: {argv}");
    assert!(argv.contains("deleted my prod db"), "got: {argv}");
    assert!(argv.contains("--technique-id"), "got: {argv}");
    assert!(argv.contains("T0051"), "got: {argv}");
}

#[test]
fn guard_evaluate_dispatches_three_positional_args() {
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    let _mock = write_mock_module(dir.path(), "mcp-guard", "mcp-guard 0.5.5", &argv_log);

    capframe()
        .env("PATH", dir.path())
        .args([
            "guard",
            "evaluate",
            "/tmp/policy.yaml",
            "order.refund",
            "{\"amount\":50}",
        ])
        .assert()
        .success();

    let argv = fs::read_to_string(&argv_log).expect("mock wrote argv");
    assert!(argv.contains("evaluate"), "got: {argv}");
    assert!(argv.contains("policy.yaml"), "got: {argv}");
    assert!(argv.contains("order.refund"), "got: {argv}");
    assert!(argv.contains("amount"), "got: {argv}");
}

#[test]
fn dispatch_rejects_incompatible_version_via_external_flag() {
    // With in-process dispatch as the default, the version-check path only
    // fires when the user explicitly asks for the external binary. The
    // contract is preserved: if you opt into `--external`, the on-PATH
    // binary's version_req still gates the call.
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    // mcp-recon's version_req is >=0.0.1, <0.1.0 — 9.9.9 must be rejected.
    let _mock = write_mock_module(dir.path(), "mcp-recon", "mcp-recon 9.9.9", &argv_log);

    capframe()
        .env("PATH", dir.path())
        .args(["find", "--external", "./does-not-matter.toml"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("requires").or(predicate::str::contains("capframe install")),
        );
}

#[test]
fn find_runs_in_process_against_a_real_inventory() {
    // No on-PATH mcp-recon — the in-process path must classify the inventory
    // and emit a valid capframe.findings.v1 envelope without touching the
    // subprocess fallback at all.
    let dir = tempfile::tempdir().unwrap();
    let inventory = dir.path().join("inventory.json");
    let findings_out = dir.path().join("findings.json");

    let inv = serde_json::json!({
        "schema": "mcp-recon.inventory.v1",
        "servers": [{
            "name": "test",
            "tools": [
                { "name": "execute_shell",
                  "description": "Execute a shell command.",
                  "parameters": { "type": "object", "properties": {
                      "cmd": { "type": "string", "maxLength": 4096 }
                  }},
                  "side_effects": [],
                  "auth_required": true },
                { "name": "list_users",
                  "description": "List users.",
                  "side_effects": ["read"],
                  "auth_required": true }
            ]
        }]
    });
    fs::write(&inventory, serde_json::to_string(&inv).unwrap()).unwrap();

    capframe()
        // Empty PATH — proves no subprocess fallback was used.
        .env("PATH", "")
        .args([
            "find",
            inventory.to_string_lossy().as_ref(),
            "--out",
            findings_out.to_string_lossy().as_ref(),
            "--format",
            "pretty",
        ])
        .assert()
        .success();

    let body = fs::read_to_string(&findings_out).expect("findings file written");
    let v: serde_json::Value = serde_json::from_str(&body).expect("findings JSON");
    assert_eq!(v["schema_version"], "capframe.findings.v1");
    assert_eq!(v["scanner"]["name"], "mcp-recon");
    // R7 should fire on execute_shell.
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(
        ids.iter()
            .any(|id| id.contains("r7") && id.contains("execute_shell")),
        "R7 should fire on execute_shell; got {ids:?}"
    );
    assert_eq!(v["summary"]["by_severity"]["critical"], 1);
}

#[test]
fn find_external_flag_actually_dispatches_to_on_path_binary() {
    // With --external the on-PATH binary IS invoked; argv should reach it.
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    let _mock = write_mock_module(dir.path(), "mcp-recon", "mcp-recon 0.0.12", &argv_log);

    let inventory = dir.path().join("inventory.json");
    fs::write(
        &inventory,
        r#"{"schema":"mcp-recon.inventory.v1","servers":[]}"#,
    )
    .unwrap();

    capframe()
        .env("PATH", dir.path())
        .args([
            "find",
            "--external",
            inventory.to_string_lossy().as_ref(),
            "--out",
            dir.path().join("findings.json").to_string_lossy().as_ref(),
        ])
        .assert()
        .success();

    let argv = fs::read_to_string(&argv_log).expect("mock wrote argv");
    assert!(argv.contains("--target"), "got: {argv}");
    assert!(argv.contains("--out"), "got: {argv}");
}

#[test]
fn pipeline_find_bind_guard_full_cycle() {
    // ── Setup ─────────────────────────────────────────────────────────────────
    let dir = tempfile::tempdir().unwrap();
    let argv_bind = dir.path().join("argv_bind.txt");
    let argv_guard = dir.path().join("argv_guard.txt");

    let _mock_capnagent = write_mock_module(dir.path(), "capnagent", "capnagent 0.7.5", &argv_bind);
    let _mock_guard = write_mock_module(dir.path(), "mcp-guard", "mcp-guard 0.5.5", &argv_guard);

    let inventory = dir.path().join("inventory.json");
    let findings_out = dir.path().join("findings.json");

    // Two dangerous tools: one monetary (R4), one exec (R7).
    let inv = serde_json::json!({
        "schema": "mcp-recon.inventory.v1",
        "servers": [{
            "name": "shopify-mcp",
            "tools": [
                {
                    "name": "order.refund",
                    "description": "Issue a full refund on an order.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "order_id": { "type": "string" },
                            "amount":   { "type": "number" }
                        }
                    },
                    "side_effects": ["write", "money", "irreversible"],
                    "auth_required": true
                },
                {
                    "name": "run_shell",
                    "description": "Execute a shell command on the host.",
                    "parameters": {},
                    "side_effects": [],
                    "auth_required": true
                }
            ]
        }]
    });
    fs::write(&inventory, serde_json::to_string(&inv).unwrap()).unwrap();

    // ── STEP 1: FIND ──────────────────────────────────────────────────────────
    capframe()
        .env("PATH", dir.path())
        .args([
            "find",
            inventory.to_string_lossy().as_ref(),
            "--out",
            findings_out.to_string_lossy().as_ref(),
            "--format",
            "pretty",
        ])
        .assert()
        .success();

    let body = fs::read_to_string(&findings_out).expect("findings written");
    let v: serde_json::Value = serde_json::from_str(&body).expect("findings JSON");
    assert_eq!(
        v["schema_version"], "capframe.findings.v1",
        "find must emit findings.v1 envelope"
    );
    assert_eq!(
        v["scanner"]["name"], "mcp-recon",
        "scanner name must be mcp-recon"
    );
    // R7 fires on run_shell → Critical.
    assert!(
        v["summary"]["by_severity"]["critical"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "R7 must fire on run_shell; summary: {}",
        v["summary"]
    );
    // R4 fires on order.refund (unbounded numeric amount) → High.
    assert!(
        v["summary"]["by_severity"]["high"].as_u64().unwrap_or(0) >= 1,
        "R4 must fire on order.refund; summary: {}",
        v["summary"]
    );
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap_or(""))
        .collect();
    assert!(
        ids.iter().any(|id| id.contains("r7")),
        "must have an R7 finding; ids: {ids:?}"
    );

    // ── STEP 2: BIND ──────────────────────────────────────────────────────────
    capframe()
        .env("PATH", dir.path())
        .args([
            "bind",
            "--agent",
            "shopify-bot",
            "--tools",
            "order.refund",
            "--limit",
            "max_refund=100.00",
            "--ttl",
            "24h",
        ])
        .assert()
        .success();

    let bind_argv = fs::read_to_string(&argv_bind).expect("mock capnagent wrote argv");
    assert!(
        bind_argv.contains("shopify-bot"),
        "agent name must reach capnagent; got: {bind_argv}"
    );
    assert!(
        bind_argv.contains("order.refund"),
        "tool list must reach capnagent; got: {bind_argv}"
    );
    assert!(
        bind_argv.contains("max_refund=100.00"),
        "limit must reach capnagent; got: {bind_argv}"
    );
    assert!(
        bind_argv.contains("24h"),
        "ttl must reach capnagent; got: {bind_argv}"
    );

    // ── STEP 3: GUARD evaluate ────────────────────────────────────────────────
    capframe()
        .env("PATH", dir.path())
        .args([
            "guard",
            "evaluate",
            "/tmp/policy.yaml",
            "order.refund",
            r#"{"order_id":"ord-123","amount":47.50}"#,
        ])
        .assert()
        .success();

    let guard_argv = fs::read_to_string(&argv_guard).expect("mock mcp-guard wrote argv");
    assert!(
        guard_argv.contains("evaluate"),
        "evaluate subcommand must reach mcp-guard; got: {guard_argv}"
    );
    assert!(
        guard_argv.contains("order.refund"),
        "tool name must reach mcp-guard; got: {guard_argv}"
    );
    assert!(
        guard_argv.contains("amount"),
        "args must reach mcp-guard; got: {guard_argv}"
    );
    assert!(
        guard_argv.contains("policy.yaml"),
        "policy path must reach mcp-guard; got: {guard_argv}"
    );
}
