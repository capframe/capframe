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
fn dispatch_rejects_incompatible_version() {
    let dir = tempfile::tempdir().unwrap();
    let argv_log = dir.path().join("argv.txt");
    // mcp-recon's version_req is >=0.0.1, <0.1.0 — 9.9.9 must be rejected.
    let _mock = write_mock_module(dir.path(), "mcp-recon", "mcp-recon 9.9.9", &argv_log);

    capframe()
        .env("PATH", dir.path())
        .args(["find", "./does-not-matter.toml"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("requires").or(predicate::str::contains("capframe install")),
        );
}
