use anyhow::Result;

use crate::modules::{binary_version, resolve, resolve_compatible, Module};

/// Health of one module binary as observed by `doctor`.
enum Health {
    /// Not resolvable on PATH (carries the resolve error message).
    Missing(String),
    /// Resolved, but `--version` could not be read/parsed.
    Unreadable(String),
    /// Resolved and readable, but the version is outside the required band.
    Incompatible { version: String, req: String },
    /// Resolved, readable, and in-band.
    Ok { version: String, path: String },
}

/// Render one module's health line. Pure (no I/O) so the OK/BAD verdict and
/// formatting are exercised directly by tests.
fn render_line(short: &str, health: &Health) -> String {
    match health {
        Health::Missing(e) => format!("  {short:<6} --   {e}"),
        Health::Unreadable(e) => format!("  {short:<6} ??   {e}"),
        Health::Incompatible { version, req } => {
            format!("  {short:<6} BAD  {version} (requires {req})")
        }
        Health::Ok { version, path } => format!("  {short:<6} OK   {version}  {path}"),
    }
}

/// Resolve a module and evaluate it against its required version band.
/// Never bails — doctor reports state, it does not fail the process.
fn health(m: Module) -> Health {
    let bin = match resolve(m) {
        Ok(p) => p,
        Err(e) => return Health::Missing(e.to_string()),
    };
    let version = match binary_version(&bin) {
        Ok(v) => v,
        Err(e) => return Health::Unreadable(e.to_string()),
    };
    // Delegate compat check to resolve_compatible so the gate is identical
    // to dispatch(). If the two diverged, doctor could report OK on a binary
    // that dispatch() would reject.
    if resolve_compatible(m).is_err() {
        return Health::Incompatible {
            version: version.to_string(),
            req: m.version_req().to_string(),
        };
    }
    Health::Ok {
        version: version.to_string(),
        path: bin.display().to_string(),
    }
}

pub fn run() -> Result<()> {
    println!("capframe doctor — module resolution & version compatibility\n");
    for (label, m) in [
        ("find", Module::Find),
        ("bind", Module::Bind),
        ("guard", Module::Guard),
    ] {
        println!("{}", render_line(label, &health(m)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incompatible_line_shows_version_and_band() {
        let line = render_line(
            "find",
            &Health::Incompatible {
                version: "9.9.9".to_string(),
                req: ">=0.0.1, <0.1.0".to_string(),
            },
        );
        assert!(line.contains("BAD"), "{line}");
        assert!(line.contains("9.9.9"), "{line}");
        assert!(line.contains("requires >=0.0.1, <0.1.0"), "{line}");
    }

    #[test]
    fn ok_line_shows_version() {
        let line = render_line(
            "bind",
            &Health::Ok {
                version: "0.7.5".to_string(),
                path: "/usr/local/bin/capnagent".to_string(),
            },
        );
        assert!(line.contains("OK"), "{line}");
        assert!(line.contains("0.7.5"), "{line}");
    }

    #[test]
    fn missing_line_preserves_resolve_error() {
        let line = render_line("guard", &Health::Missing("module not found: x".to_string()));
        assert!(line.contains("module not found"), "{line}");
    }
}
