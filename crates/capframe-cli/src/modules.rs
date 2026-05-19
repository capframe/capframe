//! Module dispatch — locate the underlying module binary, version-check it, run it.
use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Copy, Debug)]
pub enum Module {
    Find,
    Bind,
    Guard,
}

impl Module {
    /// Binary name we shell out to today.
    pub fn underlying_binary(self) -> &'static str {
        match self {
            Module::Find => "mcp-recon",
            Module::Bind => "capnagent",
            Module::Guard => "mcp-guard",
        }
    }

    pub fn install_hint(self) -> &'static str {
        match self {
            Module::Find => "https://github.com/euanmcrosson-dotcom/mcp-recon",
            Module::Bind => "https://github.com/euanmcrosson-dotcom/capnagent",
            Module::Guard => "https://github.com/euanmcrosson-dotcom/mcp-guard",
        }
    }

    /// Semver range this capframe build is known to be wire-compatible with.
    /// Bump in lockstep with breaking changes to the underlying binary's CLI.
    pub fn version_req(self) -> &'static str {
        match self {
            Module::Find => ">=0.0.1, <0.1.0",
            Module::Bind => ">=0.7.0, <0.8.0",
            Module::Guard => ">=0.5.0, <0.6.0",
        }
    }

    pub fn short_name(self) -> &'static str {
        match self {
            Module::Find => "find",
            Module::Bind => "bind",
            Module::Guard => "guard",
        }
    }
}

pub fn resolve(m: Module) -> Result<PathBuf> {
    which::which(m.underlying_binary()).map_err(|_| {
        anyhow!(
            "module not found: `{}` is not on PATH.\n\nInstall with: capframe install {}\nOr see: {}",
            m.underlying_binary(),
            m.short_name(),
            m.install_hint()
        )
    })
}

/// Resolve the module binary AND verify its version satisfies `Module::version_req`.
pub fn resolve_compatible(m: Module) -> Result<PathBuf> {
    let bin = resolve(m)?;
    let req = semver::VersionReq::parse(m.version_req())
        .with_context(|| format!("parse version_req for {}", m.underlying_binary()))?;
    let v = binary_version(&bin)
        .with_context(|| format!("read --version from {}", bin.display()))?;
    if !req.matches(&v) {
        bail!(
            "module `{}` is version {} but capframe requires {}.\n\
             Reinstall with: capframe install {}",
            m.underlying_binary(),
            v,
            m.version_req(),
            m.short_name(),
        );
    }
    tracing::debug!(module = m.underlying_binary(), version = %v, "version ok");
    Ok(bin)
}

pub fn binary_version(bin: &std::path::Path) -> Result<semver::Version> {
    let out = Command::new(bin).arg("--version").output()?;
    if !out.status.success() {
        bail!("`{} --version` exited {}", bin.display(), out.status);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_version(&stdout)
}

/// Accepts both `prog 0.3.1` (clap default) and `prog v0.3.1`.
pub(crate) fn parse_version(s: &str) -> Result<semver::Version> {
    let token = s
        .split_whitespace()
        .last()
        .ok_or_else(|| anyhow!("empty --version output"))?;
    let token = token.trim_start_matches('v');
    semver::Version::parse(token).with_context(|| format!("parse semver `{token}`"))
}

pub fn dispatch(m: Module, args: &[String]) -> Result<()> {
    let bin = resolve_compatible(m)?;
    tracing::debug!(?bin, ?args, "dispatching");
    let status = Command::new(&bin)
        .args(args)
        .status()
        .with_context(|| format!("failed to launch {}", bin.display()))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clap_default_output() {
        let v = parse_version("mcp-recon 0.3.1\n").unwrap();
        assert_eq!(v, semver::Version::new(0, 3, 1));
    }

    #[test]
    fn parse_v_prefixed() {
        let v = parse_version("capnagent v1.2.0").unwrap();
        assert_eq!(v, semver::Version::new(1, 2, 0));
    }
}
