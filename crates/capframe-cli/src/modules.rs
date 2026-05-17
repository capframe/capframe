//! Module dispatch — find the underlying module binary or report how to install it.
use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Copy, Debug)]
pub enum Module {
    Find,
    Bind,
    Guard,
}

impl Module {
    /// Binary name we shell out to today. Will become an in-process call once
    /// the modules are folded into the workspace.
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
}

pub fn resolve(m: Module) -> Result<PathBuf> {
    which::which(m.underlying_binary()).map_err(|_| {
        anyhow!(
            "module not found: `{}` is not on PATH.\n\nInstall instructions: {}",
            m.underlying_binary(),
            m.install_hint()
        )
    })
}

pub fn dispatch(m: Module, args: &[String]) -> Result<()> {
    let bin = resolve(m)?;
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
