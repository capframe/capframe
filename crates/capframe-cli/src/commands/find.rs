use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

use crate::modules::{dispatch, Module};

#[derive(ClapArgs, Debug)]
#[command(about = "Discover the tool surface of an MCP server")]
pub struct Args {
    /// Path to the MCP server configuration to scan
    pub target: PathBuf,

    /// Write findings to this file (default: ./capframe.findings.json)
    #[arg(short, long, default_value = "capframe.findings.json")]
    pub out: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub format: Format,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Format {
    Json,
    Pretty,
}

pub fn run(args: Args) -> Result<()> {
    tracing::info!(target = %args.target.display(), "running capframe find");
    let mut raw = vec![
        "--target".to_string(),
        args.target.display().to_string(),
        "--out".to_string(),
        args.out.display().to_string(),
    ];
    if matches!(args.format, Format::Pretty) {
        raw.push("--pretty".into());
    }
    dispatch(Module::Find, &raw)
}
