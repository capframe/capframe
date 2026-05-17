use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

use crate::modules::{dispatch, Module};

#[derive(ClapArgs, Debug)]
#[command(about = "Run the runtime sentry that gates every tool call")]
pub struct Args {
    /// Path to the policy file
    #[arg(short, long)]
    pub policy: PathBuf,

    /// Address to bind on
    #[arg(short = 'a', long, default_value = "127.0.0.1:8783")]
    pub addr: String,
}

pub fn run(args: Args) -> Result<()> {
    let raw = vec![
        "--policy".into(),
        args.policy.display().to_string(),
        "--addr".into(),
        args.addr,
    ];
    dispatch(Module::Guard, &raw)
}
