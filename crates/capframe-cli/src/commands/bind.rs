use anyhow::Result;
use clap::Args as ClapArgs;

use crate::modules::{dispatch, Module};

#[derive(ClapArgs, Debug)]
#[command(about = "Mint a scoped, revocable capability token")]
pub struct Args {
    /// Logical agent name this token is issued to
    #[arg(long)]
    pub agent: String,

    /// Comma-separated tool scopes (e.g. "order.read, refund.write")
    #[arg(long)]
    pub tools: String,

    /// Optional refund ceiling (USD)
    #[arg(long)]
    pub max_refund: Option<f64>,

    /// Token TTL, e.g. 24h, 7d
    #[arg(long, default_value = "24h")]
    pub ttl: String,
}

pub fn run(args: Args) -> Result<()> {
    let mut raw = vec![
        "--agent".into(),
        args.agent,
        "--tools".into(),
        args.tools,
        "--ttl".into(),
        args.ttl,
    ];
    if let Some(max) = args.max_refund {
        raw.push("--max-refund".into());
        raw.push(max.to_string());
    }
    dispatch(Module::Bind, &raw)
}
