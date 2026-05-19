use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use std::path::PathBuf;

use crate::modules::{dispatch, Module};

#[derive(ClapArgs, Debug)]
#[command(about = "Synthesize / evaluate / backtest policies via mcp-guard")]
pub struct Args {
    #[command(subcommand)]
    op: Op,
}

#[derive(Subcommand, Debug)]
enum Op {
    /// Synthesize a YAML policy from a free-text description of the gap.
    Synthesize {
        /// Free-text description of the observed gap.
        detail: String,
        /// Optional MITRE ATLAS technique id (e.g. T0051).
        #[arg(long)]
        technique_id: Option<String>,
        /// Optional source kind tag.
        #[arg(long)]
        kind: Option<String>,
    },

    /// Evaluate one candidate tool call against a policy.
    Evaluate {
        /// Path to the YAML policy.
        policy: PathBuf,
        /// Tool name being evaluated.
        tool_name: String,
        /// JSON-encoded tool args (use '{}' for none).
        tool_args: String,
        /// Optional JSON-encoded user context.
        #[arg(long)]
        user_context: Option<String>,
    },

    /// Run the default corpus backtest against a policy.
    Backtest {
        /// Path to the YAML policy.
        policy: PathBuf,
    },
}

pub fn run(args: Args) -> Result<()> {
    let raw: Vec<String> = match args.op {
        Op::Synthesize {
            detail,
            technique_id,
            kind,
        } => {
            let mut v = vec!["synthesize".into(), detail];
            if let Some(t) = technique_id {
                v.push("--technique-id".into());
                v.push(t);
            }
            if let Some(k) = kind {
                v.push("--kind".into());
                v.push(k);
            }
            v
        }
        Op::Evaluate {
            policy,
            tool_name,
            tool_args,
            user_context,
        } => {
            let mut v = vec![
                "evaluate".into(),
                policy.display().to_string(),
                tool_name,
                tool_args,
            ];
            if let Some(ctx) = user_context {
                v.push("--user-context".into());
                v.push(ctx);
            }
            v
        }
        Op::Backtest { policy } => vec!["backtest".into(), policy.display().to_string()],
    };
    dispatch(Module::Guard, &raw)
}
