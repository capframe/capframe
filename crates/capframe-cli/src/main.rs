use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod modules;

#[derive(Parser, Debug)]
#[command(
    name = "capframe",
    version,
    about = "Capability-based security for AI agents",
    long_about = "Capframe finds the tool surface your agents touch, \
                  binds their authority with revocable capability tokens, \
                  and guards every call at runtime."
)]
struct Cli {
    /// Increase output verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Discover the tool surface of an MCP server or agent and emit findings
    Find(commands::find::Args),

    /// Mint a scoped, revocable capability token for an agent
    Bind(commands::bind::Args),

    /// Run the runtime sentry that evaluates every tool call against policy
    Guard(commands::guard::Args),

    /// Produce an audit-ready compliance report (OWASP / NIST / ATLAS)
    Report(commands::report::Args),

    /// Show installed module versions and where each binary resolves from
    Doctor,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Command::Find(a) => commands::find::run(a),
        Command::Bind(a) => commands::bind::run(a),
        Command::Guard(a) => commands::guard::run(a),
        Command::Report(a) => commands::report::run(a),
        Command::Doctor => commands::doctor::run(),
    }
}

fn init_tracing(v: u8) {
    let default = match v {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_env("CAPFRAME_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
