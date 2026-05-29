//! capframe-leaderboard CLI — reads a directory of `*.findings.v2.json`
//! files and emits a single `leaderboard.json` consumed by
//! `capframe.ai/leaderboard`.
//!
//! Usage:
//!
//!     capframe-leaderboard build \
//!         --findings ./findings/ \
//!         --out ./leaderboard.json \
//!         [--pretty]

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use time::OffsetDateTime;

#[derive(Parser, Debug)]
#[command(name = "capframe-leaderboard", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Aggregate findings.v2 files in `--findings` into a single
    /// leaderboard JSON at `--out`.
    Build {
        /// Directory of `*.findings.v2.json` files.
        #[arg(long, default_value = "findings/")]
        findings: PathBuf,
        /// Output leaderboard JSON path.
        #[arg(long, default_value = "leaderboard.json")]
        out: PathBuf,
        /// Pretty-print the emitted JSON.
        #[arg(long)]
        pretty: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build {
            findings,
            out,
            pretty,
        } => {
            let board = capframe_leaderboard::build(&findings, OffsetDateTime::now_utc())?;
            let body = capframe_leaderboard::to_json(&board, pretty)?;
            std::fs::write(&out, body)?;
            eprintln!(
                "[leaderboard] {} servers ranked, generated_at={}, written to {}",
                board.total_scanned,
                capframe_leaderboard::fmt_generated_at(&board),
                out.display()
            );
            Ok(())
        }
    }
}
