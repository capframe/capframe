use anyhow::{Context, Result};
use capframe_findings::Findings;
use clap::Args as ClapArgs;
use std::{fs, path::PathBuf};

#[derive(ClapArgs, Debug)]
#[command(about = "Produce an audit-ready compliance report")]
pub struct Args {
    /// Findings file to read
    #[arg(short, long, default_value = "capframe.findings.json")]
    pub findings: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Html)]
    pub format: Format,

    /// Output path
    #[arg(short, long)]
    pub out: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Format {
    Html,
    Pdf,
    Json,
}

pub fn run(args: Args) -> Result<()> {
    let body = fs::read_to_string(&args.findings)
        .with_context(|| format!("read findings: {}", args.findings.display()))?;
    let findings: Findings = serde_json::from_str(&body).context("parse findings v1")?;

    match args.format {
        Format::Json => fs::write(&args.out, serde_json::to_vec_pretty(&findings)?)?,
        Format::Html => {
            let html = render_html(&findings);
            fs::write(&args.out, html)?;
        }
        Format::Pdf => {
            anyhow::bail!(
                "PDF rendering not yet implemented — use --format html and print to PDF for now"
            );
        }
    }
    tracing::info!(out = %args.out.display(), "report written");
    Ok(())
}

fn render_html(f: &Findings) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Capframe Report</title>\
         <h1>Capframe Findings Report</h1>\
         <p>Scan: {scan_id}</p>\
         <p>Total findings: {total}</p>\
         <pre>{json}</pre>",
        scan_id = f.scan_id.as_deref().unwrap_or("(none)"),
        total = f.summary.total,
        json = serde_json::to_string_pretty(f).unwrap_or_default(),
    )
}
