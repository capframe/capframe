use anyhow::{anyhow, bail, Context, Result};
use capframe_findings::{Findings, Severity};
use clap::Args as ClapArgs;
use maud::{html, Markup, PreEscaped, DOCTYPE};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

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

    /// External tool to use for PDF rendering. Auto-detects if unset.
    /// Supported: `weasyprint`, `chromium`, `chrome`.
    #[arg(long)]
    pub pdf_tool: Option<String>,
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
        Format::Json => {
            fs::write(&args.out, serde_json::to_vec_pretty(&findings)?)?;
        }
        Format::Html => {
            fs::write(&args.out, render_html(&findings).into_string())?;
        }
        Format::Pdf => {
            render_pdf(&findings, &args.out, args.pdf_tool.as_deref())?;
        }
    }
    tracing::info!(out = %args.out.display(), "report written");
    Ok(())
}

fn render_pdf(findings: &Findings, out: &Path, requested: Option<&str>) -> Result<()> {
    let tmp_html = tempfile_path(out, "html")?;
    fs::write(&tmp_html, render_html(findings).into_string())?;

    let tool = match requested {
        Some(t) => t.to_string(),
        None => detect_pdf_tool().ok_or_else(|| {
            anyhow!(
                "no PDF tool found on PATH (tried: weasyprint, chromium, chrome).\n\
                 Install one, or pass --pdf-tool, or use --format html."
            )
        })?,
    };

    let status = match tool.as_str() {
        "weasyprint" => Command::new("weasyprint").arg(&tmp_html).arg(out).status(),
        "chromium" | "chrome" => Command::new(&tool)
            .args([
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                &format!("--print-to-pdf={}", out.display()),
            ])
            .arg(format!("file://{}", tmp_html.display()))
            .status(),
        other => bail!("unknown --pdf-tool `{other}`"),
    }
    .with_context(|| format!("spawn {tool}"))?;

    let _ = fs::remove_file(&tmp_html);
    if !status.success() {
        bail!("{tool} exited {status} writing {}", out.display());
    }
    Ok(())
}

fn detect_pdf_tool() -> Option<String> {
    for cand in ["weasyprint", "chromium", "chrome"] {
        if which::which(cand).is_ok() {
            return Some(cand.to_string());
        }
    }
    None
}

fn tempfile_path(near: &Path, ext: &str) -> Result<PathBuf> {
    let parent = near.parent().unwrap_or_else(|| Path::new("."));
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(parent.join(format!(".capframe-report-{stamp}.{ext}")))
}

fn render_html(f: &Findings) -> Markup {
    let scan_id = f.scan_id.as_deref().unwrap_or("(none)");
    let scanned_at = f
        .scanned_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into());

    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Capframe Report — " (scan_id) }
                style { (PreEscaped(CSS)) }
            }
            body {
                header.report-header {
                    h1 { "Capframe Findings Report" }
                    p.meta {
                        "Scan " code { (scan_id) } " · " (scanned_at)
                        " · scanner " code { (f.scanner.name) " " (f.scanner.version) }
                    }
                }

                section {
                    h2 { "Summary" }
                    div.summary-grid {
                        (sev_card("Critical", f.summary.by_severity.critical, "crit"))
                        (sev_card("High",     f.summary.by_severity.high,     "high"))
                        (sev_card("Medium",   f.summary.by_severity.medium,   "med"))
                        (sev_card("Low",      f.summary.by_severity.low,      "low"))
                        (sev_card("Info",     f.summary.by_severity.info,     "info"))
                    }
                    p { "Total findings: " strong { (f.summary.total) } }
                }

                @if !f.summary.mappings.is_empty() {
                    section {
                        h2 { "Compliance mappings (aggregate)" }
                        (mapping_table(&f.summary.mappings))
                    }
                }

                section {
                    h2 { "Target" }
                    table.kv {
                        tr { th { "Kind" }      td { code { (format!("{:?}", f.target.kind)) } } }
                        @if let Some(n) = &f.target.name { tr { th { "Name" }     td { (n) } } }
                        @if let Some(u) = &f.target.url  { tr { th { "URL" }      td { code { (u) } } } }
                        @if let Some(p) = &f.target.path { tr { th { "Path" }     td { code { (p) } } } }
                        @if let Some(t) = &f.target.transport { tr { th { "Transport" } td { code { (format!("{:?}", t)) } } } }
                    }
                }

                @if !f.tools.is_empty() {
                    section {
                        h2 { "Tool surface (" (f.tools.len()) ")" }
                        table.tools {
                            thead { tr {
                                th { "Tool" }
                                th { "Side effects" }
                                th { "Auth" }
                                th { "Description" }
                            } }
                            tbody {
                                @for t in &f.tools {
                                    tr {
                                        td { code { (t.name) } }
                                        td {
                                            @for s in &t.side_effects {
                                                span.chip { (format!("{:?}", s).to_lowercase()) }
                                            }
                                        }
                                        td { (yes_no(t.auth_required)) }
                                        td.desc { (t.description.clone().unwrap_or_default()) }
                                    }
                                }
                            }
                        }
                    }
                }

                section {
                    h2 { "Findings (" (f.findings.len()) ")" }
                    @if f.findings.is_empty() {
                        p.empty { "No findings produced." }
                    } @else {
                        @for finding in &f.findings {
                            article.finding {
                                header {
                                    span class=(format!("sev sev-{}", sev_class(&finding.severity))) {
                                        (format!("{:?}", finding.severity).to_uppercase())
                                    }
                                    h3 { (finding.title) }
                                    p.id { "ID: " code { (finding.id) } " · category: " code { (format!("{:?}", finding.category)) } }
                                }
                                @if let Some(d) = &finding.description {
                                    p.desc { (d) }
                                }
                                @if let Some(t) = &finding.tool {
                                    p.tool { "Tool: " code { (t) } }
                                }
                                @if let Some(r) = &finding.remediation {
                                    p.remed { strong { "Remediation: " } (r) }
                                }
                                @if !finding.mappings.is_empty() {
                                    (mapping_table(&finding.mappings))
                                }
                            }
                        }
                    }
                }

                footer.report-footer {
                    p { "Generated by capframe report · "
                        a href="https://capframe.ai" { "capframe.ai" } }
                }
            }
        }
    }
}

fn sev_class(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn sev_card(label: &str, n: u32, class: &str) -> Markup {
    html! {
        div class=(format!("sev-card sev-{}", class)) {
            div.label { (label) }
            div.count { (n) }
        }
    }
}

fn yes_no(b: Option<bool>) -> &'static str {
    match b {
        Some(true) => "yes",
        Some(false) => "no",
        None => "—",
    }
}

fn mapping_table(m: &capframe_findings::Mappings) -> Markup {
    html! {
        table.mappings {
            @if !m.owasp_llm.is_empty() {
                tr { th { "OWASP LLM" } td {
                    @for id in &m.owasp_llm { span.chip { (id) } }
                } }
            }
            @if !m.nist_rmf.is_empty() {
                tr { th { "NIST AI RMF" } td {
                    @for id in &m.nist_rmf { span.chip { (id) } }
                } }
            }
            @if !m.mitre_atlas.is_empty() {
                tr { th { "MITRE ATLAS" } td {
                    @for id in &m.mitre_atlas { span.chip { (id) } }
                } }
            }
        }
    }
}

const CSS: &str = r#"
:root {
    --bg: #fafafa; --fg: #111; --muted: #555; --border: #e0e0e0;
    --crit: #b00020; --high: #d2691e; --med: #b8860b; --low: #4a7d3a; --info: #5577aa;
    --code-bg: #f3f3f3;
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--fg); margin: 0; padding: 32px; max-width: 960px; margin-inline: auto; line-height: 1.45; }
h1 { font-size: 26px; margin: 0 0 6px; }
h2 { font-size: 18px; margin: 28px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
h3 { font-size: 15px; margin: 6px 0 4px; font-weight: 600; }
code { background: var(--code-bg); padding: 1px 5px; border-radius: 3px; font-size: 90%; }
.meta { color: var(--muted); font-size: 13px; margin: 0; }
.report-header { margin-bottom: 18px; }
.summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 12px 0; }
.sev-card { background: white; border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; text-align: center; }
.sev-card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
.sev-card .count { font-size: 22px; font-weight: 700; margin-top: 4px; }
.sev-card.sev-crit  .count { color: var(--crit); }
.sev-card.sev-high  .count { color: var(--high); }
.sev-card.sev-med   .count { color: var(--med); }
.sev-card.sev-low   .count { color: var(--low); }
.sev-card.sev-info  .count { color: var(--info); }
table { border-collapse: collapse; width: 100%; margin: 8px 0; background: white; }
th, td { border: 1px solid var(--border); padding: 6px 10px; text-align: left; font-size: 13px; vertical-align: top; }
th { background: #f5f5f5; font-weight: 600; }
.kv th { width: 120px; }
.tools .desc { color: var(--muted); }
.mappings th { width: 120px; }
.chip { display: inline-block; padding: 2px 8px; margin: 0 4px 4px 0; border: 1px solid var(--border); border-radius: 999px; background: white; font-size: 11px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.finding { background: white; border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; margin: 12px 0; }
.finding header { display: grid; grid-template-columns: 80px 1fr; gap: 10px; align-items: start; }
.finding .id { color: var(--muted); font-size: 12px; grid-column: 1 / -1; margin: 6px 0 0; }
.finding .desc, .finding .remed, .finding .tool { margin: 8px 0; font-size: 13px; }
.sev { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 700; color: white; text-align: center; }
.sev-crit  { background: var(--crit); }
.sev-high  { background: var(--high); }
.sev-med   { background: var(--med); }
.sev-low   { background: var(--low); }
.sev-info  { background: var(--info); }
.empty { color: var(--muted); font-style: italic; }
.report-footer { margin-top: 32px; color: var(--muted); font-size: 12px; text-align: center; border-top: 1px solid var(--border); padding-top: 12px; }
@media print { body { padding: 16px; } .finding, .sev-card, table { break-inside: avoid; } }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_example_payload() {
        let body = include_str!("../../../../schemas/findings.example.json");
        let f: Findings = serde_json::from_str(body).unwrap();
        let html = render_html(&f).into_string();
        assert!(html.contains("Capframe Findings Report"));
        assert!(html.contains("order.refund"));
        assert!(html.contains("LLM08"));
    }
}
