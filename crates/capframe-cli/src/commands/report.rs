use anyhow::{anyhow, bail, Context, Result};
use capframe_findings::v2::{from_v1, FindingsV2, Server, ServerSource, SCHEMA_VERSION_V2};
use capframe_findings::{
    CastCategory, Category, Finding, Mappings, Severity, SeverityCounts, TargetKind, Transport,
    SCHEMA_VERSION,
};
use clap::Args as ClapArgs;
use maud::{html, Markup, PreEscaped, DOCTYPE};
use std::collections::BTreeMap;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(ClapArgs, Debug)]
#[command(about = "Produce an audit-ready compliance report")]
pub struct Args {
    /// Findings file to read (findings.v1 or findings.v2)
    #[arg(short, long, default_value = "capframe.findings.json")]
    pub findings: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Html)]
    pub format: Format,

    /// Output path
    #[arg(short, long)]
    pub out: PathBuf,

    /// External tool to use for PDF rendering. Auto-detects if unset.
    /// Supported: `weasyprint`, `chromium`, `chrome`, `edge` (Microsoft Edge).
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
    let doc = load(&body)?;

    match args.format {
        Format::Json => {
            // Schema-agnostic passthrough: pretty-print whatever was read.
            let value: serde_json::Value = serde_json::from_str(&body).context("parse findings")?;
            fs::write(&args.out, serde_json::to_vec_pretty(&value)?)?;
        }
        Format::Html => {
            fs::write(&args.out, render_html(&doc).into_string())?;
        }
        Format::Pdf => {
            render_pdf(&doc, &args.out, args.pdf_tool.as_deref())?;
        }
    }
    tracing::info!(out = %args.out.display(), "report written");
    Ok(())
}

/// Read a findings document in either wire version and normalize to v2 (the
/// richer envelope the renderer targets). v1 is migrated via `from_v1`; an
/// unrecognized `schema_version` is refused rather than mislabeled.
fn load(body: &str) -> Result<FindingsV2> {
    let value: serde_json::Value = serde_json::from_str(body).context("parse findings json")?;
    let ver = value
        .get("schema_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if ver == SCHEMA_VERSION_V2 {
        serde_json::from_str(body).context("parse findings v2")
    } else if ver == SCHEMA_VERSION {
        let v1: capframe_findings::Findings =
            serde_json::from_str(body).context("parse findings v1")?;
        // v1 had no `source`/`handle`; synthesize from the thin target.
        let source = if v1.target.url.is_some() {
            ServerSource::Http
        } else {
            ServerSource::File
        };
        let handle = v1
            .target
            .url
            .clone()
            .or_else(|| v1.target.name.clone())
            .unwrap_or_else(|| "local".to_string());
        Ok(from_v1(v1, source, handle))
    } else {
        bail!(
            "unexpected schema_version `{}` (want {} or {})",
            ver,
            SCHEMA_VERSION,
            SCHEMA_VERSION_V2
        )
    }
}

// ----------------------------------------------------------------------------
// scoring + presentation helpers
// ----------------------------------------------------------------------------

/// Same weighting the public leaderboard uses: clean surface starts at 100,
/// each finding deducts by severity. Clamped to 0.
fn score(c: &SeverityCounts) -> u32 {
    let deduction = 10 * c.critical + 4 * c.high + 2 * c.medium + c.low;
    100u32.saturating_sub(deduction)
}

/// (verdict label, severity CSS variable) for the score band.
fn band(s: u32) -> (&'static str, &'static str) {
    match s {
        90..=u32::MAX => ("Clean", "low"),
        75..=89 => ("Solid", "low"),
        60..=74 => ("Needs work", "med"),
        40..=59 => ("At risk", "high"),
        _ => ("Critical", "crit"),
    }
}

fn sev_var(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn cat_label(c: Category) -> &'static str {
    use Category::*;
    match c {
        IndirectInjection => "Indirect injection",
        ExcessiveAgency => "Excessive agency",
        UnconstrainedInput => "Unconstrained input",
        MissingAuthz => "Missing authorization",
        InsecureOutputHandling => "Insecure output handling",
        SecretExposure => "Secret exposure",
        ToolNamingConflict => "Tool naming conflict",
        Deserialization => "Deserialization",
        SsrfSurface => "SSRF surface",
        FilesystemEgress => "Filesystem egress",
        NetworkEgress => "Network egress",
        UntrustedDependency => "Untrusted dependency",
        Other => "Other",
    }
}

fn cast_label(c: CastCategory) -> &'static str {
    use CastCategory::*;
    match c {
        Cast01 => "CAST-01",
        Cast02 => "CAST-02",
        Cast03 => "CAST-03",
        Cast04 => "CAST-04",
        Cast05 => "CAST-05",
        Cast06 => "CAST-06",
        Cast07 => "CAST-07",
        Cast08 => "CAST-08",
        Cast09 => "CAST-09",
    }
}

fn kind_label(k: TargetKind) -> &'static str {
    use TargetKind::*;
    match k {
        McpServer => "MCP server",
        OpenaiFunction => "OpenAI function",
        AnthropicTool => "Anthropic tool",
        LanggraphNode => "LangGraph node",
        Custom => "Custom",
    }
}

fn transport_label(t: Transport) -> &'static str {
    use Transport::*;
    match t {
        Stdio => "stdio",
        Http => "HTTP",
        Sse => "SSE",
        Websocket => "WebSocket",
    }
}

fn source_label(s: ServerSource) -> &'static str {
    use ServerSource::*;
    match s {
        Registry => "Registry",
        Http => "HTTP (live)",
        Sandbox => "Sandbox",
        File => "File",
    }
}

fn display_name(s: &Server) -> String {
    s.name.clone().unwrap_or_else(|| s.handle.clone())
}

/// One-line headline: counts + the two dominant categories.
fn exec_summary(doc: &FindingsV2) -> String {
    let c = &doc.summary.by_severity;
    let mut parts = Vec::new();
    for (n, label) in [
        (c.critical, "critical"),
        (c.high, "high"),
        (c.medium, "medium"),
        (c.low, "low"),
        (c.info, "info"),
    ] {
        if n > 0 {
            parts.push(format!("{n} {label}"));
        }
    }
    let sev = if parts.is_empty() {
        "no findings".to_string()
    } else {
        parts.join(", ")
    };

    let mut counts: BTreeMap<&'static str, u32> = BTreeMap::new();
    for f in &doc.findings {
        *counts.entry(cat_label(f.category)).or_default() += 1;
    }
    let mut cats: Vec<(&'static str, u32)> = counts.into_iter().collect();
    cats.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let top: Vec<String> = cats.iter().take(2).map(|(k, _)| k.to_lowercase()).collect();
    let cat_line = if top.is_empty() {
        String::new()
    } else {
        format!(" Dominated by {}.", top.join(" and "))
    };

    let total = doc.summary.total;
    format!(
        "{total} finding{} — {sev}.{cat_line}",
        if total == 1 { "" } else { "s" }
    )
}

/// Aggregate mappings across all findings (v2 scans don't populate the
/// summary-level mappings the way v1 did, so derive them).
fn aggregate_mappings(doc: &FindingsV2) -> Mappings {
    let mut m = Mappings::default();
    let push = |dst: &mut Vec<String>, src: &[String]| {
        for id in src {
            if !dst.contains(id) {
                dst.push(id.clone());
            }
        }
    };
    for f in &doc.findings {
        push(&mut m.owasp_llm, &f.mappings.owasp_llm);
        push(&mut m.nist_rmf, &f.mappings.nist_rmf);
        push(&mut m.mitre_atlas, &f.mappings.mitre_atlas);
    }
    m
}

fn map_pills(m: &Mappings) -> Markup {
    html! {
        @if !m.owasp_llm.is_empty() {
            span.mapgroup { span.maplabel { "OWASP" } @for id in &m.owasp_llm { span.pill { (id) } } }
        }
        @if !m.nist_rmf.is_empty() {
            span.mapgroup { span.maplabel { "NIST" } @for id in &m.nist_rmf { span.pill { (id) } } }
        }
        @if !m.mitre_atlas.is_empty() {
            span.mapgroup { span.maplabel { "ATLAS" } @for id in &m.mitre_atlas { span.pill { (id) } } }
        }
    }
}

// ----------------------------------------------------------------------------
// render
// ----------------------------------------------------------------------------

fn render_html(doc: &FindingsV2) -> Markup {
    let name = display_name(&doc.server);
    let s = score(&doc.summary.by_severity);
    let (verdict, bvar) = band(s);

    let ts = doc
        .scanned_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let date = ts.get(0..10).unwrap_or("").to_string();
    let time = ts.get(11..16).unwrap_or("").to_string();

    // score ring geometry
    let r = 54.0_f64;
    let circ = 2.0 * std::f64::consts::PI * r;
    let dash = (s as f64 / 100.0) * circ;
    let ring = format!(
        r##"<svg width="128" height="128" viewBox="0 0 128 128"><circle cx="64" cy="64" r="54" fill="none" stroke="#eceee9" stroke-width="11"/><circle cx="64" cy="64" r="54" fill="none" stroke="var(--{bvar})" stroke-width="11" stroke-linecap="round" stroke-dasharray="{dash:.1} {rest:.1}"/></svg>"##,
        bvar = bvar,
        dash = dash,
        rest = circ - dash,
    );

    let counts = &doc.summary.by_severity;
    let legend: Vec<(u32, Severity)> = vec![
        (counts.critical, Severity::Critical),
        (counts.high, Severity::High),
        (counts.medium, Severity::Medium),
        (counts.low, Severity::Low),
        (counts.info, Severity::Info),
    ];

    // findings ordered by severity, worst first
    let mut findings: Vec<&Finding> = doc.findings.iter().collect();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let agg = aggregate_mappings(doc);
    let has_cov =
        !agg.owasp_llm.is_empty() || !agg.nist_rmf.is_empty() || !agg.mitre_atlas.is_empty();

    let repo_distinct = doc
        .server
        .repo_url
        .as_ref()
        .filter(|u| **u != doc.server.handle)
        .cloned();

    let transport_str = doc.server.transport.map(transport_label).unwrap_or("—");

    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Capframe Assessment — " (name) }
                style { (PreEscaped(font_faces())) (PreEscaped(CSS)) }
            }
            body { div.sheet {
                div.brand { span.mk {} b { "capframe" } span.fbg { "FIND · BIND · GUARD" } }
                div.kicker { "MCP Tool-Surface Security Assessment" }
                h1.title { "Agent-authority audit" br; "of " (name) }
                div.subject {
                    span.nm { (name) }
                    @if let Some(u) = &doc.server.repo_url { span.url { (u) } }
                }
                div.byline {
                    "Prepared by Capframe · " (date) " · " (time) " UTC · scan " span.mono { (doc.scan_id) }
                }

                div.scorecard {
                    div.ring { (PreEscaped(ring)) div.ctr { div.num { (s) } div.den { "/ 100" } } }
                    div {
                        p.exec { (exec_summary(doc)) }
                        div.legend {
                            @for (n, sev) in &legend {
                                div class=(format!("legrow {}", if *n == 0 { "zero" } else { "" })) {
                                    span class=(format!("dot dot-{}", sev_var(*sev))) {}
                                    span.legn { (*n) }
                                    span.legl { (sev_label(*sev)) }
                                }
                            }
                        }
                        span class=(format!("verdict tag-{}", bvar)) { (verdict) }
                    }
                }

                section {
                    h2 { "Scope & target" }
                    div.meta-grid {
                        div.row { span.k { "Target" } span.vv { (name) } }
                        div.row { span.k { "Kind" } span.vv { (kind_label(doc.server.kind)) } }
                        div.row { span.k { "Handle" } span.vv { (doc.server.handle) } }
                        div.row { span.k { "Source" } span.vv { (source_label(doc.server.source)) } }
                        div.row { span.k { "Transport" } span.vv { (transport_str) } }
                        div.row { span.k { "Scanner" } span.vv { (doc.scanner.name) " " (doc.scanner.version) } }
                        @if let Some(repo) = &repo_distinct {
                            div.row { span.k { "Repository" } span.vv { (repo) } }
                        }
                        div.row { span.k { "Findings" } span.vv { (doc.summary.total) } }
                    }
                }

                @if has_cov {
                    section {
                        h2 { "Compliance coverage" }
                        div.cov.maps-inline { (map_pills(&agg)) }
                    }
                }

                @if !findings.is_empty() {
                    section {
                        h2 { "Findings at a glance" }
                        table.index { tbody {
                            @for f in &findings {
                                tr {
                                    td { span class=(format!("tag tag-{}", sev_var(f.severity))) { (sev_label(f.severity)) } }
                                    td.ix-title { (f.title) }
                                    td { @if let Some(t) = &f.tool { code { (t) } } @else { "—" } }
                                }
                            }
                        } }
                    }
                }

                section {
                    h2 { "Findings & remediation" }
                    @if findings.is_empty() {
                        p.empty { "No findings produced — the tool surface is clean against the current rule set." }
                    } @else {
                        @for f in &findings {
                            article class=(format!("finding sev-border-{}", sev_var(f.severity))) {
                                div.f-head {
                                    span class=(format!("tag tag-{}", sev_var(f.severity))) { (sev_label(f.severity)) }
                                    h3 { (f.title) }
                                }
                                div.f-meta {
                                    code { (f.id) }
                                    span.sep { "·" } span.cat { (cat_label(f.category)) }
                                    @if let Some(t) = &f.tool { span.sep { "·" } code { (t) } }
                                }
                                @if let Some(d) = &f.description { p.f-desc { (d) } }
                                @if let Some(rm) = &f.remediation {
                                    div.f-remed { span.rk { "Remediation" } span { (rm) } }
                                }
                                @if !f.mappings.is_empty() { div.f-maps { (map_pills(&f.mappings)) } }
                                @if !f.cast_category.is_empty() {
                                    div.f-cast {
                                        span.castlabel { "CAST" }
                                        @for c in &f.cast_category {
                                            span.pill.cast-pill { (cast_label(*c)) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                footer {
                    span { "capframe.ai · Confidential — prepared for " (name) }
                    span { "Generated by capframe report" }
                }
            } }
        }
    }
}

// ----------------------------------------------------------------------------
// fonts (embedded so the PDF is self-contained — no network at render time)
// ----------------------------------------------------------------------------

fn font_faces() -> String {
    let fonts: [(&str, u32, &[u8]); 6] = [
        (
            "IBM Plex Sans",
            400,
            include_bytes!("../../assets/fonts/ibm-plex-sans-latin-400-normal.woff2"),
        ),
        (
            "IBM Plex Sans",
            500,
            include_bytes!("../../assets/fonts/ibm-plex-sans-latin-500-normal.woff2"),
        ),
        (
            "IBM Plex Sans",
            600,
            include_bytes!("../../assets/fonts/ibm-plex-sans-latin-600-normal.woff2"),
        ),
        (
            "IBM Plex Serif",
            600,
            include_bytes!("../../assets/fonts/ibm-plex-serif-latin-600-normal.woff2"),
        ),
        (
            "IBM Plex Mono",
            400,
            include_bytes!("../../assets/fonts/ibm-plex-mono-latin-400-normal.woff2"),
        ),
        (
            "IBM Plex Mono",
            500,
            include_bytes!("../../assets/fonts/ibm-plex-mono-latin-500-normal.woff2"),
        ),
    ];
    let mut out = String::new();
    for (fam, wt, bytes) in fonts {
        out.push_str(&format!(
            "@font-face{{font-family:'{fam}';font-style:normal;font-weight:{wt};font-display:swap;src:url(data:font/woff2;base64,{}) format('woff2')}}",
            b64(bytes)
        ));
    }
    out
}

/// Standard base64 (no external dependency).
fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for ch in data.chunks(3) {
        let b0 = ch[0] as u32;
        let b1 = *ch.get(1).unwrap_or(&0) as u32;
        let b2 = *ch.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if ch.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if ch.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

// ----------------------------------------------------------------------------
// pdf
// ----------------------------------------------------------------------------

fn render_pdf(doc: &FindingsV2, out: &Path, requested: Option<&str>) -> Result<()> {
    let tmp_html = tempfile_path(out, "html")?;
    write_new(&tmp_html, render_html(doc).into_string().as_bytes())?;

    let tool = match requested {
        Some(t) => normalize_tool(t),
        None => detect_pdf_tool().ok_or_else(|| {
            anyhow!(
                "no PDF tool found (tried: weasyprint, chromium, chrome, Microsoft Edge).\n\
                 Install one, or pass --pdf-tool, or use --format html."
            )
        })?,
    };

    // A throwaway profile dir keeps Chromium/Edge from contending with a
    // running browser's locked default profile (the common headless failure).
    let profile = std::env::temp_dir().join(format!("capframe-pdf-{}", std::process::id()));

    let status = if tool == "weasyprint" {
        Command::new("weasyprint")
            .arg(&tmp_html)
            .arg(out)
            .status()
            .with_context(|| "spawn weasyprint".to_string())?
    } else {
        // chromium family (chromium / chrome / edge / a full path to one).
        Command::new(&tool)
            .args([
                "--headless=new".to_string(),
                "--disable-gpu".to_string(),
                "--no-sandbox".to_string(),
                "--no-pdf-header-footer".to_string(),
                format!("--user-data-dir={}", profile.display()),
                format!("--print-to-pdf={}", out.display()),
            ])
            .arg(file_url(&tmp_html))
            .status()
            .with_context(|| format!("spawn {tool}"))?
    };

    let _ = fs::remove_file(&tmp_html);
    let _ = fs::remove_dir_all(&profile);
    if !status.success() {
        bail!("{tool} exited {status} writing {}", out.display());
    }
    Ok(())
}

/// Map a user-supplied `--pdf-tool` alias to an invocable program. `edge`
/// resolves to the real binary (rarely on PATH on Windows).
fn normalize_tool(t: &str) -> String {
    match t.to_lowercase().as_str() {
        "edge" | "msedge" | "microsoft-edge" => edge_binary().unwrap_or_else(|| t.to_string()),
        _ => t.to_string(),
    }
}

fn edge_binary() -> Option<String> {
    for cand in ["msedge", "microsoft-edge", "microsoft-edge-stable"] {
        if which::which(cand).is_ok() {
            return Some(cand.to_string());
        }
    }
    for p in [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ] {
        if Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

/// Build a `file://` URL for a local path that Chromium can load on every
/// platform. Backslashes become forward slashes and a drive-rooted Windows path
/// (`C:/...`) gets the three-slash `file:///` prefix — `file://C:\...` did not
/// load on Windows, so PDF rendering via Chromium was effectively broken there.
fn file_url(path: &Path) -> String {
    let s = path.display().to_string().replace('\\', "/");
    if s.starts_with('/') {
        format!("file://{s}")
    } else {
        format!("file:///{s}")
    }
}

fn detect_pdf_tool() -> Option<String> {
    for cand in ["weasyprint", "chromium", "chrome", "chromium-browser"] {
        if which::which(cand).is_ok() {
            return Some(cand.to_string());
        }
    }
    edge_binary()
}

fn tempfile_path(near: &Path, ext: &str) -> Result<PathBuf> {
    let parent = near.parent().unwrap_or_else(|| Path::new("."));
    let pid = std::process::id();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(parent.join(format!(".capframe-report-{pid}-{stamp}.{ext}")))
}

/// Write `contents` to `path`, failing if anything already exists there
/// (`O_EXCL`). The temp filename is predictable enough that a pre-planted
/// symlink/file at that path could otherwise redirect the write; exclusive
/// creation refuses to follow or clobber it.
fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create temp file {}", path.display()))?;
    f.write_all(contents)?;
    Ok(())
}

const CSS: &str = r#"
:root{
  --ink:#16181c; --ink2:#5c626b; --ink3:#878d95; --paper:#fff; --bg:#f4f5f2;
  --line:#e7e9e4; --line2:#d7dad3;
  --mint:#00f5a0; --mint-ink:#047857; --mint-deep:#064e3b;
  --crit:#c2143b; --crit-bg:#fdecef; --crit-br:#f3b9c5;
  --high:#cf5a16; --high-bg:#fcf0e7; --high-br:#f1cba9;
  --med:#9a6f08; --med-bg:#faf3df; --med-br:#ead9a4;
  --low:#3f8f4f; --low-bg:#eef6ef; --low-br:#bfe0c4;
  --info:#3f6fb0; --info-bg:#eef2f9; --info-br:#c2d2ec;
}
*{box-sizing:border-box}
html,body{margin:0}
body{font-family:"IBM Plex Sans",system-ui,sans-serif;color:var(--ink);background:var(--bg);font-size:13px;line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.sheet{max-width:820px;margin:0 auto;background:var(--paper);padding:48px 56px 64px}
code,.mono{font-family:"IBM Plex Mono",ui-monospace,monospace}
.brand{display:flex;align-items:center;gap:9px;font-family:"IBM Plex Mono",monospace;font-size:12px;letter-spacing:.02em;color:var(--ink)}
.brand .mk{width:9px;height:9px;border-radius:2px;background:var(--mint);box-shadow:0 0 0 3px rgba(0,245,160,.18)}
.brand b{font-weight:600}
.brand .fbg{color:var(--ink3);letter-spacing:.18em;font-size:10px;margin-left:2px}
.kicker{margin:30px 0 6px;font-family:"IBM Plex Mono",monospace;font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:var(--mint-ink)}
h1.title{font-family:"IBM Plex Serif",Georgia,serif;font-weight:600;font-size:30px;line-height:1.12;letter-spacing:-.01em;margin:0 0 14px}
.subject{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:2px}
.subject .nm{font-size:18px;font-weight:600}
.subject .url{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--ink2)}
.byline{color:var(--ink3);font-size:11.5px;margin-top:3px}
.scorecard{display:grid;grid-template-columns:auto 1fr;gap:30px;align-items:center;margin:26px 0 8px;padding:22px 24px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,#fff,#fcfdfc)}
.ring{position:relative;width:128px;height:128px}
.ring svg{transform:rotate(-90deg)}
.ring .ctr{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .num{font-family:"IBM Plex Serif",serif;font-weight:600;font-size:34px;line-height:1}
.ring .den{font-family:"IBM Plex Mono",monospace;font-size:11px;color:var(--ink3);margin-top:2px}
.verdict{display:inline-block;margin-top:8px;font-family:"IBM Plex Mono",monospace;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;padding:3px 9px;border-radius:999px}
.exec{font-size:14px;line-height:1.55;margin:0 0 16px;font-weight:500}
.legend{display:grid;grid-template-columns:repeat(5,auto);gap:18px;justify-content:start}
.legrow{display:flex;align-items:center;gap:7px}
.legrow.zero{opacity:.38}
.dot{width:9px;height:9px;border-radius:50%}
.dot-crit{background:var(--crit)}.dot-high{background:var(--high)}.dot-med{background:var(--med)}.dot-low{background:var(--low)}.dot-info{background:var(--info)}
.legn{font-family:"IBM Plex Mono",monospace;font-weight:500;font-size:16px}
.legl{font-size:10.5px;color:var(--ink2);text-transform:uppercase;letter-spacing:.04em}
section{margin-top:34px}
h2{font-size:12px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--ink2);margin:0 0 14px;padding-bottom:9px;border-bottom:1px solid var(--line);position:relative}
h2::after{content:"";position:absolute;left:0;bottom:-1px;width:44px;height:2px;background:var(--mint)}
.meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 30px}
.meta-grid .row{display:flex;justify-content:space-between;gap:14px;padding:7px 0;border-bottom:1px solid var(--line)}
.meta-grid .k{color:var(--ink3);font-size:11.5px}
.meta-grid .vv{font-family:"IBM Plex Mono",monospace;font-size:11.5px;text-align:right;word-break:break-all}
.cov{display:flex;flex-wrap:wrap;gap:8px}
.maps-inline .mapgroup,.cov .mapgroup{display:inline-flex;align-items:center;gap:6px;margin:0 14px 4px 0}
.maplabel{font-family:"IBM Plex Mono",monospace;font-size:9.5px;letter-spacing:.1em;color:var(--ink3);text-transform:uppercase;margin-right:1px}
.pill{display:inline-block;font-family:"IBM Plex Mono",monospace;font-size:10.5px;padding:2px 8px;border:1px solid var(--line2);border-radius:6px;background:#fbfbf9;color:var(--ink)}
table.index{width:100%;border-collapse:collapse}
table.index td{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
table.index tr:last-child td{border-bottom:none}
table.index td:first-child{width:78px}
.ix-title{font-weight:500}
table.index code{font-size:11px;color:var(--ink2)}
.finding{border:1px solid var(--line);border-left-width:3px;border-radius:10px;padding:16px 18px;margin:12px 0;background:#fff;break-inside:avoid}
.sev-border-crit{border-left-color:var(--crit)}.sev-border-high{border-left-color:var(--high)}.sev-border-med{border-left-color:var(--med)}.sev-border-low{border-left-color:var(--low)}.sev-border-info{border-left-color:var(--info)}
.f-head{display:flex;align-items:baseline;gap:11px}
.f-head h3{font-size:14.5px;font-weight:600;margin:0;line-height:1.35}
.f-meta{margin:8px 0 10px;font-family:"IBM Plex Mono",monospace;font-size:10.5px;color:var(--ink3)}
.f-meta .cat{color:var(--ink2)}.f-meta .sep{margin:0 7px;color:var(--line2)}
.f-desc{font-size:12.5px;color:#2c2f34;margin:0 0 11px;white-space:pre-wrap;word-break:break-word}
.f-remed{display:grid;grid-template-columns:auto 1fr;gap:10px;align-items:start;background:rgba(0,245,160,.07);border:1px solid rgba(0,245,160,.28);border-radius:8px;padding:9px 12px;font-size:12px;margin-bottom:11px}
.f-remed .rk{font-family:"IBM Plex Mono",monospace;font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--mint-deep);padding-top:2px}
.f-maps{display:flex;flex-wrap:wrap;gap:4px 0;align-items:center}
.tag{display:inline-block;font-family:"IBM Plex Mono",monospace;font-size:9.5px;font-weight:500;letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;border-radius:5px;white-space:nowrap}
.tag-crit{color:var(--crit);background:var(--crit-bg);border:1px solid var(--crit-br)}
.tag-high{color:var(--high);background:var(--high-bg);border:1px solid var(--high-br)}
.tag-med{color:var(--med);background:var(--med-bg);border:1px solid var(--med-br)}
.tag-low{color:var(--low);background:var(--low-bg);border:1px solid var(--low-br)}
.tag-info{color:var(--info);background:var(--info-bg);border:1px solid var(--info-br)}
.verdict.tag-crit,.verdict.tag-high,.verdict.tag-med,.verdict.tag-low,.verdict.tag-info{font-size:10.5px}
.empty{color:var(--ink2);font-style:italic}
footer{margin-top:40px;padding-top:14px;border-top:1px solid var(--line);display:flex;justify-content:space-between;color:var(--ink3);font-family:"IBM Plex Mono",monospace;font-size:10px;letter-spacing:.03em}
@page{size:A4;margin:14mm 0}
@media print{ body{background:#fff} .sheet{max-width:none;margin:0;padding:0 18mm} }
.f-cast{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:6px}
.castlabel{font-family:"IBM Plex Mono",monospace;font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink3);margin-right:2px}
.cast-pill{background:#f0f4ff;border-color:#c2ccee;color:#2c4a8c}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_cast_pills_on_finding() {
        let body = include_str!("../../../../schemas/findings.example.json");
        let mut doc = load(body).expect("load v1 example");
        if let Some(f) = doc.findings.first_mut() {
            f.cast_category = vec![CastCategory::Cast01, CastCategory::Cast03];
        }
        let html = render_html(&doc).into_string();
        assert!(html.contains("CAST-01"), "report must render CAST-01 pill");
        assert!(html.contains("CAST-03"), "report must render CAST-03 pill");
    }

    #[test]
    fn renders_v1_example_payload() {
        // v1 input is migrated to v2 then rendered.
        let body = include_str!("../../../../schemas/findings.example.json");
        let doc = load(body).expect("load v1");
        let html = render_html(&doc).into_string();
        assert!(html.contains("Agent-authority audit"));
        assert!(html.contains("order.refund"));
        assert!(html.contains("LLM08"));
        assert!(html.contains("MCP Tool-Surface Security Assessment"));
        // embedded fonts, not a network @import
        assert!(html.contains("@font-face"));
        assert!(!html.contains("fonts.googleapis.com"));
    }

    #[test]
    fn renders_v2_example_payload() {
        let body = include_str!("../../../../schemas/findings.v2.example.json");
        let doc = load(body).expect("load v2");
        let html = render_html(&doc).into_string();
        assert!(html.contains("Agent-authority audit"));
        assert!(
            html.contains("Findings &amp; remediation") || html.contains("Findings & remediation")
        );
    }

    #[test]
    fn score_matches_leaderboard_weighting() {
        let c = SeverityCounts {
            info: 0,
            low: 0,
            medium: 15,
            high: 3,
            critical: 0,
        };
        // 100 - (4*3 + 2*15) = 100 - 42 = 58  (the real Webzum score)
        assert_eq!(score(&c), 58);
        let clean = SeverityCounts::default();
        assert_eq!(score(&clean), 100);
        // saturating: a wildly bad surface floors at 0, never underflows
        let bad = SeverityCounts {
            critical: 99,
            ..Default::default()
        };
        assert_eq!(score(&bad), 0);
    }

    #[test]
    fn base64_round_trips_known_vector() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let body = r#"{
            "schema_version":"capframe.findings.v999",
            "scanned_at":"2026-05-17T14:32:00Z",
            "scanner":{"name":"x","version":"0.0.0"},
            "target":{"kind":"mcp_server"},
            "summary":{"total":0,"by_severity":{"info":0,"low":0,"medium":0,"high":0,"critical":0}}
        }"#;
        let err = load(body).unwrap_err();
        assert!(
            err.to_string().contains("schema_version"),
            "should reject a wrong schema_version, got: {err}"
        );
    }

    #[test]
    fn file_url_is_well_formed_cross_platform() {
        assert_eq!(
            file_url(&PathBuf::from("/tmp/r.html")),
            "file:///tmp/r.html"
        );
        assert_eq!(
            file_url(&PathBuf::from(r"C:\Users\x\r.html")),
            "file:///C:/Users/x/r.html"
        );
    }

    #[test]
    fn write_new_refuses_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.html");
        assert!(write_new(&p, b"hello").is_ok(), "fresh path should write");
        assert!(
            write_new(&p, b"again").is_err(),
            "existing path must be refused, not clobbered"
        );
    }
}
