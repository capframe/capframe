//! Aggregate findings.v2 documents into a ranked leaderboard JSON.
//!
//! Input: a directory of `*.findings.v2.json` files produced by
//! `mcp-recon producer registry` (or any other producer that emits the
//! v2 envelope).
//!
//! Output: a single `leaderboard.json` document — one row per server,
//! sorted by score descending, suitable for static serving at
//! `capframe.ai/leaderboard.json` and for hydration by the Next.js
//! `/leaderboard` page.
//!
//! Score formula (public, tunable, defensible):
//!
//! ```text
//! score = 100 - (10*crit + 4*high + 2*med + 1*low), clamped [0, 100]
//! ```
//!
//! A perfect server with zero findings scores 100. Anything with a
//! single Critical finding starts at 90 and falls from there.

use anyhow::{anyhow, Context, Result};
use capframe_findings::v2::{FindingsV2, ServerSource};
use capframe_findings::SeverityCounts;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const LEADERBOARD_SCHEMA_VERSION: &str = "capframe.leaderboard.v1";

/// The score weights are documented at the schema level so consumers
/// know how the score is computed without reading source.
pub const WEIGHT_CRITICAL: u32 = 10;
pub const WEIGHT_HIGH: u32 = 4;
pub const WEIGHT_MEDIUM: u32 = 2;
pub const WEIGHT_LOW: u32 = 1;
pub const SCORE_MAX: u32 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leaderboard {
    pub schema_version: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub total_scanned: usize,
    pub weights: Weights,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Weights {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub score_max: u32,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            critical: WEIGHT_CRITICAL,
            high: WEIGHT_HIGH,
            medium: WEIGHT_MEDIUM,
            low: WEIGHT_LOW,
            score_max: SCORE_MAX,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    /// Score in [0, 100]. Higher is safer.
    pub score: u32,
    /// `<registry>:<name>@<version>`.
    pub handle: String,
    pub source: ServerSource,
    /// Human-readable name if the producer recorded one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// GitHub/GitLab URL if the producer recorded one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,
    /// Per-severity finding counts.
    pub counts: SeverityCounts,
    /// Last scan timestamp from the source findings.v2 document.
    #[serde(with = "time::serde::rfc3339")]
    pub last_scanned: OffsetDateTime,
}

/// Compute score from severity counts using the public formula.
pub fn score_from_counts(counts: &SeverityCounts) -> u32 {
    let penalty = WEIGHT_CRITICAL * counts.critical
        + WEIGHT_HIGH * counts.high
        + WEIGHT_MEDIUM * counts.medium
        + WEIGHT_LOW * counts.low;
    SCORE_MAX.saturating_sub(penalty).min(SCORE_MAX)
}

/// Convert one v2 document into a leaderboard row.
fn row_from(doc: FindingsV2) -> Row {
    let counts = doc.summary.by_severity.clone();
    let score = score_from_counts(&counts);
    Row {
        score,
        handle: doc.server.handle,
        source: doc.server.source,
        name: doc.server.name,
        repo_url: doc.server.repo_url,
        counts,
        last_scanned: doc.scanned_at,
    }
}

/// Read every `*.findings.v2.json` file in `dir` (non-recursive), parse,
/// score, and return them as a Leaderboard sorted by score descending.
///
/// Files that fail to parse are logged via `tracing::warn` and skipped —
/// one malformed file doesn't tank the whole leaderboard.
pub fn build(dir: &Path, now: OffsetDateTime) -> Result<Leaderboard> {
    let entries = fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))?;
    let mut rows: Vec<Row> = Vec::new();
    let mut bad = 0_usize;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.ends_with(".findings.v2.json") {
            continue;
        }
        match parse_one(&path) {
            Ok(doc) => rows.push(row_from(doc)),
            Err(err) => {
                tracing::warn!(
                    file = %path.display(),
                    error = ?err,
                    "skipping malformed findings document",
                );
                bad += 1;
            }
        }
    }
    if rows.is_empty() && bad == 0 {
        return Err(anyhow!("no *.findings.v2.json files in {}", dir.display()));
    }
    rows.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.handle.cmp(&b.handle)));
    Ok(Leaderboard {
        schema_version: LEADERBOARD_SCHEMA_VERSION.to_string(),
        generated_at: now,
        total_scanned: rows.len(),
        weights: Weights::default(),
        rows,
    })
}

fn parse_one(path: &Path) -> Result<FindingsV2> {
    let body = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let doc: FindingsV2 =
        serde_json::from_str(&body).with_context(|| format!("parse {}", path.display()))?;
    if doc.schema_version != "capframe.findings.v2" {
        return Err(anyhow!(
            "{}: unexpected schema_version `{}` (want capframe.findings.v2)",
            path.display(),
            doc.schema_version,
        ));
    }
    Ok(doc)
}

/// Serialize a Leaderboard to a JSON string. Wraps serde_json to keep
/// callers from reaching for the dep directly.
pub fn to_json(board: &Leaderboard, pretty: bool) -> Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(board)?)
    } else {
        Ok(serde_json::to_string(board)?)
    }
}

/// Format a leaderboard's generated_at as an RFC 3339 string. Used by
/// the binary's stdout summary.
pub fn fmt_generated_at(board: &Leaderboard) -> String {
    board
        .generated_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| "<unformattable>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(critical: u32, high: u32, medium: u32, low: u32, info: u32) -> SeverityCounts {
        SeverityCounts {
            critical,
            high,
            medium,
            low,
            info,
        }
    }

    #[test]
    fn perfect_server_scores_100() {
        assert_eq!(score_from_counts(&counts(0, 0, 0, 0, 0)), 100);
    }

    #[test]
    fn one_critical_drops_to_90() {
        assert_eq!(score_from_counts(&counts(1, 0, 0, 0, 0)), 90);
    }

    #[test]
    fn ten_criticals_clamp_at_zero() {
        assert_eq!(score_from_counts(&counts(10, 0, 0, 0, 0)), 0);
        assert_eq!(score_from_counts(&counts(20, 5, 5, 5, 0)), 0);
    }

    #[test]
    fn info_does_not_affect_score() {
        assert_eq!(score_from_counts(&counts(0, 0, 0, 0, 99)), 100);
    }

    #[test]
    fn mixed_severities_sum_correctly() {
        // 1*10 + 2*4 + 3*2 + 4*1 = 28 -> score 72
        assert_eq!(score_from_counts(&counts(1, 2, 3, 4, 0)), 72);
    }
}
