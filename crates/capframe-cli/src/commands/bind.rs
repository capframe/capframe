use anyhow::{bail, Result};
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

    /// Repeatable constraint passed through to the bind module.
    /// Format: `key=value` (e.g. `--limit max_refund=50` `--limit region=eu`)
    #[arg(long = "limit", value_parser = parse_limit, num_args = 0..)]
    pub limits: Vec<(String, String)>,

    /// Token TTL, e.g. 24h, 7d
    #[arg(long, default_value = "24h")]
    pub ttl: String,
}

fn parse_limit(raw: &str) -> Result<(String, String), String> {
    let (k, v) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected key=value, got `{raw}`"))?;
    let k = k.trim();
    let v = v.trim();
    if k.is_empty() || v.is_empty() {
        return Err(format!("blank key or value in `{raw}`"));
    }
    if !k
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return Err(format!("limit key must be [A-Za-z0-9_.], got `{k}`"));
    }
    Ok((k.to_string(), v.to_string()))
}

pub fn run(args: Args) -> Result<()> {
    if args.agent.trim().is_empty() {
        bail!("--agent must not be empty");
    }
    let mut raw = vec![
        "--agent".into(),
        args.agent,
        "--tools".into(),
        args.tools,
        "--ttl".into(),
        args.ttl,
    ];
    for (k, v) in args.limits {
        raw.push("--limit".into());
        raw.push(format!("{k}={v}"));
    }
    dispatch(Module::Bind, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_round_trips() {
        let (k, v) = parse_limit("max_refund=50.00").unwrap();
        assert_eq!(k, "max_refund");
        assert_eq!(v, "50.00");
    }

    #[test]
    fn rejects_missing_value() {
        assert!(parse_limit("max_refund=").is_err());
    }

    #[test]
    fn rejects_bad_chars() {
        assert!(parse_limit("hello world=1").is_err());
    }
}
