use anyhow::{anyhow, bail, Context, Result};
use clap::Args as ClapArgs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::modules::Module;

#[derive(ClapArgs, Debug)]
#[command(about = "Install Capframe modules locally with sha256 verification")]
pub struct Args {
    /// Modules to install. Empty = all three.
    #[arg(value_enum)]
    pub modules: Vec<ModuleArg>,

    /// Pin to a release tag (e.g. v0.3.1). Default = latest.
    #[arg(long)]
    pub version: Option<String>,

    /// Install root (default: ~/.capframe)
    #[arg(long, env = "CAPFRAME_INSTALL")]
    pub install_dir: Option<PathBuf>,

    /// Skip if the binary is already present in the install dir
    #[arg(long)]
    pub skip_existing: bool,

    /// Force reinstall even if cached
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum ModuleArg {
    Find,
    Bind,
    Guard,
}

impl ModuleArg {
    fn module(self) -> Module {
        match self {
            ModuleArg::Find => Module::Find,
            ModuleArg::Bind => Module::Bind,
            ModuleArg::Guard => Module::Guard,
        }
    }
}

#[derive(Debug)]
enum Source {
    GithubRelease {
        owner: &'static str,
        repo: &'static str,
    },
}

fn source_for(m: Module) -> Source {
    match m {
        Module::Find => Source::GithubRelease {
            owner: "euanmcrosson-dotcom",
            repo: "mcp-recon",
        },
        Module::Bind => Source::GithubRelease {
            owner: "euanmcrosson-dotcom",
            repo: "capnagent",
        },
        Module::Guard => Source::GithubRelease {
            owner: "euanmcrosson-dotcom",
            repo: "mcp-guard",
        },
    }
}

pub fn run(args: Args) -> Result<()> {
    let modules: Vec<Module> = if args.modules.is_empty() {
        vec![Module::Find, Module::Bind, Module::Guard]
    } else {
        args.modules.iter().map(|m| m.module()).collect()
    };

    let root = args.install_dir.unwrap_or_else(default_install_dir);
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("create install dir: {}", bin_dir.display()))?;

    let mut state = State::load(&root).unwrap_or_default();
    let mut failures: Vec<&'static str> = Vec::new();

    for m in modules {
        let label = m.underlying_binary();
        println!("→ {label}");
        match install_one(
            m,
            &source_for(m),
            args.version.as_deref(),
            &bin_dir,
            &mut state,
            args.force,
            args.skip_existing,
        ) {
            Ok(InstallOutcome::Installed { version }) => println!("  ✓ {label} {version}"),
            Ok(InstallOutcome::Skipped) => println!("  · {label} already present (skipped)"),
            Err(e) => {
                eprintln!("  ✗ {label}: {e:#}");
                failures.push(label);
            }
        }
    }

    state.save(&root)?;

    if !failures.is_empty() {
        bail!("{} module(s) failed: {:?}", failures.len(), failures);
    }
    println!("\nVerify with: capframe doctor");
    println!("Add to PATH: {}", bin_dir.display());
    Ok(())
}

enum InstallOutcome {
    Installed { version: String },
    Skipped,
}

fn install_one(
    m: Module,
    src: &Source,
    version_pin: Option<&str>,
    bin_dir: &Path,
    state: &mut State,
    force: bool,
    skip_existing: bool,
) -> Result<InstallOutcome> {
    let binary = m.underlying_binary();
    let bin_filename = with_exe_suffix(binary);

    let target_path = bin_dir.join(&bin_filename);
    if skip_existing && !force && target_path.exists() {
        return Ok(InstallOutcome::Skipped);
    }

    match src {
        Source::GithubRelease { owner, repo } => {
            let version = match version_pin {
                Some(v) => v.to_string(),
                None => resolve_latest_tag(owner, repo)
                    .with_context(|| format!("resolve latest tag for {owner}/{repo}"))?,
            };

            let target = host_triple()?;
            let (archive_name, ext) = archive_name(binary, &version, &target);
            let base = format!("https://github.com/{owner}/{repo}/releases/download/{version}");
            let archive_url = format!("{base}/{archive_name}");
            let sha_url = format!("{archive_url}.sha256");

            let tmp = make_tempdir(bin_dir.parent().unwrap_or(bin_dir))?;
            let cleanup = TempGuard(tmp.clone());

            let archive_path = tmp.join(&archive_name);
            download(&archive_url, &archive_path)
                .with_context(|| format!("download {archive_url}"))?;
            let expected = parse_sha256_line(&download_to_string(&sha_url)?)?;
            let actual = sha256_file(&archive_path)?;
            if !actual.eq_ignore_ascii_case(&expected) {
                bail!("sha256 mismatch (expected {expected}, got {actual})");
            }

            extract(&archive_path, &tmp, ext)?;

            let from = find_binary(&tmp, &bin_filename)
                .with_context(|| format!("locate {bin_filename} inside {archive_name}"))?;
            fs::copy(&from, &target_path)
                .with_context(|| format!("install {}", target_path.display()))?;
            make_executable(&target_path)?;

            drop(cleanup);

            state.modules.insert(
                binary.to_string(),
                ModuleState {
                    version: version.clone(),
                    sha256: actual,
                },
            );
            Ok(InstallOutcome::Installed { version })
        }
    }
}

fn default_install_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".capframe"))
        .unwrap_or_else(|| PathBuf::from(".capframe"))
}

fn host_triple() -> Result<String> {
    let arch_tag = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => bail!("unsupported arch: {other}"),
    };
    let os_tag = match std::env::consts::OS {
        "linux" => "unknown-linux-gnu",
        "macos" => "apple-darwin",
        "windows" => "pc-windows-msvc",
        other => bail!("unsupported os: {other}"),
    };
    Ok(format!("{arch_tag}-{os_tag}"))
}

fn archive_name(binary: &str, version: &str, target: &str) -> (String, &'static str) {
    let ext = if cfg!(windows) { "zip" } else { "tar.gz" };
    (format!("{binary}-{version}-{target}.{ext}"), ext)
}

fn with_exe_suffix(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn resolve_latest_tag(owner: &str, repo: &str) -> Result<String> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
    let body = ureq::get(&url)
        .set("User-Agent", "capframe-install")
        .set("Accept", "application/vnd.github+json")
        .call()
        .with_context(|| format!("GET {url}"))?
        .into_string()?;
    let v: serde_json::Value = serde_json::from_str(&body)?;
    v["tag_name"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("no tag_name in release response"))
}

fn download(url: &str, to: &Path) -> Result<()> {
    let resp = ureq::get(url)
        .set("User-Agent", "capframe-install")
        .call()
        .with_context(|| format!("GET {url}"))?;
    let mut reader = resp.into_reader();
    let mut out = fs::File::create(to)?;
    std::io::copy(&mut reader, &mut out)?;
    Ok(())
}

fn download_to_string(url: &str) -> Result<String> {
    Ok(ureq::get(url)
        .set("User-Agent", "capframe-install")
        .call()?
        .into_string()?)
}

fn parse_sha256_line(body: &str) -> Result<String> {
    let first = body
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty sha256 file"))?;
    let token = first
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("malformed sha256 line"))?;
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("expected 64-hex sha256, got `{token}`");
    }
    Ok(token.to_string())
}

fn sha256_file(p: &Path) -> Result<String> {
    let mut f = fs::File::open(p).with_context(|| format!("open {}", p.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn extract(archive: &Path, into: &Path, _ext: &str) -> Result<()> {
    // System `tar` extracts both .tar.gz and .zip on Linux/macOS/Windows-10+.
    let status = Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .status()
        .with_context(|| format!("spawn tar to extract {}", archive.display()))?;
    if !status.success() {
        bail!("tar exited with {status} extracting {}", archive.display());
    }
    Ok(())
}

fn find_binary(root: &Path, name: &str) -> Result<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|s| s.to_str()) == Some(name) {
                return Ok(path);
            }
        }
    }
    bail!("not found: {name} under {}", root.display())
}

fn make_tempdir(parent: &Path) -> Result<PathBuf> {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = parent.join(format!(".capframe-install-{pid}-{nanos}"));
    fs::create_dir_all(&path)?;
    Ok(path)
}

struct TempGuard(PathBuf);
impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn make_executable(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(p)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(p, perms)?;
    Ok(())
}
#[cfg(not(unix))]
fn make_executable(_p: &Path) -> Result<()> {
    Ok(())
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub modules: BTreeMap<String, ModuleState>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleState {
    pub version: String,
    pub sha256: String,
}

impl State {
    fn path(root: &Path) -> PathBuf {
        root.join("state.json")
    }
    pub fn load(root: &Path) -> Result<Self> {
        let p = Self::path(root);
        if !p.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_str(&fs::read_to_string(&p)?).unwrap_or_default())
    }
    pub fn save(&self, root: &Path) -> Result<()> {
        let p = Self::path(root);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&p, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}
