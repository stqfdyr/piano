//! Development tasks. Run as `cargo xtask <task>`.
//!
//! - `ci`: format check, clippy with warnings denied, tests, dependency policy.
//! - `dist`: static musl release binary for x86-64-v2 hosts and the release archive
//!   (binary, service files, install script), each with a sha256 file.
//! - `deploy HOST (--release TAG | --local | --rollback) [--instance NAME]`: installs on
//!   HOST over ssh with `contrib/install.sh` and switches a running daemon with
//!   `piano upgrade`. `--release` takes a GitHub release of this repository, checked
//!   against its sha256 and build attestation; `--local` builds with `dist`;
//!   `--rollback` goes back to the binary installed before.

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const DIST_TARGET: &str = "x86_64-unknown-linux-musl";
/// Platform part of release file names.
const DIST_PLATFORM: &str = "x86_64-linux-musl";
/// Oldest production CPU has no AVX2.
const DIST_CPU: &str = "x86-64-v2";

type Result<T = ()> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["ci"] => ci(),
        ["dist"] => dist().map(drop),
        ["deploy", rest @ ..] => parse_deploy(rest).and_then(|d| deploy(&d)),
        _ => {
            eprintln!("usage: cargo xtask <ci|dist|{DEPLOY_USAGE}>");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn cargo() -> Command {
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(root());
    cmd
}

/// Runs `cmd`, echoing it first, and fails on a non-zero exit.
fn run(step: &str, mut cmd: Command) -> Result {
    let shown: Vec<_> = std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(OsStr::to_string_lossy)
        .collect();
    eprintln!("==> {step}: {}", shown.join(" "));
    let start = Instant::now();
    let status = cmd
        .status()
        .map_err(|e| format!("{step}: cannot start: {e}"))?;
    if !status.success() {
        return Err(format!("{step} failed ({status})"));
    }
    eprintln!("    {step} ok in {:.1}s", start.elapsed().as_secs_f64());
    Ok(())
}

/// Upper bound on running the tests, several times what the whole suite takes (about
/// 20 s). A hung test fails the run instead of holding it open.
const TEST_LIMIT: Duration = Duration::from_secs(120);

/// Like [`run`], but kills the command and everything it started once `limit` passes.
fn run_limited(step: &str, cmd: Command, limit: Duration) -> Result {
    run_bounded(step, cmd, limit, None, false).map(drop)
}

/// Runs `cmd` in its own process group with `input` (if any) on stdin, killing the
/// group once `limit` passes. With `capture`, returns what it printed on stdout, which
/// must be little, as it is read only after the command exits; otherwise its output goes
/// straight to ours.
fn run_bounded(
    step: &str,
    mut cmd: Command,
    limit: Duration,
    input: Option<&[u8]>,
    capture: bool,
) -> Result<Vec<u8>> {
    eprintln!("==> {step} (limit {}s)", limit.as_secs());
    let start = Instant::now();
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    if capture {
        cmd.stdout(Stdio::piped());
    }
    // Its own process group, so what it starts goes with it.
    let mut child = cmd
        .process_group(0)
        .spawn()
        .map_err(|e| format!("{step}: cannot start: {e}"))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin
            .write_all(input)
            .map_err(|e| format!("{step}: writing its input: {e}"))?;
    }
    loop {
        if let Some(status) = child.try_wait().map_err(|e| format!("{step}: {e}"))? {
            let mut out = Vec::new();
            if let Some(mut stdout) = child.stdout.take() {
                std::io::Read::read_to_end(&mut stdout, &mut out)
                    .map_err(|e| format!("{step}: reading its output: {e}"))?;
            }
            if !status.success() {
                return Err(format!("{step} failed ({status})"));
            }
            eprintln!("    {step} ok in {:.1}s", start.elapsed().as_secs_f64());
            return Ok(out);
        }
        if start.elapsed() >= limit {
            let group = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
            let _ = child.wait();
            return Err(format!("{step} killed after {}s", limit.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn ci() -> Result {
    let mut fmt = cargo();
    // No --all: that would also reformat the vendored fork.
    fmt.args(["fmt", "--check"]);
    run("fmt", fmt)?;

    let mut clippy = cargo();
    clippy.args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]);
    run("clippy", clippy)?;

    let mut build = cargo();
    build.args(["test", "--workspace", "--locked", "--no-run"]);
    run("build tests", build)?;

    let mut test = cargo();
    // Most tests wait on timeouts and sleeps (a run keeps about a tenth of four cores
    // busy), so many more run at once than there are cores.
    test.args(["test", "--workspace", "--locked", "--", "--test-threads=16"]);
    run_limited("test", test, TEST_LIMIT)?;

    let mut deny = cargo();
    deny.args(["deny", "--locked", "check"]);
    run("deny", deny)
}

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root().join("target"), PathBuf::from)
}

/// Builds the release binary and the release archive into `target/dist`, each with its
/// `.sha256` file; returns the binary's path.
fn dist() -> Result<PathBuf> {
    let mut build = cargo();
    // RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS take precedence over the per-target flags
    // below, which would then be dropped without a word: the CPU level among them.
    for var in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        if std::env::var_os(var).is_some_and(|v| !v.is_empty()) {
            eprintln!("    warning: {var} is set; dist ignores it");
        }
        build.env_remove(var);
    }
    build
        .args([
            "build",
            "--release",
            "--locked",
            "--package",
            "piano",
            "--target",
            DIST_TARGET,
        ])
        .env(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS",
            format!("-C target-cpu={DIST_CPU} -C target-feature=+crt-static"),
        );
    run("build", build)?;

    let target_dir = target_dir();
    let built = target_dir.join(DIST_TARGET).join("release").join("piano");
    let bytes = std::fs::read(&built).map_err(|e| format!("{}: {e}", built.display()))?;
    if has_interpreter(&bytes)? {
        return Err(format!("{} is dynamically linked", built.display()));
    }

    // xtask and piano both take the workspace version, which release.yml checks the tag
    // against.
    let version = env!("CARGO_PKG_VERSION");
    let out_dir = target_dir.join("dist");
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let name = format!("piano-{version}-{DIST_PLATFORM}");
    let out = out_dir.join(&name);
    std::fs::write(&out, &bytes).map_err(|e| format!("{}: {e}", out.display()))?;
    set_executable(&out)?;
    let sum = write_sha256(&out_dir, &name)?;
    let archive = package(&out_dir, &name, &out)?;
    let archive_sum = write_sha256(&out_dir, &archive)?;

    println!("{}", out.display());
    println!(
        "  size   {:.2} MiB ({} bytes)",
        bytes.len() as f64 / 1048576.0,
        bytes.len()
    );
    println!("  static yes ({DIST_TARGET}, target-cpu={DIST_CPU})");
    print!("  sha256 {sum}");
    println!("{}", out_dir.join(&archive).display());
    print!("  sha256 {archive_sum}");
    Ok(out)
}

/// Writes `dir/name.sha256` in `sha256sum` format; returns its line.
fn write_sha256(dir: &Path, name: &str) -> Result<String> {
    let sum = Command::new("sha256sum")
        .arg(name)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("sha256sum: {e}"))?;
    if !sum.status.success() {
        return Err(format!("sha256sum {name} failed"));
    }
    let path = dir.join(format!("{name}.sha256"));
    std::fs::write(&path, &sum.stdout).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(String::from_utf8_lossy(&sum.stdout).into_owned())
}

/// Repository files shipped in the release archive besides the binary and `CONTRIB`.
const ARCHIVED: [&str; 2] = ["LICENSE", "README.md"];

/// Packs `binary` (as `piano`), `CONTRIB` and `ARCHIVED` into `out_dir/name.tar.gz`
/// under the directory `name`, so that `install.sh` finds the binary next to itself;
/// returns the archive's file name. The same tree gives the same bytes: fixed order,
/// owner and times, and no name or time in the gzip header.
fn package(out_dir: &Path, name: &str, binary: &Path) -> Result<String> {
    let io = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let stage = out_dir.join("stage");
    if stage.exists() {
        std::fs::remove_dir_all(&stage).map_err(|e| io(&stage, e))?;
    }
    let dir = stage.join(name);
    std::fs::create_dir_all(&dir).map_err(|e| io(&dir, e))?;
    set_mode(&dir, 0o755)?;
    let contrib = CONTRIB.iter().map(|f| (root().join("contrib").join(f), *f));
    let archived = ARCHIVED.iter().map(|f| (root().join(f), *f));
    for (from, to) in std::iter::once((binary.to_path_buf(), "piano"))
        .chain(contrib)
        .chain(archived)
    {
        let staged = dir.join(to);
        std::fs::copy(&from, &staged).map_err(|e| io(&from, e))?;
        // Modes from the checkout depend on the umask of whoever made it.
        let mode = if matches!(to, "piano" | "install.sh") {
            0o755
        } else {
            0o644
        };
        set_mode(&staged, mode)?;
    }

    let tar_name = format!("{name}.tar");
    let mut tar = Command::new("tar");
    tar.args([
        "--sort=name",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        &format!("--mtime=@{}", source_date()?),
        "-cf",
    ])
    .arg(out_dir.join(&tar_name))
    .arg("-C")
    .arg(&stage)
    .arg(name);
    run("archive", tar)?;
    let mut gzip = Command::new("gzip");
    gzip.args(["-n", "-9", "-f"]).arg(out_dir.join(&tar_name));
    run("compress", gzip)?;
    std::fs::remove_dir_all(&stage).map_err(|e| io(&stage, e))?;
    Ok(format!("{tar_name}.gz"))
}

/// `SOURCE_DATE_EPOCH` if set, else the time of the commit being built. A tree with
/// uncommitted changes gets that commit's time too, with a warning.
fn source_date() -> Result<String> {
    if let Some(t) = std::env::var_os("SOURCE_DATE_EPOCH") {
        return t
            .into_string()
            .map_err(|_| "SOURCE_DATE_EPOCH is not text".into());
    }
    let out = Command::new("git")
        .args(["log", "-1", "--format=%ct"])
        .current_dir(root())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    let t = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if !out.status.success() || t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err("no commit time: set SOURCE_DATE_EPOCH".into());
    }
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(root())
        .output()
        .is_ok_and(|o| !o.stdout.is_empty());
    if dirty {
        eprintln!("    warning: uncommitted changes; the archive is dated as HEAD");
    }
    Ok(t)
}

/// The remote half of `deploy`, run as `sh -s` on the host.
const DEPLOY_SH: &str = include_str!("deploy.sh");
/// Files of `contrib/` that `install.sh` installs next to the binary.
const CONTRIB: [&str; 5] = [
    "install.sh",
    "piano.service",
    "piano.initd",
    "piano.confd",
    "piano.logrotate",
];
/// Fail fast instead of waiting on a host that does not answer.
const SSH_OPTIONS: [&str; 8] = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=10",
    "-o",
    "ServerAliveCountMax=3",
];
/// Copying a release binary of about 10 MiB.
const COPY_LIMIT: Duration = Duration::from_secs(300);
/// Installing and `piano upgrade`, which itself gives up after 120 s.
const REMOTE_LIMIT: Duration = Duration::from_secs(300);
const REMOTE_DIR_PREFIX: &str = "/tmp/piano-deploy.";

/// Downloading a release archive of about 4 MiB.
const DOWNLOAD_LIMIT: Duration = Duration::from_secs(300);
/// `gh attestation verify` fetches the attestation and the signing roots.
const ATTESTATION_LIMIT: Duration = Duration::from_secs(120);
const DEPLOY_USAGE: &str = "deploy HOST (--release TAG | --local | --rollback) [--instance NAME]";

#[derive(Debug, PartialEq, Eq)]
struct Deploy<'a> {
    host: &'a str,
    instance: Option<&'a str>,
    source: Source<'a>,
}

/// Where the binary to install comes from.
#[derive(Debug, PartialEq, Eq)]
enum Source<'a> {
    /// A GitHub release of this repository, by tag.
    Release(&'a str),
    /// Built here with `dist`.
    Local,
    /// The binary installed before the current one.
    Rollback,
}

fn parse_deploy<'a>(args: &[&'a str]) -> Result<Deploy<'a>> {
    let usage = || format!("usage: cargo xtask {DEPLOY_USAGE}");
    let mut host = None;
    let mut instance = None;
    let mut source = None;
    let mut set = |s| match source.replace(s) {
        None => Ok(()),
        Some(_) => Err("give one of --release, --local and --rollback".to_owned()),
    };
    let mut args = args.iter();
    while let Some(&a) = args.next() {
        match a {
            "--rollback" => set(Source::Rollback)?,
            "--local" => set(Source::Local)?,
            "--release" => {
                let tag = *args.next().ok_or_else(usage)?;
                // Passed to gh and used as a directory name.
                let valid = tag.strip_prefix('v').is_some_and(|v| {
                    v.starts_with(|c: char| c.is_ascii_digit())
                        && v.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                });
                if !valid {
                    return Err(format!("release tags look like v0.1.0: {tag}"));
                }
                set(Source::Release(tag))?;
            }
            "--instance" => {
                let name = *args.next().ok_or_else(usage)?;
                let valid = !name.is_empty()
                    && name.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b)
                    });
                if !valid {
                    return Err(format!("instance names use a-z, 0-9, _ and -: {name}"));
                }
                instance = Some(name);
            }
            _ if host.is_none() && !a.starts_with('-') => host = Some(a),
            _ => return Err(usage()),
        }
    }
    let host = host.ok_or_else(usage)?;
    let source = source.ok_or_else(usage)?;
    // Passed to ssh and scp as an argument and shown in commands; keep it plain.
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
    {
        return Err(format!("not a plain host name: {host}"));
    }
    Ok(Deploy {
        host,
        instance,
        source,
    })
}

/// `owner/name` of the GitHub repository `origin` points at.
fn github_repo() -> Result<String> {
    let out = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(root())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    let url = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    parse_github(&url).ok_or_else(|| format!("origin is not a GitHub repository: {url:?}"))
}

fn parse_github(url: &str) -> Option<String> {
    let path = [
        "git@github.com:",
        "ssh://git@github.com/",
        "https://github.com/",
    ]
    .iter()
    .find_map(|p| url.strip_prefix(p))?;
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (owner, name) = path.split_once('/')?;
    let plain = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    (plain(owner) && plain(name)).then(|| format!("{owner}/{name}"))
}

/// Downloads release `tag` into `target/releases/<tag>`, checks its sha256 and its
/// build attestation (made by this repository's release workflow for that tag) and
/// unpacks it; returns the unpacked directory.
fn fetch_release(tag: &str) -> Result<PathBuf> {
    let repo = github_repo()?;
    let version = tag.trim_start_matches('v');
    let name = format!("piano-{version}-{DIST_PLATFORM}");
    let archive = format!("{name}.tar.gz");
    let dir = target_dir().join("releases").join(tag);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let mut download = Command::new("gh");
    download
        .args(["release", "download", tag, "--repo", &repo, "--dir"])
        .arg(&dir)
        .args([
            "--pattern",
            &archive,
            "--pattern",
            &format!("{archive}.sha256"),
        ]);
    run_bounded("download", download, DOWNLOAD_LIMIT, None, false)?;

    let mut check = Command::new("sha256sum");
    check
        .args(["--check", "--quiet", &format!("{archive}.sha256")])
        .current_dir(&dir);
    run("checksum", check)?;

    // The checksum comes from the same place as the archive; the attestation ties the
    // archive to a run of the release workflow of this repository.
    let mut attestation = Command::new("gh");
    attestation
        .args(["attestation", "verify"])
        .arg(dir.join(&archive))
        .args([
            "--repo",
            &repo,
            "--signer-workflow",
            &format!("{repo}/.github/workflows/release.yml"),
            "--source-ref",
            &format!("refs/tags/{tag}"),
        ]);
    run_bounded("attestation", attestation, ATTESTATION_LIMIT, None, false)?;

    let mut unpack = Command::new("tar");
    unpack
        .arg("-xzf")
        .arg(dir.join(&archive))
        .arg("-C")
        .arg(&dir);
    run("unpack", unpack)?;
    Ok(dir.join(name))
}

fn ssh(host: &str) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args(SSH_OPTIONS).arg(host);
    cmd
}

fn deploy(d: &Deploy<'_>) -> Result {
    let contrib = |dir: &Path| -> Vec<PathBuf> { CONTRIB.iter().map(|f| dir.join(f)).collect() };
    let (files, binary) = match d.source {
        Source::Rollback => (contrib(&root().join("contrib")), None),
        Source::Local => {
            let built = dist()?;
            let name = built
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or("dist produced no file name")?
                .to_owned();
            let mut files = contrib(&root().join("contrib"));
            files.push(built.with_file_name(format!("{name}.sha256")));
            files.push(built);
            (files, Some(name))
        }
        Source::Release(tag) => {
            // Everything the release ships, not what this checkout would ship: its
            // service files and install script go with its binary.
            let dir = fetch_release(tag)?;
            write_sha256(&dir, "piano")?;
            let files = std::fs::read_dir(&dir)
                .and_then(|entries| {
                    entries
                        .map(|e| e.map(|e| e.path()))
                        .collect::<std::io::Result<Vec<_>>>()
                })
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            (files, Some("piano".to_owned()))
        }
    };
    let rollback = d.source == Source::Rollback;

    let mut mktemp = ssh(d.host);
    mktemp.args(["mktemp", "-d", &format!("{REMOTE_DIR_PREFIX}XXXXXX")]);
    let out = run_bounded(
        "remote directory",
        mktemp,
        Duration::from_secs(30),
        Some(b""),
        true,
    )?;
    let dir = String::from_utf8_lossy(&out).trim().to_owned();
    let plain = dir.starts_with(REMOTE_DIR_PREFIX)
        && !dir.contains("..")
        && dir
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b));
    if !plain {
        return Err(format!("unexpected remote directory: {dir:?}"));
    }

    let mut scp = Command::new("scp");
    scp.arg("-q")
        .args(SSH_OPTIONS)
        .args(&files)
        .arg(format!("{}:{dir}/", d.host));
    if let Err(e) = run_bounded("copy", scp, COPY_LIMIT, None, false) {
        let mut clean = ssh(d.host);
        clean.args(["rm", "-rf", &dir]);
        let _ = run_bounded("clean up", clean, Duration::from_secs(30), Some(b""), false);
        return Err(e);
    }

    // The script removes the directory itself, whatever happens.
    let mut remote = ssh(d.host);
    remote.args([
        "sh",
        "-s",
        "--",
        if rollback { "rollback" } else { "install" },
        &dir,
        d.instance.unwrap_or("-"),
    ]);
    remote.args(binary.as_deref());
    run_bounded(
        "install",
        remote,
        REMOTE_LIMIT,
        Some(DEPLOY_SH.as_bytes()),
        false,
    )?;
    if !rollback {
        let instance = d
            .instance
            .map(|i| format!(" --instance {i}"))
            .unwrap_or_default();
        println!(
            "to go back: cargo xtask deploy {}{instance} --rollback",
            d.host
        );
    }
    Ok(())
}

fn set_executable(path: &Path) -> Result {
    set_mode(path, 0o755)
}

fn set_mode(path: &Path, mode: u32) -> Result {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Whether an ELF64 little-endian image requests a program interpreter (`PT_INTERP`),
/// i.e. needs a dynamic loader at run time.
fn has_interpreter(elf: &[u8]) -> Result<bool> {
    const PT_INTERP: u32 = 3;
    let bad = || "not an ELF64 little-endian file".to_owned();
    if elf.get(..6) != Some(b"\x7fELF\x02\x01".as_slice()) {
        return Err(bad());
    }
    let u16_at = |o: usize| elf.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| {
        elf.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u64_at = |o: usize| {
        elf.get(o..o + 8).map(|b| {
            let mut a = [0; 8];
            a.copy_from_slice(b);
            u64::from_le_bytes(a)
        })
    };
    let phoff = u64_at(0x20).ok_or_else(bad)? as usize;
    let phentsize = usize::from(u16_at(0x36).ok_or_else(bad)?);
    let phnum = usize::from(u16_at(0x38).ok_or_else(bad)?);
    for i in 0..phnum {
        let p_type = u32_at(phoff + i * phentsize).ok_or_else(bad)?;
        if p_type == PT_INTERP {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_interpreter_in_own_binary_or_not() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        // Test binaries on a gnu host are dynamically linked.
        if cfg!(target_env = "gnu") {
            assert!(has_interpreter(&exe).unwrap());
        }
        assert!(has_interpreter(b"not elf").is_err());
    }

    #[test]
    fn parses_deploy_arguments() {
        assert_eq!(
            parse_deploy(&["relay-1", "--instance", "shadow", "--release", "v0.1.0"]).unwrap(),
            Deploy {
                host: "relay-1",
                instance: Some("shadow"),
                source: Source::Release("v0.1.0"),
            }
        );
        assert_eq!(
            parse_deploy(&["--rollback", "root@relay-1"])
                .unwrap()
                .source,
            Source::Rollback
        );
        assert_eq!(
            parse_deploy(&["a", "--local"]).unwrap().source,
            Source::Local
        );
        for bad in [
            &[][..],
            &["a"],
            &["-oProxyCommand=x", "--local"],
            &["a", "b", "--local"],
            &["a", "--local", "--instance"],
            &["a", "--local", "--instance", "Bad/Name"],
            &["a;b", "--local"],
            &["a", "--force"],
            &["a", "--local", "--rollback"],
            &["a", "--release"],
            &["a", "--release", "0.1.0"],
            &["a", "--release", "v../x"],
            &["a", "--release", "v"],
        ] {
            assert!(parse_deploy(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn reads_github_remotes() {
        for url in [
            "git@github.com:owner/repo.git",
            "ssh://git@github.com/owner/repo",
            "https://github.com/owner/repo.git",
            "https://github.com/owner/repo/",
        ] {
            assert_eq!(parse_github(url).as_deref(), Some("owner/repo"), "{url}");
        }
        for url in [
            "",
            "https://example.com/owner/repo",
            "git@github.com:owner",
            "git@github.com:owner/re po",
            "git@github.com:owner/a/b",
        ] {
            assert_eq!(parse_github(url), None, "{url}");
        }
    }
}
