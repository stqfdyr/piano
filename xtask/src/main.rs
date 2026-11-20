//! Development tasks. Run as `cargo xtask <task>`.
//!
//! - `ci`: format check, clippy with warnings denied, tests, dependency policy.
//! - `dist`: static musl release binary for x86-64-v2 hosts, with size and sha256.

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

const DIST_TARGET: &str = "x86_64-unknown-linux-musl";
/// Oldest production CPU has no AVX2.
const DIST_CPU: &str = "x86-64-v2";

type Result<T = ()> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["ci"] => ci(),
        ["dist"] => dist(),
        _ => {
            eprintln!("usage: cargo xtask <ci|dist>");
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

/// Upper bound on running the tests, about three times what the whole suite takes. A
/// hung test fails the run instead of holding it open.
const TEST_LIMIT: Duration = Duration::from_secs(120);

/// Like [`run`], but kills the command and everything it started once `limit` passes.
fn run_limited(step: &str, mut cmd: Command, limit: Duration) -> Result {
    eprintln!("==> {step} (limit {}s)", limit.as_secs());
    let start = Instant::now();
    // Its own process group, so the test binaries cargo starts go with it.
    let mut child = cmd
        .process_group(0)
        .spawn()
        .map_err(|e| format!("{step}: cannot start: {e}"))?;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| format!("{step}: {e}"))? {
            if !status.success() {
                return Err(format!("{step} failed ({status})"));
            }
            eprintln!("    {step} ok in {:.1}s", start.elapsed().as_secs_f64());
            return Ok(());
        }
        if start.elapsed() >= limit {
            let group = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
            let _ = child.wait();
            return Err(format!(
                "{step} killed after {}s: a test hangs",
                limit.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
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
    test.args(["test", "--workspace", "--locked"]);
    run_limited("test", test, TEST_LIMIT)?;

    let mut deny = cargo();
    deny.args(["deny", "--locked", "check"]);
    run("deny", deny)
}

fn dist() -> Result {
    let mut build = cargo();
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

    let target_dir =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root().join("target"), PathBuf::from);
    let built = target_dir.join(DIST_TARGET).join("release").join("piano");
    let bytes = std::fs::read(&built).map_err(|e| format!("{}: {e}", built.display()))?;
    if has_interpreter(&bytes)? {
        return Err(format!("{} is dynamically linked", built.display()));
    }

    let version = workspace_version()?;
    let out_dir = target_dir.join("dist");
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let name = format!("piano-{version}-x86_64-linux-musl");
    let out = out_dir.join(&name);
    std::fs::write(&out, &bytes).map_err(|e| format!("{}: {e}", out.display()))?;
    set_executable(&out)?;

    let sum = Command::new("sha256sum")
        .arg(&name)
        .current_dir(&out_dir)
        .output()
        .map_err(|e| format!("sha256sum: {e}"))?;
    if !sum.status.success() {
        return Err("sha256sum failed".into());
    }
    let sum_path = out_dir.join(format!("{name}.sha256"));
    std::fs::write(&sum_path, &sum.stdout).map_err(|e| format!("{}: {e}", sum_path.display()))?;

    println!("{}", out.display());
    println!(
        "  size   {:.2} MiB ({} bytes)",
        bytes.len() as f64 / 1048576.0,
        bytes.len()
    );
    println!("  static yes ({DIST_TARGET}, target-cpu={DIST_CPU})");
    print!("  sha256 {}", String::from_utf8_lossy(&sum.stdout));
    Ok(())
}

fn set_executable(path: &Path) -> Result {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
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

/// `version` from `[workspace.package]` in the root manifest.
fn workspace_version() -> Result<String> {
    let path = root().join("Cargo.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut in_package = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_package = line == "[workspace.package]";
        } else if in_package && let Some(v) = line.strip_prefix("version") {
            let v = v
                .trim_start()
                .trim_start_matches('=')
                .trim()
                .trim_matches('"');
            return Ok(v.to_owned());
        }
    }
    Err("no version in [workspace.package]".into())
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
    fn reads_workspace_version() {
        assert!(!workspace_version().unwrap().is_empty());
    }
}
