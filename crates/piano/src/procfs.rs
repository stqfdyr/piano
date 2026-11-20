//! Process figures from `/proc/self`.

use std::fmt::Write as _;
use std::io::Read as _;
use std::sync::OnceLock;

use piano_ctl::proto::Process;

/// A `Name:   value kB` line of `/proc/self/status`, as its first number.
fn status_field(status: &str, name: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

pub fn process() -> Process {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let open_files = std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|d| d.count() as u64);
    let max_open_files = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)
        .ok()
        .map(|(soft, _)| soft);
    Process {
        rss_bytes: status_field(&status, "VmRSS").map(|kib| kib * 1024),
        threads: status_field(&status, "Threads"),
        open_files,
        max_open_files,
        binary_sha256: binary_sha256(),
    }
}

/// Hex sha256 of the executable this process runs, computed on first use (about 20 ms).
/// `/proc/self/exe` still opens it after the file at its path has been replaced.
fn binary_sha256() -> Option<String> {
    static SUM: OnceLock<Option<String>> = OnceLock::new();
    SUM.get_or_init(|| {
        let mut file = std::fs::File::open("/proc/self/exe").ok()?;
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buf = vec![0; 64 * 1024];
        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            ctx.update(&buf[..n]);
        }
        let mut hex = String::with_capacity(64);
        for b in ctx.finish().as_ref() {
            let _ = write!(hex, "{b:02x}");
        }
        Some(hex)
    })
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fields_and_this_process() {
        let s = "Name:\tpiano\nVmRSS:\t   11264 kB\nThreads:\t2\n";
        assert_eq!(status_field(s, "VmRSS"), Some(11264));
        assert_eq!(status_field(s, "Threads"), Some(2));
        assert_eq!(status_field(s, "VmSwap"), None);
        let p = process();
        assert!(p.rss_bytes.unwrap() > 0);
        assert!(p.open_files.unwrap() > 0);
        let exe = std::fs::read("/proc/self/exe").unwrap();
        let want = ring::digest::digest(&ring::digest::SHA256, &exe);
        let hex: String = want.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(p.binary_sha256.as_deref(), Some(hex.as_str()));
    }
}
