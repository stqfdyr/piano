//! Process figures from `/proc/self`.

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
    }
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
    }
}
