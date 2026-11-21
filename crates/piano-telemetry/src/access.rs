//! The access log file: one JSON line per request, written by a dedicated thread.
//!
//! Requests never wait for the disk. Lines go through a bounded queue; when the queue
//! is full because the disk stalls, lines are dropped and counted, as are lines a
//! failing write (a full disk) loses. The writer collects
//! what is queued in a 64 KiB buffer and writes it out as soon as the queue is empty, so
//! a burst costs one write and a line is on disk moments after its request ended, also
//! when the process exits. Rotation is left to the system (logrotate):
//! [`AccessLog::reopen`] starts a fresh file at the same path.

use log::{info, warn};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// Lines held while the disk is slow: about 2 MiB at typical line sizes.
const QUEUE: usize = 4096;
const BUFFER: usize = 64 << 10;
/// How long [`AccessLog::flush`] waits for the writer.
const FLUSH_WAIT: Duration = Duration::from_secs(5);

enum Msg {
    Line(String),
    /// Continue in this file; `None` stops writing.
    Switch(Option<File>),
    Flush(SyncSender<()>),
}

/// Handle to the access log; cheap to call from request tasks.
#[derive(Debug)]
pub struct AccessLog {
    tx: SyncSender<Msg>,
    path: Mutex<Option<PathBuf>>,
    enabled: AtomicBool,
    /// Shared with the writer thread, which counts the lines failed writes lose.
    dropped: Arc<AtomicU64>,
}

impl AccessLog {
    /// Opens `path` for appending (created with mode 0640) and starts the writer thread.
    /// `None` keeps the log off until a path is set.
    pub fn open(path: Option<&Path>) -> io::Result<Self> {
        let file = path.map(open_file).transpose()?;
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let lost = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("piano-access-log".to_owned())
            .spawn(move || run(rx, file, &lost))?;
        Ok(Self {
            tx,
            enabled: AtomicBool::new(path.is_some()),
            path: Mutex::new(path.map(Path::to_owned)),
            dropped,
        })
    }

    /// Whether lines are written anywhere; skip building them when not.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Queues one line, which must end in a newline. Never blocks.
    pub fn write(&self, line: String) {
        match self.tx.try_send(Msg::Line(line)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Lines lost: dropped because the writer fell behind, or not written because a
    /// write failed.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The file written to, unless the log is off.
    pub fn path(&self) -> Option<PathBuf> {
        self.path
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Starts a new file at the current path, after the old one was moved away.
    pub fn reopen(&self) -> io::Result<()> {
        let path = self.path.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(p) = path.as_deref() else {
            return Ok(());
        };
        let file = open_file(p)?;
        self.send(Msg::Switch(Some(file)));
        Ok(())
    }

    /// Moves the log to `path` (`None` turns it off). The new file is opened before
    /// anything changes, so on error the log keeps its current file.
    pub fn set_path(&self, path: Option<&Path>) -> io::Result<()> {
        let mut current = self.path.lock().unwrap_or_else(PoisonError::into_inner);
        if current.as_deref() == path {
            return Ok(());
        }
        let file = path.map(open_file).transpose()?;
        self.send(Msg::Switch(file));
        self.enabled.store(path.is_some(), Ordering::Relaxed);
        *current = path.map(Path::to_owned);
        Ok(())
    }

    /// Writes out everything queued so far; waits a few seconds at most.
    pub fn flush(&self) {
        let (done, wait) = mpsc::sync_channel(1);
        self.send(Msg::Flush(done));
        let _ = wait.recv_timeout(FLUSH_WAIT);
    }

    /// Control messages wait for room in the queue: they are rare and must not be lost.
    fn send(&self, msg: Msg) {
        let _ = self.tx.send(msg);
    }
}

fn open_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o640)
        .open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display())))
}

/// The writer thread: ends when every handle is gone, after writing what is queued.
/// Counts in `lost` the lines that failed writes lose.
fn run(rx: Receiver<Msg>, file: Option<File>, lost: &AtomicU64) {
    let mut out = file.map(|f| BufWriter::with_capacity(BUFFER, f));
    let mut failing = false;
    while let Ok(first) = rx.recv() {
        let mut next = Some(first);
        while let Some(msg) = next.take() {
            match msg {
                Msg::Line(line) => {
                    // Fails only when the buffer is full and cannot be written out; the
                    // buffer keeps its lines for the next try, this one is gone.
                    if let Some(w) = out.as_mut()
                        && let Err(e) = w.write_all(line.as_bytes())
                    {
                        lost.fetch_add(1, Ordering::Relaxed);
                        failed(&e, &mut failing);
                    }
                }
                Msg::Switch(file) => {
                    if let Some(w) = out.take() {
                        close(w, lost, &mut failing);
                    }
                    out = file.map(|f| BufWriter::with_capacity(BUFFER, f));
                }
                Msg::Flush(done) => {
                    if let Some(w) = out.as_mut() {
                        flush(w, &mut failing);
                    }
                    let _ = done.send(());
                }
            }
            next = rx.try_recv().ok();
        }
        if let Some(w) = out.as_mut() {
            flush(w, &mut failing);
        }
    }
    if let Some(w) = out.take() {
        close(w, lost, &mut failing);
    }
}

/// Writes out the buffer. Only a write that reached the file ends a streak of failures:
/// lines that merely fit in the buffer say nothing about the disk.
fn flush(w: &mut BufWriter<File>, failing: &mut bool) {
    match w.flush() {
        Ok(()) if *failing => {
            *failing = false;
            info!("access log writes recovered");
        }
        Ok(()) => {}
        Err(e) => failed(&e, failing),
    }
}

/// Logs the first failure of a streak.
fn failed(e: &io::Error, failing: &mut bool) {
    if !*failing {
        *failing = true;
        warn!("access log write failed, lines are being lost: {e}");
    }
}

/// Writes out and closes `w`; lines it still holds after a failed write are lost.
fn close(mut w: BufWriter<File>, lost: &AtomicU64, failing: &mut bool) {
    flush(&mut w, failing);
    // into_parts hands back the unwritten bytes instead of trying again on drop.
    if let (_, Ok(rest)) = w.into_parts() {
        let lines = rest.iter().filter(|&&b| b == b'\n').count();
        lost.fetch_add(lines as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("piano-access-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap_or_default()
    }

    #[test]
    fn writes_reopens_and_moves() {
        let d = Dir::new("move");
        let a = d.0.join("a.log");
        let log = AccessLog::open(Some(&a)).unwrap();
        log.write("1\n".to_owned());
        log.flush();
        assert_eq!(read(&a), "1\n");

        let rotated = d.0.join("a.log.1");
        std::fs::rename(&a, &rotated).unwrap();
        log.write("2\n".to_owned());
        log.reopen().unwrap();
        log.write("3\n".to_owned());
        log.flush();
        assert_eq!(read(&rotated), "1\n2\n");
        assert_eq!(read(&a), "3\n");

        let b = d.0.join("b.log");
        log.set_path(Some(&b)).unwrap();
        log.write("4\n".to_owned());
        log.flush();
        assert_eq!(read(&b), "4\n");
        assert_eq!(read(&a), "3\n");

        log.set_path(None).unwrap();
        assert!(!log.enabled());
        log.write("5\n".to_owned());
        log.flush();
        assert_eq!(read(&b), "4\n");
        assert_eq!(log.dropped(), 0);
    }

    #[test]
    fn a_bad_path_leaves_the_current_file() {
        let d = Dir::new("bad");
        let a = d.0.join("a.log");
        let log = AccessLog::open(Some(&a)).unwrap();
        let err = log.set_path(Some(&d.0.join("missing/b.log"))).unwrap_err();
        assert!(err.to_string().contains("missing/b.log"), "{err}");
        log.write("1\n".to_owned());
        log.flush();
        assert_eq!(read(&a), "1\n");
        assert!(AccessLog::open(Some(&d.0.join("missing/c.log"))).is_err());
    }

    #[test]
    fn lines_failed_writes_lose_count_as_dropped() {
        // Every write to /dev/full fails with ENOSPC.
        let log = AccessLog::open(Some(Path::new("/dev/full"))).unwrap();
        let line = format!("{}\n", "x".repeat(499));
        for _ in 0..300 {
            log.write(line.clone());
            log.flush();
        }
        // The buffer holds what fits for a later try; the lines after it are lost.
        let held = (BUFFER / line.len()) as u64;
        assert_eq!(log.dropped(), 300 - held);
        // Leaving the file gives up what the buffer holds.
        log.set_path(None).unwrap();
        log.flush();
        assert_eq!(log.dropped(), 300);
    }

    #[test]
    fn dropping_the_handle_writes_what_is_queued() {
        let d = Dir::new("drop");
        let a = d.0.join("a.log");
        let log = AccessLog::open(Some(&a)).unwrap();
        log.write("1\n".to_owned());
        drop(log);
        let deadline = std::time::Instant::now() + FLUSH_WAIT;
        while read(&a).is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(read(&a), "1\n");
    }
}
