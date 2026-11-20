//! The access log file: one JSON line per request, written by a dedicated thread.
//!
//! Requests never wait for the disk. Lines go through a bounded queue; when the queue
//! is full because the disk stalls, lines are dropped and counted. The writer collects
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
use std::sync::{Mutex, PoisonError};
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
    dropped: AtomicU64,
}

impl AccessLog {
    /// Opens `path` for appending (created with mode 0640) and starts the writer thread.
    /// `None` keeps the log off until a path is set.
    pub fn open(path: Option<&Path>) -> io::Result<Self> {
        let file = path.map(open_file).transpose()?;
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        std::thread::Builder::new()
            .name("piano-access-log".to_owned())
            .spawn(move || run(rx, file))?;
        Ok(Self {
            tx,
            enabled: AtomicBool::new(path.is_some()),
            path: Mutex::new(path.map(Path::to_owned)),
            dropped: AtomicU64::new(0),
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

    /// Lines dropped because the writer fell behind.
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
fn run(rx: Receiver<Msg>, file: Option<File>) {
    let mut out = file.map(|f| BufWriter::with_capacity(BUFFER, f));
    let mut failing = false;
    while let Ok(first) = rx.recv() {
        let mut next = Some(first);
        while let Some(msg) = next.take() {
            match msg {
                Msg::Line(line) => {
                    if let Some(w) = out.as_mut() {
                        report(w.write_all(line.as_bytes()), &mut failing);
                    }
                }
                Msg::Switch(file) => {
                    if let Some(mut w) = out.take() {
                        report(w.flush(), &mut failing);
                    }
                    out = file.map(|f| BufWriter::with_capacity(BUFFER, f));
                }
                Msg::Flush(done) => {
                    if let Some(w) = out.as_mut() {
                        report(w.flush(), &mut failing);
                    }
                    let _ = done.send(());
                }
            }
            next = rx.try_recv().ok();
        }
        if let Some(w) = out.as_mut() {
            report(w.flush(), &mut failing);
        }
    }
}

/// Logs the first failure of a streak and the recovery after it.
fn report(result: io::Result<()>, failing: &mut bool) {
    match result {
        Err(e) if !*failing => {
            *failing = true;
            warn!("access log write failed, lines are being lost: {e}");
        }
        Ok(()) if *failing => {
            *failing = false;
            info!("access log writes recovered");
        }
        _ => {}
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
