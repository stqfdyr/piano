//! The daemon side: binding the socket, checking who connects, one request per
//! connection.

use crate::frame::{self, MAX_REQUEST};
use crate::{PROTOCOL_VERSION, Request, Response};
use async_trait::async_trait;
use log::{debug, info, warn};
use serde_json::Value;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Connections served at once. Only root and the daemon's own user may connect, so this
/// only bounds a runaway script.
pub const MAX_CLIENTS: usize = 4;

/// Limit on reading a request and on writing its response; both are small and local.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("{0}: another process is listening on it")]
    InUse(PathBuf),
    #[error("{0} exists and is not a socket")]
    NotSocket(PathBuf),
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> BindError + '_ {
    move |source| BindError::Io {
        path: path.to_owned(),
        source,
    }
}

/// A bound control socket, not yet served.
#[derive(Debug)]
pub struct Bound {
    listener: UnixListener,
    path: PathBuf,
    /// Where the socket sits until [`Bound::publish`] moves it to `path`.
    unpublished: Option<PathBuf>,
    /// Device and inode of the socket file, to remove it at exit only if it is still ours.
    id: (u64, u64),
}

impl Bound {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether clients can reach the socket at [`Bound::path`] yet.
    pub fn is_published(&self) -> bool {
        self.unpublished.is_none()
    }

    /// Moves the socket to its path, replacing whatever socket is there.
    pub fn publish(&mut self) -> io::Result<()> {
        if let Some(tmp) = &self.unpublished {
            fs::rename(tmp, &self.path)?;
            self.unpublished = None;
        }
        Ok(())
    }

    fn remove(&self) {
        if let Some(tmp) = &self.unpublished {
            let _ = fs::remove_file(tmp);
            return;
        }
        let ours = fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.id);
        if ours && let Err(e) = fs::remove_file(&self.path) {
            warn!("cannot remove control socket {}: {e}", self.path.display());
        }
    }
}

/// Creates the socket at `path`, readable and writable by the owner only. A socket file
/// left by a process that is gone is replaced; one with a live listener is an error.
/// The socket gets its mode under a temporary name and is then renamed into place, so
/// it is never reachable with a wider mode.
pub fn bind(path: &Path) -> Result<Bound, BindError> {
    bind_at(path, false)
}

/// Like [`bind`], but leaves the socket under a temporary name until
/// [`Bound::publish`], which then replaces the socket at `path` even if it has a live
/// listener: a daemon taking over from another in an upgrade publishes once the other
/// has handed over. The other keeps serving the connections it has and leaves the file
/// alone at exit, since it is no longer its own.
pub fn bind_unpublished(path: &Path) -> Result<Bound, BindError> {
    bind_at(path, true)
}

fn bind_at(path: &Path, replace_live: bool) -> Result<Bound, BindError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(dir)
            .map_err(io_err(dir))?;
    }
    match fs::symlink_metadata(path) {
        // Renaming over it below replaces it without disturbing its listener.
        Ok(m) if m.file_type().is_socket() && replace_live => {}
        Ok(m) if m.file_type().is_socket() => match UnixStream::connect(path) {
            Ok(_) => return Err(BindError::InUse(path.to_owned())),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                fs::remove_file(path).map_err(io_err(path))?;
            }
            Err(e) => return Err(io_err(path)(e)),
        },
        Ok(_) => return Err(BindError::NotSocket(path.to_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(path)(e)),
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp).map_err(io_err(&tmp))?;
    let placed = fs::set_permissions(&tmp, Permissions::from_mode(0o600)).and_then(|()| {
        if replace_live {
            Ok(())
        } else {
            fs::rename(&tmp, path)
        }
    });
    if let Err(e) = placed {
        let _ = fs::remove_file(&tmp);
        return Err(io_err(path)(e));
    }
    let at = if replace_live { tmp.as_path() } else { path };
    let m = fs::symlink_metadata(at).map_err(io_err(at))?;
    listener.set_nonblocking(true).map_err(io_err(path))?;
    Ok(Bound {
        listener,
        path: path.to_owned(),
        unpublished: replace_live.then_some(tmp),
        id: (m.dev(), m.ino()),
    })
}

/// Answers commands. `None` means the command is unknown.
#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(&self, cmd: &str) -> Option<Result<Value, String>>;
}

/// Whether a peer with user id `uid` may use the socket: root and the daemon's user.
/// The socket's mode already keeps others out; this also holds if the mode is widened.
fn allowed(uid: u32) -> bool {
    uid == 0 || uid == nix::unistd::geteuid().as_raw()
}

/// Serves `bound` until `shutdown` completes, then removes the socket file.
pub async fn serve(bound: Bound, handler: Arc<dyn Handler>, shutdown: impl Future<Output = ()>) {
    let listener = match bound
        .listener
        .try_clone()
        .and_then(tokio::net::UnixListener::from_std)
    {
        Ok(l) => l,
        Err(e) => {
            warn!("control socket {} is unusable: {e}", bound.path.display());
            bound.remove();
            return;
        }
    };
    info!("control socket listening on {}", bound.path.display());
    let slots = Arc::new(Semaphore::new(MAX_CLIENTS));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                        debug!("control socket busy, closing a connection");
                        continue;
                    };
                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        connection(stream, &*handler).await;
                        drop(slot);
                    });
                }
                Err(e) => {
                    warn!("control socket accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            () = &mut shutdown => break,
        }
    }
    bound.remove();
}

async fn connection(mut stream: tokio::net::UnixStream, handler: &dyn Handler) {
    match stream.peer_cred() {
        Ok(c) if allowed(c.uid()) => {}
        Ok(c) => {
            warn!("control socket: refused a connection from uid {}", c.uid());
            return;
        }
        Err(e) => {
            warn!("control socket: cannot identify the peer: {e}");
            return;
        }
    }
    let request =
        match tokio::time::timeout(IO_TIMEOUT, frame::read(&mut stream, MAX_REQUEST)).await {
            Ok(Ok(body)) => body,
            Ok(Err(e)) => {
                debug!("control socket: reading a request failed: {e}");
                return;
            }
            Err(_) => {
                debug!("control socket: no request within {IO_TIMEOUT:?}");
                return;
            }
        };
    let response = match serde_json::from_slice::<Request>(&request) {
        Err(e) => Response::error(format!("bad request: {e}")),
        Ok(r) if r.v != PROTOCOL_VERSION => Response::error(format!(
            "protocol version {} is not supported; the daemon speaks {PROTOCOL_VERSION}",
            r.v
        )),
        Ok(r) => match handler.handle(&r.cmd).await {
            Some(Ok(data)) => Response::data(data),
            Some(Err(e)) => Response::error(e),
            None => Response::error(format!("unknown command {:?}", r.cmd)),
        },
    };
    let body = match serde_json::to_vec(&response) {
        Ok(b) => b,
        Err(e) => {
            warn!("control socket: cannot encode a response: {e}");
            return;
        }
    };
    if let Ok(Err(e)) | Err(e) = tokio::time::timeout(IO_TIMEOUT, frame::write(&mut stream, &body))
        .await
        .map_err(io::Error::other)
    {
        debug!("control socket: writing a response failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientError, call};
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let d = std::env::temp_dir().join(format!(
                "piano-ctl-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&d).unwrap();
            Self(d)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Echo;

    #[async_trait]
    impl Handler for Echo {
        async fn handle(&self, cmd: &str) -> Option<Result<Value, String>> {
            match cmd {
                "ping" => Some(Ok(Value::String("pong".into()))),
                "fail" => Some(Err("it failed".into())),
                _ => None,
            }
        }
    }

    #[test]
    fn socket_is_private_and_a_stale_one_is_replaced() {
        let dir = Dir::new();
        let path = dir.0.join("run/ctl.sock");
        let bound = bind(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // A live listener is not taken over.
        assert!(matches!(bind(&path), Err(BindError::InUse(_))));
        // Once its process is gone, the file is stale.
        drop(bound);
        let again = bind(&path).unwrap();
        // Removing does not touch a file that someone else put in its place.
        fs::remove_file(&path).unwrap();
        fs::write(&path, "other").unwrap();
        again.remove();
        assert!(path.exists());
        assert!(matches!(bind(&path), Err(BindError::NotSocket(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serves_commands_and_removes_the_socket_at_shutdown() {
        let dir = Dir::new();
        let path = dir.0.join("ctl.sock");
        let bound = bind(&path).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(bound, Arc::new(Echo), async move {
            let _ = stopped.await;
        }));
        let p = path.clone();
        let results = tokio::task::spawn_blocking(move || {
            let t = Duration::from_secs(5);
            (
                call(&p, "ping", t),
                call(&p, "fail", t),
                call(&p, "nope", t),
            )
        })
        .await
        .unwrap();
        assert_eq!(results.0.unwrap(), Value::String("pong".into()));
        assert!(matches!(results.1, Err(ClientError::Daemon(ref e)) if e == "it failed"));
        assert!(
            matches!(results.2, Err(ClientError::Daemon(ref e)) if e.contains("unknown command"))
        );

        // Another protocol version is answered with an error, not misread.
        let mut s = tokio::net::UnixStream::connect(&path).await.unwrap();
        frame::write(&mut s, br#"{"v":2,"cmd":"ping"}"#)
            .await
            .unwrap();
        let reply: Response =
            serde_json::from_slice(&frame::read(&mut s, 4096).await.unwrap()).unwrap();
        assert!(!reply.ok);
        assert!(reply.error.unwrap().contains("version 2"));

        stop.send(()).unwrap();
        server.await.unwrap();
        assert!(!path.exists());
        let p = path.clone();
        let gone = tokio::task::spawn_blocking(move || call(&p, "ping", Duration::from_secs(1)))
            .await
            .unwrap();
        assert!(matches!(gone, Err(ClientError::Unreachable { .. })));
    }
}
