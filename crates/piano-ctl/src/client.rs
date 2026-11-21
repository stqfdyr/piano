//! The CLI side: one blocking request per connection.

use crate::frame::{self, MAX_RESPONSE};
use crate::{PROTOCOL_VERSION, Request, Response};
use serde_json::Value;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// No daemon there, or no permission to reach it.
    #[error("cannot reach the daemon at {path}: {source}")]
    Unreachable { path: PathBuf, source: io::Error },
    /// The daemon closed the connection without replying: it serves a few connections at a
    /// time and closes the others at once, closes them all when it stops, and closes one
    /// whose peer it refuses or whose request it cannot read (logged).
    #[error(
        "the daemon closed the connection without a reply: busy with other commands, stopping, or refusing this connection (see its log)"
    )]
    Closed(#[source] io::Error),
    #[error("talking to the daemon: {0}")]
    Io(#[from] io::Error),
    #[error("unexpected reply from the daemon: {0}")]
    Protocol(String),
    /// The daemon answered with an error.
    #[error("{0}")]
    Daemon(String),
}

/// Sends `cmd` to the daemon at `socket` and returns the reply's data. `timeout` bounds
/// each read and write.
pub fn call(socket: &Path, cmd: &str, timeout: Duration) -> Result<Value, ClientError> {
    let mut stream = UnixStream::connect(socket).map_err(|source| ClientError::Unreachable {
        path: socket.to_owned(),
        source,
    })?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = Request {
        v: PROTOCOL_VERSION,
        cmd: cmd.to_owned(),
    };
    let body = serde_json::to_vec(&request).map_err(|e| ClientError::Protocol(e.to_string()))?;
    frame::write_blocking(&mut stream, &body).map_err(closed)?;
    let reply = frame::read_blocking(&mut stream, MAX_RESPONSE).map_err(closed)?;
    let response: Response =
        serde_json::from_slice(&reply).map_err(|e| ClientError::Protocol(e.to_string()))?;
    if response.v != PROTOCOL_VERSION {
        return Err(ClientError::Protocol(format!(
            "protocol version {}, expected {PROTOCOL_VERSION}",
            response.v
        )));
    }
    match (response.ok, response.data, response.error) {
        (true, Some(data), _) => Ok(data),
        (true, None, _) => Err(ClientError::Protocol("no data".into())),
        (false, _, e) => Err(ClientError::Daemon(e.unwrap_or_default())),
    }
}

/// A read that ends early, or a write to a connection the daemon already closed.
fn closed(e: io::Error) -> ClientError {
    match e.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset => ClientError::Closed(e),
        _ => ClientError::Io(e),
    }
}
