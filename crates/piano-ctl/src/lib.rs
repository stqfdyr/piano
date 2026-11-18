//! Control protocol between the CLI and the daemon: length-prefixed JSON frames over a
//! unix socket. Configuration changes never travel over it; they go through the file.

#![forbid(unsafe_code)]

/// Protocol version carried in every request and response.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default control socket path.
pub const DEFAULT_SOCKET: &str = "/run/piano/ctl.sock";
