//! Control protocol between the CLI and the daemon: length-prefixed JSON frames over a
//! unix socket. Configuration changes never travel over it; they go through the file.
//!
//! A connection carries one request and its response. A frame is a 4-byte big-endian
//! length followed by that many bytes of JSON. Requests are `{"v":1,"cmd":"status"}`;
//! responses are `{"v":1,"ok":true,"data":…}` or `{"v":1,"ok":false,"error":"…"}`.

#![forbid(unsafe_code)]

pub mod client;
pub mod frame;
pub mod proto;
pub mod server;

pub use client::{ClientError, call};
pub use proto::{Request, Response};

/// Protocol version carried in every request and response.
pub const PROTOCOL_VERSION: u32 = 1;
