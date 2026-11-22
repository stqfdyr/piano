//! The parts of the media stream engine that do no I/O: the byte range a client asks
//! for, whether another response can continue a body already being sent, and the table
//! of streams being relayed.

#![forbid(unsafe_code)]

mod range;
mod streams;

pub use range::{ByteRange, ContentRange, Head, Mismatch, Resume};
pub use streams::{Request, Stream, StreamGuard, Streams};
