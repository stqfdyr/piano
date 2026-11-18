//! The request pipeline, as a pingora `ProxyHttp` implementation.

#![forbid(unsafe_code)]

mod relay;
mod sites;

pub use relay::{Ctx, Relay};
pub use sites::{Site, Sites};
