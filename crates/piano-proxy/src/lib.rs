//! The request pipeline, as a pingora `ProxyHttp` implementation.

#![forbid(unsafe_code)]

pub mod follow;
pub mod headers;
mod relay;
pub mod rewrite;
pub mod route;
mod sites;

pub use relay::{Ctx, MAX_ATTEMPTS, Relay};
pub use sites::{Mounts, Policy, Site, SiteError, Sites};
