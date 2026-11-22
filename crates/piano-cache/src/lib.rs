//! Image cache building blocks: cache keys, freshness, a size-bounded LRU store and the
//! per-upstream request budget. Free of I/O; the proxy drives them.

#![forbid(unsafe_code)]

mod budget;
mod fresh;
mod key;
mod lru;

pub use budget::{Budget, BudgetState, Rate, Wait};
pub use fresh::{Freshness, shared_ttl};
pub use key::{image_key, variant_key};
pub use lru::{ENTRY, Lru, Weigh};
