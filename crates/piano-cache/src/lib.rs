//! Image engine building blocks: image keys, a size-bounded LRU store for what is
//! remembered about images, and the per-upstream request budget. Free of I/O; the proxy
//! drives them.

#![forbid(unsafe_code)]

mod budget;
mod key;
mod lru;

pub use budget::{Budget, BudgetState, Rate, Wait};
pub use key::{image_key, variant_key};
pub use lru::{ENTRY, Lru, Weigh};
