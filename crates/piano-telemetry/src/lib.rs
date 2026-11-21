//! Access log, diagnostic logger, credential redaction, log identifiers, counters and
//! latency histograms.

#![forbid(unsafe_code)]

/// A fieldless enum whose variants index counter arrays, with `ALL` and the label of
/// each variant generated from one list, so a new variant cannot be left out of `ALL`
/// (which sizes the arrays) or lack a label.
macro_rules! labelled {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $label:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// Every variant in declaration order, so `ALL[v.index()] == v`.
            pub const ALL: [$name; [$($label),+].len()] = [$($name::$variant),+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $( $name::$variant => $label, )+
                }
            }

            pub(crate) fn index(self) -> usize {
                self as usize
            }
        }
    };
}

pub mod access;
pub mod id;
pub mod json;
pub mod latency;
pub mod logger;
pub mod metrics;
pub mod redact;

pub use access::AccessLog;
pub use id::Id;
pub use latency::Ttfb;
pub use metrics::{End, Kind, Metrics, SiteCounters};
pub use redact::redact;
