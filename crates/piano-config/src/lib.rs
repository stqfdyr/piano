//! Configuration file model, parsing and validation.
//!
//! The file is the single source of truth: it is parsed into [`Config`], checked as a
//! whole, and only a fully valid configuration is handed to the rest of the process.

#![forbid(unsafe_code)]

mod duration;
mod model;
mod net;
mod validate;

pub use duration::{Duration, ParseDurationError};
pub use model::{Access, Config, Server, ServerDomains, Site, Tls, UaRule, Upstream};
pub use net::{IpNet, ParseIpNetError};
pub use validate::{UpstreamUrl, ValidationError, Warning, host_matches, is_dns_name};

use std::path::Path;

/// Default location of the configuration file.
pub const DEFAULT_PATH: &str = "/etc/piano/piano.toml";

/// Failure to load a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: String,
        source: Box<toml::de::Error>,
    },
    #[error("invalid configuration in {path}:\n{}", format_errors(.errors))]
    Invalid {
        path: String,
        errors: Vec<ValidationError>,
    },
}

fn format_errors(errors: &[ValidationError]) -> String {
    errors
        .iter()
        .map(|e| format!("  - {e}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Reads, parses and validates the configuration file at `path`.
pub fn load(path: &Path) -> Result<Config, Error> {
    let display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: display.clone(),
        source,
    })?;
    parse(&text).map_err(|e| match e {
        Error::Parse { source, .. } => Error::Parse {
            path: display,
            source,
        },
        Error::Invalid { errors, .. } => Error::Invalid {
            path: display,
            errors,
        },
        other => other,
    })
}

/// Parses and validates configuration text.
pub fn parse(text: &str) -> Result<Config, Error> {
    let mut config: Config = toml::from_str(text).map_err(|source| Error::Parse {
        path: String::new(),
        source: Box::new(source),
    })?;
    validate::validate(&mut config).map_err(|errors| Error::Invalid {
        path: String::new(),
        errors,
    })?;
    Ok(config)
}
