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
pub use model::{
    Access, Cache, Config, Control, DEFAULT_SOCKET, DEFAULT_TRAFFIC_FILE, Limits, Log, LogLevel,
    Server, ServerDomains, Site, Tls, Traffic, UaRule, Upstream, UpstreamLimit,
};
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
    parse(&text).map_err(|e| e.at(display))
}

impl Error {
    /// The same error, naming the file it is about.
    fn at(self, path: String) -> Self {
        match self {
            Error::Parse { source, .. } => Error::Parse { path, source },
            Error::Invalid { errors, .. } => Error::Invalid { path, errors },
            other => other,
        }
    }
}

/// The `[control]` section of the configuration file at `path`, read without the rest of
/// the file: the command-line tool finds the daemon's socket by it even while another
/// section is invalid.
pub fn load_control(path: &Path) -> Result<Control, Error> {
    let display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: display.clone(),
        source,
    })?;
    parse_control(&text).map_err(|e| e.at(display))
}

fn parse_control(text: &str) -> Result<Control, Error> {
    use serde::de::IgnoredAny;
    /// The sections of [`Config`]: the others are not looked at, but an unknown one is an
    /// error, since a misspelled `[control]` would otherwise leave the default socket.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[expect(dead_code, reason = "only checked to exist")]
    struct OnlyControl {
        #[serde(default)]
        control: Control,
        version: Option<IgnoredAny>,
        server: Option<IgnoredAny>,
        tls: Option<IgnoredAny>,
        access: Option<IgnoredAny>,
        limits: Option<IgnoredAny>,
        upstream: Option<IgnoredAny>,
        log: Option<IgnoredAny>,
        cache: Option<IgnoredAny>,
        traffic: Option<IgnoredAny>,
        site: Option<IgnoredAny>,
    }
    let control = toml::from_str::<OnlyControl>(text)
        .map_err(|source| Error::Parse {
            path: String::new(),
            source: Box::new(source),
        })?
        .control;
    if control.socket_path().is_some_and(|p| !p.is_absolute()) {
        return Err(Error::Invalid {
            path: String::new(),
            errors: vec![ValidationError::RelativeSocket(control.socket)],
        });
    }
    Ok(control)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_control_section_is_read_while_the_rest_is_invalid() {
        let text = "[server]\nlisten = 5\n[control]\nsocket = \"/run/b/ctl.sock\"\n";
        assert!(parse(text).is_err());
        let c = parse_control(text).unwrap();
        assert_eq!(c.socket_path(), Some(Path::new("/run/b/ctl.sock")));
    }

    #[test]
    fn the_control_section_defaults_and_turns_off_as_in_the_full_model() {
        let c = parse_control("[server]\nthreads = 1\n").unwrap();
        assert_eq!(c.socket_path(), Some(Path::new(DEFAULT_SOCKET)));
        let c = parse_control("[control]\nsocket = \"\"\n").unwrap();
        assert_eq!(c.socket_path(), None);
    }

    #[test]
    fn no_socket_is_guessed_from_a_file_that_is_not_toml_or_not_there() {
        assert!(parse_control("[control]\nsocket = \n").is_err());
        assert!(parse_control("[control]\nsokcet = \"/x\"\n").is_err());
        assert!(parse_control("[contol]\nsocket = \"/run/b/ctl.sock\"\n").is_err());
        assert!(matches!(
            parse_control("[control]\nsocket = \"ctl.sock\"\n"),
            Err(Error::Invalid { .. })
        ));
        let missing = load_control(Path::new("/nonexistent/piano.toml")).unwrap_err();
        assert!(matches!(missing, Error::Read { .. }));
    }
}
