//! The `piano` command: daemon and management tool in one binary.

#![forbid(unsafe_code)]

mod logtail;
mod render;

use clap::{Parser, Subcommand};
use piano_ctl::ClientError;
use piano_ctl::proto::{ReloadReply, Status};
use piano_upstream::Resolver;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Exit codes shared by all commands.
mod exit {
    pub const RUNTIME: u8 = 1;
    pub const CONFIG: u8 = 2;
    pub const WARNINGS: u8 = 3;
    pub const UNREACHABLE: u8 = 4;
}

/// How long the CLI waits for each read or write on the control socket. A reload
/// resolves new upstream names, which can take several resolver timeouts.
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(name = "piano", version, about = "Emby relay")]
struct Cli {
    /// Configuration file.
    #[arg(short, long, global = true, default_value = piano_config::DEFAULT_PATH)]
    config: PathBuf,
    /// Diagnostic log level: error, warn, info, debug or trace. Overrides log.level in
    /// the configuration file, also across reloads.
    #[arg(long, global = true)]
    log_level: Option<String>,
    /// Control socket of the running daemon; defaults to control.socket in the
    /// configuration file.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Print machine-readable JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
    /// No colours in text output (also when NO_COLOR is set or output is not a terminal).
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon in the foreground.
    Run,
    /// Show what the running daemon is doing and anything that needs attention.
    Status,
    /// Reread the configuration file and certificates; the running configuration stays
    /// if the new one fails.
    Reload,
    /// Configuration commands.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Access log commands.
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
    /// Print the version.
    Version,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Parse and validate the configuration without starting anything.
    Check,
    /// Print the configuration with every default written out.
    Show,
}

#[derive(Subcommand)]
enum LogCommand {
    /// Print the last requests from the access log file; --json prints the raw lines.
    Tail {
        /// How many lines to print before following.
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Keep printing new lines, across log rotation, until interrupted.
        #[arg(short, long)]
        follow: bool,
        /// Only this site.
        #[arg(long)]
        site: Option<String>,
        /// Only this status code (404) or class (5xx).
        #[arg(long)]
        status: Option<String>,
        /// Only this route class (media, image, api, …).
        #[arg(long)]
        class: Option<String>,
        /// Read this file instead of log.access, e.g. a rotated one.
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level_override = match cli
        .log_level
        .as_deref()
        .map(piano_telemetry::logger::parse_level)
    {
        None => None,
        Some(Some(level)) => Some(level),
        Some(None) => {
            eprintln!(
                "invalid --log-level {:?}",
                cli.log_level.unwrap_or_default()
            );
            return ExitCode::from(exit::CONFIG);
        }
    };
    match cli.command {
        Command::Version => {
            version(cli.json);
            ExitCode::SUCCESS
        }
        Command::Status => status(&cli),
        Command::Reload => reload(&cli),
        Command::Config {
            command: ConfigCommand::Check,
        } => config_check(&cli.config),
        Command::Config {
            command: ConfigCommand::Show,
        } => config_show(&cli),
        Command::Log { ref command } => log(&cli, command),
        Command::Run => {
            let level = level_override.unwrap_or(log::LevelFilter::Info);
            if let Err(e) = piano_telemetry::logger::init(level) {
                eprintln!("cannot install logger: {e}");
                return ExitCode::from(exit::RUNTIME);
            }
            run(&cli.config, level_override)
        }
    }
}

fn version(json: bool) {
    let v = env!("CARGO_PKG_VERSION");
    if json {
        println!("{{\"schema\":1,\"version\":\"{v}\"}}");
    } else {
        println!("piano {v}");
    }
}

/// Where the daemon's control socket is: `--socket`, else the configuration file's
/// setting, else the default. `None` when the configuration turns the socket off.
fn socket_path(cli: &Cli) -> Option<PathBuf> {
    if let Some(s) = &cli.socket {
        return Some(s.clone());
    }
    match piano_config::load(&cli.config) {
        Ok(c) => c.control.socket_path().map(Path::to_owned),
        Err(_) => Some(PathBuf::from(piano_config::DEFAULT_SOCKET)),
    }
}

/// Sends `cmd` and decodes the reply, or reports the failure and the exit code.
fn ask<T: serde::de::DeserializeOwned>(
    cli: &Cli,
    cmd: &str,
    timeout: Duration,
) -> Result<T, ExitCode> {
    let Some(socket) = socket_path(cli) else {
        eprintln!(
            "the control socket is off (control.socket = \"\" in {})",
            cli.config.display()
        );
        return Err(ExitCode::from(exit::UNREACHABLE));
    };
    let value = piano_ctl::call(&socket, cmd, timeout).map_err(|e| {
        eprintln!("{e}");
        match e {
            ClientError::Unreachable { .. } => ExitCode::from(exit::UNREACHABLE),
            _ => ExitCode::from(exit::RUNTIME),
        }
    })?;
    serde_json::from_value(value).map_err(|e| {
        eprintln!("unexpected reply from the daemon: {e}");
        ExitCode::from(exit::RUNTIME)
    })
}

fn print_json<T: serde::Serialize>(v: &T) {
    match serde_json::to_string_pretty(v) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("cannot encode the reply: {e}"),
    }
}

fn status(cli: &Cli) -> ExitCode {
    let status: Status = match ask(cli, "status", STATUS_TIMEOUT) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if cli.json {
        print_json(&status);
    } else {
        print!("{}", render::status(&status, render::color(cli.no_color)));
    }
    ExitCode::SUCCESS
}

fn reload(cli: &Cli) -> ExitCode {
    let reply: ReloadReply = match ask(cli, "reload", RELOAD_TIMEOUT) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if cli.json {
        print_json(&reply);
    } else {
        print!("{}", render::reload(&reply));
    }
    match (reply.ok, reply.config_error) {
        (true, _) => ExitCode::SUCCESS,
        (false, true) => ExitCode::from(exit::CONFIG),
        (false, false) => ExitCode::from(exit::RUNTIME),
    }
}

fn config_show(cli: &Cli) -> ExitCode {
    let config = match piano_config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    if cli.json {
        print_json(&config);
        return ExitCode::SUCCESS;
    }
    match config.effective_toml() {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("cannot write the configuration as TOML: {e}");
            ExitCode::from(exit::RUNTIME)
        }
    }
}

fn log(cli: &Cli, command: &LogCommand) -> ExitCode {
    let LogCommand::Tail {
        lines,
        follow,
        site,
        status,
        class,
        file,
    } = command;
    let filter = match logtail::Filter::new(site.clone(), status.as_deref(), class.clone()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    let path = match file {
        Some(f) => f.clone(),
        None => match piano_config::load(&cli.config) {
            Ok(c) => match c.log.access_path() {
                Some(p) => p.to_owned(),
                None => {
                    eprintln!(
                        "the access log is off (log.access = \"\" in {})",
                        cli.config.display()
                    );
                    return ExitCode::from(exit::CONFIG);
                }
            },
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(exit::CONFIG);
            }
        },
    };
    let out = logtail::Output {
        json: cli.json,
        color: render::color(cli.no_color),
    };
    match logtail::tail(&path, *lines, *follow, &filter, &out) {
        Ok(()) => ExitCode::SUCCESS,
        // The reader went away, as with `| head`.
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            ExitCode::from(exit::RUNTIME)
        }
    }
}

fn config_check(path: &Path) -> ExitCode {
    let config = match piano_config::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    if let Err(e) = piano_edge::tls::SniTable::load(&config) {
        eprintln!("{e}");
        return ExitCode::from(exit::CONFIG);
    }
    if let Err(e) = piano_upstream::tls::client_config(&config.upstream.extra_roots) {
        eprintln!("{e}");
        return ExitCode::from(exit::CONFIG);
    }
    let warnings = config.warnings();
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    println!("{}: ok ({} sites)", path.display(), config.sites.len());
    if warnings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(exit::WARNINGS)
    }
}

fn run(path: &Path, level_override: Option<log::LevelFilter>) -> ExitCode {
    let config = match piano_config::load(path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    if level_override.is_none() {
        piano_telemetry::logger::set_level(piano::level_filter(config.log.level));
    }
    for w in config.warnings() {
        log::warn!("{w}");
    }
    piano::raise_open_file_limit(&config);
    let piano::Daemon { mut server, live } = match piano::build(&config, Resolver::system()) {
        Ok(d) => d,
        Err(e) => {
            log::error!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    let control = match config.control.socket_path().map(piano_ctl::server::bind) {
        None => None,
        Some(Ok(bound)) => Some(bound),
        Some(Err(e)) => {
            log::error!("control socket: {e}");
            return ExitCode::from(exit::RUNTIME);
        }
    };
    let admin = piano::Admin::new(live, path.to_owned(), level_override);
    server.add_service(piano::Reloader::new(std::sync::Arc::clone(&admin)));
    if let Some(bound) = control {
        server.add_service(piano::ControlService::new(admin, bound));
    }
    log::info!(
        "piano {} serving {} sites on {}",
        env!("CARGO_PKG_VERSION"),
        config.sites.len(),
        config.server.listen.join(", ")
    );
    server.run(piano::RunArgs::default());
    ExitCode::SUCCESS
}
