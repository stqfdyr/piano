//! The `piano` command: daemon and management tool in one binary.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use piano_upstream::Resolver;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Exit codes shared by all commands.
mod exit {
    pub const RUNTIME: u8 = 1;
    pub const CONFIG: u8 = 2;
}

#[derive(Parser)]
#[command(name = "piano", version, about = "Emby relay")]
struct Cli {
    /// Configuration file.
    #[arg(short, long, global = true, default_value = piano_config::DEFAULT_PATH)]
    config: PathBuf,
    /// Diagnostic log level: error, warn, info, debug or trace.
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon in the foreground.
    Run,
    /// Configuration commands.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Print the version.
    Version {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Parse and validate the configuration without starting anything.
    Check,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(level) = piano_telemetry::logger::parse_level(&cli.log_level) else {
        eprintln!("invalid --log-level {:?}", cli.log_level);
        return ExitCode::from(exit::CONFIG);
    };
    match cli.command {
        Command::Version { json } => {
            version(json);
            ExitCode::SUCCESS
        }
        Command::Config {
            command: ConfigCommand::Check,
        } => config_check(&cli.config),
        Command::Run => {
            if let Err(e) = piano_telemetry::logger::init(level) {
                eprintln!("cannot install logger: {e}");
                return ExitCode::from(exit::RUNTIME);
            }
            run(&cli.config)
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

fn config_check(path: &std::path::Path) -> ExitCode {
    let config = match piano_config::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    if let Err(e) = piano_edge::tls::server_config(&config) {
        eprintln!("{e}");
        return ExitCode::from(exit::CONFIG);
    }
    if let Err(e) = piano_upstream::tls::client_config(&config.upstream.extra_roots) {
        eprintln!("{e}");
        return ExitCode::from(exit::CONFIG);
    }
    println!("{}: ok ({} sites)", path.display(), config.sites.len());
    ExitCode::SUCCESS
}

fn run(path: &std::path::Path) -> ExitCode {
    let config = match piano_config::load(path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    let server = match piano::build_server(&config, &Resolver::system()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    log::info!(
        "piano {} serving {} sites on {}",
        env!("CARGO_PKG_VERSION"),
        config.sites.len(),
        config.server.listen.join(", ")
    );
    server.run(piano::RunArgs::default());
    ExitCode::SUCCESS
}
