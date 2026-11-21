//! The `piano` command: daemon and management tool in one binary.

#![forbid(unsafe_code)]

mod logtail;
mod render;
mod top;

use clap::{Parser, Subcommand};
use piano_ctl::ClientError;
use piano_ctl::proto::{CacheStats, PurgeReply, ReloadReply, Status, StopReply, UpgradeReply};
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
/// An upgrade checks the new binary, waits for it to load and to take the sockets.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(120);

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
    Run {
        /// Write the process id to this file once serving, and again after an upgrade
        /// (for OpenRC); removed at exit unless a successor took it over.
        #[arg(long)]
        pidfile: Option<PathBuf>,
        /// Take the listening sockets over from this process, which is upgrading. Used
        /// by `piano upgrade`.
        #[arg(long, hide = true)]
        takeover: Option<u32>,
    },
    /// Stop the daemon as SIGTERM does and wait until it has exited, together with a
    /// process it replaced that is still draining. Use as the service manager's stop
    /// command: after an upgrade the daemon is not the service manager's child, so it
    /// could not wait for it.
    Stop,
    /// Replace the running daemon by a new process without dropping streams: the new
    /// process takes over the listening sockets, the old one keeps its media streams
    /// until they end (server.drain_timeout at most). Also applies settings that need a
    /// restart.
    Upgrade {
        /// The new binary; by default the file the daemon was started from (a symlink
        /// resolved at startup), which may have been replaced since.
        #[arg(long)]
        binary: Option<PathBuf>,
    },
    /// Show what the running daemon is doing and anything that needs attention.
    Status,
    /// Reread the configuration file and certificates; the running configuration stays
    /// if the new one fails.
    Reload,
    /// Full-screen view of what the daemon is doing now: media streams, sites, upstream
    /// budgets and recent problems. --json prints one reply of the daemon instead.
    Top {
        /// Seconds between updates.
        #[arg(long, default_value_t = 1.0)]
        interval: f64,
    },
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
    /// Image cache commands.
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// Bytes relayed per site and kind: today, the last 7 and 30 days. Reads the traffic
    /// record, which the daemon writes once a minute; --json prints the record itself.
    Traffic {
        /// Also list the last N days one by one.
        #[arg(long, default_value_t = 0)]
        days: usize,
        /// Read this file instead of traffic.file.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Walk a site as an Emby client does and time each step: server info, and with
    /// --login the libraries, the latest item, its image, playback info and the first MiB
    /// of its stream. Goes through the relay on this host unless --direct.
    Probe {
        /// Site name or host.
        site: String,
        /// Log in with PIANO_PROBE_USER and PIANO_PROBE_PASSWORD, or the user and password
        /// as two lines on standard input; logs out at the end.
        #[arg(long)]
        login: bool,
        /// Go to the upstream itself, without the relay and the site's rules: what the
        /// upstream does with each --ua.
        #[arg(long)]
        direct: bool,
        /// Run the steps with this User-Agent; repeat to compare several.
        #[arg(long = "ua", value_name = "UA")]
        user_agents: Vec<String>,
    },
    /// Check what status cannot see: whether the daemon could start (configuration,
    /// certificate, files the service user reads and writes, listening ports), whether
    /// the configuration, certificate and binary on disk are the ones running, and
    /// whether every upstream host completes a TLS handshake now.
    Doctor {
        /// The service user, when no daemon runs to take it from.
        #[arg(long, default_value = "piano")]
        user: String,
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
enum CacheCommand {
    /// How image requests were answered, memory in use and each upstream's budget.
    Stats,
    /// Forget stored images, remembered redirects and remembered misses.
    Purge,
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
        Command::Top { interval } => top(&cli, interval),
        Command::Config {
            command: ConfigCommand::Check,
        } => config_check(&cli.config),
        Command::Config {
            command: ConfigCommand::Show,
        } => config_show(&cli),
        Command::Log { ref command } => log(&cli, command),
        Command::Traffic { days, ref file } => traffic(&cli, days, file.as_deref()),
        Command::Cache {
            command: CacheCommand::Stats,
        } => cache_stats(&cli),
        Command::Cache {
            command: CacheCommand::Purge,
        } => cache_purge(&cli),
        Command::Upgrade { ref binary } => upgrade(&cli, binary.as_deref()),
        Command::Stop => stop(&cli),
        Command::Doctor { ref user } => doctor(&cli, user),
        Command::Probe {
            ref site,
            login,
            direct,
            ref user_agents,
        } => probe(&cli, site, login, direct, user_agents),
        Command::Run {
            ref pidfile,
            takeover,
        } => {
            let level = level_override.unwrap_or(log::LevelFilter::Info);
            if let Err(e) = piano_telemetry::logger::init(level) {
                eprintln!("cannot install logger: {e}");
                return ExitCode::from(exit::RUNTIME);
            }
            let relaunch = piano::upgrade::Relaunch {
                exe: exe_path(),
                config: absolute(&cli.config),
                log_level: cli.log_level.clone(),
                pidfile: pidfile.as_deref().map(absolute),
            };
            run(&relaunch, level_override, takeover)
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
/// setting, which defaults when the file leaves it out. `None` when the file turns the
/// socket off. A file that cannot be read is an error, not a reason to try the default:
/// with several instances on a host, the default belongs to another one.
fn socket_path(cli: &Cli) -> Result<Option<PathBuf>, piano_config::Error> {
    if let Some(s) = &cli.socket {
        return Ok(Some(s.clone()));
    }
    piano_config::load_control(&cli.config).map(|c| c.socket_path().map(Path::to_owned))
}

/// The socket of the daemon to talk to, or the message and exit code why there is none.
fn daemon_socket(cli: &Cli) -> Result<PathBuf, ExitCode> {
    match socket_path(cli) {
        Ok(Some(socket)) => Ok(socket),
        Ok(None) => {
            eprintln!(
                "the control socket is off (control.socket = \"\" in {})",
                cli.config.display()
            );
            Err(ExitCode::from(exit::UNREACHABLE))
        }
        Err(e) => {
            eprintln!("{}", e.to_string().trim_end());
            eprintln!("cannot tell which control socket to use; give it with --socket");
            Err(ExitCode::from(exit::CONFIG))
        }
    }
}

/// Sends `cmd` and decodes the reply, or reports the failure and the exit code.
fn ask<T: serde::de::DeserializeOwned>(
    cli: &Cli,
    cmd: &str,
    timeout: Duration,
) -> Result<T, ExitCode> {
    let socket = daemon_socket(cli)?;
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

/// Longest the doctor may run; each upstream host has 10 s.
const DOCTOR_TIMEOUT: Duration = Duration::from_secs(120);

fn doctor(cli: &Cli, user: &str) -> ExitCode {
    use piano::doctor::Level;
    // A daemon that does not answer is one of the findings, not a failure.
    let socket = socket_path(cli).ok().flatten();
    let status: Option<Status> = socket.as_ref().and_then(|socket| {
        let value = piano_ctl::call(socket, "status", STATUS_TIMEOUT).ok()?;
        serde_json::from_value(value).ok()
    });
    // What `piano upgrade` would run (the file at the daemon's path), and this command's
    // binary, which is usually what the service manager starts.
    let mut paths: Vec<(PathBuf, bool)> = status
        .as_ref()
        .and_then(|s| piano::doctor::started_from(s.pid))
        .map(|path| (path, true))
        .into_iter()
        .collect();
    if let Ok(exe) = std::env::current_exe()
        && !paths.iter().any(|(p, _)| *p == exe)
    {
        paths.push((exe, false));
    }
    let installed = paths
        .into_iter()
        .map(|(path, started_from)| piano::doctor::Installed {
            sha256: piano::doctor::file_sha256(&path).map_err(|e| e.to_string()),
            path,
            started_from,
        })
        .collect();
    let input = piano::doctor::Input {
        config: &cli.config,
        status: status.as_ref(),
        socket: socket.as_deref(),
        user,
        installed,
        resolver: Resolver::system(),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot start the runtime: {e}");
            return ExitCode::from(exit::RUNTIME);
        }
    };
    let Ok(report) = runtime
        .block_on(async { tokio::time::timeout(DOCTOR_TIMEOUT, piano::doctor::run(&input)).await })
    else {
        eprintln!(
            "the checks did not end within {}s",
            DOCTOR_TIMEOUT.as_secs()
        );
        return ExitCode::from(exit::RUNTIME);
    };
    if cli.json {
        print_json(&report);
    } else {
        print!("{}", render::doctor(&report, render::color(cli.no_color)));
    }
    match report.worst() {
        _ if report.config_failed() => ExitCode::from(exit::CONFIG),
        Level::Error => ExitCode::from(exit::RUNTIME),
        Level::Warn => ExitCode::from(exit::WARNINGS),
        Level::Ok | Level::Skip => ExitCode::SUCCESS,
    }
}

/// Longest a probe may run, every step and User-Agent together.
const PROBE_TIMEOUT: Duration = Duration::from_secs(600);

fn probe(cli: &Cli, site: &str, login: bool, direct: bool, user_agents: &[String]) -> ExitCode {
    let config = match piano_config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    let login = if login {
        match probe_credentials() {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(exit::CONFIG);
            }
        }
    } else {
        None
    };
    let args = piano::probe::Args {
        site: site.to_owned(),
        login,
        direct,
        user_agents: user_agents.to_vec(),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot start the runtime: {e}");
            return ExitCode::from(exit::RUNTIME);
        }
    };
    let resolver = Resolver::system();
    let ran = runtime.block_on(async {
        tokio::time::timeout(PROBE_TIMEOUT, piano::probe::run(&config, &resolver, &args)).await
    });
    let report = match ran {
        Ok(Ok(r)) => r,
        Ok(Err(
            e @ (piano::probe::Error::UnknownSite(_)
            | piano::probe::Error::Listen(_)
            | piano::probe::Error::Tls(_)),
        )) => {
            eprintln!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
        Ok(Err(e)) => {
            eprintln!("{e}");
            return ExitCode::from(exit::RUNTIME);
        }
        Err(_) => {
            eprintln!("the probe did not end within {}s", PROBE_TIMEOUT.as_secs());
            return ExitCode::from(exit::RUNTIME);
        }
    };
    if cli.json {
        print_json(&report);
    } else {
        print!("{}", render::probe(&report, render::color(cli.no_color)));
    }
    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(exit::RUNTIME)
    }
}

/// The account for `probe --login`: from the environment, else two lines on standard
/// input (never the command line, which other users can read).
fn probe_credentials() -> Result<piano::probe::Credentials, String> {
    use std::io::{BufRead, IsTerminal};
    if let (Ok(user), Ok(password)) = (
        std::env::var("PIANO_PROBE_USER"),
        std::env::var("PIANO_PROBE_PASSWORD"),
    ) {
        return Ok(piano::probe::Credentials { user, password });
    }
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(
            "--login needs PIANO_PROBE_USER and PIANO_PROBE_PASSWORD, or the user and the \
             password as two lines on standard input"
                .into(),
        );
    }
    let mut lines = stdin.lock().lines();
    let mut next = || -> Result<String, String> {
        match lines.next() {
            Some(Ok(l)) => Ok(l.trim_end_matches('\r').to_owned()),
            Some(Err(e)) => Err(format!("standard input: {e}")),
            None => Err("--login: expected the user and the password on standard input".into()),
        }
    };
    let user = next()?;
    let password = next()?;
    Ok(piano::probe::Credentials { user, password })
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

/// Shortest interval for `top`: each update asks the daemon and redraws the screen.
const MIN_INTERVAL: f64 = 0.2;

fn top(cli: &Cli, interval: f64) -> ExitCode {
    if !interval.is_finite() || interval < MIN_INTERVAL {
        eprintln!("--interval must be at least {MIN_INTERVAL} seconds");
        return ExitCode::from(exit::CONFIG);
    }
    if cli.json {
        let live: piano_ctl::proto::Live = match ask(cli, "live", STATUS_TIMEOUT) {
            Ok(l) => l,
            Err(code) => return code,
        };
        print_json(&live);
        return ExitCode::SUCCESS;
    }
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        eprintln!("piano top needs a terminal; piano top --json prints one reply");
        return ExitCode::from(exit::CONFIG);
    }
    let socket = match daemon_socket(cli) {
        Ok(s) => s,
        Err(code) => return code,
    };
    // Fail before taking over the screen when the daemon is not there at all.
    if let Err(e) = top::ask(&socket, STATUS_TIMEOUT) {
        eprintln!("{e}");
        return ExitCode::from(exit::UNREACHABLE);
    }
    let opts = top::Options {
        socket,
        interval: Duration::from_secs_f64(interval),
    };
    match top::run(&opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("terminal: {e}");
            ExitCode::from(exit::RUNTIME)
        }
    }
}

/// The binary as `/proc/self/exe` names it (symlinks resolved): a file installed over it
/// later is what an upgrade runs. Without `/proc`, `piano` as found on PATH.
fn exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("piano"))
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_owned())
}

/// Extra time `stop` allows beyond the daemon's own limit, for its exit itself.
const STOP_MARGIN: Duration = Duration::from_secs(5);

fn stop(cli: &Cli) -> ExitCode {
    let reply: StopReply = match ask(cli, "stop", STATUS_TIMEOUT) {
        Ok(r) => r,
        Err(code) => return code,
    };
    // The process an upgrade replaced gets the signal passed on and stops within the same
    // limit. It no longer listens, but waiting for it lets its last access log lines and
    // traffic record be written before the service manager deals with what is left.
    let limit = Duration::from_secs(reply.limit_secs) + STOP_MARGIN;
    let deadline = std::time::Instant::now() + limit;
    let pids: Vec<u32> = std::iter::once(reply.pid)
        .chain(reply.draining_pid)
        .collect();
    loop {
        let left: Vec<u32> = pids
            .iter()
            .copied()
            .filter(|p| Path::new(&format!("/proc/{p}")).exists())
            .collect();
        if left.is_empty() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let left: Vec<String> = left.iter().map(u32::to_string).collect();
            eprintln!(
                "pid {} still running {}s after it was asked to stop",
                left.join(", "),
                limit.as_secs()
            );
            return ExitCode::from(exit::RUNTIME);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if cli.json {
        print_json(&reply);
    } else {
        println!("pid {} stopped", reply.pid);
    }
    ExitCode::SUCCESS
}

fn upgrade(cli: &Cli, binary: Option<&Path>) -> ExitCode {
    let cmd = match binary {
        None => "upgrade".to_owned(),
        Some(b) => match std::fs::canonicalize(b) {
            Ok(b) => format!("upgrade {}", b.display()),
            Err(e) => {
                eprintln!("{}: {e}", b.display());
                return ExitCode::from(exit::RUNTIME);
            }
        },
    };
    let reply: UpgradeReply = match ask(cli, &cmd, UPGRADE_TIMEOUT) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if cli.json {
        print_json(&reply);
    } else {
        print!("{}", render::upgrade(&reply));
    }
    match (reply.ok, reply.config_error) {
        (true, _) => ExitCode::SUCCESS,
        (false, true) => ExitCode::from(exit::CONFIG),
        (false, false) => ExitCode::from(exit::RUNTIME),
    }
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

fn cache_stats(cli: &Cli) -> ExitCode {
    let stats: CacheStats = match ask(cli, "cache", STATUS_TIMEOUT) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if cli.json {
        print_json(&stats);
    } else {
        print!("{}", render::cache(&stats));
    }
    ExitCode::SUCCESS
}

fn cache_purge(cli: &Cli) -> ExitCode {
    let reply: PurgeReply = match ask(cli, "cache purge", STATUS_TIMEOUT) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if cli.json {
        print_json(&reply);
    } else {
        println!(
            "purged {} images, {} remembered misses, {} remembered redirects",
            reply.images, reply.missing, reply.redirects
        );
    }
    ExitCode::SUCCESS
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
                // Another file may come from another configuration; only this one's
                // site names are known.
                Some(_)
                    if let Some(s) = site
                        && !c.sites.iter().any(|x| &x.name == s) =>
                {
                    let names: Vec<&str> = c.sites.iter().map(|x| x.name.as_str()).collect();
                    eprintln!(
                        "--site {s:?}: no such site in {} (sites: {})",
                        cli.config.display(),
                        names.join(", ")
                    );
                    return ExitCode::from(exit::CONFIG);
                }
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

fn traffic(cli: &Cli, days: usize, file: Option<&Path>) -> ExitCode {
    let path = match file {
        Some(f) => f.to_owned(),
        None => match piano_config::load(&cli.config) {
            Ok(c) => match c.traffic.file_path() {
                Some(p) => p.to_owned(),
                None => {
                    eprintln!(
                        "no traffic is recorded (traffic.file = \"\" in {})",
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
    let record = match piano::traffic::read(&path) {
        Ok(Some(r)) => r,
        Ok(None) => {
            eprintln!(
                "{}: no traffic recorded yet; the daemon writes it once a minute",
                path.display()
            );
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(exit::RUNTIME);
        }
    };
    if cli.json {
        print_json(&record);
        return ExitCode::SUCCESS;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let local = chrono::Local::now();
    print!(
        "{}",
        render::traffic(
            &record,
            &path.display().to_string(),
            local.date_naive(),
            local.fixed_offset().timezone(),
            now,
            days
        )
    );
    ExitCode::SUCCESS
}

fn config_check(path: &Path) -> ExitCode {
    let config = match piano_config::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    let table = match piano_edge::tls::SniTable::load(&config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    if let Err(e) = piano_upstream::tls::client_config(&config.upstream.extra_roots) {
        eprintln!("{e}");
        return ExitCode::from(exit::CONFIG);
    }
    let mut warnings: Vec<String> = config.warnings().iter().map(ToString::to_string).collect();
    if table.info().incomplete_chain {
        warnings.push(format!(
            "{}: {}",
            config.tls.cert.display(),
            piano_edge::tls::INCOMPLETE_CHAIN
        ));
    }
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

fn run(
    relaunch: &piano::upgrade::Relaunch,
    level_override: Option<log::LevelFilter>,
    takeover: Option<u32>,
) -> ExitCode {
    let path = &relaunch.config;
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
    let built = piano::build_with(&config, Resolver::system(), takeover);
    let piano::Daemon { mut server, live } = match built {
        Ok(d) => d,
        Err(e) => {
            log::error!("{e}");
            // An upstream that does not resolve may at the next start; the service
            // manager restarts on any code but the configuration one.
            let code = if e.is_config() {
                exit::CONFIG
            } else {
                exit::RUNTIME
            };
            return ExitCode::from(code);
        }
    };
    // Taking over, the old process still listens on the control socket.
    let bind = if takeover.is_some() {
        piano_ctl::server::bind_unpublished
    } else {
        piano_ctl::server::bind
    };
    let control = match config.control.socket_path().map(bind) {
        None => None,
        Some(Ok(bound)) => Some(bound),
        Some(Err(e)) => {
            log::error!("control socket: {e}");
            return ExitCode::from(exit::RUNTIME);
        }
    };
    let admin = piano::Admin::new(
        std::sync::Arc::clone(&live),
        path.to_owned(),
        level_override,
    );
    admin.set_relaunch(relaunch.clone());
    server.add_service(piano::Reloader::new(std::sync::Arc::clone(&admin)));
    server.add_service(piano::upgrade::ReadyService::new(
        std::sync::Arc::clone(&live),
        relaunch.pidfile.clone(),
    ));
    if let Some(bound) = control {
        server.add_service(piano::ControlService::new(admin, bound));
    }
    log::info!(
        "piano {} serving {} sites on {}",
        env!("CARGO_PKG_VERSION"),
        config.sites.len(),
        config.server.listen.join(", ")
    );
    server.run(piano::RunArgs {
        shutdown_signal: live.signals(Box::new(piano::UnixShutdownSignalWatch)),
    });
    live.stopped();
    if let Some(p) = &relaunch.pidfile {
        piano::upgrade::remove_pidfile(p);
    }
    log::info!("stopped");
    ExitCode::SUCCESS
}
