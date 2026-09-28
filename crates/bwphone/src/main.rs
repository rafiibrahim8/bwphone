use std::{
    io::{BufRead as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use bwphone::{
    Ctx,
    accounts::{Accounts, id_hex},
    control::ControlRequest,
    enroll::{self, EnrollOptions, KeySource},
    hostname, manifests, no_core_dumps,
    notify::Notifier,
    pair::{self, PairOptions, Ui},
    pairing::Pairing,
    paths::Paths,
    phone::Phone,
    secrets::Secrets,
    socket, unlock,
};
use clap::{CommandFactory as _, Parser, Subcommand};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::UnixStream,
};

#[derive(Parser)]
#[command(
    name = "bwphone",
    version,
    about = "Phone-gated Bitwarden unlock",
    long_about = "The bwphone daemon and command line. The daemon serves the Bitwarden browser \
extensions over native messaging and releases the vault key only after an emoji pick and a \
fingerprint on the paired phone. The other subcommands pair the phone, enrol accounts, \
write the browsers' manifests and query the running daemon."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (the default).
    Daemon {
        /// Log to stderr instead of the state directory.
        #[arg(long)]
        foreground: bool,
    },
    /// What the daemon knows: pairing, wallet, phone, accounts.
    Status,
    /// A real unlock, emoji pick and fingerprint included; prints the user
    /// key's SHA-256 fingerprint, never the key.
    Unlock {
        #[arg(long)]
        label: String,
        /// Accepted for the spec's wording; an unlock through this command
        /// never prints the key either way.
        #[arg(long)]
        dry_run: bool,
    },
    /// Hand the daemon the phone's address, as `bwphone-hello` does.
    Hello { ip: IpAddr, port: u16, seq: u64 },
    /// Forget the last hello sequence number, if hellos are being refused as stale.
    HelloReset,
    /// Pair with the phone: a QR code here, six words on both screens.
    Pair {
        /// This PC's LAN address for the QR; detected if omitted.
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        /// Port to accept the phone on; a free one if omitted.
        #[arg(long, default_value_t = 0)]
        pair_port: u16,
        /// Port `bwphone-hello` will listen on.
        #[arg(long, default_value_t = bwphone_transport::DEFAULT_HELLO_PORT)]
        hello_port: u16,
        /// Replace an existing pairing (after Revoke all on the phone).
        #[arg(long)]
        replace: bool,
    },
    /// Enrol one Bitwarden account: the phone creates its key, the user key
    /// is wrapped to it, and a full unwrap is proven before anything is destroyed.
    Enroll {
        /// The name shown in prompts and used by `unlock --label`.
        #[arg(long)]
        label: String,
        /// A BW_SESSION key you already have, e.g. `--from-arg (bw unlock --raw)`.
        /// Note: an argument is visible in /proc/<pid>/cmdline to other local users
        /// while enroll runs; `--from-stdin` is not.
        #[arg(long, value_name = "BW_SESSION", conflicts_with_all = ["from_stdin", "test_user_key"])]
        from_arg: Option<String>,
        /// Read a BW_SESSION key from stdin: `bw unlock --raw | bwphone enroll --label Work --from-stdin`.
        #[arg(long, conflicts_with = "test_user_key")]
        from_stdin: bool,
        /// The CLI's data directory; defaults to $BITWARDENCLI_APPDATA_DIR. Put it on /dev/shm.
        #[arg(long)]
        appdata_dir: Option<PathBuf>,
        /// The phone's address, if no hello has arrived yet.
        #[arg(long)]
        phone: Option<SocketAddr>,
        /// TESTING ONLY: enrol this 64-byte key (base64) instead of a real
        /// vault key, so the phone path can be exercised without Bitwarden.
        #[arg(long, value_name = "BASE64")]
        test_user_key: Option<String>,
        /// TESTING ONLY: the Bitwarden userId to route for, with --test-user-key.
        #[arg(long, default_value = "test-user", value_name = "ID")]
        test_user_id: String,
    },
    /// Enrolled accounts.
    #[command(subcommand)]
    Account(AccountCommand),
    /// The browsers' native-messaging manifests.
    #[command(subcommand)]
    Manifests(ManifestsCommand),
    /// Print a shell completion script (bash, zsh, fish, elvish, powershell).
    #[command(hide = true)]
    Completions { shell: clap_complete::Shell },
    /// Write the man pages (bwphone.1 and one per subcommand) into a directory.
    #[command(hide = true)]
    Manpages { out_dir: PathBuf },
}

#[derive(Subcommand)]
enum AccountCommand {
    List,
    /// Delete an account's directory here; revoke it on the phone as well.
    Remove { label: String },
}

#[derive(Subcommand)]
enum ManifestsCommand {
    /// Write `com.8bit.bitwarden.json` for every installed browser.
    Write {
        /// Path the manifests point at.
        #[arg(long)]
        proxy: Option<PathBuf>,
    },
    /// Report manifests that no longer point at bwphone-proxy.
    Check {
        #[arg(long)]
        proxy: Option<PathBuf>,
    },
}

/// The daemons read pairing.json, the wallet and the accounts once at
/// start, so the commands that change those restart what they affect.
/// Only units that are running are touched; nothing is started.
fn restart_units(units: &[&str]) {
    let running: Vec<&str> = units
        .iter()
        .copied()
        .filter(|u| {
            std::process::Command::new("systemctl")
                .args(["--user", "--quiet", "is-active", u])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
        .collect();
    if running.is_empty() {
        println!("(no bwphone units running; nothing restarted)");
        return;
    }
    let status = std::process::Command::new("systemctl").arg("--user").arg("restart").args(&running).status();
    match status {
        Ok(s) if s.success() => println!("Restarted {}.", running.join(" and ")),
        _ => println!("Could not restart {}; run `systemctl --user restart {}` yourself.", running.join(" and "), running.join(" ")),
    }
}

struct Terminal;

impl Ui for Terminal {
    fn show(&mut self, text: &str) {
        println!("{text}");
    }

    /// Reads the answer from the terminal itself, so it still works when
    /// stdin is a pipe (`--from-stdin`).
    fn confirm(&mut self, question: &str) -> bool {
        print!("{question} [y/N] ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::fs::File::open("/dev/tty") {
            Ok(tty) => {
                let _ = std::io::BufReader::new(tty).read_line(&mut line);
            }
            Err(_) => {
                let _ = std::io::stdin().lock().read_line(&mut line);
            }
        }
        matches!(line.trim(), "y" | "Y" | "yes")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Every subcommand, before anything else: `pair` holds the Noise key and
    // `enroll` the plaintext user key, so neither may ever land in a core dump.
    if !no_core_dumps() {
        eprintln!("bwphone: could not disable core dumps; refusing to handle secrets");
        std::process::exit(1);
    }
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Daemon { foreground: false }) {
        Command::Daemon { foreground } => daemon(foreground).await,
        Command::Status => control(ControlRequest::Status).await,
        Command::Unlock { label, dry_run: _ } => control(ControlRequest::Unlock { label }).await,
        Command::Hello { ip, port, seq } => control(ControlRequest::Hello { ip, port, seq }).await,
        Command::HelloReset => control(ControlRequest::ResetHello).await,
        Command::Pair { ip, pair_port, hello_port, replace } => {
            let paths = Paths::from_env()?;
            pair::run(&paths, PairOptions { ip, pair_port, hello_port, replace }, &mut Terminal).await?;
            // A new Noise key and hello key: both daemons must reread the wallet.
            restart_units(&["bwphone", "bwphone-hello"]);
            Ok(())
        }
        Command::Enroll { label, from_arg, from_stdin, appdata_dir, phone, test_user_key, test_user_id } => {
            let paths = Paths::from_env()?;
            let cli_dir = || {
                appdata_dir
                    .clone()
                    .or_else(|| std::env::var_os("BITWARDENCLI_APPDATA_DIR").map(PathBuf::from))
                    .ok_or("set BITWARDENCLI_APPDATA_DIR (on /dev/shm) or pass --appdata-dir")
            };
            let session_from = |text: &str| -> Result<bwphone_nm::session::SessionKey, Box<dyn std::error::Error>> {
                let mut raw = zeroize::Zeroizing::new(bwphone_transport::unb64(text.trim()).map_err(|_| "the session key is not base64")?);
                let key = bwphone_nm::session::SessionKey::from_slice(&raw).ok_or("the session key must decode to 64 bytes");
                zeroize::Zeroize::zeroize(&mut *raw);
                Ok(key?)
            };
            let source = if let Some(mut text) = from_arg {
                let session = session_from(&text);
                zeroize::Zeroize::zeroize(&mut text);
                KeySource::Session { appdata_dir: cli_dir()?, session: session? }
            } else if from_stdin {
                let mut text = zeroize::Zeroizing::new(String::new());
                std::io::stdin().lock().read_line(&mut text)?;
                KeySource::Session { appdata_dir: cli_dir()?, session: session_from(&text)? }
            } else if let Some(b64) = test_user_key {
                let raw = bwphone_transport::unb64(b64.trim()).map_err(|_| "--test-user-key is not base64")?;
                let user_key = bwphone_wrap::UserKey::from_slice(&raw).ok_or("--test-user-key must decode to 64 bytes")?;
                eprintln!("bwphone: enrolling a TEST key, not a vault key");
                KeySource::Given { user_id: test_user_id, user_key }
            } else {
                return Err("pipe the session key in: `bw unlock --raw | bwphone enroll --label <name> --from-stdin` (or --from-arg <BW_SESSION>; --test-user-key is for testing only)".into());
            };
            enroll::run(&paths, EnrollOptions { label, source, phone_addr: phone }, &mut Terminal).await?;
            restart_units(&["bwphone", "bwphone-hello"]);
            Ok(())
        }
        Command::Account(AccountCommand::List) => {
            let paths = Paths::from_env()?;
            let accounts = Accounts::load(&paths.accounts())?;
            for a in accounts.iter() {
                println!("{:<16} {:<40} {}", a.label, a.user_id, id_hex(&a.id));
            }
            for r in accounts.retired() {
                println!(
                    "{:<16} {:<40} {}  retired vault.blob 0x{:02x}: remove it, revoke it on the phone, enrol again",
                    r.label, r.user_id, id_hex(&r.id), r.version
                );
            }
            Ok(())
        }
        Command::Account(AccountCommand::Remove { label }) => {
            let paths = Paths::from_env()?;
            let accounts = Accounts::load(&paths.accounts())?;
            let id = accounts.id_for_label(&label).ok_or_else(|| format!("no account labelled {label}"))?;
            std::fs::remove_dir_all(paths.accounts().join(id_hex(&id)))?;
            println!("Removed {label}. Revoke it on the phone too.");
            restart_units(&["bwphone", "bwphone-hello"]);
            Ok(())
        }
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "bwphone", &mut std::io::stdout());
            Ok(())
        }
        Command::Manpages { out_dir } => {
            std::fs::create_dir_all(&out_dir)?;
            clap_mangen::generate_to(Cli::command(), &out_dir)?;
            Ok(())
        }
        Command::Manifests(cmd) => {
            let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?);
            match cmd {
                ManifestsCommand::Write { proxy } => {
                    let proxy = proxy.unwrap_or_else(|| manifests::default_proxy_path(&home));
                    for b in manifests::write_all(&home, &proxy)? {
                        println!("{:<10} {}", b.name, b.manifest.display());
                    }
                    Ok(())
                }
                ManifestsCommand::Check { proxy } => {
                    let proxy = proxy.unwrap_or_else(|| manifests::default_proxy_path(&home));
                    let problems = manifests::check_all(&home, &proxy);
                    for (b, what) in &problems {
                        println!("{:<10} {} {what}", b.name, b.manifest.display());
                    }
                    if problems.is_empty() { Ok(()) } else { std::process::exit(1) }
                }
            }
        }
    }
}

async fn daemon(foreground: bool) -> Result<(), Box<dyn std::error::Error>> {
    let paths = Paths::from_env()?;
    std::fs::create_dir_all(&paths.state)?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if foreground {
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
    } else {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(paths.log())?;
        tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(log).init();
    }

    let pairing = Pairing::load(&paths.pairing())?;
    let accounts = Accounts::load(&paths.accounts())?;
    let (phone, state) = match &pairing {
        Some(p) => (
            Phone { public: p.phone_pub()?, pairing_id: p.pairing_id()?, host: hostname() },
            unlock::PhoneState { addr: p.last_address.map(|ip| (ip, p.phone_port).into()), ..Default::default() },
        ),
        None => {
            tracing::warn!("not paired: serving unavailable until `bwphone pair` has run");
            (Phone { public: [0; 32], pairing_id: [0; 16], host: hostname() }, unlock::PhoneState::default())
        }
    };
    tracing::info!(accounts = accounts.iter().count(), paired = pairing.is_some(), "starting");
    let retired: Vec<String> = accounts.retired().map(|r| r.label.clone()).collect();
    for r in accounts.retired() {
        tracing::warn!(label = %r.label, version = r.version, "retired vault.blob: not served");
    }

    let (config, config_problem) = bwphone::config::Config::load(&paths.config_file());
    if let Some(why) = &config_problem {
        tracing::warn!("config: {why}");
    }
    tracing::info!(
        notification = config.indicator.notification,
        tray = config.indicator.tray,
        tray_idle = ?config.indicator.tray_idle,
        "indicator"
    );
    let notifier = match bwphone::notify::DBusNotifier::connect(&config.indicator).await {
        Ok(n) => Notifier::DBus(n),
        Err(e) => {
            tracing::warn!("no session bus for notifications: {e}");
            Notifier::Silent
        }
    };

    // The real desktop app overwrites our manifests under the same name.
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let proxy = manifests::default_proxy_path(&home);
        let problems = manifests::check_all(&home, &proxy);
        if !problems.is_empty() {
            let list = problems.iter().map(|(b, what)| format!("{}: {what}", b.name)).collect::<Vec<_>>().join("; ");
            notifier.warn("bwphone: a browser manifest no longer points at bwphone-proxy", &format!("{list}. Run `bwphone manifests write`.")).await;
        }
    }

    if !retired.is_empty() {
        let names = retired.join(", ");
        notifier
            .warn(
                "bwphone: an account needs enrolling again",
                &format!(
                    "{names}: the vault file is in an old format that phones below Android 14 cannot open, so it is not offered. \
                     Run `bwphone account remove <label>`, revoke it on the phone, and enrol it again."
                ),
            )
            .await;
    }

    let ctx = Arc::new(Ctx {
        accounts,
        phone,
        state: std::sync::Mutex::new(state),
        secrets: Secrets::wallet(),
        notifier,
        queue: unlock::Queue::default(),
        pairing: std::sync::Mutex::new(pairing),
        pairing_path: Some(paths.pairing()),
    });
    tokio::spawn(unlock::worker(ctx.clone()));

    let proxies = socket::bind_private(&paths.proxy_socket()).await?;
    let controls = socket::bind_private(&paths.control_socket()).await?;
    let hellos = socket::bind_private(&paths.hello_socket()).await?;
    tracing::info!(sock = %paths.proxy_socket().display(), ctl = %paths.control_socket().display(), hello = %paths.hello_socket().display(), "listening");

    let accept_proxies = {
        let ctx = ctx.clone();
        async move {
            loop {
                let Ok((stream, _)) = proxies.accept().await else { continue };
                if !socket::same_uid(&stream) {
                    tracing::warn!("proxy socket: rejected a peer with another uid");
                    continue;
                }
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = bwphone::serve::serve_proxy(stream, ctx).await {
                        tracing::info!("browser connection ended: {e}");
                    }
                });
            }
        }
    };
    let accept_controls = {
        let ctx = ctx.clone();
        async move {
            loop {
                let Ok((stream, _)) = controls.accept().await else { continue };
                if !socket::same_uid(&stream) {
                    tracing::warn!("control socket: rejected a peer with another uid");
                    continue;
                }
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = bwphone::control::serve_control(stream, ctx).await {
                        tracing::info!("control connection ended: {e}");
                    }
                });
            }
        }
    };

    let accept_hellos = {
        let ctx = ctx.clone();
        async move {
            loop {
                let Ok((stream, _)) = hellos.accept().await else { continue };
                if !socket::same_uid(&stream) {
                    tracing::warn!("hello socket: rejected a peer with another uid");
                    continue;
                }
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = bwphone::hellosock::serve_hello_socket(stream, ctx).await {
                        tracing::info!("hello connection ended: {e}");
                    }
                });
            }
        }
    };

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = accept_proxies => {}
        _ = accept_controls => {}
        _ = accept_hellos => {}
        _ = term.recv() => tracing::info!("SIGTERM"),
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
    }
    let _ = std::fs::remove_file(paths.proxy_socket());
    let _ = std::fs::remove_file(paths.control_socket());
    let _ = std::fs::remove_file(paths.hello_socket());
    Ok(())
}

async fn control(request: ControlRequest) -> Result<(), Box<dyn std::error::Error>> {
    let paths = Paths::from_env()?;
    let stream = UnixStream::connect(paths.control_socket())
        .await
        .map_err(|e| format!("cannot reach the daemon at {}: {e}", paths.control_socket().display()))?;
    let mut stream = BufReader::new(stream);
    let mut line = serde_json::to_vec(&request)?;
    line.push(b'\n');
    stream.get_mut().write_all(&line).await?;
    let mut reply = String::new();
    stream.read_line(&mut reply).await?;
    let value: serde_json::Value = serde_json::from_str(reply.trim())?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    if value.get("ok") == Some(&serde_json::Value::Bool(true)) { Ok(()) } else { std::process::exit(1) }
}
