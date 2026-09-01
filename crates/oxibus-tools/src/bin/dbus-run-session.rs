// Runs a command inside a private session bus.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut command: Vec<String> = Vec::new();
    let mut dbus_daemon: Option<String> = None;
    let mut config_file: Option<String> = None;
    let mut address: Option<String> = None;
    let mut print_address = false;

    while let Some(a) = args.peek() {
        match a.as_str() {
            "--" => {
                args.next();
                command.extend(args);
                break;
            }
            "--session" | "--nofork" => {
                // --session is already what we do; --nofork is already how
                // we run the private daemon. Accepted for compatibility.
                args.next();
            }
            "--print-address" => {
                print_address = true;
                args.next();
            }
            "--dbus-daemon" => {
                args.next();
                dbus_daemon = args.next();
            }
            "--config-file" => {
                args.next();
                config_file = args.next();
            }
            "--address" => {
                args.next();
                address = args.next();
            }
            "--version" => {
                println!("dbus-run-session (oxibus) {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "Usage: dbus-run-session [--dbus-daemon=BINARY] [--config-file=FILE] \
                     [--address=ADDRESS] [--print-address] -- COMMAND [ARGS...]"
                );
                return Ok(());
            }
            _ => {
                command.push(args.next().unwrap());
            }
        }
    }
    if command.is_empty() {
        anyhow::bail!("usage: dbus-run-session -- COMMAND [ARGS...]");
    }

    let daemon_bin = dbus_daemon
        .or_else(|| std::env::var("OXIBUS_DAEMON_BIN").ok())
        .unwrap_or_else(|| "dbus-daemon".into());

    let mut daemon_args = vec!["--session".to_string(), "--print-address".to_string()];
    if let Some(cfg) = &config_file {
        daemon_args.push("--config".to_string());
        daemon_args.push(cfg.clone());
    }
    if let Some(addr) = &address {
        daemon_args.push("--address".to_string());
        daemon_args.push(addr.clone());
    }

    let mut daemon = Command::new(&daemon_bin)
        .args(&daemon_args)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {daemon_bin}: {e}"))?;

    let stdout = daemon.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut bus_address = String::new();
    reader.read_line(&mut bus_address)?;
    let bus_address = bus_address.trim().to_string();
    if bus_address.is_empty() {
        let _ = daemon.kill();
        anyhow::bail!("dbus-daemon did not print a bus address");
    }
    if print_address {
        println!("{bus_address}");
    }

    let status = Command::new(&command[0])
        .args(&command[1..])
        // Standard D-Bus env var — every client that uses libdbus/zbus/GDBus
        // (cosmic-session included) reads exactly this name, not a
        // Zainium-specific one. OXIBUS_SESSION_BUS_ADDRESS is kept alongside
        // for anything in our own stack that already looks for it.
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_address)
        .env("OXIBUS_SESSION_BUS_ADDRESS", &bus_address)
        .status();

    let _ = daemon.kill();
    let _ = daemon.wait();

    std::process::exit(status.map(|s| s.code().unwrap_or(1)).unwrap_or(1));
}
