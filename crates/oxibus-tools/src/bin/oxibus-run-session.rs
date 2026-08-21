// Runs a command inside a private session bus.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut command: Vec<String> = Vec::new();

    while let Some(a) = args.peek() {
        match a.as_str() {
            "--" => {
                args.next();
                command.extend(args);
                break;
            }
            "--help" | "-h" => {
                println!("Usage: oxibus-run-session -- COMMAND [ARGS...]");
                return Ok(());
            }
            _ => {
                command.push(args.next().unwrap());
            }
        }
    }
    if command.is_empty() {
        anyhow::bail!("usage: oxibus-run-session -- COMMAND [ARGS...]");
    }

    let daemon_bin = std::env::var("OXIBUS_DAEMON_BIN").unwrap_or_else(|_| "oxibus-daemon".into());
    let mut daemon = Command::new(&daemon_bin)
        .args(["--session", "--print-address"])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {daemon_bin}: {e}"))?;

    let stdout = daemon.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut address = String::new();
    reader.read_line(&mut address)?;
    let address = address.trim().to_string();
    if address.is_empty() {
        let _ = daemon.kill();
        anyhow::bail!("oxibus-daemon did not print a bus address");
    }

    let status = Command::new(&command[0])
        .args(&command[1..])
        .env("OXIBUS_SESSION_BUS_ADDRESS", &address)
        .status();

    let _ = daemon.kill();
    let _ = daemon.wait();

    std::process::exit(status.map(|s| s.code().unwrap_or(1)).unwrap_or(1));
}
