// Starts a session daemon and exports/prints its bus address.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut exit_with_session = false;
    let mut command: Vec<String> = Vec::new();

    while let Some(a) = args.peek() {
        match a.as_str() {
            "--exit-with-session" => {
                exit_with_session = true;
                args.next();
            }
            "--help" | "-h" => {
                println!("Usage: oxibus-launch [--exit-with-session] [-- COMMAND [ARGS...]]");
                return Ok(());
            }
            "--" => {
                args.next();
                command.extend(args);
                break;
            }
            _ => {
                args.next();
            }
        }
    }

    let daemon_bin = std::env::var("OXIBUS_DAEMON_BIN").unwrap_or_else(|_| "oxibus-daemon".into());
    let mut child = Command::new(&daemon_bin)
        .args(["--session", "--print-address"])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {daemon_bin}: {e}"))?;

    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut address = String::new();
    reader.read_line(&mut address)?;
    let address = address.trim().to_string();
    if address.is_empty() {
        anyhow::bail!("oxibus-daemon did not print a bus address");
    }

    let pid = child.id();

    if command.is_empty() {
        println!("OXIBUS_SESSION_BUS_ADDRESS='{address}'; export OXIBUS_SESSION_BUS_ADDRESS;");
        println!("OXIBUS_SESSION_BUS_PID={pid};");
        std::mem::forget(child);
        return Ok(());
    }

    let status = Command::new(&command[0])
        .args(&command[1..])
        .env("OXIBUS_SESSION_BUS_ADDRESS", &address)
        .env("OXIBUS_SESSION_BUS_PID", pid.to_string())
        .status();

    if exit_with_session {
        let _ = child.kill();
        let _ = child.wait();
    } else {
        std::mem::forget(child);
    }

    std::process::exit(status.map(|s| s.code().unwrap_or(1)).unwrap_or(1));
}
