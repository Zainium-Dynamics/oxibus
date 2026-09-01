// Starts a session daemon and exports/prints its bus address.

use std::io::{BufRead, BufReader};
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Syntax {
    Sh,
    Csh,
    Binary,
}

fn detect_shell_syntax() -> Syntax {
    match std::env::var("SHELL") {
        Ok(s) if s.contains("csh") => Syntax::Csh,
        _ => Syntax::Sh,
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut exit_with_session = false;
    let mut print_pid = false;
    let mut fork = false;
    let mut config_file: Option<String> = None;
    let mut syslog = false;
    let mut syslog_only = false;
    let mut syntax: Option<Syntax> = None;
    let mut command: Vec<String> = Vec::new();

    while let Some(a) = args.peek() {
        match a.as_str() {
            "--exit-with-session" => {
                exit_with_session = true;
                args.next();
            }
            "--print-pid" => {
                print_pid = true;
                args.next();
            }
            "--fork" => {
                fork = true;
                args.next();
            }
            "--config-file" => {
                args.next();
                config_file = args.next();
            }
            "--syslog" => {
                syslog = true;
                args.next();
            }
            "--syslog-only" => {
                syslog_only = true;
                args.next();
            }
            "--sh-syntax" => {
                syntax = Some(Syntax::Sh);
                args.next();
            }
            "--csh-syntax" => {
                syntax = Some(Syntax::Csh);
                args.next();
            }
            "--binary-syntax" => {
                syntax = Some(Syntax::Binary);
                args.next();
            }
            "--auto-syntax" => {
                syntax = Some(detect_shell_syntax());
                args.next();
            }
            "--version" => {
                println!("dbus-launch (oxibus) {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "Usage: dbus-launch [--exit-with-session] [--print-pid] [--fork] \
                     [--config-file=FILE] [--syslog|--syslog-only] \
                     [--sh-syntax|--csh-syntax|--binary-syntax|--auto-syntax] \
                     [-- COMMAND [ARGS...]]"
                );
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
    let syntax = syntax.unwrap_or(Syntax::Sh);

    let daemon_bin = std::env::var("OXIBUS_DAEMON_BIN").unwrap_or_else(|_| "dbus-daemon".into());
    let mut daemon_args = vec!["--session".to_string(), "--print-address".to_string()];
    if let Some(cfg) = &config_file {
        daemon_args.push("--config".to_string());
        daemon_args.push(cfg.clone());
    }
    if syslog_only {
        daemon_args.push("--syslog-only".to_string());
    } else if syslog {
        daemon_args.push("--syslog".to_string());
    }

    let mut child = Command::new(&daemon_bin)
        .args(&daemon_args)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {daemon_bin}: {e}"))?;

    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut address = String::new();
    reader.read_line(&mut address)?;
    let address = address.trim().to_string();
    if address.is_empty() {
        anyhow::bail!("dbus-daemon did not print a bus address");
    }

    let pid = child.id();

    if command.is_empty() {
        print_startup(syntax, &address, pid, print_pid);
        std::mem::forget(child);
        if fork {
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let _ = daemonize();
        }
        return Ok(());
    }

    // Output (if any was requested) is already flushed above; safe to
    // detach from the terminal now, same "print first, then background"
    // ordering as dbus-daemon's own --fork.
    if fork {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        if let Err(e) = daemonize() {
            eprintln!("dbus-launch: --fork: could not daemonize: {e} — continuing in foreground");
        }
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

fn print_startup(syntax: Syntax, address: &str, pid: u32, print_pid: bool) {
    match syntax {
        Syntax::Sh => {
            println!("OXIBUS_SESSION_BUS_ADDRESS='{address}'; export OXIBUS_SESSION_BUS_ADDRESS;");
            println!("OXIBUS_SESSION_BUS_PID={pid};");
        }
        Syntax::Csh => {
            println!("setenv OXIBUS_SESSION_BUS_ADDRESS '{address}';");
            println!("set OXIBUS_SESSION_BUS_PID={pid};");
        }
        Syntax::Binary => {
            use std::io::Write;
            let mut out = std::io::stdout();
            let _ = write!(out, "OXIBUS_SESSION_BUS_ADDRESS={address}\0OXIBUS_SESSION_BUS_PID={pid}\0");
            let _ = out.flush();
            return;
        }
    }
    if print_pid {
        println!("{pid}");
    }
}

/// Same double-fork-and-detach dbus-daemon uses for its own --fork: makes
/// dbus-launch itself background and release the caller's terminal/shell,
/// after any requested output has already been printed and flushed.
fn daemonize() -> std::io::Result<()> {
    unsafe {
        match libc::fork() {
            -1 => return Err(std::io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }
        if libc::setsid() < 0 {
            return Err(std::io::Error::last_os_error());
        }
        match libc::fork() {
            -1 => return Err(std::io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }
    }
    let _ = std::env::set_current_dir("/");
    redirect_stdio_to_devnull();
    Ok(())
}

fn redirect_stdio_to_devnull() {
    if let Ok(devnull) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        let fd = devnull.as_raw_fd();
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }
}
