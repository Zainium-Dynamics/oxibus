// Removes stale session-bus socket files from a directory.

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: dbus-cleanup-sockets [DIRECTORY]");
        return;
    }
    if args.iter().any(|a| a == "--version") {
        println!("dbus-cleanup-sockets (oxibus) {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let dir = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("dbus-cleanup-sockets: cannot read {}: {e}", dir.display());
            std::process::exit(1);
        }
    };

    let mut removed = 0u32;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.file_type().is_socket() {
            continue;
        }
        match UnixStream::connect(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                if fs::remove_file(&path).is_ok() {
                    println!("removed stale socket {}", path.display());
                    removed += 1;
                }
            }
            Err(_) => {}
        }
    }
    println!(
        "dbus-cleanup-sockets: removed {removed} stale socket(s) from {}",
        dir.display()
    );
}
