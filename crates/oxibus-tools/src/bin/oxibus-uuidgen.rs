// OxiBus machine-id UUID generator utility.

use std::path::PathBuf;

fn default_machine_id_path() -> PathBuf {
    oxibus_config::GlobalConfig::load_default()
        .paths
        .machine_id_file()
}

fn split_flag<'a>(arg: &'a str, name: &str) -> Option<Option<&'a str>> {
    let rest = arg.strip_prefix(name)?;
    if rest.is_empty() {
        Some(None)
    } else {
        rest.strip_prefix('=').map(Some)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut ensure = false;
    let mut get = false;
    let mut filename: Option<String> = None;

    for a in &args {
        if let Some(f) = split_flag(a, "--ensure") {
            ensure = true;
            if let Some(f) = f {
                filename = Some(f.to_string());
            }
        } else if let Some(f) = split_flag(a, "--get") {
            get = true;
            if let Some(f) = f {
                filename = Some(f.to_string());
            }
        } else if a == "--help" {
            println!("Usage: oxibus-uuidgen [--ensure[=FILENAME]] [--get[=FILENAME]]");
            return;
        } else if a == "--version" {
            println!("OxiBus UUID Generator 0.1.0");
            return;
        } else {
            eprintln!("oxibus-uuidgen: unknown option '{a}'");
            std::process::exit(1);
        }
    }

    let path = filename
        .map(PathBuf::from)
        .unwrap_or_else(default_machine_id_path);

    if get {
        match std::fs::read_to_string(&path) {
            Ok(s) if !s.trim().is_empty() => println!("{}", s.trim()),
            _ => std::process::exit(1),
        }
        return;
    }

    if ensure {
        let already = std::fs::read_to_string(&path)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if already {
            return;
        }
        let uuid = oxibus_auth::generate_guid_hex();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&path, &uuid) {
            eprintln!("oxibus-uuidgen: could not write {}: {e}", path.display());
            std::process::exit(1);
        }
        return;
    }

    println!("{}", oxibus_auth::generate_guid_hex());
}
