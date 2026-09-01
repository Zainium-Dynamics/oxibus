// Pushes environment variables into the bus for future activated services.

use clap::Parser;
use oxibus_client::{Connection, ObjectPath, Value};
use oxibus_core::{ArrayValue, Type, well_known};
use oxibus_tools::{BusChoice, resolve_address};

#[derive(Parser, Debug)]
#[command(
    name = "dbus-update-activation-environment",
    about = "Update the OxiBus activation environment"
)]
struct Args {
    #[arg(long)]
    system: bool,
    #[arg(long)]
    session: bool,
    #[arg(long)]
    address: Option<String>,

    /// Push the whole current environment instead of just the NAME[=VALUE]
    /// arguments given on the command line.
    #[arg(long)]
    all: bool,
    /// Accepted for compatibility: also try to update systemd's own
    /// activation environment. Not implemented (no systemd manager D-Bus
    /// integration yet) — only the bus's own environment is updated.
    #[arg(long)]
    systemd: bool,
    #[arg(long)]
    verbose: bool,

    vars: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.vars.is_empty() && !args.all {
        anyhow::bail!(
            "usage: dbus-update-activation-environment [--system|--session] [--all] NAME[=VALUE]..."
        );
    }
    if args.systemd {
        eprintln!(
            "dbus-update-activation-environment: --systemd is accepted but not implemented \
             (no systemd manager D-Bus integration yet) — only the bus's own environment is updated"
        );
    }
    let choice = if args.system {
        BusChoice::System
    } else {
        BusChoice::Session
    };
    let address = resolve_address(choice, args.address.as_deref())?;

    let pairs: Vec<(String, String)> = if args.all {
        std::env::vars().collect()
    } else {
        args.vars
            .iter()
            .map(|v| match v.split_once('=') {
                Some((n, v)) => (n.to_string(), v.to_string()),
                None => (v.clone(), std::env::var(v).unwrap_or_default()),
            })
            .collect()
    };

    if args.verbose {
        for (name, value) in &pairs {
            eprintln!("dbus-update-activation-environment: {name}={value}");
        }
    }

    let entries = pairs
        .into_iter()
        .map(|(name, value)| {
            Value::DictEntry(Box::new(Value::string(name)), Box::new(Value::string(value)))
        })
        .collect();
    let env_arg = Value::Array(ArrayValue::new(
        Type::DictEntry(Box::new(Type::String), Box::new(Type::String)),
        entries,
    ));

    let conn = Connection::connect(&address).await?;
    conn.bus_hello().await?;
    conn.call_method(
        Some(well_known::BUS_NAME),
        ObjectPath::new(well_known::BUS_PATH).unwrap(),
        Some(well_known::BUS_INTERFACE),
        "UpdateActivationEnvironment",
        vec![env_arg],
    )
    .await?;

    Ok(())
}
