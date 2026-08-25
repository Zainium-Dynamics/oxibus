// Pushes environment variables into the bus for future activated services.

use clap::Parser;
use oxibus_client::{Connection, ObjectPath, Value};
use oxibus_core::{ArrayValue, Type, well_known};
use oxibus_tools::{BusChoice, resolve_address};

#[derive(Parser, Debug)]
#[command(
    name = "oxibus-update-activation-environment",
    about = "Update the OxiBus activation environment"
)]
struct Args {
    #[arg(long)]
    system: bool,
    #[arg(long)]
    session: bool,
    #[arg(long)]
    address: Option<String>,

    vars: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.vars.is_empty() {
        anyhow::bail!(
            "usage: oxibus-update-activation-environment [--system|--session] NAME[=VALUE]..."
        );
    }
    let choice = if args.system {
        BusChoice::System
    } else {
        BusChoice::Session
    };
    let address = resolve_address(choice, args.address.as_deref())?;

    let mut entries = Vec::new();
    for v in &args.vars {
        let (name, value) = match v.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => {
                let value = std::env::var(v).unwrap_or_default();
                (v.clone(), value)
            }
        };
        entries.push(Value::DictEntry(
            Box::new(Value::string(name)),
            Box::new(Value::string(value)),
        ));
    }
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
