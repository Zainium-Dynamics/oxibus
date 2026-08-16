//! `oxibus-monitor` — become a bus monitor and print every message that
//! crosses the bus (reimplementation of `dbus-monitor`).

use clap::Parser;
use oxibus_client::{Connection, ObjectPath, Value};
use oxibus_core::well_known;
use oxibus_tools::{format_value, resolve_address, BusChoice};

#[derive(Parser, Debug)]
#[command(name = "oxibus-monitor", about = "Monitor an OxiBus bus")]
struct Args {
    #[arg(long)]
    system: bool,
    #[arg(long)]
    session: bool,
    #[arg(long)]
    address: Option<String>,

    /// Match rules, e.g. "type='signal'" (default: everything).
    rules: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let choice = if args.system { BusChoice::System } else { BusChoice::Session };
    let address = resolve_address(choice, args.address.as_deref())?;

    let conn = Connection::connect(&address).await?;
    conn.bus_hello().await?;

    let rule_values: Vec<Value> = args.rules.iter().map(|r| Value::string(r.clone())).collect();
    conn.call_method(
        Some(well_known::BUS_NAME),
        ObjectPath::new(well_known::BUS_PATH).unwrap(),
        Some(well_known::MONITORING_INTERFACE),
        "BecomeMonitor",
        vec![
            Value::Array(oxibus_core::ArrayValue::new(oxibus_core::Type::String, rule_values)),
            Value::UInt32(0),
        ],
    )
    .await?;

    eprintln!("oxibus-monitor: watching bus traffic (Ctrl-C to stop)");
    let mut rx = conn.subscribe_all_messages();
    loop {
        match rx.recv().await {
            Ok(msg) => print_message(&msg),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                eprintln!("[dropped {n} messages, receiver too slow]");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

fn print_message(msg: &oxibus_core::Message) {
    let kind = match msg.message_type() {
        oxibus_core::header::MessageType::MethodCall => "method call",
        oxibus_core::header::MessageType::MethodReturn => "method return",
        oxibus_core::header::MessageType::Error => "error",
        oxibus_core::header::MessageType::Signal => "signal",
    };
    println!(
        "{kind} sender={} destination={} path={} interface={} member={}",
        msg.sender().unwrap_or("(none)"),
        msg.destination().unwrap_or("(none)"),
        msg.path().map(|p| p.as_str().to_string()).unwrap_or_default(),
        msg.interface().unwrap_or(""),
        msg.member().unwrap_or(""),
    );
    for v in &msg.body {
        println!("   {}", format_value(v));
    }
}
