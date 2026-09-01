// OxiBus monitoring tool.

use clap::Parser;
use oxibus_client::{Connection, ObjectPath, Value};
use oxibus_core::well_known;
use oxibus_tools::{BusChoice, format_value, resolve_address};

#[derive(Parser, Debug)]
#[command(name = "dbus-monitor", about = "Monitor an OxiBus bus")]
struct Args {
    #[arg(long)]
    system: bool,
    #[arg(long)]
    session: bool,
    #[arg(long)]
    address: Option<String>,

    /// Accepted for compatibility — this is already the default mode.
    #[arg(long)]
    monitor: bool,

    /// Not implemented yet: print each message as raw marshaled bytes
    /// instead of the formatted text form.
    #[arg(long)]
    binary: bool,
    /// Not implemented yet: capture to a libpcap-format stream.
    #[arg(long)]
    pcap: bool,
    /// Not implemented yet: annotate each message with a lock-contention
    /// profile.
    #[arg(long)]
    profile: bool,

    rules: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.binary || args.pcap || args.profile {
        anyhow::bail!("dbus-monitor: --binary/--pcap/--profile are not implemented yet");
    }
    let choice = if args.system {
        BusChoice::System
    } else {
        BusChoice::Session
    };
    let address = resolve_address(choice, args.address.as_deref())?;

    let conn = Connection::connect(&address).await?;
    conn.bus_hello().await?;

    let rule_values: Vec<Value> = args
        .rules
        .iter()
        .map(|r| Value::string(r.clone()))
        .collect();
    conn.call_method(
        Some(well_known::BUS_NAME),
        ObjectPath::new(well_known::BUS_PATH).unwrap(),
        Some(well_known::MONITORING_INTERFACE),
        "BecomeMonitor",
        vec![
            Value::Array(oxibus_core::ArrayValue::new(
                oxibus_core::Type::String,
                rule_values,
            )),
            Value::UInt32(0),
        ],
    )
    .await?;

    eprintln!("dbus-monitor: watching bus traffic (Ctrl-C to stop)");
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
        msg.path()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default(),
        msg.interface().unwrap_or(""),
        msg.member().unwrap_or(""),
    );
    for v in &msg.body {
        println!("   {}", format_value(v));
    }
}
