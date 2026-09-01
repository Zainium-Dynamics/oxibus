// Sends a method call or signal from the CLI.

use std::time::Duration;

use clap::Parser;
use oxibus_client::{Connection, ObjectPath};
use oxibus_tools::{BusChoice, format_value, parse_typed_arg, resolve_address};

#[derive(Parser, Debug)]
#[command(name = "dbus-send", about = "Send a message to an OxiBus bus")]
struct Args {
    #[arg(long)]
    system: bool,
    #[arg(long)]
    session: bool,
    #[arg(long)]
    address: Option<String>,
    /// Alias for --address.
    #[arg(long, conflicts_with_all = ["address", "peer"])]
    bus: Option<String>,
    /// Alias for --address (upstream dbus-send distinguishes "bus" from
    /// "peer" connections; oxibus-send always talks through a bus).
    #[arg(long, conflicts_with_all = ["address", "bus"])]
    peer: Option<String>,

    /// Sender name to claim on the outgoing message. Accepted for
    /// compatibility — has no effect, since a bus always stamps the real
    /// sender on delivery regardless of what the client sends.
    #[arg(long)]
    sender: Option<String>,

    #[arg(long)]
    dest: Option<String>,
    #[arg(long = "type", default_value = "method_call")]
    message_type: String,
    #[arg(long)]
    print_reply: bool,
    /// Give up waiting for a reply after MSEC milliseconds.
    #[arg(long, value_name = "MSEC")]
    reply_timeout: Option<u64>,

    object_path: String,
    interface_member: String,
    typed_args: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.sender.is_some() {
        eprintln!(
            "dbus-send: --sender is accepted but has no effect on bus-routed messages \
             (the bus always stamps the real sender)"
        );
    }

    let explicit_address = args
        .address
        .as_deref()
        .or(args.bus.as_deref())
        .or(args.peer.as_deref());
    if explicit_address.is_some() && (args.system || args.session) {
        anyhow::bail!("--address/--bus/--peer may not be used with --system or --session");
    }
    let choice = if args.system {
        BusChoice::System
    } else {
        BusChoice::Session
    };
    let address = resolve_address(choice, explicit_address)?;

    let (interface, member) = args.interface_member.rsplit_once('.').ok_or_else(|| {
        anyhow::anyhow!("expected INTERFACE.MEMBER, got '{}'", args.interface_member)
    })?;

    let path = ObjectPath::new(&args.object_path)?;
    let values: Vec<_> = args
        .typed_args
        .iter()
        .map(|s| parse_typed_arg(s))
        .collect::<Result<_, _>>()?;

    let conn = Connection::connect(&address).await?;
    conn.bus_hello().await?;

    match args.message_type.as_str() {
        "signal" => {
            conn.emit_signal(path, interface, member, values).await?;
        }
        "method_call" => {
            let call =
                conn.call_method(args.dest.as_deref(), path, Some(interface), member, values);
            let reply = match args.reply_timeout {
                Some(ms) => tokio::time::timeout(Duration::from_millis(ms), call)
                    .await
                    .map_err(|_| anyhow::anyhow!("no reply within {ms}ms (--reply-timeout)"))??,
                None => call.await?,
            };
            if args.print_reply {
                println!("method return");
                for v in &reply {
                    println!("   {}", format_value(v));
                }
            }
        }
        other => anyhow::bail!("unsupported --type '{other}' (use method_call or signal)"),
    }

    Ok(())
}
