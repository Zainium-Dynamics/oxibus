// Sends a method call or signal from the CLI.

use clap::Parser;
use oxibus_client::{Connection, ObjectPath};
use oxibus_tools::{BusChoice, format_value, parse_typed_arg, resolve_address};

#[derive(Parser, Debug)]
#[command(name = "oxibus-send", about = "Send a message to an OxiBus bus")]
struct Args {
    #[arg(long)]
    system: bool,
    #[arg(long)]
    session: bool,
    #[arg(long)]
    address: Option<String>,

    #[arg(long)]
    dest: Option<String>,
    #[arg(long = "type", default_value = "method_call")]
    message_type: String,
    #[arg(long)]
    print_reply: bool,

    object_path: String,
    interface_member: String,
    typed_args: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let choice = if args.system {
        BusChoice::System
    } else {
        BusChoice::Session
    };
    let address = resolve_address(choice, args.address.as_deref())?;

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
            let reply = conn
                .call_method(args.dest.as_deref(), path, Some(interface), member, values)
                .await?;
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
