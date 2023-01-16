use bpf_common::program::{BpfContext, BpfEvent, BpfLogLevel, Pinning};
use network_monitor::NetworkEvent;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let ctx = BpfContext::new(Pinning::Disabled, 512, BpfLogLevel::Disabled).unwrap();
    let (tx, mut rx) = mpsc::channel(100);
    let _program = network_monitor::program(ctx, tx)
        .await
        .expect("initialization failed");

    while let Some(msg) = rx.recv().await {
        match msg {
            Ok(BpfEvent {
                pid,
                timestamp,
                payload: NetworkEvent::Bind { addr, proto },
                buffer: _,
            }) => {
                println!("{timestamp} - {pid} bind on {addr} ({proto:?})");
            }
            Ok(_) => {}
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}
