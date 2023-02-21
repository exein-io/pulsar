use bpf_common::{
    feature_autodetect::lsm::lsm_supported,
    program::{BpfContext, BpfEvent, BpfLogLevel, Pinning},
};
use network_monitor::NetworkEvent;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let lsm_supported = tokio::task::spawn_blocking(lsm_supported).await.unwrap();
    let ctx =
        BpfContext::new(Pinning::Disabled, 512, BpfLogLevel::Disabled, lsm_supported).unwrap();
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
                println!("Error: {err:?}");
                break;
            }
        }
    }
}
