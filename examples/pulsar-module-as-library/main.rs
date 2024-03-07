use bpf_common::{
    feature_autodetect::lsm::lsm_supported,
    program::{EbpfContext, EbpfEvent, EbpfLogLevel, Pinning},
};
use network_monitor::NetworkEvent;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let lsm_supported = tokio::task::spawn_blocking(lsm_supported).await.unwrap();
    let ctx = EbpfContext::new(
        Pinning::Disabled,
        512,
        EbpfLogLevel::Disabled,
        lsm_supported,
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(100);
    let _program = network_monitor::program(ctx, tx)
        .await
        .expect("initialization failed");

    while let Some(msg) = rx.recv().await {
        match msg {
            Ok(EbpfEvent {
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
