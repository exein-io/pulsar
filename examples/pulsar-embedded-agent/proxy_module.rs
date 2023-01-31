use std::sync::{Arc, Mutex};

use anyhow::Context;
use pulsar_core::pdk::{ModuleContext, PulsarModule, Version};
use tokio::sync::oneshot;

const MODULE_NAME: &str = "proxy-module";

/// Fake module used to extract the ModuleContext out of pulsar.
pub fn module(tx_ctx: oneshot::Sender<ModuleContext>) -> PulsarModule {
    // This code supports starting the module only once. A smarter solution
    // needs to be architected if restarts are required.
    let tx_ctx = Arc::new(Mutex::new(Some(tx_ctx)));
    PulsarModule::new(
        MODULE_NAME,
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        move |ctx, mut shutdown| {
            let tx_ctx = tx_ctx.clone();
            async move {
                let tx_ctx = tx_ctx
                    .lock()
                    .ok()
                    .context("Getting mutex failed")?
                    .take()
                    .context("Module can be started only once")?;
                tx_ctx.send(ctx).ok().context("Sending context failed")?;
                shutdown.recv().await
            }
        },
    )
}
