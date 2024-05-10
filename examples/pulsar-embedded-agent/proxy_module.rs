use pulsar_core::pdk::{
    CleanExit, Event, ModuleContext, ModuleDetails, ModuleError, ModuleName, PulsarModule,
    ShutdownSignal, Version,
};
use std::sync::Arc;
use tokio::sync::mpsc;

const MODULE_NAME: &str = "proxy-module";

pub struct ProxyModule {
    pub tx_proxy: mpsc::Sender<Arc<Event>>,
}

impl PulsarModule for ProxyModule {
    const DEFAULT_ENABLED: bool = true;

    fn name(&self) -> ModuleName {
        MODULE_NAME.into()
    }

    fn details(&self) -> ModuleDetails {
        ModuleDetails {
            version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            enabled_by_default: Self::DEFAULT_ENABLED,
        }
    }

    fn start(
        &self,
        ctx: ModuleContext,
        shutdown: ShutdownSignal,
    ) -> impl std::future::Future<Output = Result<CleanExit, ModuleError>> + Send + 'static {
        proxy_task(ctx, shutdown, self.tx_proxy.clone())
    }
}

async fn proxy_task(
    ctx: ModuleContext,
    mut shutdown: ShutdownSignal,
    proxy_tx: mpsc::Sender<Arc<Event>>,
) -> Result<CleanExit, ModuleError> {
    let mut receiver = ctx.get_receiver();

    loop {
        tokio::select! {
            r = shutdown.recv() => return r,
            msg = receiver.recv() => {
                 let event = msg?;
                proxy_tx.send(event).await?;
            }
        }
    }
}
