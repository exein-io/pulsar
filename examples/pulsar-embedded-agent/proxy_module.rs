use pulsar_core::pdk::{Event, ModuleContext, ModuleError, NoConfig, SimplePulsarModule};
use tokio::sync::mpsc;

pub struct ProxyModule {
    pub tx_proxy: mpsc::Sender<Event>,
}

impl SimplePulsarModule for ProxyModule {
    type Config = NoConfig;
    type State = ProxyModuleState;

    const MODULE_NAME: &'static str = "proxy-module";
    const DEFAULT_ENABLED: bool = true;

    async fn init_state(
        &self,
        _config: &Self::Config,
        _ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        Ok(Self::State {
            tx_proxy: self.tx_proxy.clone(),
        })
    }

    async fn on_event(
        event: &Event,
        _config: &Self::Config,
        state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        state.tx_proxy.send(event.clone()).await?;
        Ok(())
    }
}

pub struct ProxyModuleState {
    tx_proxy: mpsc::Sender<Event>,
}
