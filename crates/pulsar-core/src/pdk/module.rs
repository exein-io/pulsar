use std::{borrow::Cow, fmt, future::Future, ops::Deref};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use validatron::Validatron;

use super::{ConfigError, Event, ModuleConfig, ModuleContext};

#[derive(Debug)]
pub struct NoConfig(());

impl<'a> TryFrom<&'a ModuleConfig> for NoConfig {
    type Error = ConfigError;

    fn try_from(value: &'a ModuleConfig) -> std::prelude::v1::Result<Self, Self::Error> {
        let _ = value;
        Ok(Self(()))
    }
}

/// Trait to implement to create a pulsar pluggable module. Note that this is the fully
/// featured interface which is often too much. Please see [`SimplePulsarModule`] for a simpler interface.
pub trait PulsarModule: Send {
    type Config: for<'a> TryFrom<&'a ModuleConfig, Error = ConfigError> + Send + Sync + 'static;
    type State: Send + 'static;
    type Extension: Send + 'static;
    type TriggerOutput: Send + Sync;

    const MODULE_NAME: &'static str;
    const DEFAULT_ENABLED: bool;

    fn init_state(
        &self,
        config: &Self::Config,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(Self::State, Self::Extension), ModuleError>> + Send;

    fn trigger(
        extension: &mut Self::Extension,
    ) -> impl Future<Output = Result<Self::TriggerOutput, ModuleError>> + Send;

    fn action(
        trigger_output: &Self::TriggerOutput,
        config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send;

    #[allow(unused_variables)]
    fn on_config_change(
        new_config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send {
        ctx.stop_cfg_recv()
    }

    #[allow(unused_variables)]
    fn on_event(
        event: &Event,
        config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send {
        ctx.stop_event_recv()
    }

    /// Default: normal state drop
    fn graceful_stop(_state: Self::State) -> impl Future<Output = Result<(), ModuleError>> + Send {
        std::future::ready(Ok(()))
    }
}

/// A simpler version of [`PulsarModule`] which is often enough. A blanket implementation ensures that
/// [`PulsarModule`] is implemented for all implementors of [`SimplePulsarModule`].
pub trait SimplePulsarModule: Send + Sync {
    type Config: for<'a> TryFrom<&'a ModuleConfig, Error = ConfigError> + Send + Sync + 'static;
    type State: Send + 'static;

    const MODULE_NAME: &'static str;
    const DEFAULT_ENABLED: bool;

    fn init_state(
        &self,
        config: &Self::Config,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<Self::State, ModuleError>> + Send;

    #[allow(unused_variables)]
    fn on_config_change(
        new_config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send {
        ctx.stop_cfg_recv()
    }

    #[allow(unused_variables)]
    fn on_event(
        event: &Event,
        config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send {
        ctx.stop_event_recv()
    }

    /// Default: normal state drop
    fn graceful_stop(_state: Self::State) -> impl Future<Output = Result<(), ModuleError>> + Send {
        std::future::ready(Ok(()))
    }
}

impl<T> PulsarModule for T
where
    T: SimplePulsarModule,
{
    type Config = T::Config;

    type State = T::State;

    type Extension = ();

    type TriggerOutput = ();

    const MODULE_NAME: &'static str = Self::MODULE_NAME;

    const DEFAULT_ENABLED: bool = Self::DEFAULT_ENABLED;

    async fn init_state(
        &self,
        config: &Self::Config,
        ctx: &ModuleContext,
    ) -> Result<(Self::State, Self::Extension), ModuleError> {
        SimplePulsarModule::init_state(self, config, ctx)
            .await
            .map(|v| (v, ()))
    }

    async fn trigger(_extension: &mut Self::Extension) -> Result<Self::TriggerOutput, ModuleError> {
        std::future::pending().await
    }

    async fn action(
        _trigger_output: &Self::TriggerOutput,
        _config: &Self::Config,
        _state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        Ok(())
    }

    async fn on_config_change(
        new_config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        <Self as SimplePulsarModule>::on_config_change(new_config, state, ctx).await
    }

    async fn on_event(
        event: &Event,
        config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        <Self as SimplePulsarModule>::on_event(event, config, state, ctx).await
    }

    async fn graceful_stop(state: Self::State) -> Result<(), ModuleError> {
        <Self as SimplePulsarModule>::graceful_stop(state).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Hash)]
pub struct ModuleName(Cow<'static, str>);

impl Deref for ModuleName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&'static str> for ModuleName {
    fn from(val: &'static str) -> ModuleName {
        ModuleName(std::borrow::Cow::Borrowed(val))
    }
}

impl From<String> for ModuleName {
    fn from(val: String) -> ModuleName {
        ModuleName(std::borrow::Cow::Owned(val))
    }
}

impl fmt::Display for ModuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Validatron for ModuleName {
    fn get_class() -> validatron::ValidatronClass {
        Self::class_builder()
            .primitive_class_builder(
                Box::new(|s| Ok(ModuleName(Cow::Owned(s.to_string())))),
                Box::new(|op| match op {
                    validatron::Operator::String(op) => match op {
                        validatron::StringOperator::StartsWith => {
                            Ok(Box::new(|a, b| a.0.as_ref().starts_with(b.0.as_ref())))
                        }
                        validatron::StringOperator::EndsWith => {
                            Ok(Box::new(|a, b| a.0.as_ref().ends_with(b.0.as_ref())))
                        }
                    },
                    validatron::Operator::Relational(op) => {
                        Ok(Box::new(move |a, b| op.apply(a, b)))
                    }
                    _ => Err(validatron::ValidatronError::OperatorNotAllowedOnType(
                        op,
                        "ModuleName".to_string(),
                    )),
                }),
            )
            .build()
    }
}

pub type ModuleError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub enum ModuleSignal {
    Warning(String),
    Error(ModuleError),
}
