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

/// Trait to implement to create a pulsar pluggable module
pub trait PulsarModule: Send {
    type Config: for<'a> TryFrom<&'a ModuleConfig, Error = ConfigError> + Send + Sync + 'static;
    type State: Send + 'static;
    type Extra: Extra<Self>;

    const MODULE_NAME: &'static str;
    const DEFAULT_ENABLED: bool;

    fn init_state(
        &self,
        config: &Self::Config,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<Self::State, ModuleError>> + Send;

    fn on_config_change(
        new_config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send {
        let _ = new_config;
        let _ = state;
        let _ = ctx;
        ctx.stop_cfg_recv()
    }

    fn on_event(
        event: &Event,
        config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send {
        let _ = event;
        let _ = config;
        let _ = state;
        let _ = ctx;
        ctx.stop_event_recv()
    }

    /// Default: normal state drop
    fn graceful_stop(state: Self::State) -> impl Future<Output = Result<(), ModuleError>> + Send {
        drop(state);
        std::future::ready(Ok(()))
    }
}

pub trait Extra<T: PulsarModule + ?Sized> {
    type ExtraState: Send + 'static;
    type TriggerOutput: Send;

    fn init_extra_state(
        module: &T,
        config: &T::Config,
    ) -> impl Future<Output = Result<Self::ExtraState, ModuleError>> + Send;

    fn trigger(
        extra_state: &mut Self::ExtraState,
    ) -> impl Future<Output = Result<Self::TriggerOutput, ModuleError>> + Send;

    fn action(
        trigger_output: &Self::TriggerOutput,
        config: &T::Config,
        state: &mut T::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send;
}

pub struct NoExtra(());

impl<T: PulsarModule> Extra<T> for NoExtra {
    type ExtraState = ();

    type TriggerOutput = ();

    fn init_extra_state(
        module: &T,
        config: &<T as PulsarModule>::Config,
    ) -> impl Future<Output = Result<Self::ExtraState, ModuleError>> + Send {
        let _ = module;
        let _ = config;
        std::future::ready(Ok(()))
    }

    fn trigger(
        extra_state: &mut Self::ExtraState,
    ) -> impl Future<Output = Result<Self::TriggerOutput, ModuleError>> {
        let _ = extra_state;
        std::future::pending()
    }

    fn action(
        trigger_output: &Self::TriggerOutput,
        config: &<T as PulsarModule>::Config,
        state: &mut <T as PulsarModule>::State,
        ctx: &ModuleContext,
    ) -> impl Future<Output = Result<(), ModuleError>> + Send {
        let _ = trigger_output;
        let _ = config;
        let _ = state;
        let _ = ctx;
        std::future::ready(Ok(()))
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
