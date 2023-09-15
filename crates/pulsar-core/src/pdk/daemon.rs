use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use super::ModuleConfig;

/// Error happening during daemon administration.
#[derive(Error, Debug)]
pub enum PulsarDaemonError {
    #[error("module {0} not found")]
    ModuleNotFound(String),
    #[error("{0}")]
    StopError(String),
    #[error("error updating the configuration")]
    ConfigurationUpdateError(#[from] anyhow::Error),
}

/// Handle to a running PulsarDaemon.
///
/// Provides module overviews and administration functionalities.
#[derive(Debug, Clone)]
pub struct PulsarDaemonHandle {
    pub tx_cmd: mpsc::Sender<PulsarDaemonCommand>,
}

impl PulsarDaemonHandle {
    pub fn new(sender: mpsc::Sender<PulsarDaemonCommand>) -> Self {
        Self { tx_cmd: sender }
    }

    pub async fn modules(&self) -> Vec<ModuleOverview> {
        let (send, recv) = oneshot::channel();
        let msg = PulsarDaemonCommand::ModulesList { tx_reply: send };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn status(&self, module_name: String) -> Result<ModuleStatus, PulsarDaemonError> {
        let (send, recv) = oneshot::channel();
        let msg = PulsarDaemonCommand::Status {
            tx_reply: send,
            module_name,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn start(&self, module_name: String) -> Result<(), PulsarDaemonError> {
        let (send, recv) = oneshot::channel();
        let msg = PulsarDaemonCommand::StartModule {
            tx_reply: send,
            module_name,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn stop(&self, module_name: String) -> Result<(), PulsarDaemonError> {
        let (send, recv) = oneshot::channel();
        let msg = PulsarDaemonCommand::StopModule {
            tx_reply: send,
            module_name,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn restart(&self, module_name: String) -> Result<(), PulsarDaemonError> {
        let (send, recv) = oneshot::channel();
        let msg = PulsarDaemonCommand::RestartModule {
            tx_reply: send,
            module_name,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn get_configuration(
        &self,
        module_name: String,
    ) -> Result<ModuleConfig, PulsarDaemonError> {
        let (send, recv) = oneshot::channel();
        let msg = PulsarDaemonCommand::GetConfiguration {
            tx_reply: send,
            module_name,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn update_configuration(
        &self,
        module_name: String,
        key: String,
        value: String,
    ) -> Result<(), PulsarDaemonError> {
        let (send, recv) = oneshot::channel();
        let msg = PulsarDaemonCommand::SetConfiguration {
            tx_reply: send,
            module_name,
            key,
            value,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn get_configurations(&self) -> Vec<(String, ModuleConfig)> {
        let (send, recv) = oneshot::channel();
        let msg = PulsarDaemonCommand::Configs { tx_reply: send };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.tx_cmd.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}

/// Status of loaded module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleStatus {
    Created,
    Running(Vec<String>),
    Failed(String),
    Stopped,
}

impl fmt::Display for ModuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ModuleStatus::Running(warnings) if !warnings.is_empty() => {
                write!(f, "Running([\"{}\"])", warnings.join("\",\""))
            }
            ModuleStatus::Running(_) => write!(f, "Running"),
            _ => write!(f, "{:?}", self),
        }
    }
}

/// Messages used for internal communication between [`PulsarDaemonHandle`] and the underlying PulsarDaemon actor.
pub enum PulsarDaemonCommand {
    ModulesList {
        tx_reply: oneshot::Sender<Vec<ModuleOverview>>,
    },
    Status {
        tx_reply: oneshot::Sender<Result<ModuleStatus, PulsarDaemonError>>,
        module_name: String,
    },
    StartModule {
        tx_reply: oneshot::Sender<Result<(), PulsarDaemonError>>,
        module_name: String,
    },
    RestartModule {
        tx_reply: oneshot::Sender<Result<(), PulsarDaemonError>>,
        module_name: String,
    },
    StopModule {
        tx_reply: oneshot::Sender<Result<(), PulsarDaemonError>>,
        module_name: String,
    },
    GetConfiguration {
        tx_reply: oneshot::Sender<Result<ModuleConfig, PulsarDaemonError>>,
        module_name: String,
    },
    SetConfiguration {
        tx_reply: oneshot::Sender<Result<(), PulsarDaemonError>>,
        module_name: String,
        key: String,
        value: String,
    },
    Configs {
        tx_reply: oneshot::Sender<Vec<(String, ModuleConfig)>>,
    },
}

/// Overview of loaded module.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ModuleOverview {
    pub name: String,
    pub version: Version,
    pub status: ModuleStatus,
}
