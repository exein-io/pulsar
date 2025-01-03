use std::fmt::Display;

use axum::{http::StatusCode, response::IntoResponse};
use pulsar_core::pdk::PulsarDaemonError;
use thiserror::Error;

#[derive(Debug)]
pub enum EngineApiError {
    InternalServerError,
    BadRequest(String),
    ServiceUnavailable,
}

#[derive(Debug, Error)]
pub enum WebsocketError {
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    ConnectionError(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("unsupported message type")]
    UnsupportedMessageType,
}

impl Display for EngineApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl EngineApiError {
    fn status_code(&self) -> StatusCode {
        match *self {
            Self::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::ServiceUnavailable => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

impl IntoResponse for EngineApiError {
    fn into_response(self) -> axum::response::Response {
        let status_code = self.status_code();

        match self {
            Self::InternalServerError => (status_code, "internal").into_response(),
            Self::BadRequest(err) => (status_code, err).into_response(),
            Self::ServiceUnavailable => (status_code, "unavailable").into_response(),
        }
    }
}

impl From<PulsarDaemonError> for EngineApiError {
    fn from(error: PulsarDaemonError) -> Self {
        match &error {
            PulsarDaemonError::ModuleNotFound(_) => Self::BadRequest(error.to_string()),
            PulsarDaemonError::StartError(_) => Self::BadRequest(error.to_string()),
            PulsarDaemonError::StopError(_) => Self::BadRequest(error.to_string()),
            PulsarDaemonError::ConfigurationUpdateError(_) => {
                log::error!("Unexpected Error {}", error.to_string());
                Self::InternalServerError
            }
        }
    }
}
