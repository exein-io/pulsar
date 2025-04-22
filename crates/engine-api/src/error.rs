use axum::{http::StatusCode, response::IntoResponse};
use hyper::http;
use pulsar_core::pdk::PulsarDaemonError;
use std::fmt::Display;
use std::str::Utf8Error;
use thiserror::Error;

#[derive(Debug)]
pub enum EngineApiError {
    InternalServerError,
    BadRequest(String),
    ServiceUnavailable,
}

/// Error types for the Engine API client
#[derive(Debug, Error)]
pub enum EngineClientError {
    /// Socket not found
    #[error("Unix socket not found: {0}")]
    SocketNotFound(String),

    /// Failed to get metadata
    #[error("Failed to get metadata: {0}")]
    FailedToGetMetadata(String),

    /// No write permission
    #[error("No write permission: {0}")]
    NoWritePermission(String),

    /// No read permission
    #[error("No read permission: {0}")]
    NoReadPermission(String),

    /// Not a unix socket
    #[error("Not a unix socket: {0}")]
    NotASocket(String),

    /// C string conversion error
    #[error("C string conversion error: {0}")]
    CStringConversion(#[from] std::ffi::NulError),

    /// Hyper error
    #[error("Hyper client error: {0}")]
    HyperError(#[from] hyper_util::client::legacy::Error), // For client.request() errors

    /// Collect Response Error
    #[error("Error collecting response: {0}")]
    CollectResponseError(#[from] hyper::Error), // For res.collect() errors

    /// Error during request building
    #[error("Failed to build request: {0}")]
    RequestBuilderError(#[from] http::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializeError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializeError(String),

    /// UTF-8 error
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] Utf8Error),

    /// Unexpected response
    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    /// Socket connection error
    #[error("Failed to connect to socket: {0}")]
    SocketConnectionError(#[from] std::io::Error),

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocketError(#[from] tokio_tungstenite::tungstenite::Error),

    /// Unknown error
    #[error("Unknown error: {0}")]
    Other(String),
}

impl From<serde_json::Error> for EngineClientError {
    fn from(err: serde_json::Error) -> Self {
        match err.classify() {
            serde_json::error::Category::Io => {
                Self::SerializeError(format!("IO error during serialization: {}", err))
            }
            serde_json::error::Category::Syntax => {
                Self::DeserializeError(format!("JSON syntax error: {}", err))
            }
            serde_json::error::Category::Data => {
                Self::DeserializeError(format!("JSON data error: {}", err))
            }
            serde_json::error::Category::Eof => {
                Self::DeserializeError(format!("Unexpected end of JSON input: {}", err))
            }
        }
    }
}

/// WebSocket related errors
#[derive(Debug, Error)]
pub enum WebsocketError {
    /// JSON error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Unsupported message type
    #[error("Unsupported message type")]
    UnsupportedMessageType,

    /// Connection error
    #[error("WebSocket connection error: {0}")]
    ConnectionError(String),
}
impl From<tokio_tungstenite::tungstenite::Error> for WebsocketError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        WebsocketError::ConnectionError(err.to_string())
    }
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
