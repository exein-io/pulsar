use std::fmt::Display;

use axum::{
    body,
    http::{Response, StatusCode},
    response::IntoResponse,
};
use pulsar_core::pdk::PulsarDaemonError;

#[derive(Debug)]
pub enum EngineApiError {
    InternalServerError,
    BadRequest(String),
    ServiceUnavailable,
}

impl Display for EngineApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
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
        let status_code = &self.status_code();

        let body = match self {
            Self::InternalServerError => body::boxed(body::Full::from("internal")),
            Self::BadRequest(err) => body::boxed(body::Full::from(err)),
            Self::ServiceUnavailable => body::boxed(body::Full::from("unavailable")),
        };

        Response::builder().status(status_code).body(body).unwrap()
    }
}

impl From<PulsarDaemonError> for EngineApiError {
    fn from(error: PulsarDaemonError) -> Self {
        match &error {
            PulsarDaemonError::ModuleNotFound(_) => Self::BadRequest(error.to_string()),
            PulsarDaemonError::StopError(_) => Self::BadRequest(error.to_string()),
            PulsarDaemonError::ConfigurationUpdateError(_) => {
                log::error!("Unexpected Error {}", error.to_string());
                Self::InternalServerError
            }
        }
    }
}
