use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoggerError {
    #[error("Please specify number of bytes > 0.")]
    ZeroBytes,
    #[error("Please specify number of lines > 0.")]
    ZeroLines,
    #[error("Could not initialize the logger: {0}")]
    IoError(#[source] std::io::Error),
}
