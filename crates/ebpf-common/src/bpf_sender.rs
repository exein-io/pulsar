//! The [`EbpfSender`] trait is used by [`crate::Program`] to send events and errors.
//!
//! [`EbpfSender::send`] must not block since it can be used in async contexts

use tokio::sync::mpsc;

use crate::{program::EbpfEvent, ProgramError};

pub trait EbpfSender<T>: Clone + Send + 'static {
    /// Must not block since it can be used in async contexts
    fn send(&mut self, data: Result<EbpfEvent<T>, ProgramError>);
}

/// Simple implementation for tokio::mpsc bounded channels.
/// Sending with full channel will drop messages.
impl<T: 'static + Send> EbpfSender<T> for mpsc::Sender<Result<EbpfEvent<T>, ProgramError>> {
    fn send(&mut self, data: Result<EbpfEvent<T>, ProgramError>) {
        if self.try_send(data).is_err() {
            log::warn!("dropping msg");
        }
    }
}

/// EbpfSenderWrapper wraps an EbpfSender with a new one which calls
/// a callback on every event generated. This is useful for modules
/// which want to take some actions when sending events.
#[derive(Clone)]
pub struct EbpfSenderWrapper<S, F> {
    cb: F,
    inner: S,
}

impl<S, F> EbpfSenderWrapper<S, F> {
    pub fn new(inner: S, cb: F) -> Self {
        Self { inner, cb }
    }
}

impl<S, F, E> EbpfSender<E> for EbpfSenderWrapper<S, F>
where
    S: EbpfSender<E> + Clone + Send + 'static,
    F: FnMut(&EbpfEvent<E>) + Clone + Send + 'static,
{
    fn send(&mut self, data: Result<EbpfEvent<E>, ProgramError>) {
        if let Ok(event) = &data {
            (self.cb)(event);
        }
        self.inner.send(data)
    }
}
