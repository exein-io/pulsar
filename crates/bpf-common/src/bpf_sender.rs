//! The [`BpfSender`] trait is used by [`crate::Program`] to send events and errors.
//!
//! [`BpfSender::send`] must not block since it can be used in async contexts

use tokio::sync::mpsc;

use crate::{ProgramError, program::BpfEvent};

pub trait BpfSender<T>: Clone + Send + 'static {
    /// Must not block since it can be used in async contexts
    fn send(&mut self, data: Result<BpfEvent<T>, ProgramError>);
}

/// Simple implementation for tokio::mpsc bounded channels.
/// Sending with full channel will drop messages.
impl<T: 'static + Send> BpfSender<T> for mpsc::Sender<Result<BpfEvent<T>, ProgramError>> {
    fn send(&mut self, data: Result<BpfEvent<T>, ProgramError>) {
        if self.try_send(data).is_err() {
            log::warn!("dropping msg");
        }
    }
}

/// BpfSenderWrapper wraps a BpfSender with a new one which calls
/// a callback on every event generated. This is useful for modules
/// which want to take some actions when sending events.
#[derive(Clone)]
pub struct BpfSenderWrapper<S, F> {
    cb: F,
    inner: S,
}

impl<S, F> BpfSenderWrapper<S, F> {
    pub fn new(inner: S, cb: F) -> Self {
        Self { inner, cb }
    }
}

impl<S, F, E> BpfSender<E> for BpfSenderWrapper<S, F>
where
    S: BpfSender<E> + Clone + Send + 'static,
    F: FnMut(&BpfEvent<E>) + Clone + Send + 'static,
{
    fn send(&mut self, data: Result<BpfEvent<E>, ProgramError>) {
        if let Ok(event) = &data {
            (self.cb)(event);
        }
        self.inner.send(data)
    }
}
