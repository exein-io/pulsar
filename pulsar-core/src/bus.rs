use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::pdk::Event;

#[derive(Clone)]
pub struct Bus {
    tx: broadcast::Sender<Arc<Event>>,
}

/// Describes a bus error.
#[derive(Error, Debug)]
pub enum BusError {
    #[error("bus is stopped")]
    Stopped,
}

const BUFFER_SIZE: usize = 1000;

impl Bus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(BUFFER_SIZE);
        Self { tx }
    }

    pub fn send(&self, event: Event) -> Result<(), BusError> {
        log::trace!(
            target: &format!("event::{}", event.header.source),
            "{:?} [{}:{}]  {:?}",
            event.header.timestamp,
            event.header.pid,
            event.header.image,
            event.payload
        );

        let _ = self.tx.send(Arc::new(event));
        Ok(())
    }

    pub fn get_sender(&self) -> Self {
        self.clone()
    }

    pub fn get_receiver(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}
