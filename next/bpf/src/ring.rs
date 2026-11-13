//! Reading the shared ring and its loss counters.

use std::{io, path::Path};

use aya::maps::{Array, Map, MapData, MapError, RingBuf};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc,
};

use crate::{
    ProducerId,
    abi::{PULSAR_LOST_TOTAL, pulsar_record_header},
    record::{DecodeError, RecordView},
};

pub const RING_MAP: &str = "pulsar_events";
pub const LOST_MAP: &str = "pulsar_lost";

/// One record, copied out of the ring.
pub struct Record(Box<[u8]>);

impl Record {
    pub fn view(&self) -> Result<RecordView<'_>, DecodeError> {
        RecordView::parse(&self.0)
    }
}

/// The ring every probe writes into.
pub struct Ring {
    fd: AsyncFd<RingBuf<MapData>>,
}

impl Ring {
    /// Opens the ring pinned in `pin_dir`; at least one object must be
    /// loaded. Must run inside a tokio runtime.
    pub fn open(pin_dir: &Path) -> io::Result<Self> {
        let map = MapData::from_pin(pin_dir.join(RING_MAP))
            .and_then(Map::from_map_data)
            .map_err(io::Error::other)?;
        let ring = RingBuf::try_from(map).map_err(io::Error::other)?;
        // `ring` owns the map's fd, which stays open and unchanged until `ring`
        // is dropped together with the AsyncFd. Becomes the unsafe
        // `AsyncFd::register_with_interest` once tokio is >= 1.53.3 (#450).
        let fd = AsyncFd::with_interest(ring, Interest::READABLE)?;
        Ok(Self { fd })
    }

    /// Copies every record into `tx`, in ring order, until the receiver is
    /// dropped.
    ///
    /// A full channel stops the reading: the ring then fills up and probes
    /// lose records, which the following records report. Records are never
    /// dropped or reordered here.
    pub async fn run<T: From<Record>>(mut self, tx: mpsc::Sender<T>) -> io::Result<()> {
        loop {
            let mut guard = self.fd.readable_mut().await?;
            while let Some(item) = guard.get_inner_mut().next() {
                let record = Record(Box::from(&*item));
                drop(item);
                if tx.send(record.into()).await.is_err() {
                    return Ok(());
                }
            }
            guard.clear_ready();
        }
    }
}

/// How many records the probes failed to write, in total and per producer.
pub struct LossCounters {
    map: Array<MapData, u64>,
}

impl LossCounters {
    /// Opens the counters pinned in `pin_dir`; at least one object must be
    /// loaded.
    pub fn open(pin_dir: &Path) -> Result<Self, MapError> {
        let map = Map::from_map_data(MapData::from_pin(pin_dir.join(LOST_MAP))?)?;
        Ok(Self {
            map: Array::try_from(map)?,
        })
    }

    pub fn total(&self) -> Result<u64, MapError> {
        self.map.get(&PULSAR_LOST_TOTAL, 0)
    }

    pub fn of(&self, producer: ProducerId) -> Result<u64, MapError> {
        self.map.get(&(PULSAR_LOST_TOTAL + 1 + producer.0), 0)
    }
}

/// Finds the positions in the stream where records were lost, from the loss
/// counter that every header carries.
#[derive(Default)]
pub struct LossCursor {
    // The counter starts at 0: pins of earlier runs are removed at load.
    seen: u32,
}

impl LossCursor {
    /// The number of records lost right before the one with `header`.
    pub fn advance(&mut self, header: &pulsar_record_header) -> u32 {
        // The counter is 32 bits wide and wraps. A record written concurrently
        // on another CPU can carry an older value than the record before it;
        // that is not a gap.
        let gap = header.lost.wrapping_sub(self.seen) as i32;
        if gap > 0 {
            self.seen = header.lost;
            gap as u32
        } else {
            0
        }
    }
}
