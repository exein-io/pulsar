//! This benchmark simulates a typical Pulsar session.
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::{Arc, Barrier};

criterion_main!(benches);
criterion_group!(benches, criterion_benchmark);

/// Event payload size.
/// If this is big, we must wrap events in Arc.
const EVENT_SIZE: usize = 32;

/// Number of producer threads
const PRODUCERS: usize = 10;

/// Number of consumer threads
const CONSUMERS: usize = 10;

/// Number of events each producer will make before quitting
const EVENTS_PER_PRODUCER: usize = 1000;

/// Buffer size in queues where it's preallocated
const QUEUE_SIZE: usize = 10000;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut c = c.benchmark_group("bus");
    let c = c.sample_size(10);

    for (name, bus) in [
        ("argo", argo::bus as Bus),
        ("crossbeam_dispacher", crossbeam_dispacher::bus as Bus),
        ("crossbeam_mutex", crossbeam_mutex::bus as Bus),
        ("jonhoo", jonhoo::bus as Bus),
    ] {
        let tasks = bus();
        let runner = ThreadRunner::new(tasks);
        c.bench_function(name, |bencher| bencher.iter(|| runner.run()));
    }

    let bus = tokio_broadcast::Bus::new();
    c.bench_function("tokio", |bencher| bencher.iter(|| bus.benchmark()));
}

/// A function which can be executed inside the thread runner
type Closure = Box<dyn FnMut() -> () + Send + 'static>;
type Bus = fn() -> Vec<Closure>;

#[derive(Clone, Debug)]
pub struct Event {
    pub payload: [u8; EVENT_SIZE],
}

impl Default for Event {
    fn default() -> Self {
        Self {
            payload: [0; EVENT_SIZE],
        }
    }
}

/// Benchmark utility to start several threads at the same time
struct ThreadRunner {
    barrier: Arc<Barrier>,
}

impl ThreadRunner {
    fn new(tasks: Vec<Closure>) -> Self {
        let barrier = Arc::new(Barrier::new(tasks.len() + 1));
        tasks.into_iter().for_each(|mut task| {
            let c = barrier.clone();
            std::thread::spawn(move || loop {
                c.wait();
                task();
                c.wait();
            });
        });
        Self { barrier }
    }

    fn run(&self) {
        // println!("start");
        self.barrier.wait();
        // println!("wait end");
        self.barrier.wait();
        // println!("end");
    }
}

/// There is a single mpsc channel for sending events to the dispacher.
/// There is a different channel for every consumer.
/// The dispacher runs in its own thread and broadcasts the events to every consumer.
mod crossbeam_dispacher {
    use super::*;
    pub fn bus() -> Vec<Closure> {
        let mut tasks: Vec<Closure> = Vec::new();
        let (tx_producer, rx_producer) = crossbeam_channel::unbounded();
        for _ in 0..PRODUCERS {
            let tx = tx_producer.clone();
            tasks.push(Box::new(move || {
                for _ in 0..EVENTS_PER_PRODUCER {
                    tx.send(Arc::new(black_box(Event::default()))).unwrap()
                }
            }));
        }
        let mut tx_consumers = Vec::new();
        for _ in 0..CONSUMERS {
            let (tx, rx) = crossbeam_channel::unbounded();
            tx_consumers.push(tx);
            tasks.push(Box::new(move || {
                for _ in 0..PRODUCERS * EVENTS_PER_PRODUCER {
                    let _ = black_box(rx.recv().unwrap());
                }
                assert!(rx.try_recv().is_err());
            }));
        }
        // Spawn the broadcast thread, which broadcasts messages received
        // by producers to every consumer
        std::thread::spawn(move || loop {
            while let Ok(msg) = rx_producer.recv() {
                for tx in &tx_consumers {
                    let _ = tx.send(msg.clone());
                }
            }
        });
        tasks
    }
}

/// There is a crossbeam channel for each consumer.
/// All senders share a Arc<Mutex<>> with the list of all receivers.
/// No dispacher thread is used.
mod crossbeam_mutex {
    use super::*;
    use parking_lot::Mutex;
    pub fn bus() -> Vec<Closure> {
        let mut tasks: Vec<Closure> = Vec::new();
        let mut tx_consumers = Vec::new();
        for _ in 0..CONSUMERS {
            let (tx, rx) = crossbeam_channel::unbounded();
            tx_consumers.push(tx);
            tasks.push(Box::new(move || {
                for _ in 0..PRODUCERS * EVENTS_PER_PRODUCER {
                    let _ = black_box(rx.recv().unwrap());
                }
                assert!(rx.try_recv().is_err());
            }));
        }
        // Add consumers to Arc<Mutex<>> to share it between all producers
        let tx_consumers = Arc::new(Mutex::new(tx_consumers));
        for _ in 0..PRODUCERS {
            let tx_consumers = tx_consumers.clone();
            tasks.push(Box::new(move || {
                for _ in 0..EVENTS_PER_PRODUCER {
                    let msg = Arc::new(black_box(Event::default()));
                    for tx in tx_consumers.lock().iter() {
                        let _ = tx.send(msg.clone());
                    }
                }
            }));
        }
        tasks
    }
}

/// Argo ring_channel-based bus:
/// - Each subscriber creates a new ring_channel and stores in the bus the sender.
/// - On send we copy the event to each receiver.
mod argo {
    use super::*;
    use parking_lot::Mutex;
    use ring_channel::RingSender;
    use std::{num::NonZeroUsize, sync::Arc};

    pub fn bus() -> Vec<Closure> {
        let senders: Arc<Mutex<Vec<RingSender<Box<Event>>>>> = Arc::new(Mutex::new(Vec::new()));

        let mut tasks: Vec<Closure> = Vec::new();
        for _ in 0..CONSUMERS {
            let (tx, mut rx) = ring_channel::ring_channel(NonZeroUsize::new(QUEUE_SIZE).unwrap());
            senders.lock().push(tx);
            tasks.push(Box::new(move || {
                for _ in 0..PRODUCERS * EVENTS_PER_PRODUCER {
                    let _ = black_box(rx.recv().unwrap());
                }
                assert!(rx.try_recv().is_err());
            }));
        }
        for _ in 0..PRODUCERS {
            let senders = Arc::clone(&senders);
            tasks.push(Box::new(move || {
                for _ in 0..EVENTS_PER_PRODUCER {
                    let event = Box::new(black_box(Event::default()));
                    for tx in senders.lock().iter_mut() {
                        tx.send(event.clone()).unwrap();
                    }
                }
            }));
        }
        tasks
    }
}

/// This bus supports only one producer.
/// https://github.com/jonhoo/bus
mod jonhoo {
    use super::*;
    use bus::Bus;
    pub fn bus() -> Vec<Closure> {
        let mut bus = Bus::new(QUEUE_SIZE);

        let mut tasks: Vec<Closure> = Vec::new();
        for _ in 0..CONSUMERS {
            let mut rx = bus.add_rx();
            tasks.push(Box::new(move || {
                for _ in 0..PRODUCERS * EVENTS_PER_PRODUCER {
                    let _ = black_box(rx.recv().unwrap());
                }
                assert!(rx.try_recv().is_err());
            }));
        }
        //for _ in 0..PRODUCERS {
        tasks.push(Box::new(move || {
            for _ in 0..PRODUCERS * EVENTS_PER_PRODUCER {
                let msg = Arc::new(black_box(Event::default()));
                let _ = bus.broadcast(msg);
            }
        }));
        //}
        tasks
    }
}

/// Uses the brodcast tokio channel
mod tokio_broadcast {
    use super::*;
    use tokio::{
        runtime::Runtime,
        sync::{broadcast, Barrier},
    };

    pub struct Bus {
        rt: Runtime,
        barrier: Arc<Barrier>,
    }

    impl Bus {
        pub fn new() -> Self {
            let rt = Runtime::new().unwrap();
            let barrier = Arc::new(Barrier::new(CONSUMERS + PRODUCERS + 1));
            rt.block_on(async { setup(barrier.clone()).await });
            Self { rt, barrier }
        }

        pub fn benchmark(&self) {
            self.rt.block_on(async {
                //println!("start");
                self.barrier.wait().await;
                //println!("wait");
                self.barrier.wait().await;
                //println!("end");
            });
        }
    }

    async fn setup(barrier: Arc<Barrier>) {
        let (tx, _rx) = broadcast::channel(QUEUE_SIZE);
        for _ in 0..PRODUCERS {
            let tx = tx.clone();
            let c = barrier.clone();
            tokio::spawn(async move {
                loop {
                    c.wait().await;
                    for _ in 0..EVENTS_PER_PRODUCER {
                        tx.send(Arc::new(black_box(Event::default()))).unwrap();
                    }
                    c.wait().await;
                }
            });
        }
        for _ in 0..CONSUMERS {
            let mut rx = tx.subscribe();
            let c = barrier.clone();
            tokio::spawn(async move {
                loop {
                    c.wait().await;
                    for _ in 0..PRODUCERS * EVENTS_PER_PRODUCER {
                        let _ = black_box(rx.recv().await.unwrap());
                    }
                    c.wait().await;
                }
            });
        }
    }
}
