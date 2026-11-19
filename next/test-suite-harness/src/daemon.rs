//! The daemon under test.
//!
//! Every test starts its own daemon, after its helpers are running, and stops
//! it when they are done. That costs a probe load and a read of /proc per test,
//! and tests can't run in parallel, because they share the pin directory. In
//! exchange:
//!
//! - A helper's own start (the exec of `/proc/self/exe`, procspawn's socket)
//!   happens before anything is watching. The daemon learns about helpers
//!   from /proc, like about any process started before Pulsar, so their image
//!   is the real path of this binary.
//! - Every test starts with an empty ring, process table and interest map, so
//!   nothing left over from an earlier test can change its result.
//! - Every test knows how many records were lost or invalid while it ran, and
//!   fails as incomplete when any were. A test without them that misses an
//!   event fails for real, never as a side effect of losses.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};
use next_core::{
    CoreConfig, Oss, Pulsar, Schema,
    daemon::PulsarBuilder,
    event::Event,
    payload::{KindOf, OssPayload, OssPayloadKind, PayloadSet},
    probe::ProcessProbe,
    processor::{DetectCtx, Detector, Interest, Stats},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout_at},
};

use crate::{Outcome, Verdict};

/// Not the daemon's: a start removes stale pins, which would break a
/// `pulsard-next` running on the same machine.
const PIN_DIR: &str = "/sys/fs/bpf/pulsar-next-tests";

/// How long the records of an exited helper may take to be read, unless the
/// test sets its own with [`TestDaemon::read_timeout`].
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A daemon of schema `S`: [`Oss`], or an extension's.
pub struct TestDaemon<S: Schema = Oss> {
    events: mpsc::UnboundedReceiver<Arc<Event<S::Payload>>>,
    shutdown: oneshot::Sender<()>,
    running: JoinHandle<anyhow::Result<Stats>>,
    read_timeout: Duration,
}

/// What the daemon produced while a test ran.
pub struct Recording<P = OssPayload> {
    pub events: Vec<Arc<Event<P>>>,
    pub stats: Stats,
}

impl<P> Recording<P> {
    /// The outcome of a test that found `verdict` on these events.
    pub fn outcome(&self, verdict: Verdict) -> Outcome {
        Outcome {
            verdict,
            lost: self.stats.lost,
            invalid: self.stats.invalid,
        }
    }
}

impl TestDaemon {
    /// With the OSS probes and the default configuration. Returns once the
    /// probes are attached and /proc was read.
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_configured(|_| {}).await
    }

    /// With the OSS probes and the configuration `configure` makes of the
    /// default.
    pub async fn start_configured(configure: impl FnOnce(&mut CoreConfig)) -> anyhow::Result<Self> {
        Self::start_with(configure, |pulsar| pulsar.probe(ProcessProbe)).await
    }
}

impl<S: Schema> TestDaemon<S> {
    /// With the configuration `configure` makes of the default, and the
    /// probes `probes` adds. Returns once they are attached and /proc was
    /// read.
    pub async fn start_with(
        configure: impl FnOnce(&mut CoreConfig),
        probes: impl FnOnce(PulsarBuilder<S>) -> PulsarBuilder<S>,
    ) -> anyhow::Result<Self> {
        let mut config = CoreConfig::default();
        config.loader.pin_dir = PIN_DIR.into();
        configure(&mut config);
        let (collected, events) = mpsc::unbounded_channel();
        let running = probes(Pulsar::<S>::builder(config))
            .detector(Collector::<S>(collected))
            .build()
            .await
            .context("starting the daemon")?;
        let (shutdown, stop) = oneshot::channel();
        let running = tokio::spawn(running.run(async {
            stop.await.ok();
        }));
        Ok(Self {
            events,
            shutdown,
            running,
            read_timeout: DEFAULT_READ_TIMEOUT,
        })
    }

    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Stops the daemon once the exit of `pid` was read, and returns every
    /// event read until then. The ring keeps the order records were written
    /// in, so everything written before that exit was read too.
    pub async fn stop_after_exit(mut self, pid: u32) -> anyhow::Result<Recording<S::Payload>> {
        let deadline = Instant::now() + self.read_timeout;
        let mut events = Vec::new();
        let missing = loop {
            match timeout_at(deadline, self.events.recv()).await {
                Err(_) => break Some(format!("no exit of {pid} within {:?}", self.read_timeout)),
                Ok(None) => break Some("the daemon stopped".to_owned()),
                Ok(Some(event)) => {
                    let exited = event.payload.kind() == OssPayloadKind::Exit.into()
                        && subject_pid(&event) == Some(pid);
                    events.push(event);
                    if exited {
                        break None;
                    }
                }
            }
        };
        self.shutdown.send(()).ok();
        let stats = self.running.await??;
        // The exit may be one of the records lost or invalid: the test then
        // fails as incomplete, not as broken.
        if let Some(missing) = missing
            && stats.lost == 0
            && stats.invalid == 0
        {
            bail!(missing);
        }
        Ok(Recording { events, stats })
    }
}

pub fn subject_pid<P>(event: &Event<P>) -> Option<u32> {
    event.header.subject.as_ref().map(|subject| subject.pid)
}

/// Hands every event to the test. The channel is unbounded, so the collector
/// neither blocks the processor nor drops events.
struct Collector<S: Schema>(mpsc::UnboundedSender<Arc<Event<S::Payload>>>);

impl<S: Schema> Detector<S> for Collector<S> {
    fn name(&self) -> &'static str {
        "test-collector"
    }

    fn interest(&self) -> Interest<KindOf<S>> {
        Interest::All
    }

    fn on_event(&mut self, event: &Arc<Event<S::Payload>>, _: &mut DetectCtx<'_, S>) {
        // Fails only once the test stopped reading.
        self.0.send(event.clone()).ok();
    }
}
