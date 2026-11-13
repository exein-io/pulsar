//! Composing and running Pulsar: probes, detectors and reporters around one
//! processor.

use std::{future::Future, marker::PhantomData, os::unix::ffi::OsStringExt, sync::Arc};

use anyhow::Context;
use bpf_filtering::{
    config::{Config as FilteringConfig, Rule},
    maps::{Image, RuleMap},
};
use next_bpf::{
    loader::{LoadedProbe, Loader, LoaderConfig},
    ring::Ring,
};
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
};

use crate::{
    Schema,
    probe::Probe,
    processor::{Detector, Input, Processor, Reporter, Stats, Tapped},
    seed,
    table::TableConfig,
    threat::Threat,
};

#[derive(Clone, Debug)]
pub struct CoreConfig {
    pub loader: LoaderConfig,
    pub filtering: FilteringConfig,
    pub table: TableConfig,
    /// Records between the ring and the processor.
    pub input_queue: usize,
    /// Threats waiting for each reporter; the oldest is dropped when full.
    pub threat_queue: usize,
    pub tap_queue: usize,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            loader: LoaderConfig::default(),
            filtering: FilteringConfig::default(),
            table: TableConfig::default(),
            input_queue: 4096,
            threat_queue: 1024,
            tap_queue: 1024,
        }
    }
}

pub struct Pulsar<S: Schema>(PhantomData<S>);

impl<S: Schema> Pulsar<S> {
    pub fn builder(config: CoreConfig) -> PulsarBuilder<S> {
        PulsarBuilder {
            config,
            probes: Vec::new(),
            detectors: Vec::new(),
            reporters: Vec::new(),
        }
    }
}

type StartReporter<S> =
    Box<dyn FnOnce(broadcast::Receiver<Arc<Threat<S>>>) -> JoinHandle<()> + Send>;

pub struct PulsarBuilder<S: Schema> {
    config: CoreConfig,
    probes: Vec<Box<dyn Probe<S>>>,
    detectors: Vec<Box<dyn Detector<S>>>,
    reporters: Vec<StartReporter<S>>,
}

impl<S: Schema> PulsarBuilder<S> {
    pub fn probe(mut self, probe: impl Probe<S>) -> Self {
        self.probes.push(Box::new(probe));
        self
    }

    pub fn detector(mut self, detector: impl Detector<S>) -> Self {
        self.detectors.push(Box::new(detector));
        self
    }

    pub fn reporter(mut self, reporter: impl Reporter<S>) -> Self {
        self.reporters.push(Box::new(|threats| {
            tokio::spawn(run_reporter(reporter, threats))
        }));
        self
    }

    /// Starts everything, in an order that loses nothing at start:
    ///
    /// 1. Remove stale pins and load every object; the first creates the ring.
    /// 2. Start reading the ring and the processor.
    /// 3. Install the image rules, with Pulsar itself ignored.
    /// 4. Attach the lifecycle probes.
    /// 5. Read /proc into the interest map and the process table; the stream
    ///    already knows the processes started since step 4.
    /// 6. Attach the other probes, then start the reporters.
    pub async fn build(mut self) -> anyhow::Result<Running<S>> {
        // Lifecycle probes first: they must be attached before /proc is read.
        self.probes.sort_by_key(|probe| !probe.reports_lifecycle());
        let config = self.config;

        let mut loader = Loader::new(config.loader.clone())?;
        let mut loaded = Vec::new();
        let (tap, _) = broadcast::channel(config.tap_queue);
        let mut processor = Processor::new(config.table.clone(), tap.clone());
        for probe in self.probes {
            let object = loader.load(probe.spec())?;
            let lifecycle = probe.reports_lifecycle();
            processor.add_probe(object.producer(), probe);
            loaded.push((object, lifecycle));
        }
        for detector in self.detectors {
            processor.add_detector(detector);
        }
        let (threats, _) = broadcast::channel(config.threat_queue);
        let reporters: Vec<_> = self
            .reporters
            .into_iter()
            .map(|start| (start, threats.subscribe()))
            .collect();

        let (inputs, inputs_rx) = mpsc::channel(config.input_queue);
        let ring = Ring::open(loader.pin_dir())?;
        let ingest = tokio::spawn(ring.run(inputs.clone()));
        let processor = tokio::spawn(processor.run(inputs_rx, threats.clone()));

        let lifecycle_object = loaded
            .iter_mut()
            .find(|(_, lifecycle)| *lifecycle)
            .map(|(object, _)| object);
        let rules = match lifecycle_object {
            Some(object) => Some(install_rules(object, &config.filtering).await?),
            None => None,
        };
        for (object, _) in loaded.iter_mut().filter(|(_, lifecycle)| *lifecycle) {
            loader.attach(object)?;
        }
        let processes = tokio::task::spawn_blocking(seed::read_proc).await??;
        if let Some((object, _)) = loaded.iter_mut().find(|(_, lifecycle)| *lifecycle) {
            seed::seed_interest(object.ebpf_mut(), &config.filtering, &processes)?;
        }
        log::info!("{} running processes read from /proc", processes.len());
        inputs.send(Input::Seed(processes)).await?;
        drop(inputs);
        for (object, _) in loaded.iter_mut().filter(|(_, lifecycle)| !*lifecycle) {
            loader.attach(object)?;
        }

        let reporters = reporters
            .into_iter()
            .map(|(start, threats)| start(threats))
            .collect();
        Ok(Running {
            loader,
            _rules: rules,
            objects: loaded.into_iter().map(|(object, _)| object).collect(),
            ingest,
            processor,
            reporters,
            tap,
        })
    }
}

/// The returned map must outlive the programs: it is taken out of the object,
/// and the programs, loaded at attach, refer to it by its file descriptor.
async fn install_rules(
    object: &mut LoadedProbe,
    config: &FilteringConfig,
) -> anyhow::Result<RuleMap> {
    let mut rules = config.rules.clone();
    if config.ignore_self {
        let exe = tokio::fs::read_link("/proc/self/exe")
            .await
            .context("reading /proc/self/exe")?;
        rules.push(Rule {
            image: Image::try_from(exe.into_os_string().into_vec())?,
            with_children: true,
            track: false,
        });
    }
    let mut map = RuleMap::load(object.ebpf_mut(), &config.rule_map_name)?;
    map.clear()?;
    map.install(&rules)?;
    Ok(map)
}

async fn run_reporter<S: Schema>(
    mut reporter: impl Reporter<S>,
    mut threats: broadcast::Receiver<Arc<Threat<S>>>,
) {
    loop {
        match threats.recv().await {
            Ok(threat) => {
                if let Err(err) = reporter.report(threat).await {
                    log::warn!("{}: {err}", reporter.name());
                }
            }
            Err(broadcast::error::RecvError::Lagged(dropped)) => {
                log::warn!("{}: {dropped} threats dropped", reporter.name());
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

pub struct Running<S: Schema> {
    loader: Loader,
    _rules: Option<RuleMap>,
    objects: Vec<LoadedProbe>,
    ingest: JoinHandle<std::io::Result<()>>,
    processor: JoinHandle<Stats>,
    reporters: Vec<JoinHandle<()>>,
    tap: broadcast::Sender<Tapped<S>>,
}

impl<S: Schema> Running<S> {
    /// Every event and threat, for observers that may lose some.
    pub fn tap(&self) -> broadcast::Receiver<Tapped<S>> {
        self.tap.subscribe()
    }

    /// Runs until `shutdown` completes, then detaches the probes and lets the
    /// processor and the reporters finish what they have.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> anyhow::Result<Stats> {
        shutdown.await;
        drop(self.objects);
        // Reading stops; the processor drains its queue and returns.
        self.ingest.abort();
        let stats = self.processor.await?;
        for reporter in self.reporters {
            reporter.await?;
        }
        if let Err(err) = self.loader.remove_pins() {
            log::warn!("removing pins: {err}");
        }
        Ok(stats)
    }
}
