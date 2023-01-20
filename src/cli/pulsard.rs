use clap::Parser;

pub const NAME: &str = "pulsard";

#[derive(Parser, Debug, Clone)]
#[clap(name = NAME)]
#[clap(about = "Pulsar daemon")]
pub struct PulsarDaemonOpts {
    #[clap(long)]
    pub config_file: Option<String>,
}
