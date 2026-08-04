#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "candy-sdwan")]
struct Args {
    #[arg(long, default_value = "/etc/candy/sdwan.toml")]
    config: PathBuf,
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let args = Args::parse();
    let config = candy_sdwan::load_config(&args.config)?;
    if args.check_config {
        return Ok(());
    }
    candy_sdwan::run(config).await
}
