use anyhow::Result;
use candy_core::manifest::core_manifest;
use clap::Parser;
use serverd_linux::{
    initialize_or_rotate_ech, load_server_config_from_str, preflight_server_config_from_str,
    retire_ech_key, run_loaded_server,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, required_unless_present_any = ["setup_ech", "retire_ech_key", "core_info"])]
    config: Option<PathBuf>,

    #[arg(long, conflicts_with_all = ["check_config", "preflight", "setup_ech", "retire_ech_key"])]
    core_info: bool,

    #[arg(long)]
    check_config: bool,

    #[arg(long)]
    preflight: bool,

    /// Create or rotate a server ECH key for this public DNS name.
    #[arg(long, value_name = "PUBLIC_NAME", conflicts_with_all = ["check_config", "preflight"])]
    setup_ech: Option<String>,

    #[arg(long, default_value = "/var/lib/candy/ech")]
    ech_directory: PathBuf,

    /// Retire an old ECH key after the previous DNS TTL and client cache lifetime elapsed.
    #[arg(long, value_parser = parse_hex_byte, conflicts_with_all = ["setup_ech", "check_config", "preflight"])]
    retire_ech_key: Option<u8>,
}

fn parse_hex_byte(value: &str) -> Result<u8, String> {
    u8::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|_| "ECH key ID must be one hexadecimal byte, for example 7f".to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    if args.core_info {
        println!(
            "{}",
            serde_json::to_string_pretty(&core_manifest())?
        );
        return Ok(());
    }
    if let Some(public_name) = args.setup_ech {
        let report = initialize_or_rotate_ech(&args.ech_directory, &public_name)?;
        println!("ECH key created: {:02x}", report.config_id);
        println!("ECH key count: {}", report.key_count);
        println!("Add this to server.toml:");
        println!("[ech]");
        println!("directory = {:?}", args.ech_directory.to_string_lossy());
        println!("Restart Candy, then publish this HTTPS/SVCB parameter:");
        println!("ech={}", report.dns_ech_value);
        println!(
            "ECHConfigList: {}",
            report.config_list_file.to_string_lossy()
        );
        return Ok(());
    }
    if let Some(config_id) = args.retire_ech_key {
        let report = retire_ech_key(&args.ech_directory, config_id)?;
        println!("ECH key retired: {config_id:02x}");
        println!("ECH key count: {}", report.key_count);
        println!("Restart Candy, then publish this HTTPS/SVCB parameter:");
        println!("ech={}", report.dns_ech_value);
        return Ok(());
    }
    let config = args.config.expect("clap requires --config");
    let text = std::fs::read_to_string(&config)?;
    if args.check_config {
        let loaded = load_server_config_from_str(&text)?;
        println!("config ok: {}", loaded.summary.listen);
        return Ok(());
    }
    if args.preflight {
        let report = preflight_server_config_from_str(&text).await?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let loaded = load_server_config_from_str(&text)?;
    if loaded.summary.cert_source == "generated-development" {
        tracing::warn!("using generated ephemeral certificate; client pins will change on restart");
    }
    run_loaded_server(loaded).await
}
