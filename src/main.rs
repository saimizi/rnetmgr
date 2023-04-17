//cspell:word netif ifname iftype netifs jinfo jdebug jwarn jerror rnetmgr routeif
mod netif;
mod netif_mon;
mod rnetmgr_error;

#[allow(unused)]
use {
    clap::Parser,
    error_stack::{IntoReport, Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    netif_mon::NetIfMon,
    rnetmgr_error::RnetmgrError,
    serde_derive::{Deserialize, Serialize},
    std::fs,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about= None)]
struct Cli {
    #[clap(short='c', long="config-file", default_value_t=String::from("/etc/rnetmgr.json"))]
    config_file: String,

    #[clap(short='d', long="dhcp-conf", default_value_t=String::from("/etc/dhcp4-template.conf"))]
    dhcp_conf: String,

    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetIfConfigEntry {
    ifname: String,
    iftype: String,
    addr_type: String,
    ipv4: Option<String>,
    routeif: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetIfConfig {
    netifs: Vec<NetIfConfigEntry>,
}

async fn main_work() -> Result<(), RnetmgrError> {
    let cli = Cli::parse();

    let max_level = match cli.verbose {
        1 => LevelFilter::DEBUG,
        2 => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_time(LogTimeFormat::TimeStamp)
        .build();

    jinfo!("Use config: {}", cli.config_file);

    let config_str = fs::read_to_string(cli.config_file.as_str())
        .into_report()
        .change_context(RnetmgrError::InvalidValue)
        .attach_printable(format!("Failed to read config file {}", cli.config_file))?;

    jdebug!("{}", config_str);

    let config = serde_json::from_str(&config_str)
        .into_report()
        .change_context(RnetmgrError::InvalidValue)
        .attach_printable(format!("Config file {} is invalid", cli.config_file))?;

    let dhcp_conf = fs::read_to_string(cli.dhcp_conf.as_str())
        .into_report()
        .change_context(RnetmgrError::InvalidValue)
        .attach_printable(format!("Failed to read dhcp config file {}", cli.dhcp_conf))?;

    NetIfMon::run(config, dhcp_conf).await
}

fn main() -> Result<(), RnetmgrError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(3 * 1024 * 1024)
        .enable_io()
        .enable_time()
        .thread_name("tokio-rnetmgr")
        .build()
        .unwrap();

    rt.block_on(async { main_work().await })
}
