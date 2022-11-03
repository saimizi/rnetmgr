//cspell:word netif ifname iftype netifs jinfo jdebug jwarn jerror rnetmgr routeif
mod netif;
mod netif_mon;

use clap::{App, Arg};

#[allow(unused)]
use jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder};

use log::LevelFilter;
use netif_mon::NetIfMon;
use serde_derive::{Deserialize, Serialize};
use std::fs;

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

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(3 * 1024 * 1024)
        .enable_io()
        .enable_time()
        .thread_name("tokio-rnetmgr")
        .build()
        .unwrap();

    let main_work = async {
        let matches = App::new("rnetmgr")
            .version("0.1")
            .about("Network manager")
            .arg(
                Arg::new("config-file")
                    .short('f')
                    .long("config-file")
                    .value_name("CONFIG_FILE")
                    .about("Configuration file")
                    .required(true)
                    .takes_value(true),
            )
            .arg(
                Arg::new("log-file")
                    .short('l')
                    .long("log-file")
                    .value_name("LOG_FILE")
                    .about("Log file"),
            )
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .multiple_occurrences(true)
                    .about("Level of verbosity"),
            )
            .get_matches();

        let max_level = match matches.occurrences_of("verbose") {
            0 => LevelFilter::Info,
            1 => LevelFilter::Debug,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        };

        JloggerBuilder::new()
            .max_level(max_level)
            .log_time(true)
            .log_time_format(jlogger::LogTimeFormat::TimeStamp)
            .build();

        let config_file = matches.value_of("config-file").unwrap();

        jinfo!("Use config: {}", config_file);

        let config_str = match fs::read_to_string(&config_file) {
            Ok(a) => a,
            Err(e) => {
                jerror!("Open {} failed: {}", config_file, e);
                std::process::exit(1);
            }
        };

        jdebug!("{}", config_str);

        let config: NetIfConfig = match serde_json::from_str(&config_str) {
            Ok(a) => a,
            Err(e) => {
                jerror!("Invalid configuration: {}.", e);
                std::process::exit(1);
            }
        };

        if let Err(e) = NetIfMon::run(config).await {
            jerror!("Error: {}", e);
        }
    };

    rt.block_on(async { main_work.await });
}
