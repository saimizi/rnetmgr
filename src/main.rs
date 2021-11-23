mod logger;
mod netif;
mod netinfo;
mod netif_mon;

use clap::{App, Arg};
use log::LevelFilter;
use logger::js_logger_init;
use netif_mon::NetIfMon;
use serde_derive::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetIfConfigEntry {
    ifname: String,
    iftype: String,
    addr_type: String,
    ipv4: Option<String>,
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
                Arg::new("verbos")
                    .short('v')
                    .multiple_occurrences(true)
                    .about("Level of verbosity"),
            )
            .get_matches();

        match matches.occurrences_of("verbos") {
            0 => js_logger_init(matches.value_of("log-file"), LevelFilter::Info, false),
            1 => js_logger_init(matches.value_of("log-file"), LevelFilter::Debug, false),
            2 => js_logger_init(matches.value_of("log-file"), LevelFilter::Debug, true),
            _ => js_logger_init(matches.value_of("log-file"), LevelFilter::Trace, true),
        }

        let config_file = matches.value_of("config-file").unwrap();

        finfo!("Use config: {}", config_file);

        let config_str = match fs::read_to_string(&config_file) {
            Ok(a) => a,
            Err(e) => {
                ferror!("Open {} faled: {}", config_file, e);
                std::process::exit(1);
            }
        };

        fdebug!("{}", config_str);

        let config: NetIfConfig = match serde_json::from_str(&config_str) {
            Ok(a) => a,
            Err(e) => {
                ferror!("Invalid configuration: {}.", e);
                std::process::exit(1);
            }
        };

        if let Err(e) = NetIfMon::run(config).await {
            ferror!("Error: {}", e);
        }
    };

    rt.block_on(async { main_work.await });
}
