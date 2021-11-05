mod netif_mon;
use clap::{App, Arg};
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
        .get_matches();

    let config_file = matches.value_of("config-file").unwrap();

    println!("Use config: {}", config_file);

    let config_str = match fs::read_to_string(&config_file) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Open {} faled: {}", config_file, e);
            std::process::exit(1);
        }
    };

    println!("{}", config_str);

    let config: NetIfConfig = match serde_json::from_str(&config_str) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Invalid configuration: {}.", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = NetIfMon::run(config) {
        eprintln!("Error: {}", e);
    }
}
