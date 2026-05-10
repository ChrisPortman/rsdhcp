use std::env;
use std::fs::File;
use std::thread::sleep;
use std::time::Duration;

use log::info;

use rsdhcp::backends::memory::Memory;
use rsdhcp::backends::netbox::Netbox;
use rsdhcp::{config, server};

fn load_config(path: &str) -> Option<&'static config::Config> {
    let cfg_file = File::open(path);
    if let Err(e) = cfg_file {
        println!("{}", e);
        return None;
    }

    let cfg = config::Config::load_from_file(&cfg_file.expect(""));
    if let Err(e) = cfg {
        println!("{}", e);
        return None;
    }
    Some(cfg.expect(""))
}

fn config_file() -> String {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        // No arguments - return default
        1 => return "config.yaml".to_string(),
        3 if args[1] == "-c" => {
            return args[2].clone();
        }
        _ => {}
    };

    print!("Usage: {} [-c path_to_config]", args[0]);
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    env_logger::init();

    info!("Starting...");
    let cfg_file = config_file();
    let cfg = match load_config(&cfg_file) {
        Some(c) => c,
        None => return,
    };

    println!("{:#?}", cfg);

    match &cfg.backend {
        config::Backend::Memory(s) => {
            info!("Using backend Memory");
            let mem_backend = Memory::from_cfg(s);
            let mut srv = server::Server::new(mem_backend);
            srv.serve().await.expect("server died with error");
        }
        config::Backend::Netbox(s) => {
            info!("Using backend Netbox");
            let nb_backend = Netbox::from_cfg(s);
            let mut srv = server::Server::new(nb_backend);
            srv.serve().await.expect("server died with error");
        }
    }

    loop {
        sleep(Duration::from_secs(10));
    }
}
