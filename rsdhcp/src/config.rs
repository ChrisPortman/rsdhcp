use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::Ipv4Addr;

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: Ipv4Addr,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Netbox {
    pub base_url: String,
    pub auth_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Memory {
    pub scope: [Ipv4Addr; 2],
    pub gateway: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub domain_name: String,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_search: Vec<String>,
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            scope: [Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)],
            gateway: Ipv4Addr::new(0, 0, 0, 0),
            subnet_mask: Ipv4Addr::new(0, 0, 0, 0),
            domain_name: String::new(),
            dns_servers: vec![],
            dns_search: vec![],
        }
    }
}

// Create a lazy loaded config singleton as a threadsafe static.
static CONFIG: OnceCell<Config> = OnceCell::new();

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "backend_name")]
pub enum Backend {
    #[serde(rename = "netbox")]
    Netbox(Netbox),
    #[serde(rename = "memory")]
    Memory(Memory),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub backend: Backend,
}

impl Config {
    pub fn load_from_file<R: Read>(file: R) -> Result<&'static Self, serde_yaml::Error> {
        let c: Self = serde_yaml::from_reader(file)?;
        CONFIG.set(c).unwrap();
        Ok(CONFIG.get().expect("Config not initialized"))
    }
}

#[cfg(test)]
mod tests {
    use crate::config;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_netbox_config() {
        let config_yaml = r#"
---
server:
  listen: "0.0.0.0"

backend:
  backend_name: netbox
  base_url: http://localhost
  auth_token: abcd1234
        "#;

        let config: config::Config = serde_yaml::from_str(config_yaml).expect("failed");
        println!("Config: {:#?}", config);
        assert_eq!(config.server.listen.to_string(), "0.0.0.0");

        if let config::Backend::Netbox(b) = config.backend {
            assert_eq!(b.base_url, "http://localhost");
            assert_eq!(b.auth_token, "abcd1234");
        } else {
            assert_eq!(1, 2, "Backend did not resolve a Netbox config");
        }
    }

    #[test]
    fn test_parse_memory_config() {
        let config_yaml = r#"
---
server:
  listen: "0.0.0.0"

backend:
  backend_name: memory
  scope:
    - 192.168.0.10
    - 192.168.0.100
  gateway: 192.168.0.1
  subnet_mask: 255.255.255.0
  dns_servers:
    - 8.8.8.8
    - 8.8.1.1
        "#;

        let config: config::Config = serde_yaml::from_str(config_yaml).expect("failed");
        println!("Config: {:#?}", config);
        assert_eq!(config.server.listen.to_string(), "0.0.0.0");

        if let config::Backend::Memory(b) = config.backend {
            assert_eq!(
                b.scope,
                [
                    Ipv4Addr::new(192, 168, 0, 10),
                    Ipv4Addr::new(192, 168, 0, 100)
                ]
            );
            assert_eq!(b.gateway, Ipv4Addr::new(192, 168, 0, 1));
            assert_eq!(
                b.dns_servers,
                vec!(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 1, 1))
            );
        } else {
            assert_eq!(1, 2, "Backend did not resolve a Memory config");
        }
    }
}
