use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
// use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use ipnetwork::Ipv4Network;
use log::info;

use crate::backends::DhcpStore;
use crate::backends::Lease;
use crate::config;
use crate::protocol::option::DhcpOption;
use crate::protocol::packet::DhcpOptions;
use crate::protocol::{option, packet};
use crate::util::domain_name_list_compression;

use super::BackendError;

const DEFAULT_PARAM_LIST: [u8; 3] = [
    option::DhcpOption::SUBNETMASK,
    option::DhcpOption::ROUTER,
    option::DhcpOption::DOMAINSERVER,
];

type Database = Arc<Mutex<HashMap<Ipv4Addr, Lease>>>;

trait DatabaseMethods {
    fn get_unused_ip_addr(&self, scope: &[Ipv4Addr; 2]) -> Option<Ipv4Addr>;
    fn get_exprired_lease_ip_addr(&self) -> Option<Ipv4Addr>;
    fn get_lease_for_xid(&self, xid: u32) -> Option<Lease>;
    fn get_lease_for_ip(&self, ip: &Ipv4Addr) -> Option<Lease>;
    fn store_lease(&self, lease: Lease);
    fn remove_lease(&self, ip: &Ipv4Addr);
}

impl DatabaseMethods for Database {
    fn get_unused_ip_addr(&self, scope: &[Ipv4Addr; 2]) -> Option<Ipv4Addr> {
        for ip in <u32>::from(scope[0])..<u32>::from(scope[1]) {
            let ip = Ipv4Addr::from(ip);
            let db = self.lock().unwrap();
            if !db.contains_key(&ip) {
                return Some(ip);
            }
        }

        None
    }

    fn get_exprired_lease_ip_addr(&self) -> Option<Ipv4Addr> {
        let db = self.lock().unwrap();
        for (ip, lease) in &*db {
            if !lease.is_current() {
                return Some(*ip);
            }
        }

        None
    }

    fn get_lease_for_xid(&self, xid: u32) -> Option<Lease> {
        let db = self.lock().unwrap();
        for lease in (*db).values() {
            if lease.xid == xid {
                return Some(lease.clone());
            }
        }

        None
    }

    fn get_lease_for_ip(&self, ip: &Ipv4Addr) -> Option<Lease> {
        let db = self.lock().unwrap();
        if let Some(lease) = db.get(ip) {
            return Some(lease.clone());
        }
        None
    }

    fn store_lease(&self, lease: Lease) {
        if let Some(ip) = lease.yiaddr {
            let mut db = self.lock().unwrap();
            db.insert(ip, lease);
        }
    }

    fn remove_lease(&self, ip: &Ipv4Addr) {
        let mut db = self.lock().unwrap();
        db.remove(ip);
    }
}

pub struct Memory {
    pub scope: [Ipv4Addr; 2],
    pub gateway: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub domain_name: String,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_search: Vec<String>,

    database: Database,
}

impl Memory {
    pub fn from_cfg(cfg: &config::Memory) -> Self {
        Self {
            scope: cfg.scope,
            gateway: cfg.gateway,
            subnet_mask: cfg.subnet_mask,
            domain_name: cfg.domain_name.clone(),
            dns_servers: cfg.dns_servers.clone(),
            dns_search: cfg.dns_search.clone(),
            database: Arc::new(Mutex::new(HashMap::new())),
        }
    }
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
            database: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl DhcpStore for Memory {
    async fn handle_discover(
        &self,
        _recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        info!("Handling discover message");
        let mut ip = self.database.get_unused_ip_addr(&self.scope);
        if ip.is_none() {
            ip = self.database.get_exprired_lease_ip_addr();
        }
        if ip.is_none() {
            return Err(BackendError::NoLeaseAvailable());
        }

        // let mut lease = Lease::default();
        let mut lease = Lease {
            xid: packet.xid,
            yiaddr: Some(ip.unwrap()),
            lease_duration: Duration::seconds(60 * 60), // 1 hour
            ..Default::default()
        };

        let mut requested_params: &Vec<u8> = &(DEFAULT_PARAM_LIST.into());
        if let Some(DhcpOption::ParameterList(o)) = packet.get_option(DhcpOption::PARAMETERLIST)
            && !o.is_empty()
        {
            requested_params = o;
        }

        let param_options = self.process_params(requested_params);
        if !param_options.is_empty() {
            let lease_options = DhcpOptions::new(Some(param_options));
            lease.options = Some(lease_options)
        }

        self.database.store_lease(lease.clone());
        return Ok(lease);
    }

    async fn handle_request_selecting(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        // selecting is the client state that comes after a discover packet.
        // the "Requested IP address" option is used to carry the IP address contained in the
        // offer.
        info!("Handling request/selecting message");
        if *recv_ip != packet.siaddr {
            return Err(BackendError::BackendError(
                "server ID does is not this server".to_string(),
            ));
        }

        let mut requested_ip_found = false;
        let mut requested_ip = Ipv4Addr::new(0, 0, 0, 0);

        if let Some(DhcpOption::AddressRequest(o)) =
            packet.get_option(option::DhcpOption::ADDRESSREQUEST)
        {
            requested_ip_found = true;
            requested_ip = *o;
        }

        if !requested_ip_found {
            return Err(BackendError::NoLeaseAvailable());
        }

        if let Some(lease) = self.database.get_lease_for_ip(&requested_ip) {
            if lease.xid != packet.xid {
                return Err(BackendError::NoLeaseAvailable());
            }
            return Ok(lease);
        }

        Err(BackendError::NoLeaseAvailable())
    }

    async fn handle_request_init_reboot(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        // A client that previously had an IP address that is rebooting.  The client is attempting
        // to reacquire the previous address.
        // First validate taht the requested IP address is valid for the network it is now
        // connected to (per the giaddr or recv_ip) and then that the requested IP address is still
        // available for it.  If either are false, send a DHCPNAK.
        // The server ID (siaddr) will be empty.
        // The "Requested IP Address" option will be used to carry the requested IP address.
        info!("Handling request/init_reboot message");
        let mut requested_ip = Ipv4Addr::new(0, 0, 0, 0);
        if let Some(DhcpOption::AddressRequest(o)) =
            packet.get_option(option::DhcpOption::ADDRESSREQUEST)
        {
            requested_ip = *o;
        }

        if requested_ip.is_unspecified() {
            return Err(BackendError::ProtocolError(
                "Init Reboot state expects".to_string(),
            ));
        }

        let mut lease = match self.database.get_lease_for_ip(&requested_ip) {
            Some(l) => l,
            None => return Err(BackendError::NoLeaseAvailable()),
        };

        let mut subnet_mask = Ipv4Addr::new(0, 0, 0, 0);
        if let Some(opts) = &lease.options {
            match opts.get_option(option::DhcpOption::SUBNETMASK) {
                Some(opt) => {
                    if let DhcpOption::SubnetMask(m) = opt {
                        subnet_mask = *m;
                    }
                }
                None => {
                    return Err(BackendError::Generic(
                        "Malformed lease: no subnet mask".to_string(),
                    ));
                }
            };
        }

        if subnet_mask.is_unspecified() {
            return Err(BackendError::Generic(
                "Malformed lease: no subnet mask".to_string(),
            ));
        }

        let origin_ip = if !packet.giaddr.is_unspecified() {
            packet.giaddr
        } else {
            *recv_ip
        };
        if let Ok(requested_net) = Ipv4Network::with_netmask(requested_ip, subnet_mask)
            && !requested_net.contains(origin_ip)
        {
            self.database.remove_lease(&requested_ip);
        }

        lease.lease_time = Utc::now();
        self.database.store_lease(lease.clone());
        return Ok(lease);
    }

    async fn handle_request_renewing(
        &self,
        _recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        info!("Handling request/renewing message");

        let requested_ip = if let Some(opt) = packet.get_option(option::DhcpOption::ADDRESSREQUEST)
        {
            if let DhcpOption::AddressRequest(o) = opt {
                *o
            } else {
                info!("No requested address");
                packet.ciaddr
            }
        } else {
            info!("No requested address option");
            packet.ciaddr
        };

        if requested_ip.is_unspecified() {
            info!("Request packet had no usable requested address");
            return Err(BackendError::ProtocolError(
                "renewing clients must include requested IP".to_string(),
            ));
        }

        if let Some(mut lease) = self.database.get_lease_for_ip(&requested_ip) {
            //Todo: extend the lease
            lease.lease_time = Utc::now();
            self.database.store_lease(lease.clone());
            return Ok(lease);
        }
        info!("No existing lease for {}", requested_ip);

        Err(BackendError::NoLeaseAvailable())
    }

    async fn handle_request_rebinding(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        info!("Handling request/rebinding message");
        self.handle_request_renewing(recv_ip, packet).await
    }

    async fn handle_release(&self, packet: &packet::DhcpPacket) -> Result<(), BackendError> {
        info!("Handling release message");
        let ip = packet.yiaddr;
        self.database.remove_lease(&ip);
        Ok(())
    }

    async fn handle_decline(&self, packet: &packet::DhcpPacket) -> Result<(), BackendError> {
        // This should mark the IP address as invalid in a way and log a warning for the admistrator to indicate
        // an issue with the IP address on the network
        info!("Handling decline message");

        if let Some(lease) = self.database.get_lease_for_xid(packet.xid)
            && let Some(yiadder) = lease.yiaddr
        {
            self.database.remove_lease(&yiadder);
        }
        Ok(())
    }

    async fn handle_inform(
        &self,
        _recv_ip: &Ipv4Addr,
        _packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        info!("Handling inform message");
        Err(BackendError::Generic("Not implemented".to_string()))
    }
}

impl Memory {
    fn process_params(&self, codes: &Vec<u8>) -> Vec<DhcpOption> {
        let mut options: Vec<DhcpOption> = vec![];

        for c in codes {
            match *c {
                option::DhcpOption::ROUTER if !self.gateway.is_unspecified() => {
                    options.push(option::DhcpOption::Router(vec![self.gateway]));
                }
                option::DhcpOption::SUBNETMASK if !self.subnet_mask.is_unspecified() => {
                    options.push(option::DhcpOption::SubnetMask(self.subnet_mask));
                }
                option::DhcpOption::DOMAINSERVER if !self.dns_servers.is_empty() => {
                    options.push(option::DhcpOption::DomainServer(self.dns_servers.clone()));
                }
                option::DhcpOption::DOMAINNAME if !self.domain_name.is_empty() => {
                    options.push(option::DhcpOption::DomainName(self.domain_name.clone()));
                }
                option::DhcpOption::DOMAINSEARCH if !self.dns_search.is_empty() => {
                    let names: Vec<&str> = self.dns_search.iter().map(|s| s.as_ref()).collect();
                    let compressed_names = domain_name_list_compression(&names);
                    options.push(option::DhcpOption::DomainSearch(compressed_names));
                }
                _ => {}
            }
        }

        options
    }
}
