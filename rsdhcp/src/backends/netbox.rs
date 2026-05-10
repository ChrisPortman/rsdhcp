//! Use netbox for lease management.  Requres that the Netbox installation has the
//! `netbox-dhcp` plugin installed.
use std::io::Write;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use log::info;
use reqwest;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::backends::Lease;
use crate::backends::{BackendError, DhcpStore};
use crate::config;
use crate::protocol::option::DhcpOption;
use crate::protocol::packet;

#[derive(Serialize, Debug)]
struct NetboxDhcpLeaseRequest {
    mac_address: String,
    client_id: String,
    receiving_ip: Ipv4Addr,
    requested_ip: Option<Ipv4Addr>,
    hostname: Option<String>,
}

impl From<&packet::DhcpPacket> for NetboxDhcpLeaseRequest {
    fn from(item: &packet::DhcpPacket) -> Self {
        let receiving_ip = item.giaddr;

        let client_id: Vec<u8> = match item.get_option(DhcpOption::CLIENTID) {
            Some(DhcpOption::ClientId(o)) => o.clone(),
            _ => item.chaddr[0..6].to_vec(),
        };

        let requested_ip = match item.get_option(DhcpOption::ADDRESSREQUEST) {
            Some(DhcpOption::AddressRequest(o)) => Some(*o),
            _ => None,
        };

        let hostname = match item.get_option(DhcpOption::HOSTNAME) {
            Some(DhcpOption::Hostname(o)) => Some(o.clone()),
            _ => None,
        };

        NetboxDhcpLeaseRequest {
            mac_address: u8_to_hex(&item.chaddr[0..6].to_vec()),
            client_id: u8_to_hex(&client_id),
            receiving_ip,
            requested_ip,
            hostname,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct NetboxIPAddress {
    address: Ipv4Net,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct NetboxOptions {
    dns_servers: Option<Vec<Ipv4Addr>>,
    domain_name: Option<String>,
    boot_file: Option<String>,
    boot_server: Option<Ipv4Addr>,
    grub_default: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct NetboxDhcpLease {
    id: u32,
    url: String,
    mac_address: String,
    client_id: String,
    receiving_ip: Ipv4Addr,
    requested_ip: Option<Ipv4Addr>,
    hostname: Option<String>,
    lease_time: DateTime<Utc>,
    expire_time: DateTime<Utc>,
    ip_address: NetboxIPAddress,
    gateway: Option<Ipv4Addr>,
    options: NetboxOptions,
    acknowledged: bool,
}

impl NetboxDhcpLease {
    async fn acknowledge(&mut self, client: &Client) -> Result<(), BackendError> {
        self.acknowledged = true;

        match send_request(client.put(&self.url).json(&self)).await {
            Ok(_) => Ok(()),
            Err(e) => {
                self.acknowledged = false;
                Err(e)
            }
        }
    }

    async fn delete(&mut self, client: &Client) -> Result<(), BackendError> {
        match send_request(client.delete(&self.url)).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn update_from_packet(&mut self, packet: &packet::DhcpPacket) {
        if let Some(DhcpOption::Hostname(hostname)) = packet.get_option(DhcpOption::HOSTNAME) {
            self.hostname = Some(hostname.clone());
        }

        if let Some(DhcpOption::ClientId(client_id)) = packet.get_option(DhcpOption::CLIENTID) {
            self.client_id = u8_to_hex(client_id);
        };
    }
}

impl From<NetboxDhcpLease> for Lease {
    fn from(val: NetboxDhcpLease) -> Self {
        let mut p = Lease {
            yiaddr: Some(val.ip_address.address.addr()),
            lease_time: val.lease_time,
            lease_duration: val.expire_time - val.lease_time,
            ..Default::default()
        };

        let mut opts: Vec<DhcpOption> =
            vec![DhcpOption::SubnetMask(val.ip_address.address.netmask())];

        if let Some(o) = val.gateway {
            opts.push(DhcpOption::Router(vec![o]));
        }

        if let Some(o) = val.options.dns_servers {
            opts.push(DhcpOption::DomainServer(o));
        }

        if let Some(o) = val.options.domain_name {
            opts.push(DhcpOption::DomainName(o));
        }

        if let Some(o) = val.options.boot_file {
            let mut filebuf = [0; 128];
            let mut filebuf_p: &mut [u8] = &mut filebuf;
            if filebuf_p.write(o.as_bytes()).is_ok() {
                p.file = Some(filebuf);
            }
            opts.push(DhcpOption::BootfileName(o));
        }

        if let Some(o) = val.options.boot_server {
            p.siaddr = Some(o);
            opts.push(DhcpOption::ServerName(o.to_string()))
        }

        if let Some(o) = val.options.grub_default {
            opts.push(DhcpOption::VendorSpecific(o))
        }

        p.options = Some(packet::DhcpOptions::new(Some(opts)));
        p
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct NetboxPaginatedList<T> {
    count: usize,
    next: Option<String>,
    previous: Option<String>,
    results: Vec<T>,
}

impl<T: DeserializeOwned + Clone> NetboxPaginatedList<T> {
    async fn get(client: &Client, url: &str) -> Result<Self, BackendError> {
        let response = send_request(client.get(url)).await?;
        let page = match response.json::<NetboxPaginatedList<T>>().await {
            Ok(p) => p,
            Err(e) => return Err(BackendError::BackendError(e.to_string())),
        };

        Ok(page)
    }

    async fn all(&self, client: &Client) -> Result<Vec<T>, BackendError> {
        let mut items: Vec<T> = self.results.to_vec();
        let mut next = self.next.clone();

        while let Some(n) = next {
            let page: NetboxPaginatedList<T> = NetboxPaginatedList::get(client, &n).await?;
            items.extend(page.results);
            next = page.next.clone();
        }

        Ok(items)
    }
}

/// The netbox backend implementaion
pub struct Netbox {
    client: Client,
    lease_url: String,
}

impl Netbox {
    /// Generate a netbox backend from the provided config
    pub fn from_cfg(cfg: &config::Netbox) -> Self {
        let mut auth_header =
            HeaderValue::from_str(format!("Token {}", cfg.auth_token).as_str()).unwrap();
        auth_header.set_sensitive(true);

        let mut default_headers = HeaderMap::new();
        default_headers.insert("AUTHORIZATION", auth_header);

        let client = Client::builder()
            .default_headers(default_headers)
            .build()
            .unwrap();

        Self {
            client,
            lease_url: cfg.base_url.clone() + "/api/plugins/dhcp/leases/",
        }
    }

    async fn get_leases_for_mac(
        &self,
        mac_address: String,
    ) -> Result<Vec<NetboxDhcpLease>, BackendError> {
        let response = send_request(
            self.client
                .get(&self.lease_url)
                .query(&[("mac_address", mac_address)]),
        )
        .await?;
        let leases = match response
            .json::<NetboxPaginatedList<NetboxDhcpLease>>()
            .await
        {
            Ok(p) => p.all(&self.client).await?,
            Err(e) => return Err(BackendError::BackendError(e.to_string())),
        };

        Ok(leases)
    }

    async fn get_lease(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<NetboxDhcpLease, BackendError> {
        let mac_address = u8_to_hex(&packet.chaddr[0..6].to_vec());

        let existing_leases = self.get_leases_for_mac(mac_address).await?;
        for mut l in existing_leases {
            if l.ip_address.address.contains(recv_ip) {
                l.update_from_packet(packet);
                l.acknowledge(&self.client).await?;
                return Ok(l);
            }
        }

        let mut new_lease_req = NetboxDhcpLeaseRequest::from(packet);
        if new_lease_req.receiving_ip.is_unspecified() {
            new_lease_req.receiving_ip = *recv_ip;
        }

        info!("request: {:?}", new_lease_req);
        let new_lease_resp =
            send_request(self.client.post(&self.lease_url).json(&new_lease_req)).await?;
        let new_lease = match new_lease_resp.json::<NetboxDhcpLease>().await {
            Ok(r) => r,
            Err(e) => {
                return Err(BackendError::BackendError(format!(
                    "error decoding response data: {:?}",
                    e,
                )));
            }
        };

        Ok(new_lease)
    }

    async fn renew_lease(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<NetboxDhcpLease, BackendError> {
        // We need to consider that Netbox may have multiple leases for the same
        // MAC address.  This may happen expecially if a machine has multiple vlan interfaces on
        // the same physical, and each inherrit the MAC from the physical and each of the VLAN
        // interfaces are DHCP enabled.
        // However, a MAC address SHOULD be unique on any given subnet.  The subnet may be
        // identified by (in order of priority):
        //
        // 1. a CIADDR on the packet
        // 2. a GIADDR which is the IP address of a DHCP relay local to the client
        // 3. the IP address of the server interface which recieved the request.
        //
        // Note that `recv_ip` will contain 2 if present, else 3.
        //
        // Based on this we process the existing_leases, ignoring those that are not on the correct
        // network - assuming they are valid for some other interface on that network.
        // When we find a lease on the correct network, if the ciaddr is present and it matches the
        // lease, return it.  If it doesnt match and the client state is renewing, send and NAK,
        // otherwise ignore it.

        // work out what IP we're using to check leases for subnet locality
        let compare_ip: Ipv4Addr = if !packet.ciaddr.is_unspecified() {
            packet.ciaddr
        } else {
            *recv_ip
        };
        let mac_address = u8_to_hex(&packet.chaddr[0..6].to_vec());
        let mut selected_lease: Option<NetboxDhcpLease> = None;

        // Find an existing lease for the MAC address on the correct subnet
        let existing_leases = self.get_leases_for_mac(mac_address).await?;
        for lease in existing_leases {
            if lease.ip_address.address.contains(&compare_ip) {
                selected_lease = Some(lease);
                break;
            }
        }

        // Work out if the lease is correct per the request (ciaddr or requested ip) match the
        // lease
        if let Some(mut lease) = selected_lease {
            if !packet.ciaddr.is_unspecified() && packet.ciaddr != lease.ip_address.address.addr() {
                return Err(BackendError::LeaseMismatchClientIP());
            }

            if let Some(DhcpOption::AddressRequest(req_ip)) =
                packet.get_option(DhcpOption::ADDRESSREQUEST)
                && *req_ip != lease.ip_address.address.addr()
            {
                return Err(BackendError::LeaseMismatchClientIP());
            }

            lease.update_from_packet(packet);
            lease.acknowledge(&self.client).await?;
            return Ok(lease);
        }

        Err(BackendError::NoLeaseAvailable())
    }

    async fn delete_lease(&self, packet: &packet::DhcpPacket) -> Result<(), BackendError> {
        let mac_address = u8_to_hex(&packet.chaddr[0..6].to_vec());

        let existing_leases = self.get_leases_for_mac(mac_address).await?;
        for mut l in existing_leases {
            if l.ip_address.address.addr() == packet.ciaddr {
                l.delete(&self.client).await?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl DhcpStore for Netbox {
    async fn handle_discover(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        let netbox_lease = self.get_lease(recv_ip, packet).await?;
        Ok(netbox_lease.into())
    }

    async fn handle_request_selecting(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        let netbox_lease = self.renew_lease(recv_ip, packet).await?;
        Ok(netbox_lease.into())
    }

    async fn handle_request_init_reboot(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        let netbox_lease = self.renew_lease(recv_ip, packet).await?;
        Ok(netbox_lease.into())
    }

    async fn handle_request_renewing(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        let netbox_lease = self.renew_lease(recv_ip, packet).await?;
        Ok(netbox_lease.into())
    }

    async fn handle_request_rebinding(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        let netbox_lease = self.renew_lease(recv_ip, packet).await?;
        Ok(netbox_lease.into())
    }

    async fn handle_release(&self, packet: &packet::DhcpPacket) -> Result<(), BackendError> {
        self.delete_lease(packet).await
    }

    async fn handle_decline(&self, packet: &packet::DhcpPacket) -> Result<(), BackendError> {
        self.delete_lease(packet).await
    }

    async fn handle_inform(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &packet::DhcpPacket,
    ) -> Result<Lease, BackendError> {
        let netbox_lease = self.get_lease(recv_ip, packet).await?;
        Ok(netbox_lease.into())
    }
}

fn u8_to_hex(bytes: &Vec<u8>) -> String {
    let mut mac_octets: Vec<String> = vec![];
    for b in bytes {
        mac_octets.push(format!("{:02X?}", b));
    }

    mac_octets.join(":")
}

async fn send_request(request: RequestBuilder) -> Result<reqwest::Response, BackendError> {
    match request.send().await {
        Ok(r) => {
            let status = r.status();
            if status.is_success() {
                return Ok(r);
            }

            let body = match r.text().await {
                Ok(t) => t,
                Err(_) => "failed to parse response body".to_string(),
            };

            Err(BackendError::BackendError(format!(
                "Error {}: {}",
                status.as_str(),
                body,
            )))
        }
        Err(e) => Err(BackendError::BackendError(e.to_string())),
    }
}
