//! Backend implementations.
//! A backend is any system or logic that is able to derive a DCHP lease from incomming
//! DHCP packets.
pub mod memory;
pub mod netbox;

use std::fmt;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use crate::protocol::packet::{DhcpOptions, DhcpPacket};

/// BackendError is an error that may occur when interacting with a Backend.
#[derive(Debug, Clone)]
pub enum BackendError {
    NoLeaseAvailable(),
    LeaseMismatchClientIP(),
    BackendError(String),
    ProtocolError(String),
    Generic(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoLeaseAvailable() => write!(f, "No suitable lease available"),
            Self::LeaseMismatchClientIP() => write!(
                f,
                "The client IP address and the resolved lease IP don't match"
            ),
            Self::BackendError(s) => write!(f, "Backend Error: {}", s),
            Self::ProtocolError(s) => write!(f, "Backend Error: {}", s),
            Self::Generic(s) => write!(f, "{}", s),
        }
    }
}

/// Lease is returned from backend implementations.
#[derive(Debug, Clone)]
pub struct Lease {
    pub xid: u32,
    pub yiaddr: Option<Ipv4Addr>,
    pub siaddr: Option<Ipv4Addr>,
    pub file: Option<[u8; 128]>,
    pub options: Option<DhcpOptions>,
    pub lease_time: DateTime<Utc>,
    pub lease_duration: Duration,
    pub server_identifier: Ipv4Addr,
}

impl Lease {
    /// Returns true if the lease is current. I.e. it has not expired.
    pub fn is_current(&self) -> bool {
        let now = Utc::now();
        now < self.lease_time + self.lease_duration
    }
}

impl Default for Lease {
    fn default() -> Self {
        Self {
            xid: 0,
            yiaddr: None,
            siaddr: None,
            file: None,
            options: None,
            lease_time: Utc::now(),
            lease_duration: Duration::seconds(0),
            server_identifier: Ipv4Addr::new(0, 0, 0, 0),
        }
    }
}

/// DhcpStore is the interface trait that all backend implementations must implement
#[async_trait]
pub trait DhcpStore: Sync + Send {
    async fn handle_discover(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &DhcpPacket,
    ) -> Result<Lease, BackendError>;

    async fn handle_request_selecting(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &DhcpPacket,
    ) -> Result<Lease, BackendError>;

    async fn handle_request_init_reboot(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &DhcpPacket,
    ) -> Result<Lease, BackendError>;

    async fn handle_request_renewing(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &DhcpPacket,
    ) -> Result<Lease, BackendError>;

    async fn handle_request_rebinding(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &DhcpPacket,
    ) -> Result<Lease, BackendError>;

    async fn handle_release(&self, packet: &DhcpPacket) -> Result<(), BackendError>;

    async fn handle_decline(&self, packet: &DhcpPacket) -> Result<(), BackendError>;

    async fn handle_inform(
        &self,
        recv_ip: &Ipv4Addr,
        packet: &DhcpPacket,
    ) -> Result<Lease, BackendError>;
}
