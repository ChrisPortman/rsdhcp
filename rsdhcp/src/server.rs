use crate::backends::{BackendError, DhcpStore, Lease};
use crate::protocol::{enums, option, packet};
use log::{error, info};
use nix::ifaddrs::getifaddrs;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Server represents the DHCP server using the provided store.
pub struct Server<T: DhcpStore + Sync + Send + 'static> {
    store: Arc<T>,
}

impl<T: DhcpStore + Sync + Send + 'static> Server<T> {
    /// Create a new DHCP server using the provided store.
    pub fn new(store: T) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    /// Start the DHCP server on every IP address.  This process is blocking
    /// returning only if/when an error occurs.
    pub async fn serve(&mut self) -> Result<(), &'static str> {
        let ip_addrs = match getifaddrs() {
            Ok(i) => i,
            Err(_) => return Err("Failed to enumeration host IP addresses"),
        };

        for i in ip_addrs {
            let address = match i.address {
                Some(a) => match a.as_sockaddr_in() {
                    Some(a2) => a2.ip(),
                    None => continue,
                },
                None => continue,
            };

            info!(
                "Starting DHCP listener on IP: {} ({})",
                address, i.interface_name
            );

            let store_ref = self.store.clone();
            tokio::spawn(async move {
                let ip_server = IPServer {
                    ip: address,
                    store: store_ref,
                    iface_name: i.interface_name,
                };
                let _ = ip_server.serve().await;
            });
        }

        Ok(())
    }
}

/// A DHCP server instance on a a specific IP address.
pub struct IPServer<T: DhcpStore + Sync + Send> {
    ip: Ipv4Addr,
    iface_name: String,
    store: Arc<T>,
}

impl<T: DhcpStore + Sync + Send + 'static> IPServer<T> {
    pub fn new(ip: Ipv4Addr, iface_name: String, store: Arc<T>) -> Self {
        Self {
            ip,
            iface_name,
            store,
        }
    }

    /// Start the server on this IP address.
    pub async fn serve(&self) -> io::Result<()> {
        let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if let Err(e) = sock.set_reuse_port(true) {
            error!("Could not enable reuse port on socket {}", self.ip);
            return Err(e);
        }

        // so we can send broadcast packets
        if let Err(e) = sock.set_broadcast(true) {
            error!("Could not enable broadcast on socket {}", self.ip);
            return Err(e);
        }

        // so our broadcast packets only leave via this interface
        if let Err(e) = sock.bind_device(Some(self.iface_name.as_bytes())) {
            error!("Could not bind to device {}: {}", self.iface_name, e);
            return Err(e);
        }

        let sock_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67);
        if let Err(e) = sock.bind(&sock_addr.into()) {
            error!("Could not bind to {}: {}", self.iface_name, e);
            return Err(e);
        }

        if let Err(e) = sock.set_nonblocking(true) {
            error!("Could not set socket to non-blocking: {}", e);
            return Err(e);
        }

        let socket = match UdpSocket::from_std(sock.into()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to convert socket into async socket: {}", e);
                return Err(e);
            }
        };

        let socket_arc = Arc::new(socket);
        let mut buf = [0u8; 1500];
        let mut len: usize;
        let mut src: std::net::SocketAddr;

        loop {
            info!("waiting for packet on {}", self.ip);
            match socket_arc.recv_from(&mut buf).await {
                Ok(r) => (len, src) = r,
                Err(e) => {
                    error!("Reading from network failed: {}", e);
                    continue;
                }
            };

            info!("Data received on IP {} from {}", self.ip, src.ip());
            let ip = self.ip;
            let sock = socket_arc.clone();
            let store = self.store.clone();

            // Launch a task to process the data
            tokio::spawn(
                async move { process_packet_data(ip, sock, buf[..len].to_vec(), store).await },
            );
        }
    }
}

/// Processes a single UDP datagram containing a DHCP packet.
async fn process_packet_data<T: DhcpStore>(
    server_ip: Ipv4Addr,
    sock: Arc<UdpSocket>,
    data: Vec<u8>,
    store: Arc<T>,
) {
    let packet = match packet::DhcpPacket::from_network(&data) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to decode bytes from network: {}", e);
            return;
        }
    };

    info!("Received packet: {}", packet);

    if let Some(option::DhcpOption::DhcpServerId(o)) =
        packet.get_option(option::DhcpOption::DHCPSERVERID)
        && *o != server_ip
    {
        return;
    }

    let mut recv_ip = server_ip;
    if !packet.giaddr.is_unspecified() {
        recv_ip = packet.giaddr;
    }

    if let Some(message_type) = packet.message_type() {
        // Release and decline require no response.
        match message_type {
            enums::MessageType::Release => {
                if let Err(e) = store.handle_release(&packet).await {
                    error!("Error processing release: {}", e);
                }
                return;
            }
            enums::MessageType::Decline => {
                if let Err(e) = store.handle_decline(&packet).await {
                    error!("Error processing decline: {}", e);
                }
                return;
            }
            _ => {}
        };

        let lease_result: Result<Lease, BackendError> = match message_type {
            enums::MessageType::Discover => store.handle_discover(&recv_ip, &packet).await,
            enums::MessageType::Request => match packet.client_state() {
                Some(state) => match state {
                    enums::ClientState::Selecting => {
                        info!("client is in the SELECTING state");
                        store.handle_request_selecting(&recv_ip, &packet).await
                    }
                    enums::ClientState::InitReboot => {
                        info!("client is in the INIT REBOOT state");
                        store.handle_request_init_reboot(&recv_ip, &packet).await
                    }
                    enums::ClientState::Renewing => {
                        info!("client is in the RENEWING state");
                        store.handle_request_renewing(&recv_ip, &packet).await
                    }
                    enums::ClientState::Rebinding => {
                        info!("client is in the REBINDING state");
                        store.handle_request_rebinding(&recv_ip, &packet).await
                    }
                    enums::ClientState::Init => {
                        error!("client is in the INIT state");
                        Err(BackendError::NoLeaseAvailable())
                    }
                },
                None => Err(BackendError::ProtocolError(
                    "could not determine client state".to_string(),
                )),
            },
            enums::MessageType::Inform => store.handle_inform(&recv_ip, &packet).await,
            _ => Err(BackendError::ProtocolError(
                "unknown message type".to_string(),
            )),
        };

        let mut response: packet::DhcpPacket = match lease_result {
            Ok(lease) => {
                info!("resolved lease: {:?}", lease);
                packet::DhcpPacket::response(&packet, lease)
            }
            Err(e) => match e {
                BackendError::LeaseMismatchClientIP() => {
                    error!("Resonding with NAK due to inconsistent lease information");
                    packet::DhcpPacket::nak(&packet)
                }
                BackendError::NoLeaseAvailable() => {
                    error!("{}", e);
                    return;
                }
                _ => {
                    error!("Error processing packet: {}", e);
                    return;
                }
            },
        };

        response.add_option(option::DhcpOption::DhcpServerId(server_ip));

        let mut dst_ip = Ipv4Addr::new(255, 255, 255, 255);
        let mut dst_p = enums::DHCP_CLIENT_PORT;

        if !packet.giaddr.is_unspecified() {
            dst_ip = packet.giaddr;
            dst_p = enums::DHCP_SERVER_PORT;
        } else if !packet.is_broadcast() && !packet.ciaddr.is_unspecified() {
            dst_ip = packet.ciaddr;
        }

        info!(
            "sending response packet to {}:{} - {}",
            dst_ip, dst_p, response
        );
        let dst = format!("{}:{}", dst_ip, dst_p);
        if sock.send_to(&response.to_network(), dst).await.is_err() {
            print!("Failed to send response");
        }
    }
}
