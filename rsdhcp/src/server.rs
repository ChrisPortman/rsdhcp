use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use chrono::{Duration, Utc};
use log::{debug, error, info, warn};
use nix::errno::Errno;
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;

use crate::backends::{BackendError, DhcpStore, Lease};
use crate::protocol::enums::MessageType;
use crate::protocol::option::DhcpOption;
use crate::protocol::{enums, option, packet};

const RECV_BUF_SIZE: usize = 4096;

struct PacketMetadata {
    length: usize,
    source: Option<SocketAddr>,
    destination: Option<Ipv4Addr>,
    // interface_index: Option<u32>,
}

struct Packet {
    meta: PacketMetadata,
    recv_ip: Ipv4Addr,
    data: [u8; RECV_BUF_SIZE],
}

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

        // enable IP_PKTINFO
        if let Err(e) = enable_ip_pktinfo(sock.as_raw_fd()) {
            error!("Could not enable PKTINFO: {}", e);
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
        let mut buffer = [0u8; 4096];

        loop {
            debug!("waiting for packet on {}", self.ip);
            if let Err(e) = socket_arc.readable().await {
                error!("error waiting for socket data: {}", e);
                continue;
            }

            let meta = match socket_arc.try_io(Interest::READABLE, || {
                receive_packet(socket_arc.as_raw_fd(), &mut buffer)
            }) {
                Ok(meta) => meta,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    error!("error reading data from socket: {}", e);
                    continue;
                }
            };

            info!(
                "Data received on IP {} from {}",
                self.ip,
                meta.source
                    .map(|a| a.to_string())
                    .unwrap_or(String::from("unknown")),
            );

            let ip = self.ip;
            let sock = socket_arc.clone();
            let store = self.store.clone();

            let packet = Packet {
                meta,
                recv_ip: ip,
                data: buffer,
            };

            // Launch a task to process the data
            tokio::spawn(async move { process_packet_data(sock, packet, store).await });
        }
    }
}

/// Processes a single UDP datagram containing a DHCP packet.
async fn process_packet_data<T: DhcpStore>(sock: Arc<UdpSocket>, packet: Packet, store: Arc<T>) {
    let data = &packet.data[0..packet.meta.length];

    let broadcast = match packet.meta.destination {
        Some(dst) => dst.is_broadcast(),
        None => false,
    };

    let dhcp_packet = match packet::DhcpPacket::from_network(data, broadcast) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to decode bytes from network: {}", e);
            return;
        }
    };

    debug!("Received packet: {}", dhcp_packet);

    if let Some(option::DhcpOption::DhcpServerId(o)) =
        dhcp_packet.get_option(option::DhcpOption::DHCPSERVERID)
        && *o != packet.recv_ip
    {
        return;
    }

    let mut recv_ip = packet.recv_ip;
    if !dhcp_packet.giaddr.is_unspecified() {
        recv_ip = dhcp_packet.giaddr;
    }

    if let Some(message_type) = dhcp_packet.message_type() {
        // Release and decline require no response.
        match message_type {
            enums::MessageType::Release => {
                if let Err(e) = store.handle_release(&dhcp_packet).await {
                    error!("Error processing release: {}", e);
                }
                info!(
                    "lease released by MAC: {}, IP: {}",
                    dhcp_packet.hex_chaddr(),
                    dhcp_packet.yiaddr,
                );

                return;
            }
            enums::MessageType::Decline => {
                if let Err(e) = store.handle_decline(&dhcp_packet).await {
                    error!("Error processing decline: {}", e);
                }

                warn!(
                    "lease declined by MAC: {}, IP: {}",
                    dhcp_packet.hex_chaddr(),
                    match dhcp_packet.get_option(DhcpOption::ADDRESSREQUEST) {
                        Some(DhcpOption::AddressRequest(a)) => a.to_string(),
                        _ => String::from("UNKNOWN"),
                    },
                );

                return;
            }
            _ => {}
        };

        let lease_result: Result<Lease, BackendError> = match message_type {
            enums::MessageType::Discover => store.handle_discover(&recv_ip, &dhcp_packet).await,
            enums::MessageType::Request => match dhcp_packet.client_state() {
                Some(state) => match state {
                    enums::ClientState::Selecting => {
                        debug!("client is in the SELECTING state");
                        store.handle_request_selecting(&recv_ip, &dhcp_packet).await
                    }
                    enums::ClientState::InitReboot => {
                        debug!("client is in the INIT REBOOT state");
                        store
                            .handle_request_init_reboot(&recv_ip, &dhcp_packet)
                            .await
                    }
                    enums::ClientState::Renewing => {
                        debug!("client is in the RENEWING state");
                        store.handle_request_renewing(&recv_ip, &dhcp_packet).await
                    }
                    enums::ClientState::Rebinding => {
                        debug!("client is in the REBINDING state");
                        store.handle_request_rebinding(&recv_ip, &dhcp_packet).await
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
            enums::MessageType::Inform => store.handle_inform(&recv_ip, &dhcp_packet).await,
            _ => Err(BackendError::ProtocolError(
                "unknown message type".to_string(),
            )),
        };

        let response: packet::DhcpPacket = match lease_result {
            Ok(mut lease) => {
                debug!("resolved lease: {:?}", lease);
                lease.server_identifier = packet.recv_ip;
                dhcp_packet.response(lease)
            }
            Err(e) => match e {
                BackendError::LeaseMismatchClientIP() => {
                    error!("Resonding with NAK due to inconsistent lease information");
                    packet::DhcpPacket::nak(&dhcp_packet)
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

        let mut dst_ip = Ipv4Addr::new(255, 255, 255, 255);
        let mut dst_p = enums::DHCP_CLIENT_PORT;

        if !dhcp_packet.giaddr.is_unspecified() {
            dst_ip = dhcp_packet.giaddr;
            dst_p = enums::DHCP_SERVER_PORT;
        } else if !dhcp_packet.return_broadcast() && !dhcp_packet.ciaddr.is_unspecified() {
            dst_ip = dhcp_packet.ciaddr;
        }

        debug!(
            "sending response packet to {}:{} - {}",
            dst_ip, dst_p, response
        );
        let dst = format!("{}:{}", dst_ip, dst_p);
        if sock.send_to(&response.to_network(), dst).await.is_err() {
            print!("Failed to send response");
        }

        info!(
            "lease {} for {} ({:?}): IP: {}, Mask: {}, Expires: {}",
            match response.message_type() {
                Some(MessageType::Offer) => "offered",
                Some(MessageType::Acknowledge) => "acknowledged",
                _ => "processed",
            },
            response.hex_chaddr(),
            match dhcp_packet.client_state() {
                Some(state) => state,
                None => enums::ClientState::Init, // should not happen
            },
            response.yiaddr,
            match response.get_option(DhcpOption::SUBNETMASK) {
                Some(DhcpOption::SubnetMask(m)) => m.to_string(),
                _ => String::from("unknown"),
            },
            match response.get_option(DhcpOption::ADDRESSTIME) {
                Some(DhcpOption::AddressTime(t)) =>
                    (Utc::now() + Duration::seconds(i64::from(*t))).to_rfc3339(),
                _ => String::from("unknown"),
            }
        );
    }
}

fn enable_ip_pktinfo(fd: i32) -> Result<(), io::Error> {
    let enabled: libc::c_int = 1;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn errno_to_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn receive_packet(fd: RawFd, buffer: &mut [u8]) -> io::Result<PacketMetadata> {
    let mut iov = [IoSliceMut::new(buffer)];

    let mut control_buffer = nix::cmsg_space!(libc::in_pktinfo);

    let message = recvmsg::<SockaddrStorage>(
        fd,
        &mut iov,
        Some(&mut control_buffer),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(errno_to_io)?;

    let source = message.address.as_ref().and_then(|address| {
        address
            .as_sockaddr_in()
            .map(|address| SocketAddr::V4(SocketAddrV4::new(address.ip(), address.port())))
    });

    let mut destination = None;
    // let mut interface_index = None;

    for control_message in message.cmsgs().map_err(errno_to_io)? {
        if let ControlMessageOwned::Ipv4PacketInfo(packet_info) = control_message {
            let destination_u32 = u32::from_be(packet_info.ipi_addr.s_addr);

            destination = Some(Ipv4Addr::from(destination_u32.to_be_bytes()));

            // interface_index = Some(packet_info.ipi_ifindex as u32);
        }
    }

    Ok(PacketMetadata {
        length: message.bytes,
        source,
        destination,
        // interface_index,
    })
}
