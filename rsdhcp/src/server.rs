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
use crate::protocol::packet::DhcpPacket;
use crate::protocol::{enums, errors, option, packet};

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

        let dest = match determine_response_dest(&dhcp_packet, &response) {
            Ok(d) => d,
            Err(e) => {
                error!("{}", e);
                return;
            }
        };

        debug!(
            "sending response packet to {}:{} - {}",
            dest.ip(),
            dest.port(),
            response
        );
        if sock.send_to(&response.to_network(), dest).await.is_err() {
            error!("Failed to send response");
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

fn determine_response_dest(
    request: &DhcpPacket,
    response: &DhcpPacket,
) -> Result<SocketAddrV4, errors::PacketError> {
    if !request.giaddr.is_unspecified() {
        return Ok(SocketAddrV4::new(request.giaddr, enums::DHCP_SERVER_PORT));
    }

    if let Some(MessageType::NegAcknowledge) = response.message_type() {
        return Ok(SocketAddrV4::new(
            Ipv4Addr::BROADCAST,
            enums::DHCP_CLIENT_PORT,
        ));
    }

    if !request.ciaddr.is_unspecified() {
        return Ok(SocketAddrV4::new(request.ciaddr, enums::DHCP_CLIENT_PORT));
    }

    if request.return_broadcast() {
        return Ok(SocketAddrV4::new(
            Ipv4Addr::BROADCAST,
            enums::DHCP_CLIENT_PORT,
        ));
    }

    if !response.yiaddr.is_unspecified() {
        // RFC 2131, Section 4.1 states that a packet with:
        // * The broadcast flag set 0; and
        // * giaddr set 0; and
        // * ciaddr set 0; and
        // * yiaddr set not 0
        // SHOULD be unicast to the `yiaddr` AND the link layer address in `chaddr`.
        //
        // It goes on to say that if for a hardware or software reason, unicast is not
        // feasible, the server MAY fallback to broadcasting to IP ffffff and the broadcast
        // link layer address.
        //
        // We can not set the link layer address manually to chaddr, and the client may
        // not be configured enough yet to respond to ARP requests.
        //
        // We will fall back to broadcast.
        return Ok(SocketAddrV4::new(
            Ipv4Addr::BROADCAST,
            enums::DHCP_CLIENT_PORT,
        ));
    }

    Err(errors::PacketError::new(
        "state voilation. requst/response does not match a return address condition",
    ))
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

#[cfg(test)]
mod tests {
    use super::determine_response_dest;
    use crate::backends::Lease;
    use crate::protocol::packet::DhcpPacket;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn request() -> DhcpPacket {
        let mut raw = vec![0u8; 240];
        raw[236..240].copy_from_slice(&[99, 130, 83, 99]);
        raw.extend_from_slice(&[53, 1, 3, 255]); // DHCPREQUEST, END

        DhcpPacket::from_network(&raw, false).expect("test request should decode")
    }

    fn ack(request: &DhcpPacket, yiaddr: Ipv4Addr) -> DhcpPacket {
        let mut response = DhcpPacket::response(request, Lease::default());
        response.yiaddr = yiaddr;
        response
    }

    #[test]
    fn relay_destination_takes_precedence() {
        let mut request = request();
        request.giaddr = Ipv4Addr::new(192, 0, 2, 1);
        request.ciaddr = Ipv4Addr::new(192, 0, 2, 20);
        request.flags = 0x8000;

        let response = DhcpPacket::nak(&request);
        let destination = determine_response_dest(&request, &response).unwrap();

        assert_eq!(destination, SocketAddrV4::new(request.giaddr, 67));
    }

    #[test]
    fn nak_without_relay_is_broadcast() {
        let mut request = request();
        request.ciaddr = Ipv4Addr::new(192, 0, 2, 20);

        let response = DhcpPacket::nak(&request);
        let destination = determine_response_dest(&request, &response).unwrap();

        assert_eq!(destination, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
    }

    #[test]
    fn ciaddr_takes_precedence_over_broadcast_flag() {
        let mut request = request();
        request.ciaddr = Ipv4Addr::new(192, 0, 2, 20);
        request.flags = 0x8000;

        let response = ack(&request, Ipv4Addr::new(192, 0, 2, 21));
        let destination = determine_response_dest(&request, &response).unwrap();

        assert_eq!(destination, SocketAddrV4::new(request.ciaddr, 68));
    }

    #[test]
    fn broadcast_flag_selects_limited_broadcast() {
        let mut request = request();
        request.flags = 0x8000;

        let response = ack(&request, Ipv4Addr::new(192, 0, 2, 21));
        let destination = determine_response_dest(&request, &response).unwrap();

        assert_eq!(destination, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
    }

    #[test]
    fn broadcast_is_used_where_yiaddr_is_set() {
        let request = request();
        let yiaddr = Ipv4Addr::new(192, 0, 2, 21);

        let response = ack(&request, yiaddr);
        let destination = determine_response_dest(&request, &response).unwrap();

        assert_eq!(destination, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
    }

    #[test]
    fn missing_destination_returns_an_error() {
        let request = request();
        let response = DhcpPacket::response(&request, Lease::default());

        assert!(determine_response_dest(&request, &response).is_err());
    }
}
