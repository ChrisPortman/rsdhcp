use std::fmt::{Display, Formatter};
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::{cmp, fmt};

use byteorder::ReadBytesExt;
use log::warn;

use crate::backends::Lease;
use crate::protocol::enums;
use crate::protocol::errors::PacketError;
use crate::protocol::option::DhcpOption;

const COOKIE: [u8; 4] = [99, 130, 83, 99];
const DHCP_HEADER_LEN: usize = 240;
const MIN_MAX_MESSAGE_LEN: usize = 576;
const DEFAULT_LEASE_TIME_SECS: u32 = 3600;

/// Represents the structure of a DHCP message or packet.
#[derive(Debug)]
pub struct DhcpPacket {
    pub op: enums::DhcpOperation,
    pub htype: enums::HardwareType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub cookie: [u8; 4],
    pub options: DhcpOptions,

    max_client_message_size: Option<u16>,
    received_by_broadcast: bool,
}

impl DhcpPacket {
    /// Given a DhcpPacket and a lease, generate the appropriate response packet
    /// according to DHCP specified symantics.
    pub fn response(&self, lease: Lease) -> Self {
        let mut msg_type = enums::MessageType::Unknown(255);
        if let Some(DhcpOption::DhcpMsgType(mt)) = self.get_option(DhcpOption::DHCPMSGTYPE) {
            match mt {
                enums::MessageType::Discover => msg_type = enums::MessageType::Offer,
                enums::MessageType::Request => msg_type = enums::MessageType::Acknowledge,
                enums::MessageType::Inform => msg_type = enums::MessageType::Acknowledge,
                _ => (),
            }
        }

        let mut new = Self {
            op: enums::DhcpOperation::BootReply,
            htype: self.htype,
            hlen: self.hlen,
            hops: 0,
            xid: self.xid,
            secs: 0,
            flags: self.flags,
            ciaddr: self.ciaddr,
            yiaddr: self.yiaddr,
            siaddr: self.siaddr,
            giaddr: self.giaddr,
            chaddr: self.chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            cookie: COOKIE,
            options: DhcpOptions::new(None),
            max_client_message_size: None,
            received_by_broadcast: self.received_by_broadcast,
        };

        if let Some(DhcpOption::DhcpMaxMsgSize(s)) = self.get_option(DhcpOption::DHCPMAXMSGSIZE) {
            new.max_client_message_size = Some(*s);
        }

        new.options.options.push(DhcpOption::DhcpMsgType(msg_type));
        new.options
            .options
            .push(DhcpOption::DhcpServerId(lease.server_identifier));

        let mut lease_time = DEFAULT_LEASE_TIME_SECS;
        if lease.lease_duration.num_seconds() > 0 {
            lease_time = lease
                .lease_duration
                .num_seconds()
                .try_into()
                .unwrap_or(DEFAULT_LEASE_TIME_SECS);
        }
        new.options
            .options
            .push(DhcpOption::AddressTime(lease_time));

        if let Some(ip) = lease.yiaddr {
            new.yiaddr = ip.addr();
            new.options
                .options
                .push(DhcpOption::SubnetMask(ip.netmask()));
        }

        if let Some(ip) = lease.siaddr {
            new.siaddr = ip;
        }
        if let Some(f) = lease.file {
            new.file = f;
        }

        // Echo back options in the incomming packet as required by the RFC
        if let Some(o) = self.get_option(DhcpOption::CLIENTID) {
            new.options.options.push(o.clone());
        }

        if let Some(options) = lease.options {
            new.options.options.extend(options.options);
        }

        new
    }

    /// Given a DhcpPacket generate the appropriate Negative Acknowledgment accoding
    /// to DHCP specified symantics.
    pub fn nak(&self) -> Self {
        let op = enums::DhcpOperation::BootReply;
        let msg_type = enums::MessageType::NegAcknowledge;

        let mut new = Self {
            op,
            htype: self.htype,
            hlen: self.hlen,
            hops: 0,
            xid: self.xid,
            secs: 0,
            flags: self.flags,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: self.giaddr,
            chaddr: self.chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            cookie: COOKIE,
            options: DhcpOptions::new(None),
            max_client_message_size: None,
            received_by_broadcast: self.received_by_broadcast,
        };

        new.options.options.push(DhcpOption::DhcpMsgType(msg_type));

        // Echo back options in the incomming packet as required by the RFC
        if let Some(o) = self.get_option(DhcpOption::CLIENTID) {
            new.options.options.push(o.clone());
        }

        new
    }

    /// Deserialze a DHCP packet from the provided byte slice.  E.g. bytes read
    /// from a UDP socket.
    pub fn from_network(raw: &[u8], broadcast: bool) -> Result<Self, PacketError> {
        if raw.len() < 240 {
            return Err(PacketError::new("insufficient bytes in packet"));
        }

        let mut packet = Self {
            op: enums::DhcpOperation::from(raw[0]),
            htype: enums::HardwareType::from(raw[1]),
            hlen: raw[2],
            hops: raw[3],
            xid: u32::from_be_bytes(raw[4..8].try_into()?),
            secs: u16::from_be_bytes(raw[8..10].try_into()?),
            flags: u16::from_be_bytes(raw[10..12].try_into()?),
            ciaddr: Ipv4Addr::from(u32::from_be_bytes(raw[12..16].try_into()?)),
            yiaddr: Ipv4Addr::from(u32::from_be_bytes(raw[16..20].try_into()?)),
            siaddr: Ipv4Addr::from(u32::from_be_bytes(raw[20..24].try_into()?)),
            giaddr: Ipv4Addr::from(u32::from_be_bytes(raw[24..28].try_into()?)),
            chaddr: raw[28..44].try_into()?,
            sname: raw[44..108].try_into()?,
            file: raw[108..236].try_into()?,
            cookie: raw[236..240].try_into()?,
            options: DhcpOptions::new(None),
            max_client_message_size: None,
            received_by_broadcast: broadcast,
        };

        if packet.cookie != COOKIE {
            return Err(PacketError::new("Invalid DHCP packet - incorrect cookie"));
        }

        if raw.len() > 240 {
            packet.options = DhcpOptions::from_network(&raw[240..])?;
        }

        Ok(packet)
    }

    /// Serialize the DhcpPacket to bytes that can be written to a UDP socket.
    pub fn to_network(&self) -> Vec<u8> {
        let mut options: Vec<u8>;
        let mut file = self.file;
        let mut sname = self.sname;

        match self.max_client_message_size {
            Some(max) => {
                let max_options_len = cmp::max(max.into(), MIN_MAX_MESSAGE_LEN) - DHCP_HEADER_LEN;
                let (options_data, file_data, sname_data) =
                    self.options
                        .to_network_overflow(max_options_len, file[0] == 0, sname[0] == 0);

                options = options_data;

                if let Some(fd) = file_data {
                    file[0..fd.len()].copy_from_slice(&fd);
                }
                if let Some(sd) = sname_data {
                    sname[0..sd.len()].copy_from_slice(&sd);
                }
            }
            None => {
                options = self.options.to_network();
            }
        }

        let mut data = Vec::<u8>::with_capacity(1500);
        data.push(u8::from(self.op));
        data.push(u8::from(self.htype));
        data.push(self.hlen);
        data.push(self.hops);
        data.extend(self.xid.to_be_bytes());
        data.extend(self.secs.to_be_bytes());
        data.extend(self.flags.to_be_bytes());
        data.extend(u32::from(self.ciaddr).to_be_bytes());
        data.extend(u32::from(self.yiaddr).to_be_bytes());
        data.extend(u32::from(self.siaddr).to_be_bytes());
        data.extend(u32::from(self.giaddr).to_be_bytes());
        data.extend(self.chaddr);
        data.extend(sname);
        data.extend(file);
        data.extend(COOKIE);

        // Force a length of at least 300.  There are documented cases of clients
        // expecting the old BOOTP options of 64bytes (including cookie) making the
        // total packet size 300 bytes.
        if options.len() < 60 {
            options.extend(vec![0u8; 60 - options.len()]);
        }
        data.extend(options);

        data
    }

    /// Return the message type of the DhcpPacket.
    pub fn message_type(&self) -> Option<enums::MessageType> {
        for o in &self.options.options {
            if let DhcpOption::DhcpMsgType(o) = o {
                return Some(*o);
            }
        }
        None
    }

    /// Determine and return the client state based on the contents of the DhcpPacket.
    pub fn client_state(&self) -> Option<enums::ClientState> {
        if let enums::DhcpOperation::BootReply = self.op {
            // This is a server generated packet.
            return None;
        }

        if let Some(enums::MessageType::Discover) = self.message_type() {
            return Some(enums::ClientState::Init);
        }

        if let Some(enums::MessageType::Request) = self.message_type() {
            if self.ciaddr.is_unspecified()
                && self.get_option(DhcpOption::DHCPSERVERID).is_some()
                && self.get_option(DhcpOption::ADDRESSREQUEST).is_some()
            {
                return Some(enums::ClientState::Selecting);
            }

            if !self.broadcast_by_client()
                && !self.ciaddr.is_unspecified()
                && self.giaddr.is_unspecified()
                && self.get_option(DhcpOption::DHCPSERVERID).is_none()
                && self.get_option(DhcpOption::ADDRESSREQUEST).is_none()
            {
                return Some(enums::ClientState::Renewing);
            }

            if self.broadcast_by_client()
                && !self.ciaddr.is_unspecified()
                && self.get_option(DhcpOption::DHCPSERVERID).is_none()
                && self.get_option(DhcpOption::ADDRESSREQUEST).is_none()
            {
                return Some(enums::ClientState::Rebinding);
            }

            if self.ciaddr.is_unspecified()
                && self.get_option(DhcpOption::DHCPSERVERID).is_none()
                && self.get_option(DhcpOption::ADDRESSREQUEST).is_some()
            {
                return Some(enums::ClientState::InitReboot);
            }
        }

        None
    }

    /// Return true if the broadcast flag in the DhcpPacket is set.
    pub fn return_broadcast(&self) -> bool {
        if self.flags >> 15 == 1 {
            return true;
        }
        false
    }

    /// Get the DHCP option for the given option code if it is present.
    pub fn get_option(&self, code: u8) -> Option<&DhcpOption> {
        self.options.get_option(code)
    }

    /// Add the provided option to the DhcpPacket packet.
    pub fn add_option(&mut self, option: DhcpOption) {
        self.options.options.push(option);
    }

    /// Retuns true if the client sent its request by broadcast.  We know that it did
    /// if we either received the packet via a dhcp gateway (giaddr is set) or if the
    /// server received it directly by local broadcast.
    pub fn broadcast_by_client(&self) -> bool {
        if !self.giaddr.is_unspecified() {
            // indicates that the client broadcast and was handled by the local dhcp gateway
            return true;
        }

        self.received_by_broadcast
    }

    pub fn hex_chaddr(&self) -> String {
        let mut s = String::with_capacity(20);

        for i in 0..self.hlen {
            s.push_str(format!("{:02X?}", self.chaddr[i as usize]).as_str());

            if i < self.hlen - 1 {
                s.push(':');
            }
        }

        s
    }
}

impl Display for DhcpPacket {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let chaddr: [u8; 6] = self.chaddr[0..6].try_into().unwrap();

        let sname = std::str::from_utf8(&self.sname).unwrap_or("");
        let file = std::str::from_utf8(&self.file).unwrap_or("");

        let mut msg_type = enums::MessageType::Unknown(255);
        if let Some(DhcpOption::DhcpMsgType(mt)) = self.get_option(DhcpOption::DHCPMSGTYPE) {
            msg_type = *mt
        }

        writeln!(f)?;
        writeln!(f, "DHCP Operation: {:?}", self.op)?;
        writeln!(f, "DHCP Message Type: {:?}", msg_type)?;
        writeln!(f, "Hardware Type: {:?}", self.htype)?;
        writeln!(f, "Length: {}", self.hlen)?;
        writeln!(f, "Hops: {}", self.hops)?;
        writeln!(f, "Transaction ID: {}", self.xid)?;
        writeln!(f, "Seconds: {}", self.secs)?;
        writeln!(f, "Flags: {:?}", self.flags)?;
        writeln!(f, "Client IP: {}", self.ciaddr)?;
        writeln!(f, "Your IP: {}", self.yiaddr)?;
        writeln!(f, "Next Server IP: {}", self.siaddr)?;
        writeln!(f, "Gateway IP: {}", self.giaddr)?;
        writeln!(f, "Client MAC: {:02X?}", chaddr)?;
        writeln!(f, "Server Name: {}", sname)?;
        writeln!(f, "File: {}", file)?;
        write!(f, "Options:{}", self.options)
    }
}

/// A collection of DHCP Options.
#[derive(Debug, Clone)]
pub struct DhcpOptions {
    options: Vec<DhcpOption>,
}

impl DhcpOptions {
    /// Return a new set of DHCP options initialized with optional provided options.
    pub fn new(opts: Option<Vec<DhcpOption>>) -> Self {
        match opts {
            Some(o) => Self { options: o },
            None => Self { options: vec![] },
        }
    }

    /// Deserialize option from a byte slice.  Typcially end users won't use this, it
    /// is used by the `from_network` method of the `DhcpPacket`.
    pub fn from_network(raw: &[u8]) -> Result<Self, PacketError> {
        if raw.is_empty() {
            return Ok(Self::new(None));
        }

        let mut cursor = Cursor::new(raw);
        let mut options = Self { options: vec![] };

        loop {
            let code: u8 = cursor.read_u8()?;
            if code == 255 {
                break;
            }

            if code == 0 {
                continue;
            }

            let length = cursor.read_u8()? as usize;
            let start = cursor.position() as usize;
            let end = start + length;

            if end > cursor.get_ref().len() {
                return Err(PacketError::new("Malformed Packet"));
            }

            let option_data = &cursor.get_ref()[start..end];
            cursor.set_position(end as u64);

            let option = match DhcpOption::new(&code, option_data) {
                Ok(o) => o,
                Err(e) => {
                    warn!("Failed to decode data for option code {}: {}", code, e);
                    continue;
                }
            };
            options.options.push(option);
        }
        Ok(options)
    }

    /// Serialise the option set to bytes ready to be writen to a UDP socket.
    /// Typcially end users won't use this, it is used by the `from_network`
    /// method of the `DhcpPacket`.
    pub fn to_network(&self) -> Vec<u8> {
        let mut bytes = vec![];
        for o in &self.options {
            bytes.extend(o.to_network());
        }
        bytes.push(255u8);
        bytes
    }

    /// Serialise the option set upto a maximum of `max` bytes.  If the options exceeds
    /// `max` bytes, add option 52 and return a file field vec and a sname field in that order.
    pub fn to_network_overflow(
        &self,
        max: usize,
        use_file: bool,
        use_sname: bool,
    ) -> (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) {
        const RESERVED_BYTES: usize = 4;
        const FILE_BYTES: usize = 128;
        const SNAME_BYTES: usize = 64;

        let mut bytes = Vec::<u8>::with_capacity(max);
        let mut file_bytes = Vec::<u8>::with_capacity(FILE_BYTES);
        let mut sname_bytes = Vec::<u8>::with_capacity(SNAME_BYTES);

        for o in &self.options {
            let optbytes = o.to_network();

            if bytes.len() + optbytes.len() + RESERVED_BYTES <= max {
                bytes.extend(optbytes);
                continue;
            }

            if use_file && file_bytes.len() + 1 + optbytes.len() <= FILE_BYTES {
                file_bytes.extend(optbytes);
                continue;
            }

            if use_sname && sname_bytes.len() + 1 + optbytes.len() <= SNAME_BYTES {
                sname_bytes.extend(optbytes);
                continue;
            }

            warn!(
                "clients max message size limit resulted in options {} omitted.",
                o.name(),
            );
        }

        let mut overload_val = 0u8;
        let mut ret_file_bytes: Option<Vec<u8>> = None;
        let mut ret_sname_bytes: Option<Vec<u8>> = None;

        if !file_bytes.is_empty() {
            file_bytes.push(255u8);
            ret_file_bytes = Some(file_bytes);
            overload_val += 1;
        }

        if !sname_bytes.is_empty() {
            sname_bytes.push(255u8);
            ret_sname_bytes = Some(sname_bytes);
            overload_val += 2;
        }

        if overload_val > 0 {
            bytes.extend(DhcpOption::Overload(overload_val).to_network());
        }

        bytes.push(255u8);

        (bytes, ret_file_bytes, ret_sname_bytes)
    }

    /// Return the option corresponding to the provided option code if it exists.
    pub fn get_option(&self, code: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|&o| o.code() == code)
    }
}

impl Display for DhcpOptions {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for o in &self.options {
            write!(f, "\n  {}: {:?}", o.code(), o)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::panic::catch_unwind;

    use crate::protocol::enums::MessageType;
    use crate::protocol::option::DhcpOption;
    use crate::protocol::packet::{self, DhcpPacket};
    use std::fs;

    #[test]
    fn test_discover_network() {
        let sample_data =
            fs::read("test_data/discover.dhcp.bin").expect("failed to read data file");
        let dhcp_packet =
            packet::DhcpPacket::from_network(&sample_data, true).expect("Failed to decode packet");
        assert_eq!(u8::from(dhcp_packet.message_type().unwrap()), 1u8);
        let network_data = dhcp_packet.to_network();
        assert_eq!(sample_data, network_data);
    }

    #[test]
    fn test_is_broadcast() {
        let sample_data =
            fs::read("test_data/discover.dhcp.bin").expect("failed to read data file");
        let mut dhcp_packet =
            packet::DhcpPacket::from_network(&sample_data, false).expect("Failed to decode packet");
        println!("flags: {:#?}", dhcp_packet.flags);
        assert!(!dhcp_packet.return_broadcast());
        dhcp_packet.flags = 32768u16;
        assert!(dhcp_packet.return_broadcast());
    }

    #[test]
    fn test_get_option() {
        let sample_data =
            fs::read("test_data/discover.dhcp.bin").expect("failed to read data file");
        let dhcp_packet =
            packet::DhcpPacket::from_network(&sample_data, false).expect("Failed to decode packet");
        let opt = dhcp_packet.get_option(DhcpOption::DHCPMSGTYPE);
        if let Some(DhcpOption::DhcpMsgType(opt)) = opt {
            println!("Option data: {:#?}", opt);
        }
    }

    fn packet_with_options(options: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 240];
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
        packet.extend_from_slice(options);
        packet
    }

    #[test]
    fn rejects_short_fixed_header_without_panicking() {
        let result = catch_unwind(|| packet::DhcpPacket::from_network(&[0u8; 239], false));

        assert!(result.is_ok(), "short packet caused a panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn rejects_empty_options_without_panicking() {
        let raw = packet_with_options(&[]);
        let result = catch_unwind(|| packet::DhcpPacket::from_network(&raw, false));

        assert!(result.is_ok(), "empty option area caused a panic");
        assert!(result.unwrap().unwrap().options.options.is_empty());
    }

    #[test]
    fn rejects_truncated_option_payload_without_panicking() {
        // Option 1 claims two payload bytes but only one is present.
        let raw = packet_with_options(&[1, 2, 0]);
        let result = catch_unwind(|| packet::DhcpPacket::from_network(&raw, false));

        assert!(result.is_ok(), "truncated option caused a panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn generated_option_decoder_accepts_a_valid_encoded_option() {
        let result = catch_unwind(|| DhcpOption::from_network(&[53, 1, 1]));

        assert!(result.is_ok(), "encoded option caused a panic");
        assert!(matches!(
            result.unwrap(),
            Ok(DhcpOption::DhcpMsgType(MessageType::Discover))
        ));
    }

    fn packet_with_header(options: &[u8]) -> Vec<u8> {
        let mut raw = vec![0u8; 236];

        raw[0] = 2; // BOOTREPLY
        raw[1] = 1; // Ethernet
        raw[2] = 6; // MAC address length
        raw[3] = 7; // hops

        raw[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        raw[8..10].copy_from_slice(&17u16.to_be_bytes());
        raw[10..12].copy_from_slice(&0x8000u16.to_be_bytes());

        raw[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        raw[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 42).octets());
        raw[20..24].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        raw[24..28].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 254).octets());

        raw[28..44].copy_from_slice(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        raw[44..52].copy_from_slice(b"server01");
        raw[108..118].copy_from_slice(b"pxelinux.0");

        raw.extend_from_slice(&[99, 130, 83, 99]);
        raw.extend_from_slice(options);
        raw
    }

    fn option_codes(packet: &DhcpPacket) -> Vec<u8> {
        packet
            .options
            .options
            .iter()
            .map(DhcpOption::code)
            .collect()
    }

    #[test]
    fn hex_chaddr_constructs_a_mac_address_string() {
        let packet = DhcpPacket::from_network(&packet_with_header(&[]), false)
            .expect("complete DHCP packet should decode");
        assert_eq!(packet.hex_chaddr(), "00:11:22:33:44:55");
    }

    #[test]
    fn decodes_complete_packet_with_mixed_option_ranges() {
        let options = [
            0, // PAD
            53, 1, 2, // DHCP message type: OFFER
            3, 8, 10, 0, 0, 1, 10, 0, 0, 254, // Router
            51, 4, 0, 0, 14, 16, // Lease time: 3600
            61, 3, 1, 0xaa, 0xbb, // Client identifier
            0,    // PAD
            255,  // END
            0, 0, 0, // trailing padding
        ];

        let packet = DhcpPacket::from_network(&packet_with_header(&options), false)
            .expect("complete DHCP packet should decode");

        assert_eq!(u8::from(packet.op), 2);
        assert_eq!(u8::from(packet.htype), 1);
        assert_eq!(packet.hlen, 6);
        assert_eq!(packet.hops, 7);
        assert_eq!(packet.xid, 0x1234_5678);
        assert_eq!(packet.secs, 17);
        assert_eq!(packet.flags, 0x8000);

        assert_eq!(packet.ciaddr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(packet.yiaddr, Ipv4Addr::new(10, 0, 0, 42));
        assert_eq!(packet.siaddr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(packet.giaddr, Ipv4Addr::new(10, 0, 0, 254));
        assert_eq!(&packet.chaddr[..6], &[0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&packet.sname[..8], b"server01");
        assert_eq!(&packet.file[..10], b"pxelinux.0");
        assert_eq!(packet.cookie, [99, 130, 83, 99]);

        assert_eq!(option_codes(&packet), vec![53, 3, 51, 61]);
        assert!(matches!(packet.message_type(), Some(MessageType::Offer)));

        assert!(matches!(
            packet.get_option(DhcpOption::ROUTER),
            Some(DhcpOption::Router(routers)) if routers.len() == 2
        ));

        assert!(matches!(
            packet.get_option(DhcpOption::CLIENTID),
            Some(DhcpOption::ClientId(value)) if value == &[1, 0xaa, 0xbb]
        ));
    }

    #[test]
    fn accepts_exact_fixed_header_with_valid_cookie_and_no_options() {
        let packet = DhcpPacket::from_network(&packet_with_header(&[]), false)
            .expect("240-byte packet with valid cookie should decode");

        assert!(packet.options.options.is_empty());
        assert_eq!(packet.cookie, [99, 130, 83, 99]);
    }

    #[test]
    fn rejects_invalid_cookie_before_option_processing() {
        let mut raw = packet_with_header(&[53, 1, 1, 255]);
        raw[236..240].copy_from_slice(&[0, 0, 0, 0]);

        let result = catch_unwind(|| DhcpPacket::from_network(&raw, false));

        assert!(result.is_ok(), "invalid cookie caused a panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn rejects_all_packets_shorter_than_the_fixed_header() {
        for length in [0usize, 1, 28, 239] {
            let raw = vec![0u8; length];
            let result = catch_unwind(|| DhcpPacket::from_network(&raw, false));

            assert!(result.is_ok(), "length {length} caused a panic");
            assert!(result.unwrap().is_err(), "length {length} was accepted");
        }
    }

    #[test]
    fn rejects_truncated_option_headers_and_payloads() {
        let malformed_options: &[&[u8]] = &[
            &[53],                  // missing length
            &[53, 1],               // missing payload
            &[53, 2, 1],            // short payload
            &[1, 4, 255, 255, 255], // truncated IPv4 option
        ];

        for options in malformed_options {
            let raw = packet_with_header(options);
            let result = catch_unwind(|| DhcpPacket::from_network(&raw, false));

            assert!(result.is_ok(), "malformed option caused a panic");
            assert!(result.unwrap().is_err());
        }
    }

    #[test]
    fn ignores_unknown_option_and_decodes_following_known_option() {
        let options = [
            200, 3, 1, 2, 3, // Unknown option
            53, 1, 1, // DHCP message type: DISCOVER
            255,
        ];

        let packet = DhcpPacket::from_network(&packet_with_header(&options), false)
            .expect("unknown options should not desynchronize parsing");

        assert_eq!(option_codes(&packet), vec![53]);
        assert!(matches!(packet.message_type(), Some(MessageType::Discover)));
    }

    #[test]
    fn skips_invalid_known_option_without_losing_cursor_alignment() {
        let options = [
            1, 3, 192, 0, 2, // Invalid subnet-mask length
            53, 1, 1, // Valid DHCP message type
            255,
        ];

        let packet = DhcpPacket::from_network(&packet_with_header(&options), false)
            .expect("invalid option should not corrupt following options");

        assert_eq!(option_codes(&packet), vec![53]);
        assert!(matches!(packet.message_type(), Some(MessageType::Discover)));
    }

    #[test]
    fn stops_processing_at_end_option() {
        let options = [
            53, 1, 1,   // Valid option
            255, // END
            53, 1, 2, // Must not be processed
            1, 4, 255, 255, 255, 0,
        ];

        let packet = DhcpPacket::from_network(&packet_with_header(&options), false)
            .expect("options after END should not be processed");

        assert_eq!(option_codes(&packet), vec![53]);
        assert!(matches!(packet.message_type(), Some(MessageType::Discover)));
    }

    #[test]
    fn decodes_packet_after_network_round_trip() {
        let options = [0, 53, 1, 2, 3, 4, 10, 0, 0, 1, 54, 4, 10, 0, 0, 2, 255];

        let original = DhcpPacket::from_network(&packet_with_header(&options), false)
            .expect("initial packet should decode");

        let encoded = original.to_network();
        let decoded = DhcpPacket::from_network(&encoded, false)
            .expect("serialized packet should decode again");

        assert_eq!(decoded.xid, original.xid);
        assert_eq!(decoded.ciaddr, original.ciaddr);
        assert_eq!(decoded.yiaddr, original.yiaddr);
        assert_eq!(decoded.giaddr, original.giaddr);
        assert_eq!(decoded.cookie, [99, 130, 83, 99]);
        assert_eq!(option_codes(&decoded), vec![53, 3, 54]);
    }

    #[test]
    fn response_echoes_client_identifier() {
        let options = [
            53, 1, 1, // DHCPDISCOVER
            61, 3, 1, 0xaa, 0xbb, // Client identifier
            255,
        ];
        let request = DhcpPacket::from_network(&packet_with_header(&options), false)
            .expect("request should decode");

        let response = DhcpPacket::response(&request, crate::backends::Lease::default());

        assert!(matches!(
            response.get_option(DhcpOption::CLIENTID),
            Some(DhcpOption::ClientId(value)) if value == &[1, 0xaa, 0xbb]
        ));
    }

    #[test]
    fn nak_echoes_client_identifier() {
        let options = [
            53, 1, 3, // DHCPREQUEST
            61, 3, 1, 0xaa, 0xbb, // Client identifier
            255,
        ];
        let request = DhcpPacket::from_network(&packet_with_header(&options), false)
            .expect("request should decode");

        let response = DhcpPacket::nak(&request);

        assert!(matches!(
            response.get_option(DhcpOption::CLIENTID),
            Some(DhcpOption::ClientId(value)) if value == &[1, 0xaa, 0xbb]
        ));
    }

    #[test]
    fn response_sets_secs_and_hops_zero() {
        let request = DhcpPacket::from_network(
            &packet_with_header(&[
                53, 1, 1, // DHCPDISCOVER
                255,
            ]),
            false,
        )
        .expect("request should decode");

        let response = DhcpPacket::response(&request, crate::backends::Lease::default());

        assert_eq!(u8::from(response.op), 2); // BOOTREPLY
        assert_eq!(response.hops, 0);
        assert_eq!(response.secs, 0);
    }

    #[test]
    fn nak_sets_secs_and_hops_zero() {
        let request = DhcpPacket::from_network(
            &packet_with_header(&[
                53, 1, 3, // DHCPREQUEST
                255,
            ]),
            false,
        )
        .expect("request should decode");

        let response = DhcpPacket::nak(&request);

        assert_eq!(u8::from(response.op), 2); // BOOTREPLY
        assert_eq!(response.hops, 0);
        assert_eq!(response.secs, 0);
    }

    fn response_with_large_options(max_message_size: u16) -> Vec<u8> {
        let request_options = [
            53,
            1,
            1, // DHCPDISCOVER
            57,
            2,
            (max_message_size >> 8) as u8,
            max_message_size as u8, // Option 57
            255,
        ];

        let request = DhcpPacket::from_network(&packet_with_header(&request_options), false)
            .expect("request should decode");

        let mut lease = crate::backends::Lease::default();

        // Each option occupies 62 bytes on the wire:
        // 1 byte code + 1 byte length + 60-byte payload.
        let options = (0..8)
            .map(|i| DhcpOption::DomainName(format!("option-{i}-{}", "x".repeat(51))))
            .collect();

        lease.options = Some(packet::DhcpOptions::new(Some(options)));

        DhcpPacket::response(&request, lease).to_network()
    }

    #[test]
    fn response_honours_option_57_maximum_message_size() {
        let encoded = response_with_large_options(576);

        assert!(
            encoded.len() <= 576,
            "response length {} exceeded option 57 limit",
            encoded.len()
        );
    }

    #[test]
    fn response_uses_file_and_sname_for_option_overload() {
        let encoded = response_with_large_options(576);

        let main_options =
            packet::DhcpOptions::from_network(&encoded[240..]).expect("main options should decode");

        assert!(matches!(
            main_options.get_option(52),
            Some(DhcpOption::Overload(3))
        ));

        // Fixed-header offsets:
        // sname = 44..108
        // file  = 108..236
        let file_options = packet::DhcpOptions::from_network(&encoded[108..236])
            .expect("overloaded file options should decode");

        let sname_options = packet::DhcpOptions::from_network(&encoded[44..108])
            .expect("overloaded sname options should decode");

        assert_eq!(file_options.options.len(), 2);
        assert!(matches!(
            &file_options.options[0],
            DhcpOption::DomainName(value) if value.starts_with("option-5-")
        ));
        assert!(matches!(
            &file_options.options[1],
            DhcpOption::DomainName(value) if value.starts_with("option-6-")
        ));

        assert_eq!(sname_options.options.len(), 1);
        assert!(matches!(
            &sname_options.options[0],
            DhcpOption::DomainName(value) if value.starts_with("option-7-")
        ));

        assert!(
            encoded.len() <= 576,
            "overloaded response length {} exceeded option 57 limit",
            encoded.len()
        );
    }

    fn response_with_large_options_using_fields(
        max_message_size: u16,
        use_file: bool,
        use_sname: bool,
    ) -> Vec<u8> {
        let request_options = [
            53,
            1,
            1, // DHCPDISCOVER
            57,
            2,
            (max_message_size >> 8) as u8,
            max_message_size as u8,
            255,
        ];

        let request = DhcpPacket::from_network(&packet_with_header(&request_options), false)
            .expect("request should decode");

        let mut lease = crate::backends::Lease::default();

        let options = (0..8)
            .map(|i| DhcpOption::DomainName(format!("option-{i}-{}", "x".repeat(51))))
            .collect();

        lease.options = Some(packet::DhcpOptions::new(Some(options)));

        let mut response = DhcpPacket::response(&request, lease);

        // A non-zero first byte marks the field as already in use.
        if !use_file {
            response.file[0] = 1;
        }

        if !use_sname {
            response.sname[0] = 1;
        }

        response.to_network()
    }

    #[test]
    fn response_uses_file_only_for_option_overload() {
        let encoded = response_with_large_options_using_fields(576, true, false);

        let main_options =
            packet::DhcpOptions::from_network(&encoded[240..]).expect("main options should decode");

        assert!(matches!(
            main_options.get_option(52),
            Some(DhcpOption::Overload(1))
        ));

        let file_options = packet::DhcpOptions::from_network(&encoded[108..236])
            .expect("file options should decode");

        assert_eq!(file_options.options.len(), 2);
        assert_eq!(encoded[44], 1); // sname was unavailable
        assert!(encoded.len() <= 576);
    }

    #[test]
    fn response_uses_sname_only_for_option_overload() {
        let encoded = response_with_large_options_using_fields(576, false, true);

        let main_options =
            packet::DhcpOptions::from_network(&encoded[240..]).expect("main options should decode");

        assert!(matches!(
            main_options.get_option(52),
            Some(DhcpOption::Overload(2))
        ));

        let sname_options = packet::DhcpOptions::from_network(&encoded[44..108])
            .expect("sname options should decode");

        assert_eq!(sname_options.options.len(), 1);
        assert_eq!(encoded[108], 1); // file was unavailable
        assert!(encoded.len() <= 576);
    }
}
