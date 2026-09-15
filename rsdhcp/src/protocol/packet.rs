use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::Cursor;
use std::net::Ipv4Addr;

use byteorder::ReadBytesExt;
use log::warn;

use crate::backends::Lease;
use crate::protocol::enums;
use crate::protocol::errors::PacketError;
use crate::protocol::option::DhcpOption;

const COOKIE: [u8; 4] = [99, 130, 83, 99];

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
}

impl DhcpPacket {
    /// Given a DhcpPacket and a lease, generate the appropriate response packet
    /// according to DHCP specified symantics.
    pub fn response(src: &DhcpPacket, lease: Lease) -> Self {
        let op = match src.op {
            enums::DhcpOperation::BootRequest => enums::DhcpOperation::BootReply,
            enums::DhcpOperation::BootReply => enums::DhcpOperation::BootRequest,
            enums::DhcpOperation::Unknown(i) => enums::DhcpOperation::Unknown(i),
        };

        let mut msg_type = enums::MessageType::Unknown(255);
        if let Some(DhcpOption::DhcpMsgType(mt)) = src.get_option(DhcpOption::DHCPMSGTYPE) {
            match mt {
                enums::MessageType::Discover => msg_type = enums::MessageType::Offer,
                enums::MessageType::Request => msg_type = enums::MessageType::Acknowledge,
                enums::MessageType::Inform => msg_type = enums::MessageType::Acknowledge,
                _ => (),
            }
        }

        let mut new = Self {
            op,
            htype: src.htype,
            hlen: src.hlen,
            hops: src.hops,
            xid: src.xid,
            secs: src.secs,
            flags: src.flags,
            ciaddr: src.ciaddr,
            yiaddr: src.yiaddr,
            siaddr: src.siaddr,
            giaddr: src.giaddr,
            chaddr: src.chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            cookie: COOKIE,
            options: DhcpOptions::new(None),
        };

        if let Some(ip) = lease.yiaddr {
            new.yiaddr = ip;
        }
        if let Some(ip) = lease.siaddr {
            new.siaddr = ip;
        }
        if let Some(f) = lease.file {
            new.file = f;
        }
        if let Some(o) = lease.options {
            new.options.options.extend(o.options);
        }

        if lease.lease_duration.num_seconds() > 0 {
            let lease_val = lease
                .lease_duration
                .num_seconds()
                .try_into()
                .unwrap_or(u32::MAX);
            new.options.options.push(DhcpOption::AddressTime(lease_val));
        }

        new.options.options.push(DhcpOption::DhcpMsgType(msg_type));

        new
    }

    /// Given a DhcpPacket generate the appropriate Negative Acknowledgment accoding
    /// to DHCP specified symantics.
    pub fn nak(src: &DhcpPacket) -> Self {
        let op = enums::DhcpOperation::BootReply;
        let msg_type = enums::MessageType::NegAcknowledge;

        let mut new = Self {
            op,
            htype: src.htype,
            hlen: src.hlen,
            hops: src.hops,
            xid: src.xid,
            secs: src.secs,
            flags: src.flags,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: src.giaddr,
            chaddr: src.chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            cookie: COOKIE,
            options: DhcpOptions::new(None),
        };

        new.options.options.push(DhcpOption::DhcpMsgType(msg_type));

        new
    }

    /// Deserialze a DHCP packet from the provided byte slice.  E.g. bytes read
    /// from a UDP socket.
    pub fn from_network(raw: &[u8]) -> Result<Self, PacketError> {
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
        let mut data = vec![
            u8::from(self.op),
            u8::from(self.htype),
            self.hlen,
            self.hops,
        ];
        data.extend(self.xid.to_be_bytes());
        data.extend(self.secs.to_be_bytes());
        data.extend(self.flags.to_be_bytes());
        data.extend(u32::from(self.ciaddr).to_be_bytes());
        data.extend(u32::from(self.yiaddr).to_be_bytes());
        data.extend(u32::from(self.siaddr).to_be_bytes());
        data.extend(u32::from(self.giaddr).to_be_bytes());
        data.extend(self.chaddr);
        data.extend(self.sname);
        data.extend(self.file);
        data.extend(COOKIE);

        // Force a length of at least 300.  There are documented cases of clients
        // expecting the old BOOTP options of 64bytes (including cookie) making the
        // total packet size 300 bytes.
        let mut options_data = self.options.to_network();
        if options_data.len() < 60 {
            options_data.extend(vec![0u8; 60 - options_data.len()]);
        }
        data.extend(options_data);
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

        if self.get_option(DhcpOption::DHCPSERVERID).is_some() {
            return Some(enums::ClientState::Selecting);
        }

        if !self.is_broadcast() {
            return Some(enums::ClientState::Renewing);
        }

        if self.ciaddr != Ipv4Addr::new(0, 0, 0, 0) {
            return Some(enums::ClientState::Rebinding);
        }

        Some(enums::ClientState::InitReboot)
    }

    /// Return true if the broadcast flag in the DhcpPacket is set.
    pub fn is_broadcast(&self) -> bool {
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
            bytes.extend(o.to_network().to_vec());
        }
        bytes.push(255u8);
        bytes
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
    use std::panic::catch_unwind;

    use crate::protocol::enums::MessageType;
    use crate::protocol::option::DhcpOption;
    use crate::protocol::packet;
    use std::fs;

    #[test]
    fn test_discover_network() {
        let sample_data =
            fs::read("test_data/discover.dhcp.bin").expect("failed to read data file");
        let dhcp_packet =
            packet::DhcpPacket::from_network(&sample_data).expect("Failed to decode packet");
        assert_eq!(u8::from(dhcp_packet.message_type().unwrap()), 1u8);
        let network_data = dhcp_packet.to_network();
        assert_eq!(sample_data, network_data);
    }

    #[test]
    fn test_is_broadcast() {
        let sample_data =
            fs::read("test_data/discover.dhcp.bin").expect("failed to read data file");
        let mut dhcp_packet =
            packet::DhcpPacket::from_network(&sample_data).expect("Failed to decode packet");
        println!("flags: {:#?}", dhcp_packet.flags);
        assert!(!dhcp_packet.is_broadcast());
        dhcp_packet.flags = 32768u16;
        assert!(dhcp_packet.is_broadcast());
    }

    #[test]
    fn test_get_option() {
        let sample_data =
            fs::read("test_data/discover.dhcp.bin").expect("failed to read data file");
        let dhcp_packet =
            packet::DhcpPacket::from_network(&sample_data).expect("Failed to decode packet");
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
        let result = catch_unwind(|| packet::DhcpPacket::from_network(&[0u8; 239]));

        assert!(result.is_ok(), "short packet caused a panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn rejects_empty_options_without_panicking() {
        let raw = packet_with_options(&[]);
        let result = catch_unwind(|| packet::DhcpPacket::from_network(&raw));

        assert!(result.is_ok(), "empty option area caused a panic");
        assert!(result.unwrap().unwrap().options.options.is_empty());
    }

    #[test]
    fn rejects_truncated_option_payload_without_panicking() {
        // Option 1 claims two payload bytes but only one is present.
        let raw = packet_with_options(&[1, 2, 0]);
        let result = catch_unwind(|| packet::DhcpPacket::from_network(&raw));

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
}
