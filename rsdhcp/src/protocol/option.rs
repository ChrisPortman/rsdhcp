use rsdhcp_macros::DhcpOptions;
use std::net::Ipv4Addr;

use crate::protocol::enums::MessageType;
use crate::protocol::errors::PacketError;

/// DhcpOption is an option in a DHCP data structure.
#[derive(Debug, Clone, DhcpOptions)]
pub enum DhcpOption {
    #[code(0)]
    Pad,
    #[code(1)]
    SubnetMask(Ipv4Addr),
    #[code(2)]
    TimeOffset(i32),
    #[code(3)]
    Router(Vec<Ipv4Addr>),
    #[code(4)]
    TimeServer(Vec<Ipv4Addr>),
    #[code(5)]
    NameServer(Vec<Ipv4Addr>),
    #[code(6)]
    DomainServer(Vec<Ipv4Addr>),
    #[code(7)]
    LogServer(Vec<Ipv4Addr>),
    #[code(8)]
    QuotesServer(Vec<Ipv4Addr>),
    #[code(9)]
    LprServer(Vec<Ipv4Addr>),
    #[code(10)]
    ImpressServer(Vec<Ipv4Addr>),
    #[code(11)]
    RlpServer(Vec<Ipv4Addr>),
    #[code(12)]
    Hostname(String),
    #[code(13)]
    BootFileSize(u16),
    #[code(14)]
    MeritDumpFile(String),
    #[code(15)]
    DomainName(String),
    #[code(16)]
    SwapServer(Ipv4Addr),
    #[code(17)]
    RootPath(String),
    #[code(18)]
    ExtensionFile(String),
    #[code(19)]
    ForwardOnOff(u8),
    #[code(20)]
    SrcRteOnOff(u8),
    #[code(21)]
    PolicyFilter(Vec<(Ipv4Addr, Ipv4Addr)>),
    #[code(22)]
    MaxDgAssembly(u16),
    #[code(23)]
    DefaultIpTtl(u8),
    #[code(24)]
    MtuTimeout(u32),
    #[code(25)]
    MtuPlateau(Vec<u16>),
    #[code(26)]
    MtuInterface(u16),
    #[code(27)]
    MtuSubnet(u8),
    #[code(28)]
    BroadcastAddress(Ipv4Addr),
    #[code(29)]
    MaskDiscovery(u8),
    #[code(30)]
    MaskSupplier(u8),
    #[code(31)]
    RouterDiscovery(u8),
    #[code(32)]
    RouterRequest(Ipv4Addr),
    #[code(33)]
    StaticRoute(Vec<(Ipv4Addr, Ipv4Addr)>),
    #[code(34)]
    Trailers(u8),
    #[code(35)]
    ArpTimeout(u32),
    #[code(36)]
    Ethernet(u8),
    #[code(37)]
    DefaultTcpTtl(u8),
    #[code(38)]
    KeepaliveTime(u32),
    #[code(39)]
    KeepaliveData(u8),
    #[code(40)]
    NisDomain(String),
    #[code(41)]
    NisServers(Vec<Ipv4Addr>),
    #[code(42)]
    NtpServers(Vec<Ipv4Addr>),
    #[code(43)]
    VendorSpecific(Vec<u8>),
    #[code(44)]
    NetbiosNameSrv(Vec<Ipv4Addr>),
    #[code(45)]
    NetbiosDistSrv(Vec<Ipv4Addr>),
    #[code(46)]
    NetbiosNodeType(u8),
    #[code(47)]
    NetbiosScope(String),
    #[code(48)]
    XWindowFont(Vec<Ipv4Addr>),
    #[code(49)]
    XWindowManager(Vec<Ipv4Addr>),
    #[code(50)]
    AddressRequest(Ipv4Addr),
    #[code(51)]
    AddressTime(u32),
    #[code(52)]
    Overload(u8),
    #[code(53)]
    DhcpMsgType(MessageType),
    #[code(54)]
    DhcpServerId(Ipv4Addr),
    #[code(55)]
    ParameterList(Vec<u8>),
    #[code(56)]
    DhcpMessage(String),
    #[code(57)]
    DhcpMaxMsgSize(u16),
    #[code(58)]
    RenewalTime(u32),
    #[code(59)]
    RebindingTime(u32),
    #[code(60)]
    ClassId(String),
    #[code(61)]
    ClientId(Vec<u8>),
    #[code(64)]
    NisDomainName(String),
    #[code(65)]
    NisServerAddr(Vec<Ipv4Addr>),
    #[code(66)]
    ServerName(String),
    #[code(67)]
    BootfileName(String),
    #[code(68)]
    HomeAgentAddrs(Vec<Ipv4Addr>),
    #[code(69)]
    SmtpServer(Vec<Ipv4Addr>),
    #[code(70)]
    Pop3Server(Vec<Ipv4Addr>),
    #[code(71)]
    NntpServer(Vec<Ipv4Addr>),
    #[code(72)]
    WwwServer(Vec<Ipv4Addr>),
    #[code(73)]
    FingerServer(Vec<Ipv4Addr>),
    #[code(74)]
    IrcServer(Vec<Ipv4Addr>),
    #[code(75)]
    StreetTalkServer(Vec<Ipv4Addr>),
    #[code(76)]
    StdaServer(Vec<Ipv4Addr>),
    #[code(82)]
    RelayAgentInformation(Vec<u8>),
    #[code(119)]
    DomainSearch(Vec<u8>),
    #[code(255)]
    End,
}

/// Defines required behavior to serialise to and from the network according to
/// the DHCP specifications.
pub trait ValueSerde {
    /// Deserialize bytes read from the network into the type.
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError>
    where
        Self: Sized;
    /// Serialize the type into network bytes ready to be written to the network.
    fn to_network(&self) -> Vec<u8>;
}

impl ValueSerde for u8 {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() != 1 {
            return Err(PacketError::new("U8 options require 1 bytes"));
        }

        Ok(bytes[0])
    }

    fn to_network(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl ValueSerde for Vec<u8> {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        Ok(bytes.to_vec())
    }

    fn to_network(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl ValueSerde for u16 {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        let bytes_array = <[u8; 2]>::try_from(bytes);
        match bytes_array {
            Ok(a) => Ok(Self::from_be_bytes(a)),
            Err(_) => Err(PacketError::new("U16 options require 2 bytes")),
        }
    }

    fn to_network(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl ValueSerde for Vec<u16> {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        if !bytes.len().is_multiple_of(2) {
            return Err(PacketError::new(
                "u16 list options must be of length multiple of 2",
            ));
        }

        let mut result: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
        bytes.chunks_exact(2).for_each(|c| {
            let c = <[u8; 2]>::try_from(c).expect("2 byte slice did not convert to 2 byte array");
            result.push(u16::from_be_bytes(c));
        });

        Ok(result)
    }

    fn to_network(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len() * 2);
        self.iter()
            .for_each(|n| bytes.extend_from_slice(&n.to_be_bytes()));

        bytes
    }
}

impl ValueSerde for u32 {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        let bytes_array = <[u8; 4]>::try_from(bytes);
        match bytes_array {
            Ok(a) => Ok(Self::from_be_bytes(a)),
            Err(_) => Err(PacketError::new("U32 options require 4 bytes")),
        }
    }

    fn to_network(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl ValueSerde for i32 {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        let bytes_array = <[u8; 4]>::try_from(bytes);
        match bytes_array {
            Ok(a) => Ok(Self::from_be_bytes(a)),
            Err(_) => Err(PacketError::new("I32 options require 4 bytes")),
        }
    }

    fn to_network(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl ValueSerde for String {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        let value = String::from_utf8(bytes.to_vec());
        match value {
            Ok(v) => {
                if !v.is_ascii() {
                    return Err(PacketError::new("Invalid ascii bytes"));
                }
                let v = v.trim_end_matches(char::from(0));
                Ok(v.into())
            }
            Err(_) => Err(PacketError::new("Invalid ascii bytes")),
        }
    }

    fn to_network(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ValueSerde for Ipv4Addr {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        let bytes_array = <[u8; 4]>::try_from(bytes);
        match bytes_array {
            Ok(a) => Ok(Self::from(u32::from_be_bytes(a))),
            Err(_) => Err(PacketError::new("IPV4 options require 4 bytes")),
        }
    }

    fn to_network(&self) -> Vec<u8> {
        u32::from(*self).to_be_bytes().to_vec()
    }
}

impl ValueSerde for Vec<Ipv4Addr> {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        if !bytes.len().is_multiple_of(4) {
            return Err(PacketError::new(
                "IP address list options must be a multiple of 4 bytes",
            ));
        }

        let mut res: Vec<Ipv4Addr> = Vec::with_capacity(bytes.len() / 4);

        bytes.chunks_exact(4).for_each(|c| {
            let num: u32 = u32::from_be_bytes(
                c.try_into()
                    .expect("failed to convert 4byte array into u32"),
            );
            res.push(Ipv4Addr::from(num));
        });

        Ok(res)
    }

    fn to_network(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        for ip in self {
            bytes.append(&mut u32::from(*ip).to_be_bytes().to_vec());
        }
        bytes
    }
}

impl ValueSerde for Vec<(Ipv4Addr, Ipv4Addr)> {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError> {
        if !bytes.len().is_multiple_of(8) {
            return Err(PacketError::new(
                "IP/Mask list options must be a multiple of 8 bytes",
            ));
        }

        let mut res: Vec<(Ipv4Addr, Ipv4Addr)> = vec![];
        let mut offset = 0;

        loop {
            let addr_start = offset;
            let addr_end = addr_start + 4;
            let mask_start = addr_end;
            let mask_end = mask_start + 4;

            if mask_end > bytes.len() {
                break;
            }

            let addrnum: u32 = u32::from_be_bytes(bytes[addr_start..addr_end].try_into().unwrap());
            let masknum: u32 = u32::from_be_bytes(bytes[mask_start..mask_end].try_into().unwrap());

            res.push((Ipv4Addr::from(addrnum), Ipv4Addr::from(masknum)));
            offset += 8;
        }

        Ok(res)
    }

    fn to_network(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        for ip in self {
            let addr = ip.0;
            let mask = ip.1;
            bytes.append(&mut u32::from(addr).to_be_bytes().to_vec());
            bytes.append(&mut u32::from(mask).to_be_bytes().to_vec());
        }
        bytes
    }
}

impl ValueSerde for MessageType {
    fn from_network(bytes: &[u8]) -> Result<Self, PacketError>
    where
        Self: Sized,
    {
        if bytes.len() != 1 {
            return Err(PacketError::new(
                "Malformed packet: message type is 1 byte only",
            ));
        }

        let mt = Self::from(&bytes[0]);

        if let MessageType::Unknown(v) = mt {
            return Err(PacketError::new(
                format!("Malformed packet - invalid message type {v}").as_str(),
            ));
        };

        Ok(Self::from(&bytes[0]))
    }

    fn to_network(&self) -> Vec<u8> {
        vec![u8::from(self)]
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::panic::catch_unwind;

    use crate::protocol::option::{DhcpOption, ValueSerde};

    #[test]
    fn test_endianess() {
        assert_eq!(u16::from_be_bytes([0, 1]), 1u16);
        assert_eq!(u16::from_le_bytes([0, 1]), 256u16);
    }

    #[test]
    fn ipv4addr_option_from_network() {
        let be_bytes: [u8; 4] = [192, 168, 0, 1];
        let option =
            DhcpOption::SubnetMask(Ipv4Addr::from_network(&be_bytes).expect("invalid data"));
        assert_eq!(1u8, option.code());

        if let DhcpOption::SubnetMask(o) = option {
            assert_eq!("192.168.0.1", format!["{}", o]);
        }
    }

    #[test]
    fn ipv4addr_option_to_network() {
        let option = DhcpOption::SubnetMask(Ipv4Addr::new(192, 168, 0, 1));
        if let DhcpOption::SubnetMask(o) = option {
            assert_eq!(o.to_network(), vec![192, 168, 0, 1]);
        }
    }

    #[test]
    fn dhcp_option_to_network() {
        let option = DhcpOption::SubnetMask(Ipv4Addr::new(10, 1, 1, 1));
        assert_eq!(option.to_network(), vec![1, 4, 10, 1, 1, 1]);
        let option =
            DhcpOption::Router(vec![Ipv4Addr::new(10, 1, 1, 1), Ipv4Addr::new(10, 1, 1, 2)]);
        assert_eq!(option.to_network(), vec![3, 8, 10, 1, 1, 1, 10, 1, 1, 2]);
    }

    #[test]
    fn pad_and_end_are_single_octet_options() {
        assert_eq!(DhcpOption::Pad.to_network(), vec![0]);
        assert_eq!(DhcpOption::End.to_network(), vec![255]);
    }

    #[test]
    fn binary_standard_options_are_not_decoded_as_ascii() {
        // RFC 2132 defines these as binary structures or opaque bytes.
        assert!(DhcpOption::new(&21, &[192, 0, 2, 1, 255, 255, 255, 0]).is_ok());
        assert!(DhcpOption::new(&25, &[5, 220]).is_ok());
        assert!(DhcpOption::new(&33, &[192, 0, 2, 1, 192, 0, 2, 254]).is_ok());
        assert!(DhcpOption::new(&43, &[255, 0, 1]).is_ok());
        assert!(DhcpOption::new(&44, &[192, 0, 2, 1]).is_ok());
        assert!(DhcpOption::new(&48, &[192, 0, 2, 1]).is_ok());
    }

    fn assert_rfc2132_wire_format(code: u8, payload: Vec<u8>) {
        let decoded = catch_unwind(|| DhcpOption::new(&code, &payload));
        assert!(decoded.is_ok(), "option {} decoder panicked", code);

        let option = decoded
            .unwrap()
            .unwrap_or_else(|error| panic!("RFC-valid option {} was rejected: {}", code, error));

        let expected = if code == 0 || code == 255 {
            vec![code]
        } else {
            let mut wire = vec![code, payload.len() as u8];
            wire.extend_from_slice(&payload);
            wire
        };

        assert_eq!(option.code(), code);
        assert_eq!(option.to_network(), expected, "option {} wire format", code);
    }

    #[test]
    fn all_declared_options_use_rfc2132_wire_formats() {
        // This list covers every option variant declared in DhcpOption. The
        // payloads are RFC-valid examples.
        let cases = vec![
            (0, vec![]),
            (1, vec![255, 255, 255, 0]),
            (2, vec![0, 0, 0, 0]),
            (3, vec![192, 0, 2, 1, 192, 0, 2, 254]),
            (4, vec![192, 0, 2, 2]),
            (5, vec![192, 0, 2, 3]),
            (6, vec![192, 0, 2, 4]),
            (7, vec![192, 0, 2, 5]),
            (8, vec![192, 0, 2, 6]),
            (9, vec![192, 0, 2, 7]),
            (10, vec![192, 0, 2, 8]),
            (11, vec![192, 0, 2, 9]),
            (12, b"client.example".to_vec()),
            (13, vec![0, 32]),
            (14, b"/var/dump".to_vec()),
            (15, b"example".to_vec()),
            (16, vec![192, 0, 2, 10]),
            (17, b"/".to_vec()),
            (18, b"/etc/dhcp.ext".to_vec()),
            (19, vec![1]),
            (20, vec![0]),
            (21, vec![192, 0, 2, 1, 255, 255, 255, 0]),
            (22, vec![5, 220]),
            (23, vec![64]),
            (24, vec![0, 0, 0, 120]),
            (25, vec![5, 220, 2, 0]),
            (26, vec![5, 220]),
            (27, vec![1]),
            (28, vec![192, 0, 2, 255]),
            (29, vec![1]),
            (30, vec![0]),
            (31, vec![1]),
            (32, vec![192, 0, 2, 1]),
            (33, vec![192, 0, 2, 1, 192, 0, 2, 254]),
            (34, vec![1]),
            (35, vec![0, 0, 0, 60]),
            (36, vec![1]),
            (37, vec![64]),
            (38, vec![0, 0, 0, 30]),
            (39, vec![1]),
            (40, b"example".to_vec()),
            (41, vec![192, 0, 2, 11]),
            (42, vec![192, 0, 2, 12]),
            (43, vec![0xde, 0xad, 0xbe, 0xef]),
            (44, vec![192, 0, 2, 13]),
            (45, vec![192, 0, 2, 14]),
            (46, vec![8]),
            (47, b"scope".to_vec()),
            (48, vec![192, 0, 2, 15]),
            (49, vec![192, 0, 2, 16]),
            (50, vec![192, 0, 2, 20]),
            (51, vec![0, 0, 14, 16]),
            (52, vec![3]),
            (53, vec![1]),
            (54, vec![192, 0, 2, 1]),
            (55, vec![1, 3, 6]),
            (56, b"configuration rejected".to_vec()),
            (57, vec![5, 220]),
            (58, vec![0, 0, 7, 8]),
            (59, vec![0, 0, 12, 96]),
            (60, b"vendor-class".to_vec()),
            (61, vec![1, 0xff, 2]),
            (64, b"example".to_vec()),
            (65, vec![192, 0, 2, 17]),
            (66, b"boot.example".to_vec()),
            (67, b"pxelinux.0".to_vec()),
            (68, vec![192, 0, 2, 18]),
            (69, vec![192, 0, 2, 19]),
            (70, vec![192, 0, 2, 20]),
            (71, vec![192, 0, 2, 21]),
            (72, vec![192, 0, 2, 22]),
            (73, vec![192, 0, 2, 23]),
            (74, vec![192, 0, 2, 24]),
            (75, vec![192, 0, 2, 25]),
            (76, vec![192, 0, 2, 26]),
            // Relay Agent Information: circuit-id "abc", remote-id 0x0102.
            (82, vec![1, 3, b'a', b'b', b'c', 2, 2, 1, 2]),
            // RFC 3397 domain-search encoding for "www.example.com".
            (
                119,
                vec![
                    3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c',
                    b'o', b'm', 0,
                ],
            ),
            (255, vec![]),
        ];

        for (code, payload) in cases {
            assert_rfc2132_wire_format(code, payload);
        }
    }

    #[test]
    fn fixed_width_and_list_options_reject_invalid_lengths() {
        let cases = [
            (1, vec![255, 255, 255]),
            (2, vec![0, 0, 0]),
            (3, vec![192, 0, 2]),
            (13, vec![0]),
            (16, vec![192, 0, 2]),
            (21, vec![192, 0, 2, 1]),
            (22, vec![0]),
            (24, vec![0, 0, 0]),
            (25, vec![0]),
            (26, vec![0]),
            (33, vec![192, 0, 2, 1]),
            (35, vec![0]),
            (41, vec![192, 0, 2]),
            (50, vec![192, 0, 2]),
            (51, vec![0, 0, 0]),
            (54, vec![192, 0, 2]),
            (57, vec![0]),
            (58, vec![0, 0, 0]),
            (59, vec![0, 0, 0]),
            (65, vec![192, 0, 2]),
            (68, vec![192, 0, 2]),
        ];

        for (code, payload) in cases {
            let decoded = catch_unwind(|| DhcpOption::new(&code, &payload));
            assert!(decoded.is_ok(), "option {} decoder panicked", code);
            assert!(
                decoded.unwrap().is_err(),
                "option {} accepted invalid payload length {}",
                code,
                payload.len()
            );
        }
    }

    #[test]
    fn message_type_option_rejects_values_outside_rfc2131() {
        for value in [0u8, 9u8, 255u8] {
            assert!(
                DhcpOption::new(&53, &[value]).is_err(),
                "invalid DHCP message type {} was accepted",
                value
            );
        }
    }
    #[test]
    fn list_valued_options_support_one_and_multiple_elements() {
        let ip_lists = vec![
            (3, vec![192, 0, 2, 1], vec![192, 0, 2, 1, 192, 0, 2, 254]),
            (4, vec![192, 0, 2, 2], vec![192, 0, 2, 2, 192, 0, 2, 3]),
            (5, vec![192, 0, 2, 4], vec![192, 0, 2, 4, 192, 0, 2, 5]),
            (6, vec![192, 0, 2, 6], vec![192, 0, 2, 6, 192, 0, 2, 7]),
            (7, vec![192, 0, 2, 8], vec![192, 0, 2, 8, 192, 0, 2, 9]),
            (8, vec![192, 0, 2, 10], vec![192, 0, 2, 10, 192, 0, 2, 11]),
            (9, vec![192, 0, 2, 12], vec![192, 0, 2, 12, 192, 0, 2, 13]),
            (10, vec![192, 0, 2, 14], vec![192, 0, 2, 14, 192, 0, 2, 15]),
            (11, vec![192, 0, 2, 16], vec![192, 0, 2, 16, 192, 0, 2, 17]),
            (41, vec![192, 0, 2, 18], vec![192, 0, 2, 18, 192, 0, 2, 19]),
            (42, vec![192, 0, 2, 20], vec![192, 0, 2, 20, 192, 0, 2, 21]),
            (44, vec![192, 0, 2, 22], vec![192, 0, 2, 22, 192, 0, 2, 23]),
            (45, vec![192, 0, 2, 24], vec![192, 0, 2, 24, 192, 0, 2, 25]),
            (48, vec![192, 0, 2, 26], vec![192, 0, 2, 26, 192, 0, 2, 27]),
            (49, vec![192, 0, 2, 28], vec![192, 0, 2, 28, 192, 0, 2, 29]),
            (65, vec![192, 0, 2, 30], vec![192, 0, 2, 30, 192, 0, 2, 31]),
            (68, vec![192, 0, 2, 32], vec![192, 0, 2, 32, 192, 0, 2, 33]),
            (69, vec![192, 0, 2, 34], vec![192, 0, 2, 34, 192, 0, 2, 35]),
            (70, vec![192, 0, 2, 36], vec![192, 0, 2, 36, 192, 0, 2, 37]),
            (71, vec![192, 0, 2, 38], vec![192, 0, 2, 38, 192, 0, 2, 39]),
            (72, vec![192, 0, 2, 40], vec![192, 0, 2, 40, 192, 0, 2, 41]),
            (73, vec![192, 0, 2, 42], vec![192, 0, 2, 42, 192, 0, 2, 43]),
            (74, vec![192, 0, 2, 44], vec![192, 0, 2, 44, 192, 0, 2, 45]),
            (75, vec![192, 0, 2, 46], vec![192, 0, 2, 46, 192, 0, 2, 47]),
            (76, vec![192, 0, 2, 48], vec![192, 0, 2, 48, 192, 0, 2, 49]),
        ];

        for (code, one, multiple) in ip_lists {
            assert_rfc2132_wire_format(code, one);
            assert_rfc2132_wire_format(code, multiple);
        }

        let structured_lists = [
            // Policy Filter: one and two address/mask pairs.
            (
                21,
                vec![192, 0, 2, 1, 255, 255, 255, 0],
                vec![
                    192, 0, 2, 1, 255, 255, 255, 0, 198, 51, 100, 1, 255, 255, 255, 0,
                ],
            ),
            // MTU Plateau Table: one and two uint16 values.
            (25, vec![5, 220], vec![5, 220, 2, 0]),
            // Static Route: one and two destination/router pairs.
            (
                33,
                vec![192, 0, 2, 1, 192, 0, 2, 254],
                vec![
                    192, 0, 2, 1, 192, 0, 2, 254, 198, 51, 100, 0, 192, 0, 2, 254,
                ],
            ),
            // Parameter Request List: one and multiple option codes.
            (55, vec![1], vec![1, 3, 6]),
            // Relay Agent Information: one and multiple suboptions.
            (
                82,
                vec![1, 3, b'a', b'b', b'c'],
                vec![1, 3, b'a', b'b', b'c', 2, 2, 1, 2],
            ),
            // RFC 3397: one and multiple domain names.
            (
                119,
                vec![3, b'o', b'n', b'e', 0],
                vec![3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o', 0],
            ),
        ];

        for (code, one, multiple) in structured_lists {
            assert_rfc2132_wire_format(code, one);
            assert_rfc2132_wire_format(code, multiple);
        }
    }
}
