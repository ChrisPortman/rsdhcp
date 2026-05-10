use rsdhcp_macros::DhcpOptions;
use std::net::Ipv4Addr;

use crate::protocol::errors::PacketError;

/// DhcpOption is an option in a DHCP data structure.
#[derive(Debug, Clone, DhcpOptions)]
pub enum DhcpOption {
    #[code(0)]
    Pad(String),
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
    SwapServer(String),
    #[code(17)]
    RootPath(String),
    #[code(18)]
    ExtensionFile(String),
    #[code(19)]
    ForwardOnOff(u8),
    #[code(20)]
    SrcRteOnOff(u8),
    #[code(21)]
    PolicyFilter(String),
    #[code(22)]
    MaxDgAssembly(u16),
    #[code(23)]
    DefaultIpTtl(u8),
    #[code(24)]
    MtuTimeout(u32),
    #[code(25)]
    MtuPlateau(String),
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
    StaticRoute(String),
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
    VendorSpecific(String),
    #[code(44)]
    NetbiosNameSrv(String),
    #[code(45)]
    NetbiosDistSrv(String),
    #[code(46)]
    NetbiosNodeType(u8),
    #[code(47)]
    NetbiosScope(String),
    #[code(48)]
    XWindowFont(String),
    #[code(49)]
    XWindowManager(String),
    #[code(50)]
    AddressRequest(Ipv4Addr),
    #[code(51)]
    AddressTime(u32),
    #[code(52)]
    Overload(u8),
    #[code(53)]
    DhcpMsgType(u8),
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
    End(String),
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
        let bytes_array = <[u8; 1]>::try_from(bytes);
        match bytes_array {
            Ok(a) => Ok(a[0]),
            Err(_) => Err(PacketError::new("U8 options require 1 bytes")),
        }
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

        let mut res: Vec<Ipv4Addr> = vec![];
        let mut offset = 0;
        loop {
            if offset + 4 > bytes.len() {
                break;
            }
            let num: u32 = u32::from_be_bytes(bytes[offset..4].try_into().unwrap());
            res.push(Ipv4Addr::from(num));
            offset += 4;
        }
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

#[cfg(test)]
mod tests {
    use crate::protocol::option::{DhcpOption, ValueSerde};
    use std::net::Ipv4Addr;

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
}
