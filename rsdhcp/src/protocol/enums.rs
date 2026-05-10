pub const DHCP_SERVER_PORT: usize = 67;
pub const DHCP_CLIENT_PORT: usize = 68;

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum DhcpOperation {
    BootRequest,
    BootReply,
    Unknown(u8),
}

impl From<u8> for DhcpOperation {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::BootRequest,
            2 => Self::BootReply,
            _ => Self::Unknown(value),
        }
    }
}

impl From<DhcpOperation> for u8 {
    fn from(value: DhcpOperation) -> Self {
        match value {
            DhcpOperation::BootRequest => 1,
            DhcpOperation::BootReply => 2,
            DhcpOperation::Unknown(n) => n,
        }
    }
}

#[derive(Debug)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Acknowledge,
    NegAcknowledge,
    Release,
    Inform,
    Unknown(u8),
}

impl From<&u8> for MessageType {
    fn from(value: &u8) -> Self {
        match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Acknowledge,
            6 => Self::NegAcknowledge,
            7 => Self::Release,
            8 => Self::Inform,
            _ => Self::Unknown(*value),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Discover => 1,
            MessageType::Offer => 2,
            MessageType::Request => 3,
            MessageType::Decline => 4,
            MessageType::Acknowledge => 5,
            MessageType::NegAcknowledge => 6,
            MessageType::Release => 7,
            MessageType::Inform => 8,
            MessageType::Unknown(value) => value,
        }
    }
}

// Hardware Types (RFC1700)
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum HardwareType {
    Ethernet,
    ExperimentalEthernet,
    AmateurRadio,
    TokenRing,
    Chaos,
    Ieee802,
    Arcnet,
    HyperChannel,
    Lanstar,
    AutonetShortAddress,
    LocalTalk,
    LocalNe,
    UltraLink,
    Smds,
    FrameRelay,
    AsynchronousTransmissionMode,
    Hdlc,
    FibreChannel,
    Unknown(u8),
}

impl From<u8> for HardwareType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Ethernet,
            2 => Self::ExperimentalEthernet,
            3 => Self::AmateurRadio,
            4 => Self::TokenRing,
            5 => Self::Chaos,
            6 => Self::Ieee802,
            7 => Self::Arcnet,
            8 => Self::HyperChannel,
            9 => Self::Lanstar,
            10 => Self::AutonetShortAddress,
            11 => Self::LocalTalk,
            12 => Self::LocalNe,
            13 => Self::UltraLink,
            14 => Self::Smds,
            15 => Self::FrameRelay,
            16 => Self::AsynchronousTransmissionMode,
            17 => Self::Hdlc,
            18 => Self::FibreChannel,
            _ => Self::Unknown(value),
        }
    }
}

impl From<HardwareType> for u8 {
    fn from(value: HardwareType) -> Self {
        match value {
            HardwareType::Ethernet => 1,
            HardwareType::ExperimentalEthernet => 2,
            HardwareType::AmateurRadio => 3,
            HardwareType::TokenRing => 4,
            HardwareType::Chaos => 5,
            HardwareType::Ieee802 => 6,
            HardwareType::Arcnet => 7,
            HardwareType::HyperChannel => 8,
            HardwareType::Lanstar => 9,
            HardwareType::AutonetShortAddress => 10,
            HardwareType::LocalTalk => 11,
            HardwareType::LocalNe => 12,
            HardwareType::UltraLink => 13,
            HardwareType::Smds => 14,
            HardwareType::FrameRelay => 15,
            HardwareType::AsynchronousTransmissionMode => 16,
            HardwareType::Hdlc => 17,
            HardwareType::FibreChannel => 18,
            HardwareType::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ClientState {
    Init,
    InitReboot,
    Selecting,
    Renewing,
    Rebinding,
}
