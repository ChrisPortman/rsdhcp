use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct PacketError {
    error: String,
}

impl PacketError {
    pub fn new(msg: &str) -> Self {
        Self {
            error: msg.to_string(),
        }
    }
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for PacketError {
    fn description(&self) -> &str {
        &self.error
    }
}

impl From<&str> for PacketError {
    fn from(err: &str) -> Self {
        Self {
            error: err.to_string(),
        }
    }
}

impl From<std::array::TryFromSliceError> for PacketError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        Self {
            error: err.to_string(),
        }
    }
}
