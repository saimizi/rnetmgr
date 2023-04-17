use std::{error::Error, fmt::Display};

#[allow(unused)]
#[derive(Debug)]
pub enum RnetmgrError {
    InvalidValue,
    RtNetlinkError,
    SocketError,
    SystemError,
    Unknown,
}

impl Display for RnetmgrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_str = match self {
            RnetmgrError::InvalidValue => "Invalid parameter",
            RnetmgrError::RtNetlinkError => "Rtnetlink error",
            RnetmgrError::SocketError => "Socket error",
            RnetmgrError::SystemError => "System error",
            RnetmgrError::Unknown => "Unknown error",
        };

        write!(f, "{}", err_str)
    }
}

impl Error for RnetmgrError {}
