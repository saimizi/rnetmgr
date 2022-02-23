use crate::netif::MacAddr;
use ipnetwork::IpNetwork;
use serde_derive::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};

#[allow(unused)]
use crate::{fdebug, ferror, finfo, ftrace, fwarn, NetIfConfig, NetIfConfigEntry};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetInfoNewLink {
    pub ifname: String,
    pub if_index: u32,
    pub mac: MacAddr,
    pub flags: u32,
}

impl Display for NetInfoNewLink {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NewLink {} {} {} {:2x}",
            self.ifname, self.if_index, self.mac, self.flags
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetInfoDelLink {
    pub ifname: String,
    pub if_index: u32,
    pub flags: u32,
}

impl Display for NetInfoDelLink {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DelLink {} {} {:2x}",
            self.ifname, self.if_index, self.flags
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetInfoNewAddress {
    pub ifname: String,
    pub if_index: u32,
    pub ipv4addr: IpNetwork,
}

impl Display for NetInfoNewAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NewAddr {} {} {}",
            self.ifname, self.if_index, self.ipv4addr
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetInfoDelAddress {
    pub ifname: String,
    pub if_index: u32,
    pub ipv4addr: IpNetwork,
}

impl Display for NetInfoDelAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DelAddr {} {} {}",
            self.ifname, self.if_index, self.ipv4addr
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetInfoMessage {
    NewLink(NetInfoNewLink),
    DelLink(NetInfoDelLink),
    NewAddress(NetInfoNewAddress),
    DelAddress(NetInfoDelAddress),
    NoInfo,
    InvalidReq,
}

impl Display for NetInfoMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NetInfoMessage::NewLink(a) => write!(f, "{}", a),
            NetInfoMessage::DelLink(a) => write!(f, "{}", a),
            NetInfoMessage::NewAddress(a) => write!(f, "{}", a),
            NetInfoMessage::DelAddress(a) => write!(f, "{}", a),
            NetInfoMessage::NoInfo => write!(f, "none"),
            NetInfoMessage::InvalidReq => write!(f, "invalid"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetInfoReqMessage {
    ReqLink(String),
    ReqAddress(String),
}
