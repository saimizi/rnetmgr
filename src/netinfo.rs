use crate::netif::{NetIf, MacAddr, Ipv4Entry};
use std::fmt::{self, Display, Formatter};
use netlink_sys::TokioSocket as Socket;
use std::collections::HashMap;

pub struct NetInfoNewLINK {
    pub ifname: String,
    pub if_index: u32,
    pub mac: MacAddr,
    pub flags: u32,
}

impl Display for NetInfoNewLINK {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NewLink {} {} {} {:2x}",
            self.ifname, self.if_index, self.mac, self.flags
        )
    }
}

pub struct NetInfoDelLINK {
    pub ifname: String,
    pub if_index: u32,
    pub flags: u32,
}

impl Display for NetInfoDelLINK {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DelLink {} {} {:2x}",
            self.ifname, self.if_index, self.flags
        )
    }
}

pub struct NetInfoNewAddress {
    pub ifname: String,
    pub if_index: u32,
    pub ipv4addr: Ipv4Entry,
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

pub struct NetInfoDelAddress {
    pub ifname: String,
    pub if_index: u32,
    pub ipv4addr: Ipv4Entry,
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

pub enum NetInfoMessage {
    NewLink(NetInfoNewLINK),
    DelLink(NetInfoDelLINK),
    NewAddress(NetInfoNewAddress),
    DelAddress(NetInfoDelAddress),
}

impl Display for NetInfoMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NetInfoMessage::NewLink(a) => write!(f, "{}", a),
            NetInfoMessage::DelLink(a) => write!(f, "{}", a),
            NetInfoMessage::NewAddress(a) => write!(f, "{}", a),
            NetInfoMessage::DelAddress(a) => write!(f, "{}", a),
        }
    }
}

pub struct NetInfo {
    socket: Socket,
    netif_hash: HashMap<String, NetIf>,
}
