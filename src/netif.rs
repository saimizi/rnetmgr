#[allow(unused)]
use netlink_packet_route::{
    rtnl, AddressHeader, AddressMessage, LinkHeader, LinkMessage, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, RtnlMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};

use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::SocketAddr;
use netlink_sys::TokioSocket as Socket;

#[allow(unused)]
use rtnl::address::nlas::Nla as AddrNla;

#[allow(unused)]
use rtnl::link::nlas::Nla as LinkNla;
use std::fmt::{self, Display, Formatter};
use std::net::Ipv4Addr;
use tokio::io::{Error, ErrorKind, Result};

use serde_derive::{Deserialize, Serialize};

#[allow(unused)]
use crate::{fdebug, ferror, finfo, ftrace, fwarn, NetIfConfig, NetIfConfigEntry};

#[derive(Serialize, Deserialize, Debug)]
pub struct MacAddr {
    pub addr: Vec<u8>,
}

impl Default for MacAddr {
    fn default() -> Self {
        MacAddr {
            addr: vec![0, 0, 0, 0, 0, 0, 0],
        }
    }
}

impl Clone for MacAddr {
    fn clone(&self) -> Self {
        MacAddr {
            addr: self.addr.clone(),
        }
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !self.addr.is_empty() {
            let mac_str = self
                .addr
                .iter()
                .map(|a| format!("{:02x}", a))
                .collect::<Vec<String>>()
                .join(":");

            write!(f, "{}", mac_str)
        } else {
            write!(f, "--:--:--:--:--:--")
        }
    }
}

impl PartialEq for MacAddr {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Ipv4Entry {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
}

impl Display for Ipv4Entry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix_len,)
    }
}

pub struct NetIf {
    ifname: String,
    ipv4: Vec<Ipv4Entry>,
    mac: MacAddr,
    flags: u32,
    if_index: u32,
}

impl PartialEq for NetIf {
    fn eq(&self, other: &Self) -> bool {
        if self.ifname != other.ifname {
            return false;
        }

        let ipv4_s = self
            .ipv4
            .iter()
            .map(|a| format!("{}", a))
            .collect::<Vec<String>>()
            .join(".");
        let ipv4_o = other
            .ipv4
            .iter()
            .map(|a| format!("{}", a))
            .collect::<Vec<String>>()
            .join(".");

        if ipv4_s != ipv4_o {
            return false;
        }

        if self.mac != other.mac {
            return false;
        }

        if self.if_index != other.if_index {
            return false;
        }

        true
    }
}

impl Eq for NetIf {}

impl Display for NetIf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut ipv4_str = self
            .ipv4
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join("/");

        if ipv4_str.is_empty() {
            ipv4_str = "None".to_string();
        }

        write!(
            f,
            "{} : {} {} {} [{}]",
            self.ifname,
            self.if_index,
            self.mac,
            ipv4_str,
            NetIf::state_flag_str(self.flags).join(" ")
        )
    }
}

impl NetIf {
    pub const NETIF_INVALID_IF_INDEX: u32 = u32::MAX;
    pub fn new(ifname: &str, if_index: u32, mac: MacAddr, flags: u32) -> Self {
        NetIf {
            ifname: ifname.to_string(),
            ipv4: Vec::<Ipv4Entry>::new(),
            mac,
            flags,
            if_index,
        }
    }

    pub fn is_valid(&self) -> bool {
        if self.ifname.is_empty() {
            return false;
        }

        if self.mac == MacAddr::default() {
            return false;
        }

        if self.if_index == NetIf::NETIF_INVALID_IF_INDEX {
            return false;
        }
        true
    }

    pub fn ifname(&self) -> String {
        self.ifname.clone()
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    #[allow(unused)]
    pub fn mac(&self) -> &MacAddr {
        &self.mac
    }

    #[allow(unused)]
    pub fn primary_ipv4addr(&self) -> Option<Ipv4Entry> {
        if !self.ipv4.is_empty() {
            Some(self.ipv4[0])
        } else {
            None
        }
    }

    pub fn state_flag_str(flags: u32) -> Vec<String> {
        let mut state = Vec::<String>::new();
        if flags & rtnl::constants::IFF_BROADCAST != 0 {
            state.push("BROADCAST".to_string());
        }

        if flags & rtnl::constants::IFF_MULTICAST != 0 {
            state.push("MULTICAST".to_string());
        }

        if flags & rtnl::constants::IFF_RUNNING != 0 {
            state.push("RUNNING".to_string());
        }

        if flags & rtnl::constants::IFF_RUNNING == 0 {
            state.push("STOPPED".to_string());
        }

        if flags & rtnl::constants::IFF_UP != 0 {
            state.push("UP".to_string());
        }

        if flags & rtnl::constants::IFF_UP == 0 {
            state.push("DOWN".to_string());
        }
        state
    }

    pub fn add_ipv4_addr(&mut self, ipaddr: &Ipv4Entry) {
        self.ipv4.push(*ipaddr);
    }

    pub fn del_ipv4_addr(&mut self, ipaddr: &Ipv4Entry) {
        self.ipv4.retain(|addr| addr != ipaddr);
    }

    #[allow(unused)]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub async fn set_netif_updown(&self, up: bool) -> Result<()> {
        if !self.is_valid() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid netif {}", self.ifname),
            ));
        }

        let mut flags = self.flags;
        if up {
            fdebug!("Set netif {} UP", self.ifname);
            flags |= rtnl::constants::IFF_UP;
        } else {
            fdebug!("Set netif {} DOWN", self.ifname);
            flags &= !rtnl::constants::IFF_UP;
        }

        if flags == self.flags {
            return Ok(());
        }

        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let addr = SocketAddr::new(0, 0);
        socket.bind(&addr)?;
        socket.connect(&SocketAddr::new(0, 0))?;

        let header = LinkHeader {
            interface_family: rtnl::constants::AF_INET as u8,
            index: self.if_index,
            flags,
            ..Default::default()
        };

        let mut packet = NetlinkMessage {
            header: NetlinkHeader::default(),
            payload: NetlinkPayload::from(RtnlMessage::SetLink(LinkMessage {
                header,
                nlas: vec![],
            })),
        };

        packet.header.flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST | NLM_F_ACK;
        packet.header.sequence_number = 1;
        packet.finalize();

        let mut buf: Vec<u8> = vec![0; packet.header.length as usize];
        assert!(buf.len() == packet.buffer_len());
        packet.serialize(&mut buf[..]);

        socket.send(&buf[..]).await?;

        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;

        'main: loop {
            let size = socket.recv(&mut receive_buffer[..]).await?;

            loop {
                let bytes = &receive_buffer[offset..];
                let rx_packet: NetlinkMessage<RtnlMessage> = NetlinkMessage::deserialize(bytes)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}", e)))?;

                match rx_packet.payload {
                    NetlinkPayload::Done => {
                        ftrace!("LINK Msge (UP/DOWN): Receive Packet process Done");
                        break 'main;
                    }

                    NetlinkPayload::Error(e) => {
                        return Err(Error::new(ErrorKind::Other, format!("Error: {}", e)));
                    }

                    NetlinkPayload::Ack(e) => {
                        finfo!("Link (UP/DOWN) ACK: {}", e);
                        break 'main;
                    }

                    _ => {
                        fdebug! {"Unknown message"}
                    }
                }

                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn set_ipv4_addr(&self, ipaddr: &Ipv4Entry) -> Result<()> {
        fdebug!("Set IPv4 addr {} for {}", ipaddr, self.ifname);
        if !self.is_valid() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid netif {}", self.ifname),
            ));
        }

        if self.ipv4.iter().any(|x| x == ipaddr) {
            return Ok(());
        }

        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let addr = SocketAddr::new(0, 0);
        socket.bind(&addr)?;
        socket.connect(&SocketAddr::new(0, 0))?;

        let header = AddressHeader {
            family: 2,
            prefix_len: ipaddr.prefix_len,
            index: self.if_index,
            ..Default::default()
        };

        let iparray: Vec<u8> = ipaddr
            .ip
            .to_string()
            .split('.')
            .map(|a| a.parse::<u8>().unwrap())
            .collect();

        let mut packet = NetlinkMessage {
            header: NetlinkHeader::default(),
            payload: NetlinkPayload::from(RtnlMessage::NewAddress(AddressMessage {
                header,
                nlas: vec![AddrNla::Local(iparray)],
            })),
        };

        packet.header.flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST | NLM_F_ACK;
        packet.header.sequence_number = 1;
        packet.finalize();

        let mut buf: Vec<u8> = vec![0; packet.header.length as usize];
        assert!(buf.len() == packet.buffer_len());
        packet.serialize(&mut buf[..]);

        socket.send(&buf[..]).await?;

        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;

        'main: loop {
            let size = socket.recv(&mut receive_buffer[..]).await?;

            loop {
                let bytes = &receive_buffer[offset..];
                let rx_packet: NetlinkMessage<RtnlMessage> = NetlinkMessage::deserialize(bytes)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}", e)))?;

                match rx_packet.payload {
                    NetlinkPayload::Done => {
                        ftrace!("NewAddress Receive Packet process Done");
                        break 'main;
                    }

                    NetlinkPayload::Error(e) => {
                        if let Some(17) = e.to_io().raw_os_error() {
                            fwarn!(
                                "Address {} has already been set for {}.",
                                ipaddr,
                                self.ifname
                            );
                            break 'main;
                        }
                        return Err(Error::new(ErrorKind::Other, format!("Error: {}", e)));
                    }

                    NetlinkPayload::Ack(e) => {
                        finfo!("NewAddress ACK: {}", e);
                        break 'main;
                    }

                    _ => {
                        fdebug! {"Unknown message"}
                    }
                }

                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
        }

        Ok(())
    }
}
