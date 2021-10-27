#[allow(unused)]
use netlink_packet_route::{
    rtnl, AddressMessage, LinkMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload, RtnlMessage,
    NLM_F_DUMP, NLM_F_REQUEST,
};

#[allow(unused)]
use rtnl::address::nlas::Nla as AddrNla;
#[allow(unused)]
use rtnl::link::nlas::Nla as LinkNla;

use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
use tokio::io::{Error, ErrorKind, Result};
use tokio::task::JoinHandle;

struct NetIf {
    ifname: String,
    ipv4: Vec<Ipv4Addr>,
    mac: Vec<u8>,
    flags: u32,
}

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

        let mut mac_str = self
            .mac
            .iter()
            .map(|a| format!("{:02x}", a))
            .collect::<Vec<String>>()
            .join(":");

        if mac_str.is_empty() {
            mac_str = "None".to_string();
        }

        write!(
            f,
            "ifname: {:20} mac: {:18} ipv4: {:20} [{}]",
            self.ifname,
            mac_str,
            ipv4_str,
            self.state_str(),
        )
    }
}

impl NetIf {
    fn add_ipv4_addr(&mut self, ipv4addr: Ipv4Addr) {
        self.ipv4.push(ipv4addr);
    }

    fn remove_ipv4_addr(&mut self, ipv4addr: &Ipv4Addr) {
        let mut addrs = vec![];

        for addr in &self.ipv4 {
            if addr != ipv4addr {
                addrs.push(addr.to_owned());
            }
        }
        self.ipv4 = addrs;
    }

    fn set_mac(&mut self, mac: Vec<u8>) {
        self.mac = mac;
    }

    fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    fn state_str(&self) -> String {
        let mut state = Vec::<String>::new();
        if (self.flags & rtnl::constants::IFF_BROADCAST) == rtnl::constants::IFF_BROADCAST {
            state.push("BROADCAST".to_string());
        }

        if (self.flags & rtnl::constants::IFF_MULTICAST) == rtnl::constants::IFF_MULTICAST {
            state.push("MULTICAST".to_string());
        }

        if (self.flags & rtnl::constants::IFF_RUNNING) == rtnl::constants::IFF_RUNNING {
            state.push("RUNNING".to_string());
        }

        if (self.flags & rtnl::constants::IFF_UP) == rtnl::constants::IFF_UP {
            state.push("UP".to_string());
        } else {
            state.push("DOWN".to_string());
        }

        state.join(" ")
    }
}

#[allow(unused)]
pub struct NetIfMon {
    socket: Socket,
    netif_hash: HashMap<String, NetIf>,
}

impl Display for NetIfMon {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for t in self.netif_hash.values() {
            writeln!(f, "{}", t.to_string())?
        }
        Ok(())
    }
}

impl NetIfMon {
    pub const RTMGRP_LINK: u32 = 0x1;
    pub const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    pub async fn start() -> Result<JoinHandle<Result<()>>> {
        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let addr = SocketAddr::new(0, NetIfMon::RTMGRP_LINK | NetIfMon::RTMGRP_IPV4_IFADDR);

        socket.bind(&addr).unwrap();
        socket.connect(&SocketAddr::new(0, 0))?;

        let netif_mon = NetIfMon {
            socket,
            netif_hash: HashMap::<String, NetIf>::new(),
        };

        let thread = tokio::spawn(async move { mon_thread(netif_mon).await });

        Ok(thread)
    }

    async fn update(&mut self) -> Result<()> {
        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;

        'main: loop {
            let size = self.socket.recv(&mut receive_buffer[..], 0)?;

            loop {
                let bytes = &receive_buffer[offset..];

                let rx_packet: NetlinkMessage<RtnlMessage> = NetlinkMessage::deserialize(bytes)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}", e)))?;

                match rx_packet.payload {
                    NetlinkPayload::Done => {
                        break 'main;
                    }
                    NetlinkPayload::Error(e) => {
                        eprint!("Error: {}", e);
                        break;
                    }
                    NetlinkPayload::InnerMessage(RtnlMessage::DelLink(lm)) => {
                        let mut ifname = String::new();

                        for nla in lm.nlas {
                            match nla {
                                rtnl::link::nlas::Nla::IfName(name) => {
                                    ifname = name;
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(nif) = self.netif_hash.remove(&ifname) {
                                println!("DEL_LINK: {}", nif);
                            }
                        }
                    }
                    NetlinkPayload::InnerMessage(RtnlMessage::NewLink(lm)) => {
                        let mut ifname = String::new();
                        let mut mac = Vec::<u8>::new();

                        for nla in lm.nlas {
                            match nla {
                                rtnl::link::nlas::Nla::IfName(name) => {
                                    ifname = name.clone();
                                }
                                rtnl::link::nlas::Nla::Address(addr) => {
                                    mac = addr.clone();
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(nif) = self.netif_hash.get_mut(&ifname) {
                                if !mac.is_empty() {
                                    nif.set_mac(mac);
                                }
                                nif.set_flags(lm.header.flags);
                                println!("UPDATE_LINK: {}", nif);
                            } else {
                                let nif = NetIf {
                                    ifname: ifname.clone(),
                                    ipv4: Vec::<Ipv4Addr>::new(),
                                    mac,
                                    flags: lm.header.flags,
                                };
                                println!("ADD_LINK: {}", nif);
                                self.netif_hash.insert(ifname, nif);
                            }
                        }
                    }
                    NetlinkPayload::InnerMessage(RtnlMessage::DelAddress(am)) => {
                        let mut ifname = String::new();
                        let mut ipv4: Option<Ipv4Addr> = None;

                        for nla in am.nlas {
                            match nla {
                                rtnl::address::nlas::Nla::Label(l) => {
                                    ifname = l.clone();
                                }
                                rtnl::address::nlas::Nla::Address(addr) => {
                                    let ipv4_addr = addr
                                        .iter()
                                        .map(|a| format! {"{}", a})
                                        .collect::<Vec<String>>()
                                        .join(".");
                                    if let Ok(a) = ipv4_addr.parse() {
                                        ipv4 = Some(a);
                                    }
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(ipv4addr) = ipv4 {
                                println!("DEL_ADDRESS: {} from {}", ipv4addr.to_string(), ifname);
                                if let Some(nif) = self.netif_hash.get_mut(&ifname) {
                                    nif.remove_ipv4_addr(&ipv4addr);
                                    println!("DEL_ADDRESS: {}", nif);
                                }
                            }
                        }
                    }

                    NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(am)) => {
                        let mut ifname = String::new();
                        let mut ipv4: Option<Ipv4Addr> = None;

                        for nla in am.nlas {
                            match nla {
                                rtnl::address::nlas::Nla::Label(l) => {
                                    ifname = l.clone();
                                }
                                rtnl::address::nlas::Nla::Address(addr) => {
                                    let ipv4_addr = addr
                                        .iter()
                                        .map(|a| format! {"{}", a})
                                        .collect::<Vec<String>>()
                                        .join(".");
                                    if let Ok(a) = ipv4_addr.parse() {
                                        ipv4 = Some(a);
                                    }
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(nif) = self.netif_hash.get_mut(&ifname) {
                                if let Some(addr) = ipv4 {
                                    nif.add_ipv4_addr(addr);
                                    println!("UPDATE_ADDRESS: {}", nif);
                                }
                            } else {
                                let nif = NetIf {
                                    ifname: ifname.clone(),
                                    ipv4: Vec::<Ipv4Addr>::new(),
                                    mac: Vec::<u8>::new(),
                                    flags: 0,
                                };
                                println!("ADD_ADDRESS: {}", nif);
                                self.netif_hash.insert(ifname.clone(), nif);
                            }
                        }
                    }
                    _ => {}
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

async fn mon_thread(mut netif_mon: NetIfMon) -> Result<()> {
    let mut packet = NetlinkMessage {
        header: NetlinkHeader::default(),
        payload: NetlinkPayload::from(RtnlMessage::GetLink(LinkMessage::default())),
    };
    packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    packet.header.sequence_number = 1;
    packet.finalize();

    let mut buf: Vec<u8> = vec![0; packet.header.length as usize];
    assert!(buf.len() == packet.buffer_len());
    packet.serialize(&mut buf[..]);

    netif_mon.socket.send(&buf[..], 0)?;

    if let Err(e) = netif_mon.update().await {
        eprintln!("Update error: {}", e);
    }

    let mut packet = NetlinkMessage {
        header: NetlinkHeader::default(),
        payload: NetlinkPayload::from(RtnlMessage::GetAddress(AddressMessage::default())),
    };
    packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    packet.header.sequence_number = 1;
    packet.finalize();

    let mut buf: Vec<u8> = vec![0; packet.header.length as usize];
    assert!(buf.len() == packet.buffer_len());
    packet.serialize(&mut buf[..]);

    netif_mon.socket.send(&buf[..], 0)?;
    if let Err(e) = netif_mon.update().await {
        eprintln!("Update error: {}", e);
    }

    loop {
        if let Err(e) = netif_mon.update().await {
            eprintln!("Update error: {}", e);
        }
    }
}
