#[allow(unused)]
use netlink_packet_route::{
    rtnl, AddressHeader, AddressMessage, LinkMessage, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, RtnlMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};

use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};
#[allow(unused)]
use rtnl::address::nlas::Nla as AddrNla;
#[allow(unused)]
use rtnl::link::nlas::Nla as LinkNla;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::thread;

use crate::{fdebug, ferror, finfo, ftrace, fwarn, NetIfConfig, NetIfConfigEntry};

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Ipv4Entry {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
}

impl Display for Ipv4Entry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix_len,)
    }
}

#[derive(PartialEq, Eq)]
enum NetIfType {
    EthernetDHCP,
    EthernetStaticIpv4(Ipv4Entry),
    Invalid,
}

impl Display for NetIfType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                NetIfType::EthernetDHCP => "Ethernet+DHCP",
                NetIfType::EthernetStaticIpv4(_) => "Ethernet+Static+Ipv4",
                NetIfType::Invalid => "Invalid",
            }
        )
    }
}

impl NetIfType {
    pub fn from(cfg: NetIfConfigEntry) -> NetIfType {
        let mut iftype = NetIfType::Invalid;

        if cfg.iftype == "Ethernet" {
            if cfg.addr_type == "Static" {
                if let Some(ipv4) = cfg.ipv4 {
                    let tmp: Vec<&str> = ipv4.split('/').collect();
                    let mut prefix_len: u8 = 24;

                    if tmp.len() > 1 {
                        if let Ok(l) = tmp[1].parse() {
                            if l > 32 {
                                return NetIfType::Invalid;
                            }
                            prefix_len = l;
                        } else {
                            return NetIfType::Invalid;
                        }
                    }

                    if let Ok(ip) = tmp[0].parse() {
                        iftype = NetIfType::EthernetStaticIpv4(Ipv4Entry { ip, prefix_len });
                    }
                }
            }

            if cfg.addr_type == "DHCP" {
                iftype = NetIfType::EthernetDHCP;
            }
        }

        iftype
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self, NetIfType::Invalid)
    }
}

pub struct NetIfRunTime {
    ipv4: Vec<Ipv4Entry>,
    mac: Vec<u8>,
    flags: u32,
    if_index: u32,
}

impl PartialEq for NetIfRunTime {
    fn eq(&self, other: &Self) -> bool {
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

        let mac_s = self
            .ipv4
            .iter()
            .map(|a| format!("{}", a))
            .collect::<Vec<String>>()
            .join(":");
        let mac_o = other
            .ipv4
            .iter()
            .map(|a| format!("{}", a))
            .collect::<Vec<String>>()
            .join(":");
        if mac_s != mac_o {
            return false;
        }

        if self.if_index != other.if_index {
            return false;
        }

        true
    }
}

impl Eq for NetIfRunTime {}

impl Display for NetIfRunTime {
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
            "IF_INDEX:{:2} MAC: {:18} IPV4: {:15} [{}]",
            self.if_index,
            mac_str,
            ipv4_str,
            NetIfRunTime::state_flag_str(self.flags).join(" ")
        )
    }
}

impl NetIfRunTime {
    pub fn new(if_index: u32, mac: Option<Vec<u8>>, flags: u32) -> NetIfRunTime {
        if let Some(mac) = mac {
            NetIfRunTime {
                ipv4: Vec::<Ipv4Entry>::new(),
                mac,
                flags,
                if_index,
            }
        } else {
            NetIfRunTime {
                ipv4: Vec::<Ipv4Entry>::new(),
                mac: Vec::<u8>::new(),
                flags,
                if_index,
            }
        }
    }

    pub fn ifindex(&self) -> u32 {
        self.if_index
    }

    pub fn del_ipv4_addr(&mut self, ipaddr: Ipv4Entry) {
        if self.ipv4.is_empty() {
            return;
        }

        let mut new = vec![];
        while let Some(addr) = self.ipv4.pop() {
            if addr != ipaddr {
                new.push(addr);
            }
        }

        self.ipv4 = new;
    }

    pub fn add_ipv4_addr(&mut self, ipaddr: Ipv4Entry) {
        self.ipv4.push(ipaddr);
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
}

#[derive(PartialEq, Eq)]
pub enum NetIfState {
    Init,
    Established,
}

impl Display for NetIfState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                NetIfState::Init => "Init".to_string(),
                NetIfState::Established => "Fini".to_string(),
            }
        )
    }
}

struct NetIf {
    ifname: String,
    iftype: NetIfType,
    state: NetIfState,
    runtime: Option<NetIfRunTime>,
}

impl Display for NetIf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IFNAME:{:4} TYPE: {:20} STATE: {:5} {}",
            self.ifname,
            self.iftype.to_string(),
            self.state.to_string(),
            match &self.runtime {
                Some(r) => r.to_string(),
                None => "None".to_string(),
            }
        )
    }
}

impl NetIf {
    pub fn ifname(&self) -> String {
        self.ifname.clone()
    }

    pub fn is_valid(&self) -> bool {
        self.iftype.is_valid()
    }

    pub fn set_runtime(&mut self, r: NetIfRunTime) -> Result<()> {
        if let Some(t) = &self.runtime {
            if *t != r {
                return Err(Error::new(ErrorKind::InvalidInput, "Invalid runtime"));
            }
        }

        self.runtime = Some(r);
        Ok(())
    }

    pub fn reset(&mut self) {
        self.runtime = None;
        self.state = NetIfState::Init;
    }

    pub fn is_established(&self) -> bool {
        self.state == NetIfState::Established
    }

    pub fn newlink_setup(&self) {
        fdebug!("Start to setup {}", self.ifname);
        match self.iftype {
            NetIfType::EthernetStaticIpv4(ipv4addr) => {
                if let Err(e) = self.set_ipv4_addr(ipv4addr) {
                    ferror!(
                        "Failed to set up {} with {} : {}",
                        self.ifname,
                        self.iftype.to_string(),
                        e
                    );
                }
            }
            _ => {
                ferror!(
                    "Interface type {} not is supported ({})",
                    self.iftype.to_string(),
                    self.ifname
                );
            }
        }
    }

    pub fn reg_ipv4_addr(&mut self, ipaddr: Ipv4Entry) {
        let r = match &mut self.runtime {
            Some(r) => r,
            None => return,
        };

        if self.state == NetIfState::Init {
            match self.iftype {
                NetIfType::EthernetDHCP => {
                    finfo!("{} established ({})", self.ifname, self.iftype);
                    self.state = NetIfState::Established;
                }
                NetIfType::EthernetStaticIpv4(addr) => {
                    if addr == ipaddr {
                        finfo!("{} established ({})", self.ifname, self.iftype);
                        self.state = NetIfState::Established;
                    }
                }
                _ => {}
            }
        }

        r.add_ipv4_addr(ipaddr);
    }

    pub fn unreg_ipv4_addr(&mut self, ipaddr: Ipv4Entry) {
        let mut reset_ip = false;
        let r = match &mut self.runtime {
            Some(r) => r,
            None => return,
        };

        if self.state == NetIfState::Established {
            if let NetIfType::EthernetStaticIpv4(addr) = self.iftype {
                if addr == ipaddr {
                    self.state = NetIfState::Init;
                    fwarn!(
                        "Static IP address {} for {} is removed, try to reset it",
                        addr.to_string(),
                        self.ifname
                    );

                    reset_ip = true;
                }
            }
        }

        r.del_ipv4_addr(ipaddr);

        if reset_ip {
            self.set_ipv4_addr(ipaddr).unwrap_or(());
        }
    }

    fn set_ipv4_addr(&self, ipaddr: Ipv4Entry) -> Result<()> {
        fdebug!("Set IPv4 addr {} for {}", ipaddr, self.ifname);
        let r = self
            .runtime
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Interface not created"))?;

        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let addr = SocketAddr::new(0, 0);
        socket.bind(&addr)?;
        socket.connect(&SocketAddr::new(0, 0))?;

        let header = AddressHeader {
            family: 2,
            prefix_len: ipaddr.prefix_len,
            index: r.ifindex(),
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

        socket.send(&buf[..], 0)?;

        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;

        'main: loop {
            let size = socket.recv(&mut receive_buffer[..], 0)?;

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
                            fwarn!("Address {} has already been set for {}.", ipaddr, self.ifname);
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

#[allow(unused)]
pub struct NetIfMon {
    socket: Socket,
    netif_hash: HashMap<String, NetIf>,
}

impl Display for NetIfMon {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for t in self.netif_hash.keys() {
            writeln!(f, "Monitoring {}", t)?
        }
        Ok(())
    }
}

impl NetIfMon {
    pub const RTMGRP_LINK: u32 = 0x1;
    pub const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    pub fn run(nifcfg: NetIfConfig) -> Result<()> {
        let mut netif_hash = HashMap::<String, NetIf>::new();
        for cfg in nifcfg.netifs {
            let netif = NetIf {
                ifname: cfg.ifname.clone(),
                iftype: NetIfType::from(cfg),
                state: NetIfState::Init,
                runtime: None,
            };

            if !netif.is_valid() {
                ferror!("Invalid configuration :{}", netif.ifname());
                std::process::exit(1);
            } else {
                fdebug!("{}", netif);
            }

            netif_hash.insert(netif.ifname(), netif);
        }

        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let addr = SocketAddr::new(0, NetIfMon::RTMGRP_LINK | NetIfMon::RTMGRP_IPV4_IFADDR);
        socket.bind(&addr).unwrap();
        socket.connect(&SocketAddr::new(0, 0))?;

        let handler =
            thread::spawn(move || -> Result<()> { mon_thread(NetIfMon { socket, netif_hash }) });

        if let Err(_e) = handler.join() {
            ferror!("Error!");
        }

        Ok(())
    }

    fn update(&mut self) -> Result<()> {
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
                        ftrace!("Packet process Done");
                        break 'main;
                    }
                    NetlinkPayload::Error(e) => {
                        ferror!("Error: {}", e);
                        return Err(Error::new(ErrorKind::Other, format!("Error: {}", e)));
                    }
                    NetlinkPayload::InnerMessage(RtnlMessage::DelLink(lm)) => {
                        let mut ifname = String::new();

                        for nla in lm.nlas {
                            if let rtnl::link::nlas::Nla::IfName(name) = nla {
                                ifname = name;
                            }
                        }

                        if !ifname.is_empty() {
                            ftrace!("DelLink: {}", ifname);
                            if let Some(n) = self.netif_hash.get_mut(&ifname) {
                                n.reset();
                                fwarn!("{} link disconnected.", n.ifname());
                            }
                        }
                    }

                    NetlinkPayload::InnerMessage(RtnlMessage::NewLink(lm)) => {
                        let mut ifname = String::new();
                        let mut mac: Option<Vec<u8>> = None;
                        let flags = lm.header.flags;
                        let if_index = lm.header.index;

                        for nla in lm.nlas {
                            match nla {
                                rtnl::link::nlas::Nla::IfName(name) => {
                                    ifname = name.clone();
                                }
                                rtnl::link::nlas::Nla::Address(addr) => {
                                    mac = Some(addr);
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            ftrace!("NewLink: {}", ifname);
                            if let Some(n) = self.netif_hash.get_mut(&ifname) {
                                /* This may only update flags for established interface */
                                n.set_runtime(NetIfRunTime::new(if_index, mac, flags))?;
                                if !n.is_established() {
                                    fdebug!("{}", n);
                                    n.newlink_setup();
                                }
                            }
                        }
                    }
                    NetlinkPayload::InnerMessage(RtnlMessage::DelAddress(am)) => {
                        let mut ifname = String::new();
                        let mut ipaddr: Option<Ipv4Entry> = None;

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
                                    if let Ok(ip) = ipv4_addr.parse() {
                                        let prefix_len = am.header.prefix_len;
                                        ipaddr = Some(Ipv4Entry { ip, prefix_len });
                                    }
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(addr) = ipaddr {
                                ftrace!("{} Del address {}", ifname, addr);
                                if let Some(n) = self.netif_hash.get_mut(&ifname) {
                                    n.unreg_ipv4_addr(addr);
                                }
                            }
                        }
                    }

                    NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(am)) => {
                        let mut ifname = String::new();
                        let mut ipaddr: Option<Ipv4Entry> = None;

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
                                    if let Ok(ip) = ipv4_addr.parse() {
                                        let prefix_len = am.header.prefix_len;
                                        ipaddr = Some(Ipv4Entry { ip, prefix_len });
                                    }
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(addr) = ipaddr {
                                ftrace!("{} New address {}", ifname, addr);
                                if let Some(n) = self.netif_hash.get_mut(&ifname) {
                                    n.reg_ipv4_addr(addr);
                                }
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

fn mon_thread(mut netif_mon: NetIfMon) -> Result<()> {
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

    netif_mon.update().unwrap();

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
    netif_mon.update().unwrap();

    loop {
        netif_mon.update().unwrap();
    }
}
