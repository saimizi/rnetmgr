#[allow(unused)]
use netlink_packet_route::{
    rtnl, AddressMessage, LinkMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload, RtnlMessage,
    NLM_F_DUMP, NLM_F_REQUEST,
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
use std::sync::mpsc::{self, Receiver, Sender};
#[allow(unused)]
use std::thread::{self, JoinHandle};

use crate::{NetIfConfig, NetIfConfigEntry};

#[derive(Debug)]
pub enum NetIfEvent {
    AddLink,
    DelLink,
    StateFlag(u32),
    AddMac(Vec<u8>),
    AddIpv4Addr(Ipv4Addr),
    DelIpv4Addr(Ipv4Addr),
}

enum NetIfType {
    EthernetDHCP,
    EthernetStaticIpv4(Ipv4Addr),
    Invalid,
}

pub trait NetIfOp {
    fn ifname(&self) -> String;
    fn handle_event(&mut self, rx: &mut Receiver<NetIfEvent>) -> Result<()>;
}

pub struct NetIfSetting {
    iftype: NetIfType,
}

impl NetIfSetting {
    pub fn from(cfg: NetIfConfigEntry) -> NetIfSetting {
        let mut iftype = NetIfType::Invalid;

        if cfg.iftype == "Ethernet" {
            if cfg.addr_type == "Static" {
                if let Some(ipv4) = cfg.ipv4 {
                    if let Ok(ipv4) = ipv4.parse() {
                        iftype = NetIfType::EthernetStaticIpv4(ipv4);
                    }
                }
            }

            if cfg.addr_type == "DHCP" {
                iftype = NetIfType::EthernetDHCP;
            }
        }

        NetIfSetting { iftype }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self.iftype, NetIfType::Invalid)
    }
}

pub struct NetIfRunTime {
    ipv4: Vec<Ipv4Addr>,
    mac: Vec<u8>,
    flags: u32,
}

struct NetIf {
    ifname: String,
    setting: NetIfSetting,
    runtime: NetIfRunTime,
}

impl Display for NetIf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut ipv4_str = self
            .runtime
            .ipv4
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join("/");

        if ipv4_str.is_empty() {
            ipv4_str = "None".to_string();
        }

        let mut mac_str = self
            .runtime
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

impl NetIfOp for NetIf {
    fn ifname(&self) -> String {
        self.ifname.clone()
    }

    fn handle_event(&mut self, rx: &mut Receiver<NetIfEvent>) -> Result<()> {
        println!("Wait!!!");
        let ne = rx.recv();
        println!("received event!!!");
        match ne {
            Ok(NetIfEvent::AddLink) => {
                println!("{} added", self.ifname());
            }
            Ok(NetIfEvent::DelLink) => {
                println!("{} deleted", self.ifname());
            }
            Ok(NetIfEvent::StateFlag(flags)) => {
                let mut state = Vec::<String>::new();
                if (flags & rtnl::constants::IFF_BROADCAST != 0)
                    && (self.runtime.flags & rtnl::constants::IFF_BROADCAST == 0)
                {
                    state.push("BROADCAST".to_string());
                }

                if (flags & rtnl::constants::IFF_MULTICAST != 0)
                    && (self.runtime.flags & rtnl::constants::IFF_MULTICAST == 0)
                {
                    state.push("MULTICAST".to_string());
                }

                if (flags & rtnl::constants::IFF_RUNNING != 0)
                    && (self.runtime.flags & rtnl::constants::IFF_RUNNING == 0)
                {
                    state.push("RUNNING".to_string());
                }

                if (flags & rtnl::constants::IFF_RUNNING == 0)
                    && (self.runtime.flags & rtnl::constants::IFF_RUNNING != 0)
                {
                    state.push("STOPPED".to_string());
                }

                if (flags & rtnl::constants::IFF_UP != 0)
                    && (self.runtime.flags & rtnl::constants::IFF_UP == 0)
                {
                    state.push("UP".to_string());
                }

                if (flags & rtnl::constants::IFF_UP == 0)
                    && (self.runtime.flags & rtnl::constants::IFF_UP != 0)
                {
                    state.push("DOWN".to_string());
                }

                println!("{} State changed: [{}]", self.ifname(), state.join(" "));
                self.set_flags(flags);
            }
            Ok(NetIfEvent::AddIpv4Addr(addr)) => {
                println!("{} add addr {}", self.ifname(), addr.to_string());
                self.add_ipv4_addr(&addr);
            }
            Ok(NetIfEvent::DelIpv4Addr(addr)) => {
                println!("{} del addr {}", self.ifname(), addr.to_string());
                self.remove_ipv4_addr(&addr);
            }
            Ok(NetIfEvent::AddMac(mac)) => {
                if mac != self.runtime.mac {
                    println!(
                        "{} mac addr {}",
                        self.ifname(),
                        mac.iter()
                            .map(|a| format!("{:02x}", a))
                            .collect::<Vec<String>>()
                            .join(":")
                    );
                    self.set_mac(mac);
                }
            }
            Err(_e) => {
                return Err(Error::new(ErrorKind::Other, "Closed"));
            }
        }
        Ok(())
    }
}

impl NetIf {
    fn add_ipv4_addr(&mut self, ipv4addr: &Ipv4Addr) {
        self.runtime.ipv4.push(*ipv4addr);
    }

    fn remove_ipv4_addr(&mut self, ipv4addr: &Ipv4Addr) {
        let mut addrs = vec![];

        for addr in &self.runtime.ipv4 {
            if addr != ipv4addr {
                addrs.push(addr.to_owned());
            }
        }
        self.runtime.ipv4 = addrs;
    }

    fn set_mac(&mut self, mac: Vec<u8>) {
        self.runtime.mac = mac;
    }

    fn set_flags(&mut self, flags: u32) {
        self.runtime.flags = flags;
    }

    fn state_str(&self) -> String {
        let mut state = Vec::<String>::new();
        if (self.runtime.flags & rtnl::constants::IFF_BROADCAST) == rtnl::constants::IFF_BROADCAST {
            state.push("BROADCAST".to_string());
        }

        if (self.runtime.flags & rtnl::constants::IFF_MULTICAST) == rtnl::constants::IFF_MULTICAST {
            state.push("MULTICAST".to_string());
        }

        if (self.runtime.flags & rtnl::constants::IFF_RUNNING) == rtnl::constants::IFF_RUNNING {
            state.push("RUNNING".to_string());
        }

        if (self.runtime.flags & rtnl::constants::IFF_UP) == rtnl::constants::IFF_UP {
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
    netif_hash: HashMap<String, Sender<NetIfEvent>>,
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
        let mut netif_hash = HashMap::<String, Sender<NetIfEvent>>::new();
        let mut handlers = vec![];

        for cfg in nifcfg.netifs {
            let (tx, mut rx) = mpsc::channel();
            let ifname = cfg.ifname.clone();
            netif_hash.insert(ifname.clone(), tx);
            let setting = NetIfSetting::from(cfg);
            if !setting.is_valid() {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid cfg data"));
            }

            let mut nif = NetIf {
                ifname,
                setting,
                runtime: NetIfRunTime {
                    ipv4: Vec::<Ipv4Addr>::new(),
                    mac: Vec::<u8>::new(),
                    flags: 0,
                },
            };

            handlers.push(thread::spawn(move || -> Result<()> {
                println!("Start thread for {}", nif.ifname());
                loop {
                    nif.handle_event(&mut rx)?;
                }
            }))
        }

        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let addr = SocketAddr::new(0, NetIfMon::RTMGRP_LINK | NetIfMon::RTMGRP_IPV4_IFADDR);
        socket.bind(&addr).unwrap();
        socket.connect(&SocketAddr::new(0, 0))?;

        handlers.push(thread::spawn(move || -> Result<()> {
            mon_thread(NetIfMon { socket, netif_hash })
        }));

        for t in handlers {
            if let Err(_e) = t.join() {
                eprintln!("Error!");
            }
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
                        break 'main;
                    }
                    NetlinkPayload::Error(e) => {
                        eprint!("Error: {}", e);
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
                            if let Some(s) = self.netif_hash.get_mut(&ifname) {
                                if let Err(e) = s.send(NetIfEvent::DelLink) {
                                    panic!("Send error: {}", e);
                                } else {
                                    println!("Send successed. close");
                                }
                            }
                        }
                    }
                    NetlinkPayload::InnerMessage(RtnlMessage::NewLink(lm)) => {
                        let mut ifname = String::new();
                        let mut nie = vec![NetIfEvent::StateFlag(lm.header.flags)];

                        for nla in lm.nlas {
                            match nla {
                                rtnl::link::nlas::Nla::IfName(name) => {
                                    ifname = name.clone();
                                    nie.push(NetIfEvent::AddLink);
                                }
                                rtnl::link::nlas::Nla::Address(addr) => {
                                    nie.push(NetIfEvent::AddMac(addr));
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(s) = self.netif_hash.get_mut(&ifname) {
                                for n in nie {
                                    print!("Send AddLINK: {} ... ", ifname);
                                    s.send(n)
                                        .map_err(|_e| Error::new(ErrorKind::Other, "IF closed"))?;
                                    println!("Sent");
                                }
                            }
                        }
                    }
                    NetlinkPayload::InnerMessage(RtnlMessage::DelAddress(am)) => {
                        let mut ifname = String::new();
                        let mut nie = Vec::<NetIfEvent>::new();

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
                                        nie.push(NetIfEvent::DelIpv4Addr(a));
                                    }
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(s) = self.netif_hash.get_mut(&ifname) {
                                for n in nie {
                                    s.send(n)
                                        .map_err(|_e| Error::new(ErrorKind::Other, "IF closed"))?;
                                }
                            }
                        }
                    }

                    NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(am)) => {
                        let mut ifname = String::new();
                        let mut nie = Vec::<NetIfEvent>::new();

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
                                        nie.push(NetIfEvent::AddIpv4Addr(a));
                                    }
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            if let Some(s) = self.netif_hash.get_mut(&ifname) {
                                for n in nie {
                                    s.send(n)
                                        .map_err(|_e| Error::new(ErrorKind::Other, "IF closed"))?;
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
