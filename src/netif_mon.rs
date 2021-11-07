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
    AddLink(u32),
    DelLink,
    AddMac(Vec<u8>),
    AddIpv4Addr(Ipv4Addr),
    DelIpv4Addr(Ipv4Addr),
}

impl NetIfEvent {
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

enum NetIfType {
    EthernetDHCP,
    EthernetStaticIpv4(Ipv4Addr),
    Invalid,
}

pub trait NetIfOp {
    fn ifname(&self) -> String;
    fn handle_event(&mut self, rx: &mut Receiver<NetIfEvent>) -> Result<()>;
    fn run(
        mut tgt: impl NetIfOp + Send + 'static,
        mut rx: Receiver<NetIfEvent>,
    ) -> JoinHandle<Result<()>> {
        thread::spawn(move || -> Result<()> {
            println!("Start thread for {}", tgt.ifname());
            loop {
                tgt.handle_event(&mut rx)?;
            }
        })
    }
}

pub struct NetIfSetting {
    #[allow(unused)]
    iftype: NetIfType,
}

impl NetIfSetting {
    pub fn from(cfg: NetIfConfigEntry) -> Result<NetIfSetting> {
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

        if !matches!(iftype, NetIfType::Invalid) {
            Ok(NetIfSetting { iftype })
        } else {
            Err(Error::new(ErrorKind::InvalidData, "Invalid config data"))
        }
    }

    #[allow(unused)]
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
    #[allow(unused)]
    setting: NetIfSetting,
    runtime: Option<NetIfRunTime>,
}

impl Display for NetIf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(runtime) = &self.runtime {
            let mut ipv4_str = runtime
                .ipv4
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<String>>()
                .join("/");

            if ipv4_str.is_empty() {
                ipv4_str = "None".to_string();
            }

            let mut mac_str = runtime
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
                NetIfEvent::state_flag_str(runtime.flags).join(" ")
            )
        } else {
            write!(
                f,
                "ifname: {:20} mac: {:18} ipv4: {:20} []",
                self.ifname, "None", "None",
            )
        }
    }
}

impl NetIfOp for NetIf {
    fn ifname(&self) -> String {
        self.ifname.clone()
    }

    fn handle_event(&mut self, rx: &mut Receiver<NetIfEvent>) -> Result<()> {
        let ne = rx.recv();
        match ne {
            Ok(NetIfEvent::AddLink(flags)) => {
                if let Some(runtime) = &mut self.runtime {
                    let state_new = NetIfEvent::state_flag_str(flags);
                    let state_old = NetIfEvent::state_flag_str(runtime.flags);
                    let mut state_changed = vec![];

                    for flag in state_new.into_iter() {
                        if !state_old.iter().any(|a| *a == flag) {
                            state_changed.push(flag);
                        }
                    }

                    println!(
                        "{} State changed: [{}]",
                        self.ifname,
                        state_changed.join(" ")
                    );
                    runtime.flags = flags;
                } else {
                    self.runtime = Some(NetIfRunTime {
                        ipv4: vec![],
                        mac: vec![],
                        flags,
                    });
                    println!(
                        "{}: added State: [{}]",
                        self.ifname(),
                        NetIfEvent::state_flag_str(flags).join(" ")
                    );
                }
            }
            Ok(NetIfEvent::DelLink) => {
                if self.runtime.is_some() {
                    println!("{}: deleted", self.ifname());
                    self.runtime = None;
                }
            }
            Ok(NetIfEvent::AddIpv4Addr(addr)) => {
                if let Some(runtime) = &mut self.runtime {
                    if !runtime.ipv4.iter().any(|a| *a == addr) {
                        println!("{}:  addr {} is added", self.ifname, addr.to_string());
                        runtime.ipv4.push(addr);
                    }
                } else {
                    return Err(Error::new(
                        ErrorKind::NotFound,
                        format!("AddIpv4Addr: Link {} not created.", self.ifname),
                    ));
                }
            }
            Ok(NetIfEvent::DelIpv4Addr(addr)) => {
                if let Some(runtime) = &mut self.runtime {
                    let mut addrs = vec![];

                    for a in &runtime.ipv4 {
                        if a != &addr {
                            addrs.push(addr.to_owned());
                        } else {
                            println!("{}: addr {} is deleted", self.ifname, addr.to_string());
                        }
                    }
                    runtime.ipv4 = addrs;
                } else {
                    return Err(Error::new(
                        ErrorKind::NotFound,
                        format!("DelIpv4Addr: Link {} not created.", self.ifname),
                    ));
                }
            }
            Ok(NetIfEvent::AddMac(mac)) => {
                if let Some(runtime) = &mut self.runtime {
                    if mac != runtime.mac {
                        println!(
                            "{} mac addr {}",
                            self.ifname,
                            mac.iter()
                                .map(|a| format!("{:02x}", a))
                                .collect::<Vec<String>>()
                                .join(":")
                        );
                        runtime.mac = mac;
                    }
                } else {
                    return Err(Error::new(
                        ErrorKind::NotFound,
                        format!("AddMac: Link {} not created.", self.ifname),
                    ));
                }
            }
            Err(_e) => {
                return Err(Error::new(ErrorKind::Other, "Closed"));
            }
        }

        Ok(())
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
            let (tx, rx) = mpsc::channel();
            let ifname = cfg.ifname.clone();
            netif_hash.insert(ifname.clone(), tx);

            handlers.push(NetIf::run(
                NetIf {
                    ifname,
                    setting: NetIfSetting::from(cfg)?,
                    runtime: None,
                },
                rx,
            ));
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
                        let mut nie = vec![NetIfEvent::AddLink(lm.header.flags)];

                        for nla in lm.nlas {
                            match nla {
                                rtnl::link::nlas::Nla::IfName(name) => {
                                    ifname = name.clone();
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
