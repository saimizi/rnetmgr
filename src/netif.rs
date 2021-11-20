#[allow(unused)]
use netlink_packet_route::{
    rtnl, AddressHeader, AddressMessage, LinkMessage, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, RtnlMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};

use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::SocketAddr;
use netlink_sys::TokioSocket as Socket;
#[allow(unused)]
use rtnl::address::nlas::Nla as AddrNla;
#[allow(unused)]
use rtnl::link::nlas::Nla as LinkNla;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::net::Ipv4Addr;
use tokio::{
    io::{Error, ErrorKind, Result},
    sync::mpsc,
    task,
};

use crate::{fdebug, ferror, finfo, ftrace, fwarn, NetIfConfig, NetIfConfigEntry};

pub struct MacAddr {
    addr: Vec<u8>,
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

struct NetInfoNewLINK {
    ifname: String,
    if_index: u32,
    mac: MacAddr,
    flags: u32,
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

struct NetInfoDelLINK {
    ifname: String,
    if_index: u32,
    flags: u32,
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

struct NetInfoNewAddress {
    ifname: String,
    if_index: u32,
    ipv4addr: Ipv4Entry,
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

struct NetInfoDelAddress {
    ifname: String,
    if_index: u32,
    ipv4addr: Ipv4Entry,
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

enum NetInfoMessage {
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
    mac: MacAddr,
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

        if self.mac != other.mac {
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

        write!(
            f,
            "IF_INDEX:{:2} MAC: {:18} IPV4: {:15} [{}]",
            self.if_index,
            self.mac,
            ipv4_str,
            NetIfRunTime::state_flag_str(self.flags).join(" ")
        )
    }
}

impl NetIfRunTime {
    pub fn new(if_index: u32, mac: MacAddr, flags: u32) -> NetIfRunTime {
        NetIfRunTime {
            ipv4: Vec::<Ipv4Entry>::new(),
            mac,
            flags,
            if_index,
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

    pub async fn newlink_setup(&self) {
        fdebug!("Start to setup {}", self.ifname);
        match self.iftype {
            NetIfType::EthernetStaticIpv4(ipv4addr) => {
                if let Err(e) = self.set_ipv4_addr(ipv4addr).await {
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

    pub async fn unreg_ipv4_addr(&mut self, ipaddr: Ipv4Entry) {
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
            if let Err(e) = self.set_ipv4_addr(ipaddr).await {
                fwarn!("failed to reset ipaddr: {}", e);
            }
        }
    }

    async fn set_ipv4_addr(&self, ipaddr: Ipv4Entry) -> Result<()> {
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
    pub async fn run(nifcfg: NetIfConfig) -> Result<()> {
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

        let mut handlers = vec![];
        let (s, r) = mpsc::channel(100);
        handlers.push(task::spawn(async move {
            mon_thread(NetIfMon { socket, netif_hash }, s).await
        }));

        handlers.push(task::spawn(async move { info_thread(r).await }));

        for handler in handlers {
            if let Err(_e) = handler.await {
                ferror!("Error!");
            }
        }

        Ok(())
    }

    async fn update(&mut self, s: &mut mpsc::Sender<Box<NetInfoMessage>>) -> Result<()> {
        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;

        'main: loop {
            let size = self.socket.recv(&mut receive_buffer[..]).await?;

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
                            s.send(Box::new(NetInfoMessage::DelLink(NetInfoDelLINK {
                                ifname: ifname.clone(),
                                if_index: lm.header.index,
                                flags: lm.header.flags,
                            })))
                            .await
                            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}", e)))?;
                            if let Some(n) = self.netif_hash.get_mut(&ifname) {
                                n.reset();
                                fwarn!("{} link disconnected.", n.ifname());
                            }
                        }
                    }

                    NetlinkPayload::InnerMessage(RtnlMessage::NewLink(lm)) => {
                        let mut ifname = String::new();
                        let mut mac = MacAddr { addr: vec![] };
                        let flags = lm.header.flags;
                        let if_index = lm.header.index;

                        for nla in lm.nlas {
                            match nla {
                                rtnl::link::nlas::Nla::IfName(name) => {
                                    ifname = name.clone();
                                }
                                rtnl::link::nlas::Nla::Address(addr) => {
                                    mac = MacAddr { addr };
                                }
                                _ => {}
                            }
                        }

                        if !ifname.is_empty() {
                            s.send(Box::new(NetInfoMessage::NewLink(NetInfoNewLINK {
                                ifname: ifname.clone(),
                                if_index: lm.header.index,
                                mac: mac.clone(),
                                flags: lm.header.flags,
                            })))
                            .await
                            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}", e)))?;

                            if let Some(n) = self.netif_hash.get_mut(&ifname) {
                                /* This may only update flags for established interface */
                                n.set_runtime(NetIfRunTime::new(if_index, mac, flags))?;
                                if !n.is_established() {
                                    n.newlink_setup().await;
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
                                s.send(Box::new(NetInfoMessage::DelAddress(NetInfoDelAddress {
                                    ifname: ifname.clone(),
                                    if_index: am.header.index,
                                    ipv4addr: addr,
                                })))
                                .await
                                .map_err(|e| {
                                    Error::new(ErrorKind::InvalidData, format!("{}", e))
                                })?;
                                if let Some(n) = self.netif_hash.get_mut(&ifname) {
                                    n.unreg_ipv4_addr(addr).await;
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
                                s.send(Box::new(NetInfoMessage::NewAddress(NetInfoNewAddress {
                                    ifname: ifname.clone(),
                                    if_index: am.header.index,
                                    ipv4addr: addr,
                                })))
                                .await
                                .map_err(|e| {
                                    Error::new(ErrorKind::InvalidData, format!("{}", e))
                                })?;
                                if let Some(n) = self.netif_hash.get_mut(&ifname) {
                                    n.reg_ipv4_addr(addr);
                                }
                            }
                        }
                    }
                    _ => {
                        fdebug!("Unexpectd msg");
                    }
                }

                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
        }
        ftrace!("Out");
        Ok(())
    }
}

async fn mon_thread(
    mut netif_mon: NetIfMon,
    mut s: mpsc::Sender<Box<NetInfoMessage>>,
) -> Result<()> {
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

    netif_mon.socket.send(&buf[..]).await?;
    ftrace!("Send GetLink Message");
    netif_mon.update(&mut s).await.unwrap();

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

    netif_mon.socket.send(&buf[..]).await?;
    ftrace!("Send GetAddress Message");
    netif_mon.update(&mut s).await.unwrap();

    loop {
        ftrace!("Do update");
        netif_mon.update(&mut s).await.unwrap();
    }
}

async fn info_thread(mut r: mpsc::Receiver<Box<NetInfoMessage>>) -> Result<()> {
    while let Some(msg) = r.recv().await {
        finfo!("{}", msg);
    }

    Ok(())
}
