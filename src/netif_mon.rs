use crate::netif::{Ipv4Entry, MacAddr, NetIf};
#[allow(unused)]
use crate::netinfo::{
    NetInfoDelAddress, NetInfoDelLink, NetInfoMessage, NetInfoNewAddress, NetInfoNewLink,
    NetInfoReqMessage,
};
#[allow(unused)]
use crate::{fdebug, ferror, finfo, ftrace, fwarn, NetIfConfig, NetIfConfigEntry};

#[allow(unused)]
use netlink_packet_route::{
    rtnl, AddressHeader, AddressMessage, LinkHeader, LinkMessage, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, RtnlMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_sys::TokioSocket as Socket;
use netlink_sys::{protocols::NETLINK_ROUTE, SocketAddr};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use tokio::{
    io::{Error, ErrorKind, Result},
    sync::mpsc::{self, Receiver, Sender},
    task,
};

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
    pub fn from(cfg: &NetIfConfigEntry) -> NetIfType {
        let mut iftype = NetIfType::Invalid;

        if cfg.iftype == "Ethernet" {
            if cfg.addr_type == "Static" {
                if let Some(ipv4) = &cfg.ipv4 {
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

pub struct NetIfMon {
    netif_hash: HashMap<String, NetIf>,
    netiftype_hash: HashMap<String, NetIfType>,
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
        let mut netiftype_hash = HashMap::<String, NetIfType>::new();

        for cfg in nifcfg.netifs {
            let netif_type = NetIfType::from(&cfg);
            if !netif_type.is_valid() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid netif type for {}", cfg.ifname),
                ));
            }
            netiftype_hash.insert(cfg.ifname.clone(), netif_type);
        }

        let mut handlers = vec![];

        handlers.push(task::spawn(async move {
            mon_thread(NetIfMon {
                netif_hash: HashMap::<String, NetIf>::new(),
                netiftype_hash,
            })
            .await
        }));

        for handler in handlers {
            if let Err(_e) = handler.await {
                ferror!("Error!");
            }
        }

        Ok(())
    }

    async fn update(
        &mut self,
        buf: Vec<u8>,
        size: usize,
        mut sender: Option<&mut Sender<NetInfoMessage>>,
    ) -> Result<bool> {
        let mut offset = 0;

        loop {
            let bytes = &buf[offset..];

            let rx_packet: NetlinkMessage<RtnlMessage> = NetlinkMessage::deserialize(bytes)
                .map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}", e)))?;

            match rx_packet.payload {
                NetlinkPayload::Done => {
                    return Ok(true);
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
                        let msg = NetInfoMessage::DelLink(NetInfoDelLink {
                            ifname: ifname.clone(),
                            if_index: lm.header.index,
                            flags: lm.header.flags,
                        });

                        fdebug!("{}", msg);

                        if let Some(s) = &mut sender {
                            if let Err(e) = s.send(msg).await {
                                ferror!("MPSC send error: {}", e);
                            }
                        }

                        self.netif_hash.retain(|k, _v| k != &ifname);
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
                        let msg = NetInfoMessage::NewLink(NetInfoNewLink {
                            ifname: ifname.clone(),
                            if_index: lm.header.index,
                            mac: mac.clone(),
                            flags: lm.header.flags,
                        });

                        fdebug!("{}", msg);

                        if let Some(s) = &mut sender {
                            if let Err(e) = s.send(msg).await {
                                ferror!("MPSC send error: {}", e);
                            }
                        }

                        let netif = self
                            .netif_hash
                            .entry(ifname.clone())
                            .and_modify(|n| {
                                assert_eq!(mac, *n.mac());
                                assert_eq!(if_index, n.if_index());
                                n.update_flags(flags);
                            })
                            .or_insert_with(|| NetIf::new(&ifname, if_index, mac, flags));

                        if let Some(NetIfType::EthernetStaticIpv4(addr)) =
                            self.netiftype_hash.get(&ifname)
                        {
                            /*
                             * set_ipv4_addr() will return Ok(()) directly if the ip
                             * address has been set
                             */
                            if let Err(e) = netif.set_ipv4_addr(addr).await {
                                ferror!("Failed to set ip address {} to {}: {}", addr, ifname, e);
                            } else if let Err(e) = netif.set_netif_updown(true).await {
                                ferror!("Failed to set {} UP: {}", ifname, e);
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
                            let n = self
                                .netif_hash
                                .entry(ifname.clone())
                                .and_modify(|e| e.del_ipv4_addr(&addr))
                                .or_default();

                            if !n.is_valid() {
                                return Err(Error::new(
                                    ErrorKind::Other,
                                    format!("DelAddress: netif {} is not found.", ifname),
                                ));
                            }

                            let msg = NetInfoMessage::DelAddress(NetInfoDelAddress {
                                ifname: ifname.clone(),
                                if_index: n.if_index(),
                                ipv4addr: addr,
                            });

                            fdebug!("{}", msg);

                            if let Some(s) = &mut sender {
                                if let Err(e) = s.send(msg).await {
                                    ferror!("MPSC send error: {}", e);
                                }
                            }

                            if let Some(NetIfType::EthernetStaticIpv4(addr_s)) =
                                self.netiftype_hash.get(&ifname)
                            {
                                if addr_s == &addr {
                                    fwarn!("{} is removed from {}, try to reset it.", addr, ifname);

                                    let netif = self.netif_hash.get_mut(&ifname).unwrap();
                                    /*
                                     * set_ipv4_addr() will return Ok(()) directly if the ip
                                     * address has been set
                                     */
                                    if let Err(e) = netif.set_ipv4_addr(&addr).await {
                                        ferror!(
                                            "Failed to set ip address {} to {}: {}",
                                            addr,
                                            ifname,
                                            e
                                        );
                                    } else if let Err(e) = netif.set_netif_updown(true).await {
                                        ferror!("Failed to set {} UP: {}", ifname, e);
                                    }
                                }
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
                            let n = self
                                .netif_hash
                                .entry(ifname.clone())
                                .and_modify(|n| n.add_ipv4_addr(&addr))
                                .or_default();

                            if !n.is_valid() {
                                return Err(Error::new(
                                    ErrorKind::Other,
                                    format!("NewAddress: netif {} is not found.", ifname),
                                ));
                            }

                            let msg = NetInfoMessage::NewAddress(NetInfoNewAddress {
                                ifname: ifname.clone(),
                                if_index: n.if_index(),
                                ipv4addr: addr,
                            });

                            fdebug!("{}", msg);

                            if let Some(s) = &mut sender {
                                if let Err(e) = s.send(msg).await {
                                    ferror!("MPSC send error: {}", e);
                                }
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
                break;
            }
        }
        Ok(false)
    }

    async fn recv_netlink_msg(socket: &mut Socket) -> Result<(Vec<u8>, usize)> {
        let mut buf = vec![0; 4096];
        let size = socket.recv(buf.as_mut()).await?;
        Ok((buf, size))
    }

    async fn monitor(
        &mut self,
        socket: &mut Socket,
        mut s: Sender<NetInfoMessage>,
        mut r: Receiver<NetInfoMessage>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                Ok((buf, size)) =  NetIfMon::recv_netlink_msg(socket) => {
                    if let Err(e) = self.update(buf, size, Some(&mut s)).await {
                        ferror!("{}", e);
                    }
                }
                Some(m)= r.recv() => {
                    finfo!("{}",m);
                }
            }
        }
    }

}

async fn mon_thread(mut netif_mon: NetIfMon) -> Result<()> {
    let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
    let addr = SocketAddr::new(0, 0);
    socket.bind(&addr).unwrap();
    socket.connect(&SocketAddr::new(0, 0))?;

    let (mut s, r) = mpsc::channel(100);

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

    socket.send(&buf[..]).await?;
    finfo!("Get link information...");
    loop {
        let (buf, size) = NetIfMon::recv_netlink_msg(&mut socket).await?;
        let finish = netif_mon.update(buf, size, Some(&mut s)).await?;
        if finish {
            break;
        }
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

    socket.send(&buf[..]).await?;
    finfo!("Get address information...");
    loop {
        let (buf, size) = NetIfMon::recv_netlink_msg(&mut socket).await?;
        let finish = netif_mon.update(buf, size, Some(&mut s)).await?;
        if finish {
            break;
        }
    }

    let mut mon_socket = Socket::new(NETLINK_ROUTE).unwrap();
    let addr = SocketAddr::new(0, NetIfMon::RTMGRP_LINK | NetIfMon::RTMGRP_IPV4_IFADDR);
    mon_socket.bind(&addr).unwrap();
    mon_socket.connect(&SocketAddr::new(0, 0))?;

    finfo!("Start monitoring...");
    netif_mon.monitor(&mut mon_socket, s, r).await
}
