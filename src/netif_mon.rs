use crate::netif::{Ipv4Entry, MacAddr, NetIf};
#[allow(unused)]
use crate::netinfo::{
    NetInfoDelAddress, NetInfoDelLink, NetInfoMessage, NetInfoNewAddress, NetInfoNewLink,
};
#[allow(unused)]
use crate::{fdebug, ferror, finfo, ftrace, fwarn, NetIfConfig, NetIfConfigEntry};
use bytes::Bytes;
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
    task,
};

#[cfg(feature = "netinfo-ipcon")]
use ipcon_sys::{
    ipcon::{IPF_RCV_IF, IPF_SND_IF},
    ipcon_async::AsyncIpcon,
};

#[cfg(feature = "netinfo-ipcon")]
const NETINFO_IPCON_GROUP: &'static str = "netinfo";

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
    socket: Socket,
    netif_hash: HashMap<String, NetIf>,
    netiftype_hash: HashMap<String, NetIfType>,
    #[cfg(feature = "netinfo-ipcon")]
    ih: AsyncIpcon,
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

        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let addr = SocketAddr::new(0, NetIfMon::RTMGRP_LINK | NetIfMon::RTMGRP_IPV4_IFADDR);
        socket.bind(&addr).unwrap();
        socket.connect(&SocketAddr::new(0, 0))?;

        let mut handlers = vec![];

        cfg_if::cfg_if! {
            if #[cfg(feature = "netinfo-ipcon")] {
                let ih = AsyncIpcon::new(Some("rnetmgr"), Some(IPF_RCV_IF | IPF_SND_IF)).unwrap();
                ih.register_group(NETINFO_IPCON_GROUP).await?;
            }
        }

        handlers.push(task::spawn(async move {
            mon_thread(NetIfMon {
                socket,
                netif_hash: HashMap::<String, NetIf>::new(),
                netiftype_hash,
                #[cfg(feature = "netinfo-ipcon")]
                ih,
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

    #[cfg(feature = "netinfo-ipcon")]
    async fn send_netinfo_ipcon_msg(&self, msg: NetInfoMessage) -> Result<()> {
        let buf = serde_json::to_string(&msg)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Serialze error: {}", e)))?;

        self.ih
            .send_multicast(NETINFO_IPCON_GROUP, Bytes::from(buf), false)
            .await
    }

    async fn update(&mut self) -> Result<()> {
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
                            {
                                let msg = NetInfoMessage::DelLink(NetInfoDelLink {
                                    ifname: ifname.clone(),
                                    if_index: lm.header.index,
                                    flags: lm.header.flags,
                                });

                                fdebug!("{}", msg);

                                #[cfg(feature = "netinfo-ipcon")]
                                self.send_netinfo_ipcon_msg(msg).await;
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
                            {
                                let msg = NetInfoMessage::NewLink(NetInfoNewLink {
                                    ifname: ifname.clone(),
                                    if_index: lm.header.index,
                                    mac: mac.clone(),
                                    flags: lm.header.flags,
                                });

                                fdebug!("{}", msg);

                                #[cfg(feature = "netinfo-ipcon")]
                                self.send_netinfo_ipcon_msg(msg).await;
                            }

                            let netif = NetIf::new(&ifname, if_index, mac, flags);
                            self.netif_hash.insert(netif.ifname(), netif);

                            if let Some(NetIfType::EthernetStaticIpv4(addr)) =
                                self.netiftype_hash.get(&ifname)
                            {
                                let netif = self.netif_hash.get_mut(&ifname).unwrap();
                                /*
                                 * set_ipv4_addr() will return Ok(()) directly if the ip
                                 * address has been set
                                 */
                                if let Err(e) = netif.set_ipv4_addr(addr).await {
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
                                let n = self.netif_hash.get_mut(&ifname).ok_or_else(|| {
                                    Error::new(
                                        ErrorKind::Other,
                                        format!("DelAddress: netif {} is not found.", ifname),
                                    )
                                })?;

                                n.del_ipv4_addr(&addr);

                                let msg = NetInfoMessage::DelAddress(NetInfoDelAddress {
                                    ifname: ifname.clone(),
                                    if_index: n.if_index(),
                                    ipv4addr: addr,
                                });

                                fdebug!("{}", msg);

                                #[cfg(feature = "netinfo-ipcon")]
                                self.send_netinfo_ipcon_msg(msg).await;

                                if let Some(NetIfType::EthernetStaticIpv4(addr_s)) =
                                    self.netiftype_hash.get(&ifname)
                                {
                                    if addr_s == &addr {
                                        fwarn!(
                                            "{} is removed from {}, try to reset it.",
                                            addr,
                                            ifname
                                        );

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
                                let n = self.netif_hash.get_mut(&ifname).ok_or_else(|| {
                                    Error::new(
                                        ErrorKind::Other,
                                        format!("NewAddress: netif {} is not found.", ifname),
                                    )
                                })?;
                                n.add_ipv4_addr(&addr);

                                let msg = NetInfoMessage::NewAddress(NetInfoNewAddress {
                                    ifname: ifname.clone(),
                                    if_index: n.if_index(),
                                    ipv4addr: addr,
                                });

                                fdebug!("{}", msg);

                                #[cfg(feature = "netinfo-ipcon")]
                                self.send_netinfo_ipcon_msg(msg).await;
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

    netif_mon.socket.send(&buf[..]).await?;
    ftrace!("Send GetLink Message");
    netif_mon.update().await.unwrap();

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
    netif_mon.update().await.unwrap();

    loop {
        ftrace!("Do update");
        netif_mon.update().await.unwrap();
    }
}
