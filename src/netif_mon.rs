use crate::netif::NetIf;
#[allow(unused)]
use crate::{fdebug, ferror, finfo, ftrace, fwarn, NetIfConfig, NetIfConfigEntry};
use ipnetwork::{IpNetwork, Ipv4Network};
#[allow(unused)]
use rnetmgr_lib::netinfo::{
    MacAddr, NetInfoDelAddress, NetInfoDelLink, NetInfoMessage, NetInfoNewAddress, NetInfoNewLink,
    NetInfoReqMessage, NETINFO_IPCON, NETINFO_IPCON_GROUP,
};

#[allow(unused)]
use netlink_packet_route::{
    constants::*, rtnl, AddressHeader, AddressMessage, LinkHeader, LinkMessage, NetlinkHeader,
    NetlinkMessage, NetlinkPayload, RtnlMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
    NLM_F_REQUEST,
};

use futures::stream::StreamExt;
use futures::TryStreamExt;
use rtnetlink::sys::{AsyncSocket, SocketAddr};

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use tokio::{
    io::{Error, ErrorKind, Result},
    sync::mpsc::{self, Sender},
};

use bytes::Bytes;
use ipcon_sys::ipcon::{IPF_RCV_IF, IPF_SND_IF};
use ipcon_sys::ipcon_async::AsyncIpcon;
use ipcon_sys::ipcon_msg::IpconMsg;
use std::ffi::CStr;

#[derive(PartialEq, Eq)]
enum NetIfType {
    EthernetDHCP,
    EthernetStaticIpv4(IpNetwork),
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
                    if let Ok(ip) = ipv4.parse::<Ipv4Network>() {
                        iftype = NetIfType::EthernetStaticIpv4(IpNetwork::V4(ip));
                    } else {
                        return NetIfType::Invalid;
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

async fn netinfo_rcv(ih: &AsyncIpcon) -> (String, Result<NetInfoReqMessage>) {
    match ih.receive_msg().await {
        Ok(ipcon_msg) => {
            if let IpconMsg::IpconMsgUser(body) = ipcon_msg {
                match unsafe { CStr::from_ptr(body.buf.as_ptr() as *const i8).to_str() } {
                    Ok(s) => match serde_json::from_str::<NetInfoReqMessage>(s) {
                        Ok(req) => (body.peer, Ok(req)),
                        Err(e) => (
                            body.peer,
                            Err(Error::new(ErrorKind::InvalidData, format!("{}", e))),
                        ),
                    },
                    Err(e) => (
                        body.peer,
                        Err(Error::new(ErrorKind::InvalidData, format!("{}", e))),
                    ),
                }
            } else {
                (
                    String::new(),
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid NetInfoReqMessage",
                    )),
                )
            }
        }
        Err(e) => (String::new(), Err(e)),
    }
}

async fn netinfo_send(ih: &AsyncIpcon, peer: Option<String>, msg: NetInfoMessage) -> Result<()> {
    let buf = serde_json::to_string(&msg)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Serialize error {}", e)))?;

    let cstr_buf = unsafe { CStr::from_ptr(buf.as_ptr()) };

    if let Some(p) = &peer {
        fdebug!("Send to {} : {}", p, buf);
        ih.send_unicast_msg(p, Bytes::from(cstr_buf.to_bytes_with_nul()))
            .await
    } else {
        fdebug!("Send multicast : {}", buf);
        ih.send_multicast(NETINFO_IPCON_GROUP, Bytes::from(buf), false)
            .await
    }
}

impl NetIfMon {
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

        let (mut conn, handle, mut messages) = rtnetlink::new_connection()?;
        let groups = 1 << (RTNLGRP_LINK - 1) | 1 << (RTNLGRP_IPV4_IFADDR - 1);
        fdebug!("group: {}", groups);
        let addr = SocketAddr::new(0, groups);
        let (mut s, mut r) = mpsc::channel(100);
        conn.socket_mut().socket_mut().bind(&addr)?;
        tokio::spawn(conn);

        let mut netif_mon = NetIfMon {
            netif_hash: HashMap::<String, NetIf>::new(),
            netiftype_hash,
        };

        /* Dump all Link information */
        let mut links = handle.link().get().execute();
        while let Some(lm) = links
            .try_next()
            .await
            .map_err(|_| Error::new(ErrorKind::Other, "Get Link Error"))?
        {
            let nmsg = NetlinkMessage {
                header: NetlinkHeader::default(),
                payload: NetlinkPayload::InnerMessage(RtnlMessage::NewLink(lm)),
            };

            netif_mon.update(nmsg, Some(&mut s)).await?;
        }

        /* Dump all address information */
        let mut addrs = handle.address().get().execute();
        while let Some(am) = addrs
            .try_next()
            .await
            .map_err(|_| Error::new(ErrorKind::Other, "Get Link Error"))?
        {
            let nmsg = NetlinkMessage {
                header: NetlinkHeader::default(),
                payload: NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(am)),
            };

            netif_mon.update(nmsg, Some(&mut s)).await?;
        }

        finfo!("Start monitoring...");

        let ih = AsyncIpcon::new(Some(NETINFO_IPCON), Some(IPF_RCV_IF | IPF_SND_IF))
            .expect("Failed to create IPCON handler.");

        ih.register_group(NETINFO_IPCON_GROUP)
            .await
            .expect("Failed to register rnetmgr group.");

        loop {
            tokio::select! {
                Some((msg, _)) = messages.next() => {
                        if let Err(e) = netif_mon.update(msg, Some(&mut s)).await {
                            ferror!("{}", e);
                        }
                }

                Some(m) = r.recv() => {
                        finfo!("{}", m);
                        if let Err(e) = netinfo_send(&ih, None, m).await {
                            ferror!("{}", e);
                        }
                }

                (peer, ret) = netinfo_rcv(&ih) => {
                    match ret {
                        Ok(m) => {
                            fdebug!("ReqMessage from {}", peer);
                            match m {
                                NetInfoReqMessage::ReqLink(s) => {
                                        let mut m = NetInfoMessage::NoInfo;

                                        if let Some(nif) = netif_mon.netif_hash.get(&s) {
                                            m = NetInfoMessage::NewLink(NetInfoNewLink {
                                                    ifname : nif.ifname(),
                                                    if_index : nif.if_index(),
                                                    mac : nif.mac().clone(),
                                                    flags : nif.flags(),
                                            });
                                        }

                                        let _ = netinfo_send(&ih, Some(peer), m).await;
                                }
                                NetInfoReqMessage::ReqAddress(s) => {
                                        fdebug!("ReqMessage from {} for {}", peer, s);
                                        if let Some(nif) = netif_mon.netif_hash.get(&s) {
                                            let iparray = nif.ipv4addr();
                                            for ip in iparray.iter() {
                                                let m = NetInfoMessage::NewAddress(
                                                    NetInfoNewAddress {
                                                        ifname : nif.ifname(),
                                                        if_index : nif.if_index(),
                                                        ipv4addr : *ip,
                                                });

                                                fdebug!("Reply {} in {} to  {}", m, s, peer);
                                                let _ = netinfo_send(&ih, Some(peer.clone()), m).await;
                                            }
                                        } else {
                                            fdebug!("No IP found for {}", s);
                                        }

                                        let _ = netinfo_send(&ih, Some(peer), NetInfoMessage::NoInfo).await;
                                }
                            }
                        }
                        Err(e) => {
                            if !peer.is_empty() {
                                ferror!("Bad NetInfoReqMessage from {} : {}", peer, e);
                                let _ = netinfo_send(&ih, Some(peer), NetInfoMessage::InvalidReq).await;
                            } else {
                                ferror!("Unexpectd NetInfoReqMessage : {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn update(
        &mut self,
        msg: NetlinkMessage<RtnlMessage>,
        mut sender: Option<&mut Sender<NetInfoMessage>>,
    ) -> Result<bool> {
        match msg.payload {
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

                    if let Some(ntype) = self.netiftype_hash.get(&ifname) {
                        if let NetIfType::EthernetStaticIpv4(addr) = ntype {
                            if let Err(e) = netif.set_ipv4_addr(addr).await {
                                ferror!("Failed to set ip address {} to {}: {}", addr, ifname, e);
                            } else if let Err(e) = netif.set_netif_updown(true).await {
                                ferror!("Failed to set {} UP: {}", ifname, e);
                            }
                        }

                        if let NetIfType::EthernetDHCP = ntype {
                            if let Err(e) = netif.enable_dhcp_client().await {
                                ferror!("Failed to enable dhcp client for {}: {}", ifname, e);
                            }
                        }
                    }
                }
            }

            NetlinkPayload::InnerMessage(RtnlMessage::DelAddress(am)) => {
                let mut ifname = String::new();
                let mut ipaddr: Option<IpNetwork> = None;

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
                                if let Ok(i) = Ipv4Network::new(ip, prefix_len) {
                                    ipaddr = Some(IpNetwork::V4(i));
                                }
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
                let mut ipaddr: Option<IpNetwork> = None;

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
                                if let Ok(i) = Ipv4Network::new(ip, prefix_len) {
                                    ipaddr = Some(IpNetwork::V4(i));
                                }
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

        Ok(false)
    }
}
