#[allow(unused)]
use {
    super::netif::NetIf,
    super::rnetmgr_error::RnetmgrError,
    super::{NetIfConfig, NetIfConfigEntry},
    error_stack::{Report, Result, ResultExt},
    futures::stream::StreamExt,
    futures::TryStreamExt,
    ipnetwork::{IpNetwork, Ipv4Network},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    netlink_packet_route::{
        constants::*, rtnl, AddressHeader, AddressMessage, LinkHeader, LinkMessage, NetlinkHeader,
        NetlinkMessage, NetlinkPayload, RtnlMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP,
        NLM_F_EXCL, NLM_F_REQUEST,
    },
    rnetmgr_lib::netinfo::{
        MacAddr, NetInfoDelAddress, NetInfoDelLink, NetInfoMessage, NetInfoNewAddress,
        NetInfoNewLink, NetInfoReqMessage, NETINFO_IPCON, NETINFO_IPCON_GROUP,
    },
    rtnetlink::sys::{AsyncSocket, SocketAddr},
    std::{
        collections::HashMap,
        convert::TryFrom,
        fmt::{self, Display, Formatter},
    },
    tokio::{
        io::{Error, ErrorKind},
        process::Command,
        sync::mpsc::{self, Sender},
    },
};

fn config_route(internal_if: &str, external_if: &str) -> Result<(), RnetmgrError> {
    let ipt = iptables::new(false).map_err(|e| {
        Report::new(RnetmgrError::SystemError)
            .attach_printable(format!("Failed to initialize iptables: {}", e))
    })?;

    // Flush filter and nat tables
    ipt.flush_table("filter").map_err(|e| {
        Report::new(RnetmgrError::SystemError)
            .attach_printable(format!("Failed to flush filter table: {}", e))
    })?;
    ipt.flush_table("nat").map_err(|e| {
        Report::new(RnetmgrError::SystemError)
            .attach_printable(format!("Failed to flush nat table: {}", e))
    })?;

    // NAT masquerade on external interface
    ipt.append(
        "nat",
        "POSTROUTING",
        &format!("-o {} -j MASQUERADE", external_if),
    )
    .map_err(|e| {
        Report::new(RnetmgrError::SystemError)
            .attach_printable(format!("Failed to add MASQUERADE rule: {}", e))
    })?;

    // Permit output to external network
    ipt.append("filter", "OUTPUT", &format!("-o {} -j ACCEPT", external_if))
        .map_err(|e| {
            Report::new(RnetmgrError::SystemError).attach_printable(format!(
                "Failed to add OUTPUT rule for {}: {}",
                external_if, e
            ))
        })?;

    // Permit internal network
    ipt.append("filter", "INPUT", &format!("-i {} -j ACCEPT", internal_if))
        .map_err(|e| {
            Report::new(RnetmgrError::SystemError).attach_printable(format!(
                "Failed to add INPUT rule for {}: {}",
                internal_if, e
            ))
        })?;
    ipt.append("filter", "OUTPUT", &format!("-o {} -j ACCEPT", internal_if))
        .map_err(|e| {
            Report::new(RnetmgrError::SystemError).attach_printable(format!(
                "Failed to add OUTPUT rule for {}: {}",
                internal_if, e
            ))
        })?;

    // Permit loopback
    ipt.append("filter", "INPUT", "-i lo -j ACCEPT")
        .map_err(|e| {
            Report::new(RnetmgrError::SystemError)
                .attach_printable(format!("Failed to add loopback INPUT rule: {}", e))
        })?;
    ipt.append("filter", "OUTPUT", "-o lo -j ACCEPT")
        .map_err(|e| {
            Report::new(RnetmgrError::SystemError)
                .attach_printable(format!("Failed to add loopback OUTPUT rule: {}", e))
        })?;

    // Permit forwarding from internal to external
    ipt.append(
        "filter",
        "FORWARD",
        &format!("-i {} -o {} -j ACCEPT", internal_if, external_if),
    )
    .map_err(|e| {
        Report::new(RnetmgrError::SystemError)
            .attach_printable(format!("Failed to add FORWARD rule: {}", e))
    })?;

    // Enable IP forwarding
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| {
        Report::new(RnetmgrError::SystemError)
            .attach_printable(format!("Failed to enable IP forwarding: {}", e))
    })?;

    Ok(())
}

#[cfg(feature = "enable_ipcon")]
use ipcon_sys::{
    ipcon::{IPF_RCV_IF, IPF_SND_IF},
    ipcon_async::AsyncIpcon,
    ipcon_msg::IpconMsg,
};

#[cfg(feature = "enable_ipcon")]
use std::ffi::{CStr, CString};

struct DHCPServerIpv4Config {
    ipv4: IpNetwork,
    routeif: Option<String>,
}

impl PartialEq for DHCPServerIpv4Config {
    fn eq(&self, other: &Self) -> bool {
        self.ipv4 == other.ipv4
    }
}

impl Eq for DHCPServerIpv4Config {}

#[derive(PartialEq, Eq)]
enum NetIfType {
    EthernetDHCP,
    EthernetStaticIpv4(IpNetwork),
    EthernetDHCPServerIpv4(DHCPServerIpv4Config),
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
                NetIfType::EthernetDHCPServerIpv4(_) => "Ethernet+DHCPServer+Ipv4",
                NetIfType::Invalid => "Invalid",
            }
        )
    }
}

impl TryFrom<&NetIfConfigEntry> for NetIfType {
    type Error = RnetmgrError;

    fn try_from(cfg: &NetIfConfigEntry) -> std::result::Result<Self, Self::Error> {
        let mut iftype = NetIfType::Invalid;

        if cfg.iftype == "Ethernet" {
            if cfg.addr_type == "Static" {
                if let Some(ipv4) = &cfg.ipv4 {
                    if let Ok(ip) = ipv4.parse::<Ipv4Network>() {
                        iftype = NetIfType::EthernetStaticIpv4(IpNetwork::V4(ip));
                    }
                }
            }

            if cfg.addr_type == "DHCP" {
                iftype = NetIfType::EthernetDHCP;
            }

            if cfg.addr_type == "DHCPServer" {
                let routeif = match &cfg.routeif {
                    Some(s) => Some(s.clone()),
                    None => None,
                };

                if let Some(ipv4) = &cfg.ipv4 {
                    if let Ok(ip) = ipv4.parse::<Ipv4Network>() {
                        iftype = NetIfType::EthernetDHCPServerIpv4(DHCPServerIpv4Config {
                            ipv4: IpNetwork::V4(ip),
                            routeif,
                        });
                    }
                }
            }
        }

        if iftype == NetIfType::Invalid {
            Err(RnetmgrError::InvalidValue)
        } else {
            Ok(iftype)
        }
    }
}

pub struct NetIfMon {
    netif_hash: HashMap<String, NetIf>,
    netiftype_hash: HashMap<String, NetIfType>,
    dhcp_conf: String,
}

impl Display for NetIfMon {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for t in self.netif_hash.keys() {
            writeln!(f, "Monitoring {}", t)?
        }
        Ok(())
    }
}

#[cfg(feature = "enable_ipcon")]
async fn netinfo_rcv(ih: &AsyncIpcon) -> (String, Result<NetInfoReqMessage, Error>) {
    match ih.receive_msg().await {
        Ok(ipcon_msg) => {
            if let IpconMsg::IpconMsgUser(body) = ipcon_msg {
                match {
                    #[cfg(target_arch = "aarch64")]
                    unsafe {
                        CStr::from_ptr(body.buf.as_ptr()).to_str()
                    }

                    #[cfg(target_arch = "x86_64")]
                    unsafe {
                        CStr::from_ptr(body.buf.as_ptr() as *const i8).to_str()
                    }
                } {
                    Ok(s) => match serde_json::from_str::<NetInfoReqMessage>(s) {
                        Ok(req) => (body.peer, Ok(req)),
                        Err(e) => (
                            body.peer,
                            Err(Error::new(ErrorKind::InvalidData, format!("{}", e))).into_report(),
                        ),
                    },
                    Err(e) => (
                        body.peer,
                        Err(Error::new(ErrorKind::InvalidData, format!("{}", e))).into_report(),
                    ),
                }
            } else {
                (
                    String::new(),
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid NetInfoReqMessage",
                    ))
                    .into_report(),
                )
            }
        }
        Err(e) => (
            String::new(),
            Err(e.change_context(Error::new(ErrorKind::Other, "IPCON error"))),
        ),
    }
}

#[cfg(feature = "enable_ipcon")]
async fn netinfo_send(
    ih: &AsyncIpcon,
    peer: Option<String>,
    msg: NetInfoMessage,
) -> Result<(), Error> {
    let buf = serde_json::to_string(&msg)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Serialize error {}", e)))?;

    if let Some(p) = &peer {
        jdebug!("Send to {} : {}", p, buf);
    } else {
        jdebug!("Send multicast : {}", buf);
    }

    let c_buf = CString::new(buf)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("CString trans error {}", e)))?;

    if let Some(p) = &peer {
        ih.send_unicast_msg(p, &c_buf.into_bytes_with_nul())
            .await
            .change_context(Error::new(ErrorKind::Other, "IPCON error"))
    } else {
        ih.send_multicast(NETINFO_IPCON_GROUP, &c_buf.into_bytes_with_nul(), false)
            .await
            .change_context(Error::new(ErrorKind::Other, "IPCON error"))
    }
}

impl NetIfMon {
    pub async fn run(nifcfg: NetIfConfig, dhcp_conf: String) -> Result<(), RnetmgrError> {
        let mut netiftype_hash = HashMap::<String, NetIfType>::new();

        for cfg in nifcfg.netifs {
            netiftype_hash.insert(
                cfg.ifname.clone(),
                NetIfType::try_from(&cfg)
                    .map_err(|e| Report::new(RnetmgrError::InvalidValue).attach_printable(e))?,
            );
        }

        let (mut conn, handle, mut messages) = rtnetlink::new_connection()
            .map_err(|e| Report::new(RnetmgrError::RtNetlinkError).attach_printable(e))?;

        let groups = 1 << (RTNLGRP_LINK - 1) | 1 << (RTNLGRP_IPV4_IFADDR - 1);
        jdebug!("group: {}", groups);
        let addr = SocketAddr::new(0, groups);

        let (mut s, mut r) = mpsc::channel(100);
        conn.socket_mut()
            .socket_mut()
            .bind(&addr)
            .map_err(|e| Report::new(RnetmgrError::SocketError).attach_printable(e))?;

        tokio::spawn(conn);

        let mut netif_mon = NetIfMon {
            netif_hash: HashMap::<String, NetIf>::new(),
            netiftype_hash,
            dhcp_conf,
        };

        /* Dump all Link information */
        let mut links = handle.link().get().execute();
        while let Some(lm) = links
            .try_next()
            .await
            .map_err(|e| Report::new(RnetmgrError::RtNetlinkError).attach_printable(e))?
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
            .map_err(|e| Report::new(RnetmgrError::RtNetlinkError).attach_printable(e))?
        {
            let nmsg = NetlinkMessage {
                header: NetlinkHeader::default(),
                payload: NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(am)),
            };

            netif_mon.update(nmsg, Some(&mut s)).await?;
        }

        jinfo!("Start monitoring...");

        #[cfg(feature = "enable_ipcon")]
        {
            let ih = AsyncIpcon::new(Some(NETINFO_IPCON), Some(IPF_RCV_IF | IPF_SND_IF))
                .expect("Failed to create IPCON handler.");

            ih.register_group(NETINFO_IPCON_GROUP)
                .await
                .expect("Failed to register rnetmgr group.");

            loop {
                tokio::select! {
                    Some((msg, _)) = messages.next() => {
                            if let Err(e) = netif_mon.update(msg, Some(&mut s)).await {
                                jerror!("{}", e);
                            }
                    }

                    Some(m) = r.recv() => {
                            jinfo!("{}", m);
                            if let Err(e) = netinfo_send(&ih, None, m).await {
                                jerror!("{}", e);
                            }
                    }

                    (peer, ret) = netinfo_rcv(&ih) => {
                        match ret {
                            Ok(m) => {
                                jdebug!("ReqMessage from {}", peer);
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
                                            jdebug!("ReqMessage from {} for {}", peer, s);
                                            if let Some(nif) = netif_mon.netif_hash.get(&s) {
                                                let iparray = nif.ipv4addr();
                                                for ip in iparray.iter() {
                                                    let m = NetInfoMessage::NewAddress(
                                                        NetInfoNewAddress {
                                                            ifname : nif.ifname(),
                                                            if_index : nif.if_index(),
                                                            ipv4addr : *ip,
                                                    });

                                                    jdebug!("Reply {} in {} to  {}", m, s, peer);
                                                    let _ = netinfo_send(&ih, Some(peer.clone()), m).await;
                                                }
                                            } else {
                                                jdebug!("No IP found for {}", s);
                                            }

                                            let _ = netinfo_send(&ih, Some(peer), NetInfoMessage::NoInfo).await;
                                    }
                                }
                            }
                            Err(e) => {
                                if !peer.is_empty() {
                                    jerror!("Bad NetInfoReqMessage from {} : {}", peer, e);
                                    let _ = netinfo_send(&ih, Some(peer), NetInfoMessage::InvalidReq).await;
                                } else {
                                    jerror!("Unexpected NetInfoReqMessage : {}", e);
                                }
                            }
                        }
                    }

                }
            }
        }

        #[cfg(not(feature = "enable_ipcon"))]
        loop {
            tokio::select! {
                Some((msg, _)) = messages.next() => {
                        if let Err(e) = netif_mon.update(msg, Some(&mut s)).await {
                            jerror!("{}", e);
                        }
                }

                Some(m) = r.recv() => {
                        jinfo!("{}", m);
                }
            }
        }
    }

    async fn update(
        &mut self,
        msg: NetlinkMessage<RtnlMessage>,
        mut sender: Option<&mut Sender<NetInfoMessage>>,
    ) -> Result<bool, RnetmgrError> {
        match msg.payload {
            NetlinkPayload::Done => {
                return Ok(true);
            }
            NetlinkPayload::Error(e) => {
                return Err(
                    Report::new(RnetmgrError::RtNetlinkError).attach_printable(format!("{}", e))
                );
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

                    jdebug!("{}", msg);

                    if let Some(s) = &mut sender {
                        if let Err(e) = s.send(msg).await {
                            jerror!("MPSC send error: {}", e);
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

                    jinfo!(
                        newlink = ifname,
                        idex = lm.header.index,
                        mac = mac.clone().to_string()
                    );

                    if let Some(s) = &mut sender {
                        if let Err(e) = s.send(msg).await {
                            jerror!("MPSC send error: {}", e);
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
                        let mut ipaddr = None;
                        if let NetIfType::EthernetStaticIpv4(addr) = ntype {
                            ipaddr = Some(addr);
                        }

                        if let NetIfType::EthernetDHCPServerIpv4(cfg) = ntype {
                            ipaddr = Some(&cfg.ipv4);
                        }

                        if let NetIfType::EthernetDHCP = ntype {
                            if let Err(e) = netif.start_dhcp_client().await {
                                jerror!("Failed to start dhcp client for {}: {}", ifname, e);
                            }
                        }

                        if let Some(addr) = ipaddr {
                            if netif.flags() & IFF_RUNNING == IFF_RUNNING {
                                jinfo!("NetIf {} is UP, set IP address.", netif.ifname());
                                if let Err(e) = netif.set_ipv4_addr(addr).await {
                                    jerror!(
                                        "Failed to set ip address {} to {}: {}",
                                        addr,
                                        ifname,
                                        e
                                    );
                                }
                            } else {
                                jinfo!("NetIf {} is DOWN, bring UP", netif.ifname());
                                if let Err(e) = netif.set_netif_updown(true).await {
                                    jerror!("Failed to set {} UP: {}", ifname, e);
                                }
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
                            return Err(Report::new(RnetmgrError::RtNetlinkError)
                                .attach_printable(format!(
                                    "DelAddress: netif {} is not found.",
                                    ifname
                                )));
                        }

                        let msg = NetInfoMessage::DelAddress(NetInfoDelAddress {
                            ifname: ifname.clone(),
                            if_index: n.if_index(),
                            ipv4addr: addr,
                        });

                        jdebug!("{}", msg);

                        if let Some(s) = &mut sender {
                            if let Err(e) = s.send(msg).await {
                                jerror!("MPSC send error: {}", e);
                            }
                        }

                        if let Some(NetIfType::EthernetStaticIpv4(addr_s)) =
                            self.netiftype_hash.get(&ifname)
                        {
                            if addr_s == &addr {
                                jwarn!("{} is removed from {}, try to reset it.", addr, ifname);

                                let netif = self.netif_hash.get_mut(&ifname).unwrap();
                                /*
                                 * set_ipv4_addr() will return Ok(()) directly if the ip
                                 * address has been set
                                 */
                                if let Err(e) = netif.set_ipv4_addr(&addr).await {
                                    jerror!(
                                        "Failed to set ip address {} to {}: {}",
                                        addr,
                                        ifname,
                                        e
                                    );
                                } else if let Err(e) = netif.set_netif_updown(true).await {
                                    jerror!("Failed to set {} UP: {}", ifname, e);
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
                        let netif = self
                            .netif_hash
                            .entry(ifname.clone())
                            .and_modify(|n| n.add_ipv4_addr(&addr))
                            .or_default();

                        jinfo!(
                            newaddr = addr.to_string(),
                            ifname = ifname,
                            index = netif.if_index()
                        );

                        if !netif.is_valid() {
                            jerror!("NewAddress: netif {} is not found.", ifname);
                            return Ok(false);
                        }

                        let msg = NetInfoMessage::NewAddress(NetInfoNewAddress {
                            ifname: ifname.clone(),
                            if_index: netif.if_index(),
                            ipv4addr: addr,
                        });

                        if let Some(s) = &mut sender {
                            if let Err(e) = s.send(msg).await {
                                jerror!("MPSC send error: {}", e);
                            }
                        }

                        if let Some(ntype) = self.netiftype_hash.get(&ifname) {
                            if let NetIfType::EthernetDHCPServerIpv4(cfg) = ntype {
                                let ip = &cfg.ipv4;
                                if ip == &addr {
                                    jinfo!("Found IP address {}, start DHCP server.", ip);
                                    netif.start_dhcp_server(ip, self.dhcp_conf.as_str()).await?;
                                    if let Some(routeif) = &cfg.routeif {
                                        jinfo!("Setup route to {}", routeif);
                                        config_route(&ifname, routeif)?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                jdebug!("Unexpected msg");
            }
        }

        Ok(false)
    }
}
