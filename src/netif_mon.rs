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
#[allow(unused)]
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;

struct NetIf {
    ifname: String,
    ipv4: Option<Ipv4Addr>,
    mac: Vec<u8>,
}

impl Display for NetIf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let ipv4_str = self
            .ipv4
            .map(|a| a.to_string())
            .unwrap_or("None".to_string());
        write!(
            f,
            "ifname: {:20} mac: {:18} ipv4: {:20}",
            self.ifname,
            self.mac
                .iter()
                .map(|a| format!("{:x}", a))
                .collect::<Vec<String>>()
                .join(":"),
            ipv4_str
        )
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
    pub fn new() -> Self {
        let mut netif_hash = HashMap::<String, NetIf>::new();

        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        let addr = SocketAddr::new(0, NetIfMon::RTMGRP_LINK | NetIfMon::RTMGRP_IPV4_IFADDR);

        socket.bind(&addr).unwrap();
        socket.connect(&SocketAddr::new(0, 0)).unwrap();

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
        socket.send(&buf[..], 0).unwrap();

        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;

        'main: loop {
            let size = socket.recv(&mut receive_buffer[..], 0).unwrap();

            loop {
                let bytes = &receive_buffer[offset..];

                let rx_packet: NetlinkMessage<RtnlMessage> =
                    NetlinkMessage::deserialize(bytes).unwrap();

                match rx_packet.payload {
                    NetlinkPayload::Done => {
                        break 'main;
                    }
                    NetlinkPayload::Error(e) => {
                        eprint!("Error: {}", e);
                        break;
                    }
                    NetlinkPayload::InnerMessage(r) => {
                        match r {
                            RtnlMessage::NewLink(lm) => {
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

                                if !ifname.is_empty() && !mac.is_empty() {
                                    let netif = NetIf {
                                        ifname: ifname.clone(),
                                        ipv4: None,
                                        mac,
                                    };
                                    netif_hash.insert(ifname, netif);
                                }
                            }
                            RtnlMessage::NewAddress(am) => {
                                for nla in am.nlas {
                                    match nla {
                                        rtnl::address::nlas::Nla::Label(l) => {
                                            print!("{:5}", l);
                                        }
                                        rtnl::address::nlas::Nla::Address(_addr) => {}

                                        _ => {
                                        }
                                    }
                                }
                            }
                            _ => {}
                        };
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

        NetIfMon { socket, netif_hash }
    }
}
