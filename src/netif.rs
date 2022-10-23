//cspell:word netlink rtnl Netlink Rtnl nlas ipnetwork rnetmgr netinfo ifname
//cspell:word NETIF ipaddr updown rtnetlink dhcpcd rfind dhcpv

#[allow(unused)]
use netlink_packet_route::{
    rtnl, AddressHeader, AddressMessage, LinkHeader, LinkMessage, NetlinkHeader, NetlinkMessage,
    NetlinkPayload, RtnlMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};

#[allow(unused)]
use rtnl::address::nlas::Nla as AddrNla;

use ipnetwork::IpNetwork;
use tokio::process::{Child, Command};

#[allow(unused)]
use rtnl::link::nlas::Nla as LinkNla;
use std::fmt::{self, Display, Formatter};
use tokio::{
    fs::File,
    io::{AsyncWriteExt, Error, ErrorKind, Result},
};

use rnetmgr_lib::netinfo::MacAddr;

#[allow(unused)]
use jlogger::{jdebug, jerror, jinfo, jwarn};

static DHCP_SERVER_CONF: &str = include_str!("dhcp4-template.conf");

pub struct NetIf {
    ifname: String,
    ipv4: Vec<IpNetwork>,
    mac: MacAddr,
    flags: u32,
    if_index: u32,
    dhcp_client: Option<Child>,
    dhcp_server: Option<Child>,
}

impl Default for NetIf {
    fn default() -> Self {
        NetIf {
            ifname: String::new(),
            ipv4: Vec::<IpNetwork>::new(),
            mac: Default::default(),
            flags: 0,
            if_index: NetIf::NETIF_INVALID_IF_INDEX,
            dhcp_client: None,
            dhcp_server: None,
        }
    }
}

impl PartialEq for NetIf {
    fn eq(&self, other: &Self) -> bool {
        if self.ifname != other.ifname {
            return false;
        }

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

impl Eq for NetIf {}

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

        write!(
            f,
            "{} : {} {} {} [{}]",
            self.ifname,
            self.if_index,
            self.mac,
            ipv4_str,
            NetIf::state_flag_str(self.flags).join(" ")
        )
    }
}

impl NetIf {
    pub const NETIF_INVALID_IF_INDEX: u32 = u32::MAX;
    pub fn new(ifname: &str, if_index: u32, mac: MacAddr, flags: u32) -> Self {
        NetIf {
            ifname: ifname.to_string(),
            ipv4: Vec::<IpNetwork>::new(),
            mac,
            flags,
            if_index,
            dhcp_client: None,
            dhcp_server: None,
        }
    }

    pub fn is_valid(&self) -> bool {
        if self.ifname.is_empty() {
            return false;
        }

        if self.mac == Default::default() {
            return false;
        }

        if self.if_index == NetIf::NETIF_INVALID_IF_INDEX {
            return false;
        }
        true
    }

    #[allow(unused)]
    pub fn ifname(&self) -> String {
        self.ifname.clone()
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    #[allow(unused)]
    pub fn mac(&self) -> &MacAddr {
        &self.mac
    }

    #[allow(unused)]
    pub fn ipv4addr(&self) -> &Vec<IpNetwork> {
        &self.ipv4
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

    pub fn add_ipv4_addr(&mut self, ipaddr: &IpNetwork) {
        jdebug!("Add {} to {}", ipaddr, self.ifname);
        if !self.ipv4.iter().any(|a| a == ipaddr) {
            self.ipv4.push(*ipaddr);
        }
    }

    pub fn del_ipv4_addr(&mut self, ipaddr: &IpNetwork) {
        jdebug!("Del {} to {}", ipaddr, self.ifname);
        self.ipv4.retain(|addr| addr != ipaddr);
    }

    #[allow(unused)]
    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn update_flags(&mut self, new_flag: u32) {
        self.flags = new_flag;
    }

    pub async fn set_netif_updown(&self, up: bool) -> Result<()> {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(conn);
        if up {
            handle
                .link()
                .set(self.if_index)
                .up()
                .execute()
                .await
                .map_err(|e| Error::new(ErrorKind::Other, format!("rtnetlink error: {}", e)))
        } else {
            handle
                .link()
                .set(self.if_index)
                .down()
                .execute()
                .await
                .map_err(|e| Error::new(ErrorKind::Other, format!("rtnetlink error: {}", e)))
        }
    }

    pub async fn set_ipv4_addr(&self, ipaddr: &IpNetwork) -> Result<()> {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(conn);

        jdebug!("Set IPv4 addr {} for {}", ipaddr, self.ifname);
        if !self.is_valid() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid netif {}", self.ifname),
            ));
        }

        if self
            .ipv4
            .iter()
            .any(|x| (x.ip() == ipaddr.ip()) && (x.prefix() == ipaddr.prefix()))
        {
            return Ok(());
        }

        handle
            .address()
            .add(self.if_index, ipaddr.ip(), ipaddr.prefix())
            .execute()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("rtnetlink error: {}", e)))
    }

    pub async fn start_dhcp_client(&mut self) -> Result<()> {
        if let Some(dc) = &mut self.dhcp_client {
            if let Ok(None) = dc.try_wait() {
                jinfo!("dhcp client is running for {}\n", self.ifname);
                return Ok(());
            }
        }

        let cmd = "/sbin/dhcpcd";
        let args = vec![String::from("-B"), self.ifname()];

        jinfo!("Start dhcp for {}", self.ifname);
        jinfo!("CMD: {} {}", cmd, args.join(" "));
        let c = Command::new(cmd).args(args).spawn()?;
        self.dhcp_client = Some(c);

        Ok(())
    }

    pub async fn start_dhcp_server(&mut self, ip: &IpNetwork) -> Result<()> {
        if let Some(ds) = &mut self.dhcp_server {
            if let Ok(None) = ds.try_wait() {
                jinfo!("dhcp server is running for {}\n", self.ifname);
                return Ok(());
            }
        }

        let ip_str = ip.ip().to_string();
        let prefix_str = ip.prefix().to_string();
        let subnet_str = format!("{}/{}", ip.network().to_string(), prefix_str);
        let pos = ip_str.rfind('.').unwrap();
        let start = format!("{}.{}", &ip_str[0..pos], 10);
        let end = format!("{}.{}", &ip_str[0..pos], 240);

        let interface = format!("{}", &self.ifname);

        let conf_str = DHCP_SERVER_CONF
            .replace("@INTERFACE@", &interface)
            .replace("@SUBNET@", &subnet_str)
            .replace("@START@", &start)
            .replace("@END@", &end)
            .replace("@GATEWAY_IP@", &ip_str);

        let conf_file = format!("/tmp/dhcpv4_{}.conf", self.ifname);
        let mut file = File::create(&conf_file).await?;
        file.write_all(conf_str.as_bytes()).await?;

        let _ = tokio::fs::create_dir("/var/run/kea").await;
        let _ = tokio::fs::create_dir("/var/lib/kea").await;

        jinfo!("{}", conf_str);
        let cmd = "/usr/sbin/kea-dhcp4";
        let args = vec![String::from("-c"), conf_file];

        jinfo!("Start dhcp server for {}", self.ifname);
        jinfo!("CMD: {} {}", cmd, args.join(" "));
        let c = Command::new(cmd).args(args).spawn()?;
        self.dhcp_server = Some(c);

        Ok(())
    }
}
