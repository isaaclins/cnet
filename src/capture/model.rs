use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub type MacAddr = [u8; 6];

#[derive(Clone)]
pub struct CapturedPacket {
    pub seq: u64,
    pub ts: Duration,
    pub wire_len: usize,
    pub data: Vec<u8>,
    pub summary: PacketSummary,
}

#[derive(Clone)]
pub struct PacketSummary {
    pub src: String,
    pub dst: String,
    pub protocol: &'static str,
    pub info: String,
}

#[derive(Clone)]
pub enum Layer {
    Ethernet {
        src: MacAddr,
        dst: MacAddr,
        ethertype: u16,
    },
    BsdLoopback {
        family: u32,
    },
    Ipv4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        ttl: u8,
        total_len: u16,
    },
    Ipv6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        hop_limit: u8,
        payload_len: u16,
    },
    Arp {
        op: u16,
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
    },
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload_len: usize,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
        payload_len: usize,
    },
    Icmp {
        type_: u8,
        code: u8,
    },
    Icmpv6 {
        type_: u8,
        code: u8,
    },
    Unknown {
        label: String,
    },
}

impl Layer {
    pub fn title(&self) -> &'static str {
        match self {
            Layer::Ethernet { .. } => "Ethernet II",
            Layer::BsdLoopback { .. } => "Loopback",
            Layer::Ipv4 { .. } => "IPv4",
            Layer::Ipv6 { .. } => "IPv6",
            Layer::Arp { .. } => "ARP",
            Layer::Tcp { .. } => "TCP",
            Layer::Udp { .. } => "UDP",
            Layer::Icmp { .. } => "ICMP",
            Layer::Icmpv6 { .. } => "ICMPv6",
            Layer::Unknown { .. } => "Unknown",
        }
    }
}

#[derive(Clone, Default)]
pub struct Decoded {
    pub layers: Vec<Layer>,
    pub payload_offset: usize,
}

pub fn format_mac(m: &MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

pub fn tcp_flags_str(flags: u8) -> String {
    let mut out = Vec::new();
    if flags & 0x01 != 0 {
        out.push("FIN");
    }
    if flags & 0x02 != 0 {
        out.push("SYN");
    }
    if flags & 0x04 != 0 {
        out.push("RST");
    }
    if flags & 0x08 != 0 {
        out.push("PSH");
    }
    if flags & 0x10 != 0 {
        out.push("ACK");
    }
    if flags & 0x20 != 0 {
        out.push("URG");
    }
    if flags & 0x40 != 0 {
        out.push("ECE");
    }
    if flags & 0x80 != 0 {
        out.push("CWR");
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out.join(",")
    }
}
