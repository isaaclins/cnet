use std::net::{Ipv4Addr, Ipv6Addr};

use super::model::{Decoded, Layer, MacAddr, PacketSummary};

/// Link types we understand.
#[derive(Clone, Copy)]
pub enum LinkType {
    Ethernet,
    BsdLoopback,
    Raw,
    Other,
}

impl LinkType {
    pub fn from_pcap(lt: pcap::Linktype) -> Self {
        match lt.0 {
            1 => LinkType::Ethernet,
            0 => LinkType::BsdLoopback,
            12 | 14 | 101 => LinkType::Raw,
            _ => LinkType::Other,
        }
    }
}

/// Decode a raw frame. `dec.payload_offset` is set to the absolute byte offset of the
/// innermost application payload (past all L2/L3/L4 headers), or `bytes.len()` when there
/// is no application payload (ARP, unknown ethertype, truncated headers).
pub fn decode(link: LinkType, bytes: &[u8]) -> (Decoded, PacketSummary) {
    let mut dec = Decoded::default();
    let mut summary = PacketSummary {
        src: "?".into(),
        dst: "?".into(),
        protocol: "?",
        info: String::new(),
    };

    let next = match link {
        LinkType::Ethernet => parse_ethernet(bytes, &mut dec),
        LinkType::BsdLoopback => parse_bsd_loopback(bytes, &mut dec),
        LinkType::Raw => Some((0usize, 0x0800u16)),
        LinkType::Other => None,
    };

    let Some((base, ethertype)) = next else {
        dec.payload_offset = bytes.len();
        summary.protocol = "RAW";
        summary.info = format!("{} bytes (unsupported link-layer)", bytes.len());
        return (dec, summary);
    };

    // Default: no app payload unless an L4 parser advances it.
    dec.payload_offset = bytes.len();

    match ethertype {
        0x0800 => parse_ipv4(bytes, base, &mut dec, &mut summary),
        0x86DD => parse_ipv6(bytes, base, &mut dec, &mut summary),
        0x0806 => parse_arp(&bytes[base.min(bytes.len())..], &mut dec, &mut summary),
        et => {
            dec.layers.push(Layer::Unknown {
                label: format!("EtherType 0x{:04x}", et),
            });
            summary.protocol = "ETH";
            summary.info = format!("EtherType 0x{:04x}, {} bytes", et, bytes.len());
        }
    }

    (dec, summary)
}

/// Returns (offset where L3 begins, ethertype).
fn parse_ethernet(b: &[u8], dec: &mut Decoded) -> Option<(usize, u16)> {
    if b.len() < 14 {
        return None;
    }
    let mut dst: MacAddr = [0; 6];
    let mut src: MacAddr = [0; 6];
    dst.copy_from_slice(&b[0..6]);
    src.copy_from_slice(&b[6..12]);
    let ethertype = u16::from_be_bytes([b[12], b[13]]);
    dec.layers.push(Layer::Ethernet {
        src,
        dst,
        ethertype,
    });
    Some((14, ethertype))
}

/// BSD loopback link has a 4-byte AF_* family value (host order).
fn parse_bsd_loopback(b: &[u8], dec: &mut Decoded) -> Option<(usize, u16)> {
    if b.len() < 4 {
        return None;
    }
    let family = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    dec.layers.push(Layer::BsdLoopback { family });
    let ethertype = match family {
        2 => 0x0800,            // AF_INET
        24 | 28 | 30 => 0x86DD, // AF_INET6 across BSDs
        _ => 0,
    };
    Some((4, ethertype))
}

fn parse_ipv4(bytes: &[u8], base: usize, dec: &mut Decoded, summary: &mut PacketSummary) {
    let b = &bytes[base.min(bytes.len())..];
    if b.len() < 20 {
        summary.protocol = "IPv4";
        summary.info = "truncated".into();
        return;
    }
    let ihl = ((b[0] & 0x0F) as usize) * 4;
    if ihl < 20 || b.len() < ihl {
        summary.protocol = "IPv4";
        summary.info = "bad IHL".into();
        return;
    }
    let total_len = u16::from_be_bytes([b[2], b[3]]);
    let ttl = b[8];
    let proto = b[9];
    let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    summary.src = src.to_string();
    summary.dst = dst.to_string();
    dec.layers.push(Layer::Ipv4 {
        src,
        dst,
        proto,
        ttl,
        total_len,
    });

    let l4_base = base + ihl;
    match proto {
        6 => parse_tcp(bytes, l4_base, dec, summary),
        17 => parse_udp(bytes, l4_base, dec, summary),
        1 => parse_icmp(bytes, l4_base, dec, summary),
        58 => parse_icmpv6(bytes, l4_base, dec, summary),
        p => {
            summary.protocol = "IPv4";
            summary.info = format!("proto {p}, {} bytes", b.len().saturating_sub(ihl));
        }
    }
}

fn parse_ipv6(bytes: &[u8], base: usize, dec: &mut Decoded, summary: &mut PacketSummary) {
    let b = &bytes[base.min(bytes.len())..];
    if b.len() < 40 {
        summary.protocol = "IPv6";
        summary.info = "truncated".into();
        return;
    }
    let payload_len = u16::from_be_bytes([b[4], b[5]]);
    let next_header = b[6];
    let hop_limit = b[7];
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    s.copy_from_slice(&b[8..24]);
    d.copy_from_slice(&b[24..40]);
    let src = Ipv6Addr::from(s);
    let dst = Ipv6Addr::from(d);
    summary.src = src.to_string();
    summary.dst = dst.to_string();
    dec.layers.push(Layer::Ipv6 {
        src,
        dst,
        next_header,
        hop_limit,
        payload_len,
    });

    let l4_base = base + 40;
    match next_header {
        6 => parse_tcp(bytes, l4_base, dec, summary),
        17 => parse_udp(bytes, l4_base, dec, summary),
        58 => parse_icmpv6(bytes, l4_base, dec, summary),
        p => {
            summary.protocol = "IPv6";
            summary.info = format!("next-header {p}, {} bytes", b.len().saturating_sub(40));
        }
    }
}

fn parse_arp(b: &[u8], dec: &mut Decoded, summary: &mut PacketSummary) {
    if b.len() < 28 {
        summary.protocol = "ARP";
        summary.info = "truncated".into();
        return;
    }
    let op = u16::from_be_bytes([b[6], b[7]]);
    let mut smac = [0u8; 6];
    let mut tmac = [0u8; 6];
    smac.copy_from_slice(&b[8..14]);
    tmac.copy_from_slice(&b[18..24]);
    let sip = Ipv4Addr::new(b[14], b[15], b[16], b[17]);
    let tip = Ipv4Addr::new(b[24], b[25], b[26], b[27]);
    summary.protocol = "ARP";
    summary.src = sip.to_string();
    summary.dst = tip.to_string();
    summary.info = match op {
        1 => format!("Who has {tip}? Tell {sip}"),
        2 => format!("{sip} is at {}", super::model::format_mac(&smac)),
        _ => format!("op {op}"),
    };
    dec.layers.push(Layer::Arp {
        op,
        sender_mac: smac,
        sender_ip: sip,
        target_mac: tmac,
        target_ip: tip,
    });
}

fn parse_tcp(bytes: &[u8], base: usize, dec: &mut Decoded, summary: &mut PacketSummary) {
    let b = &bytes[base.min(bytes.len())..];
    if b.len() < 20 {
        summary.protocol = "TCP";
        summary.info = "truncated".into();
        return;
    }
    let src_port = u16::from_be_bytes([b[0], b[1]]);
    let dst_port = u16::from_be_bytes([b[2], b[3]]);
    let seq = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    let ack = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
    let data_offset = ((b[12] >> 4) as usize) * 4;
    let flags = b[13];
    let window = u16::from_be_bytes([b[14], b[15]]);
    let payload_len = b.len().saturating_sub(data_offset);
    dec.layers.push(Layer::Tcp {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload_len,
    });
    // App payload starts after the (variable-length) TCP header.
    dec.payload_offset = (base + data_offset).min(bytes.len());
    summary.protocol = "TCP";
    summary.src = format!("{}:{}", summary.src, src_port);
    summary.dst = format!("{}:{}", summary.dst, dst_port);
    summary.info = format!(
        "{src_port} → {dst_port} [{}] Seq={seq} Win={window} Len={payload_len}",
        super::model::tcp_flags_str(flags)
    );
}

fn parse_udp(bytes: &[u8], base: usize, dec: &mut Decoded, summary: &mut PacketSummary) {
    let b = &bytes[base.min(bytes.len())..];
    if b.len() < 8 {
        summary.protocol = "UDP";
        summary.info = "truncated".into();
        return;
    }
    let src_port = u16::from_be_bytes([b[0], b[1]]);
    let dst_port = u16::from_be_bytes([b[2], b[3]]);
    let length = u16::from_be_bytes([b[4], b[5]]);
    let payload_len = b.len().saturating_sub(8);
    dec.layers.push(Layer::Udp {
        src_port,
        dst_port,
        length,
        payload_len,
    });
    // App payload starts after the fixed 8-byte UDP header.
    dec.payload_offset = (base + 8).min(bytes.len());
    summary.src = format!("{}:{}", summary.src, src_port);
    summary.dst = format!("{}:{}", summary.dst, dst_port);

    // App-layer hints by port.
    summary.protocol = match (src_port, dst_port) {
        (53, _) | (_, 53) => "DNS",
        (67, 68) | (68, 67) => "DHCP",
        (5353, _) | (_, 5353) => "mDNS",
        (123, _) | (_, 123) => "NTP",
        _ => "UDP",
    };
    summary.info = format!("{src_port} → {dst_port} Len={payload_len}");
}

fn parse_icmp(bytes: &[u8], base: usize, dec: &mut Decoded, summary: &mut PacketSummary) {
    let b = &bytes[base.min(bytes.len())..];
    if b.len() < 4 {
        summary.protocol = "ICMP";
        summary.info = "truncated".into();
        return;
    }
    let type_ = b[0];
    let code = b[1];
    dec.layers.push(Layer::Icmp { type_, code });
    summary.protocol = "ICMP";
    summary.info = match type_ {
        0 => "Echo Reply".to_string(),
        3 => format!("Destination Unreachable (code {code})"),
        8 => "Echo Request".to_string(),
        11 => "Time Exceeded".to_string(),
        t => format!("type {t}, code {code}"),
    };
}

fn parse_icmpv6(bytes: &[u8], base: usize, dec: &mut Decoded, summary: &mut PacketSummary) {
    let b = &bytes[base.min(bytes.len())..];
    if b.len() < 4 {
        summary.protocol = "ICMPv6";
        summary.info = "truncated".into();
        return;
    }
    let type_ = b[0];
    let code = b[1];
    dec.layers.push(Layer::Icmpv6 { type_, code });
    summary.protocol = "ICMPv6";
    summary.info = match type_ {
        128 => "Echo Request".into(),
        129 => "Echo Reply".into(),
        133 => "Router Solicitation".into(),
        134 => "Router Advertisement".into(),
        135 => "Neighbor Solicitation".into(),
        136 => "Neighbor Advertisement".into(),
        t => format!("type {t}, code {code}"),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build Ethernet + IPv4 + UDP and confirm payload_offset lands on the UDP payload.
    #[test]
    fn payload_offset_points_at_udp_payload() {
        let mut pkt = Vec::new();
        // Ethernet (14)
        pkt.extend_from_slice(&[0xff; 6]); // dst
        pkt.extend_from_slice(&[0x11; 6]); // src
        pkt.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
                                              // IPv4 (20)
        pkt.push(0x45); // version+ihl
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x29]); // total len (41)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.push(0x40); // ttl
        pkt.push(17); // proto UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src ip
        pkt.extend_from_slice(&[224, 0, 0, 251]); // dst ip
                                                  // UDP (8)
        pkt.extend_from_slice(&[0x14, 0xe9]); // src port 5353
        pkt.extend_from_slice(&[0x14, 0xe9]); // dst port 5353
        pkt.extend_from_slice(&[0x00, 0x0d]); // length
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
                                              // payload (5)
        pkt.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x42]);

        let (dec, summary) = decode(LinkType::Ethernet, &pkt);
        assert_eq!(dec.payload_offset, 14 + 20 + 8);
        assert_eq!(&pkt[dec.payload_offset..], &[0xde, 0xad, 0xbe, 0xef, 0x42]);
        assert_eq!(summary.protocol, "mDNS");
    }

    #[test]
    fn arp_has_no_app_payload() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xff; 6]);
        pkt.extend_from_slice(&[0x11; 6]);
        pkt.extend_from_slice(&[0x08, 0x06]); // ARP
        pkt.extend_from_slice(&[0u8; 28]);
        let (dec, summary) = decode(LinkType::Ethernet, &pkt);
        assert_eq!(summary.protocol, "ARP");
        assert_eq!(dec.payload_offset, pkt.len());
    }
}
