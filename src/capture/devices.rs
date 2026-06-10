//! Per-device inventory: aggregates everything we learn about each host.
//!
//! A "host" is keyed by MAC when we know it (LAN devices), otherwise by IP
//! (remote internet hosts). When a later observation links a MAC to an IP we've
//! been tracking by IP, the two entries merge.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

use super::discovery::{
    mac_from_eui64, parse_dhcp_chaddr, parse_dhcp_hostname, parse_mdns, parse_nbns_name,
    parse_tls_sni, Hit, HitKind,
};
use super::model::{format_mac, CapturedPacket, Layer, MacAddr};
use super::oui;
use super::parser::{decode, LinkType};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum NameSource {
    /// Multicast DNS / Bonjour
    Mdns,
    /// DHCP option 12 hostname
    Dhcp,
    /// NetBIOS Name Service
    Nbns,
    /// TLS SNI (ClientHello)
    Sni,
    /// Reverse DNS lookup
    ReverseDns,
}

impl NameSource {
    pub fn label(self) -> &'static str {
        match self {
            NameSource::Mdns => "mDNS",
            NameSource::Dhcp => "DHCP",
            NameSource::Nbns => "NBNS",
            NameSource::Sni => "SNI",
            NameSource::ReverseDns => "rDNS",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum HostKey {
    Mac(MacAddr),
    Ip(IpAddr),
}

impl HostKey {
    pub fn pretty(&self) -> String {
        match self {
            HostKey::Mac(m) => format_mac(m),
            HostKey::Ip(ip) => ip.to_string(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Name,
    Vendor,
    Mac,
    Ip,
    Services,
    Packets,
    Bytes,
}

impl SortColumn {
    pub const ALL: [SortColumn; 7] = [
        SortColumn::Name,
        SortColumn::Vendor,
        SortColumn::Mac,
        SortColumn::Ip,
        SortColumn::Services,
        SortColumn::Packets,
        SortColumn::Bytes,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SortColumn::Name => "name",
            SortColumn::Vendor => "vendor",
            SortColumn::Mac => "mac",
            SortColumn::Ip => "ip",
            SortColumn::Services => "services",
            SortColumn::Packets => "packets",
            SortColumn::Bytes => "bytes",
        }
    }

    pub fn next(self) -> SortColumn {
        let i = Self::ALL.iter().position(|c| *c == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    /// Sensible default direction: text columns ascending, numeric columns descending.
    pub fn default_desc(self) -> bool {
        matches!(
            self,
            SortColumn::Services | SortColumn::Packets | SortColumn::Bytes
        )
    }
}

#[derive(Clone, Default)]
pub struct Host {
    pub mac: Option<MacAddr>,
    pub vendor: Option<&'static str>,
    pub ips: BTreeSet<IpAddr>,
    pub names: BTreeMap<String, NameSource>,
    pub services: BTreeSet<String>,
    pub first_seen_seq: u64,
    pub last_seen_seq: u64,
    pub first_seen_at: Option<Instant>,
    pub last_seen_at: Option<Instant>,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub history: Vec<DiscoveryNote>,
}

#[derive(Clone)]
pub struct DiscoveryNote {
    pub seq: u64,
    pub source: &'static str,
    pub detail: String,
}

impl Host {
    /// Best-effort display name: prefer the most authoritative source, fall back to IP/MAC.
    pub fn display_name(&self) -> String {
        if let Some(n) = self.preferred_name() {
            return n;
        }
        if let Some(ip) = self.primary_ip() {
            return ip.to_string();
        }
        if let Some(mac) = self.mac {
            return format_mac(&mac);
        }
        "(unknown)".into()
    }

    /// Best human-facing name for this device.
    ///
    /// mDNS exposes many strings for one host — the bare hostname (`MacBook-Xisca.local`),
    /// service instances (`MacBook Xisca._airplay._tcp.local`), AirPlay identity strings
    /// (`68CA…@MacBook Xisca`), and occasional junk (`0,1,2`). We want the clean hostname,
    /// not the shortest string. Strategy: prefer a `*.local` hostname that isn't a service
    /// instance; otherwise fall back to source priority while skipping service/junk names.
    pub fn preferred_name(&self) -> Option<String> {
        // 1. A clean mDNS hostname: ends in `.local`, not a service (`_x._tcp`) instance.
        let mut clean: Vec<&String> = self
            .names
            .keys()
            .filter(|n| n.ends_with(".local") && !n.starts_with('_') && !n.contains("._"))
            .collect();
        clean.sort_by_key(|n| (n.len(), n.as_str().to_owned()));
        if let Some(name) = clean.first() {
            return Some((*name).clone());
        }

        // 2. Fall back through source priority, skipping service instances and junk-ish names.
        use NameSource::*;
        for source in [Dhcp, Mdns, Nbns, ReverseDns, Sni] {
            let mut candidates: Vec<&String> = self
                .names
                .iter()
                .filter(|(_, &s)| s == source)
                .map(|(n, _)| n)
                .filter(|n| !n.starts_with('_') && !n.contains("._"))
                .collect();
            // Junk names (commas, '@' identity prefixes) sort last; then shortest wins.
            candidates.sort_by_key(|n| (looks_junky(n), n.len(), n.as_str().to_owned()));
            if let Some(name) = candidates.first() {
                return Some((*name).clone());
            }
        }
        None
    }

    pub fn primary_ip(&self) -> Option<IpAddr> {
        // Prefer IPv4 over IPv6 link-local.
        self.ips
            .iter()
            .find(|ip| matches!(ip, IpAddr::V4(_)) && !is_unspecified(ip))
            .or_else(|| self.ips.iter().find(|ip| !is_link_local_v6(ip)))
            .or_else(|| self.ips.iter().next())
            .copied()
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_in + self.packets_out
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }
}

/// True for names that read more like identifiers than human hostnames.
fn looks_junky(name: &str) -> bool {
    name.contains('@')
        || name.contains(',')
        || name.contains(' ') && name.chars().any(|c| c.is_ascii_digit())
}

fn is_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_unspecified(),
        IpAddr::V6(v) => v.is_unspecified(),
    }
}

fn is_link_local_v6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
}

#[derive(Default)]
pub struct HostInventory {
    pub hosts: HashMap<HostKey, Host>,
    by_ip: HashMap<IpAddr, HostKey>,
    pending_rdns: BTreeSet<IpAddr>,
}

impl HostInventory {
    pub fn observe(&mut self, link: LinkType, pkt: &CapturedPacket) {
        let (decoded, _) = decode(link, &pkt.data);
        let mut src_mac: Option<MacAddr> = None;
        let mut dst_mac: Option<MacAddr> = None;
        let mut src_ip: Option<IpAddr> = None;
        let mut dst_ip: Option<IpAddr> = None;
        let mut udp_ports: Option<(u16, u16)> = None;
        let mut tcp_ports: Option<(u16, u16)> = None;
        let mut payload_offset = decoded.payload_offset;

        for layer in &decoded.layers {
            match layer {
                Layer::Ethernet { src, dst, .. } => {
                    src_mac = Some(*src);
                    dst_mac = Some(*dst);
                }
                Layer::Ipv4 { src, dst, .. } => {
                    src_ip = Some(IpAddr::V4(*src));
                    dst_ip = Some(IpAddr::V4(*dst));
                }
                Layer::Ipv6 { src, dst, .. } => {
                    src_ip = Some(IpAddr::V6(*src));
                    dst_ip = Some(IpAddr::V6(*dst));
                }
                Layer::Udp {
                    src_port, dst_port, ..
                } => {
                    udp_ports = Some((*src_port, *dst_port));
                }
                Layer::Tcp {
                    src_port, dst_port, ..
                } => {
                    tcp_ports = Some((*src_port, *dst_port));
                }
                Layer::Arp {
                    sender_mac,
                    sender_ip,
                    target_mac,
                    target_ip,
                    ..
                } => {
                    // ARP gives us a confirmed (MAC, IP) pair.
                    self.note_pair(*sender_mac, IpAddr::V4(*sender_ip), pkt.seq);
                    if *target_mac != [0u8; 6] {
                        self.note_pair(*target_mac, IpAddr::V4(*target_ip), pkt.seq);
                    }
                    return;
                }
                _ => {}
            }
        }

        // Record the source host (the one originating this packet).
        let src_key = self.touch(src_mac, src_ip, pkt, /*outbound=*/ true);
        // Record the destination too — but don't credit "out" packets to it.
        let dst_key = self.touch(dst_mac, dst_ip, pkt, /*outbound=*/ false);

        // Application-layer discovery — only if we can locate the payload.
        if payload_offset >= pkt.data.len() {
            payload_offset = pkt.data.len();
        }
        let payload = &pkt.data[payload_offset..];

        if let Some((s, d)) = udp_ports {
            // mDNS — UDP/5353. Both queries and responses carry useful names, and in
            // both cases the originating device is the L2/L3 source, so credit src_key.
            if s == 5353 || d == 5353 {
                let hits = parse_mdns(payload);
                if let Some(key) = src_key {
                    self.apply_hits(&key, &hits, pkt.seq, NameSource::Mdns);
                }
            }
            // DHCP — client→server (68→67) carries the client hostname
            if s == 68 || d == 68 || s == 67 || d == 67 {
                if let Some(name) = parse_dhcp_hostname(payload) {
                    // Prefer keying by DHCP chaddr (the actual client MAC) over the L2 src.
                    let mac = parse_dhcp_chaddr(payload).or(src_mac);
                    let key = if let Some(m) = mac {
                        self.touch(Some(m), src_ip, pkt, true)
                            .unwrap_or(HostKey::Mac(m))
                    } else if let Some(k) = src_key {
                        k
                    } else {
                        return;
                    };
                    self.apply_name(&key, &name, NameSource::Dhcp, pkt.seq);
                }
            }
            // NetBIOS Name Service — UDP/137
            if s == 137 || d == 137 {
                if let Some(name) = parse_nbns_name(payload) {
                    if let Some(key) = src_key {
                        self.apply_name(&key, &name, NameSource::Nbns, pkt.seq);
                    }
                }
            }
        }

        // TLS SNI on TCP/443 (or any TCP — the parser is happy to be wrong)
        if let Some((_s, d)) = tcp_ports {
            if d == 443 || d == 8443 {
                if let Some(name) = parse_tls_sni(payload) {
                    // SNI describes the destination, not the source.
                    if let Some(key) = dst_key {
                        self.apply_name(&key, &name, NameSource::Sni, pkt.seq);
                    }
                }
            }
        }

        // IPv6 link-local → MAC heuristic.
        if let Some(IpAddr::V6(v6)) = src_ip {
            if let Some(mac) = mac_from_eui64(v6) {
                self.note_pair(mac, IpAddr::V6(v6), pkt.seq);
            }
        }
        if let Some(IpAddr::V6(v6)) = dst_ip {
            if let Some(mac) = mac_from_eui64(v6) {
                self.note_pair(mac, IpAddr::V6(v6), pkt.seq);
            }
        }

        // Queue unnamed remote IPs for reverse DNS.
        if let Some(ip) = dst_ip {
            if let Some(HostKey::Ip(_)) = dst_key {
                if needs_rdns(ip) {
                    self.pending_rdns.insert(ip);
                }
            }
        }
        if let Some(ip) = src_ip {
            if let Some(HostKey::Ip(_)) = src_key {
                if needs_rdns(ip) {
                    self.pending_rdns.insert(ip);
                }
            }
        }
    }

    fn touch(
        &mut self,
        mac: Option<MacAddr>,
        ip: Option<IpAddr>,
        pkt: &CapturedPacket,
        outbound: bool,
    ) -> Option<HostKey> {
        // Identity priority: MAC (when present) > IP. But if we already have a host indexed
        // by this IP, we want to *merge* under the MAC key when we learn it.
        let key = match (mac, ip) {
            (Some(m), Some(i)) => {
                // Merge any prior IP-keyed entry into the MAC-keyed one.
                let mac_key = HostKey::Mac(m);
                if let Some(existing) = self.by_ip.get(&i).copied() {
                    if existing != mac_key {
                        let prior = self.hosts.remove(&existing);
                        if let Some(p) = prior {
                            let merged = self.hosts.entry(mac_key).or_default();
                            merge_into(merged, p);
                        }
                    }
                }
                self.by_ip.insert(i, mac_key);
                let h = self.hosts.entry(mac_key).or_default();
                h.mac = Some(m);
                h.vendor = oui::lookup(&m);
                h.ips.insert(i);
                Some(mac_key)
            }
            (Some(m), None) => {
                let k = HostKey::Mac(m);
                let h = self.hosts.entry(k).or_default();
                h.mac = Some(m);
                h.vendor = oui::lookup(&m);
                Some(k)
            }
            (None, Some(i)) => {
                let key = self.by_ip.get(&i).copied().unwrap_or(HostKey::Ip(i));
                self.by_ip.insert(i, key);
                let h = self.hosts.entry(key).or_default();
                h.ips.insert(i);
                Some(key)
            }
            (None, None) => None,
        };

        if let Some(k) = key {
            if let Some(h) = self.hosts.get_mut(&k) {
                if h.first_seen_seq == 0 {
                    h.first_seen_seq = pkt.seq;
                    h.first_seen_at = Some(Instant::now());
                }
                h.last_seen_seq = pkt.seq;
                h.last_seen_at = Some(Instant::now());
                if outbound {
                    h.packets_out += 1;
                    h.bytes_out += pkt.wire_len as u64;
                } else {
                    h.packets_in += 1;
                    h.bytes_in += pkt.wire_len as u64;
                }
            }
        }

        key
    }

    fn note_pair(&mut self, mac: MacAddr, ip: IpAddr, seq: u64) {
        let mac_key = HostKey::Mac(mac);
        if let Some(existing) = self.by_ip.get(&ip).copied() {
            if existing != mac_key {
                if let Some(p) = self.hosts.remove(&existing) {
                    let merged = self.hosts.entry(mac_key).or_default();
                    merge_into(merged, p);
                }
            }
        }
        self.by_ip.insert(ip, mac_key);
        let h = self.hosts.entry(mac_key).or_default();
        h.mac = Some(mac);
        h.vendor = oui::lookup(&mac);
        h.ips.insert(ip);
        if h.first_seen_seq == 0 {
            h.first_seen_seq = seq;
            h.first_seen_at = Some(Instant::now());
        }
        h.last_seen_seq = seq;
        h.last_seen_at = Some(Instant::now());
    }

    fn apply_hits(&mut self, key: &HostKey, hits: &[Hit], seq: u64, source: NameSource) {
        let h = self.hosts.entry(*key).or_default();
        for hit in hits {
            match hit.kind {
                HitKind::Service => {
                    h.services.insert(hit.name.clone());
                }
                HitKind::Hostname => {
                    h.names.entry(hit.name.clone()).or_insert(source);
                }
            }
        }
        if !hits.is_empty() {
            h.history.push(DiscoveryNote {
                seq,
                source: source.label(),
                detail: format!(
                    "{} hits: {}",
                    hits.len(),
                    hits.iter()
                        .map(|x| x.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }

    fn apply_name(&mut self, key: &HostKey, name: &str, source: NameSource, seq: u64) {
        let h = self.hosts.entry(*key).or_default();
        h.names.entry(name.to_string()).or_insert(source);
        h.history.push(DiscoveryNote {
            seq,
            source: source.label(),
            detail: name.to_string(),
        });
    }

    pub fn apply_rdns(&mut self, ip: IpAddr, name: String) {
        let key = self.by_ip.get(&ip).copied().unwrap_or(HostKey::Ip(ip));
        let h = self.hosts.entry(key).or_default();
        if h.ips.is_empty() {
            h.ips.insert(ip);
        }
        h.names
            .entry(name.clone())
            .or_insert(NameSource::ReverseDns);
        h.history.push(DiscoveryNote {
            seq: 0,
            source: NameSource::ReverseDns.label(),
            detail: name,
        });
        self.pending_rdns.remove(&ip);
    }

    /// Pop up to `n` IPs that still need reverse DNS lookups.
    pub fn drain_pending_rdns(&mut self, n: usize) -> Vec<IpAddr> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(&ip) = self.pending_rdns.iter().next() {
                self.pending_rdns.remove(&ip);
                out.push(ip);
            } else {
                break;
            }
        }
        out
    }

    pub fn clear(&mut self) {
        self.hosts.clear();
        self.by_ip.clear();
        self.pending_rdns.clear();
    }

    pub fn count(&self) -> usize {
        self.hosts.len()
    }

    /// Hosts filtered then sorted by the chosen column/direction.
    /// A non-empty `filter` is matched case-insensitively against the display name,
    /// every IP, the MAC, the vendor, and the service list.
    pub fn ranked_filtered(
        &self,
        filter: &str,
        sort: SortColumn,
        desc: bool,
    ) -> Vec<(&HostKey, &Host)> {
        let needle = filter.trim().to_ascii_lowercase();
        let mut v: Vec<_> = self
            .hosts
            .iter()
            .filter(|(_, h)| needle.is_empty() || host_matches(h, &needle))
            .collect();
        v.sort_by(|a, b| {
            let ord = match sort {
                SortColumn::Name => {
                    a.1.display_name()
                        .to_ascii_lowercase()
                        .cmp(&b.1.display_name().to_ascii_lowercase())
                }
                SortColumn::Vendor => {
                    a.1.vendor
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .cmp(&b.1.vendor.unwrap_or("").to_ascii_lowercase())
                }
                SortColumn::Mac => a.1.mac.cmp(&b.1.mac),
                SortColumn::Ip => a.1.primary_ip().cmp(&b.1.primary_ip()),
                SortColumn::Services => a.1.services.len().cmp(&b.1.services.len()),
                SortColumn::Packets => a.1.total_packets().cmp(&b.1.total_packets()),
                SortColumn::Bytes => a.1.total_bytes().cmp(&b.1.total_bytes()),
            };
            let ord = if desc { ord.reverse() } else { ord };
            // Deterministic tiebreak so equal rows don't jitter between frames.
            ord.then_with(|| a.0.cmp(b.0))
        });
        v
    }

    /// Look up a host by its stable key (used by the detail view so it stays pinned to
    /// the chosen device even as live traffic re-orders the ranked list).
    pub fn get(&self, key: &HostKey) -> Option<&Host> {
        self.hosts.get(key)
    }
}

fn host_matches(h: &Host, needle: &str) -> bool {
    if h.display_name().to_ascii_lowercase().contains(needle) {
        return true;
    }
    if let Some(v) = h.vendor {
        if v.to_ascii_lowercase().contains(needle) {
            return true;
        }
    }
    if let Some(mac) = h.mac {
        if format_mac(&mac).contains(needle) {
            return true;
        }
    }
    if h.ips
        .iter()
        .any(|ip| ip.to_string().to_ascii_lowercase().contains(needle))
    {
        return true;
    }
    if h.names
        .keys()
        .any(|n| n.to_ascii_lowercase().contains(needle))
    {
        return true;
    }
    h.services
        .iter()
        .any(|s| s.to_ascii_lowercase().contains(needle))
}

fn merge_into(dst: &mut Host, src: Host) {
    if dst.mac.is_none() {
        dst.mac = src.mac;
    }
    if dst.vendor.is_none() {
        dst.vendor = src.vendor;
    }
    dst.ips.extend(src.ips);
    for (name, source) in src.names {
        dst.names.entry(name).or_insert(source);
    }
    dst.services.extend(src.services);
    if dst.first_seen_seq == 0
        || (src.first_seen_seq != 0 && src.first_seen_seq < dst.first_seen_seq)
    {
        dst.first_seen_seq = src.first_seen_seq;
        dst.first_seen_at = src.first_seen_at.or(dst.first_seen_at);
    }
    if src.last_seen_seq > dst.last_seen_seq {
        dst.last_seen_seq = src.last_seen_seq;
        dst.last_seen_at = src.last_seen_at.or(dst.last_seen_at);
    }
    dst.packets_in += src.packets_in;
    dst.packets_out += src.packets_out;
    dst.bytes_in += src.bytes_in;
    dst.bytes_out += src.bytes_out;
    dst.history.extend(src.history);
}

/// Should we attempt reverse DNS for this IP?
fn needs_rdns(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_loopback()
                && !v.is_broadcast()
                && !v.is_multicast()
                && !v.is_unspecified()
                && !v.is_link_local()
        }
        IpAddr::V6(v) => {
            !v.is_loopback() && !v.is_multicast() && !v.is_unspecified() && !is_v6_link_local(v)
        }
    }
}

fn is_v6_link_local(v: Ipv6Addr) -> bool {
    v.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::model::PacketSummary;
    use std::time::Duration;

    fn eth_ipv4_udp(src_mac: MacAddr, src_port: u16, dst_port: u16, app: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xff; 6]); // dst mac (broadcast)
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4
                                              // IPv4 header (20)
        pkt.push(0x45);
        pkt.push(0x00);
        let total = (20 + 8 + app.len()) as u16;
        pkt.extend_from_slice(&total.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.push(0x40);
        pkt.push(17); // UDP
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&[10, 0, 0, 5]);
        pkt.extend_from_slice(&[224, 0, 0, 251]);
        // UDP header (8)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&((8 + app.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(app);
        pkt
    }

    fn packet(data: Vec<u8>) -> CapturedPacket {
        let wire_len = data.len();
        CapturedPacket {
            seq: 1,
            ts: Duration::from_millis(0),
            wire_len,
            data,
            summary: PacketSummary {
                src: String::new(),
                dst: String::new(),
                protocol: "?",
                info: String::new(),
            },
        }
    }

    /// End-to-end: an mDNS query for a service must surface that service on the source device.
    /// This is the regression test for the payload-offset bug.
    #[test]
    fn mdns_service_reaches_inventory() {
        // DNS: header + one PTR question for "_airplay._tcp.local"
        let mut dns = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        dns.push(8);
        dns.extend_from_slice(b"_airplay");
        dns.push(4);
        dns.extend_from_slice(b"_tcp");
        dns.push(5);
        dns.extend_from_slice(b"local");
        dns.push(0);
        dns.extend_from_slice(&[0x00, 0x0c]); // PTR
        dns.extend_from_slice(&[0x00, 0x01]); // IN

        let mac = [0xb8, 0x53, 0xac, 0x01, 0x02, 0x03];
        let pkt = packet(eth_ipv4_udp(mac, 5353, 5353, &dns));

        let mut inv = HostInventory::default();
        inv.observe(LinkType::Ethernet, &pkt);

        let host = inv.hosts.get(&HostKey::Mac(mac)).expect("device created");
        assert_eq!(host.vendor, Some("Apple"));
        assert!(
            host.services.iter().any(|s| s.contains("_airplay")),
            "expected _airplay service, got {:?}",
            host.services
        );
    }

    /// preferred_name must pick the clean `.local` hostname, not the shortest junk string.
    #[test]
    fn preferred_name_prefers_clean_hostname() {
        let mut h = Host::default();
        for n in [
            "0,1,2",
            "68CAC4A30309@MacBook Xisca",
            "MacBook Xisca._airplay._tcp.local",
            "MacBook-Xisca.local",
        ] {
            h.names.insert(n.to_string(), NameSource::Mdns);
        }
        assert_eq!(h.preferred_name().as_deref(), Some("MacBook-Xisca.local"));
    }

    /// With no `.local` hostname, fall back to a non-junk DHCP/mDNS name (not `0,1,2`).
    #[test]
    fn preferred_name_skips_junk_when_no_local() {
        let mut h = Host::default();
        h.names.insert("0,1,2".to_string(), NameSource::Mdns);
        h.names
            .insert("MacBook Xisca".to_string(), NameSource::Mdns);
        assert_eq!(h.preferred_name().as_deref(), Some("MacBook Xisca"));
    }

    #[test]
    fn sort_by_bytes_and_name() {
        let mut inv = HostInventory::default();
        let mut a = Host::default();
        a.mac = Some([1, 0, 0, 0, 0, 0]);
        a.bytes_out = 100;
        a.names.insert("zeta.local".into(), NameSource::Mdns);
        let mut b = Host::default();
        b.mac = Some([2, 0, 0, 0, 0, 0]);
        b.bytes_out = 5000;
        b.names.insert("alpha.local".into(), NameSource::Mdns);
        inv.hosts.insert(HostKey::Mac([1, 0, 0, 0, 0, 0]), a);
        inv.hosts.insert(HostKey::Mac([2, 0, 0, 0, 0, 0]), b);

        // Bytes desc → b (5000) first.
        let by_bytes = inv.ranked_filtered("", SortColumn::Bytes, true);
        assert_eq!(by_bytes[0].1.display_name(), "alpha.local"); // b has more bytes

        // Name asc → alpha before zeta.
        let by_name = inv.ranked_filtered("", SortColumn::Name, false);
        assert_eq!(by_name[0].1.display_name(), "alpha.local");
        assert_eq!(by_name[1].1.display_name(), "zeta.local");

        // Name desc → zeta first.
        let by_name_desc = inv.ranked_filtered("", SortColumn::Name, true);
        assert_eq!(by_name_desc[0].1.display_name(), "zeta.local");
    }
}
