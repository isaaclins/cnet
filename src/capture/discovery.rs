//! Extract device names + services from observed packet payloads.
//!
//! Sources:
//! - mDNS responses (UDP/5353): hostnames + advertised services
//! - DHCP requests (UDP/68→67) option 12: device hostname
//! - NetBIOS Name Service (UDP/137): Windows machine names
//! - TLS ClientHello SNI extension (TCP/443+): remote hostnames

use std::net::Ipv6Addr;

use super::model::MacAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub name: String,
    pub kind: HitKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HitKind {
    /// A device hostname (`bobs-iphone.local`, `BOBSPC`).
    Hostname,
    /// An mDNS service advertisement (`_airplay._tcp.local`).
    Service,
}

/// Parse an mDNS (UDP/5353) payload — both queries and responses contain useful names.
pub fn parse_mdns(payload: &[u8]) -> Vec<Hit> {
    let mut out = Vec::new();
    let Ok(msg) = DnsMessage::parse(payload) else {
        return out;
    };

    for q in &msg.questions {
        for n in interesting_names(&q.name) {
            out.push(Hit {
                name: n,
                kind: classify(&q.name),
            });
        }
    }
    for r in msg.records() {
        for n in interesting_names(&r.name) {
            out.push(Hit {
                name: n,
                kind: classify(&r.name),
            });
        }
        // SRV records embed the target hostname.
        if r.rtype == 33 && r.data.len() >= 7 {
            // priority(2) weight(2) port(2) then target name
            let mut pos = 6;
            if let Ok((target, _)) = read_name(payload, r.data, &mut pos) {
                if !target.is_empty() {
                    out.push(Hit {
                        name: target,
                        kind: HitKind::Hostname,
                    });
                }
            }
        }
        // TXT records sometimes have human-readable names.
        if r.rtype == 16 {
            for txt in parse_txt(r.data) {
                if let Some(name) = txt
                    .strip_prefix("name=")
                    .or_else(|| txt.strip_prefix("md="))
                {
                    let trimmed = name.trim();
                    if !trimmed.is_empty() && trimmed.len() <= 80 {
                        out.push(Hit {
                            name: trimmed.to_string(),
                            kind: HitKind::Hostname,
                        });
                    }
                }
            }
        }
    }

    dedup(out)
}

fn classify(name: &str) -> HitKind {
    if name.starts_with('_') {
        HitKind::Service
    } else {
        HitKind::Hostname
    }
}

fn interesting_names(name: &str) -> Vec<String> {
    let n = name.trim_end_matches('.');
    if n.is_empty() {
        return vec![];
    }
    if n.starts_with('_') {
        // service type — keep as-is for "services" set
        return vec![n.to_string()];
    }
    // Strip the leading instance label of a service instance name
    // (e.g. "iPhone-of-Bob._device-info._tcp.local" → take "iPhone-of-Bob")
    if let Some(idx) = n.find("._") {
        let before = &n[..idx];
        if !before.is_empty() {
            return vec![before.to_string(), n.to_string()];
        }
    }
    vec![n.to_string()]
}

fn parse_txt(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&data[i..i + len]) {
            out.push(s.to_string());
        }
        i += len;
    }
    out
}

fn dedup(mut hits: Vec<Hit>) -> Vec<Hit> {
    hits.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)))
    });
    hits.dedup_by(|a, b| a.name == b.name && a.kind == b.kind);
    hits
}

// ─────────────────────────── DHCP option 12 ───────────────────────────

/// Parse a DHCP message payload; returns the hostname (option 12) if present.
pub fn parse_dhcp_hostname(payload: &[u8]) -> Option<String> {
    if payload.len() < 240 {
        return None;
    }
    // op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2) ciaddr(4) yiaddr(4) siaddr(4) giaddr(4)
    // chaddr(16) sname(64) file(128) magic(4 = 0x63825363) then options
    let magic = &payload[236..240];
    if magic != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }
    let mut i = 240;
    while i < payload.len() {
        let code = payload[i];
        i += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        if i >= payload.len() {
            break;
        }
        let len = payload[i] as usize;
        i += 1;
        if i + len > payload.len() {
            break;
        }
        if code == 12 {
            if let Ok(s) = std::str::from_utf8(&payload[i..i + len]) {
                let s = s.trim().trim_end_matches('\0');
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        i += len;
    }
    None
}

/// Extract the client MAC (chaddr) from a DHCP payload.
pub fn parse_dhcp_chaddr(payload: &[u8]) -> Option<MacAddr> {
    if payload.len() < 34 {
        return None;
    }
    let hlen = payload[2] as usize;
    if hlen != 6 {
        return None;
    }
    let mut m = [0u8; 6];
    m.copy_from_slice(&payload[28..34]);
    Some(m)
}

// ─────────────────────────── NetBIOS Name Service ───────────────────────────

/// Parse a NBNS query/response; returns the (decoded) NetBIOS name if present.
pub fn parse_nbns_name(payload: &[u8]) -> Option<String> {
    // header(12) then question/answer with name field
    if payload.len() < 13 + 32 {
        return None;
    }
    // The name field at offset 12 starts with length byte = 0x20 (32), then 32 encoded chars.
    if payload[12] != 0x20 {
        return None;
    }
    let encoded = &payload[13..13 + 32];
    let mut decoded = [0u8; 16];
    for i in 0..16 {
        let a = encoded[i * 2];
        let b = encoded[i * 2 + 1];
        if !(b'A'..=b'P').contains(&a) || !(b'A'..=b'P').contains(&b) {
            return None;
        }
        decoded[i] = ((a - b'A') << 4) | (b - b'A');
    }
    // First 15 bytes are the name; byte 16 is the resource type. Trim trailing spaces.
    let raw = &decoded[..15];
    let name: String = raw
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .map(|&b| b as char)
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ─────────────────────────── TLS SNI ───────────────────────────

/// Parse a TLS ClientHello payload (TCP segment payload, after TCP header);
/// returns the SNI host name if present.
pub fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS record header: type(1)=22, version(2), length(2)
    if payload.len() < 5 || payload[0] != 22 {
        return None;
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let body = &payload[5..5 + rec_len.min(payload.len() - 5)];

    // Handshake: type(1)=1 ClientHello, length(3), body...
    if body.len() < 4 || body[0] != 1 {
        return None;
    }
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    let hs = &body[4..4 + hs_len.min(body.len() - 4)];

    // ClientHello body: version(2), random(32), session_id_len(1), session_id,
    // cipher_suites_len(2), cipher_suites, compression_methods_len(1), compression_methods,
    // extensions_len(2), extensions
    let mut p = 0;
    if hs.len() < 2 + 32 + 1 {
        return None;
    }
    p += 2 + 32;
    let sid_len = hs[p] as usize;
    p += 1 + sid_len;
    if hs.len() < p + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2 + cs_len;
    if hs.len() < p + 1 {
        return None;
    }
    let cm_len = hs[p] as usize;
    p += 1 + cm_len;
    if hs.len() < p + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2;

    let ext_end = (p + ext_len).min(hs.len());
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let elen = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        if p + elen > ext_end {
            return None;
        }
        if etype == 0 {
            // SNI: list_len(2), then entries: name_type(1)=0, name_len(2), name
            if elen < 5 {
                return None;
            }
            let _list_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
            let mut q = p + 2;
            while q + 3 <= p + elen {
                let nt = hs[q];
                let nl = u16::from_be_bytes([hs[q + 1], hs[q + 2]]) as usize;
                q += 3;
                if q + nl > p + elen {
                    return None;
                }
                if nt == 0 {
                    if let Ok(s) = std::str::from_utf8(&hs[q..q + nl]) {
                        return Some(s.to_string());
                    }
                }
                q += nl;
            }
        }
        p += elen;
    }
    None
}

// ─────────────────────────── IPv6 link-local → MAC (EUI-64) ───────────────────────────

/// If `ip` is an EUI-64-derived IPv6 address (fe80::… or any unicast address with the
/// `ff:fe` middle marker), recover the underlying 48-bit MAC. Returns None for modern
/// stable-privacy addresses.
pub fn mac_from_eui64(ip: Ipv6Addr) -> Option<MacAddr> {
    let s = ip.segments();
    // Bottom 64 bits = bytes 8..15. EUI-64 has `ff fe` injected at bytes 11/12.
    let byte11 = (s[5] & 0xff) as u8;
    let byte12 = (s[6] >> 8) as u8;
    if byte11 != 0xff || byte12 != 0xfe {
        return None;
    }
    let byte8 = (s[4] >> 8) as u8;
    let byte9 = (s[4] & 0xff) as u8;
    let byte10 = (s[5] >> 8) as u8;
    let byte13 = (s[6] & 0xff) as u8;
    let byte14 = (s[7] >> 8) as u8;
    let byte15 = (s[7] & 0xff) as u8;

    // Flip the universal/local bit in the first byte.
    let first = byte8 ^ 0x02;
    Some([first, byte9, byte10, byte13, byte14, byte15])
}

// ─────────────────────────── tiny DNS-message parser ───────────────────────────

struct DnsMessage<'a> {
    payload: &'a [u8],
    an: u16,
    ns: u16,
    ar: u16,
    questions: Vec<DnsQuestion>,
    records_start: usize,
}

struct DnsQuestion {
    name: String,
}

struct DnsRecord<'a> {
    name: String,
    rtype: u16,
    data: &'a [u8],
}

impl<'a> DnsMessage<'a> {
    fn parse(payload: &'a [u8]) -> Result<Self, ()> {
        if payload.len() < 12 {
            return Err(());
        }
        let qd = u16::from_be_bytes([payload[4], payload[5]]);
        let an = u16::from_be_bytes([payload[6], payload[7]]);
        let ns = u16::from_be_bytes([payload[8], payload[9]]);
        let ar = u16::from_be_bytes([payload[10], payload[11]]);

        let mut p = 12;
        let mut questions = Vec::with_capacity(qd.min(64) as usize);
        for _ in 0..qd.min(64) {
            let (name, _new_p) = read_name(payload, payload, &mut p)?;
            if p + 4 > payload.len() {
                return Err(());
            }
            p += 4; // qtype + qclass
            questions.push(DnsQuestion { name });
        }

        Ok(DnsMessage {
            payload,
            an,
            ns,
            ar,
            questions,
            records_start: p,
        })
    }

    fn records(&self) -> Vec<DnsRecord<'a>> {
        let mut out = Vec::new();
        let mut p = self.records_start;
        let total = self.an as usize + self.ns as usize + self.ar as usize;
        for _ in 0..total.min(256) {
            let (name, _) = match read_name(self.payload, self.payload, &mut p) {
                Ok(v) => v,
                Err(_) => return out,
            };
            if p + 10 > self.payload.len() {
                return out;
            }
            let rtype = u16::from_be_bytes([self.payload[p], self.payload[p + 1]]);
            p += 8; // type(2) class(2) ttl(4)
            let rdlen = u16::from_be_bytes([self.payload[p], self.payload[p + 1]]) as usize;
            p += 2;
            if p + rdlen > self.payload.len() {
                return out;
            }
            out.push(DnsRecord {
                name,
                rtype,
                data: &self.payload[p..p + rdlen],
            });
            p += rdlen;
        }
        out
    }
}

/// Read a DNS-encoded name (with compression pointers) starting at *pos in `slice`.
/// `whole` is the original packet (for resolving pointers). Updates *pos past the name.
fn read_name<'a>(whole: &'a [u8], slice: &'a [u8], pos: &mut usize) -> Result<(String, usize), ()> {
    let mut out = String::new();
    let mut p = *pos;
    let mut steps = 0;

    loop {
        if p >= slice.len() {
            return Err(());
        }
        let len = slice[p];
        if len == 0 {
            p += 1;
            *pos = p;
            return Ok((out, p));
        }
        if (len & 0xC0) == 0xC0 {
            // Pointer — resolve from `whole`, then return to the position after the 2-byte pointer.
            if p + 1 >= slice.len() {
                return Err(());
            }
            let off = (((len & 0x3F) as usize) << 8) | (slice[p + 1] as usize);
            let after = p + 2;
            return read_name_from(whole, off, out, after, pos);
        }
        let len = len as usize;
        if p + 1 + len > slice.len() {
            return Err(());
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&slice[p + 1..p + 1 + len]));
        p += 1 + len;
        steps += 1;
        if steps > 128 {
            return Err(());
        }
    }
}

fn read_name_from(
    whole: &[u8],
    mut p: usize,
    mut out: String,
    after: usize,
    pos: &mut usize,
) -> Result<(String, usize), ()> {
    let mut steps = 0;
    loop {
        if p >= whole.len() {
            return Err(());
        }
        let len = whole[p];
        if len == 0 {
            *pos = after;
            return Ok((out, p + 1));
        }
        if (len & 0xC0) == 0xC0 {
            if p + 1 >= whole.len() {
                return Err(());
            }
            let off = (((len & 0x3F) as usize) << 8) | (whole[p + 1] as usize);
            p = off;
            steps += 1;
            if steps > 128 {
                return Err(());
            }
            continue;
        }
        let len = len as usize;
        if p + 1 + len > whole.len() {
            return Err(());
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&whole[p + 1..p + 1 + len]));
        p += 1 + len;
        steps += 1;
        if steps > 128 {
            return Err(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dhcp_hostname() {
        let mut p = vec![0u8; 240];
        p[0] = 1;
        p[2] = 6; // op, hlen
        p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        // Add option 12 = "myhost"
        p.extend_from_slice(&[12, 6, b'm', b'y', b'h', b'o', b's', b't', 255]);
        assert_eq!(parse_dhcp_hostname(&p), Some("myhost".to_string()));
    }

    #[test]
    fn decodes_nbns_name() {
        // Construct an NBNS query with name "BOBPC          " (15 chars + spaces)
        let raw = b"BOBPC          \x00";
        let mut encoded = [0u8; 32];
        for (i, &b) in raw.iter().enumerate() {
            encoded[i * 2] = b'A' + ((b >> 4) & 0xF);
            encoded[i * 2 + 1] = b'A' + (b & 0xF);
        }
        let mut p = vec![0u8; 12];
        p.push(0x20);
        p.extend_from_slice(&encoded);
        assert_eq!(parse_nbns_name(&p), Some("BOBPC".to_string()));
    }

    #[test]
    fn eui64_recovers_mac() {
        // fe80::b89b:baff:fe4a:0aa8 → ba:9b:ba:4a:0a:a8
        let ip: Ipv6Addr = "fe80::b89b:baff:fe4a:aa8".parse().unwrap();
        assert_eq!(
            mac_from_eui64(ip),
            Some([0xba, 0x9b, 0xba, 0x4a, 0x0a, 0xa8])
        );
    }

    #[test]
    fn eui64_rejects_privacy() {
        // No ff:fe in the middle → not EUI-64.
        let ip: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
        assert_eq!(mac_from_eui64(ip), None);
    }
}
