//! Translate user-friendly filter syntax to BPF.
//!
//! BPF is what libpcap expects (`tcp port 443`, `arp`, `host 1.2.3.4`). Users coming from
//! Wireshark often type display-filter syntax (`proto=ARP`, `ip.addr==1.2.3.4`,
//! `tcp.port==443`). This pass rewrites those tokens so both work.

use std::sync::OnceLock;

use regex::Regex;

fn op_normalize() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\s*==?\s*").unwrap())
}

pub fn translate(input: &str) -> String {
    let s = input.trim();
    if s.is_empty() {
        return String::new();
    }

    // Collapse `==` / `=` with surrounding whitespace down to `=` so prefix-strip works.
    let s = op_normalize().replace_all(s, "=").to_string();
    let s = s.replace("&&", " and ").replace("||", " or ");

    s.split_whitespace()
        .map(translate_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn translate_token(tok: &str) -> String {
    // Wireshark-style display fields → BPF
    if let Some(rest) = tok
        .strip_prefix("proto=")
        .or_else(|| tok.strip_prefix("protocol="))
    {
        return rest.to_ascii_lowercase();
    }
    if let Some(rest) = tok
        .strip_prefix("ip.addr=")
        .or_else(|| tok.strip_prefix("addr="))
    {
        return format!("host {rest}");
    }
    if let Some(rest) = tok
        .strip_prefix("ip.src=")
        .or_else(|| tok.strip_prefix("src="))
    {
        return format!("src host {rest}");
    }
    if let Some(rest) = tok
        .strip_prefix("ip.dst=")
        .or_else(|| tok.strip_prefix("dst="))
    {
        return format!("dst host {rest}");
    }
    if let Some(rest) = tok.strip_prefix("tcp.port=") {
        return format!("tcp port {rest}");
    }
    if let Some(rest) = tok.strip_prefix("tcp.srcport=") {
        return format!("tcp src port {rest}");
    }
    if let Some(rest) = tok.strip_prefix("tcp.dstport=") {
        return format!("tcp dst port {rest}");
    }
    if let Some(rest) = tok.strip_prefix("udp.port=") {
        return format!("udp port {rest}");
    }
    if let Some(rest) = tok.strip_prefix("udp.srcport=") {
        return format!("udp src port {rest}");
    }
    if let Some(rest) = tok.strip_prefix("udp.dstport=") {
        return format!("udp dst port {rest}");
    }
    if let Some(rest) = tok.strip_prefix("port=") {
        return format!("port {rest}");
    }
    if let Some(rest) = tok.strip_prefix("host=") {
        return format!("host {rest}");
    }

    // Bare protocol aliases.
    match tok.to_ascii_lowercase().as_str() {
        "dns" => "port 53".to_string(),
        "dhcp" => "port 67 or port 68".to_string(),
        "mdns" => "port 5353".to_string(),
        "ntp" => "port 123".to_string(),
        "http" => "tcp port 80".to_string(),
        "https" => "tcp port 443".to_string(),
        "ssh" => "tcp port 22".to_string(),
        _ => tok.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::translate;

    #[test]
    fn passes_bpf_through() {
        assert_eq!(translate("tcp port 443"), "tcp port 443");
        assert_eq!(translate("arp"), "arp");
        assert_eq!(
            translate("host 1.2.3.4 and tcp port 22"),
            "host 1.2.3.4 and tcp port 22"
        );
    }

    #[test]
    fn rewrites_proto_eq() {
        assert_eq!(translate("proto=ARP"), "arp");
        assert_eq!(translate("proto == TCP"), "tcp");
        assert_eq!(translate("protocol=udp"), "udp");
    }

    #[test]
    fn rewrites_ports_and_hosts() {
        assert_eq!(translate("tcp.port==443"), "tcp port 443");
        assert_eq!(translate("ip.addr == 10.0.0.1"), "host 10.0.0.1");
        assert_eq!(translate("ip.src=10.0.0.1"), "src host 10.0.0.1");
    }

    #[test]
    fn rewrites_logical_ops() {
        assert_eq!(translate("tcp && port=22"), "tcp and port 22");
        assert_eq!(translate("arp || icmp"), "arp or icmp");
    }

    #[test]
    fn aliases() {
        assert_eq!(translate("dns"), "port 53");
        assert_eq!(translate("https"), "tcp port 443");
    }
}
