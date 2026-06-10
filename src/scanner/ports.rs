use std::net::Ipv4Addr;

pub fn default_port_list() -> Vec<u16> {
    const PORTS: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 631, 993, 995, 1352,
        1433, 1521, 1723, 2049, 2379, 27017, 3000, 3128, 3306, 3389, 4333, 5000, 5432, 5672, 5900,
        5984, 6379, 6443, 7001, 8080, 8443, 8888, 9000, 9090, 9200,
    ];
    PORTS.to_vec()
}

pub fn port_service(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 | 8000 | 8080 => Some("HTTP"),
        110 => Some("POP3"),
        135 => Some("RPC"),
        139 => Some("NetBIOS"),
        143 => Some("IMAP"),
        389 => Some("LDAP"),
        443 | 8443 => Some("HTTPS"),
        445 => Some("SMB"),
        465 | 587 => Some("SMTPS"),
        631 => Some("IPP"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1352 => Some("Lotus Notes"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle"),
        1723 => Some("PPTP"),
        2049 => Some("NFS"),
        2379 | 2380 => Some("etcd"),
        27017 => Some("MongoDB"),
        3000 => Some("Node.js"),
        3128 => Some("Proxy"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        4333 => Some("mSQL"),
        5000 => Some("UPnP"),
        5432 => Some("Postgres"),
        5672 => Some("AMQP"),
        5900 => Some("VNC"),
        5984 => Some("CouchDB"),
        6379 => Some("Redis"),
        6443 => Some("K8s API"),
        7001 => Some("WebLogic"),
        8888 => Some("Proxy"),
        9000 => Some("SonarQube"),
        9090 => Some("Prometheus"),
        9200 => Some("Elasticsearch"),
        11211 => Some("Memcached"),
        _ => None,
    }
}

pub fn port_url(ip: Ipv4Addr, port: u16, service: Option<&'static str>) -> Option<String> {
    match service {
        Some("FTP") => Some(format!("ftp://{ip}:{port}")),
        Some("SSH") => Some(format!("ssh {ip}")),
        Some("Telnet") => Some(format!("telnet {ip}")),
        Some("HTTP") => Some(format!("http://{ip}:{port}")),
        Some("HTTPS") => Some(format!("https://{ip}:{port}")),
        Some("SMTPS") => Some(format!("smtps://{ip}:{port}")),
        Some("SMTP") => Some(format!("smtp://{ip}:{port}")),
        Some("IPP") => Some(format!("ipp://{ip}:{port}")),
        Some("MongoDB") => Some(format!("mongodb://{ip}:{port}")),
        Some("MySQL") => Some(format!("mysql://{ip}:{port}")),
        Some("Postgres") => Some(format!("postgresql://{ip}:{port}")),
        Some("Redis") => Some(format!("redis://{ip}:{port}")),
        Some("Prometheus") => Some(format!("http://{ip}:{port}")),
        Some("SonarQube") => Some(format!("http://{ip}:{port}")),
        Some("Elasticsearch") => Some(format!("http://{ip}:{port}")),
        Some("Proxy") => Some(format!("http://{ip}:{port}")),
        _ => None,
    }
}

/// Heuristic: pull a one-line label out of a banner string.
/// HTTP responses have "Server:" headers; SSH starts with "SSH-".
pub fn distill_banner(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(raw);

    if let Some(line) = text.lines().next() {
        if line.starts_with("SSH-") {
            return Some(line.trim().to_string());
        }
    }

    for line in text.lines() {
        let l = line.trim();
        let lower = l.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("server:") {
            let v = rest.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }

    // Fallback: first non-empty printable line, capped.
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if l.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            let mut out: String = l.chars().take(40).collect();
            if l.len() > out.len() {
                out.push('…');
            }
            return Some(out);
        }
        break;
    }
    None
}
