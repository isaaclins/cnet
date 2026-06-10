use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub enum PublicStatus {
    Accessible { ip: String, port: u16 },
    NotAccessible,
    Unknown,
    Error(String),
}

impl PublicStatus {
    pub fn label(&self) -> String {
        match self {
            PublicStatus::Accessible { ip, port } => format!("{ip}:{port}"),
            PublicStatus::NotAccessible => "private".to_string(),
            PublicStatus::Unknown => "pending".to_string(),
            PublicStatus::Error(msg) => format!("error: {msg}"),
        }
    }
}

#[derive(Clone)]
pub struct PortInfo {
    pub port: u16,
    pub service: Option<&'static str>,
    pub banner: Option<String>,
    pub url_display: String,
    pub public_status: PublicStatus,
    pub public_label: String,
}

impl PortInfo {
    pub fn set_public_status(&mut self, status: PublicStatus) {
        self.public_label = status.label();
        self.public_status = status;
    }

    pub fn service_label(&self) -> String {
        match (self.service, self.banner.as_deref()) {
            (Some(s), Some(b)) => format!("{s} ({b})"),
            (Some(s), None) => s.to_string(),
            (None, Some(b)) => b.to_string(),
            (None, None) => "unknown".to_string(),
        }
    }
}

pub struct HostReport {
    pub ip_addr: Ipv4Addr,
    pub ip: String,
    pub ports: Vec<PortInfo>,
    pub ports_display: String,
    pub services_display: String,
}

impl HostReport {
    pub fn new(ip: Ipv4Addr, ports: Vec<PortInfo>) -> Self {
        let ports_display = if ports.is_empty() {
            "-".to_string()
        } else {
            ports
                .iter()
                .map(|p| p.port.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mut services = Vec::new();
        for entry in &ports {
            if let Some(name) = entry.service {
                if !services.contains(&name) {
                    services.push(name);
                }
            }
        }
        let services_display = if services.is_empty() {
            "-".to_string()
        } else {
            services.join(", ")
        };

        HostReport {
            ip_addr: ip,
            ip: ip.to_string(),
            ports,
            ports_display,
            services_display,
        }
    }
}

pub struct ScanResults {
    pub hosts: Vec<HostReport>,
    pub hosts_considered: usize,
    pub hosts_planned: usize,
    pub hosts_total: usize,
    pub local_ip: Ipv4Addr,
    pub scan_complete: bool,
    pub capped: bool,
}

impl ScanResults {
    pub fn insert_host(&mut self, host: HostReport) {
        match self
            .hosts
            .binary_search_by(|existing| existing.ip_addr.cmp(&host.ip_addr))
        {
            Ok(idx) => self.hosts[idx] = host,
            Err(idx) => self.hosts.insert(idx, host),
        }
    }
}
