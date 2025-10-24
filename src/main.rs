use std::io::{stdout, Stdout, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use get_if_addrs::{get_if_addrs, IfAddr};
use ipnetwork::Ipv4Network;
use rayon::prelude::*;

const CONNECT_TIMEOUT_MS: u64 = 150;
const MIN_PREFIX: u8 = 24;

fn main() -> std::io::Result<()> {
    println!("Scanning local network. This may take a few seconds...");
    let scan_results = match scan_network() {
        Ok(results) => results,
        Err(err) => {
            eprintln!("Failed to scan network: {err}");
            return Ok(());
        }
    };

    let mut stdout = stdout();
    terminal::enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, Hide)?;

    let outcome = run_app(&mut stdout, &scan_results);

    execute!(stdout, Show, LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    match outcome {
        Ok(Some(index)) => {
            if let Some(host) = scan_results.hosts.get(index) {
                println!("Selected host: {}", &host.ip);
                println!("Open ports: {}", &host.ports_display);
                println!("Services: {}", &host.services_display);
            } else {
                println!("Selection index {index} is out of range.");
            }
        }
        Ok(None) => println!("Selection cancelled."),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn run_app(stdout: &mut Stdout, scan: &ScanResults) -> Result<Option<usize>, String> {
    let mut index = 0usize;

    loop {
        draw(stdout, index, scan).map_err(|err| err.to_string())?;

        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Up | KeyCode::Left => {
                    if !scan.hosts.is_empty() {
                        if index == 0 {
                            index = scan.hosts.len() - 1;
                        } else {
                            index -= 1;
                        }
                    }
                }
                KeyCode::Down | KeyCode::Right => {
                    if !scan.hosts.is_empty() {
                        index = (index + 1) % scan.hosts.len();
                    }
                }
                KeyCode::Enter => {
                    if scan.hosts.is_empty() {
                        return Err("No hosts with open ports were found.".to_string());
                    }
                    return Ok(Some(index));
                }
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(None),
                _ => {}
            },
            Ok(Event::Resize(_, _)) => {}
            Ok(_) => {}
            Err(err) => return Err(err.to_string()),
        }
    }
}

fn draw(stdout: &mut Stdout, index: usize, scan: &ScanResults) -> std::io::Result<()> {
    execute!(stdout, MoveTo(0, 0), Clear(ClearType::All))?;
    let layout = compute_layout(scan);

    execute!(
        stdout,
        Print(format!("Network Scan Results\r\n{}\r\n", "=".repeat(23))),
        Print(format!("Subnet: {}\r\n", scan.network)),
        Print(format!(
            "Local IP: {} | Hosts scanned: {} | Hosts with open ports: {}\r\n",
            scan.local_ip,
            scan.total_hosts_scanned,
            scan.hosts.len()
        )),
        Print(format!(
            "Ports tested ({}): {}\r\n\r\n",
            scan.ports_checked,
            scan.ports_display
        )),
    )?;

    if scan.hosts.is_empty() {
        execute!(
            stdout,
            Print("No hosts with open ports were discovered.\r\n\r\n"),
            Print("Press q or Esc to exit.\r\n"),
            Print("Use Enter to retry after rerunning the program.\r\n")
        )?;
    } else {
        let border = format!(
            "+{}+{}+{}+\r\n",
            "-".repeat(layout.ip_width + 2),
            "-".repeat(layout.ports_width + 2),
            "-".repeat(layout.services_width + 2)
        );
        let header = format!(
            "| {:^ip_w$} | {:^ports_w$} | {:^services_w$} |\r\n",
            "IP Address",
            "Open Ports",
            "Service",
            ip_w = layout.ip_width,
            ports_w = layout.ports_width,
            services_w = layout.services_width
        );

        execute!(stdout, Print(border.clone()), Print(header), Print(border.clone()))?;

        for (row_idx, host) in scan.hosts.iter().enumerate() {
            let line = format!(
                "| {:<ip_w$} | {:<ports_w$} | {:<services_w$} |\r\n",
                &host.ip,
                &host.ports_display,
                &host.services_display,
                ip_w = layout.ip_width,
                ports_w = layout.ports_width,
                services_w = layout.services_width
            );

            if row_idx == index {
                execute!(
                    stdout,
                    SetForegroundColor(Color::Black),
                    SetBackgroundColor(Color::Cyan),
                    Print(line),
                    ResetColor
                )?;
            } else {
                execute!(stdout, Print(line))?;
            }
        }

        execute!(stdout, Print(border))?;
    }

    execute!(
        stdout,
        Print("\r\nUse ↑/↓ or ←/→ to navigate, Enter to select, q or Esc to cancel.\r\n")
    )?;
    stdout.flush()?;
    Ok(())
}

fn compute_layout(scan: &ScanResults) -> TableLayout {
    let mut ip_width = "IP Address".len();
    let mut ports_width = "Open Ports".len();
    let mut services_width = "Service".len();

    for host in &scan.hosts {
        ip_width = ip_width.max(host.ip.len());
        ports_width = ports_width.max(host.ports_display.len());
        services_width = services_width.max(host.services_display.len());
    }

    TableLayout {
        ip_width,
        ports_width,
        services_width,
    }
}

fn scan_network() -> Result<ScanResults, String> {
    let interfaces = get_if_addrs().map_err(|err| err.to_string())?;
    let interface = interfaces
        .into_iter()
        .find(|iface| match &iface.addr {
            IfAddr::V4(v4) => !v4.ip.is_loopback() && v4.ip.is_private(),
            _ => false,
        })
        .ok_or_else(|| "No active IPv4 interface found.".to_string())?;

    let v4 = match interface.addr {
        IfAddr::V4(v4) => v4,
        _ => unreachable!("filtered above"),
    };

    let base_network =
        Ipv4Network::with_netmask(v4.ip, v4.netmask).map_err(|err| err.to_string())?;
    let effective_prefix = base_network.prefix().max(MIN_PREFIX);
    let effective_network = if effective_prefix == base_network.prefix() {
        base_network
    } else {
        let network_ip = network_address(v4.ip, effective_prefix);
        Ipv4Network::new(network_ip, effective_prefix).map_err(|err| err.to_string())?
    };

    let network_addr = effective_network.network();
    let broadcast_addr = effective_network.broadcast();
    let host_ips: Vec<Ipv4Addr> = effective_network
        .iter()
        .filter(|ip| *ip != network_addr && *ip != broadcast_addr)
        .collect();
    let total_hosts_scanned = host_ips.len();
    let ports = default_port_list();
    let ports_display = ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mut hosts: Vec<HostReport> = host_ips
        .into_par_iter()
        .filter_map(|ip| scan_host(ip, &ports))
        .collect();

    hosts.sort_by(|a, b| a.ip_addr.cmp(&b.ip_addr));

    Ok(ScanResults {
        hosts,
        total_hosts_scanned,
        ports_checked: ports.len(),
        ports_display,
        network: effective_network.to_string(),
        local_ip: v4.ip,
    })
}

fn scan_host(ip: Ipv4Addr, ports: &[u16]) -> Option<HostReport> {
    let timeout = Duration::from_millis(CONNECT_TIMEOUT_MS);
    let mut open_ports = Vec::new();

    for port in ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), *port);
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            open_ports.push(PortInfo {
                port: *port,
                service: port_service(*port),
            });
        }
    }

    if open_ports.is_empty() {
        None
    } else {
        Some(HostReport::new(ip, open_ports))
    }
}

fn default_port_list() -> Vec<u16> {
    const PORTS: &[u16] = &[
        20, 21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 631, 993, 995, 1352, 1433,
        1521, 2049, 2379, 2380, 27017, 3000, 3128, 3306, 3389, 5432, 5672, 5900, 5984, 6379, 6443,
        7001, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 11211,
    ];
    PORTS.to_vec()
}

fn port_service(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 | 8000 | 8080 => Some("HTTP"),
        110 => Some("POP3"),
        1352 => Some("Lotus Notes"),
        143 => Some("IMAP"),
        389 => Some("LDAP"),
        443 | 8443 => Some("HTTPS"),
        445 => Some("SMB"),
        465 | 587 => Some("SMTPS"),
        631 => Some("IPP"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle"),
        2049 => Some("NFS"),
        2379 | 2380 => Some("etcd"),
        27017 => Some("MongoDB"),
        3000 => Some("Node.js"),
        3128 => Some("Proxy"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
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

fn network_address(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(ip_u32 & mask)
}

struct ScanResults {
    hosts: Vec<HostReport>,
    total_hosts_scanned: usize,
    ports_checked: usize,
    ports_display: String,
    network: String,
    local_ip: Ipv4Addr,
}

struct HostReport {
    ip_addr: Ipv4Addr,
    ip: String,
    ports: Vec<PortInfo>,
    ports_display: String,
    services_display: String,
}

impl HostReport {
    fn new(ip: Ipv4Addr, ports: Vec<PortInfo>) -> Self {
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
                if !services.iter().any(|existing| *existing == name) {
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

struct PortInfo {
    port: u16,
    service: Option<&'static str>,
}

struct TableLayout {
    ip_width: usize,
    ports_width: usize,
    services_width: usize,
}
