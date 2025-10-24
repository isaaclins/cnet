use std::io::{stdout, ErrorKind, Stdout, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
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

const CONNECT_TIMEOUT_MS: u64 = 200;
const PROBE_TIMEOUT_MS: u64 = 60;
const MIN_PREFIX: u8 = 24;
const MAX_HOSTS_TO_SCAN: usize = 512;
const PROBE_PORTS: &[u16] = &[1, 22, 80];

#[derive(Clone, Copy)]
struct Selection {
    host_index: usize,
    port_index: usize,
}

#[derive(Clone, Copy)]
enum ViewState {
    Hosts {
        selected: usize,
    },
    Ports {
        host_index: usize,
        port_index: usize,
    },
}

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
        Ok(Some(selection)) => {
            if let Some(host) = scan_results.hosts.get(selection.host_index) {
                if let Some(port) = host.ports.get(selection.port_index) {
                    println!("Host: {}", host.ip);
                    println!("Port: {}", port.port);
                    println!("Service: {}", port.service.unwrap_or("unknown service"));
                    match &port.url {
                        Some(url) => println!("URL: {url}"),
                        None => println!("URL: (unknown)"),
                    }
                } else {
                    println!(
                        "Selected port index {} is out of range for host {}.",
                        selection.port_index, host.ip
                    );
                }
            } else {
                println!(
                    "Selected host index {} is out of range.",
                    selection.host_index
                );
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

fn run_app(stdout: &mut Stdout, scan: &ScanResults) -> Result<Option<Selection>, String> {
    let mut state = ViewState::Hosts { selected: 0 };

    drain_pending_events().map_err(|err| err.to_string())?;

    loop {
        draw(stdout, state, scan).map_err(|err| err.to_string())?;

        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                match key.code {
                    KeyCode::Up => match &mut state {
                        ViewState::Hosts { selected } => {
                            if !scan.hosts.is_empty() {
                                *selected = if *selected == 0 {
                                    scan.hosts.len() - 1
                                } else {
                                    *selected - 1
                                };
                            }
                        }
                        ViewState::Ports {
                            host_index,
                            port_index,
                        } => {
                            if let Some(host) = scan.hosts.get(*host_index) {
                                if !host.ports.is_empty() {
                                    *port_index = if *port_index == 0 {
                                        host.ports.len() - 1
                                    } else {
                                        *port_index - 1
                                    };
                                }
                            }
                        }
                    },
                    KeyCode::Down => match &mut state {
                        ViewState::Hosts { selected } => {
                            if !scan.hosts.is_empty() {
                                *selected = (*selected + 1) % scan.hosts.len();
                            }
                        }
                        ViewState::Ports {
                            host_index,
                            port_index,
                        } => {
                            if let Some(host) = scan.hosts.get(*host_index) {
                                if !host.ports.is_empty() {
                                    *port_index = (*port_index + 1) % host.ports.len();
                                }
                            }
                        }
                    },
                    KeyCode::Left => match state {
                        ViewState::Hosts { .. } => {
                            if let ViewState::Hosts { selected } = &mut state {
                                if !scan.hosts.is_empty() {
                                    *selected = if *selected == 0 {
                                        scan.hosts.len() - 1
                                    } else {
                                        *selected - 1
                                    };
                                }
                            }
                        }
                        ViewState::Ports { host_index, .. } => {
                            state = ViewState::Hosts {
                                selected: host_index.min(scan.hosts.len().saturating_sub(1)),
                            };
                        }
                    },
                    KeyCode::Right => match &mut state {
                        ViewState::Hosts { selected } => {
                            if !scan.hosts.is_empty() {
                                *selected = (*selected + 1) % scan.hosts.len();
                            }
                        }
                        ViewState::Ports {
                            host_index,
                            port_index,
                        } => {
                            if let Some(host) = scan.hosts.get(*host_index) {
                                if !host.ports.is_empty() {
                                    *port_index = (*port_index + 1) % host.ports.len();
                                }
                            }
                        }
                    },
                    KeyCode::Backspace => {
                        if let ViewState::Ports { host_index, .. } = state {
                            state = ViewState::Hosts {
                                selected: host_index.min(scan.hosts.len().saturating_sub(1)),
                            };
                        }
                    }
                    KeyCode::Enter => match state {
                        ViewState::Hosts { selected } => {
                            if !scan.hosts.is_empty() {
                                let safe_index = selected % scan.hosts.len();
                                if let Some(host) = scan.hosts.get(safe_index) {
                                    if host.ports.is_empty() {
                                        // Nothing to inspect on this host.
                                    } else {
                                        state = ViewState::Ports {
                                            host_index: safe_index,
                                            port_index: 0,
                                        };
                                    }
                                }
                            }
                        }
                        ViewState::Ports {
                            host_index,
                            port_index,
                        } => {
                            return Ok(Some(Selection {
                                host_index,
                                port_index,
                            }));
                        }
                    },
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(None),
                    _ => {}
                }
            }
            Ok(Event::Resize(_, _)) => {}
            Ok(_) => {}
            Err(err) => return Err(err.to_string()),
        }
    }
}

fn drain_pending_events() -> std::io::Result<()> {
    while event::poll(Duration::from_millis(0))? {
        let _ = event::read()?;
    }
    Ok(())
}

fn draw(stdout: &mut Stdout, state: ViewState, scan: &ScanResults) -> std::io::Result<()> {
    execute!(stdout, MoveTo(0, 0), Clear(ClearType::All))?;
    match state {
        ViewState::Hosts { selected } => draw_host_view(stdout, scan, selected)?,
        ViewState::Ports {
            host_index,
            port_index,
        } => draw_port_view(stdout, scan, host_index, port_index)?,
    }
    stdout.flush()?;
    Ok(())
}

fn draw_host_view(stdout: &mut Stdout, scan: &ScanResults, selected: usize) -> std::io::Result<()> {
    let layout = compute_layout(scan);

    execute!(
        stdout,
        Print(format!("Network Scan Results\r\n{}\r\n", "=".repeat(23))),
        Print(format!("Subnet: {}\r\n", scan.network)),
        Print(format!(
            "Local IP: {} | Hosts probed: {} / {} | Hosts with open ports: {}\r\n",
            scan.local_ip,
            scan.hosts_considered,
            scan.hosts_available,
            scan.hosts.len()
        )),
        Print(format!(
            "Ports tested ({}): {}\r\n",
            scan.ports_checked, scan.ports_display
        )),
    )?;

    if scan.hosts_considered < scan.hosts_available {
        execute!(
            stdout,
            Print(format!(
                "Note: scan limited to first {} of {} hosts. Adjust MAX_HOSTS_TO_SCAN to widen coverage.\r\n",
                scan.hosts_considered, scan.hosts_available
            ))
        )?;
    }

    execute!(stdout, Print("\r\n"))?;

    if scan.hosts.is_empty() {
        execute!(
            stdout,
            Print("No hosts with open ports were discovered.\r\n"),
            Print("Press q or Esc to exit.\r\n")
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

        execute!(
            stdout,
            Print(border.clone()),
            Print(header),
            Print(border.clone())
        )?;

        let highlight = if scan.hosts.is_empty() {
            None
        } else {
            Some(selected.min(scan.hosts.len() - 1))
        };

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

            if Some(row_idx) == highlight {
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
        Print("\r\nUse ↑/↓ or ←/→ to browse hosts, Enter to inspect, q or Esc to quit.\r\n")
    )?;

    Ok(())
}

fn draw_port_view(
    stdout: &mut Stdout,
    scan: &ScanResults,
    host_index: usize,
    port_index: usize,
) -> std::io::Result<()> {
    if let Some(host) = scan.hosts.get(host_index) {
        let title = format!(" {} ", host.ip);
        let title_border = format!("+{}+\r\n", "-".repeat(title.len()));
        execute!(
            stdout,
            Print(title_border.clone()),
            Print(format!("|{title}|\r\n")),
            Print(title_border)
        )?;

        let layout = compute_port_layout(host);
        let border = format!(
            "+{}+{}+{}+\r\n",
            "-".repeat(layout.port_width + 2),
            "-".repeat(layout.service_width + 2),
            "-".repeat(layout.url_width + 2)
        );
        let header = format!(
            "| {:^port_w$} | {:^service_w$} | {:^url_w$} |\r\n",
            "Port",
            "Service",
            "URL",
            port_w = layout.port_width,
            service_w = layout.service_width,
            url_w = layout.url_width
        );

        execute!(
            stdout,
            Print(border.clone()),
            Print(header),
            Print(border.clone())
        )?;

        let highlight = if host.ports.is_empty() {
            None
        } else {
            Some(port_index.min(host.ports.len() - 1))
        };

        for (row_idx, port) in host.ports.iter().enumerate() {
            let label = port.service.unwrap_or("unknown");
            let line = format!(
                "| {:>port_w$} | {:<service_w$} | {:<url_w$} |\r\n",
                port.port,
                label,
                port.url_display,
                port_w = layout.port_width,
                service_w = layout.service_width,
                url_w = layout.url_width
            );

            if Some(row_idx) == highlight {
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

        execute!(
            stdout,
            Print(
                "\r\nUse ↑/↓ to browse ports, Enter to finish, ← or Backspace to return, q or Esc to quit.\r\n"
            )
        )?;
    } else {
        execute!(
            stdout,
            Print("Host no longer available. Press ← to return to the host list.\r\n")
        )?;
    }

    Ok(())
}

fn compute_port_layout(host: &HostReport) -> PortTableLayout {
    let mut port_width = "Port".len();
    let mut service_width = "Service".len();
    let mut url_width = "URL".len();

    for port in &host.ports {
        port_width = port_width.max(port.port.to_string().len());
        let label = port.service.unwrap_or("unknown");
        service_width = service_width.max(label.len());
        url_width = url_width.max(port.url_display.len());
    }

    PortTableLayout {
        port_width,
        service_width,
        url_width,
    }
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
    let hosts_available = effective_network.size().saturating_sub(2) as usize;
    let host_ips: Vec<Ipv4Addr> = effective_network
        .iter()
        .filter(|ip| *ip != network_addr && *ip != broadcast_addr && *ip != v4.ip)
        .take(MAX_HOSTS_TO_SCAN)
        .collect();
    let hosts_considered = host_ips.len();
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
        hosts_considered,
        hosts_available,
        ports_checked: ports.len(),
        ports_display,
        network: effective_network.to_string(),
        local_ip: v4.ip,
    })
}

fn host_is_reachable(ip: Ipv4Addr) -> bool {
    let timeout = Duration::from_millis(PROBE_TIMEOUT_MS);

    for port in PROBE_PORTS {
        let addr = SocketAddr::new(IpAddr::V4(ip), *port);
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
                return true;
            }
            Err(err) => match err.kind() {
                ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::PermissionDenied
                | ErrorKind::AddrInUse
                | ErrorKind::AddrNotAvailable => return true,
                ErrorKind::TimedOut | ErrorKind::WouldBlock => {}
                _ => {}
            },
        }
    }

    false
}

fn scan_host(ip: Ipv4Addr, ports: &[u16]) -> Option<HostReport> {
    if !host_is_reachable(ip) {
        return None;
    }

    let timeout = Duration::from_millis(CONNECT_TIMEOUT_MS);
    let mut open_ports = Vec::new();

    for port in ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), *port);
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
                let service = port_service(*port);
                let url = port_url(ip, *port, service);
                let url_display = url
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| "(unknown)".to_string());
                open_ports.push(PortInfo {
                    port: *port,
                    service,
                    url,
                    url_display,
                });
            }
            Err(err) => {
                if matches!(
                    err.kind(),
                    ErrorKind::ConnectionRefused
                        | ErrorKind::PermissionDenied
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::NotConnected
                ) {
                    // Port closed or filtered, ignore.
                }
            }
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
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 631, 993, 995, 1352,
        1433, 1521, 1723, 2049, 2379, 27017, 3000, 3128, 3306, 3389, 4333, 5000, 5432, 5672, 5900,
        5984, 6379, 6443, 7001, 8080, 8443, 8888, 9000, 9090, 9200,
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
        135 => Some("RPC"),
        139 => Some("NetBIOS"),
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
        1723 => Some("PPTP"),
        2049 => Some("NFS"),
        2379 | 2380 => Some("etcd"),
        27017 => Some("MongoDB"),
        3000 => Some("Node.js"),
        3128 => Some("Proxy"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        4333 => Some("mSQL"),
        5432 => Some("Postgres"),
        5672 => Some("AMQP"),
        5900 => Some("VNC"),
        5000 => Some("UPnP"),
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

fn port_url(ip: Ipv4Addr, port: u16, service: Option<&'static str>) -> Option<String> {
    match service {
        Some("FTP") => Some(format!("ftp://{}:{}", ip, port)),
        Some("SSH") => Some(format!("ssh {}", ip)),
        Some("Telnet") => Some(format!("telnet {}", ip)),
        Some("HTTP") => Some(format!("http://{}:{}", ip, port)),
        Some("HTTPS") => Some(format!("https://{}:{}", ip, port)),
        Some("SMTPS") => Some(format!("smtps://{}:{}", ip, port)),
        Some("SMTP") => Some(format!("smtp://{}:{}", ip, port)),
        Some("IPP") => Some(format!("ipp://{}:{}", ip, port)),
        Some("MongoDB") => Some(format!("mongodb://{}:{}", ip, port)),
        Some("MySQL") => Some(format!("mysql://{}:{}", ip, port)),
        Some("Postgres") => Some(format!("postgresql://{}:{}", ip, port)),
        Some("Redis") => Some(format!("redis://{}:{}", ip, port)),
        Some("Prometheus") => Some(format!("http://{}:{}", ip, port)),
        Some("SonarQube") => Some(format!("http://{}:{}", ip, port)),
        Some("Elasticsearch") => Some(format!("http://{}:{}", ip, port)),
        Some("Proxy") => Some(format!("http://{}:{}", ip, port)),
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
    hosts_considered: usize,
    hosts_available: usize,
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
    url: Option<String>,
    url_display: String,
}

struct TableLayout {
    ip_width: usize,
    ports_width: usize,
    services_width: usize,
}

struct PortTableLayout {
    port_width: usize,
    service_width: usize,
    url_width: usize,
}
