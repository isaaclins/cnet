use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use get_if_addrs::{get_if_addrs, IfAddr};
use ipnetwork::Ipv4Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::timeout;

use super::models::{HostReport, PortInfo, PublicStatus, ScanResults};
use super::ports::{default_port_list, distill_banner, port_service, port_url};

const CONNECT_TIMEOUT_MS: u64 = 200;
const PROBE_TIMEOUT_MS: u64 = 60;
const BANNER_READ_MS: u64 = 200;
const MIN_PREFIX: u8 = 24;
const MAX_HOSTS_TO_SCAN: usize = 512;
const HOST_CONCURRENCY: usize = 64;
const PROBE_PORTS: &[u16] = &[1, 22, 80];

pub enum ScanMessage {
    HostProgress {
        processed: usize,
        report: Option<HostReport>,
    },
    Finished,
    PublicStatus {
        ip: Ipv4Addr,
        port: u16,
        status: PublicStatus,
    },
}

pub struct ScanHandle {
    pub results: ScanResults,
    pub rx: UnboundedReceiver<ScanMessage>,
    pub tx: UnboundedSender<ScanMessage>,
}

/// Kicks off the scan on the current tokio runtime and returns the handle.
pub fn start_scan() -> Result<ScanHandle, String> {
    let interfaces = get_if_addrs().map_err(|e| e.to_string())?;
    let interface = interfaces
        .into_iter()
        .find(|iface| matches!(&iface.addr, IfAddr::V4(v4) if !v4.ip.is_loopback() && v4.ip.is_private()))
        .ok_or_else(|| "No active IPv4 interface found.".to_string())?;

    let v4 = match interface.addr {
        IfAddr::V4(v4) => v4,
        _ => unreachable!(),
    };

    let base = Ipv4Network::with_netmask(v4.ip, v4.netmask).map_err(|e| e.to_string())?;
    let effective_prefix = base.prefix().max(MIN_PREFIX);
    let network = if effective_prefix == base.prefix() {
        base
    } else {
        Ipv4Network::new(network_address(v4.ip, effective_prefix), effective_prefix)
            .map_err(|e| e.to_string())?
    };

    let net = network.network();
    let bcast = network.broadcast();
    let all_hosts: Vec<Ipv4Addr> = network
        .iter()
        .filter(|ip| *ip != net && *ip != bcast && *ip != v4.ip)
        .collect();
    let hosts_total = all_hosts.len();
    let host_ips: Vec<Ipv4Addr> = all_hosts.into_iter().take(MAX_HOSTS_TO_SCAN).collect();
    let hosts_planned = host_ips.len();
    let capped = hosts_total > hosts_planned;

    let (tx, rx) = mpsc::unbounded_channel::<ScanMessage>();
    let tx_clone = tx.clone();

    tokio::spawn(async move {
        let ports = Arc::new(default_port_list());
        let processed = Arc::new(AtomicUsize::new(0));

        stream::iter(host_ips)
            .for_each_concurrent(Some(HOST_CONCURRENCY), |ip| {
                let tx = tx_clone.clone();
                let ports = Arc::clone(&ports);
                let processed = Arc::clone(&processed);
                async move {
                    let report = scan_host_async(ip, ports.as_slice()).await;
                    let n = processed.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = tx.send(ScanMessage::HostProgress {
                        processed: n,
                        report,
                    });
                }
            })
            .await;

        let _ = tx_clone.send(ScanMessage::Finished);
    });

    Ok(ScanHandle {
        results: ScanResults {
            hosts: Vec::new(),
            hosts_considered: 0,
            hosts_planned,
            hosts_total,
            local_ip: v4.ip,
            scan_complete: false,
            capped,
        },
        rx,
        tx,
    })
}

async fn host_is_reachable_async(ip: Ipv4Addr) -> bool {
    let dur = Duration::from_millis(PROBE_TIMEOUT_MS);
    for port in PROBE_PORTS {
        let addr = SocketAddr::new(IpAddr::V4(ip), *port);
        match timeout(dur, AsyncTcpStream::connect(addr)).await {
            Ok(Ok(mut s)) => {
                let _ = s.shutdown().await;
                return true;
            }
            Ok(Err(e)) => match e.kind() {
                ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::PermissionDenied
                | ErrorKind::AddrInUse
                | ErrorKind::AddrNotAvailable => return true,
                _ => {}
            },
            Err(_) => {}
        }
    }
    false
}

async fn grab_banner(stream: &mut AsyncTcpStream, port: u16) -> Option<String> {
    if matches!(
        port,
        80 | 8000 | 8080 | 3000 | 5000 | 8888 | 9000 | 9090 | 9200
    ) {
        let _ = stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await;
    }

    let mut buf = [0u8; 512];
    match timeout(Duration::from_millis(BANNER_READ_MS), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => distill_banner(&buf[..n]),
        _ => None,
    }
}

async fn scan_host_async(ip: Ipv4Addr, ports: &[u16]) -> Option<HostReport> {
    if !host_is_reachable_async(ip).await {
        return None;
    }

    let dur = Duration::from_millis(CONNECT_TIMEOUT_MS);
    let mut open_ports = Vec::new();

    for &port in ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        let Ok(Ok(mut stream)) = timeout(dur, AsyncTcpStream::connect(addr)).await else {
            continue;
        };

        let banner = grab_banner(&mut stream, port).await;
        let _ = stream.shutdown().await;

        let service = port_service(port);
        let url = port_url(ip, port, service);
        let url_display = url.unwrap_or_else(|| "(unknown)".to_string());

        open_ports.push(PortInfo {
            port,
            service,
            banner,
            url_display,
            public_status: PublicStatus::Unknown,
            public_label: "pending".to_string(),
        });
    }

    if open_ports.is_empty() {
        None
    } else {
        Some(HostReport::new(ip, open_ports))
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
