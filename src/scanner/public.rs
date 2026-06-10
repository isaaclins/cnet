use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use reqwest::header::ACCEPT;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;

use super::models::PublicStatus;
use super::scan::ScanMessage;

#[derive(Deserialize, Default)]
struct PortCheckResponse {
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    open: Option<bool>,
    #[serde(default)]
    reachable: Option<bool>,
    #[serde(default)]
    status: Option<String>,
}

/// Async public-port check. Spawns onto the current tokio runtime; never blocks the UI.
pub fn spawn_public_check(
    tx: UnboundedSender<ScanMessage>,
    host: Ipv4Addr,
    local_ip: Ipv4Addr,
    port: u16,
) {
    tokio::spawn(async move {
        let status = if host == local_ip {
            check_local_public_port(port).await
        } else if host.is_private() {
            PublicStatus::NotAccessible
        } else {
            probe_public_host(host, port).await
        };
        let _ = tx.send(ScanMessage::PublicStatus {
            ip: host,
            port,
            status,
        });
    });
}

async fn check_local_public_port(port: u16) -> PublicStatus {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => return PublicStatus::Error(e.to_string()),
    };

    let endpoint = format!("https://ifconfig.co/port/{port}");
    let resp = match client
        .get(&endpoint)
        .header(ACCEPT, "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return PublicStatus::Error(e.to_string()),
    };

    if !resp.status().is_success() {
        return PublicStatus::Error(format!("HTTP {}", resp.status().as_u16()));
    }

    let body: PortCheckResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => return PublicStatus::Error(format!("parse: {e}")),
    };

    let open = body
        .open
        .or(body.reachable)
        .or_else(|| {
            body.status
                .as_ref()
                .map(|s| matches!(s.to_ascii_lowercase().as_str(), "open" | "reachable"))
        })
        .unwrap_or(false);

    if open {
        let ip = body
            .origin
            .or(body.ip)
            .unwrap_or_else(|| "unknown".to_string());
        PublicStatus::Accessible { ip, port }
    } else {
        PublicStatus::NotAccessible
    }
}

async fn probe_public_host(host: Ipv4Addr, port: u16) -> PublicStatus {
    let addr = SocketAddr::new(IpAddr::V4(host), port);
    match timeout(Duration::from_secs(3), AsyncTcpStream::connect(addr)).await {
        Ok(Ok(mut s)) => {
            let _ = s.shutdown().await;
            PublicStatus::Accessible {
                ip: host.to_string(),
                port,
            }
        }
        Ok(Err(_)) | Err(_) => PublicStatus::NotAccessible,
    }
}
