use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use pcap::{Capture, Device};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::model::CapturedPacket;
use super::parser::{decode, LinkType};

pub struct CaptureHandle {
    pub rx: UnboundedReceiver<CaptureEvent>,
    pub event_tx: UnboundedSender<CaptureEvent>,
    pub interface: String,
    pub link: LinkType,
    pub stop_flag: Arc<AtomicBool>,
}

impl CaptureHandle {
    pub fn rx_clone_sender(&self) -> UnboundedSender<CaptureEvent> {
        self.event_tx.clone()
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

pub enum CaptureEvent {
    Packet(CapturedPacket),
    Error(String),
    Ended,
    Rdns { ip: std::net::IpAddr, name: String },
}

pub struct CaptureOptions {
    pub interface: Option<String>,
    pub filter: Option<String>,
    pub snaplen: i32,
    pub promisc: bool,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            interface: None,
            filter: None,
            snaplen: 1500,
            promisc: true,
        }
    }
}

pub fn list_interfaces() -> Result<Vec<Device>, String> {
    Device::list().map_err(|e| e.to_string())
}

/// Pick a sensible default device. Ranks by name pattern (en* / eth* / wl* > utun* / awdl* / ap*),
/// presence of an IPv4 address, and link state — so we land on en0 instead of a virtual AP.
pub fn default_interface() -> Result<Device, String> {
    let devices = capturable_interfaces()?;
    devices
        .into_iter()
        .max_by_key(score_device)
        .ok_or_else(|| "no capture interface available".into())
}

/// All capture-eligible devices on the system, in their natural order.
pub fn capturable_interfaces() -> Result<Vec<Device>, String> {
    let mut devices = list_interfaces()?;
    devices.retain(|d| !d.name.is_empty() && !d.flags.is_loopback());
    Ok(devices)
}

fn score_device(d: &Device) -> i32 {
    let mut score = 0;
    let name = &d.name;

    if d.flags.is_up() {
        score += 200;
    }
    if d.flags.is_running() {
        score += 100;
    }
    if d.addresses.iter().any(|a| a.addr.is_ipv4()) {
        score += 80;
    }

    score += if name.starts_with("en") || name.starts_with("eth") || name.starts_with("enp") {
        300
    } else if name.starts_with("wlan") || name.starts_with("wlp") || name.starts_with("wlx") {
        250
    } else if name.starts_with("br") || name.starts_with("bridge") {
        50
    } else if name.starts_with("ap")
        || name.starts_with("awdl")
        || name.starts_with("llw")
        || name.starts_with("utun")
        || name.starts_with("anpi")
        || name.starts_with("p2p")
        || name.starts_with("gif")
        || name.starts_with("stf")
        || name.starts_with("XHC")
    {
        -200
    } else {
        0
    };

    // Tiebreak: lower trailing number wins (en0 over en1).
    let digits: String = name
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if let Ok(n) = digits.chars().rev().collect::<String>().parse::<i32>() {
        score -= n;
    }

    score
}

pub fn start(opts: CaptureOptions) -> Result<CaptureHandle, String> {
    let device = match opts.interface.as_deref() {
        Some(name) => Device::from(name),
        None => default_interface()?,
    };
    let iface_name = device.name.clone();

    let cap = Capture::from_device(device)
        .map_err(|e| e.to_string())?
        .promisc(opts.promisc)
        .snaplen(opts.snaplen)
        .timeout(200)
        .immediate_mode(true);

    let mut cap = cap.open().map_err(|e| format!("open {iface_name}: {e}"))?;

    if let Some(filter) = opts.filter.as_deref().filter(|s| !s.is_empty()) {
        cap.filter(filter, true)
            .map_err(|e| format!("bad filter '{filter}': {e}"))?;
    }

    let link = LinkType::from_pcap(cap.get_datalink());
    let (tx, rx) = mpsc::unbounded_channel::<CaptureEvent>();
    let started_at = Instant::now();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_thread = Arc::clone(&stop_flag);
    let tx_clone = tx.clone();

    thread::Builder::new()
        .name("cnet-capture".into())
        .spawn(move || run(cap, link, started_at, stop_flag_thread, tx_clone))
        .map_err(|e| e.to_string())?;

    Ok(CaptureHandle {
        rx,
        event_tx: tx,
        interface: iface_name,
        link,
        stop_flag,
    })
}

fn run(
    mut cap: Capture<pcap::Active>,
    link: LinkType,
    started_at: Instant,
    stop_flag: Arc<AtomicBool>,
    tx: UnboundedSender<CaptureEvent>,
) {
    let mut seq: u64 = 0;
    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let data = pkt.data.to_vec();
                let wire_len = pkt.header.len as usize;
                let ts = started_at.elapsed();
                let (_dec, summary) = decode(link, &data);
                seq += 1;
                let p = CapturedPacket {
                    seq,
                    ts,
                    wire_len,
                    data,
                    summary,
                };
                if tx.send(CaptureEvent::Packet(p)).is_err() {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                let _ = tx.send(CaptureEvent::Error(e.to_string()));
                break;
            }
        }
    }
    let _ = tx.send(CaptureEvent::Ended);
}

pub fn try_start_or_error(opts: CaptureOptions) -> StartResult {
    match start(opts) {
        Ok(h) => StartResult::Started(h),
        Err(e) => {
            let lower = e.to_lowercase();
            if lower.contains("permission")
                || lower.contains("operation not permitted")
                || lower.contains("eperm")
            {
                StartResult::NeedsPrivilege(e)
            } else {
                StartResult::Failed(e)
            }
        }
    }
}

pub enum StartResult {
    Started(CaptureHandle),
    NeedsPrivilege(String),
    Failed(String),
}
