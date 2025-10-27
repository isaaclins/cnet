use dns_lookup::lookup_addr;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{stdout, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream as BlockingTcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, Receiver, TryRecvError},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use arboard::Clipboard;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::stream::{self, StreamExt};
use get_if_addrs::{get_if_addrs, IfAddr};
use ipnetwork::Ipv4Network;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, SERVER};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::runtime::Builder;
use tokio::task;
use tokio::time::timeout;

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};

const CONNECT_TIMEOUT_MS: u64 = 200;
const PROBE_TIMEOUT_MS: u64 = 60;
const MIN_PREFIX: u8 = 24;
const MAX_HOSTS_TO_SCAN: usize = 512;
const HOST_CONCURRENCY: usize = 64;
const PROBE_PORTS: &[u16] = &[1, 22, 80];
const MAX_FINGERPRINT_LEN: usize = 80;
const MAX_HOSTNAME_LEN: usize = 80;

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

struct Spinner {
    frame: usize,
}

impl Spinner {
    fn new() -> Self {
        Spinner { frame: 0 }
    }

    fn advance(&mut self) {
        self.frame = (self.frame + 1) % 3;
    }

    fn text(&self) -> String {
        format!("Scanning{}", ".".repeat(self.frame + 1))
    }
}

struct UiStatus<'a> {
    spinner_text: Option<&'a str>,
    scan_complete: bool,
    status_message: Option<&'a str>,
}

enum ScanMessage {
    HostProgress {
        processed: usize,
        report: Option<HostReport>,
    },
    Finished,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExportMode {
    Normal,
    ChoosingFormat,
}

#[derive(Clone, Copy)]
enum ExportFormat {
    Json,
    Csv,
    Markdown,
}

impl ExportFormat {
    fn file_name(&self) -> &'static str {
        match self {
            ExportFormat::Json => "scan_results.json",
            ExportFormat::Csv => "scan_results.csv",
            ExportFormat::Markdown => "scan_results.md",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OverlayState {
    Hidden,
    ActionMenu,
}

struct ActionItem {
    key: char,
    label: &'static str,
    description: &'static str,
}

const ACTION_ITEMS: &[ActionItem] = &[
    ActionItem {
        key: 'r',
        label: "Rescan Host",
        description: "Probe the highlighted host again",
    },
    ActionItem {
        key: 'd',
        label: "Resolve Hostnames",
        description: "Reverse DNS lookup for discovered hosts",
    },
    ActionItem {
        key: 'm',
        label: "Resolve MAC/Vendor",
        description: "Read local ARP entries for hardware details",
    },
    ActionItem {
        key: 'c',
        label: "Copy Selection",
        description: "Copy the focused IP or host:port to the clipboard",
    },
    ActionItem {
        key: 'o',
        label: "Open Service",
        description: "Launch the selected service URL in a browser",
    },
    ActionItem {
        key: 'e',
        label: "Export Results",
        description: "Save the scan as JSON, CSV, or Markdown",
    },
    ActionItem {
        key: 'h',
        label: "Toggle Actions",
        description: "Show or hide this overlay",
    },
    ActionItem {
        key: 'q',
        label: "Quit",
        description: "Exit cnet",
    },
];

fn main() -> std::io::Result<()> {
    let use_fake = env::args().any(|arg| arg == "--fake");

    let (mut scan_results, scan_rx) = match if use_fake {
        start_fake_scan()
    } else {
        start_scan()
    } {
        Ok(result) => result,
        Err(err) => {
            eprintln!("Failed to start scan: {err}");
            return Ok(());
        }
    };

    terminal::enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    terminal.hide_cursor()?;

    let outcome = run_app(&mut terminal, &mut scan_results, scan_rx, use_fake);

    terminal.show_cursor()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    match outcome {
        Ok(Some(selection)) => {
            if let Some(host) = scan_results.hosts.get(selection.host_index) {
                if let Some(port) = host.ports.get(selection.port_index) {
                    let service_label = port
                        .fingerprint
                        .as_deref()
                        .unwrap_or_else(|| port.service.unwrap_or("unknown service"));
                    println!("Host: {}", host.ip);
                    if let Some(hostname) = host.hostname() {
                        println!("Hostname: {hostname}");
                    }
                    println!("Port: {}", port.port);
                    println!("Service: {}", service_label);
                    if let Some(fingerprint) = &port.fingerprint {
                        println!("Fingerprint: {fingerprint}");
                    }
                    println!("URL: {}", port.url_display);
                    match &port.public_status {
                        PublicStatus::Accessible {
                            ip,
                            port: public_port,
                        } => {
                            println!("Public endpoint: {ip}:{public_port}");
                        }
                        PublicStatus::NotAccessible => {
                            println!("Public endpoint: not reachable");
                        }
                        PublicStatus::Unknown => println!("Public endpoint: unknown"),
                        PublicStatus::Error(msg) => {
                            println!("Public check failed: {msg}");
                        }
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

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    scan: &mut ScanResults,
    scan_rx: Receiver<ScanMessage>,
    fake_mode: bool,
) -> Result<Option<Selection>, String> {
    let mut state = ViewState::Hosts { selected: 0 };
    let mut checker = PublicAccessChecker::new();
    let mut spinner = Spinner::new();
    let mut spinner_text = Some(spinner.text());
    let spinner_interval = Duration::from_millis(400);
    let mut last_tick = Instant::now();
    let mut force_draw = true;
    let mut status_message: Option<String> = if fake_mode {
        Some("Simulated network loaded (--fake).".to_string())
    } else {
        None
    };
    let mut export_mode = ExportMode::Normal;
    let mut overlay = OverlayState::Hidden;

    drain_pending_events().map_err(|err| err.to_string())?;

    loop {
        let mut needs_draw = force_draw;

        loop {
            match scan_rx.try_recv() {
                Ok(ScanMessage::HostProgress { processed, report }) => {
                    scan.hosts_considered = processed;
                    if let Some(host) = report {
                        let _ = scan.insert_host(host);
                    }
                    needs_draw = true;
                }
                Ok(ScanMessage::Finished) => {
                    scan.scan_complete = true;
                    spinner_text = None;
                    needs_draw = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    scan.scan_complete = true;
                    spinner_text = None;
                    break;
                }
            }
        }

        if !scan.scan_complete && last_tick.elapsed() >= spinner_interval {
            spinner.advance();
            spinner_text = Some(spinner.text());
            last_tick = Instant::now();
            needs_draw = true;
        }

        if needs_draw {
            let status = UiStatus {
                spinner_text: spinner_text.as_deref(),
                scan_complete: scan.scan_complete,
                status_message: status_message.as_deref(),
            };
            terminal
                .draw(|frame| {
                    render_ui(
                        frame,
                        &state,
                        scan,
                        &mut checker,
                        &status,
                        overlay,
                        export_mode,
                    );
                })
                .map_err(|err| err.to_string())?;
            force_draw = false;
        }

        let timeout = Duration::from_millis(100);
        if !event::poll(timeout).map_err(|err| err.to_string())? {
            continue;
        }

        let mut state_changed = false;
        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                if matches!(export_mode, ExportMode::ChoosingFormat) {
                    match key.code {
                        KeyCode::Char('j') | KeyCode::Char('J') => {
                            export_mode = ExportMode::Normal;
                            match export_scan_results(scan, ExportFormat::Json) {
                                Ok(path) => {
                                    status_message = Some(format!(
                                        "Exported JSON to {}",
                                        human_display_path(&path)
                                    ));
                                }
                                Err(err) => {
                                    status_message = Some(format!("JSON export failed: {err}"));
                                }
                            }
                            force_draw = true;
                            continue;
                        }
                        KeyCode::Char('c') | KeyCode::Char('C') => {
                            export_mode = ExportMode::Normal;
                            match export_scan_results(scan, ExportFormat::Csv) {
                                Ok(path) => {
                                    status_message = Some(format!(
                                        "Exported CSV to {}",
                                        human_display_path(&path)
                                    ));
                                }
                                Err(err) => {
                                    status_message = Some(format!("CSV export failed: {err}"));
                                }
                            }
                            force_draw = true;
                            continue;
                        }
                        KeyCode::Char('m') | KeyCode::Char('M') => {
                            export_mode = ExportMode::Normal;
                            match export_scan_results(scan, ExportFormat::Markdown) {
                                Ok(path) => {
                                    status_message = Some(format!(
                                        "Exported Markdown to {}",
                                        human_display_path(&path)
                                    ));
                                }
                                Err(err) => {
                                    status_message = Some(format!("Markdown export failed: {err}"));
                                }
                            }
                            force_draw = true;
                            continue;
                        }
                        KeyCode::Esc => {
                            export_mode = ExportMode::Normal;
                            status_message = Some("Export cancelled.".to_string());
                            force_draw = true;
                            continue;
                        }
                        _ => continue,
                    }
                }

                if overlay == OverlayState::ActionMenu {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('H') => {
                            overlay = OverlayState::Hidden;
                            force_draw = true;
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Up => match &mut state {
                        ViewState::Hosts { selected } => {
                            if !scan.hosts.is_empty() {
                                *selected = if *selected == 0 {
                                    scan.hosts.len() - 1
                                } else {
                                    *selected - 1
                                };
                                state_changed = true;
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
                                    state_changed = true;
                                }
                            }
                        }
                    },
                    KeyCode::Down => match &mut state {
                        ViewState::Hosts { selected } => {
                            if !scan.hosts.is_empty() {
                                *selected = (*selected + 1) % scan.hosts.len();
                                state_changed = true;
                            }
                        }
                        ViewState::Ports {
                            host_index,
                            port_index,
                        } => {
                            if let Some(host) = scan.hosts.get(*host_index) {
                                if !host.ports.is_empty() {
                                    *port_index = (*port_index + 1) % host.ports.len();
                                    state_changed = true;
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
                                    state_changed = true;
                                }
                            }
                        }
                        ViewState::Ports { host_index, .. } => {
                            state = ViewState::Hosts {
                                selected: host_index.min(scan.hosts.len().saturating_sub(1)),
                            };
                            state_changed = true;
                        }
                    },
                    KeyCode::Right => match &mut state {
                        ViewState::Hosts { selected } => {
                            if !scan.hosts.is_empty() {
                                *selected = (*selected + 1) % scan.hosts.len();
                                state_changed = true;
                            }
                        }
                        ViewState::Ports {
                            host_index,
                            port_index,
                        } => {
                            if let Some(host) = scan.hosts.get(*host_index) {
                                if !host.ports.is_empty() {
                                    *port_index = (*port_index + 1) % host.ports.len();
                                    state_changed = true;
                                }
                            }
                        }
                    },
                    KeyCode::Backspace => {
                        if let ViewState::Ports { host_index, .. } = state {
                            state = ViewState::Hosts {
                                selected: host_index.min(scan.hosts.len().saturating_sub(1)),
                            };
                            state_changed = true;
                        }
                    }
                    KeyCode::Enter => match state {
                        ViewState::Hosts { selected } => {
                            if !scan.hosts.is_empty() {
                                let safe_index = selected % scan.hosts.len();
                                if let Some(host) = scan.hosts.get(safe_index) {
                                    if !host.ports.is_empty() {
                                        state = ViewState::Ports {
                                            host_index: safe_index,
                                            port_index: 0,
                                        };
                                        state_changed = true;
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
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        if let ViewState::Hosts { selected } = &mut state {
                            if scan.hosts.is_empty() {
                                status_message = Some("No hosts available to rescan.".to_string());
                            } else {
                                let host_index = (*selected).min(scan.hosts.len() - 1);
                                let host_ip = scan.hosts[host_index].ip_addr;
                                let host_label = scan.hosts[host_index].ip.clone();
                                match rescan_host_blocking(host_ip) {
                                    Ok(Some(report)) => {
                                        let idx = scan.insert_host(report);
                                        *selected = idx;
                                        if let Some(updated) = scan.hosts.get(idx) {
                                            let count = updated.ports.len();
                                            let plural = if count == 1 { "" } else { "s" };
                                            status_message = Some(format!(
                                                "Rescan complete for {} ({} open port{})",
                                                updated.ip, count, plural
                                            ));
                                        } else {
                                            status_message =
                                                Some(format!("Rescan complete for {}", host_label));
                                        }
                                    }
                                    Ok(None) => {
                                        let removed = scan.hosts.remove(host_index);
                                        status_message = Some(format!(
                                            "{} no longer has open ports; removed from list.",
                                            removed.ip
                                        ));
                                        if scan.hosts.is_empty() {
                                            *selected = 0;
                                        } else {
                                            let new_index = host_index.min(scan.hosts.len() - 1);
                                            *selected = new_index;
                                        }
                                    }
                                    Err(err) => {
                                        status_message = Some(format!(
                                            "Rescan failed for {}: {}",
                                            host_label, err
                                        ));
                                    }
                                }
                            }
                            force_draw = true;
                            state_changed = true;
                        }
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        if matches!(state, ViewState::Hosts { .. }) {
                            if scan.hosts.is_empty() {
                                status_message = Some("No hosts discovered yet.".to_string());
                            } else {
                                let unresolved: Vec<Ipv4Addr> = scan
                                    .hosts
                                    .iter()
                                    .filter(|host| host.hostname().is_none())
                                    .map(|host| host.ip_addr)
                                    .collect();

                                if unresolved.is_empty() {
                                    status_message =
                                        Some("All hosts already have hostnames.".to_string());
                                } else {
                                    let resolved = resolve_hostnames_blocking(&unresolved);
                                    if resolved.is_empty() {
                                        status_message =
                                            Some("No hostnames could be resolved.".to_string());
                                    } else {
                                        let count = resolved.len();
                                        for host in &mut scan.hosts {
                                            if let Some(name) = resolved.get(&host.ip_addr) {
                                                host.set_hostname(Some(name.clone()));
                                            }
                                        }
                                        let plural = if count == 1 { "" } else { "s" };
                                        status_message =
                                            Some(format!("Resolved {count} hostname{plural}."));
                                    }
                                }
                            }
                            force_draw = true;
                            state_changed = true;
                        }
                    }
                    KeyCode::Char('m') | KeyCode::Char('M') => {
                        if matches!(state, ViewState::Hosts { .. }) {
                            if scan.hosts.is_empty() {
                                status_message = Some("No hosts discovered yet.".to_string());
                            } else {
                                let ips: Vec<Ipv4Addr> =
                                    scan.hosts.iter().map(|host| host.ip_addr).collect();
                                match resolve_mac_addresses_blocking(&ips) {
                                    Ok(resolved) => {
                                        if resolved.is_empty() {
                                            status_message = Some(
                                                "No MAC addresses found. Try pinging the hosts first."
                                                    .to_string(),
                                            );
                                        } else {
                                            let mut updated = 0usize;
                                            for host in &mut scan.hosts {
                                                if let Some(info) = resolved.get(&host.ip_addr) {
                                                    let mac_diff = match host.mac_address() {
                                                        Some(existing) => {
                                                            existing != info.mac.as_str()
                                                        }
                                                        None => true,
                                                    };

                                                    let vendor_diff = match (
                                                        host.vendor(),
                                                        info.vendor.as_deref(),
                                                    ) {
                                                        (Some(existing), Some(candidate)) => {
                                                            existing != candidate
                                                        }
                                                        (Some(_), None) => false,
                                                        (None, Some(_)) => true,
                                                        (None, None) => false,
                                                    };

                                                    if mac_diff || vendor_diff {
                                                        host.set_mac_info(
                                                            Some(info.mac.clone()),
                                                            info.vendor.clone(),
                                                        );
                                                        updated += 1;
                                                    }
                                                }
                                            }

                                            if updated == 0 {
                                                status_message = Some(
                                                    "MAC addresses already resolved.".to_string(),
                                                );
                                            } else {
                                                let plural = if updated == 1 { "" } else { "es" };
                                                status_message = Some(format!(
                                                    "Resolved {updated} MAC address{plural}."
                                                ));
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        status_message = Some(format!("MAC lookup failed: {err}"));
                                    }
                                }
                            }
                            force_draw = true;
                            state_changed = true;
                        }
                    }
                    KeyCode::Char('e') | KeyCode::Char('E') => {
                        if matches!(export_mode, ExportMode::ChoosingFormat) {
                            continue;
                        }

                        if !scan.scan_complete {
                            status_message =
                                Some("Scan still running; export after completion.".to_string());
                        } else {
                            export_mode = ExportMode::ChoosingFormat;
                            overlay = OverlayState::Hidden;
                            status_message = Some(
                                "Choose export format: [J] JSON, [C] CSV, [M] Markdown, Esc to cancel."
                                    .to_string(),
                            );
                        }
                        force_draw = true;
                    }
                    KeyCode::Char('o') | KeyCode::Char('O') => {
                        if let ViewState::Ports {
                            host_index,
                            port_index,
                        } = &state
                        {
                            if let Some(host) = scan.hosts.get(*host_index) {
                                if let Some(port) = host.ports.get(*port_index) {
                                    if let Some(url) = port.url.as_ref() {
                                        match open::that(url) {
                                            Ok(_) => {
                                                status_message =
                                                    Some(format!("Opened {} in browser", url));
                                            }
                                            Err(err) => {
                                                status_message = Some(format!(
                                                    "Failed to open {}: {}",
                                                    url, err
                                                ));
                                            }
                                        }
                                    } else {
                                        status_message = Some(format!(
                                            "No URL available for {} port {}",
                                            host.ip, port.port
                                        ));
                                    }
                                }
                            }
                            force_draw = true;
                        }
                    }
                    KeyCode::Char('c') | KeyCode::Char('C') => match &state {
                        ViewState::Hosts { selected } => {
                            if scan.hosts.is_empty() {
                                status_message = Some("No hosts available to copy.".to_string());
                            } else {
                                let host_index = (*selected).min(scan.hosts.len() - 1);
                                if let Some(host) = scan.hosts.get(host_index) {
                                    let clip_text = host.ip.clone();
                                    match Clipboard::new() {
                                        Ok(mut clipboard) => {
                                            match clipboard.set_text(clip_text.clone()) {
                                                Ok(()) => {
                                                    status_message = Some(format!(
                                                        "Copied {} to clipboard",
                                                        clip_text
                                                    ));
                                                }
                                                Err(err) => {
                                                    status_message =
                                                        Some(format!("Clipboard error: {}", err));
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            status_message =
                                                Some(format!("Clipboard unavailable: {}", err));
                                        }
                                    }
                                }
                            }
                            force_draw = true;
                        }
                        ViewState::Ports {
                            host_index,
                            port_index,
                        } => {
                            if let Some(host) = scan.hosts.get(*host_index) {
                                if let Some(port) = host.ports.get(*port_index) {
                                    let clip_text = format!("{}:{}", host.ip, port.port);
                                    match Clipboard::new() {
                                        Ok(mut clipboard) => {
                                            match clipboard.set_text(clip_text.clone()) {
                                                Ok(()) => {
                                                    status_message = Some(format!(
                                                        "Copied {} to clipboard",
                                                        clip_text
                                                    ));
                                                }
                                                Err(err) => {
                                                    status_message =
                                                        Some(format!("Clipboard error: {}", err));
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            status_message =
                                                Some(format!("Clipboard unavailable: {}", err));
                                        }
                                    }
                                }
                            }
                            force_draw = true;
                        }
                    },
                    KeyCode::Char('h') | KeyCode::Char('H') => {
                        if matches!(export_mode, ExportMode::ChoosingFormat) {
                            status_message = Some(
                                "Finish choosing an export format first (Esc to cancel)."
                                    .to_string(),
                            );
                        } else {
                            overlay = match overlay {
                                OverlayState::Hidden => OverlayState::ActionMenu,
                                OverlayState::ActionMenu => OverlayState::Hidden,
                            };
                        }
                        force_draw = true;
                    }
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(None),
                    _ => {}
                }
            }
            Ok(Event::Resize(_, _)) => {
                force_draw = true;
            }
            Ok(_) => {}
            Err(err) => return Err(err.to_string()),
        }

        if state_changed {
            force_draw = true;
        }
    }
}

fn render_ui(
    frame: &mut Frame<'_>,
    state: &ViewState,
    scan: &mut ScanResults,
    checker: &mut PublicAccessChecker,
    status: &UiStatus,
    overlay: OverlayState,
    export_mode: ExportMode,
) {
    let area = frame.size();
    if area.width < 2 || area.height < 2 {
        return;
    }

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(5),
        ])
        .split(area);

    render_status_panel(frame, scan, status, vertical[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(vertical[1]);

    render_hosts_view(frame, scan, state, body[0]);
    render_port_panel(frame, scan, checker, state, body[1]);

    let footer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(2)])
        .split(vertical[2]);

    render_progress_gauge(frame, scan, status, footer[0]);
    render_instructions(frame, state, export_mode, footer[1]);

    if matches!(overlay, OverlayState::ActionMenu) {
        draw_actions_overlay(frame, area);
    }
}

fn render_status_panel(frame: &mut Frame<'_>, scan: &ScanResults, status: &UiStatus, area: Rect) {
    let mut lines = Vec::new();

    let status_span = if let Some(text) = status.spinner_text {
        Span::styled(
            text.to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else if status.scan_complete {
        Span::styled(
            "Scan complete".to_string(),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "Idle".to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    };
    lines.push(Line::from(vec![status_span]));

    lines.push(Line::from(vec![
        Span::styled("Local IP: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(scan.local_ip.to_string()),
        Span::raw("   "),
        Span::styled(
            "Hosts probed: ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "{} / {}",
            scan.hosts_considered, scan.hosts_planned
        )),
        Span::raw("   "),
        Span::styled(
            "Open hosts: ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(scan.hosts.len().to_string()),
    ]));

    if let Some(message) = status.status_message {
        lines.push(Line::from(Span::styled(
            message.to_string(),
            Style::default().fg(Color::Yellow),
        )));
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Status").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_hosts_view(frame: &mut Frame<'_>, scan: &ScanResults, state: &ViewState, area: Rect) {
    if scan.hosts.is_empty() {
        let message = if scan.scan_complete {
            "No hosts with open ports were discovered."
        } else {
            "Scanning for hosts..."
        };
        let paragraph = Paragraph::new(message)
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title("Hosts").borders(Borders::ALL));
        frame.render_widget(paragraph, area);
        return;
    }

    let mut table_state = TableState::default();
    let highlight = match *state {
        ViewState::Hosts { selected } => Some(selected.min(scan.hosts.len() - 1)),
        ViewState::Ports { host_index, .. } => Some(host_index.min(scan.hosts.len() - 1)),
    };
    table_state.select(highlight);

    let header = Row::new(vec![
        Cell::from("IP Address"),
        Cell::from("MAC"),
        Cell::from("Vendor"),
        Cell::from("Ports"),
        Cell::from("Services"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows = scan.hosts.iter().map(|host| {
        Row::new(vec![
            Cell::from(host.ip_display().to_string()),
            Cell::from(host.mac_display().to_string()),
            Cell::from(host.vendor_display().to_string()),
            Cell::from(host.ports_display.clone()),
            Cell::from(host.services_display.clone()),
        ])
    });

    let widths = [
        Constraint::Percentage(30),
        Constraint::Percentage(18),
        Constraint::Percentage(20),
        Constraint::Percentage(12),
        Constraint::Percentage(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title("Hosts").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_port_panel(
    frame: &mut Frame<'_>,
    scan: &mut ScanResults,
    checker: &mut PublicAccessChecker,
    state: &ViewState,
    area: Rect,
) {
    if scan.hosts.is_empty() {
        let paragraph = Paragraph::new("No hosts discovered yet.")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title("Ports").borders(Borders::ALL));
        frame.render_widget(paragraph, area);
        return;
    }

    let host_index = match *state {
        ViewState::Hosts { selected } => Some(selected.min(scan.hosts.len() - 1)),
        ViewState::Ports { host_index, .. } => Some(host_index.min(scan.hosts.len() - 1)),
    };

    let Some(host_index) = host_index else {
        let paragraph = Paragraph::new("No host selected.")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title("Ports").borders(Borders::ALL));
        frame.render_widget(paragraph, area);
        return;
    };

    update_public_status(scan, checker, host_index);

    let Some(host) = scan.hosts.get(host_index) else {
        let paragraph =
            Paragraph::new("Host no longer available. Press ← to return to the host list.")
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().title("Ports").borders(Borders::ALL));
        frame.render_widget(paragraph, area);
        return;
    };

    let block = Block::default()
        .title(format!("Ports for {}", host.ip))
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let segments = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(1)])
        .split(inner);

    let mut summary_lines = Vec::new();
    summary_lines.push(Line::from(vec![
        Span::styled("Hostname: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(host.hostname().unwrap_or("-").to_string()),
    ]));
    summary_lines.push(Line::from(vec![
        Span::styled("MAC: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(host.mac_display().to_string()),
        Span::raw("   "),
        Span::styled("Vendor: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(host.vendor_display().to_string()),
    ]));
    summary_lines.push(Line::from(vec![
        Span::styled("Services: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(host.services_display.clone()),
    ]));

    frame.render_widget(
        Paragraph::new(summary_lines).wrap(Wrap { trim: true }),
        segments[0],
    );

    if host.ports.is_empty() {
        let paragraph = Paragraph::new("No open ports recorded for this host.")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(paragraph, segments[1]);
        return;
    }

    let header = Row::new(vec![
        Cell::from("Port"),
        Cell::from("Service"),
        Cell::from("URL"),
        Cell::from("Public"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows = host.ports.iter().map(|port| {
        Row::new(vec![
            Cell::from(port.port.to_string()),
            Cell::from(service_label(port)),
            Cell::from(port.url_display.clone()),
            Cell::from(port.public_label.clone()),
        ])
    });

    let mut table_state = TableState::default();
    let selected_port = match *state {
        ViewState::Ports {
            host_index: active_host,
            port_index,
        } if active_host == host_index => Some(port_index.min(host.ports.len() - 1)),
        _ => None,
    };
    table_state.select(selected_port);

    let widths = [
        Constraint::Length(6),
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(24),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, segments[1], &mut table_state);
}

fn render_progress_gauge(frame: &mut Frame<'_>, scan: &ScanResults, status: &UiStatus, area: Rect) {
    let planned = scan.hosts_planned.max(1);
    let ratio = (scan.hosts_considered.min(planned) as f64 / planned as f64).clamp(0.0, 1.0);
    let label = format!(
        "{} / {} hosts probed",
        scan.hosts_considered, scan.hosts_planned
    );

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title("Scan Progress")
                .borders(Borders::ALL),
        )
        .gauge_style(if status.scan_complete {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Cyan)
        })
        .ratio(ratio)
        .label(label);

    frame.render_widget(gauge, area);
}

fn render_instructions(
    frame: &mut Frame<'_>,
    state: &ViewState,
    export_mode: ExportMode,
    area: Rect,
) {
    let key = |text: &str| {
        Span::styled(
            text.to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    };

    let lines = if matches!(export_mode, ExportMode::ChoosingFormat) {
        vec![
            Line::from(vec![
                key("[J]"),
                Span::raw(" JSON   "),
                key("[C]"),
                Span::raw(" CSV   "),
                key("[M]"),
                Span::raw(" Markdown"),
            ]),
            Line::from(vec![key("Esc"), Span::raw(" to cancel")]),
        ]
    } else {
        let mut content = Vec::new();
        content.push(Line::from(vec![
            key("↑/↓"),
            Span::raw(" navigate  "),
            key("Enter"),
            Span::raw(" inspect  "),
            key("←"),
            Span::raw(" back"),
        ]));
        content.push(Line::from(vec![
            key("R"),
            Span::raw(" rescan  "),
            key("D"),
            Span::raw(" resolve DNS  "),
            key("M"),
            Span::raw(" resolve MAC  "),
            key("E"),
            Span::raw(" export  "),
            key("H"),
            Span::raw(" actions  "),
            key("Q"),
            Span::raw(" quit"),
        ]));

        if matches!(*state, ViewState::Ports { .. }) {
            content.push(Line::from(vec![
                key("C"),
                Span::raw(" copy host:port  "),
                key("O"),
                Span::raw(" open in browser"),
            ]));
        }

        content
    };

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Controls").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn draw_actions_overlay(frame: &mut Frame<'_>, area: Rect) {
    if area.width < 4 || area.height < 4 {
        return;
    }

    let overlay_area = centered_rect(60, 70, area);
    frame.render_widget(Clear, overlay_area);

    let mut lines = Vec::new();
    for item in ACTION_ITEMS {
        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}]", item.key.to_ascii_uppercase()),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(item.label, Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" — "),
            Span::raw(item.description),
        ]));
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Actions")
                .borders(Borders::ALL)
                .style(Style::default().bg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, overlay_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x).saturating_div(2)),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x).saturating_div(2)),
        ])
        .split(area);

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y).saturating_div(2)),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y).saturating_div(2)),
        ])
        .split(horizontal[1]);

    vertical[1]
}

fn update_public_status(
    scan: &mut ScanResults,
    checker: &mut PublicAccessChecker,
    host_index: usize,
) {
    if let Some(host) = scan.hosts.get_mut(host_index) {
        for port in &mut host.ports {
            if matches!(port.public_status, PublicStatus::Unknown) {
                let status = checker.check_port(host.ip_addr, scan.local_ip, port.port);
                port.set_public_status(status);
            }
        }
    }
}

fn drain_pending_events() -> std::io::Result<()> {
    while event::poll(Duration::from_millis(0))? {
        let _ = event::read()?;
    }
    Ok(())
}

fn start_fake_scan() -> Result<(ScanResults, Receiver<ScanMessage>), String> {
    let fake_local_ip = Ipv4Addr::new(10, 42, 0, 1);
    let hosts = build_fake_hosts(fake_local_ip);
    let host_count = hosts.len();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut processed = 0usize;
        for host in hosts {
            processed += 1;
            let _ = tx.send(ScanMessage::HostProgress {
                processed,
                report: Some(host),
            });
            thread::sleep(Duration::from_millis(120));
        }
        let _ = tx.send(ScanMessage::Finished);
    });

    let scan_results = ScanResults {
        hosts: Vec::new(),
        hosts_considered: 0,
        hosts_planned: host_count,
        local_ip: fake_local_ip,
        scan_complete: false,
    };

    Ok((scan_results, rx))
}

fn build_fake_hosts(local_ip: Ipv4Addr) -> Vec<HostReport> {
    let mut hosts = Vec::new();

    let mut workstation = HostReport::new(
        local_ip,
        Some("workstation".to_string()),
        vec![
            fake_port(
                22,
                Some("SSH"),
                Some("OpenSSH_9.3p1"),
                None,
                PublicStatus::NotAccessible,
            ),
            fake_port(
                9000,
                Some("HTTPS"),
                Some("Traefik Dashboard"),
                Some(format!("https://{local_ip}:9000/")),
                PublicStatus::NotAccessible,
            ),
        ],
    );
    workstation.set_mac_info(
        Some("02:42:0A:2A:00:01".to_string()),
        Some("Demo Hardware".to_string()),
    );
    hosts.push(workstation);

    let mut buildbox = HostReport::new(
        Ipv4Addr::new(10, 42, 0, 12),
        Some("buildbox".to_string()),
        vec![
            fake_port(
                8080,
                Some("HTTP"),
                Some("Jenkins 2.452"),
                Some("http://10.42.0.12:8080/".to_string()),
                PublicStatus::NotAccessible,
            ),
            fake_port(
                5000,
                Some("HTTP"),
                Some("Internal API"),
                Some("http://10.42.0.12:5000/".to_string()),
                PublicStatus::NotAccessible,
            ),
        ],
    );
    buildbox.set_mac_info(
        Some("02:42:0A:2A:00:12".to_string()),
        Some("BuildCo".to_string()),
    );
    hosts.push(buildbox);

    let mut edge = HostReport::new(
        Ipv4Addr::new(10, 42, 0, 30),
        Some("edge-proxy".to_string()),
        vec![fake_port(
            443,
            Some("HTTPS"),
            Some("Envoy 1.29"),
            Some("https://10.42.0.30/".to_string()),
            PublicStatus::Accessible {
                ip: "203.0.113.52".to_string(),
                port: 443,
            },
        )],
    );
    edge.set_mac_info(
        Some("02:42:0A:2A:00:30".to_string()),
        Some("Edge Systems".to_string()),
    );
    hosts.push(edge);

    let mut database = HostReport::new(
        Ipv4Addr::new(10, 42, 0, 50),
        None,
        vec![fake_port(
            5432,
            Some("Postgres"),
            Some("PostgreSQL 15.3"),
            None,
            PublicStatus::NotAccessible,
        )],
    );
    database.set_mac_info(
        Some("02:42:0A:2A:00:50".to_string()),
        Some("DataStack".to_string()),
    );
    hosts.push(database);

    hosts
}

fn fake_port(
    port: u16,
    service: Option<&'static str>,
    fingerprint: Option<&str>,
    url: Option<String>,
    public_status: PublicStatus,
) -> PortInfo {
    let public_label = public_status.label();
    let url_display = url.clone().unwrap_or_else(|| "-".to_string());
    PortInfo {
        port,
        service,
        fingerprint: fingerprint.map(|value| value.to_string()),
        url,
        url_display,
        public_label,
        public_status,
    }
}

fn start_scan() -> Result<(ScanResults, Receiver<ScanMessage>), String> {
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
        .filter(|ip| *ip != network_addr && *ip != broadcast_addr && *ip != v4.ip)
        .take(MAX_HOSTS_TO_SCAN)
        .collect();
    let hosts_planned = host_ips.len();

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let runtime = match Builder::new_multi_thread()
            .enable_all()
            .thread_name("cnet-scanner")
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                eprintln!("Failed to build async runtime: {err}");
                let _ = tx.send(ScanMessage::Finished);
                return;
            }
        };

        let ports = Arc::new(default_port_list());
        let processed = Arc::new(AtomicUsize::new(0));

        runtime.block_on(async move {
            let sender = tx.clone();

            stream::iter(host_ips.into_iter())
                .for_each_concurrent(Some(HOST_CONCURRENCY), {
                    let ports = Arc::clone(&ports);
                    let processed = Arc::clone(&processed);
                    move |ip| {
                        let tx = sender.clone();
                        let ports = Arc::clone(&ports);
                        let processed = Arc::clone(&processed);
                        async move {
                            let report = scan_host_async(ip, ports.as_slice()).await;
                            let processed = processed.fetch_add(1, Ordering::Relaxed) + 1;
                            let _ = tx.send(ScanMessage::HostProgress { processed, report });
                        }
                    }
                })
                .await;

            let _ = tx.send(ScanMessage::Finished);
        });
    });

    let scan_results = ScanResults {
        hosts: Vec::new(),
        hosts_considered: 0,
        hosts_planned,
        local_ip: v4.ip,
        scan_complete: false,
    };

    Ok((scan_results, rx))
}

async fn host_is_reachable_async(ip: Ipv4Addr) -> bool {
    let timeout_duration = Duration::from_millis(PROBE_TIMEOUT_MS);

    for port in PROBE_PORTS {
        let addr = SocketAddr::new(IpAddr::V4(ip), *port);
        match timeout(timeout_duration, AsyncTcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let _ = stream.shutdown().await;
                return true;
            }
            Ok(Err(err)) => match err.kind() {
                ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::PermissionDenied
                | ErrorKind::AddrInUse
                | ErrorKind::AddrNotAvailable => return true,
                ErrorKind::TimedOut | ErrorKind::WouldBlock => {}
                _ => {}
            },
            Err(_) => {}
        }
    }

    false
}

async fn scan_host_async(ip: Ipv4Addr, ports: &[u16]) -> Option<HostReport> {
    if !host_is_reachable_async(ip).await {
        return None;
    }

    let timeout_duration = Duration::from_millis(CONNECT_TIMEOUT_MS);
    let hostname = reverse_dns_lookup(ip).await;
    let mut open_ports = Vec::new();

    for port in ports {
        let addr = SocketAddr::new(IpAddr::V4(ip), *port);
        match timeout(timeout_duration, AsyncTcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let _ = stream.shutdown().await;
                let service = port_service(*port);
                let url = port_url(ip, *port, service);
                let url_display = url.clone().unwrap_or_else(|| "(unknown)".to_string());
                let fingerprint = fingerprint_service(ip, *port, service).await;
                open_ports.push(PortInfo {
                    port: *port,
                    service,
                    fingerprint,
                    url,
                    url_display,
                    public_status: PublicStatus::Unknown,
                    public_label: String::from("pending"),
                });
            }
            Ok(Err(err)) => {
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
            Err(_) => {}
        }
    }

    if open_ports.is_empty() {
        None
    } else {
        Some(HostReport::new(ip, hostname, open_ports))
    }
}

fn rescan_host_blocking(ip: Ipv4Addr) -> Result<Option<HostReport>, String> {
    let ports = default_port_list();
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;

    Ok(runtime.block_on(scan_host_async(ip, &ports)))
}

async fn reverse_dns_lookup(ip: Ipv4Addr) -> Option<String> {
    task::spawn_blocking(move || reverse_dns_lookup_inner(ip))
        .await
        .ok()
        .flatten()
}

fn reverse_dns_lookup_inner(ip: Ipv4Addr) -> Option<String> {
    lookup_addr(&IpAddr::V4(ip))
        .ok()
        .and_then(|raw| sanitize_hostname(raw.as_str()))
}

fn resolve_hostnames_blocking(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    let mut resolved = HashMap::new();
    for ip in ips {
        if let Some(name) = reverse_dns_lookup_inner(*ip) {
            resolved.insert(*ip, name);
        }
    }
    resolved
}

struct MacInfo {
    mac: String,
    vendor: Option<String>,
}

fn resolve_mac_addresses_blocking(ips: &[Ipv4Addr]) -> Result<HashMap<Ipv4Addr, MacInfo>, String> {
    if ips.is_empty() {
        return Ok(HashMap::new());
    }

    let targets: HashSet<Ipv4Addr> = ips.iter().copied().collect();
    let entries = collect_arp_entries()?;
    let mut resolved = HashMap::new();

    for (ip, mac) in entries {
        if !targets.contains(&ip) {
            continue;
        }

        let vendor = lookup_vendor(&mac).map(|name| name.to_string());
        resolved.entry(ip).or_insert_with(|| MacInfo {
            mac: mac.clone(),
            vendor,
        });
    }

    Ok(resolved)
}

fn collect_arp_entries() -> Result<Vec<(Ipv4Addr, String)>, String> {
    if let Ok(output) = Command::new("arp").arg("-an").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries = parse_arp_output(&stdout);
        if !entries.is_empty() {
            return Ok(entries);
        }
    }

    if let Ok(output) = Command::new("ip").arg("neigh").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries = parse_ip_neigh_output(&stdout);
        if !entries.is_empty() {
            return Ok(entries);
        }
    }

    Ok(Vec::new())
}

fn parse_arp_output(output: &str) -> Vec<(Ipv4Addr, String)> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let start = match trimmed.find('(') {
            Some(idx) => idx,
            None => continue,
        };
        let end = match trimmed[start + 1..].find(')') {
            Some(idx) => start + 1 + idx,
            None => continue,
        };

        let ip_str = &trimmed[start + 1..end];
        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(value) => value,
            Err(_) => continue,
        };

        let mac_start = match trimmed.find(" at ") {
            Some(idx) => idx + 4,
            None => continue,
        };
        let rest = &trimmed[mac_start..];
        let mac_end = rest.find(' ').unwrap_or(rest.len());
        let mac_raw = &rest[..mac_end];

        if mac_raw.eq_ignore_ascii_case("(incomplete)") {
            continue;
        }

        if let Some(mac) = normalize_mac(mac_raw) {
            entries.push((ip, mac));
        }
    }

    entries
}

fn parse_ip_neigh_output(output: &str) -> Vec<(Ipv4Addr, String)> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let ip_str = match parts.next() {
            Some(value) => value,
            None => continue,
        };

        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(value) => value,
            Err(_) => continue,
        };

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if let Some(pos) = tokens.iter().position(|token| *token == "lladdr") {
            if let Some(mac_raw) = tokens.get(pos + 1) {
                if let Some(mac) = normalize_mac(mac_raw) {
                    entries.push((ip, mac));
                }
            }
        }
    }

    entries
}

fn normalize_mac(mac: &str) -> Option<String> {
    let mut hex = String::with_capacity(12);
    for ch in mac.chars() {
        if ch.is_ascii_hexdigit() {
            hex.push(ch.to_ascii_uppercase());
        }
    }

    if hex.len() != 12 {
        return None;
    }

    let bytes = hex.into_bytes();
    let mut formatted = String::with_capacity(17);
    for idx in 0..6 {
        if idx > 0 {
            formatted.push(':');
        }
        formatted.push(bytes[idx * 2] as char);
        formatted.push(bytes[idx * 2 + 1] as char);
    }

    Some(formatted)
}

fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let prefix: String = mac
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_uppercase())
        .take(6)
        .collect();

    if prefix.len() != 6 {
        return None;
    }

    for (candidate, vendor) in VENDOR_PREFIXES {
        if *candidate == prefix {
            return Some(*vendor);
        }
    }

    None
}

const VENDOR_PREFIXES: &[(&str, &str)] = &[
    ("0017F2", "Apple"),
    ("A45E60", "Apple"),
    ("7C2EBD", "Apple"),
    ("BC6778", "Apple"),
    ("F0D1B8", "Amazon"),
    ("38F23E", "Amazon"),
    ("9027E4", "Amazon"),
    ("F4F5E8", "TP-Link"),
    ("14CF92", "TP-Link"),
    ("A044D1", "TP-Link"),
    ("00259C", "Cisco"),
    ("000F66", "Cisco"),
    ("3CB15B", "Cisco"),
    ("24A43C", "Ubiquiti"),
    ("249F89", "Ubiquiti"),
    ("F09FC2", "Ubiquiti"),
    ("B827EB", "Raspberry Pi"),
    ("DC44B6", "Raspberry Pi"),
    ("EC1A59", "Microsoft"),
    ("BC33AC", "Microsoft"),
    ("D4AE52", "Google"),
    ("3C5AB4", "Google"),
    ("18B430", "LG"),
    ("CC61E5", "LG"),
    ("A4CF12", "Samsung"),
    ("D8B1CB", "Samsung"),
    ("1C5CF2", "Samsung"),
    ("C025E9", "Xiaomi"),
    ("64D241", "Sonos"),
    ("F81A67", "Sonos"),
    ("F4C613", "Nest"),
    ("F0B429", "Netgear"),
    ("00146C", "Netgear"),
];

fn export_scan_results(scan: &ScanResults, format: ExportFormat) -> Result<PathBuf, String> {
    let export_dir = env::current_dir()
        .map_err(|err| err.to_string())?
        .join("exports");
    fs::create_dir_all(&export_dir)
        .map_err(|err| format!("Failed to create export directory: {err}"))?;

    let path = export_dir.join(format.file_name());

    match format {
        ExportFormat::Json => export_to_json(scan, &path)?,
        ExportFormat::Csv => export_to_csv(scan, &path)?,
        ExportFormat::Markdown => export_to_markdown(scan, &path)?,
    }

    Ok(path)
}

#[derive(Serialize)]
struct JsonExportData {
    local_ip: String,
    hosts_considered: usize,
    hosts_planned: usize,
    scan_complete: bool,
    hosts: Vec<JsonExportHost>,
}

#[derive(Serialize)]
struct JsonExportHost {
    ip: String,
    hostname: Option<String>,
    mac_address: Option<String>,
    vendor: Option<String>,
    open_ports: Vec<u16>,
    services: Vec<String>,
    ports: Vec<JsonExportPort>,
}

#[derive(Serialize)]
struct JsonExportPort {
    port: u16,
    service: Option<String>,
    service_label: String,
    fingerprint: Option<String>,
    url: Option<String>,
    public: String,
}

fn export_to_json(scan: &ScanResults, path: &Path) -> Result<(), String> {
    let hosts = scan
        .hosts
        .iter()
        .map(|host| JsonExportHost {
            ip: host.ip.clone(),
            hostname: host.hostname().map(|name| name.to_string()),
            mac_address: host.mac_address().map(|value| value.to_string()),
            vendor: host.vendor().map(|value| value.to_string()),
            open_ports: host.ports.iter().map(|p| p.port).collect(),
            services: collect_services(host),
            ports: host
                .ports
                .iter()
                .map(|port| JsonExportPort {
                    port: port.port,
                    service: port.service.map(|s| s.to_string()),
                    service_label: service_label(port),
                    fingerprint: port.fingerprint.clone(),
                    url: port.url.clone(),
                    public: port.public_label.clone(),
                })
                .collect(),
        })
        .collect();

    let payload = JsonExportData {
        local_ip: scan.local_ip.to_string(),
        hosts_considered: scan.hosts_considered,
        hosts_planned: scan.hosts_planned,
        scan_complete: scan.scan_complete,
        hosts,
    };

    let file = File::create(path).map_err(|err| format!("Failed to create JSON file: {err}"))?;
    serde_json::to_writer_pretty(file, &payload)
        .map_err(|err| format!("Failed to write JSON: {err}"))
}

fn export_to_csv(scan: &ScanResults, path: &Path) -> Result<(), String> {
    let mut rows = String::new();
    rows.push_str("host_ip,hostname,mac_address,vendor,port,service,fingerprint,url,public\n");

    if scan.hosts.is_empty() {
        rows.push_str("\n");
    } else {
        for host in &scan.hosts {
            let hostname = host.hostname().unwrap_or("");
            let mac = host.mac_address().unwrap_or("");
            let vendor = host.vendor().unwrap_or("");
            if host.ports.is_empty() {
                rows.push_str(&format!(
                    "{},{},{},{},,,,,\n",
                    csv_escape(&host.ip),
                    csv_escape(hostname),
                    csv_escape(mac),
                    csv_escape(vendor)
                ));
            } else {
                for port in &host.ports {
                    rows.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        csv_escape(&host.ip),
                        csv_escape(hostname),
                        csv_escape(mac),
                        csv_escape(vendor),
                        csv_escape(&port.port.to_string()),
                        csv_escape(&service_label(port)),
                        csv_escape(port.fingerprint.as_deref().unwrap_or("")),
                        csv_escape(port.url.as_deref().unwrap_or("")),
                        csv_escape(&port.public_label)
                    ));
                }
            }
        }
    }

    fs::write(path, rows).map_err(|err| format!("Failed to write CSV: {err}"))
}

fn export_to_markdown(scan: &ScanResults, path: &Path) -> Result<(), String> {
    let mut doc = String::new();
    doc.push_str("# cnet Scan Results\n\n");
    doc.push_str(&format!("*Local IP:* `{}`\n\n", scan.local_ip));

    doc.push_str("| IP Address | Hostname | MAC Address | Vendor | Open Ports | Services |\n");
    doc.push_str("| --- | --- | --- | --- | --- | --- |\n");

    for host in &scan.hosts {
        let hostname = host.hostname().unwrap_or("-");
        doc.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            markdown_escape(&host.ip_display()),
            markdown_escape(hostname),
            markdown_escape(host.mac_display()),
            markdown_escape(host.vendor_display()),
            markdown_escape(&host.ports_display),
            markdown_escape(&host.services_display)
        ));
    }

    if scan.hosts.is_empty() {
        doc.push_str("| *(none)* | | | | | |\n");
    }

    for host in &scan.hosts {
        doc.push_str("\n");
        doc.push_str(&format!("### {}\n\n", markdown_escape(host.ip_display())));
        doc.push_str(&format!(
            "*MAC Address:* `{}`  \n",
            markdown_escape(host.mac_display())
        ));
        doc.push_str(&format!(
            "*Vendor:* `{}`  \n\n",
            markdown_escape(host.vendor_display())
        ));
        doc.push_str("| Port | Service | Fingerprint | URL | Public |\n");
        doc.push_str("| --- | --- | --- | --- | --- |\n");

        if host.ports.is_empty() {
            doc.push_str("| *(none)* | | | | |\n");
        } else {
            for port in &host.ports {
                doc.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    port.port,
                    markdown_escape(&service_label(port)),
                    markdown_escape(port.fingerprint.as_deref().unwrap_or("")),
                    markdown_escape(port.url.as_deref().unwrap_or("")),
                    markdown_escape(&port.public_label)
                ));
            }
        }
    }

    fs::write(path, doc).map_err(|err| format!("Failed to write Markdown: {err}"))
}

fn collect_services(host: &HostReport) -> Vec<String> {
    let mut services = Vec::new();
    for port in &host.ports {
        if let Some(fingerprint) = port.fingerprint.as_ref() {
            if !services.iter().any(|existing| existing == fingerprint) {
                services.push(fingerprint.clone());
            }
            continue;
        }

        if let Some(name) = port.service {
            let name_str = name.to_string();
            if !services.iter().any(|existing| existing == &name_str) {
                services.push(name_str);
            }
        }
    }
    services
}

fn service_label(port: &PortInfo) -> String {
    port.fingerprint
        .clone()
        .unwrap_or_else(|| port.service.unwrap_or("unknown").to_string())
}

fn csv_escape(value: &str) -> String {
    let mut escaped = value.replace('"', "\"\"");
    escaped = escaped.replace('\n', " ");
    format!("\"{}\"", escaped)
}

fn markdown_escape(value: &str) -> String {
    let escaped = value.replace('|', "\\|");
    escaped.replace('\n', " ")
}

fn human_display_path(path: &Path) -> String {
    if let Ok(current) = env::current_dir() {
        if let Ok(relative) = path.strip_prefix(&current) {
            return relative.display().to_string();
        }
    }
    path.display().to_string()
}

// Best-effort fingerprint detection; runs inside spawn_blocking so scans keep progressing.
async fn fingerprint_service(
    ip: Ipv4Addr,
    port: u16,
    service: Option<&'static str>,
) -> Option<String> {
    let service_hint = service;
    task::spawn_blocking(move || match service_hint {
        Some("HTTPS") => fingerprint_http_blocking(ip, port, true)
            .or_else(|| fingerprint_http_blocking(ip, port, false))
            .or_else(|| banner_grab_blocking(ip, port)),
        Some("HTTP")
        | Some("Proxy")
        | Some("Prometheus")
        | Some("Elasticsearch")
        | Some("SonarQube") => {
            fingerprint_http_blocking(ip, port, false).or_else(|| banner_grab_blocking(ip, port))
        }
        Some("SSH") | Some("FTP") | Some("SMTP") | Some("SMTPS") | Some("Telnet") => {
            banner_grab_blocking(ip, port)
        }
        _ => banner_grab_blocking(ip, port),
    })
    .await
    .ok()
    .flatten()
}

fn fingerprint_http_blocking(ip: Ipv4Addr, port: u16, use_https: bool) -> Option<String> {
    let scheme = if use_https { "https" } else { "http" };
    let url = format!("{scheme}://{ip}:{port}/");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(800))
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;
    let response = client.get(url).header(ACCEPT, "*/*").send().ok()?;

    if let Some(server) = response
        .headers()
        .get(SERVER)
        .and_then(|value| value.to_str().ok())
        .and_then(tidy_fingerprint)
    {
        return Some(server);
    }

    if let Some(powered_by) = response
        .headers()
        .get("x-powered-by")
        .and_then(|value| value.to_str().ok())
        .and_then(tidy_fingerprint)
    {
        return Some(powered_by);
    }

    if let Ok(body) = response.text() {
        if let Some(snippet) = extract_title(&body) {
            return Some(snippet);
        }
    }

    None
}

fn banner_grab_blocking(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut stream = BlockingTcpStream::connect_timeout(&addr, Duration::from_millis(600)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
    let mut buffer = [0u8; 256];
    let size = stream.read(&mut buffer).ok()?;
    if size == 0 {
        return None;
    }

    let text = String::from_utf8_lossy(&buffer[..size]);
    tidy_fingerprint(text.lines().next().unwrap_or_default())
}

fn tidy_fingerprint(raw: &str) -> Option<String> {
    let trimmed = raw.trim_matches(|c: char| c.is_control()).trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut cleaned = String::with_capacity(trimmed.len());
    let mut last_was_space = false;
    for ch in trimmed.chars() {
        if ch.is_control() {
            if !last_was_space {
                cleaned.push(' ');
                last_was_space = true;
            }
            continue;
        }
        cleaned.push(ch);
        last_was_space = ch.is_whitespace();
    }

    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return None;
    }

    let mut result = cleaned.to_string();
    if result.len() > MAX_FINGERPRINT_LEN {
        result.truncate(MAX_FINGERPRINT_LEN);
    }

    Some(result)
}

fn sanitize_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let trimmed = trimmed.trim_end_matches('.').trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut cleaned = String::with_capacity(trimmed.len());
    let mut last_was_space = false;
    for ch in trimmed.chars() {
        if ch.is_control() {
            continue;
        }

        if ch.is_whitespace() {
            if !last_was_space {
                cleaned.push(' ');
                last_was_space = true;
            }
            continue;
        }

        cleaned.push(ch);
        last_was_space = false;
    }

    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return None;
    }

    let mut normalized = cleaned.to_string();
    normalized.make_ascii_lowercase();

    if normalized.len() > MAX_HOSTNAME_LEN {
        normalized.truncate(MAX_HOSTNAME_LEN);
    }

    Some(normalized)
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    if let (Some(start), Some(end)) = (lower.find("<title"), lower.find("</title>")) {
        let title_start = body[start..].find('>').map(|idx| start + idx + 1)?;
        let raw_title = body[title_start..end].trim();
        return tidy_fingerprint(raw_title);
    }
    None
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
    hosts_planned: usize,
    local_ip: Ipv4Addr,
    scan_complete: bool,
}

struct HostReport {
    ip_addr: Ipv4Addr,
    ip: String,
    hostname: Option<String>,
    ip_display: String,
    mac: Option<String>,
    mac_display: String,
    vendor: Option<String>,
    vendor_display: String,
    ports: Vec<PortInfo>,
    ports_display: String,
    services_display: String,
}

impl ScanResults {
    fn insert_host(&mut self, host: HostReport) -> usize {
        match self
            .hosts
            .binary_search_by(|existing| existing.ip_addr.cmp(&host.ip_addr))
        {
            Ok(idx) => {
                let mut incoming = host;
                if incoming.hostname().is_none() {
                    if let Some(existing_name) = self.hosts[idx].hostname.clone() {
                        incoming.set_hostname(Some(existing_name));
                    }
                }
                if incoming.mac_address().is_none() {
                    let existing_mac = self.hosts[idx].mac.clone();
                    let existing_vendor = self.hosts[idx].vendor.clone();
                    incoming.set_mac_info(existing_mac, existing_vendor);
                }
                self.hosts[idx] = incoming;
                idx
            }
            Err(idx) => {
                self.hosts.insert(idx, host);
                idx
            }
        }
    }
}

impl HostReport {
    fn new(ip: Ipv4Addr, hostname: Option<String>, ports: Vec<PortInfo>) -> Self {
        let ports_display = if ports.is_empty() {
            "-".to_string()
        } else {
            ports
                .iter()
                .map(|p| p.port.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mut services: Vec<String> = Vec::new();
        for entry in &ports {
            if let Some(fingerprint) = entry.fingerprint.as_ref() {
                if !services.iter().any(|existing| existing == fingerprint) {
                    services.push(fingerprint.clone());
                }
                continue;
            }

            if let Some(name) = entry.service {
                if !services.iter().any(|existing| existing == name) {
                    services.push(name.to_string());
                }
            }
        }
        let services_display = if services.is_empty() {
            "-".to_string()
        } else {
            services.join(", ")
        };

        let mut host = HostReport {
            ip_addr: ip,
            ip: ip.to_string(),
            hostname: None,
            ip_display: String::new(),
            mac: None,
            mac_display: String::from("-"),
            vendor: None,
            vendor_display: String::from("-"),
            ports,
            ports_display,
            services_display,
        };

        host.set_hostname(hostname);
        host
    }

    fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    fn ip_display(&self) -> &str {
        &self.ip_display
    }

    fn set_hostname(&mut self, hostname: Option<String>) {
        self.hostname = hostname;
        self.ip_display = match self.hostname.as_deref() {
            Some(name) => format!("{} ({})", self.ip, name),
            None => self.ip.clone(),
        };
    }

    fn mac_address(&self) -> Option<&str> {
        self.mac.as_deref()
    }

    fn mac_display(&self) -> &str {
        &self.mac_display
    }

    fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    fn vendor_display(&self) -> &str {
        &self.vendor_display
    }

    fn set_mac_info(&mut self, mac: Option<String>, vendor: Option<String>) {
        self.mac = mac;
        self.vendor = vendor;
        self.mac_display = self
            .mac
            .as_deref()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        self.vendor_display = self
            .vendor
            .as_deref()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
    }
}

struct PortInfo {
    port: u16,
    service: Option<&'static str>,
    fingerprint: Option<String>,
    url: Option<String>,
    url_display: String,
    public_status: PublicStatus,
    public_label: String,
}

#[derive(Clone, Debug)]
enum PublicStatus {
    Accessible { ip: String, port: u16 },
    NotAccessible,
    Unknown,
    Error(String),
}

impl PublicStatus {
    fn label(&self) -> String {
        match self {
            PublicStatus::Accessible { ip, port } => format!("{ip}:{port}"),
            PublicStatus::NotAccessible => "private".to_string(),
            PublicStatus::Unknown => "pending".to_string(),
            PublicStatus::Error(msg) => format!("error: {msg}"),
        }
    }
}

impl PortInfo {
    fn set_public_status(&mut self, status: PublicStatus) {
        self.public_status = status;
        self.public_label = self.public_status.label();
    }
}

struct PublicAccessChecker {
    client: Client,
    cache: HashMap<(Ipv4Addr, u16), PublicStatus>,
}

impl PublicAccessChecker {
    fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());

        PublicAccessChecker {
            client,
            cache: HashMap::new(),
        }
    }

    fn check_port(&mut self, host: Ipv4Addr, local_ip: Ipv4Addr, port: u16) -> PublicStatus {
        if let Some(status) = self.cache.get(&(host, port)) {
            return status.clone();
        }

        let status = if host == local_ip {
            self.check_local_public_port(port)
        } else if host.is_private() {
            PublicStatus::NotAccessible
        } else {
            self.probe_public_host(host, port)
        };

        self.cache.insert((host, port), status.clone());
        status
    }

    fn check_local_public_port(&self, port: u16) -> PublicStatus {
        let endpoint = format!("https://ifconfig.co/port/{port}");
        match self
            .client
            .get(&endpoint)
            .header(ACCEPT, "application/json")
            .send()
        {
            Ok(response) => {
                if !response.status().is_success() {
                    return PublicStatus::Error(format!("HTTP {}", response.status().as_u16()));
                }

                match response.json::<PortCheckResponse>() {
                    Ok(body) => {
                        let open = body
                            .open
                            .or(body.reachable)
                            .or_else(|| {
                                body.status.as_ref().map(|status| {
                                    matches!(
                                        status.to_ascii_lowercase().as_str(),
                                        "open" | "reachable"
                                    )
                                })
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
                    Err(err) => PublicStatus::Error(format!("parse: {err}")),
                }
            }
            Err(err) => PublicStatus::Error(err.to_string()),
        }
    }

    fn probe_public_host(&self, host: Ipv4Addr, port: u16) -> PublicStatus {
        let addr = SocketAddr::new(IpAddr::V4(host), port);
        match BlockingTcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            Ok(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
                PublicStatus::Accessible {
                    ip: host.to_string(),
                    port,
                }
            }
            Err(err) => match err.kind() {
                ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted => PublicStatus::NotAccessible,
                ErrorKind::TimedOut | ErrorKind::WouldBlock => PublicStatus::NotAccessible,
                _ => PublicStatus::Error(err.to_string()),
            },
        }
    }
}

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
