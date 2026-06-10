use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyModifiers};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::models::{PublicStatus, ScanResults};
use super::public::spawn_public_check;
use super::scan::{start_scan, ScanHandle, ScanMessage};

const TOAST_DURATION: Duration = Duration::from_millis(1800);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScannerView {
    Hosts,
    Ports { host_index: usize },
}

pub struct ScannerState {
    pub scan: ScanResults,
    pub rx: UnboundedReceiver<ScanMessage>,
    pub tx: UnboundedSender<ScanMessage>,
    pub view: ScannerView,
    pub host_selected: usize,
    pub port_selected: usize,
    pub filter: String,
    pub filter_mode: bool,
    pub toast: Option<(Instant, String)>,
    pub public_requested: HashSet<(Ipv4Addr, u16)>,
}

impl ScannerState {
    pub fn new() -> Result<Self, String> {
        let handle = start_scan()?;
        Ok(Self::from_handle(handle))
    }

    pub fn from_handle(handle: ScanHandle) -> Self {
        Self {
            scan: handle.results,
            rx: handle.rx,
            tx: handle.tx,
            view: ScannerView::Hosts,
            host_selected: 0,
            port_selected: 0,
            filter: String::new(),
            filter_mode: false,
            toast: None,
            public_requested: HashSet::new(),
        }
    }

    pub fn toast_message(&self) -> Option<&str> {
        match &self.toast {
            Some((t, msg)) if t.elapsed() < TOAST_DURATION => Some(msg.as_str()),
            _ => None,
        }
    }

    fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((Instant::now(), msg.into()));
    }

    pub fn filtered_host_indices(&self) -> Vec<usize> {
        if self.filter.is_empty() {
            return (0..self.scan.hosts.len()).collect();
        }
        let needle = self.filter.to_ascii_lowercase();
        self.scan
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| {
                h.ip.contains(&needle)
                    || h.services_display.to_ascii_lowercase().contains(&needle)
                    || h.ports_display.contains(&needle)
            })
            .map(|(i, _)| i)
            .collect()
    }

    pub fn pump(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            self.handle_msg(msg);
        }
    }

    fn handle_msg(&mut self, msg: ScanMessage) {
        match msg {
            ScanMessage::HostProgress { processed, report } => {
                self.scan.hosts_considered = processed;
                if let Some(host) = report {
                    self.scan.insert_host(host);
                }
            }
            ScanMessage::Finished => {
                self.scan.scan_complete = true;
            }
            ScanMessage::PublicStatus { ip, port, status } => {
                if let Some(host) = self.scan.hosts.iter_mut().find(|h| h.ip_addr == ip) {
                    if let Some(p) = host.ports.iter_mut().find(|p| p.port == port) {
                        p.set_public_status(status);
                    }
                }
            }
        }
    }

    fn request_public_checks(&mut self, host_index: usize) {
        let Some(host) = self.scan.hosts.get(host_index) else {
            return;
        };
        let local = self.scan.local_ip;
        for port in &host.ports {
            if matches!(port.public_status, PublicStatus::Unknown)
                && self.public_requested.insert((host.ip_addr, port.port))
            {
                spawn_public_check(self.tx.clone(), host.ip_addr, local, port.port);
            }
        }
    }

    fn copy_current(&mut self) {
        let Some(text) = self.current_action_text() else {
            self.set_toast("nothing to copy");
            return;
        };
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.clone())) {
            Ok(()) => self.set_toast(format!("copied: {text}")),
            Err(e) => self.set_toast(format!("copy failed: {e}")),
        }
    }

    fn open_current(&mut self) {
        let Some(text) = self.current_action_text() else {
            self.set_toast("nothing to open");
            return;
        };
        if !text.contains("://") {
            self.set_toast(format!("not a url: {text}"));
            return;
        }
        match open::that_detached(&text) {
            Ok(()) => self.set_toast(format!("opened: {text}")),
            Err(e) => self.set_toast(format!("open failed: {e}")),
        }
    }

    fn current_action_text(&self) -> Option<String> {
        match self.view {
            ScannerView::Hosts => {
                let visible = self.filtered_host_indices();
                let real = *visible.get(self.host_selected)?;
                Some(self.scan.hosts.get(real)?.ip.clone())
            }
            ScannerView::Ports { host_index } => {
                let host = self.scan.hosts.get(host_index)?;
                let port = host.ports.get(self.port_selected)?;
                if port.url_display == "(unknown)" {
                    Some(format!("{}:{}", host.ip, port.port))
                } else {
                    Some(port.url_display.clone())
                }
            }
        }
    }

    fn rescan(&mut self) {
        match start_scan() {
            Ok(h) => {
                self.scan = h.results;
                self.rx = h.rx;
                self.tx = h.tx;
                self.view = ScannerView::Hosts;
                self.host_selected = 0;
                self.port_selected = 0;
                self.public_requested.clear();
                self.set_toast("rescanning…");
            }
            Err(e) => self.set_toast(format!("rescan failed: {e}")),
        }
    }

    fn move_selection(&mut self, delta: isize) {
        match self.view {
            ScannerView::Hosts => {
                let visible = self.filtered_host_indices();
                if visible.is_empty() {
                    return;
                }
                let len = visible.len() as isize;
                let cur = self.host_selected as isize;
                self.host_selected = ((cur + delta).rem_euclid(len)) as usize;
            }
            ScannerView::Ports { host_index } => {
                let Some(host) = self.scan.hosts.get(host_index) else {
                    return;
                };
                if host.ports.is_empty() {
                    return;
                }
                let len = host.ports.len() as isize;
                let cur = self.port_selected as isize;
                self.port_selected = ((cur + delta).rem_euclid(len)) as usize;
            }
        }
    }

    fn enter_port_view(&mut self) {
        if let ScannerView::Hosts = self.view {
            let visible = self.filtered_host_indices();
            if let Some(&real) = visible.get(self.host_selected) {
                if let Some(host) = self.scan.hosts.get(real) {
                    if !host.ports.is_empty() {
                        self.view = ScannerView::Ports { host_index: real };
                        self.port_selected = 0;
                        self.request_public_checks(real);
                    }
                }
            }
        }
    }

    fn leave_port_view(&mut self) {
        if let ScannerView::Ports { host_index } = self.view {
            let visible = self.filtered_host_indices();
            if let Some(pos) = visible.iter().position(|i| *i == host_index) {
                self.host_selected = pos;
            }
            self.view = ScannerView::Hosts;
        }
    }

    /// Returns true if the panel consumed the key.
    pub fn handle_key(&mut self, code: KeyCode, _mods: KeyModifiers) -> bool {
        if self.filter_mode {
            match code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filter_mode = false;
                    self.host_selected = 0;
                }
                KeyCode::Enter => {
                    self.filter_mode = false;
                }
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.host_selected = 0;
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.host_selected = 0;
                }
                _ => {}
            }
            return true;
        }

        match code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Home => self.move_selection(isize::MIN / 2),
            KeyCode::End => self.move_selection(isize::MAX / 2),
            KeyCode::Right | KeyCode::Char('l') => self.enter_port_view(),
            KeyCode::Enter => match self.view {
                ScannerView::Hosts => self.enter_port_view(),
                ScannerView::Ports { .. } => self.copy_current(),
            },
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => self.leave_port_view(),
            KeyCode::Char('/') => {
                if matches!(self.view, ScannerView::Hosts) {
                    self.filter_mode = true;
                }
            }
            KeyCode::Char('c') => self.copy_current(),
            KeyCode::Char('o') => self.open_current(),
            KeyCode::Char('r') => self.rescan(),
            _ => return false,
        }
        true
    }
}
