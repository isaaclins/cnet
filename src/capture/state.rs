use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyModifiers};

use super::devices::{Host, HostInventory, HostKey, SortColumn};
use super::engine::{
    capturable_interfaces, default_interface, try_start_or_error, CaptureEvent, CaptureHandle,
    CaptureOptions, StartResult,
};
use super::filter::translate;
use super::model::CapturedPacket;
use super::parser::LinkType;
use super::rdns;

const BUFFER_CAP: usize = 10_000;
const TOAST_DURATION: Duration = Duration::from_millis(1800);

pub struct CaptureState {
    pub engine: Option<CaptureHandle>,
    pub start_error: Option<String>,
    pub packets: VecDeque<CapturedPacket>,
    pub dropped: u64,
    pub selected: usize,
    pub auto_scroll: bool,
    pub filter_text: String,
    pub filter_mode: bool,
    pub toast: Option<(Instant, String)>,
    pub conversations: HashMap<ConvKey, ConvStats>,
    pub proto_stats: HashMap<&'static str, ProtoStats>,
    pub total_bytes: u64,
    pub total_packets: u64,
    /// Names of every capture-eligible interface, with the current pick first-class via interface_index.
    pub interfaces: Vec<String>,
    pub interface_index: usize,
    /// Last filter string that actually started a capture — used to revert on failure.
    pub last_good_filter: String,
    /// Device inventory aggregated from observed packets.
    pub inventory: HostInventory,
    /// View state for the Hosts tab.
    pub host_selected: usize,
    /// When Some, the Hosts tab shows the detail page for this exact device. Pinning to the
    /// key (not the row index) keeps the view stable while live traffic re-orders the list.
    pub host_detail_key: Option<HostKey>,
    pub host_filter: String,
    pub host_filter_mode: bool,
    pub host_sort: SortColumn,
    pub host_sort_desc: bool,
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ConvKey {
    pub a: String,
    pub b: String,
}

#[derive(Default, Clone)]
pub struct ConvStats {
    pub packets_ab: u64,
    pub bytes_ab: u64,
    pub packets_ba: u64,
    pub bytes_ba: u64,
    pub last_seen: u64, // packet seq for sorting recency
}

#[derive(Default, Clone)]
pub struct ProtoStats {
    pub packets: u64,
    pub bytes: u64,
}

impl CaptureState {
    pub fn new() -> Self {
        // Enumerate interfaces and place the smart default at index 0.
        let mut interfaces: Vec<String> = capturable_interfaces()
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.name)
            .collect();
        if let Ok(def) = default_interface() {
            if let Some(pos) = interfaces.iter().position(|n| n == &def.name) {
                interfaces.swap(0, pos);
            } else {
                interfaces.insert(0, def.name);
            }
        }

        let mut s = Self {
            engine: None,
            start_error: None,
            packets: VecDeque::with_capacity(BUFFER_CAP),
            dropped: 0,
            selected: 0,
            auto_scroll: true,
            filter_text: String::new(),
            filter_mode: false,
            toast: None,
            conversations: HashMap::new(),
            proto_stats: HashMap::new(),
            total_bytes: 0,
            total_packets: 0,
            interfaces,
            interface_index: 0,
            last_good_filter: String::new(),
            inventory: HostInventory::default(),
            host_selected: 0,
            host_detail_key: None,
            host_filter: String::new(),
            host_filter_mode: false,
            host_sort: SortColumn::Bytes,
            host_sort_desc: true,
        };
        s.attempt_start();
        s
    }

    fn current_interface(&self) -> Option<String> {
        self.interfaces.get(self.interface_index).cloned()
    }

    fn attempt_start(&mut self) -> bool {
        let translated = translate(&self.filter_text);
        let opts = CaptureOptions {
            interface: self.current_interface(),
            filter: if translated.is_empty() {
                None
            } else {
                Some(translated)
            },
            ..Default::default()
        };
        match try_start_or_error(opts) {
            StartResult::Started(h) => {
                self.start_error = None;
                self.engine = Some(h);
                true
            }
            StartResult::NeedsPrivilege(e) => {
                self.engine = None;
                self.start_error = Some(format!(
                    "capture needs elevated privileges — try `sudo ./target/release/cnet`\n({e})"
                ));
                false
            }
            StartResult::Failed(e) => {
                self.engine = None;
                self.start_error = Some(format!("capture failed: {e}"));
                false
            }
        }
    }

    pub fn interface_label(&self) -> String {
        match &self.engine {
            Some(h) => format!("{} ({})", h.interface, link_label(h.link)),
            None => "—".into(),
        }
    }

    pub fn toast_message(&self) -> Option<&str> {
        match &self.toast {
            Some((t, m)) if t.elapsed() < TOAST_DURATION => Some(m.as_str()),
            _ => None,
        }
    }

    fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((Instant::now(), msg.into()));
    }

    pub fn current_packet(&self) -> Option<&CapturedPacket> {
        self.packets.get(self.selected)
    }

    pub fn pump(&mut self) {
        // Borrow engine.rx briefly; collect to avoid holding mutable borrow during state updates.
        let mut events = Vec::new();
        if let Some(h) = &mut self.engine {
            while let Ok(ev) = h.rx.try_recv() {
                events.push(ev);
            }
        }
        for ev in events {
            self.handle_event(ev);
        }
    }

    fn handle_event(&mut self, ev: CaptureEvent) {
        match ev {
            CaptureEvent::Packet(p) => self.add_packet(p),
            CaptureEvent::Error(e) => {
                self.engine = None;
                self.start_error = Some(format!("capture error: {e}"));
            }
            CaptureEvent::Ended => {
                self.engine = None;
            }
            CaptureEvent::Rdns { ip, name } => {
                self.inventory.apply_rdns(ip, name);
            }
        }
    }

    /// Fire off any pending reverse-DNS lookups. Called periodically.
    pub fn pump_rdns(&mut self, max: usize) {
        let Some(tx) = self.engine.as_ref().map(|h| h.rx_clone_sender()) else {
            return;
        };
        for ip in self.inventory.drain_pending_rdns(max) {
            rdns::spawn_lookup(tx.clone(), ip);
        }
    }

    fn add_packet(&mut self, p: CapturedPacket) {
        // Update aggregates.
        self.total_packets += 1;
        self.total_bytes += p.wire_len as u64;
        let entry = self.proto_stats.entry(p.summary.protocol).or_default();
        entry.packets += 1;
        entry.bytes += p.wire_len as u64;

        // Feed the device inventory.
        let link = self
            .engine
            .as_ref()
            .map(|h| h.link)
            .unwrap_or(LinkType::Ethernet);
        self.inventory.observe(link, &p);

        let (a, b) = if p.summary.src.as_str() <= p.summary.dst.as_str() {
            (p.summary.src.clone(), p.summary.dst.clone())
        } else {
            (p.summary.dst.clone(), p.summary.src.clone())
        };
        let direction_ab = p.summary.src == a;
        let key = ConvKey { a, b };
        let conv = self.conversations.entry(key).or_default();
        if direction_ab {
            conv.packets_ab += 1;
            conv.bytes_ab += p.wire_len as u64;
        } else {
            conv.packets_ba += 1;
            conv.bytes_ba += p.wire_len as u64;
        }
        conv.last_seen = p.seq;

        // Push into ring buffer.
        if self.packets.len() == BUFFER_CAP {
            self.packets.pop_front();
            self.dropped += 1;
            if self.selected > 0 {
                self.selected -= 1;
            }
        }
        self.packets.push_back(p);

        if self.auto_scroll {
            self.selected = self.packets.len().saturating_sub(1);
        }
    }

    fn clear(&mut self) {
        self.clear_aggregates();
        self.set_toast("cleared");
    }

    fn restart(&mut self) {
        // Drop the engine handle to stop the thread, then start fresh.
        self.engine = None;
        self.attempt_start();
        if self.start_error.is_none() {
            self.set_toast("restarted capture");
        }
    }

    fn apply_filter(&mut self) {
        self.filter_mode = false;
        let attempt = self.filter_text.clone();
        if attempt == self.last_good_filter && self.engine.is_some() {
            return;
        }

        self.engine = None;
        if self.attempt_start() {
            self.last_good_filter = attempt.clone();
            let msg = if attempt.is_empty() {
                "filter cleared".to_string()
            } else {
                format!("filter applied: {attempt}")
            };
            self.set_toast(msg);
        } else {
            // Revert: restore previous filter and try to bring capture back.
            let err = self.start_error.take().unwrap_or_else(|| "unknown".into());
            self.filter_text = self.last_good_filter.clone();
            self.attempt_start();
            self.set_toast(format!("bad filter — reverted ({err})"));
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.packets.is_empty() {
            return;
        }
        self.auto_scroll = false;
        let len = self.packets.len() as isize;
        let cur = self.selected as isize;
        let new = (cur + delta).clamp(0, len - 1);
        self.selected = new as usize;
    }

    fn jump_to_end(&mut self) {
        self.auto_scroll = true;
        if !self.packets.is_empty() {
            self.selected = self.packets.len() - 1;
        }
    }

    /// Returns true if the panel consumed the key.
    pub fn handle_key(&mut self, code: KeyCode, _mods: KeyModifiers) -> bool {
        if self.filter_mode {
            match code {
                KeyCode::Esc => {
                    self.filter_mode = false;
                }
                KeyCode::Enter => self.apply_filter(),
                KeyCode::Backspace => {
                    self.filter_text.pop();
                }
                KeyCode::Char(c) => {
                    self.filter_text.push(c);
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
            KeyCode::Home => {
                self.auto_scroll = false;
                self.selected = 0;
            }
            KeyCode::End => self.jump_to_end(),
            KeyCode::Char(' ') => {
                self.auto_scroll = !self.auto_scroll;
                if self.auto_scroll && !self.packets.is_empty() {
                    self.selected = self.packets.len() - 1;
                }
                let msg = if self.auto_scroll {
                    "auto-scroll on"
                } else {
                    "auto-scroll off"
                };
                self.set_toast(msg);
            }
            KeyCode::Char('x') => self.clear(),
            KeyCode::Char('f') => self.filter_mode = true,
            KeyCode::Char('r') => self.restart(),
            KeyCode::Char('c') => self.copy_packet_info(),
            KeyCode::Char('i') => self.cycle_interface(),
            _ => return false,
        }
        true
    }

    fn cycle_interface(&mut self) {
        if self.interfaces.is_empty() {
            self.set_toast("no interfaces available");
            return;
        }
        self.interface_index = (self.interface_index + 1) % self.interfaces.len();
        self.engine = None;
        self.clear_aggregates();
        self.attempt_start();
        let name = self.current_interface().unwrap_or_default();
        if self.start_error.is_none() {
            self.set_toast(format!("interface → {name}"));
        }
    }

    fn clear_aggregates(&mut self) {
        self.packets.clear();
        self.conversations.clear();
        self.proto_stats.clear();
        self.total_bytes = 0;
        self.total_packets = 0;
        self.dropped = 0;
        self.selected = 0;
        self.auto_scroll = true;
        self.inventory.clear();
        self.host_selected = 0;
        self.host_detail_key = None;
        self.host_filter.clear();
        self.host_filter_mode = false;
    }

    /// Devices currently visible on the Hosts tab (filtered, sorted).
    pub fn visible_hosts(&self) -> Vec<(&HostKey, &Host)> {
        self.inventory
            .ranked_filtered(&self.host_filter, self.host_sort, self.host_sort_desc)
    }

    fn move_host_selection(&mut self, delta: isize) {
        let total = self.visible_hosts().len();
        if total == 0 {
            self.host_selected = 0;
            return;
        }
        let len = total as isize;
        let cur = self.host_selected.min(total - 1) as isize;
        self.host_selected = (cur + delta).rem_euclid(len) as usize;
    }

    fn cycle_host_sort(&mut self) {
        self.host_sort = self.host_sort.next();
        self.host_sort_desc = self.host_sort.default_desc();
        let dir = if self.host_sort_desc { "↓" } else { "↑" };
        self.set_toast(format!("sort: {} {dir}", self.host_sort.label()));
    }

    fn toggle_host_sort_dir(&mut self) {
        self.host_sort_desc = !self.host_sort_desc;
        let dir = if self.host_sort_desc {
            "↓ desc"
        } else {
            "↑ asc"
        };
        self.set_toast(format!("sort: {} {dir}", self.host_sort.label()));
    }

    /// Key handler for the Hosts tab. Returns true if the key was consumed.
    pub fn handle_hosts_key(&mut self, code: KeyCode, _mods: KeyModifiers) -> bool {
        // Filter editor: printable keys edit the query, but arrows still move the
        // selection so you can narrow-then-pick without leaving the editor (fzf-style).
        if self.host_filter_mode {
            match code {
                KeyCode::Esc => {
                    self.host_filter.clear();
                    self.host_filter_mode = false;
                    self.host_selected = 0;
                }
                KeyCode::Enter => self.host_filter_mode = false,
                KeyCode::Backspace => {
                    self.host_filter.pop();
                    self.host_selected = 0;
                }
                KeyCode::Up => self.move_host_selection(-1),
                KeyCode::Down => self.move_host_selection(1),
                KeyCode::PageUp => self.move_host_selection(-10),
                KeyCode::PageDown => self.move_host_selection(10),
                KeyCode::Char(c) => {
                    self.host_filter.push(c);
                    self.host_selected = 0;
                }
                _ => {}
            }
            return true;
        }

        // Detail view: only cares about leaving.
        if self.host_detail_key.is_some() {
            match code {
                KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace | KeyCode::Esc => {
                    self.host_detail_key = None;
                    return true;
                }
                _ => return true, // swallow everything else so the list doesn't move underneath
            }
        }

        match code {
            KeyCode::Up | KeyCode::Char('k') => self.move_host_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_host_selection(1),
            KeyCode::PageUp => self.move_host_selection(-10),
            KeyCode::PageDown => self.move_host_selection(10),
            KeyCode::Home => self.host_selected = 0,
            KeyCode::End => self.host_selected = self.visible_hosts().len().saturating_sub(1),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                // Pin the detail view to the selected device's stable key.
                if let Some((key, _)) = self.visible_hosts().get(self.host_selected) {
                    self.host_detail_key = Some(**key);
                }
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace | KeyCode::Esc => {
                return false; // nothing to leave; let the global handler quit
            }
            KeyCode::Char('/') => self.host_filter_mode = true,
            KeyCode::Char('s') => self.cycle_host_sort(),
            KeyCode::Char('S') => self.toggle_host_sort_dir(),
            KeyCode::Char('x') => self.clear(),
            KeyCode::Char('r') => self.restart(),
            KeyCode::Char('i') => self.cycle_interface(),
            _ => return false,
        }
        true
    }

    fn copy_packet_info(&mut self) {
        let Some(p) = self.current_packet().cloned() else {
            self.set_toast("no packet selected");
            return;
        };
        let text = format!(
            "#{} {:?} {} → {} {} {}",
            p.seq, p.ts, p.summary.src, p.summary.dst, p.summary.protocol, p.summary.info
        );
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.clone())) {
            Ok(()) => self.set_toast("copied"),
            Err(e) => self.set_toast(format!("copy failed: {e}")),
        }
    }
}

fn link_label(l: LinkType) -> &'static str {
    match l {
        LinkType::Ethernet => "ethernet",
        LinkType::BsdLoopback => "loopback",
        LinkType::Raw => "raw IP",
        LinkType::Other => "unknown DLT",
    }
}
