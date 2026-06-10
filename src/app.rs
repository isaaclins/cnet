use std::time::Duration;

use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::DefaultTerminal;
use tokio::time::{interval, MissedTickBehavior};

use crate::capture::CaptureState;
use crate::scanner::ScannerState;
use crate::ui;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Capture,
    Hosts,
    Ports,
    Stats,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Capture, Tab::Hosts, Tab::Ports, Tab::Stats];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Capture => "Capture",
            Tab::Hosts => "Hosts",
            Tab::Ports => "Ports",
            Tab::Stats => "Stats",
        }
    }

    pub fn next(self) -> Tab {
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Tab {
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL[(i + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

pub struct App {
    pub tab: Tab,
    pub capture: CaptureState,
    pub scanner: Option<ScannerState>,
    pub scanner_error: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        let (scanner, scanner_error) = match ScannerState::new() {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        };
        Self {
            tab: Tab::Capture,
            capture: CaptureState::new(),
            scanner,
            scanner_error,
            should_quit: false,
        }
    }

    fn pump(&mut self) {
        self.capture.pump();
        if let Some(s) = &mut self.scanner {
            s.pump();
        }
    }

    fn dispatch_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        // 0. Ctrl+C always quits, before any tab can swallow it. In raw mode the terminal
        // does not raise SIGINT — Ctrl+C arrives as this key event, so we must handle it.
        if mods.contains(KeyModifiers::CONTROL)
            && matches!(code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            self.should_quit = true;
            return;
        }

        // 1. Give the active tab first crack. If it consumes the key, we're done.
        let consumed = match self.tab {
            Tab::Capture | Tab::Stats => self.capture.handle_key(code, mods),
            Tab::Hosts => self.capture.handle_hosts_key(code, mods),
            Tab::Ports => self
                .scanner
                .as_mut()
                .map(|s| s.handle_key(code, mods))
                .unwrap_or(false),
        };
        if consumed {
            return;
        }

        // 2. Otherwise apply global shortcuts.
        match (code, mods) {
            (KeyCode::Char('q') | KeyCode::Char('Q'), _) => self.should_quit = true,
            (KeyCode::Esc, _) => self.should_quit = true,
            (KeyCode::Tab, _) => self.tab = self.tab.next(),
            (KeyCode::BackTab, _) => self.tab = self.tab.prev(),
            (KeyCode::Char('1'), _) => self.tab = Tab::Capture,
            (KeyCode::Char('2'), _) => self.tab = Tab::Hosts,
            (KeyCode::Char('3'), _) => self.tab = Tab::Ports,
            (KeyCode::Char('4'), _) => self.tab = Tab::Stats,
            _ => {}
        }
    }
}

pub async fn run(terminal: &mut DefaultTerminal, mut app: App) -> std::io::Result<()> {
    let mut events = EventStream::new();
    let mut redraw_tick = interval(Duration::from_millis(100));
    redraw_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut rdns_tick = interval(Duration::from_millis(500));
    rdns_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    terminal.draw(|f| ui::render(f, &mut app))?;

    loop {
        if app.should_quit {
            break;
        }

        tokio::select! {
            biased;
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(k))) if k.kind == KeyEventKind::Press => {
                        app.dispatch_key(k.code, k.modifiers);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e),
                    None => break,
                }
            }
            _ = rdns_tick.tick() => {
                app.capture.pump_rdns(8);
            }
            _ = redraw_tick.tick() => {}
        }

        app.pump();
        terminal.draw(|f| ui::render(f, &mut app))?;
    }

    Ok(())
}
