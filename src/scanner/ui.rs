use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use super::models::{HostReport, PortInfo, PublicStatus};
use super::state::{ScannerState, ScannerView};

const HIGHLIGHT_STYLE: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD);

pub fn render(frame: &mut Frame, area: Rect, app: &mut ScannerState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // header
            Constraint::Length(1), // progress
            Constraint::Min(5),    // body
            Constraint::Length(1), // status/toast
            Constraint::Length(1), // help
        ])
        .split(area);

    render_header(frame, chunks[0], app);
    render_progress(frame, chunks[1], app);

    match app.view {
        ScannerView::Hosts => render_hosts(frame, chunks[2], app),
        ScannerView::Ports { host_index } => render_ports(frame, chunks[2], app, host_index),
    }

    render_status(frame, chunks[3], app);
    render_help(frame, chunks[4], app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &ScannerState) {
    let status_span = if app.scan.scan_complete {
        Span::styled(
            "✓ complete",
            Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("scanning…", Style::new().fg(Color::Yellow))
    };

    let mut cap_note = String::new();
    if app.scan.capped {
        cap_note = format!(
            "  (capped, {} skipped)",
            app.scan.hosts_total.saturating_sub(app.scan.hosts_planned)
        );
    }

    let lines = vec![
        Line::from(vec![
            status_span,
            Span::raw("  "),
            Span::styled(
                format!("local {}", app.scan.local_ip),
                Style::new().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::raw(format!(
                "probed {}/{} · open hosts {}",
                app.scan.hosts_considered,
                app.scan.hosts_planned,
                app.scan.hosts.len(),
            )),
            Span::styled(cap_note, Style::new().fg(Color::Yellow)),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), area);
}

fn render_progress(frame: &mut Frame, area: Rect, app: &ScannerState) {
    let planned = app.scan.hosts_planned.max(1);
    let ratio = if app.scan.scan_complete {
        1.0
    } else {
        (app.scan.hosts_considered.min(planned) as f64) / (planned as f64)
    };
    let gauge = Gauge::default()
        .gauge_style(Style::new().fg(Color::Magenta).bg(Color::Black))
        .ratio(ratio.clamp(0.0, 1.0))
        .label(format!("{:>3.0}%", ratio * 100.0));
    frame.render_widget(gauge, area);
}

fn render_hosts(frame: &mut Frame, area: Rect, app: &mut ScannerState) {
    let indices = app.filtered_host_indices();

    if app.scan.hosts.is_empty() {
        let msg = if app.scan.scan_complete {
            "No hosts with open ports were discovered."
        } else {
            "Scanning… results will appear here as they arrive."
        };
        let p = Paragraph::new(msg)
            .style(Style::new().fg(Color::DarkGray))
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Hosts "));
        frame.render_widget(p, area);
        return;
    }

    if indices.is_empty() {
        let p = Paragraph::new(format!("No hosts match filter: {}", app.filter))
            .style(Style::new().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title(" Hosts "));
        frame.render_widget(p, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("IP Address").style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Cell::from("Open Ports").style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Cell::from("Services").style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]);

    let rows = indices.iter().map(|&i| {
        let h: &HostReport = &app.scan.hosts[i];
        Row::new(vec![
            Cell::from(h.ip.clone()).style(Style::new().fg(Color::White)),
            Cell::from(h.ports_display.clone()).style(Style::new().fg(Color::Magenta)),
            Cell::from(h.services_display.clone()).style(service_color(&h.services_display)),
        ])
    });

    let widths = [
        Constraint::Length(15),
        Constraint::Percentage(40),
        Constraint::Percentage(45),
    ];

    let title = if app.filter.is_empty() {
        format!(" Hosts ({}) ", indices.len())
    } else {
        format!(
            " Hosts ({}/{}) filter: {} ",
            indices.len(),
            app.scan.hosts.len(),
            app.filter
        )
    };

    let table = Table::new(rows, widths)
        .header(header.bottom_margin(1))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::new().fg(Color::DarkGray)),
        )
        .row_highlight_style(HIGHLIGHT_STYLE)
        .highlight_symbol("▌ ");

    let mut state = TableState::default();
    let sel = app.host_selected.min(indices.len() - 1);
    state.select(Some(sel));
    app.host_selected = sel;
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_ports(frame: &mut Frame, area: Rect, app: &mut ScannerState, host_index: usize) {
    let Some(host) = app.scan.hosts.get(host_index) else {
        let p = Paragraph::new("Host no longer available. Press ← to return.")
            .style(Style::new().fg(Color::Red));
        frame.render_widget(p, area);
        return;
    };

    if host.ports.is_empty() {
        let p = Paragraph::new("No open ports for this host.")
            .style(Style::new().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", host.ip)),
            );
        frame.render_widget(p, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("Port"),
        Cell::from("Service"),
        Cell::from("URL"),
        Cell::from("Public"),
    ])
    .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let rows = host.ports.iter().map(|p: &PortInfo| {
        let service = p.service_label();
        Row::new(vec![
            Cell::from(p.port.to_string()).style(Style::new().fg(Color::Magenta)),
            Cell::from(service.clone()).style(service_color(&service)),
            Cell::from(p.url_display.clone()).style(Style::new().fg(Color::White)),
            Cell::from(p.public_label.clone()).style(public_color(&p.public_status)),
        ])
    });

    let widths = [
        Constraint::Length(6),
        Constraint::Percentage(30),
        Constraint::Percentage(45),
        Constraint::Percentage(25),
    ];

    let title = format!(" {} ({} ports) ", host.ip, host.ports.len());
    let table = Table::new(rows, widths)
        .header(header.bottom_margin(1))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::new().fg(Color::DarkGray)),
        )
        .row_highlight_style(HIGHLIGHT_STYLE)
        .highlight_symbol("▌ ");

    let mut state = TableState::default();
    let sel = app.port_selected.min(host.ports.len() - 1);
    state.select(Some(sel));
    app.port_selected = sel;
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_status(frame: &mut Frame, area: Rect, app: &ScannerState) {
    let line = if app.filter_mode {
        Line::from(vec![
            Span::styled(
                "/",
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Span::raw(app.filter.clone()),
            Span::styled("_", Style::new().add_modifier(Modifier::SLOW_BLINK)),
        ])
    } else if let Some(msg) = app.toast_message() {
        Line::from(Span::styled(msg.to_string(), Style::new().fg(Color::Green)))
    } else {
        Line::raw("")
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn render_help(frame: &mut Frame, area: Rect, app: &ScannerState) {
    let line = if app.filter_mode {
        Line::from(vec![
            key("Enter"),
            Span::raw(" apply  "),
            key("Esc"),
            Span::raw(" cancel  "),
            key("Backspace"),
            Span::raw(" delete"),
        ])
    } else {
        match app.view {
            ScannerView::Hosts => Line::from(vec![
                key("↑↓/jk"),
                Span::raw(" nav  "),
                key("→/Enter"),
                Span::raw(" ports  "),
                key("/"),
                Span::raw(" filter  "),
                key("c"),
                Span::raw(" copy ip  "),
                key("r"),
                Span::raw(" rescan"),
            ]),
            ScannerView::Ports { .. } => Line::from(vec![
                key("↑↓/jk"),
                Span::raw(" nav  "),
                key("Enter/c"),
                Span::raw(" copy url  "),
                key("o"),
                Span::raw(" open  "),
                key("←/Bksp"),
                Span::raw(" back"),
            ]),
        }
    };
    frame.render_widget(
        Paragraph::new(line).style(Style::new().fg(Color::DarkGray)),
        area,
    );
}

fn key(s: &str) -> Span<'_> {
    Span::styled(s, Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
}

fn service_color(text: &str) -> Style {
    let t = text.to_ascii_lowercase();
    if t.contains("http") {
        Style::new().fg(Color::Blue)
    } else if t.contains("ssh") || t.contains("ftp") || t.contains("telnet") {
        Style::new().fg(Color::Yellow)
    } else if t.contains("sql")
        || t.contains("mongo")
        || t.contains("redis")
        || t.contains("postgres")
        || t.contains("mysql")
    {
        Style::new().fg(Color::Magenta)
    } else if t.contains("smb") || t.contains("netbios") || t.contains("nfs") || t.contains("rpc") {
        Style::new().fg(Color::Red)
    } else {
        Style::new().fg(Color::White)
    }
}

fn public_color(status: &PublicStatus) -> Style {
    match status {
        PublicStatus::Accessible { .. } => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        PublicStatus::NotAccessible => Style::new().fg(Color::Green),
        PublicStatus::Unknown => Style::new().fg(Color::DarkGray),
        PublicStatus::Error(_) => Style::new().fg(Color::Yellow),
    }
}
