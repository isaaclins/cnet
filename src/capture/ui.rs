use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use super::devices::SortColumn;
use super::model::{format_mac, tcp_flags_str, CapturedPacket, Layer};
use super::parser::decode;
use super::parser::LinkType;
use super::state::{CaptureState, ProtoStats};

const HIGHLIGHT: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD);

pub fn render_capture(frame: &mut Frame, area: Rect, state: &mut CaptureState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // header
            Constraint::Length(3),  // filter bar
            Constraint::Min(8),     // list
            Constraint::Length(10), // detail+hex
            Constraint::Length(1),  // status
            Constraint::Length(1),  // help
        ])
        .split(area);

    render_capture_header(frame, chunks[0], state);
    render_filter_bar(frame, chunks[1], state);
    render_packet_list(frame, chunks[2], state);
    render_detail_and_hex(frame, chunks[3], state);
    render_status(frame, chunks[4], state);
    render_help(frame, chunks[5], state);
}

fn render_capture_header(frame: &mut Frame, area: Rect, state: &CaptureState) {
    let live = state.engine.is_some();
    let status = if live {
        Span::styled(
            "● live",
            Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "◌ idle",
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    };
    let scroll = if state.auto_scroll {
        Span::styled("[auto-scroll]", Style::new().fg(Color::Cyan))
    } else {
        Span::styled("[scroll locked]", Style::new().fg(Color::Yellow))
    };
    let drop_note = if state.dropped > 0 {
        Span::styled(
            format!(" dropped: {}", state.dropped),
            Style::new().fg(Color::Yellow),
        )
    } else {
        Span::raw("")
    };
    let iface_suffix = if state.interfaces.len() > 1 {
        format!(
            "  [{}/{} · press i]",
            state.interface_index + 1,
            state.interfaces.len()
        )
    } else {
        String::new()
    };

    let lines = vec![
        Line::from(vec![
            status,
            Span::raw("  iface: "),
            Span::styled(state.interface_label(), Style::new().fg(Color::Magenta)),
            Span::styled(iface_suffix, Style::new().fg(Color::DarkGray)),
            Span::raw("  "),
            scroll,
        ]),
        Line::from(vec![
            Span::raw(format!(
                "packets: {} ({:.1} KB)  buffer: {}/{}",
                state.total_packets,
                state.total_bytes as f64 / 1024.0,
                state.packets.len(),
                10_000,
            )),
            drop_note,
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_filter_bar(frame: &mut Frame, area: Rect, state: &CaptureState) {
    let title = if state.filter_mode {
        " filter — e.g. `arp`, `tcp port 22`, `proto=ARP`, `ip.addr==10.0.0.1`, `https`, `dns`  (Enter apply · Esc cancel) "
    } else {
        " filter — press f to edit (BPF or `proto=ARP`/`ip.addr==X`/`https`/`dns` shortcuts) "
    };
    let cursor = if state.filter_mode { "_" } else { "" };
    let style = if state.filter_mode {
        Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::White)
    };
    let p = Paragraph::new(Line::from(vec![
        Span::styled(state.filter_text.clone(), style),
        Span::styled(cursor, Style::new().add_modifier(Modifier::SLOW_BLINK)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(if state.filter_mode {
                Style::new().fg(Color::Yellow)
            } else {
                Style::new().fg(Color::DarkGray)
            }),
    );
    frame.render_widget(p, area);
}

fn render_packet_list(frame: &mut Frame, area: Rect, state: &mut CaptureState) {
    if let Some(err) = &state.start_error {
        let p = Paragraph::new(err.clone())
            .style(Style::new().fg(Color::Red))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Capture unavailable ")
                    .border_style(Style::new().fg(Color::Red)),
            );
        frame.render_widget(p, area);
        return;
    }

    if state.packets.is_empty() {
        let p = Paragraph::new("Waiting for packets…")
            .style(Style::new().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Packets ")
                    .border_style(Style::new().fg(Color::DarkGray)),
            );
        frame.render_widget(p, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("#"),
        Cell::from("Time"),
        Cell::from("Source"),
        Cell::from("Destination"),
        Cell::from("Proto"),
        Cell::from("Len"),
        Cell::from("Info"),
    ])
    .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let rows = state.packets.iter().map(|p| {
        let ts = format!("{:.3}", p.ts.as_secs_f64());
        Row::new(vec![
            Cell::from(p.seq.to_string()).style(Style::new().fg(Color::DarkGray)),
            Cell::from(ts).style(Style::new().fg(Color::DarkGray)),
            Cell::from(p.summary.src.clone()).style(Style::new().fg(Color::White)),
            Cell::from(p.summary.dst.clone()).style(Style::new().fg(Color::White)),
            Cell::from(p.summary.protocol).style(protocol_color(p.summary.protocol)),
            Cell::from(p.wire_len.to_string()).style(Style::new().fg(Color::DarkGray)),
            Cell::from(p.summary.info.clone()).style(Style::new().fg(Color::Gray)),
        ])
    });

    let widths = [
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(24),
        Constraint::Length(24),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Packets ({}) ", state.packets.len()))
                .border_style(Style::new().fg(Color::DarkGray)),
        )
        .row_highlight_style(HIGHLIGHT)
        .highlight_symbol("▌ ");

    let mut ts = TableState::default();
    let sel = state.selected.min(state.packets.len() - 1);
    ts.select(Some(sel));
    state.selected = sel;
    frame.render_stateful_widget(table, area, &mut ts);
}

fn render_detail_and_hex(frame: &mut Frame, area: Rect, state: &CaptureState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let pkt = state.current_packet();
    let link = state
        .engine
        .as_ref()
        .map(|h| h.link)
        .unwrap_or(LinkType::Ethernet);

    render_detail(frame, cols[0], pkt, link);
    render_hex(frame, cols[1], pkt);
}

fn render_detail(frame: &mut Frame, area: Rect, pkt: Option<&CapturedPacket>, link: LinkType) {
    let Some(p) = pkt else {
        let para = Paragraph::new("no packet selected")
            .style(Style::new().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL).title(" Detail "));
        frame.render_widget(para, area);
        return;
    };

    let (dec, _) = decode(link, &p.data);
    let mut lines: Vec<Line> = Vec::new();
    for layer in &dec.layers {
        lines.push(Line::from(Span::styled(
            format!("▸ {}", layer.title()),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        push_layer_fields(&mut lines, layer);
    }

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Detail (#{}) ", p.seq))
            .border_style(Style::new().fg(Color::DarkGray)),
    );
    frame.render_widget(para, area);
}

fn push_layer_fields(lines: &mut Vec<Line<'_>>, layer: &Layer) {
    let dim = Style::new().fg(Color::DarkGray);
    let val = Style::new().fg(Color::White);
    let mut row = |k: &str, v: String| {
        lines.push(Line::from(vec![
            Span::styled(format!("    {k}: "), dim),
            Span::styled(v, val),
        ]));
    };
    match layer {
        Layer::Ethernet {
            src,
            dst,
            ethertype,
        } => {
            row("src", format_mac(src));
            row("dst", format_mac(dst));
            row("ethertype", format!("0x{ethertype:04x}"));
        }
        Layer::BsdLoopback { family } => {
            row("family", family.to_string());
        }
        Layer::Ipv4 {
            src,
            dst,
            proto,
            ttl,
            total_len,
        } => {
            row("src", src.to_string());
            row("dst", dst.to_string());
            row("proto", proto.to_string());
            row("ttl", ttl.to_string());
            row("total_len", total_len.to_string());
        }
        Layer::Ipv6 {
            src,
            dst,
            next_header,
            hop_limit,
            payload_len,
        } => {
            row("src", src.to_string());
            row("dst", dst.to_string());
            row("next_header", next_header.to_string());
            row("hop_limit", hop_limit.to_string());
            row("payload_len", payload_len.to_string());
        }
        Layer::Arp {
            op,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        } => {
            row(
                "op",
                match op {
                    1 => "request".into(),
                    2 => "reply".into(),
                    o => o.to_string(),
                },
            );
            row(
                "sender",
                format!("{} ({})", sender_ip, format_mac(sender_mac)),
            );
            row(
                "target",
                format!("{} ({})", target_ip, format_mac(target_mac)),
            );
        }
        Layer::Tcp {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            payload_len,
        } => {
            row("src_port", src_port.to_string());
            row("dst_port", dst_port.to_string());
            row("seq", seq.to_string());
            row("ack", ack.to_string());
            row("flags", tcp_flags_str(*flags));
            row("window", window.to_string());
            row("payload_len", payload_len.to_string());
        }
        Layer::Udp {
            src_port,
            dst_port,
            length,
            payload_len,
        } => {
            row("src_port", src_port.to_string());
            row("dst_port", dst_port.to_string());
            row("length", length.to_string());
            row("payload_len", payload_len.to_string());
        }
        Layer::Icmp { type_, code } => {
            row("type", type_.to_string());
            row("code", code.to_string());
        }
        Layer::Icmpv6 { type_, code } => {
            row("type", type_.to_string());
            row("code", code.to_string());
        }
        Layer::Unknown { label } => {
            row("info", label.clone());
        }
    }
}

fn render_hex(frame: &mut Frame, area: Rect, pkt: Option<&CapturedPacket>) {
    let Some(p) = pkt else {
        let para = Paragraph::new("").block(Block::default().borders(Borders::ALL).title(" Hex "));
        frame.render_widget(para, area);
        return;
    };

    let inner_width = area.width.saturating_sub(2) as usize;
    let bytes_per_line = pick_bytes_per_line(inner_width);
    let max_lines = area.height.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();
    for (i, chunk) in p.data.chunks(bytes_per_line).enumerate().take(max_lines) {
        let offset = i * bytes_per_line;
        let hex: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:04x}  ", offset),
                Style::new().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{:<width$}", hex, width = bytes_per_line * 3),
                Style::new().fg(Color::White),
            ),
            Span::raw("  "),
            Span::styled(ascii, Style::new().fg(Color::Gray)),
        ]));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Hex ({} bytes) ", p.data.len()))
            .border_style(Style::new().fg(Color::DarkGray)),
    );
    frame.render_widget(para, area);
}

fn pick_bytes_per_line(inner_width: usize) -> usize {
    // Layout: 6 (offset+spaces) + 3*n (hex) + 2 (gap) + n (ascii) = 8 + 4n
    if inner_width <= 8 {
        return 8;
    }
    let candidate = (inner_width - 8) / 4;
    candidate.clamp(8, 32)
}

fn render_status(frame: &mut Frame, area: Rect, state: &CaptureState) {
    let line = if state.filter_mode {
        Line::from(Span::styled(
            "editing filter — type BPF expression, Enter to apply, Esc to cancel",
            Style::new().fg(Color::Yellow),
        ))
    } else if let Some(msg) = state.toast_message() {
        Line::from(Span::styled(msg.to_string(), Style::new().fg(Color::Green)))
    } else {
        Line::raw("")
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn render_help(frame: &mut Frame, area: Rect, _state: &CaptureState) {
    let line = Line::from(vec![
        key("↑↓"),
        Span::raw(" select  "),
        key("End"),
        Span::raw(" follow  "),
        key("Space"),
        Span::raw(" auto-scroll  "),
        key("f"),
        Span::raw(" filter  "),
        key("i"),
        Span::raw(" iface  "),
        key("x"),
        Span::raw(" clear  "),
        key("r"),
        Span::raw(" restart  "),
        key("c"),
        Span::raw(" copy"),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::new().fg(Color::DarkGray)),
        area,
    );
}

fn key(s: &str) -> Span<'_> {
    Span::styled(s, Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
}

pub fn protocol_color(proto: &str) -> Style {
    match proto {
        "TCP" => Style::new().fg(Color::Cyan),
        "UDP" => Style::new().fg(Color::Magenta),
        "DNS" | "mDNS" => Style::new().fg(Color::Blue),
        "DHCP" => Style::new().fg(Color::LightBlue),
        "NTP" => Style::new().fg(Color::Gray),
        "ARP" => Style::new().fg(Color::Yellow),
        "ICMP" | "ICMPv6" => Style::new().fg(Color::Red),
        _ => Style::new().fg(Color::White),
    }
}

// ---------- Hosts (devices) tab ----------

pub fn render_hosts(frame: &mut Frame, area: Rect, state: &mut CaptureState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    let with_names = state
        .inventory
        .hosts
        .values()
        .filter(|h| h.preferred_name().is_some())
        .count();
    let mut header_spans = vec![
        Span::raw("devices: "),
        Span::styled(
            state.inventory.count().to_string(),
            Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  named: "),
        Span::styled(with_names.to_string(), Style::new().fg(Color::Cyan)),
        Span::raw("  packets: "),
        Span::styled(
            state.total_packets.to_string(),
            Style::new().fg(Color::Cyan),
        ),
    ];
    // Filter editor / active-filter indicator on the second header line.
    let filter_line = if state.host_filter_mode {
        Line::from(vec![
            Span::styled(
                "filter: ",
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Span::styled(state.host_filter.clone(), Style::new().fg(Color::White)),
            Span::styled("_", Style::new().add_modifier(Modifier::SLOW_BLINK)),
        ])
    } else if !state.host_filter.is_empty() {
        Line::from(vec![
            Span::styled("filter: ", Style::new().fg(Color::DarkGray)),
            Span::styled(state.host_filter.clone(), Style::new().fg(Color::Yellow)),
            Span::styled(
                "  (/ to edit, Esc to clear)",
                Style::new().fg(Color::DarkGray),
            ),
        ])
    } else {
        Line::raw("")
    };
    if state.host_detail_key.is_none() {
        header_spans.push(Span::styled(
            "   / filter",
            Style::new().fg(Color::DarkGray),
        ));
    }
    let hdr = Paragraph::new(vec![Line::from(header_spans), filter_line]);
    frame.render_widget(hdr, chunks[0]);

    let in_detail = state.host_detail_key.is_some();
    if in_detail {
        render_host_detail(frame, chunks[1], state);
    } else {
        render_host_list(frame, chunks[1], state);
    }

    let help = if state.host_filter_mode {
        Line::from(vec![
            key("↑↓"),
            Span::raw(" select  "),
            key("Enter"),
            Span::raw(" apply  "),
            key("Esc"),
            Span::raw(" clear  "),
            key("Backspace"),
            Span::raw(" delete"),
        ])
    } else if in_detail {
        Line::from(vec![
            key("←/Backspace"),
            Span::raw(" back  "),
            key("q"),
            Span::raw(" quit"),
        ])
    } else {
        Line::from(vec![
            key("↑↓"),
            Span::raw(" select  "),
            key("Enter"),
            Span::raw(" inspect  "),
            key("/"),
            Span::raw(" filter  "),
            key("s"),
            Span::raw(" sort  "),
            key("S"),
            Span::raw(" dir  "),
            key("r"),
            Span::raw(" restart  "),
            key("x"),
            Span::raw(" clear  "),
            key("i"),
            Span::raw(" iface"),
        ])
    };
    frame.render_widget(
        Paragraph::new(help).style(Style::new().fg(Color::DarkGray)),
        chunks[2],
    );
}

fn render_host_list(frame: &mut Frame, area: Rect, state: &mut CaptureState) {
    if state.inventory.count() == 0 {
        let msg = if state.start_error.is_some() {
            "Capture is not running — see the Capture tab."
        } else {
            "Waiting for packets… device names appear once Bonjour/DHCP/NBNS/TLS-SNI traffic flows."
        };
        let p = Paragraph::new(msg)
            .style(Style::new().fg(Color::DarkGray))
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Devices "));
        frame.render_widget(p, area);
        return;
    }

    let ranked = state.visible_hosts();
    if ranked.is_empty() {
        let p = Paragraph::new(format!("No devices match filter: {}", state.host_filter))
            .style(Style::new().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title(" Devices "));
        frame.render_widget(p, area);
        return;
    }
    // Append a ▲/▼ arrow to the column the list is currently sorted by.
    let arrow = if state.host_sort_desc { " ▼" } else { " ▲" };
    let head = |label: &str, col: SortColumn| -> Cell<'static> {
        if state.host_sort == col {
            Cell::from(format!("{label}{arrow}")).style(
                Style::new()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Cell::from(label.to_string())
                .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        }
    };
    let header = Row::new(vec![
        head("Name / IP", SortColumn::Name),
        head("Vendor", SortColumn::Vendor),
        head("MAC", SortColumn::Mac),
        head("IPs", SortColumn::Ip),
        head("Svcs", SortColumn::Services),
        head("Pkts", SortColumn::Packets),
        head("Bytes", SortColumn::Bytes),
    ]);

    let rows = ranked.iter().map(|(_, h)| {
        let name = h.display_name();
        let is_named = h.preferred_name().is_some();
        let name_style = if is_named {
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(Color::White)
        };
        let vendor = h.vendor.unwrap_or("");
        let mac = h.mac.map(|m| format_mac(&m)).unwrap_or_default();
        let ip_count = h.ips.len();
        let ip_summary = if ip_count == 0 {
            "—".to_string()
        } else if ip_count == 1 {
            h.ips
                .iter()
                .next()
                .map(|i| i.to_string())
                .unwrap_or_default()
        } else {
            format!(
                "{} ({})",
                h.ips
                    .iter()
                    .next()
                    .map(|i| i.to_string())
                    .unwrap_or_default(),
                ip_count
            )
        };
        let svc_count = h.services.len();
        let svc_summary = if svc_count == 0 {
            "".to_string()
        } else {
            format!("{} svc", svc_count)
        };
        Row::new(vec![
            Cell::from(name).style(name_style),
            Cell::from(vendor.to_string()).style(Style::new().fg(Color::Yellow)),
            Cell::from(mac).style(Style::new().fg(Color::DarkGray)),
            Cell::from(ip_summary).style(Style::new().fg(Color::White)),
            Cell::from(svc_summary).style(Style::new().fg(Color::Magenta)),
            Cell::from(h.total_packets().to_string()).style(Style::new().fg(Color::Gray)),
            Cell::from(fmt_bytes(h.total_bytes()))
                .style(Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ])
    });

    let widths = [
        Constraint::Length(28),
        Constraint::Length(14),
        Constraint::Length(18),
        Constraint::Length(22),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(10),
    ];

    let total = ranked.len();
    let title = if state.host_filter.is_empty() {
        format!(" Devices ({total}) ")
    } else {
        format!(" Devices ({total}/{}) ", state.inventory.count())
    };
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::new().fg(Color::DarkGray)),
        )
        .row_highlight_style(HIGHLIGHT)
        .highlight_symbol("▌ ");

    let mut ts = TableState::default();
    let sel = state.host_selected.min(total.saturating_sub(1));
    state.host_selected = sel;
    ts.select(Some(sel));
    frame.render_stateful_widget(table, area, &mut ts);
}

fn render_host_detail(frame: &mut Frame, area: Rect, state: &CaptureState) {
    // Look up by the pinned key so the view stays on the chosen device even as live
    // traffic re-orders the ranked list underneath.
    let Some(key) = state.host_detail_key.as_ref() else {
        return;
    };
    let Some(host) = state.inventory.get(key) else {
        let p = Paragraph::new("This device is no longer in the buffer. Press ← to return.")
            .style(Style::new().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL).title(" Device "));
        frame.render_widget(p, area);
        return;
    };

    let title = format!(" {} ", host.display_name());
    let mut lines: Vec<Line> = Vec::new();

    let kv = |k: &str, v: String, style: Style| -> Line<'static> {
        Line::from(vec![
            Span::styled(
                format!("  {k:<14}", k = k),
                Style::new().fg(Color::DarkGray),
            ),
            Span::styled(v, style),
        ])
    };

    lines.push(Line::from(Span::styled(
        "Identity",
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    lines.push(kv("key", key.pretty(), Style::new().fg(Color::White)));
    if let Some(mac) = host.mac {
        lines.push(kv("mac", format_mac(&mac), Style::new().fg(Color::White)));
    }
    if let Some(vendor) = host.vendor {
        lines.push(kv(
            "vendor",
            vendor.into(),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(ref n) = host.preferred_name() {
        lines.push(kv(
            "display",
            n.clone(),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("IP addresses ({})", host.ips.len()),
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    if host.ips.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (none seen)",
            Style::new().fg(Color::DarkGray),
        )));
    } else {
        for ip in &host.ips {
            lines.push(Line::from(vec![
                Span::styled("  • ", Style::new().fg(Color::DarkGray)),
                Span::styled(ip.to_string(), Style::new().fg(Color::White)),
            ]));
        }
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("Names ({})", host.names.len()),
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    if host.names.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no names discovered)",
            Style::new().fg(Color::DarkGray),
        )));
    } else {
        for (name, source) in &host.names {
            lines.push(Line::from(vec![
                Span::styled("  • ", Style::new().fg(Color::DarkGray)),
                Span::styled(name.clone(), Style::new().fg(Color::Cyan)),
                Span::styled(
                    format!("  [{}]", source.label()),
                    Style::new().fg(Color::DarkGray),
                ),
            ]));
        }
    }

    if !host.services.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("Services ({})", host.services.len()),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        for svc in &host.services {
            lines.push(Line::from(vec![
                Span::styled("  • ", Style::new().fg(Color::DarkGray)),
                Span::styled(svc.clone(), Style::new().fg(Color::Magenta)),
            ]));
        }
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Activity",
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    )));
    lines.push(kv(
        "packets out",
        host.packets_out.to_string(),
        Style::new().fg(Color::White),
    ));
    lines.push(kv(
        "packets in",
        host.packets_in.to_string(),
        Style::new().fg(Color::White),
    ));
    lines.push(kv(
        "bytes out",
        fmt_bytes(host.bytes_out),
        Style::new().fg(Color::White),
    ));
    lines.push(kv(
        "bytes in",
        fmt_bytes(host.bytes_in),
        Style::new().fg(Color::White),
    ));
    lines.push(kv(
        "first / last seq",
        format!("#{} → #{}", host.first_seen_seq, host.last_seen_seq),
        Style::new().fg(Color::DarkGray),
    ));

    if !host.history.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("Discovery log ({})", host.history.len()),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        // Show the last 12 entries to keep things tidy.
        let start = host.history.len().saturating_sub(12);
        for note in &host.history[start..] {
            let seq_label = if note.seq > 0 {
                format!("#{} ", note.seq)
            } else {
                String::new()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {seq_label}[{}] ", note.source),
                    Style::new().fg(Color::Yellow),
                ),
                Span::styled(note.detail.clone(), Style::new().fg(Color::White)),
            ]));
        }
    }

    let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::new().fg(Color::Cyan)),
    );
    frame.render_widget(p, area);
}

// ---------- Stats tab ----------

pub fn render_stats(frame: &mut Frame, area: Rect, state: &CaptureState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("packets: "),
            Span::styled(
                state.total_packets.to_string(),
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  bytes: "),
            Span::styled(
                fmt_bytes(state.total_bytes),
                Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  protocols: "),
            Span::styled(
                state.proto_stats.len().to_string(),
                Style::new().fg(Color::Yellow),
            ),
        ]),
        Line::raw(""),
        Line::raw(""),
    ])
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::new().fg(Color::DarkGray)),
    );
    frame.render_widget(header, chunks[0]);

    if state.proto_stats.is_empty() {
        let p = Paragraph::new("No traffic captured yet.")
            .style(Style::new().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL).title(" Protocols "));
        frame.render_widget(p, chunks[1]);
        return;
    }

    let mut entries: Vec<(&&str, &ProtoStats)> = state.proto_stats.iter().collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.1.bytes));

    let total_bytes = state.total_bytes.max(1);
    let rows = entries.iter().map(|(proto, s)| {
        let pct = (s.bytes as f64 / total_bytes as f64) * 100.0;
        Row::new(vec![
            Cell::from(proto.to_string()).style(protocol_color(proto)),
            Cell::from(s.packets.to_string()),
            Cell::from(fmt_bytes(s.bytes)),
            Cell::from(format!("{pct:>5.1}%")),
            Cell::from(bar(pct, 20)),
        ])
    });
    let header = Row::new(vec![
        Cell::from("Protocol"),
        Cell::from("Packets"),
        Cell::from("Bytes"),
        Cell::from("Share"),
        Cell::from(""),
    ])
    .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    let widths = [
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Min(10),
    ];
    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Protocols ")
            .border_style(Style::new().fg(Color::DarkGray)),
    );
    frame.render_widget(table, chunks[1]);
}

fn fmt_bytes(b: u64) -> String {
    let f = b as f64;
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", f / 1024.0)
    } else if b < 1024 * 1024 * 1024 {
        format!("{:.2} MB", f / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", f / (1024.0 * 1024.0 * 1024.0))
    }
}

fn bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let mut s = String::with_capacity(width);
    for _ in 0..filled {
        s.push('█');
    }
    for _ in filled..width {
        s.push('░');
    }
    s
}
