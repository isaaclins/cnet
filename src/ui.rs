use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use crate::app::{App, Tab};
use crate::capture::ui::{render_capture, render_hosts, render_stats};
use crate::scanner::render_scanner;

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar + title
            Constraint::Min(8),    // body
        ])
        .split(area);

    render_tab_bar(frame, chunks[0], app);

    match app.tab {
        Tab::Capture => render_capture(frame, chunks[1], &mut app.capture),
        Tab::Hosts => render_hosts(frame, chunks[1], &mut app.capture),
        Tab::Stats => render_stats(frame, chunks[1], &app.capture),
        Tab::Ports => render_ports_tab(frame, chunks[1], app),
    }
}

fn render_tab_bar(frame: &mut Frame, area: Rect, app: &App) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(vec![
                Span::styled(format!(" {} ", i + 1), Style::new().fg(Color::DarkGray)),
                Span::styled(t.title(), Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(" "),
            ])
        })
        .collect();

    let selected = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);

    let tabs = Tabs::new(titles)
        .select(selected)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::new().fg(Color::DarkGray))
                .title(Line::from(vec![
                    Span::styled(
                        " cnet ",
                        Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("wireshark-lite", Style::new().fg(Color::DarkGray)),
                    Span::raw("   "),
                    Span::styled(
                        "Tab/Shift-Tab or 1-4 to switch  ·  q to quit",
                        Style::new().fg(Color::DarkGray),
                    ),
                ])),
        )
        .style(Style::new().fg(Color::White))
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");

    frame.render_widget(tabs, area);
}

fn render_ports_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    if let Some(scanner) = &mut app.scanner {
        render_scanner(frame, area, scanner);
        return;
    }

    let msg = match &app.scanner_error {
        Some(e) => format!("Scanner failed to start: {e}"),
        None => "Scanner not initialized.".to_string(),
    };
    let p = Paragraph::new(msg)
        .style(Style::new().fg(Color::Red))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Ports — unavailable ")
                .border_style(Style::new().fg(Color::Red)),
        );
    frame.render_widget(p, area);
}
