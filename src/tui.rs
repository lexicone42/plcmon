use crate::types::{Link, NetworkScan};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::mpsc;
use std::time::Duration;

const MAX_HISTORY: usize = 120;

/// Signals the scanner thread should do an immediate rescan.
pub enum TuiCommand {
    Rescan,
}

pub struct App {
    current: Option<NetworkScan>,
    /// Per-link speed history: (from_short, to_short) -> ring buffer of tx speeds.
    history: HashMap<(String, String), VecDeque<u64>>,
    /// Per-link signal type history for detecting MIMO/SISO flapping.
    signal_history: HashMap<(String, String), VecDeque<String>>,
    scan_rx: mpsc::Receiver<NetworkScan>,
    cmd_tx: Option<mpsc::Sender<TuiCommand>>,
    quit: bool,
    status: String,
    scan_count: u32,
    /// Which link pair to show in sparkline (index into sorted history keys).
    selected_link: usize,
    /// Show the diagnostics panel.
    show_diag: bool,
}

impl App {
    pub fn new(scan_rx: mpsc::Receiver<NetworkScan>) -> Self {
        Self {
            current: None,
            history: Default::default(),
            signal_history: Default::default(),
            scan_rx,
            cmd_tx: None,
            quit: false,
            status: "Waiting for first scan...".into(),
            scan_count: 0,
            selected_link: 0,
            show_diag: true,
        }
    }

    /// Attach a command channel so the TUI can trigger rescans.
    pub fn with_cmd_tx(mut self, tx: mpsc::Sender<TuiCommand>) -> Self {
        self.cmd_tx = Some(tx);
        self
    }

    pub fn run(mut self) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        while !self.quit {
            terminal.draw(|f| self.draw(f))?;

            if event::poll(Duration::from_millis(200))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                    KeyCode::Char('r') => {
                        if let Some(tx) = &self.cmd_tx {
                            let _ = tx.send(TuiCommand::Rescan);
                            self.status = "Rescanning...".into();
                        }
                    }
                    KeyCode::Char('d') => self.show_diag = !self.show_diag,
                    KeyCode::Tab | KeyCode::Char('n') => {
                        if !self.history.is_empty() {
                            self.selected_link = (self.selected_link + 1) % self.history.len();
                        }
                    }
                    _ => {}
                }
            }

            while let Ok(scan) = self.scan_rx.try_recv() {
                self.ingest(scan);
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }

    fn ingest(&mut self, scan: NetworkScan) {
        self.scan_count += 1;
        let n_dev = scan.devices.len();
        let n_link = scan.links.len();
        self.status = format!(
            "#{} — {} device{}, {} link{}  ({})",
            self.scan_count,
            n_dev,
            if n_dev == 1 { "" } else { "s" },
            n_link,
            if n_link == 1 { "" } else { "s" },
            scan.timestamp.format("%H:%M:%S"),
        );

        for link in &scan.links {
            let key = (link.from.short(), link.to.short());

            let buf = self.history.entry(key.clone()).or_default();
            buf.push_back(link.tx_mbps as u64);
            if buf.len() > MAX_HISTORY {
                buf.pop_front();
            }

            let sig_buf = self.signal_history.entry(key).or_default();
            sig_buf.push_back(link.tx_signal.clone());
            if sig_buf.len() > MAX_HISTORY {
                sig_buf.pop_front();
            }
        }

        self.current = Some(scan);
    }

    fn draw(&self, f: &mut Frame) {
        let mut constraints = vec![
            Constraint::Length(3), // header
            Constraint::Min(4),    // devices
            Constraint::Min(4),    // speed matrix
        ];
        if self.show_diag {
            constraints.push(Constraint::Length(6)); // diagnostics
        }
        constraints.push(Constraint::Length(5)); // sparklines
        constraints.push(Constraint::Length(1)); // footer

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(f.area());

        let mut idx = 0;
        self.draw_header(f, chunks[idx]);
        idx += 1;
        self.draw_devices(f, chunks[idx]);
        idx += 1;
        self.draw_matrix(f, chunks[idx]);
        idx += 1;
        if self.show_diag {
            self.draw_diagnostics(f, chunks[idx]);
            idx += 1;
        }
        self.draw_sparklines(f, chunks[idx]);
        idx += 1;
        self.draw_footer(f, chunks[idx]);
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let iface = self
            .current
            .as_ref()
            .map(|s| s.interface.as_str())
            .unwrap_or("—");
        let text = Line::from(vec![
            Span::styled(
                " plcmon ",
                Style::default().fg(Color::Black).bg(Color::Cyan),
            ),
            Span::raw(format!("  iface: {iface}  │  {}", self.status)),
        ]);
        let block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray));
        f.render_widget(Paragraph::new(text).block(block), area);
    }

    fn draw_devices(&self, f: &mut Frame, area: Rect) {
        let header = Row::new(["MAC", "Model", "Chip", "Status"]).style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        );

        let rows: Vec<Row> = match &self.current {
            Some(scan) => scan
                .devices
                .iter()
                .map(|d| {
                    let status = if d.is_local {
                        "● Local"
                    } else if d.is_cco {
                        "● CCo"
                    } else {
                        "● Online"
                    };
                    let status_color = if d.is_local {
                        Color::Green
                    } else {
                        Color::Yellow
                    };
                    Row::new(vec![
                        Cell::from(d.mac.to_string()),
                        Cell::from(if d.model.is_empty() {
                            "—".to_string()
                        } else {
                            d.model.clone()
                        }),
                        Cell::from(d.chipset.to_string()),
                        Cell::from(status).style(Style::default().fg(status_color)),
                    ])
                })
                .collect(),
            None => vec![Row::new(["No devices discovered", "", "", ""])],
        };

        let widths = [
            Constraint::Length(18),
            Constraint::Length(14),
            Constraint::Length(5),
            Constraint::Fill(1),
        ];

        let table = Table::new(rows, widths).header(header).block(
            Block::default()
                .title(" Devices ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(table, area);
    }

    fn draw_matrix(&self, f: &mut Frame, area: Rect) {
        let scan = match &self.current {
            Some(s) => s,
            None => {
                let block = Block::default()
                    .title(" Link Speeds (Mbps) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray));
                f.render_widget(
                    Paragraph::new("  Waiting for scan data...").block(block),
                    area,
                );
                return;
            }
        };

        let macs: Vec<_> = scan.devices.iter().map(|d| d.mac).collect();
        let labels: Vec<String> = macs.iter().map(|m| m.short()).collect();
        let matrix = scan.speed_matrix();

        // Build a signal type lookup for annotations
        let sig_map: HashMap<_, _> = scan
            .links
            .iter()
            .map(|l| ((l.from, l.to), l.tx_signal.as_str()))
            .collect();

        let mut header_cells = vec![Cell::from("")];
        for l in &labels {
            header_cells.push(Cell::from(l.as_str()).style(Style::default().fg(Color::Cyan)));
        }
        let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

        let rows: Vec<Row> = macs
            .iter()
            .enumerate()
            .map(|(i, from)| {
                let mut cells =
                    vec![Cell::from(labels[i].clone()).style(Style::default().fg(Color::Cyan))];
                for to in &macs {
                    if from == to {
                        cells.push(Cell::from("   —"));
                    } else if let Some(&speed) = matrix.get(&(*from, *to)) {
                        let color = speed_color(speed);
                        let sig = sig_map.get(&(*from, *to)).copied().unwrap_or("");
                        // Show signal type indicator: M=MIMO, S=SISO
                        let indicator = match sig {
                            "MIMO" => "M",
                            s if s.starts_with("SISO") => "S",
                            _ => " ",
                        };
                        cells.push(
                            Cell::from(format!("{speed:>3}{indicator}"))
                                .style(Style::default().fg(color)),
                        );
                    } else {
                        cells.push(Cell::from("   ?").style(Style::default().fg(Color::DarkGray)));
                    }
                }
                Row::new(cells)
            })
            .collect();

        let mut widths = vec![Constraint::Length(10)];
        for _ in &macs {
            widths.push(Constraint::Length(8));
        }

        let table = Table::new(rows, widths).header(header).block(
            Block::default()
                .title(" Link Speeds — M=MIMO S=SISO ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(table, area);
    }

    fn draw_diagnostics(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Diagnostics ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        let scan = match &self.current {
            Some(s) => s,
            None => {
                f.render_widget(Paragraph::new("  No data").block(block), area);
                return;
            }
        };

        let mut lines: Vec<Line> = Vec::new();
        for link in &scan.links {
            let assessment = assess_link(link);
            let (icon, color) = match assessment.severity {
                Severity::Good => ("  ", Color::Green),
                Severity::Warn => ("! ", Color::Yellow),
                Severity::Bad => ("!!", Color::Red),
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {icon} "),
                    Style::default().fg(Color::White).bg(color),
                ),
                Span::raw(format!(
                    " {} → {}  {:>3}/{}  {}  {}",
                    link.from.short(),
                    link.to.short(),
                    link.tx_mbps,
                    link.rx_mbps,
                    if link.tx_signal.is_empty() {
                        "—"
                    } else {
                        &link.tx_signal
                    },
                    assessment.message
                )),
            ]));
        }

        // Check for MIMO/SISO flapping
        for ((from, to), sigs) in &self.signal_history {
            if sigs.len() >= 3 {
                let unique: std::collections::HashSet<_> = sigs.iter().collect();
                if unique.len() > 1 {
                    lines.push(Line::from(vec![
                        Span::styled(" !! ", Style::default().fg(Color::White).bg(Color::Magenta)),
                        Span::raw(format!(
                            " {from} → {to}  Signal type flapping (MIMO/SISO) — unstable link"
                        )),
                    ]));
                }
            }
        }

        if lines.is_empty() {
            lines.push(Line::raw("  All links healthy"));
        }

        f.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn draw_sparklines(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Speed History (tab to cycle) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        if self.history.is_empty() {
            f.render_widget(Paragraph::new("  No history yet").block(block), area);
            return;
        }

        // Sort keys for stable ordering, pick the selected link
        let mut keys: Vec<_> = self.history.keys().cloned().collect();
        keys.sort();
        let idx = self.selected_link % keys.len();
        let key = &keys[idx];
        let buf = &self.history[key];

        let data: Vec<u64> = buf.iter().copied().collect();
        let last = data.last().copied().unwrap_or(0);
        let min_val = data.iter().copied().min().unwrap_or(0);
        let max_val = *data.iter().max().unwrap_or(&1);
        let avg_val = if data.is_empty() {
            0
        } else {
            data.iter().sum::<u64>() / data.len() as u64
        };

        let inner = block.inner(area);
        f.render_widget(block, area);

        let spark_area = Rect {
            x: inner.x,
            y: inner.y,
            width: inner.width.saturating_sub(24),
            height: inner.height,
        };
        let label_area = Rect {
            x: spark_area.x + spark_area.width + 1,
            y: inner.y,
            width: 23,
            height: inner.height,
        };

        let spark_color = speed_color(last as u16);
        f.render_widget(
            Sparkline::default()
                .data(&data)
                .max(max_val.max(1))
                .style(Style::default().fg(spark_color)),
            spark_area,
        );
        f.render_widget(
            Paragraph::new(format!(
                "{} → {}\n{last} Mbps (now)\n{avg_val}/{min_val}/{max_val} avg/min/max",
                key.0, key.1
            )),
            label_area,
        );
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let text = Line::from(vec![
            Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
            Span::raw(" quit  "),
            Span::styled(" r ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
            Span::raw(" rescan  "),
            Span::styled(" d ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
            Span::raw(" diagnostics  "),
            Span::styled("tab", Style::default().fg(Color::Black).bg(Color::DarkGray)),
            Span::raw(" cycle link"),
        ]);
        f.render_widget(Paragraph::new(text), area);
    }
}

// -- Link assessment -------------------------------------------------------

enum Severity {
    Good,
    Warn,
    Bad,
}

struct Assessment {
    severity: Severity,
    message: &'static str,
}

fn assess_link(link: &Link) -> Assessment {
    let avg = ((link.tx_mbps as u32 + link.rx_mbps as u32) / 2) as u16;
    let is_siso = link.tx_signal.starts_with("SISO");
    let asymmetry = if link.tx_mbps > 0 && link.rx_mbps > 0 {
        link.tx_mbps.max(link.rx_mbps) as f32 / link.tx_mbps.min(link.rx_mbps) as f32
    } else {
        1.0
    };

    if avg <= 20 {
        Assessment {
            severity: Severity::Bad,
            message: if is_siso {
                "SISO fallback — try: plcmon restart <MAC>"
            } else {
                "Very poor signal — different phase or heavy noise"
            },
        }
    } else if avg <= 80 {
        Assessment {
            severity: Severity::Warn,
            message: if asymmetry > 3.0 {
                "Weak + asymmetric — noise source near one adapter"
            } else {
                "Weak — cross-phase or noisy circuit"
            },
        }
    } else if is_siso && avg > 50 {
        Assessment {
            severity: Severity::Warn,
            message: "SISO mode — restart may recover MIMO",
        }
    } else if asymmetry > 3.0 {
        Assessment {
            severity: Severity::Warn,
            message: "Asymmetric — noise source near one adapter",
        }
    } else {
        Assessment {
            severity: Severity::Good,
            message: "Healthy",
        }
    }
}

fn speed_color(mbps: u16) -> Color {
    match mbps {
        0..=50 => Color::Red,
        51..=150 => Color::Yellow,
        _ => Color::Green,
    }
}
