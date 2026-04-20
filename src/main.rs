use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{prelude::*, widgets::*};
use std::{
    io,
    time::{Duration, Instant},
};
use sysinfo::{Components, Disks, Networks, System};

mod network;
mod process;
mod power;
mod disk_analyzer;

use network::NetworkMonitor;
use process::ProcessMonitor;
use power::PowerMonitor;
use disk_analyzer::DiskAnalyzer;

// ─── Constants ───────────────────────────────────────────────────────────────
const HISTORY_LEN: usize = 60;
const TICK_MS: u64 = 1000;
const NETWORK_SCAN_INTERVAL: u64 = 15000;  // Scan network every 15 seconds
const PROCESS_SCAN_INTERVAL: u64 = 15000;  // Scan processes every 15 seconds
const BATTERY_SCAN_INTERVAL: u64 = 15000;  // Update battery every 15 seconds

// ─── Color palette ───────────────────────────────────────────────────────────
const LIME: Color = Color::Rgb(50, 255, 100);
const CYAN: Color = Color::Rgb(0, 210, 255);
const PURPLE: Color = Color::Rgb(190, 80, 255);
const ORANGE: Color = Color::Rgb(255, 145, 0);
const RED: Color = Color::Rgb(255, 65, 65);
const GOLD: Color = Color::Rgb(255, 210, 50);
const DARK: Color = Color::Rgb(20, 20, 30);

// ─── Enums ───────────────────────────────────────────────────────────────────
#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Overview,
    Processes,
    Connections,      // Network + Threats combined
    Storage,
}

#[derive(PartialEq, Clone, Copy)]
enum SortBy {
    Cpu,
    Memory,
    Pid,
    Name,
}

// ─── App state ───────────────────────────────────────────────────────────────
struct App {
    sys: System,
    networks: Networks,
    components: Components,
    disks: Disks,
    last_tick: Instant,

    // Network speeds
    prev_rx: u64,
    prev_tx: u64,
    rx_speed: f64, // KB/s
    tx_speed: f64,

    // Historical sparklines (0..=100)
    cpu_hist: Vec<u64>,
    ram_hist: Vec<u64>,

    // UI state
    tab: Tab,
    proc_sel: usize,
    proc_off: usize,
    conn_off: usize,       // Scroll offset for connections table
    sort_by: SortBy,
    sort_desc: bool,

    // Alerts
    alerts: Vec<String>,

    // New security monitors
    net_monitor: NetworkMonitor,
    proc_monitor: ProcessMonitor,
    power_monitor: PowerMonitor,
    disk_analyzer: DiskAnalyzer,

    // Storage navigation state
    storage_sel: usize,

    // Rate limiting for expensive operations
    last_network_scan: Instant,
    last_process_scan: Instant,
    last_battery_scan: Instant,
}

impl App {
    fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let now = Instant::now();
        // Trigger immediate first scans by setting times to the past
        let past = now - std::time::Duration::from_secs(60);
        Self {
            sys,
            networks: Networks::new_with_refreshed_list(),
            components: Components::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            last_tick: now,
            prev_rx: 0,
            prev_tx: 0,
            rx_speed: 0.0,
            tx_speed: 0.0,
            cpu_hist: vec![0; HISTORY_LEN],
            ram_hist: vec![0; HISTORY_LEN],
            tab: Tab::Overview,
            proc_sel: 0,
            proc_off: 0,
            conn_off: 0,
            sort_by: SortBy::Cpu,
            sort_desc: true,
            alerts: vec![],
            net_monitor: NetworkMonitor::new(),
            proc_monitor: ProcessMonitor::new(),
            power_monitor: PowerMonitor::new(),
            disk_analyzer: {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/Users".to_string());
                let analyzer = DiskAnalyzer::new(&home);
                
                // Request Full Disk Access permission on macOS
                // This triggers the permission dialog by trying to access protected directories
                let _ = std::process::Command::new("sh")
                    .args(&["-c", "ls -la ~/Library/Mail 2>/dev/null | head -1"])
                    .output();
                
                analyzer
            },
            storage_sel: 0,
            last_network_scan: past,
            last_process_scan: past,
            last_battery_scan: past,
        }
    }

    fn tick(&mut self) {
        self.sys.refresh_all();
        self.networks.refresh(true);
        self.components.refresh(true);
        self.disks.refresh(true);

        // ── Network speed ──────────────────────────────────────────────────
        let (mut cur_rx, mut cur_tx) = (0u64, 0u64);
        for (_, d) in &self.networks {
            cur_rx += d.received();
            cur_tx += d.transmitted();
        }
        let dt = self.last_tick.elapsed().as_secs_f64().max(0.001);
        self.rx_speed = (cur_rx.saturating_sub(self.prev_rx) as f64 / 1024.0) / dt;
        self.tx_speed = (cur_tx.saturating_sub(self.prev_tx) as f64 / 1024.0) / dt;
        self.prev_rx = cur_rx;
        self.prev_tx = cur_tx;

        // ── History ────────────────────────────────────────────────────────
        let cpu_p = self.sys.global_cpu_usage() as u64;
        let ram_p = ram_pct_raw(&self.sys);
        push_history(&mut self.cpu_hist, cpu_p);
        push_history(&mut self.ram_hist, ram_p);

        // ── New security monitors (with rate limiting) ──────────────────────
        if self.last_network_scan.elapsed().as_millis() as u64 >= NETWORK_SCAN_INTERVAL {
            self.net_monitor.scan_connections();
            self.net_monitor.analyze_threats();
            self.last_network_scan = Instant::now();
        }
        
        if self.last_process_scan.elapsed().as_millis() as u64 >= PROCESS_SCAN_INTERVAL {
            self.proc_monitor.scan(&self.sys);
            self.last_process_scan = Instant::now();
        }
        
        if self.last_battery_scan.elapsed().as_millis() as u64 >= BATTERY_SCAN_INTERVAL {
            self.power_monitor.update_battery_status();
            self.power_monitor.update_process_impacts(&self.sys);
            self.last_battery_scan = Instant::now();
        }

        // ── Alerts ─────────────────────────────────────────────────────────
        self.alerts.clear();
        if cpu_p > 85 {
            self.alerts.push(format!("[!] CPU SURCHARGÉ : {}%", cpu_p));
        }
        if ram_p > 85 {
            self.alerts.push(format!("[!] RAM CRITIQUE  : {}%", ram_p));
        }
        let max_t = self
            .components
            .iter()
            .map(|c| c.temperature().unwrap_or(0.0))
            .fold(0.0f32, f32::max);
        if max_t > 85.0 {
            self.alerts
                .push(format!("[!] THERMIQUE     : {:.1}°C", max_t));
        }

        // Check for network threats
        let (_, suspicious_count, _) = self.net_monitor.get_summary();
        if suspicious_count > 0 {
            self.alerts.push(format!(
                "[THREAT] MENACE RÉSEAU: {} connexion(s) suspecte(s)",
                suspicious_count
            ));
        }

        // Check for process security threats
        let critical_threats = self
            .proc_monitor
            .threats
            .iter()
            .filter(|t| t.risk_score > 75)
            .count();
        if critical_threats > 0 {
            self.alerts
                .push(format!("[THREAT] SÉCURITÉ: {} processus critique(s)", critical_threats));
        }

        // Check battery health
        if let Some(battery) = &self.power_monitor.battery {
            if battery.health_percentage < 50.0 {
                self.alerts.push(format!(
                    "[WARN] BATTERIE DÉGRADÉE: {:.0}% santé",
                    battery.health_percentage
                ));
            }
        }

        self.last_tick = Instant::now();
    }

    // Sorted process list (borrowed)
    fn sorted_procs(&self) -> Vec<(sysinfo::Pid, &sysinfo::Process)> {
        let mut v: Vec<_> = self
            .sys
            .processes()
            .iter()
            .map(|(pid, p)| (*pid, p))
            .collect();
        match self.sort_by {
            SortBy::Cpu => v.sort_by(|a, b| b.1.cpu_usage().partial_cmp(&a.1.cpu_usage()).unwrap()),
            SortBy::Memory => v.sort_by(|a, b| b.1.memory().cmp(&a.1.memory())),
            SortBy::Pid => v.sort_by(|a, b| a.0.cmp(&b.0)),
            SortBy::Name => v.sort_by(|a, b| a.1.name().cmp(b.1.name())),
        }
        if !self.sort_desc {
            v.reverse();
        }
        v
    }

    fn kill_selected(&mut self) {
        let procs = self.sorted_procs();
        if let Some((pid, _)) = procs.get(self.proc_sel) {
            if let Some(p) = self.sys.process(*pid) {
                p.kill();
            }
        }
        self.tick();
    }

    fn optimizer_tips(&self) -> Vec<Line<'static>> {
        let ram_p = ram_pct_raw(&self.sys);
        let mut tips: Vec<Line<'static>> = vec![
            Line::from(vec![
                Span::styled("  RAM en cours : ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:.0}%", ram_p),
                    Style::default()
                        .fg(grade_color(ram_p as f64))
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::raw(""),
        ];

        if ram_p > 80 {
            tips.push(Line::styled(
                "   Top consommateurs RAM (onglet Processus → K pour tuer) :",
                Style::default().fg(ORANGE),
            ));
        } else {
            tips.push(Line::styled(
                "   RAM dans les normes — Top 3 processus :",
                Style::default().fg(LIME),
            ));
        }

        let mut procs: Vec<_> = self.sys.processes().values().collect();
        procs.sort_by(|a, b| b.memory().cmp(&a.memory()));
        for (i, p) in procs.iter().take(5).enumerate() {
            let mb = p.memory() as f64 / 1_048_576.0;
            let color = if i == 0 {
                RED
            } else if i == 1 {
                ORANGE
            } else {
                GOLD
            };
            let name = p.name().to_string_lossy().to_string();
            tips.push(Line::from(vec![
                Span::styled(format!("  {}. ", i + 1), Style::default().fg(color)),
                Span::styled(
                    format!("{:<22}", truncate(&name, 22)),
                    Style::default().fg(CYAN),
                ),
                Span::styled(format!("{:>7.1} MB", mb), Style::default().fg(color)),
            ]));
        }

        tips.push(Line::raw(""));
        let cpu_p = self.sys.global_cpu_usage() as f64;
        if cpu_p > 70.0 {
            tips.push(Line::styled(
                format!("   CPU élevé ({:.0}%) — vérifiez les processus", cpu_p),
                Style::default().fg(ORANGE),
            ));
        }
        tips.push(Line::styled(
            format!("  Swap utilisé : {}", fmt_bytes(self.sys.used_swap())),
            Style::default().fg(Color::DarkGray),
        ));
        tips
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
fn ram_pct_raw(sys: &System) -> u64 {
    if sys.total_memory() == 0 {
        return 0;
    }
    (sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0) as u64
}

fn push_history(v: &mut Vec<u64>, val: u64) {
    v.push(val);
    if v.len() > HISTORY_LEN {
        v.remove(0);
    }
}

fn grade_color(pct: f64) -> Color {
    if pct >= 85.0 {
        RED
    } else if pct >= 65.0 {
        ORANGE
    } else {
        LIME
    }
}

fn fmt_bytes(b: u64) -> String {
    match b {
        b if b >= 1 << 30 => format!("{:.2} GB", b as f64 / (1 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.0} KB", b as f64 / (1 << 10) as f64),
        _ => format!("{} B", b),
    }
}

fn fmt_speed(kbs: f64) -> String {
    if kbs >= 1_048_576.0 {
        format!("{:.2} GB/s", kbs / 1_048_576.0)
    } else if kbs >= 1024.0 {
        format!("{:.2} MB/s", kbs / 1024.0)
    } else {
        format!("{:.1} KB/s", kbs)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app = App::new();
    let tick = Duration::from_millis(TICK_MS);
    let mut last = Instant::now();

    // Visible rows in process table (estimated; adjusted dynamically if needed)
    const PROC_ROWS: usize = 20;

    loop {
        terminal.draw(|f| draw(f, &app))?;

        let timeout = tick.saturating_sub(last.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                let proc_count = app.sys.processes().len();
                match key.code {
                    // ── Global
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Tab => {
                        app.tab = match app.tab {
                            Tab::Overview => Tab::Processes,
                            Tab::Processes => Tab::Connections,
                            Tab::Connections => Tab::Storage,
                            Tab::Storage => Tab::Overview,
                        };
                    }
                    KeyCode::BackTab => {
                        app.tab = match app.tab {
                            Tab::Overview => Tab::Storage,
                            Tab::Processes => Tab::Overview,
                            Tab::Connections => Tab::Processes,
                            Tab::Storage => Tab::Connections,
                        };
                    }
                    // ── Processes navigation
                    KeyCode::Down if app.tab == Tab::Processes => {
                        if app.proc_sel + 1 < proc_count {
                            app.proc_sel += 1;
                            if app.proc_sel >= app.proc_off + PROC_ROWS {
                                app.proc_off += 1;
                            }
                        }
                    }
                    KeyCode::Up if app.tab == Tab::Processes => {
                        if app.proc_sel > 0 {
                            app.proc_sel -= 1;
                            if app.proc_sel < app.proc_off {
                                app.proc_off = app.proc_off.saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Char('K') if app.tab == Tab::Processes => {
                        app.kill_selected()
                    }
                    KeyCode::Char('c') if app.tab == Tab::Processes => {
                        app.sort_by = SortBy::Cpu;
                        app.sort_desc = true;
                    }
                    KeyCode::Char('m') if app.tab == Tab::Processes => {
                        app.sort_by = SortBy::Memory;
                        app.sort_desc = true;
                    }
                    KeyCode::Char('p') if app.tab == Tab::Processes => {
                        app.sort_by = SortBy::Pid;
                        app.sort_desc = false;
                    }
                    KeyCode::Char('n') if app.tab == Tab::Processes => {
                        app.sort_by = SortBy::Name;
                        app.sort_desc = false;
                    }
                    // ── Connections scroll
                    KeyCode::Down if app.tab == Tab::Connections => {
                        app.conn_off = app.conn_off.saturating_add(1);
                    }
                    KeyCode::Up if app.tab == Tab::Connections => {
                        app.conn_off = app.conn_off.saturating_sub(1);
                    }
                    KeyCode::PageDown if app.tab == Tab::Connections => {
                        app.conn_off = app.conn_off.saturating_add(10);
                    }
                    KeyCode::PageUp if app.tab == Tab::Connections => {
                        app.conn_off = app.conn_off.saturating_sub(10);
                    }
                    // ── Storage navigation (folder selection)
                    KeyCode::Down if app.tab == Tab::Storage => {
                        if app.storage_sel + 1 < app.disk_analyzer.items.len() {
                            app.storage_sel += 1;
                        }
                    }
                    KeyCode::Up if app.tab == Tab::Storage => {
                        app.storage_sel = app.storage_sel.saturating_sub(1);
                    }
                    KeyCode::Enter if app.tab == Tab::Storage => {
                        app.disk_analyzer.enter_folder(app.storage_sel);
                        app.storage_sel = 0;  // Reset selection when entering folder
                    }
                    KeyCode::Backspace if app.tab == Tab::Storage => {
                        app.disk_analyzer.go_back();
                        app.storage_sel = 0;
                    }
                    KeyCode::Char('o') | KeyCode::Char('O') if app.tab == Tab::Storage => {
                        if app.disk_analyzer.open_in_finder(app.storage_sel) {
                            app.alerts.push(format!("[✓] Ouvert dans Finder"));
                        } else {
                            app.alerts.push("[!] Erreur ouverture Finder".to_string());
                        }
                    }
                    // ── Manual scan (Connections tab)
                    KeyCode::Char('s') | KeyCode::Char('S') if app.tab == Tab::Connections => {
                        app.net_monitor.scan_connections();
                        app.net_monitor.analyze_threats();
                        app.alerts.push("[✓] Scan réseau + menaces lancé".to_string());
                    }
                    // ── Optimize RAM
                    KeyCode::Char('o') | KeyCode::Char('O') if app.tab == Tab::Overview => {
                        app.alerts.push("[!] Optimisation RAM demandée...".to_string());
                        // Flush caches
                        let _ = std::process::Command::new("sync").output();
                        let _ = std::process::Command::new("purge").output();
                        app.alerts.clear();
                        app.alerts.push("[✓] Cache vidé et mémoire purgée".to_string());
                    }
                    // ── Clean tmp files
                    KeyCode::Char('c') | KeyCode::Char('C') if app.tab == Tab::Storage => {
                        app.alerts.push("[!] Nettoyage tmp en cours...".to_string());
                        let _ = std::process::Command::new("sh")
                            .args(&["-c", "rm -rf /tmp/* /var/tmp/* 2>/dev/null"])
                            .output();
                        app.alerts.clear();
                        app.alerts.push("[✓] Fichiers temporaires supprimés".to_string());
                    }
                    _ => {}
                }
            }
        }

        if last.elapsed() >= tick {
            app.tick();
            last = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

// ─── Root layout ─────────────────────────────────────────────────────────────
fn draw(f: &mut Frame, app: &App) {
    let alert_h = if app.alerts.is_empty() { 0 } else { 3 };
    let root = Layout::vertical([
        Constraint::Length(3),       // header
        Constraint::Length(3),       // tabs
        Constraint::Min(0),          // content
        Constraint::Length(alert_h), // alerts
        Constraint::Length(3),       // footer
    ])
    .split(f.area());

    draw_header(f, app, root[0]);
    draw_tabs(f, app, root[1]);

    match app.tab {
        Tab::Overview => draw_overview(f, app, root[2]),
        Tab::Processes => draw_processes(f, app, root[2]),
        Tab::Connections => draw_connections(f, app, root[2]),
        Tab::Storage => draw_storage(f, app, root[2]),
    }

    if alert_h > 0 {
        draw_alerts(f, app, root[3]);
    }
    draw_footer(f, app, root[4]);
}

// ─── Header ──────────────────────────────────────────────────────────────────
fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let (color, blink) = if app.alerts.is_empty() {
        (LIME, Modifier::BOLD)
    } else {
        (RED, Modifier::BOLD | Modifier::RAPID_BLINK)
    };
    f.render_widget(
        Paragraph::new(" MACEON ")
            .alignment(Alignment::Center)
            .style(Style::default().fg(color).add_modifier(blink))
            .block(
                Block::bordered()
                    .border_type(BorderType::Double)
                    .border_style(Style::default().fg(color)),
            ),
        area,
    );
}

// ─── Tabs bar ─────────────────────────────────────────────────────────────────
fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let idx = match app.tab {
        Tab::Overview => 0,
        Tab::Processes => 1,
        Tab::Connections => 2,
        Tab::Storage => 3,
    };
    f.render_widget(
        Tabs::new(vec![
            "  Overview  ",
            "  Processus  ",
            "  Connections  ",
            "  Stockage  ",
        ])
        .select(idx)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(Style::default().fg(LIME).add_modifier(Modifier::BOLD))
        .divider("│")
        .block(Block::bordered().border_style(Style::default().fg(Color::Rgb(40, 40, 55)))),
        area,
    );
}

// ─── Alerts bar ───────────────────────────────────────────────────────────────
fn draw_alerts(f: &mut Frame, app: &App, area: Rect) {
    f.render_widget(
        Paragraph::new(app.alerts.join("   │   "))
            .alignment(Alignment::Center)
            .style(Style::default().fg(RED).add_modifier(Modifier::BOLD))
            .block(
                Block::bordered()
                    .title(" ALERTES ")
                    .border_style(Style::default().fg(RED)),
            ),
        area,
    );
}

// ─── Footer ───────────────────────────────────────────────────────────────────
fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let hint = match app.tab {
        Tab::Overview => "[TAB] Changer   [O] Optimiser RAM   [Q] Quitter",
        Tab::Processes => {
            "[↑↓] Naviguer   [K] Tuer   [C] CPU   [M] Mém   [P] PID   [N] Nom   [Q] Quitter"
        }
        Tab::Connections => "[TAB] Changer   [↑↓] Scroller   [S] Scanner   [Q] Quitter",
        Tab::Storage => "[TAB] Changer   [↑↓] Sélectionner   [Enter] Ouvrir   [O] Finder   [BS] Retour   [C] Nettoyer   [Q] Quitter",
    };
    f.render_widget(
        Paragraph::new(hint)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::bordered().border_style(Style::default().fg(Color::Rgb(35, 35, 50)))),
        area,
    );
}

// ─── Overview ─────────────────────────────────────────────────────────────────
fn draw_overview(f: &mut Frame, app: &App, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)]).areas(area);

    // Left column: gauges
    let [l0, l1, l2, l3] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Min(0),
    ])
    .areas(left);

    // ── CPU gauge
    let cpu_p = app.sys.global_cpu_usage();
    let cc = grade_color(cpu_p as f64);
    f.render_widget(
        Gauge::default()
            .block(
                Block::bordered()
                    .title(format!(
                        " [ CPU ] {:.1}%  |  {} cœurs ",
                        cpu_p,
                        app.sys.cpus().len()
                    ))
                    .border_style(Style::default().fg(cc)),
            )
            .gauge_style(Style::default().fg(cc).bg(DARK))
            .percent(cpu_p as u16)
            .label(format!("{:.1}%", cpu_p)),
        l0,
    );

    // ── RAM gauge
    let ram_used = app.sys.used_memory();
    let ram_total = app.sys.total_memory();
    let ram_p = ram_pct_raw(&app.sys);
    let rc = grade_color(ram_p as f64);
    f.render_widget(
        Gauge::default()
            .block(
                Block::bordered()
                    .title(format!(
                        " [ RAM ] {} / {}  ({:.0}%) ",
                        fmt_bytes(ram_used),
                        fmt_bytes(ram_total),
                        ram_p
                    ))
                    .border_style(Style::default().fg(rc)),
            )
            .gauge_style(Style::default().fg(rc).bg(DARK))
            .percent(ram_p as u16)
            .label(format!("{:.0}%", ram_p)),
        l1,
    );

    // ── Swap gauge
    let swap_u = app.sys.used_swap();
    let swap_t = app.sys.total_swap();
    let swap_p = if swap_t > 0 {
        swap_u as f64 / swap_t as f64 * 100.0
    } else {
        0.0
    };
    f.render_widget(
        Gauge::default()
            .block(
                Block::bordered()
                    .title(format!(
                        " [ SWAP ] {} / {} ",
                        fmt_bytes(swap_u),
                        fmt_bytes(swap_t)
                    ))
                    .border_style(Style::default().fg(PURPLE)),
            )
            .gauge_style(Style::default().fg(PURPLE).bg(DARK))
            .percent(swap_p as u16)
            .label(format!("{:.0}%", swap_p)),
        l2,
    );

    // ── Thermal sensors
    let temp_lines: Vec<Line> = app
        .components
        .iter()
        .map(|c| {
            let t = c.temperature().unwrap_or(0.0);
            let col = if t > 85.0 {
                RED
            } else if t > 65.0 {
                ORANGE
            } else {
                LIME
            };
            Line::from(vec![
                Span::styled(
                    format!("  {:.<30}", c.label()),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{:>6.1}°C", t),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                ),
            ])
        })
        .collect();
    f.render_widget(
        Paragraph::new(temp_lines).block(
            Block::bordered()
                .title(" [ CAPTEURS THERMIQUES ] ")
                .border_style(Style::default().fg(ORANGE)),
        ),
        l3,
    );

    // Right column: sparklines + optimizer
    let [r0, r1, r2] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Min(0),
    ])
    .areas(right);

    f.render_widget(
        Sparkline::default()
            .block(
                Block::bordered()
                    .title(" [ CPU — 60 dernières secondes ] ")
                    .border_style(Style::default().fg(LIME)),
            )
            .data(&app.cpu_hist)
            .style(Style::default().fg(LIME))
            .max(100),
        r0,
    );

    f.render_widget(
        Sparkline::default()
            .block(
                Block::bordered()
                    .title(" [ RAM — 60 dernières secondes ] ")
                    .border_style(Style::default().fg(PURPLE)),
            )
            .data(&app.ram_hist)
            .style(Style::default().fg(PURPLE))
            .max(100),
        r1,
    );

    f.render_widget(
        Paragraph::new(app.optimizer_tips()).block(
            Block::bordered()
                .title(" [ OPTIMIZER — Conseils RAM ] ")
                .border_style(Style::default().fg(CYAN)),
        ),
        r2,
    );
}

// ─── Processes ────────────────────────────────────────────────────────────────
fn draw_processes(f: &mut Frame, app: &App, area: Rect) {
    let [table_area, power_area, detail_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(8), Constraint::Length(6)]).areas(area);

    let procs = app.sorted_procs();
    let total_ram = app.sys.total_memory() as f64;

    let sort_label = match app.sort_by {
        SortBy::Cpu => "CPU ▼",
        SortBy::Memory => "MEM ▼",
        SortBy::Pid => "PID ▲",
        SortBy::Name => "NOM ▲",
    };

    let header = Row::new(["PID", "NOM", "CPU %", "RAM", "RAM %", "ÉTAT"])
        .style(
            Style::default()
                .fg(LIME)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .height(1);

    let rows: Vec<Row> = procs
        .iter()
        .enumerate()
        .skip(app.proc_off)
        .take(50)
        .map(|(abs_i, (pid, proc))| {
            let cpu = proc.cpu_usage() as f64;
            let mem = proc.memory();
            let mem_p = mem as f64 / total_ram * 100.0;
            let sel = abs_i == app.proc_sel;
            let name = proc.name().to_string_lossy().to_string();

            let base = if sel {
                Style::default().bg(Color::Rgb(30, 50, 70))
            } else {
                Style::default()
            };

            Row::new([
                Cell::from(pid.to_string()).style(base.fg(Color::DarkGray)),
                Cell::from(truncate(&name, 28)).style(base.fg(CYAN)),
                Cell::from(format!("{:.1}", cpu)).style(base.fg(grade_color(cpu))),
                Cell::from(fmt_bytes(mem)).style(base.fg(grade_color(mem_p))),
                Cell::from(format!("{:.1}%", mem_p)).style(base.fg(grade_color(mem_p))),
                Cell::from(format!("{:?}", proc.status())).style(base.fg(Color::DarkGray)),
            ])
        })
        .collect();

    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Min(22),
                Constraint::Length(7),
                Constraint::Length(11),
                Constraint::Length(7),
                Constraint::Length(10),
            ],
        )
        .header(header)
        .block(
            Block::bordered()
                .title(format!(
                    " [ PROCESSUS ]  {}  |  Tri : {} ",
                    procs.len(),
                    sort_label
                ))
                .border_style(Style::default().fg(LIME)),
        )
        .column_spacing(1),
        table_area,
    );

    // ── Power consumption info ─────────────────────────────────────────────
    let power_rows: Vec<Row> = app
        .power_monitor
        .process_impacts
        .iter()
        .take(7)
        .map(|impact| {
            let power_color = if impact.estimated_power_mw > 500.0 {
                RED
            } else if impact.estimated_power_mw > 200.0 {
                ORANGE
            } else {
                GOLD
            };

            Row::new([
                Cell::from(truncate(&impact.name, 25)).style(Style::default().fg(CYAN)),
                Cell::from(format!("{:.1}%", impact.cpu_percent))
                    .style(Style::default().fg(grade_color(impact.cpu_percent))),
                Cell::from(format!("{:.0} mW", impact.estimated_power_mw))
                    .style(Style::default().fg(power_color)),
            ])
        })
        .collect();

    f.render_widget(
        Table::new(
            power_rows,
            [
                Constraint::Min(25),
                Constraint::Length(8),
                Constraint::Length(12),
            ],
        )
        .header(
            Row::new(["Top Consommateurs", "CPU%", "Puissance"])
                .style(
                    Style::default()
                        .fg(LIME)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
        )
        .block(
            Block::bordered()
                .title(format!(" [ PUISSANCE ] Système: {:.0} mW", app.power_monitor.total_system_power_mw))
                .border_style(Style::default().fg(ORANGE)),
        )
        .column_spacing(1),
        power_area,
    );

    // ── Selected process detail ───────────────────────────────────────────
    if let Some((pid, proc)) = procs.get(app.proc_sel) {
        let cpu = proc.cpu_usage();
        let mem = proc.memory();
        let mem_p = mem as f64 / total_ram * 100.0;
        let name = proc.name().to_string_lossy().to_string();

        let lines = vec![
            Line::from(vec![
                Span::styled("  PID : ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    pid.to_string(),
                    Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
                ),
                Span::styled("   Nom : ", Style::default().fg(Color::DarkGray)),
                Span::styled(name, Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("  CPU  : ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:.2}%", cpu),
                    Style::default().fg(grade_color(cpu as f64)),
                ),
                Span::styled("   RAM : ", Style::default().fg(Color::DarkGray)),
                Span::styled(fmt_bytes(mem), Style::default().fg(grade_color(mem_p))),
                Span::styled(
                    format!("  ({:.1}%)", mem_p),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("  État : ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:?}", proc.status()), Style::default().fg(LIME)),
                Span::styled(
                    "         [K] Terminer ce processus",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ),
            ]),
        ];

        f.render_widget(
            Paragraph::new(lines).block(
                Block::bordered()
                    .title(" [ PROCESSUS SÉLECTIONNÉ ] ")
                    .border_style(Style::default().fg(ORANGE)),
            ),
            detail_area,
        );
    }
}

// ─── Connections (Network + Threats) ──────────────────────────────────────────
fn draw_connections(f: &mut Frame, app: &App, area: Rect) {
    let [speeds, table_area] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(area);

    // Global speeds
    f.render_widget(
        Paragraph::new(vec![Line::from(vec![
            Span::styled("  ↓ ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                fmt_speed(app.rx_speed),
                Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
            ),
            Span::raw("          "),
            Span::styled("↑ ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                fmt_speed(app.tx_speed),
                Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
            ),
        ])])
        .block(
            Block::bordered()
                .title(" [ VITESSE RÉSEAU ] ")
                .border_style(Style::default().fg(CYAN)),
        ),
        speeds,
    );

    // Threat summary
    let (total, suspicious, whitelisted) = app.net_monitor.get_summary();
    let summary_color = if suspicious > 0 { RED } else { LIME };

    f.render_widget(
        Paragraph::new(format!("Total: {} │ Menaces: {} │ Whitelistées: {}", total, suspicious, whitelisted))
            .block(
                Block::bordered()
                    .title(" [ CONNEXIONS ] ")
                    .border_style(Style::default().fg(summary_color)),
            ),
        Rect { x: table_area.x, y: table_area.y, width: table_area.width, height: 2 },
    );

    let connections_area = Rect {
        x: table_area.x,
        y: table_area.y + 2,
        width: table_area.width,
        height: table_area.height.saturating_sub(2),
    };

    // Connection table
    let rows: Vec<Row> = app
        .net_monitor
        .threats
        .iter()
        .skip(app.conn_off)
        .take(50)
        .map(|threat| {
            let status_color = if threat.is_whitelisted {
                LIME
            } else if threat.is_suspicious {
                RED
            } else {
                CYAN
            };

            let icon = if threat.is_whitelisted {
                "[OK]"
            } else if threat.is_suspicious {
                "[!!]"
            } else {
                "[?]"
            };

            Row::new([
                Cell::from(icon).style(Style::default().fg(status_color)),
                Cell::from(threat.connection.process_name.clone())
                    .style(Style::default().fg(CYAN)),
                Cell::from(threat.connection.remote_ip.clone())
                    .style(Style::default().fg(status_color)),
                Cell::from(threat.connection.remote_port.to_string())
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(threat.connection.protocol.clone())
                    .style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Min(28),
                Constraint::Length(18),
                Constraint::Length(6),
                Constraint::Length(6),
            ],
        )
        .header(
            Row::new(["", "Processus", "IP", "Port", "Proto"])
                .style(
                    Style::default()
                        .fg(LIME)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
        )
        .column_spacing(1),
        connections_area,
    );
}

// ─── Storage ──────────────────────────────────────────────────────────────────
// ─── Storage (Hierarchical Folder Analysis) ──────────────────────────────────
fn draw_storage(f: &mut Frame, app: &App, area: Rect) {
    let [path_area, table_area] = Layout::vertical([Constraint::Length(3), Constraint::Min(0)])
        .areas(area);

    // Current path display
    let current_path = app.disk_analyzer.current_path_str();
    f.render_widget(
        Paragraph::new(current_path)
            .block(
                Block::bordered()
                    .title(" [ CHEMIN ] ")
                    .border_style(Style::default().fg(CYAN)),
            )
            .style(Style::default().fg(LIME)),
        path_area,
    );

    // File/Folder list with sizes
    let total_size = app.disk_analyzer.total_size();
    let rows: Vec<Row> = app
        .disk_analyzer
        .items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let is_selected = i == app.storage_sel;
            let pct = disk_analyzer::calc_percentage(item.size, total_size);
            
            // Color by type: Folders are CYAN, Files are LIME
            let name_color = if item.is_dir {
                CYAN  // Folders
            } else {
                LIME  // Files
            };
            
            let size_color = if item.size > 10 * 1024 * 1024 * 1024 {
                RED  // > 10GB
            } else if item.size > 1024 * 1024 * 1024 {
                ORANGE  // > 1GB
            } else if item.size > 1024 * 1024 {
                LIME  // > 1MB
            } else {
                Color::DarkGray  // < 1MB
            };

            let bar_width = if total_size > 0 { ((pct / 100.0) * 20.0) as usize } else { 0 };
            let bar = "█".repeat(bar_width) + &" ".repeat(20 - bar_width);

            let style = if is_selected {
                Style::default().bg(Color::Rgb(30, 50, 70)).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new([
                Cell::from(format!("[{}]", if is_selected { "→" } else { " " }))
                    .style(style.fg(CYAN)),
                Cell::from(item.name.clone())
                    .style(style.fg(name_color)),
                Cell::from(format!("[{}]", bar))
                    .style(style.fg(size_color)),
                Cell::from(disk_analyzer::format_bytes(item.size))
                    .style(style.fg(size_color).add_modifier(Modifier::BOLD)),
                Cell::from(format!("{:.1}%", pct))
                    .style(style.fg(size_color)),
            ])
        })
        .collect();

    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Min(20),
                Constraint::Length(22),
                Constraint::Length(12),
                Constraint::Length(8),
            ],
        )
        .header(
            Row::new(["", "Dossier", "Usage", "Taille", "%"])
                .style(
                    Style::default()
                        .fg(LIME)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
        )
        .block(
            Block::bordered()
                .title(format!(
                    " [ ANALYSE HIÉRARCHIQUE ] Total: {} ",
                    disk_analyzer::format_bytes(total_size)
                ))
                .border_style(Style::default().fg(if total_size > 500 * 1024 * 1024 * 1024 { RED } else { LIME })),
        )
        .column_spacing(1),
        table_area,
    );
}

// ─── End of draw functions ────────────────────────────────────────────────────

