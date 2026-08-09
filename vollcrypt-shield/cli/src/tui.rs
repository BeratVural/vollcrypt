use std::io::{Read, Stdout};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap},
};
use sha2::{Digest, Sha256};
use similar::TextDiff;
use vollcrypt_shield_core::{
    AuditEvent, AuditEventKind, DifferenceKind, EntryKind, IntegrityEntry, MlDsa65PublicKey,
    NormalizedPath, PolicyMode, SignedSnapshot,
};
use vollcrypt_shield_fs::{
    AgentConfig, Scanner, ScopeConfig, WitnessRegistry, audit_store::AuditStore,
    notification::Notification, state::StateStore,
};

use crate::dashboard::{TUI_NOTIFICATION_LIMIT, read_notification_tail_with_limit};

const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MAX_PUBLIC_KEY_BYTES: u64 = 1_952;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPARISON_BYTES: u64 = 512 * 1024;
const MAX_RENDERED_DIFF_BYTES: usize = 256 * 1024;
const MAX_VISIBLE_RECORDS: usize = 500;
const FILE_CONTENT_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-FILE-v1\0";

type TuiResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Overview,
    Scopes,
    Events,
    Files,
    Witnesses,
    Notifications,
}

impl View {
    const ALL: [Self; 6] = [
        Self::Overview,
        Self::Scopes,
        Self::Events,
        Self::Files,
        Self::Witnesses,
        Self::Notifications,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Scopes => "Scopes",
            Self::Events => "Events",
            Self::Files => "Files",
            Self::Witnesses => "Witnesses",
            Self::Notifications => "Notifications",
        }
    }
}

#[derive(Debug, Clone)]
struct DifferenceView {
    relative_path: String,
    absolute_path: String,
    kind: DifferenceKind,
}

#[derive(Debug, Clone)]
struct ScopeView {
    id: String,
    root: PathBuf,
    status: String,
    policy_mode: String,
    protected_system_path: bool,
    contained: bool,
    containment_reason: Option<String>,
    baseline_root: Option<String>,
    observed_root: Option<String>,
    baseline_created_at_unix_ms: Option<u64>,
    entry_count: usize,
    difference_count: usize,
    differences: Vec<DifferenceView>,
    notifications: Vec<Notification>,
    invalid_notifications: usize,
    notification_error: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct WitnessView {
    id: String,
    key_id: String,
}

#[derive(Debug, Clone)]
struct SnapshotView {
    refreshed_at_unix_ms: u64,
    agent_key_id: String,
    audit_chain_valid: bool,
    audit_error: Option<String>,
    state_signature_valid: bool,
    state_error: Option<String>,
    events: Vec<AuditEvent>,
    scopes: Vec<ScopeView>,
    witnesses: Vec<WitnessView>,
    witness_error: Option<String>,
}

#[derive(Debug, Clone)]
struct DiffOverlay {
    title: String,
    detail: String,
    scroll: u16,
}

#[derive(Debug)]
struct App {
    config_path: PathBuf,
    requested_scope: Option<String>,
    view: View,
    scope_index: usize,
    event_index: usize,
    file_index: usize,
    witness_index: usize,
    notification_index: usize,
    snapshot: Option<SnapshotView>,
    loading: bool,
    error: Option<String>,
    help: bool,
    diff: Option<DiffOverlay>,
    no_color: bool,
    last_refresh: Instant,
}

impl App {
    fn new(config_path: PathBuf, requested_scope: Option<String>, no_color: bool) -> Self {
        Self {
            config_path,
            requested_scope,
            view: View::Overview,
            scope_index: 0,
            event_index: 0,
            file_index: 0,
            witness_index: 0,
            notification_index: 0,
            snapshot: None,
            loading: true,
            error: None,
            help: false,
            diff: None,
            no_color,
            last_refresh: Instant::now(),
        }
    }

    fn apply_refresh(&mut self, result: Result<SnapshotView, String>) {
        self.loading = false;
        self.last_refresh = Instant::now();
        match result {
            Ok(snapshot) => {
                let previous_scope = self.selected_scope().map(|scope| scope.id.clone());
                let target = previous_scope.or_else(|| self.requested_scope.take());
                self.snapshot = Some(snapshot);
                self.error = None;
                if let Some(target) = target {
                    if let Some(index) = self
                        .snapshot
                        .as_ref()
                        .and_then(|value| value.scopes.iter().position(|scope| scope.id == target))
                    {
                        self.scope_index = index;
                    } else {
                        self.error = Some(format!("unknown scope id: {target}"));
                    }
                }
                self.clamp_selection();
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn selected_scope(&self) -> Option<&ScopeView> {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.scopes.get(self.scope_index))
    }

    fn selected_difference(&self) -> Option<&DifferenceView> {
        self.selected_scope()
            .and_then(|scope| scope.differences.get(self.file_index))
    }

    fn events(&self) -> Vec<&AuditEvent> {
        let Some(scope) = self.selected_scope() else {
            return Vec::new();
        };
        self.snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .events
                    .iter()
                    .filter(|event| event.scope_id == scope.id)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn clamp_selection(&mut self) {
        let scope_len = self
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.scopes.len());
        self.scope_index = clamp_index(self.scope_index, scope_len);
        self.event_index = clamp_index(self.event_index, self.events().len());
        let file_len = self
            .selected_scope()
            .map_or(0, |scope| scope.differences.len());
        self.file_index = clamp_index(self.file_index, file_len);
        let witness_len = self
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.witnesses.len());
        self.witness_index = clamp_index(self.witness_index, witness_len);
        let notification_len = self
            .selected_scope()
            .map_or(0, |scope| scope.notifications.len());
        self.notification_index = clamp_index(self.notification_index, notification_len);
    }

    fn select_scope(&mut self, index: usize) {
        self.scope_index = index;
        self.event_index = 0;
        self.file_index = 0;
        self.notification_index = 0;
        self.clamp_selection();
    }

    fn move_selection(&mut self, delta: isize) {
        match self.view {
            View::Overview => {}
            View::Scopes => {
                let len = self
                    .snapshot
                    .as_ref()
                    .map_or(0, |snapshot| snapshot.scopes.len());
                self.select_scope(shift_index(self.scope_index, len, delta));
            }
            View::Events => {
                self.event_index = shift_index(self.event_index, self.events().len(), delta);
            }
            View::Files => {
                let len = self
                    .selected_scope()
                    .map_or(0, |scope| scope.differences.len());
                self.file_index = shift_index(self.file_index, len, delta);
            }
            View::Witnesses => {
                let len = self
                    .snapshot
                    .as_ref()
                    .map_or(0, |snapshot| snapshot.witnesses.len());
                self.witness_index = shift_index(self.witness_index, len, delta);
            }
            View::Notifications => {
                let len = self
                    .selected_scope()
                    .map_or(0, |scope| scope.notifications.len());
                self.notification_index = shift_index(self.notification_index, len, delta);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    None,
    Refresh,
    Quit,
}

pub fn require_interactive(stdin_terminal: bool, stdout_terminal: bool) -> TuiResult<()> {
    if !stdin_terminal || !stdout_terminal {
        return Err(
            "the TUI requires an interactive terminal; use dashboard --once for non-interactive output"
                .into(),
        );
    }
    Ok(())
}

pub fn run(
    config_path: PathBuf,
    requested_scope: Option<String>,
    refresh_interval: Duration,
    no_color: bool,
) -> TuiResult<()> {
    let mut session = TerminalSession::new()?;
    let (sender, receiver) = mpsc::channel();
    let mut app = App::new(config_path, requested_scope, no_color);
    request_refresh(&app.config_path, &sender);

    loop {
        receive_refresh(&mut app, &receiver);
        session.terminal.draw(|frame| draw(frame, &mut app))?;

        if !app.loading && app.last_refresh.elapsed() >= refresh_interval {
            app.loading = true;
            request_refresh(&app.config_path, &sender);
        }

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
        {
            match handle_key(&mut app, key)? {
                Action::Quit => break,
                Action::Refresh if !app.loading => {
                    app.loading = true;
                    request_refresh(&app.config_path, &sender);
                }
                Action::None | Action::Refresh => {}
            }
        }
    }
    Ok(())
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    fn new() -> TuiResult<Self> {
        enable_raw_mode()?;
        let mut terminal = match Terminal::new(CrosstermBackend::new(std::io::stdout())) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = disable_raw_mode();
                return Err(error.into());
            }
        };
        if let Err(error) = execute!(terminal.backend_mut(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error.into());
        }
        Ok(Self { terminal })
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, Show);
        let _ = self.terminal.show_cursor();
    }
}

fn request_refresh(config_path: &Path, sender: &Sender<Result<SnapshotView, String>>) {
    let config_path = config_path.to_path_buf();
    let sender = sender.clone();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(|| load_snapshot(&config_path))
            .map_err(|_| "background integrity verification panicked".to_owned())
            .and_then(|value| value.map_err(|error| error.to_string()));
        let _ = sender.send(result);
    });
}

fn receive_refresh(app: &mut App, receiver: &Receiver<Result<SnapshotView, String>>) {
    while let Ok(result) = receiver.try_recv() {
        app.apply_refresh(result);
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> TuiResult<Action> {
    if app.diff.is_some() {
        match key.code {
            KeyCode::Char('q') => return Ok(Action::Quit),
            KeyCode::Esc | KeyCode::Enter => app.diff = None,
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(diff) = app.diff.as_mut() {
                    diff.scroll = diff.scroll.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(diff) = app.diff.as_mut() {
                    diff.scroll = diff.scroll.saturating_add(1);
                }
            }
            KeyCode::PageUp => {
                if let Some(diff) = app.diff.as_mut() {
                    diff.scroll = diff.scroll.saturating_sub(10);
                }
            }
            KeyCode::PageDown => {
                if let Some(diff) = app.diff.as_mut() {
                    diff.scroll = diff.scroll.saturating_add(10);
                }
            }
            _ => {}
        }
        return Ok(Action::None);
    }
    if app.help {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter) {
            app.help = false;
        } else if key.code == KeyCode::Char('q') {
            return Ok(Action::Quit);
        }
        return Ok(Action::None);
    }

    match key.code {
        KeyCode::Char('q') => return Ok(Action::Quit),
        KeyCode::Char('r') => return Ok(Action::Refresh),
        KeyCode::Char('?') => app.help = true,
        KeyCode::Tab | KeyCode::Right => {
            let index = View::ALL
                .iter()
                .position(|view| *view == app.view)
                .unwrap_or(0);
            app.view = View::ALL[(index + 1) % View::ALL.len()];
            app.clamp_selection();
        }
        KeyCode::BackTab | KeyCode::Left => {
            let index = View::ALL
                .iter()
                .position(|view| *view == app.view)
                .unwrap_or(0);
            app.view = View::ALL[(index + View::ALL.len() - 1) % View::ALL.len()];
            app.clamp_selection();
        }
        KeyCode::Char(value @ '1'..='6') => {
            app.view = View::ALL[(value as usize) - ('1' as usize)];
            app.clamp_selection();
        }
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
        KeyCode::PageUp => app.move_selection(-10),
        KeyCode::PageDown => app.move_selection(10),
        KeyCode::Home => app.move_selection(isize::MIN),
        KeyCode::End => app.move_selection(isize::MAX),
        KeyCode::Enter if app.view == View::Files => {
            if let (Some(scope), Some(difference)) =
                (app.selected_scope(), app.selected_difference())
            {
                let title = format!(
                    "{}: {}",
                    kind_label(difference.kind),
                    difference.absolute_path
                );
                let detail =
                    inspect_difference(&app.config_path, &scope.id, &difference.relative_path)
                        .unwrap_or_else(|error| format!("Comparison unavailable: {error}"));
                app.diff = Some(DiffOverlay {
                    title,
                    detail,
                    scroll: 0,
                });
            }
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return Ok(Action::Quit);
        }
        _ => {}
    }
    Ok(Action::None)
}

fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < 48 || area.height < 12 {
        let text = Paragraph::new(
            "Vollcrypt Shield\n\nTerminal is too small. Resize to at least 48 x 12.\n\nq quit",
        )
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
        frame.render_widget(text, area);
        return;
    }

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(2),
        ])
        .split(area);
    render_header(frame, app, sections[0]);
    render_tabs(frame, app, sections[1]);
    match app.view {
        View::Overview => render_overview(frame, app, sections[2]),
        View::Scopes => render_scopes(frame, app, sections[2]),
        View::Events => render_events(frame, app, sections[2]),
        View::Files => render_files(frame, app, sections[2]),
        View::Witnesses => render_witnesses(frame, app, sections[2]),
        View::Notifications => render_notifications(frame, app, sections[2]),
    }
    render_footer(frame, app, sections[3]);
    if app.help {
        render_help(frame, app, area);
    }
    if let Some(diff) = &app.diff {
        render_diff(frame, app, diff, area);
    }
}

fn render_header(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let status = app
        .selected_scope()
        .map_or("NO DATA", |scope| scope.status.as_str());
    let scope = app
        .selected_scope()
        .map_or("no scope", |scope| scope.id.as_str());
    let refresh = if app.loading { "VERIFYING" } else { "READY" };
    let line = Line::from(vec![
        Span::styled(
            " VOLLCRYPT SHIELD ",
            Style::default()
                .fg(color(app, Color::Black))
                .bg(color(app, Color::White))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(status, status_style(app, status)),
        Span::raw(format!("  Scope: {scope}")),
        Span::raw(format!("  {refresh}")),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_tabs(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let titles = View::ALL
        .iter()
        .enumerate()
        .map(|(index, view)| Line::from(format!("{} {}", index + 1, view.label())))
        .collect::<Vec<_>>();
    let selected = View::ALL
        .iter()
        .position(|view| *view == app.view)
        .unwrap_or(0);
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::BOTTOM))
        .select(selected)
        .style(Style::default().fg(color(app, Color::DarkGray)))
        .highlight_style(
            Style::default()
                .fg(color(app, Color::Cyan))
                .add_modifier(Modifier::BOLD),
        )
        .divider(" | ");
    frame.render_widget(tabs, area);
}

fn render_overview(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        render_message(
            frame,
            area,
            app.error.as_deref().unwrap_or("Loading signed evidence..."),
        );
        return;
    };
    let verified = snapshot
        .scopes
        .iter()
        .filter(|scope| scope.status == "VERIFIED")
        .count();
    let changed = snapshot
        .scopes
        .iter()
        .filter(|scope| scope.status == "CHANGED")
        .count();
    let contained = snapshot
        .scopes
        .iter()
        .filter(|scope| scope.contained)
        .count();
    let differences: usize = snapshot
        .scopes
        .iter()
        .map(|scope| scope.difference_count)
        .sum();
    let notification_count: usize = snapshot
        .scopes
        .iter()
        .map(|scope| scope.notifications.len())
        .sum();
    let mut lines = vec![
        Line::from(vec![
            label(app, "Trust source"),
            Span::raw("signed local evidence"),
        ]),
        Line::from(vec![
            label(app, "Agent key"),
            Span::raw(short_hash(&snapshot.agent_key_id)),
        ]),
        Line::from(vec![
            label(app, "Audit chain"),
            trust_span(
                app,
                snapshot.audit_chain_valid,
                snapshot.audit_error.as_deref(),
            ),
        ]),
        Line::from(vec![
            label(app, "Agent state"),
            trust_span(
                app,
                snapshot.state_signature_valid,
                snapshot.state_error.as_deref(),
            ),
        ]),
        Line::from(vec![
            label(app, "Scopes"),
            Span::raw(format!(
                "{} total, {verified} verified, {changed} changed, {contained} contained",
                snapshot.scopes.len()
            )),
        ]),
        Line::from(vec![
            label(app, "Differences"),
            Span::styled(
                differences.to_string(),
                if differences == 0 {
                    status_style(app, "VERIFIED")
                } else {
                    status_style(app, "CHANGED")
                },
            ),
        ]),
        Line::from(vec![
            label(app, "Recent records"),
            Span::raw(format!(
                "{} audit, {notification_count} notifications, {} witnesses",
                snapshot.events.len(),
                snapshot.witnesses.len()
            )),
        ]),
        Line::from(vec![
            label(app, "Refreshed (ms)"),
            Span::raw(snapshot.refreshed_at_unix_ms.to_string()),
        ]),
    ];
    if let Some(scope) = app.selected_scope() {
        lines.extend([
            Line::from(""),
            Line::from(vec![
                label(app, "Selected root"),
                Span::raw(scope.root.display().to_string()),
            ]),
            Line::from(vec![
                label(app, "Policy boundary"),
                Span::raw(if scope.protected_system_path {
                    "passive (protected system path)"
                } else {
                    scope.policy_mode.as_str()
                }),
            ]),
            Line::from(vec![
                label(app, "Baseline root"),
                Span::raw(
                    scope
                        .baseline_root
                        .as_deref()
                        .map(short_hash)
                        .unwrap_or_else(|| "unavailable".to_owned()),
                ),
            ]),
            Line::from(vec![
                label(app, "Observed root"),
                Span::raw(
                    scope
                        .observed_root
                        .as_deref()
                        .map(short_hash)
                        .unwrap_or_else(|| "unavailable".to_owned()),
                ),
            ]),
            Line::from(vec![
                label(app, "Baseline"),
                Span::raw(format!(
                    "{} entries, created {}",
                    scope.entry_count,
                    scope
                        .baseline_created_at_unix_ms
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unavailable".to_owned())
                )),
            ]),
        ]);
        if let Some(reason) = &scope.containment_reason {
            lines.push(Line::from(vec![
                label(app, "Containment"),
                Span::styled(reason.clone(), status_style(app, "CONTAINED")),
            ]));
        }
    }
    let mut text = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Integrity summary ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    if let Some(error) = &app.error {
        text = text.block(
            Block::default()
                .title(format!(
                    " Integrity summary | Last refresh failed: {error} "
                ))
                .borders(Borders::ALL),
        );
    }
    frame.render_widget(text, area);
}

fn render_scopes(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let rows = app
        .snapshot
        .as_ref()
        .map(|snapshot| {
            snapshot
                .scopes
                .iter()
                .map(|scope| {
                    Row::new(vec![
                        Cell::from(scope.id.clone()),
                        Cell::from(scope.status.clone()),
                        Cell::from(scope.policy_mode.clone()),
                        Cell::from(scope.difference_count.to_string()),
                        Cell::from(scope.root.display().to_string()),
                    ])
                    .style(status_style(app, &scope.status))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let widths = [
        Constraint::Length(18),
        Constraint::Length(11),
        Constraint::Length(13),
        Constraint::Length(7),
        Constraint::Min(20),
    ];
    render_table(
        frame,
        area,
        app,
        TableView {
            title: " Monitoring scopes ",
            headers: ["Scope", "Status", "Policy", "Changes", "Root"],
            rows,
            widths,
            selected: app.scope_index,
        },
    );
}

fn render_events(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let rows = app
        .events()
        .into_iter()
        .map(|event| {
            Row::new(vec![
                Cell::from(event.sequence.to_string()),
                Cell::from(event.timestamp_unix_ms.to_string()),
                Cell::from(event_kind(event.kind)),
                Cell::from(event.path.clone().unwrap_or_default()),
                Cell::from(event.detail.clone()),
            ])
        })
        .collect::<Vec<_>>();
    render_table(
        frame,
        area,
        app,
        TableView {
            title: " Verified audit events ",
            headers: ["Seq", "Time (ms)", "Kind", "Path", "Detail"],
            rows,
            widths: [
                Constraint::Length(7),
                Constraint::Length(15),
                Constraint::Length(20),
                Constraint::Length(24),
                Constraint::Min(20),
            ],
            selected: app.event_index,
        },
    );
}

fn render_files(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let rows = app
        .selected_scope()
        .map(|scope| {
            scope
                .differences
                .iter()
                .map(|difference| {
                    Row::new(vec![
                        Cell::from(kind_label(difference.kind)),
                        Cell::from(difference.relative_path.clone()),
                        Cell::from(difference.absolute_path.clone()),
                    ])
                    .style(difference_style(app, difference.kind))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let title = app.selected_scope().map_or_else(
        || " Changed files ".to_owned(),
        |scope| {
            if let Some(error) = &scope.error {
                format!(" Changed files | verification failed: {error} ")
            } else {
                format!(
                    " Changed files | {} displayed of {} | Enter: verified diff ",
                    scope.differences.len(),
                    scope.difference_count
                )
            }
        },
    );
    render_table(
        frame,
        area,
        app,
        TableView {
            title: &title,
            headers: ["Kind", "Relative path", "Absolute path"],
            rows,
            widths: [
                Constraint::Length(10),
                Constraint::Percentage(35),
                Constraint::Percentage(65),
            ],
            selected: app.file_index,
        },
    );
}

fn render_witnesses(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let rows = app
        .snapshot
        .as_ref()
        .map(|snapshot| {
            snapshot
                .witnesses
                .iter()
                .map(|witness| {
                    Row::new(vec![
                        Cell::from(witness.id.clone()),
                        Cell::from(witness.key_id.clone()),
                        Cell::from("PINNED"),
                    ])
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let title = app
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.witness_error.as_ref())
        .map_or_else(
            || " Signed witness registry ".to_owned(),
            |error| format!(" Signed witness registry | invalid: {error} "),
        );
    render_table(
        frame,
        area,
        app,
        TableView {
            title: &title,
            headers: ["Witness", "Key ID", "Trust"],
            rows,
            widths: [
                Constraint::Length(24),
                Constraint::Min(36),
                Constraint::Length(10),
            ],
            selected: app.witness_index,
        },
    );
}

fn render_notifications(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let rows = app
        .selected_scope()
        .map(|scope| {
            scope
                .notifications
                .iter()
                .rev()
                .map(|notification| {
                    Row::new(vec![
                        Cell::from(notification.timestamp_unix_ms.to_string()),
                        Cell::from(notification.kind.clone()),
                        Cell::from(if notification.repeated { "yes" } else { "no" }),
                        Cell::from(notification.message.clone()),
                    ])
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let title = app.selected_scope().map_or_else(
        || " Notifications ".to_owned(),
        |scope| {
            if let Some(error) = &scope.notification_error {
                format!(" Notifications | unavailable: {error} ")
            } else if scope.invalid_notifications > 0 {
                format!(
                    " Notifications | {} malformed record(s) ignored ",
                    scope.invalid_notifications
                )
            } else {
                " Notifications ".to_owned()
            }
        },
    );
    render_table(
        frame,
        area,
        app,
        TableView {
            title: &title,
            headers: ["Time (ms)", "Kind", "Repeated", "Message"],
            rows,
            widths: [
                Constraint::Length(15),
                Constraint::Length(24),
                Constraint::Length(10),
                Constraint::Min(30),
            ],
            selected: app.notification_index,
        },
    );
}

struct TableView<'a, const N: usize> {
    title: &'a str,
    headers: [&'a str; N],
    rows: Vec<Row<'static>>,
    widths: [Constraint; N],
    selected: usize,
}

fn render_table<const N: usize>(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &App,
    view: TableView<'_, N>,
) {
    let header = Row::new(view.headers)
        .style(
            Style::default()
                .fg(color(app, Color::White))
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);
    let table = Table::new(view.rows, view.widths)
        .header(header)
        .block(Block::default().title(view.title).borders(Borders::ALL))
        .row_highlight_style(
            Style::default()
                .bg(color(app, Color::DarkGray))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    let mut state = TableState::default().with_selected(Some(view.selected));
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let error = app
        .error
        .as_ref()
        .map(|value| format!("  Refresh error: {value}"))
        .unwrap_or_default();
    let footer = Line::from(vec![
        Span::styled(
            " Tab/Left/Right ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("views  "),
        Span::styled(" j/k ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("select  "),
        Span::styled(" r ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("refresh  "),
        Span::styled(" ? ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("help  "),
        Span::styled(" q ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("quit"),
        Span::styled(error, Style::default().fg(color(app, Color::Red))),
    ]);
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(color(app, Color::Gray))),
        area,
    );
}

fn render_help(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let popup = centered_rect(70, 72, area);
    frame.render_widget(Clear, popup);
    let help = Paragraph::new(vec![
        Line::from("1-6                 Open a view"),
        Line::from("Tab / Shift-Tab     Next / previous view"),
        Line::from("Left / Right        Previous / next view"),
        Line::from("j / k, Up / Down    Move selection"),
        Line::from("Home / End          First / last record"),
        Line::from("PageUp / PageDown   Move ten records"),
        Line::from("Enter                Open verified file comparison"),
        Line::from("r                    Refresh signed evidence"),
        Line::from("q / Ctrl-C           Quit"),
        Line::from("Esc / ?              Close this panel"),
        Line::from(""),
        Line::from("Read-only boundary"),
        Line::from("No baseline, policy, containment, or break-glass action is exposed."),
    ])
    .block(
        Block::default()
            .title(" Keyboard and trust boundary ")
            .borders(Borders::ALL),
    )
    .style(Style::default().fg(color(app, Color::White)))
    .wrap(Wrap { trim: false });
    frame.render_widget(help, popup);
}

fn render_diff(frame: &mut Frame<'_>, app: &App, diff: &DiffOverlay, area: Rect) {
    let popup = centered_rect(94, 88, area);
    frame.render_widget(Clear, popup);
    let paragraph = Paragraph::new(diff.detail.clone())
        .block(
            Block::default()
                .title(format!(" {} | Esc/Enter close ", diff.title))
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(color(app, Color::White)))
        .scroll((diff.scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, popup);
}

fn render_message(frame: &mut Frame<'_>, area: Rect, message: &str) {
    frame.render_widget(
        Paragraph::new(message.to_owned())
            .block(Block::default().borders(Borders::ALL))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn label(app: &App, value: &'static str) -> Span<'static> {
    Span::styled(
        format!("{value:<18}: "),
        Style::default()
            .fg(color(app, Color::Gray))
            .add_modifier(Modifier::BOLD),
    )
}

fn trust_span(app: &App, valid: bool, error: Option<&str>) -> Span<'static> {
    if valid {
        Span::styled("VALID", status_style(app, "VERIFIED"))
    } else {
        Span::styled(
            format!("INVALID ({})", error.unwrap_or("unavailable")),
            status_style(app, "CHANGED"),
        )
    }
}

fn color(app: &App, value: Color) -> Color {
    if app.no_color { Color::Reset } else { value }
}

fn status_style(app: &App, status: &str) -> Style {
    let color_value = match status {
        "VERIFIED" | "MONITORING" | "VALID" => Color::Green,
        "CHANGED" | "CONTAINED" | "INVALID" => Color::Red,
        "CHECKING" | "VERIFYING" => Color::Yellow,
        _ => Color::White,
    };
    Style::default()
        .fg(color(app, color_value))
        .add_modifier(Modifier::BOLD)
}

fn difference_style(app: &App, kind: DifferenceKind) -> Style {
    let value = match kind {
        DifferenceKind::Added => Color::Green,
        DifferenceKind::Removed => Color::Red,
        DifferenceKind::Modified => Color::Yellow,
    };
    Style::default().fg(color(app, value))
}

fn short_hash(value: &str) -> String {
    if value.len() <= 24 {
        value.to_owned()
    } else {
        format!("{}...{}", &value[..12], &value[value.len() - 12..])
    }
}

fn clamp_index(index: usize, len: usize) -> usize {
    if len == 0 { 0 } else { index.min(len - 1) }
}

fn shift_index(index: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    if delta == isize::MIN {
        return 0;
    }
    if delta == isize::MAX {
        return len - 1;
    }
    index.saturating_add_signed(delta).min(len - 1)
}

fn load_snapshot(config_path: &Path) -> TuiResult<SnapshotView> {
    let config_text = String::from_utf8(read_bounded_regular(config_path, MAX_CONFIG_BYTES)?)?;
    let config = AgentConfig::from_toml(&config_text)?;
    let public_key = MlDsa65PublicKey::from_bytes(&read_bounded_regular(
        &config.state_dir.join("keys").join("agent.public"),
        MAX_PUBLIC_KEY_BYTES,
    )?)?;
    let agent_key_id = hex::encode(public_key.key_id());

    let audit_path = config.state_dir.join("audit.log");
    let (audit_chain_valid, audit_error, events) = if audit_path.is_file() {
        match AuditStore::load_or_new(&audit_path, &public_key).and_then(|store| store.verify()) {
            Ok(events) => (
                true,
                None,
                events.into_iter().rev().take(MAX_VISIBLE_RECORDS).collect(),
            ),
            Err(error) => (false, Some(error.to_string()), Vec::new()),
        }
    } else {
        (
            false,
            Some("signed audit log is not present".to_owned()),
            Vec::new(),
        )
    };

    let state_path = config.state_dir.join("state.cbor");
    let (state_signature_valid, state_error, state) = if state_path.is_file() {
        match StateStore::load_or_new(&state_path, &public_key) {
            Ok(state) => (true, None, Some(state)),
            Err(error) => (false, Some(error.to_string()), None),
        }
    } else {
        (
            false,
            Some("signed agent state is not present".to_owned()),
            None,
        )
    };

    let witness_path = config.state_dir.join("witnesses.cbor");
    let (witnesses, witness_error) = if witness_path.is_file() {
        match WitnessRegistry::load(&witness_path, &public_key) {
            Ok(registry) => (
                registry
                    .entries()
                    .iter()
                    .map(|entry| WitnessView {
                        id: entry.witness_id.clone(),
                        key_id: hex::encode(entry.key_id),
                    })
                    .collect(),
                None,
            ),
            Err(error) => (Vec::new(), Some(error.to_string())),
        }
    } else {
        (
            Vec::new(),
            Some("signed witness registry is not present".to_owned()),
        )
    };

    let mut scopes = Vec::with_capacity(config.scopes.len());
    for scope in &config.scopes {
        let containment = state
            .as_ref()
            .and_then(|state| state.containment(&scope.id));
        let contained = containment.is_some();
        let notifications =
            read_notification_tail_with_limit(&config.state_dir, &scope.id, TUI_NOTIFICATION_LIMIT);
        let mut view = ScopeView {
            id: scope.id.clone(),
            root: scope.root.clone(),
            status: if contained { "CONTAINED" } else { "CHECKING" }.to_owned(),
            policy_mode: response_mode(scope),
            protected_system_path: scope.protects_system_path(),
            contained,
            containment_reason: containment.map(|value| value.reason.clone()),
            baseline_root: None,
            observed_root: None,
            baseline_created_at_unix_ms: None,
            entry_count: 0,
            difference_count: 0,
            differences: Vec::new(),
            notifications: notifications.events,
            invalid_notifications: notifications.invalid_records,
            notification_error: notifications.unavailable,
            error: None,
        };

        let verification = verify_scope_read_only(&config, scope, &public_key);
        match verification {
            Ok((snapshot, report)) => {
                view.baseline_root = Some(hex::encode(snapshot.root));
                view.observed_root = Some(hex::encode(report.observed_root));
                view.baseline_created_at_unix_ms = Some(snapshot.created_at_unix_ms);
                view.entry_count = snapshot.entries.len();
                view.difference_count = report.differences.len();
                view.differences = report
                    .differences
                    .iter()
                    .take(MAX_VISIBLE_RECORDS)
                    .map(|difference| DifferenceView {
                        relative_path: difference.path.to_string(),
                        absolute_path: scope
                            .root
                            .join(difference.path.as_str())
                            .display()
                            .to_string(),
                        kind: difference.kind,
                    })
                    .collect();
                if !contained {
                    view.status = if report.is_match() {
                        "VERIFIED"
                    } else {
                        "CHANGED"
                    }
                    .to_owned();
                }
            }
            Err(error) => {
                if !contained {
                    view.status = "INVALID".to_owned();
                }
                view.error = Some(error.to_string());
            }
        }
        scopes.push(view);
    }

    Ok(SnapshotView {
        refreshed_at_unix_ms: vollcrypt_shield_fs::agent::now_unix_ms()?,
        agent_key_id,
        audit_chain_valid,
        audit_error,
        state_signature_valid,
        state_error,
        events,
        scopes,
        witnesses,
        witness_error,
    })
}

fn verify_scope_read_only(
    config: &AgentConfig,
    scope: &ScopeConfig,
    public_key: &MlDsa65PublicKey,
) -> TuiResult<(
    vollcrypt_shield_core::Snapshot,
    vollcrypt_shield_core::VerificationReport,
)> {
    let path = config
        .state_dir
        .join("snapshots")
        .join(format!("{}.snapshot.cbor", scope.id));
    let signed = SignedSnapshot::from_cbor(&read_bounded_regular(&path, MAX_SNAPSHOT_BYTES)?)?;
    if signed.public_key()?.key_id() != public_key.key_id() {
        return Err("baseline signer does not match the trusted agent key".into());
    }
    let snapshot = signed.verify()?;
    if snapshot.scope_id != scope.id {
        return Err("baseline scope does not match its configured scope".into());
    }
    let observed = Scanner::new(scope)?.full_scan(scope)?;
    let report = Scanner::compare(&snapshot, &observed);
    Ok((snapshot, report))
}

fn response_mode(scope: &ScopeConfig) -> String {
    if scope.protects_system_path() {
        "passive".to_owned()
    } else if !cfg!(any(unix, windows)) {
        "dry-run".to_owned()
    } else {
        match scope.response.mode {
            PolicyMode::DryRun => "dry-run",
            PolicyMode::Active => "active",
        }
        .to_owned()
    }
}

fn event_kind(kind: AuditEventKind) -> &'static str {
    match kind {
        AuditEventKind::AgentStarted => "agent-started",
        AuditEventKind::BaselineCreated => "baseline-created",
        AuditEventKind::VerificationPassed => "verification-passed",
        AuditEventKind::VerificationFailed => "verification-failed",
        AuditEventKind::DryRunResponse => "dry-run-response",
        AuditEventKind::Quarantined => "quarantined",
        AuditEventKind::RolledBack => "rolled-back",
        AuditEventKind::ScopeContained => "scope-contained",
        AuditEventKind::ContainmentReminder => "containment-reminder",
        AuditEventKind::BreakGlassReleased => "break-glass-released",
        AuditEventKind::PolicyPromoted => "policy-promoted",
        AuditEventKind::AgentStopped => "agent-stopped",
        AuditEventKind::MonitoringFailed => "monitoring-failed",
    }
}

fn kind_label(kind: DifferenceKind) -> &'static str {
    match kind {
        DifferenceKind::Added => "ADDED",
        DifferenceKind::Removed => "REMOVED",
        DifferenceKind::Modified => "MODIFIED",
    }
}

fn read_bounded_regular(path: &Path, limit: u64) -> TuiResult<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(format!("input is not a bounded regular file: {}", path.display()).into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    std::fs::File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > limit {
        return Err("input changed beyond its size limit".into());
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviewStatus {
    Text,
    Missing,
    Binary,
    TooLarge,
    NotFile,
}

struct ContentPreview {
    text: Option<String>,
    status: PreviewStatus,
}

fn inspect_difference(
    config_path: &Path,
    scope_id: &str,
    relative_path: &str,
) -> TuiResult<String> {
    let config_text = String::from_utf8(read_bounded_regular(config_path, MAX_CONFIG_BYTES)?)?;
    let config = AgentConfig::from_toml(&config_text)?;
    let scope = config
        .scopes
        .iter()
        .find(|scope| scope.id == scope_id)
        .ok_or("comparison scope is not configured")?;
    let normalized = NormalizedPath::new(relative_path.to_owned())?;
    let absolute_path = scope.root.join(normalized.as_str());
    let public_key = MlDsa65PublicKey::from_bytes(&read_bounded_regular(
        &config.state_dir.join("keys").join("agent.public"),
        MAX_PUBLIC_KEY_BYTES,
    )?)?;
    let snapshot_path = config
        .state_dir
        .join("snapshots")
        .join(format!("{}.snapshot.cbor", scope.id));
    let signed =
        SignedSnapshot::from_cbor(&read_bounded_regular(&snapshot_path, MAX_SNAPSHOT_BYTES)?)?;
    if signed.public_key()?.key_id() != public_key.key_id() {
        return Err("baseline signer does not match the trusted agent key".into());
    }
    let snapshot = signed.verify()?;
    if snapshot.scope_id != scope.id {
        return Err("baseline scope does not match its configured scope".into());
    }
    let baseline = snapshot
        .entries
        .iter()
        .find(|entry| entry.path == normalized)
        .cloned();
    let current = match std::fs::symlink_metadata(&absolute_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
        Ok(_) => Scanner::new(scope)?
            .incremental_scan(scope, [absolute_path.clone()])?
            .into_iter()
            .find(|entry| entry.path == normalized),
    };
    let kind = match (&baseline, &current) {
        (None, Some(_)) => DifferenceKind::Added,
        (Some(_), None) => DifferenceKind::Removed,
        (Some(expected), Some(actual)) if expected != actual => DifferenceKind::Modified,
        _ => return Err("the selected path no longer differs from the signed baseline".into()),
    };

    let baseline_preview = match baseline.as_ref() {
        Some(entry) => {
            let object = config
                .state_dir
                .join("vault")
                .join("objects")
                .join(hex::encode(entry.content_digest));
            verified_content_preview(&object, entry)?
        }
        None => ContentPreview {
            text: None,
            status: PreviewStatus::Missing,
        },
    };
    let current_preview = match current.as_ref() {
        Some(entry) => verified_content_preview(&absolute_path, entry)?,
        None => ContentPreview {
            text: None,
            status: PreviewStatus::Missing,
        },
    };

    let baseline_digest = baseline
        .as_ref()
        .map(|entry| hex::encode(entry.content_digest))
        .unwrap_or_else(|| "missing".to_owned());
    let current_digest = current
        .as_ref()
        .map(|entry| hex::encode(entry.content_digest))
        .unwrap_or_else(|| "missing".to_owned());
    let mut output = format!(
        "Absolute path: {}\nKind: {}\nBaseline digest: {}\nCurrent digest: {}\nBaseline size: {}\nCurrent size: {}\n\n",
        absolute_path.display(),
        kind_label(kind),
        baseline_digest,
        current_digest,
        baseline
            .as_ref()
            .map(|entry| entry.size.to_string())
            .unwrap_or_else(|| "missing".to_owned()),
        current
            .as_ref()
            .map(|entry| entry.size.to_string())
            .unwrap_or_else(|| "missing".to_owned()),
    );
    if comparison_is_text(kind, &baseline_preview, &current_preview) {
        let before = baseline_preview.text.as_deref().unwrap_or("");
        let after = current_preview.text.as_deref().unwrap_or("");
        if before == after {
            output.push_str("Verified contents match; this is a metadata-only difference.\n");
        } else {
            let diff = TextDiff::from_lines(before, after)
                .unified_diff()
                .context_radius(3)
                .header("signed baseline", "current file")
                .to_string();
            output.push_str(&bounded_text(diff, MAX_RENDERED_DIFF_BYTES));
        }
    } else {
        let status = if baseline_preview.status == PreviewStatus::TooLarge
            || current_preview.status == PreviewStatus::TooLarge
        {
            "Content exceeds the 512 KiB comparison limit."
        } else if baseline_preview.status == PreviewStatus::Binary
            || current_preview.status == PreviewStatus::Binary
        {
            "Binary content is not rendered; verified digests and sizes are shown above."
        } else {
            "Content comparison is available only for bounded regular text files."
        };
        output.push_str(status);
        output.push('\n');
    }
    Ok(output)
}

fn verified_content_preview(path: &Path, entry: &IntegrityEntry) -> TuiResult<ContentPreview> {
    if entry.kind != EntryKind::File {
        return Ok(ContentPreview {
            text: None,
            status: PreviewStatus::NotFile,
        });
    }
    if entry.size > MAX_COMPARISON_BYTES {
        return Ok(ContentPreview {
            text: None,
            status: PreviewStatus::TooLarge,
        });
    }
    let bytes = read_bounded_regular(path, MAX_COMPARISON_BYTES)?;
    let mut hasher = Sha256::new();
    hasher.update(FILE_CONTENT_DOMAIN);
    hasher.update(&bytes);
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != entry.content_digest {
        return Err(format!(
            "file changed while preparing comparison: {}",
            path.display()
        )
        .into());
    }
    match String::from_utf8(bytes) {
        Ok(text) if !text.contains('\0') => Ok(ContentPreview {
            text: Some(text),
            status: PreviewStatus::Text,
        }),
        _ => Ok(ContentPreview {
            text: None,
            status: PreviewStatus::Binary,
        }),
    }
}

fn comparison_is_text(
    kind: DifferenceKind,
    baseline: &ContentPreview,
    current: &ContentPreview,
) -> bool {
    match kind {
        DifferenceKind::Added => current.status == PreviewStatus::Text,
        DifferenceKind::Removed => baseline.status == PreviewStatus::Text,
        DifferenceKind::Modified => {
            baseline.status == PreviewStatus::Text && current.status == PreviewStatus::Text
        }
    }
}

fn bounded_text(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut boundary = limit;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value.push_str("\n... diff truncated by the terminal safety limit ...\n");
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn fixture() -> App {
        let scope = ScopeView {
            id: "app".to_owned(),
            root: PathBuf::from("/srv/app"),
            status: "CHANGED".to_owned(),
            policy_mode: "dry-run".to_owned(),
            protected_system_path: false,
            contained: false,
            containment_reason: None,
            baseline_root: Some("01".repeat(32)),
            observed_root: Some("02".repeat(32)),
            baseline_created_at_unix_ms: Some(40),
            entry_count: 4,
            difference_count: 1,
            differences: vec![DifferenceView {
                relative_path: "config/app.conf".to_owned(),
                absolute_path: "/srv/app/config/app.conf".to_owned(),
                kind: DifferenceKind::Modified,
            }],
            notifications: vec![Notification {
                scope_id: "app".to_owned(),
                kind: "integrity-warning".to_owned(),
                timestamp_unix_ms: 44,
                message: "config changed".to_owned(),
                repeated: false,
            }],
            invalid_notifications: 1,
            notification_error: None,
            error: None,
        };
        let snapshot = SnapshotView {
            refreshed_at_unix_ms: 50,
            agent_key_id: "03".repeat(32),
            audit_chain_valid: true,
            audit_error: None,
            state_signature_valid: true,
            state_error: None,
            events: vec![AuditEvent::new(
                1,
                42,
                "app",
                AuditEventKind::VerificationFailed,
                Some("config/app.conf".to_owned()),
                "integrity mismatch",
                [0; 32],
            )],
            scopes: vec![scope],
            witnesses: vec![WitnessView {
                id: "witness-a".to_owned(),
                key_id: "04".repeat(32),
            }],
            witness_error: None,
        };
        let mut app = App::new(PathBuf::from("shield.toml"), Some("app".to_owned()), true);
        app.apply_refresh(Ok(snapshot));
        app
    }

    #[test]
    fn non_interactive_use_is_rejected_before_terminal_setup() {
        let error = require_interactive(false, true).unwrap_err().to_string();
        assert!(error.contains("interactive terminal"));
        assert!(require_interactive(true, true).is_ok());
    }

    #[test]
    fn every_view_renders_at_normal_and_minimum_sizes_and_after_resize() {
        let mut app = fixture();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        for view in View::ALL {
            app.view = view;
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        }

        terminal.backend_mut().resize(48, 12);
        for view in View::ALL {
            app.view = view;
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        }
        terminal.backend_mut().resize(140, 50);
        app.diff = Some(DiffOverlay {
            title: "MODIFIED: /srv/app/config/app.conf".to_owned(),
            detail: "verified diff".repeat(2_000),
            scroll: 100,
        });
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    }

    #[test]
    fn keyboard_navigation_reaches_all_views_and_bounds_selection() {
        let mut app = fixture();
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('6'), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.view, View::Notifications);
        handle_key(&mut app, KeyEvent::new(KeyCode::End, KeyModifiers::NONE)).unwrap();
        assert_eq!(app.notification_index, 0);
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.notification_index, 0);
    }

    #[test]
    fn rendered_diff_is_utf8_safe_and_bounded() {
        let value = "x".repeat(MAX_RENDERED_DIFF_BYTES) + "\u{20ac}";
        let bounded = bounded_text(value, MAX_RENDERED_DIFF_BYTES + 1);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.contains("diff truncated"));
    }

    #[test]
    fn high_volume_audit_events_remain_renderable() {
        let mut app = fixture();
        app.view = View::Events;
        app.snapshot.as_mut().unwrap().events = (0..MAX_VISIBLE_RECORDS)
            .map(|sequence| {
                AuditEvent::new(
                    sequence as u64,
                    sequence as u64,
                    "app",
                    AuditEventKind::VerificationPassed,
                    None,
                    "verified",
                    [0; 32],
                )
            })
            .collect();
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        handle_key(&mut app, KeyEvent::new(KeyCode::End, KeyModifiers::NONE)).unwrap();
        assert_eq!(app.event_index, MAX_VISIBLE_RECORDS - 1);
    }
}
