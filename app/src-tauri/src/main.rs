//! Vigil's menu-bar app: a tray icon that shows whether a critical or high finding is open, a
//! popover with each target's findings and a Sweep now button, sweeps on the configured
//! schedule, and a notification for each sweep that finds something new and critical or high.
//!
//! All the work is in `vigil-core`; this crate wires it to Tauri. The popover is
//! the one window: it shows what [`overview`] returns and asks again on every `changed` event.
//! What it shows is worked out in Rust (the core's `PopoverView` and `SettingsView`); the UI
//! only lays it out. Settings are saved into `config.toml`, keeping its comments, so the file
//! stays the one source of truth that the CLI and agents also edit.

mod runner;
mod settings;
mod tray;

use std::cmp::Ordering;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

use jiff::Timestamp;
use serde::Serialize;
use tauri::ActivationPolicy;
use tauri::AppHandle;
use tauri::Manager as _;
use tauri::RunEvent;
use tauri::State;
use tauri::WindowEvent;
use tauri_plugin_autostart::MacosLauncher;
use vigil_core::AgentKind;
use vigil_core::Config;
use vigil_core::DataDir;
use vigil_core::Disk;
use vigil_core::FindingKey;
use vigil_core::ParseFindingKeyError;
use vigil_core::PopoverView;
use vigil_core::latest;
use vigil_core::plan_fix;
use vigil_core::plan_fix_all;
use vigil_core::popover_view;
use vigil_core::startup_disk;
use vigil_core::target_label;
use vigil_core::write_html_report;

use crate::runner::Runner;
use crate::runner::Status;

fn main() {
    let home = std::env::home_dir().expect("a Mac user has a home directory");
    let data_dir = DataDir::for_home(&home);
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_positioner::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Runner::new(data_dir, home))
        .manage(tray::Popover::default())
        .manage(settings::Detection::default())
        .invoke_handler(tauri::generate_handler![
            overview,
            sweep_now,
            cancel_sweep,
            open_config,
            open_report,
            quit,
            fix_preview,
            fix,
            fix_all_preview,
            fix_all,
            dismiss,
            settings::settings_data,
            settings::detect_again,
            settings::save,
            settings::add_folder,
            settings::set_nvd_key
        ])
        .setup(|app| {
            // A menu-bar app: no Dock icon and no app menu (LSUIElement).
            app.set_activation_policy(ActivationPolicy::Accessory);
            tray::create(app.handle())?;
            runner::schedule(app.handle().clone());
            settings::detect_at_start(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            match event {
                // The popover closes when it loses focus, like a menu.
                WindowEvent::Focused(false) => tray::hide_on_blur(window),
                // The menu bar changed between light and dark: switch the icon's palette. Off
                // the main thread, where clicks arrive: an idle refresh reads every report.
                WindowEvent::ThemeChanged(_) => {
                    let app = window.app_handle().clone();
                    thread::spawn(move || tray::refresh(&app));
                }
                _ => {}
            }
        })
        .build(tauri::generate_context!())
        .expect("the app's context and plugins are valid")
        .run(|app, event| {
            // An exit request while a sweep or fix runs goes through `runner::quit`, which
            // cancels it and exits once it has ended. A quit that skips this event (logout,
            // `kill`, a crash) is covered by the core's watchdog, which stops the programs.
            if let RunEvent::ExitRequested { api, .. } = event
                && runner::must_wait_to_quit(app)
            {
                api.prevent_exit();
                runner::quit(app);
            }
        });
}

/// What the popover shows.
#[derive(Debug, Serialize)]
struct Overview {
    status: StatusView,
    /// Whether a sweep or a fix is running, so another cannot start.
    busy: bool,
    /// The findings and targets; empty when the config cannot be read.
    #[serde(flatten)]
    view: PopoverView,
    /// The chosen agent's name, when one is chosen.
    agent: Option<&'static str>,
    /// "manual" or "every N hours".
    schedule: String,
    /// The config file.
    config: PathBuf,
    /// Why the config or the reports could not be read.
    problem: Option<String>,
    /// The startup disk's size and free space; `None` when diskutil cannot say, and the row
    /// is hidden.
    disk: Option<Disk>,
}

/// The status as the popover shows it: targets by their labels, and where the sweep is.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StatusView {
    Idle,
    Sweeping {
        step: String,
        current: Option<String>,
        done: Vec<String>,
        pending: Vec<String>,
        /// The target it is on, counting from 1; 0 before the first.
        position: usize,
        /// How many targets the sweep has.
        total: usize,
        /// How far the whole sweep is, from 0 to 100: each target an equal share.
        percent: usize,
        /// Where the current target's share of the bar ends, from 0 to 100.
        target_end: usize,
        /// Where the bar marks the boundaries between targets, from 0 to 100.
        ticks: Vec<f64>,
        /// Whether the current step has no known length, so the bar moves instead of filling.
        open_ended: bool,
        /// Whether the user cancelled it, and it is stopping.
        stopping: bool,
        started: Timestamp,
        step_started: Timestamp,
    },
    Fixing {
        title: String,
        place: String,
        /// Every step of the fix in order, each done, now or next.
        steps: Vec<StepView>,
        /// The agent's last line of output while it runs, one plain line.
        activity: Option<String>,
        started: Timestamp,
        step_started: Timestamp,
    },
    Failed {
        error: String,
    },
}

impl StatusView {
    fn of(status: Status) -> Self {
        let labels = |targets: Vec<String>| -> Vec<String> {
            targets.iter().map(|t| target_label(t).to_owned()).collect()
        };
        match status {
            Status::Idle => Self::Idle,
            Status::Sweeping {
                step,
                current,
                done,
                pending,
                thousandths,
                open_ended,
                stopping,
                started,
                step_started,
            } => {
                let position = done.len() + usize::from(current.is_some());
                let total = position + pending.len();
                // Thousandths of the whole sweep: the targets before this one, then this one's
                // share. `thousandths` stays under 1000, so before the first target it is 0.
                let finished = (position * 1000 + thousandths).saturating_sub(1000);
                Self::Sweeping {
                    step,
                    total,
                    position,
                    percent: finished * 100 / (total.max(1) * 1000),
                    target_end: position * 100 / total.max(1),
                    ticks: ticks(total),
                    open_ended,
                    stopping,
                    step_started,
                    current: current.map(|t| target_label(&t).to_owned()),
                    done: labels(done),
                    pending: labels(pending),
                    started,
                }
            }
            Status::Fixing {
                title,
                place,
                labels,
                step,
                started,
                step_started,
            } => Self::Fixing {
                title,
                place,
                activity: step.activity(),
                steps: {
                    let at = step.step(&labels);
                    fix_steps(labels, at)
                },
                started,
                step_started,
            },
            Status::Failed { error } => Self::Failed { error },
        }
    }
}

/// One step of a running fix, as the popover lists it.
#[derive(Debug, Serialize)]
struct StepView {
    label: String,
    state: StepState,
}

/// Where a step is, relative to the one that runs.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StepState {
    Done,
    Now,
    Next,
}

/// The steps of a fix, `labels` in order, with the one at `at` running, those before it done
/// and those after it next.
fn fix_steps(labels: Vec<String>, at: usize) -> Vec<StepView> {
    labels
        .into_iter()
        .enumerate()
        .map(|(i, label)| StepView {
            label,
            state: match i.cmp(&at) {
                Ordering::Less => StepState::Done,
                Ordering::Equal => StepState::Now,
                Ordering::Greater => StepState::Next,
            },
        })
        .collect()
}

/// The boundaries between `total` targets, as percentages of the bar, or none past
/// [`MAX_MARKED_TARGETS`] targets, where they would crowd the bar.
fn ticks(total: usize) -> Vec<f64> {
    if total > MAX_MARKED_TARGETS {
        return Vec::new();
    }
    let total = u32::try_from(total).expect("at most MAX_MARKED_TARGETS");
    (1..total)
        .map(|i| f64::from(i * 100) / f64::from(total))
        .collect()
}

/// How many targets the bar still marks apart. Arbitrary: in a 340 px bar, twelve leave
/// about 28 px between marks.
const MAX_MARKED_TARGETS: usize = 12;

// Async: Tauri runs it off the main thread, so reading every report never stalls the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn overview(runner: State<'_, Runner>) -> Overview {
    // diskutil takes about 0.3 seconds, so it runs while the reports are read, not after.
    thread::scope(|scope| {
        let disk = scope.spawn(startup_disk);
        let status = runner.status();
        let busy = status.is_busy();
        let config_path = runner.data_dir().config_file();
        let (config, problem) = match Config::load_or_default(&config_path, runner.home()) {
            Ok(config) => (Some(config), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let (targets, problem) = match (&config, problem) {
            (Some(config), None) => match latest(runner.data_dir(), config) {
                Ok(targets) => (targets, None),
                Err(e) => (Vec::new(), Some(e.to_string())),
            },
            (_, problem) => (Vec::new(), problem),
        };
        Overview {
            status: StatusView::of(status),
            busy,
            view: popover_view(targets),
            agent: config.as_ref().and_then(|c| c.agent).map(AgentKind::name),
            schedule: config.map(|c| c.schedule.to_string()).unwrap_or_default(),
            config: config_path,
            problem,
            disk: disk
                .join()
                .expect("startup_disk returns None on failure and does not panic"),
        }
    })
}

/// Async, so reading the config to list the targets never stalls the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn sweep_now(app: AppHandle) -> Result<(), String> {
    runner::start(&app).map_err(ToString::to_string)
}

/// Cancels the running sweep (see [`runner::cancel_sweep`]).
#[tauri::command]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn cancel_sweep(app: AppHandle) -> Result<(), String> {
    runner::cancel_sweep(&app).map_err(ToString::to_string)
}

/// Opens `config.toml` in the user's text editor, creating the default one first. Async, so
/// waiting for `open` never stalls the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn open_config(runner: State<'_, Runner>) -> Result<(), String> {
    let path = runner.data_dir().config_file();
    if !path.exists() {
        runner.data_dir().init().map_err(|e| e.to_string())?;
    }
    let status = Command::new("open")
        .arg("-t")
        .arg(&path)
        .status()
        .map_err(|e| format!("cannot run open: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("open -t {} failed", path.display()))
    }
}

/// Writes the HTML report of every target (`report.html` in the data directory) and opens it
/// in the default browser. Async, so reading every report and waiting for `open` never stalls
/// the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn open_report(runner: State<'_, Runner>) -> Result<(), String> {
    let config = Config::load_or_default(&runner.data_dir().config_file(), runner.home())
        .map_err(|e| e.to_string())?;
    let path = write_html_report(runner.data_dir(), &config).map_err(|e| e.to_string())?;
    let status = Command::new("/usr/bin/open")
        .arg(&path)
        .status()
        .map_err(|e| format!("cannot run open: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("open {} failed", path.display()))
    }
}

#[tauri::command]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn quit(app: AppHandle) {
    runner::quit(&app);
}

/// What the detail view shows before the user confirms a fix.
#[derive(Debug, Serialize)]
struct FixPreview {
    /// Where it runs: "this Mac", the repository, or the server and its ssh command.
    destination: String,
    /// When the sweep that found it started.
    found: Timestamp,
    summary: String,
    steps: Vec<String>,
    commands: Vec<String>,
    agent: String,
}

/// Checks the fix of `key` as the CLI's `fix` does before it asks: the finding is current and
/// not dismissed, its fix is well formed, the target is configured and the agent installed.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn fix_preview(runner: State<'_, Runner>, key: String) -> Result<FixPreview, String> {
    let key: FindingKey = key
        .parse()
        .map_err(|e: ParseFindingKeyError| e.to_string())?;
    let config = Config::load_or_default(&runner.data_dir().config_file(), runner.home())
        .map_err(|e| e.to_string())?;
    let plan = plan_fix(runner.data_dir(), &config, key).map_err(|e| e.to_string())?;
    Ok(FixPreview {
        destination: plan.destination().to_owned(),
        found: plan.found(),
        summary: plan.fix().summary.clone(),
        steps: plan.fix().steps.clone(),
        commands: plan.fix().commands.clone(),
        agent: plan.agent().to_string(),
    })
}

/// Runs the fix of `key`, which the user just confirmed in the detail view, with full access.
/// `found` is the preview's: the fix runs only when it is still the one the user saw. Async,
/// so planning it never stalls the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn fix(app: AppHandle, key: String, found: Timestamp) -> Result<(), String> {
    let key: FindingKey = key
        .parse()
        .map_err(|e: ParseFindingKeyError| e.to_string())?;
    runner::start_fix(&app, key, found)
}

/// What the target view shows before the user confirms a Fix all: every item's fix, as the
/// detail view shows one.
#[derive(Debug, Serialize)]
struct FixAllPreview {
    /// Where they run: "this Mac", or the server and its ssh command.
    destination: String,
    /// When the sweep that found them started.
    found: Timestamp,
    agent: String,
    /// The confirming button's label: "Fix all 3".
    confirm: String,
    items: Vec<FixAllPreviewItem>,
}

/// One item of a [`FixAllPreview`].
#[derive(Debug, Serialize)]
struct FixAllPreviewItem {
    /// The key of the finding whose fix it runs.
    key: String,
    /// "curl 8.1.2", or an issue's subject.
    name: String,
    summary: String,
    steps: Vec<String>,
    commands: Vec<String>,
}

/// Checks the Fix all of `target` as the CLI's `fix all` does before it asks: every item is
/// current and not dismissed, its fix well formed, the target configured and not a
/// repository, and the agent installed.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn fix_all_preview(runner: State<'_, Runner>, target: String) -> Result<FixAllPreview, String> {
    let config = Config::load_or_default(&runner.data_dir().config_file(), runner.home())
        .map_err(|e| e.to_string())?;
    let plan = plan_fix_all(runner.data_dir(), &config, &target).map_err(|e| e.to_string())?;
    Ok(FixAllPreview {
        destination: plan.destination().to_owned(),
        found: plan.found(),
        agent: plan.agent().to_string(),
        confirm: format!("Fix all {}", plan.items().len()),
        items: plan
            .items()
            .iter()
            .map(|item| FixAllPreviewItem {
                key: item.key().to_string(),
                name: item.name().to_owned(),
                summary: item.fix().summary.clone(),
                steps: item.fix().steps.clone(),
                commands: item.fix().commands.clone(),
            })
            .collect(),
    })
}

/// Runs the Fix all of `target`, which the user just confirmed, as one agent run with full
/// access. `keys` and `found` are the preview's: it runs only when its items are still the
/// ones the user saw. Async, so planning it never stalls the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn fix_all(
    app: AppHandle,
    target: String,
    keys: Vec<String>,
    found: Timestamp,
) -> Result<(), String> {
    let keys = keys
        .iter()
        .map(|key| key.parse())
        .collect::<Result<Vec<FindingKey>, ParseFindingKeyError>>()
        .map_err(|e| e.to_string())?;
    runner::start_fix_all(&app, &target, &keys, found)
}

/// Dismisses `key` for `reason`; it shows again when its advisory changes.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn dismiss(app: AppHandle, key: String, reason: String) -> Result<(), String> {
    let key: FindingKey = key
        .parse()
        .map_err(|e: ParseFindingKeyError| e.to_string())?;
    let runner = app.state::<Runner>();
    vigil_core::dismiss(runner.data_dir(), key, &reason).map_err(|e| e.to_string())?;
    runner::changed(&app);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use vigil_core::FixProgress;

    #[test]
    fn a_sweeps_status_names_targets_by_label_and_counts_where_it_is() {
        let started = Timestamp::from_second(0).unwrap();
        let sweeping = |current: Option<&str>, done: &[&str], pending: &[&str]| Status::Sweeping {
            step: "reading".to_owned(),
            current: current.map(str::to_owned),
            done: done.iter().map(|&t| t.to_owned()).collect(),
            pending: pending.iter().map(|&t| t.to_owned()).collect(),
            thousandths: 500,
            open_ended: true,
            stopping: false,
            started,
            step_started: started,
        };
        let StatusView::Sweeping {
            step,
            current,
            done,
            pending,
            position,
            total,
            percent,
            target_end,
            open_ended,
            started: at,
            ..
        } = StatusView::of(sweeping(Some("github:o/r"), &["mac"], &["server:web"]))
        else {
            panic!("still sweeping");
        };
        assert_eq!(
            (step.as_str(), current.as_deref()),
            ("reading", Some("o/r"))
        );
        assert_eq!(
            (done, pending),
            (vec!["This Mac".to_owned()], vec!["web".to_owned()])
        );
        assert_eq!((position, total, at), (2, 3, started));
        assert_eq!(
            (percent, target_end, open_ended),
            (50, 66, true),
            "one target done and half of the second: 1.5 of 3, the second ending at 2 of 3"
        );
        let StatusView::Sweeping {
            position,
            total,
            percent,
            ..
        } = StatusView::of(sweeping(None, &[], &["mac", "server:web"]))
        else {
            panic!("still sweeping");
        };
        assert_eq!(
            (position, total, percent),
            (0, 2, 0),
            "before the first target"
        );
        let StatusView::Sweeping {
            percent,
            target_end,
            ticks,
            ..
        } = StatusView::of(sweeping(Some("mac"), &[], &[]))
        else {
            panic!("still sweeping");
        };
        assert_eq!(
            (percent, target_end),
            (50, 100),
            "the agent of the only target"
        );
        assert_eq!(ticks, Vec::<f64>::new());
        assert!(matches!(StatusView::of(Status::Idle), StatusView::Idle));
    }

    #[test]
    fn a_fix_lists_its_steps_done_now_and_next() {
        use StepState::{Done, Next, Now};
        let states = |at| -> Vec<StepState> {
            fix_steps(FixProgress::labels(AgentKind::Grok), at)
                .into_iter()
                .map(|s| s.state)
                .collect()
        };
        assert_eq!(states(0), [Now, Next, Next], "claimed means preparing");
        assert_eq!(states(1), [Done, Now, Next]);
        assert_eq!(states(2), [Done, Done, Now]);
        let labels: Vec<String> = fix_steps(FixProgress::labels(AgentKind::Grok), 1)
            .into_iter()
            .map(|s| s.label)
            .collect();
        assert_eq!(
            labels,
            [
                "preparing the fix",
                "grok is applying the fix",
                "recording the result"
            ]
        );
    }

    #[test]
    fn a_fix_s_view_shows_the_agent_s_last_line_only_while_it_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("agent.log");
        std::fs::write(&log, "upgrading curl\n").unwrap();
        let at = |step: FixProgress| Status::Fixing {
            title: "t".to_owned(),
            place: "This Mac".to_owned(),
            labels: FixProgress::labels(AgentKind::Grok),
            step,
            started: Timestamp::UNIX_EPOCH,
            step_started: Timestamp::UNIX_EPOCH,
        };
        let activity = |status| match StatusView::of(status) {
            StatusView::Fixing { activity, .. } => activity,
            _ => panic!("still fixing"),
        };
        assert_eq!(
            activity(at(FixProgress::Agent {
                dir: tmp.path().to_owned(),
                keys: Vec::new(),
            }))
            .as_deref(),
            Some("upgrading curl")
        );
        assert_eq!(
            activity(at(FixProgress::Recording)),
            None,
            "not once the agent is done"
        );
    }

    #[test]
    fn a_fix_all_runs_one_item_at_a_time_as_the_agent_reports_them() {
        let tmp = tempfile::tempdir().unwrap();
        let key = "00000000000000c1";
        std::fs::write(
            tmp.path().join("results.jsonl"),
            format!("{{\"key\": \"{key}\", \"outcome\": \"fixed\", \"summary\": \"s\"}}\n"),
        )
        .unwrap();
        let status = Status::Fixing {
            title: "grok applies 2 fixes in one run".to_owned(),
            place: "This Mac".to_owned(),
            labels: [
                "preparing the fixes",
                "fixing curl 8.1",
                "fixing ffmpeg 8.1",
                "recording",
            ]
            .map(str::to_owned)
            .to_vec(),
            step: FixProgress::Agent {
                dir: tmp.path().to_owned(),
                keys: ["00000000000000c1", "00000000000000c2"]
                    .map(|k| k.parse().unwrap())
                    .to_vec(),
            },
            started: Timestamp::UNIX_EPOCH,
            step_started: Timestamp::UNIX_EPOCH,
        };
        let StatusView::Fixing { steps, .. } = StatusView::of(status) else {
            panic!("still fixing");
        };
        let states: Vec<(&str, &StepState)> =
            steps.iter().map(|s| (s.label.as_str(), &s.state)).collect();
        assert_eq!(
            states,
            [
                ("preparing the fixes", &StepState::Done),
                ("fixing curl 8.1", &StepState::Done),
                ("fixing ffmpeg 8.1", &StepState::Now),
                ("recording", &StepState::Next),
            ]
        );
    }

    #[test]
    fn the_bar_marks_target_boundaries_until_they_would_crowd_it() {
        assert_eq!(ticks(1), Vec::<f64>::new());
        assert_eq!(ticks(2), [50.0]);
        assert_eq!(ticks(4), [25.0, 50.0, 75.0]);
        assert_eq!(ticks(MAX_MARKED_TARGETS).len(), MAX_MARKED_TARGETS - 1);
        assert_eq!(ticks(MAX_MARKED_TARGETS + 1), Vec::<f64>::new());
    }
}
