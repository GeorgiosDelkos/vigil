//! Vigil's menu-bar app: a tray icon that shows the worst open finding, a popover
//! with each target's findings and a Sweep now button, sweeps on the configured schedule, and
//! a notification for each sweep that finds something new and critical or high.
//!
//! All the work is in `vigil-core`; this crate wires it to Tauri. The popover is
//! the one window: it shows what [`overview`] returns and asks again on every `changed` event.
//! What it shows is worked out in Rust (the core's `PopoverView` and `SettingsView`); the UI
//! only lays it out. Settings are saved into `config.toml`, keeping its comments, so the file
//! stays the one source of truth that the CLI and agents also edit.

mod runner;
mod settings;
mod tray;

use std::path::PathBuf;
use std::process::Command;

use jiff::Timestamp;
use serde::Serialize;
use tauri::ActivationPolicy;
use tauri::AppHandle;
use tauri::Manager as _;
use tauri::State;
use tauri::WindowEvent;
use tauri_plugin_autostart::MacosLauncher;
use vigil_core::AgentKind;
use vigil_core::Config;
use vigil_core::DataDir;
use vigil_core::FindingKey;
use vigil_core::ParseFindingKeyError;
use vigil_core::PopoverView;
use vigil_core::latest;
use vigil_core::plan_fix;
use vigil_core::popover_view;
use vigil_core::target_label;

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
            open_config,
            quit,
            fix_preview,
            fix,
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
            // The popover closes when it loses focus, like a menu.
            if let WindowEvent::Focused(false) = event {
                tray::hide_on_blur(window);
            }
        })
        .run(tauri::generate_context!())
        .expect("the app's context and plugins are valid");
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
        /// Whether the current step has no known length, so the bar moves instead of filling.
        open_ended: bool,
        started: Timestamp,
        step_started: Timestamp,
    },
    Fixing {
        title: String,
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
                started,
                step_started,
            } => {
                let position = done.len() + usize::from(current.is_some());
                let total = position + pending.len();
                let finished = position.saturating_sub(1) * 1000 + thousandths;
                Self::Sweeping {
                    step,
                    total,
                    position,
                    percent: if position == 0 {
                        0
                    } else {
                        finished * 100 / (total * 1000)
                    },
                    target_end: position * 100 / total.max(1),
                    open_ended,
                    step_started,
                    current: current.map(|t| target_label(&t).to_owned()),
                    done: labels(done),
                    pending: labels(pending),
                    started,
                }
            }
            Status::Fixing { title } => Self::Fixing { title },
            Status::Failed { error } => Self::Failed { error },
        }
    }
}

// Async: Tauri runs it off the main thread, so reading every report never stalls the UI.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn overview(runner: State<'_, Runner>) -> Overview {
    let status = runner.status();
    let busy = matches!(status, Status::Sweeping { .. } | Status::Fixing { .. });
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
    }
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

#[tauri::command]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
fn quit(app: AppHandle) {
    app.exit(0);
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
        assert!(matches!(StatusView::of(Status::Idle), StatusView::Idle));
    }
}
