//! Runs sweeps off the UI thread, one at a time, and on the configured schedule.
//!
//! [`Runner`] holds the one piece of shared state behind a single lock: the status, and when
//! the app last started a sweep. [`start`] takes it to check and claim the sweeping state in
//! one step, so two clicks, or a click and the schedule, cannot start two sweeps. The core's
//! own lock on the sweeps folder still guards against a sweep from the CLI; that one surfaces
//! as a failed sweep.
//!
//! Each sweep or fix gets its own [`Cancel`]. The user can cancel a sweep from the popover
//! ([`cancel_sweep`]); quitting ([`quit`]) cancels whatever runs and exits once it has ended,
//! or after [`QUIT_WAIT`]. However the app ends, the core's watchdog stops every program a
//! sweep started; a sweep the app did not let end leaves an unfinished folder, which the
//! schedule thread removes when the app starts ([`schedule`]).

use std::panic;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use jiff::Timestamp;
use tauri::AppHandle;
use tauri::Emitter as _;
use tauri::Manager as _;
use tauri_plugin_notification::NotificationExt as _;
use vigil_core::Cancel;
use vigil_core::Config;
use vigil_core::Confirmed;
use vigil_core::DataDir;
use vigil_core::FindingKey;
use vigil_core::FixAllItem;
use vigil_core::FixPlan;
use vigil_core::FixProgress;
use vigil_core::FixRun;
use vigil_core::LogTail;
use vigil_core::Progress;
use vigil_core::Report;
use vigil_core::SweepError;
use vigil_core::Targets;
use vigil_core::alerts;
use vigil_core::clean_up_interrupted;
use vigil_core::error_chain;
use vigil_core::last_sweep_started;
use vigil_core::plan_fix;
use vigil_core::plan_fix_all;
use vigil_core::run_fix;
use vigil_core::run_fix_all;
use vigil_core::sweep;
use vigil_core::target_label;
use vigil_core::target_names;

use crate::tray;

/// How often the schedule is checked. Arbitrary: a sweep is due every few hours, so a minute
/// late is nothing, and a Mac that wakes after a missed sweep runs it within a minute.
const SCHEDULE_CHECK: Duration = Duration::from_secs(60);

/// How long quitting waits for a cancelled sweep or fix to end. Its agent gets `SIGKILL`
/// after the core's grace period, a few seconds; this leaves room for the rest of the cleanup,
/// and quits anyway when something is slow to return (a feed request): the watchdog then stops
/// what still runs, and the next start removes the unfinished folder.
const QUIT_WAIT: Duration = Duration::from_secs(10);

/// How many alert lines a notification lists before "and N more". Arbitrary: what fits in a
/// macOS notification without being cut.
const ALERT_LINES: usize = 3;

/// The app's state: where the data is, and what the sweep is doing.
#[derive(Debug)]
pub(crate) struct Runner {
    data_dir: DataDir,
    home: PathBuf,
    shared: Mutex<Shared>,
}

#[derive(Debug)]
struct Shared {
    status: Status,
    /// When the app last started a sweep. A sweep that fails before it writes its folder (no
    /// agent configured, another sweep running) leaves no trace on disk, so the schedule
    /// counts this too, and does not retry such a sweep every minute.
    started: Option<Timestamp>,
    /// The cancel request of the sweep or fix that runs, or ran last.
    cancel: Cancel,
    /// How far quitting has got.
    quit: Quit,
}

/// How far quitting has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quit {
    /// The app is not quitting.
    No,
    /// It is waiting for the sweep or fix to end; nothing new starts, and only this wait exits.
    Waiting,
    /// It may exit now.
    Ready,
}

/// What the sweep is doing, as the popover and the tray icon show it.
#[derive(Debug, Clone)]
pub(crate) enum Status {
    /// No sweep is running, and the last one, if any, had a verdict for every target.
    Idle,
    /// A sweep is running.
    Sweeping {
        /// Its current step, one line.
        step: String,
        /// The target it is on.
        current: Option<String>,
        /// The targets it has finished, in order.
        done: Vec<String>,
        /// The targets still to come, in order.
        pending: Vec<String>,
        /// How far into the current target it is, in thousandths ([`Progress::thousandths`]).
        thousandths: usize,
        /// Whether the current step has no known length ([`Progress::open_ended`]).
        open_ended: bool,
        /// Whether the user cancelled it, and it is stopping.
        stopping: bool,
        /// When it started.
        started: Timestamp,
        /// When the current step started.
        step_started: Timestamp,
    },
    /// A confirmed fix is running.
    Fixing {
        /// What it fixes, one line.
        title: String,
        /// Its target, as `target_label` shows it: "This Mac", `owner/name`, the server.
        place: String,
        /// Its steps' labels, in order ([`FixProgress::labels`], or [`FixAllPlan::labels`] for a
        /// Fix all): preparing, the agent's step or one per item, recording.
        labels: Vec<String>,
        /// The current step.
        step: FixProgress,
        /// When it started.
        started: Timestamp,
        /// When the current step started.
        step_started: Timestamp,
    },
    /// A fix or Fix all ran, and its results show until the user closes them ([`close_fix`])
    /// or a sweep or fix starts. The owner's decision (2026-11-11): the progress view stays,
    /// each item in its final state, instead of a banner at the top.
    Fixed {
        /// What it fixed, one line, as [`Self::Fixing`] showed it.
        title: String,
        /// Its target, as [`Self::Fixing`] showed it.
        place: String,
        /// How each item ended, and the run's folder for its log.
        run: FixRun,
        /// When it finished.
        finished: Timestamp,
    },
    /// The last sweep stopped, a target in it got no verdict, or the schedule could not be
    /// checked.
    Failed {
        /// Why, one line.
        error: String,
    },
}

impl Status {
    /// Whether a sweep or a fix runs.
    pub(crate) fn is_busy(&self) -> bool {
        matches!(self, Self::Sweeping { .. } | Self::Fixing { .. })
    }
}

/// Whether an exit request must wait for [`quit`]: while it waits, and when something runs
/// that it has not been asked to stop.
fn must_wait(quit: Quit, status: &Status) -> bool {
    match quit {
        Quit::No => status.is_busy(),
        Quit::Waiting => true,
        Quit::Ready => false,
    }
}

impl Runner {
    pub(crate) fn new(data_dir: DataDir, home: PathBuf) -> Self {
        Self {
            data_dir,
            home,
            shared: Mutex::new(Shared {
                status: Status::Idle,
                started: None,
                cancel: Cancel::new(),
                quit: Quit::No,
            }),
        }
    }

    pub(crate) fn data_dir(&self) -> &DataDir {
        &self.data_dir
    }

    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn status(&self) -> Status {
        self.lock().status.clone()
    }

    /// Claims the runner for a sweep or a fix, unless one is already running or the app is
    /// quitting: one check and one write under one lock. Returns the run's cancel request.
    fn claim(&self, status: Status) -> Result<Cancel, &'static str> {
        let mut shared = self.lock();
        if shared.quit != Quit::No {
            return Err("the app is quitting");
        }
        match shared.status {
            Status::Sweeping { .. } => return Err("a sweep is running"),
            Status::Fixing { .. } => return Err("a fix is running"),
            // A new sweep or fix replaces the last fix's results.
            Status::Idle | Status::Fixed { .. } | Status::Failed { .. } => {}
        }
        if matches!(status, Status::Sweeping { .. }) {
            shared.started = Some(Timestamp::now());
        }
        shared.status = status;
        shared.cancel = Cancel::new();
        Ok(shared.cancel.clone())
    }

    fn set(&self, status: Status) {
        self.lock().status = status;
    }

    /// The state holds no invariant a panic could break halfway (each field is replaced
    /// whole), so a poisoned lock is used as it is.
    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Starts a sweep of every target on its own thread.
///
/// # Errors
///
/// Fails when a sweep or a fix started from the app is already running.
pub(crate) fn start(app: &AppHandle) -> Result<(), &'static str> {
    let runner = app.state::<Runner>();
    // Read once: the targets shown as pending are the ones the sweep takes, so its place and
    // percentage cannot disagree with an edit made while it starts.
    let config = Config::load_or_default(&runner.data_dir().config_file(), runner.home())
        .map_err(|e| e.to_string());
    let pending = config.as_ref().map(target_names).unwrap_or_default();
    let now = Timestamp::now();
    let cancel = runner.claim(Status::Sweeping {
        step: "starting".to_owned(),
        current: None,
        done: Vec::new(),
        pending,
        thousandths: 0,
        open_ended: false,
        stopping: false,
        started: now,
        step_started: now,
    })?;
    changed(app);
    let app = app.clone();
    thread::spawn(move || {
        // A panic in the sweep would otherwise leave the status at sweeping for good, and
        // every later start would be refused.
        let status = panic::catch_unwind(AssertUnwindSafe(|| run(&app, config, &cancel)))
            .unwrap_or_else(|_| Status::Failed {
                error: "the sweep stopped unexpectedly".to_owned(),
            });
        app.state::<Runner>().set(status);
        changed(&app);
    });
    Ok(())
}

/// Asks the running sweep to stop. It stops its agent and everything it started, keeps the
/// targets already swept, and removes the folder of the one it stopped in; the popover shows
/// it stopping until then.
///
/// # Errors
///
/// Fails when no sweep is running. A fix cannot be cancelled: stopped halfway, it could leave
/// a change half made.
pub(crate) fn cancel_sweep(app: &AppHandle) -> Result<(), &'static str> {
    let runner = app.state::<Runner>();
    let mut shared = runner.lock();
    let Status::Sweeping { stopping, .. } = &mut shared.status else {
        return Err("no sweep is running");
    };
    *stopping = true;
    shared.cancel.cancel();
    drop(shared);
    changed(app);
    Ok(())
}

/// Quits the app: cancels the sweep or fix that runs, and exits once it has ended, or after
/// [`QUIT_WAIT`]. The wait runs on its own thread, so the app keeps handling events (the tray,
/// the popover) meanwhile. A second request while it waits changes nothing.
pub(crate) fn quit(app: &AppHandle) {
    let runner = app.state::<Runner>();
    {
        let mut shared = runner.lock();
        if shared.quit != Quit::No {
            return;
        }
        shared.cancel.cancel();
        if !shared.status.is_busy() {
            shared.quit = Quit::Ready;
            drop(shared);
            app.exit(0);
            return;
        }
        shared.quit = Quit::Waiting;
    }
    let app = app.clone();
    thread::spawn(move || {
        let runner = app.state::<Runner>();
        let deadline = Instant::now() + QUIT_WAIT;
        // Each sweep and fix thread sets its final status once it has ended, a panic included.
        while runner.lock().status.is_busy() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        runner.lock().quit = Quit::Ready;
        app.exit(0);
    });
}

/// Whether an exit request must wait, and go through [`quit`] instead.
pub(crate) fn must_wait_to_quit(app: &AppHandle) -> bool {
    let runner = app.state::<Runner>();
    let shared = runner.lock();
    must_wait(shared.quit, &shared.status)
}

/// Runs one sweep with the config `start` read, and returns the status it leaves: idle when it
/// was cancelled.
fn run(app: &AppHandle, config: Result<Config, String>, cancel: &Cancel) -> Status {
    let runner = app.state::<Runner>();
    let swept = config.and_then(|config| {
        let mut progress = |p: Progress<'_>| {
            advance(&mut runner.lock().status, &p);
            changed(app);
        };
        match sweep(
            runner.data_dir(),
            &config,
            Targets::All,
            &mut progress,
            cancel,
        ) {
            Err(SweepError::Cancelled) => Ok(None),
            swept => swept.map(Some).map_err(|e| e.to_string()),
        }
    });
    match swept {
        Ok(None) => Status::Idle,
        Ok(Some(reports)) => {
            if let Some((title, body)) = notification(&alerts(&reports)) {
                // Best effort: a notification the user turned off is not an error to show.
                drop(app.notification().builder().title(title).body(body).show());
            }
            verdicts(&reports)
        }
        Err(error) => Status::Failed { error },
    }
}

/// Moves a running sweep's status on by one progress event: a new target finishes the one
/// before it.
fn advance(status: &mut Status, progress: &Progress<'_>) {
    let Status::Sweeping {
        step,
        current,
        done,
        pending,
        thousandths,
        open_ended,
        step_started,
        ..
    } = status
    else {
        return;
    };
    if let Progress::Target { target } = progress {
        done.extend(current.take());
        pending.retain(|t| t != target);
        *current = Some((*target).to_owned());
    }
    *step = progress.to_string();
    *thousandths = progress.thousandths();
    *open_ended = progress.open_ended();
    *step_started = Timestamp::now();
}

/// Runs the confirmed fix of `key` on its own thread; its results then show as
/// [`Status::Fixed`].
///
/// The fix is planned again and runs only when it comes from the sweep that found the one the
/// user confirmed (`found`, from the preview), so a sweep that landed since the preview is
/// refused instead of running commands the user never saw. `run_fix` checks the plan against
/// the reports once more under the sweeps lock, which catches a sweep that lands after this.
///
/// # Errors
///
/// Fails when the fix cannot be planned, changed since the preview, or a sweep or another fix
/// is running.
pub(crate) fn start_fix(app: &AppHandle, key: FindingKey, found: Timestamp) -> Result<(), String> {
    let plan = plan(app, key)?;
    if plan.found() != found {
        return Err("a newer sweep ran; open the finding again to see its fix".to_owned());
    }
    let cancel = app.state::<Runner>().claim(fixing(
        plan.fix().summary.clone(),
        target_label(plan.target()),
        FixProgress::labels(plan.agent()),
    ))?;
    changed(app);
    fix_thread(app, move |data_dir, progress| {
        let record = run_fix(data_dir, &plan, Confirmed::Asked, progress, &cancel)
            .map_err(|e| e.to_string())?;
        Ok(FixRun::single(record))
    });
    Ok(())
}

/// Runs the confirmed Fix all of `target` on its own thread, as one agent run; its results then
/// show as [`Status::Fixed`].
///
/// As for one fix, it is planned again and runs only when it is the list the user confirmed:
/// the same items, in the same order (`keys`), from the sweep that found them (`found`), both
/// from the preview. `run_fix_all` checks every item once more under the sweeps lock.
///
/// # Errors
///
/// Fails when it cannot be planned, its items changed since the preview, or a sweep or a fix
/// is running.
pub(crate) fn start_fix_all(
    app: &AppHandle,
    target: &str,
    keys: &[FindingKey],
    found: Timestamp,
) -> Result<(), String> {
    let runner = app.state::<Runner>();
    let config = Config::load_or_default(&runner.data_dir().config_file(), runner.home())
        .map_err(|e| e.to_string())?;
    let plan = plan_fix_all(runner.data_dir(), &config, target).map_err(|e| error_chain(&e))?;
    let planned: Vec<FindingKey> = plan.items().iter().map(FixAllItem::key).collect();
    if plan.found() != found || planned != keys {
        return Err(
            "a sweep, fix or dismissal changed this target's items; open Fix all again to see \
             them"
                .to_owned(),
        );
    }
    // One agent at a time (the owner's rule, 2026-11-11): claimed like any fix, so Sweep now,
    // the schedule, Fix and another Fix all are refused until it ends.
    let cancel = runner.claim(fixing(
        plan.title(),
        target_label(plan.target()),
        plan.labels(),
    ))?;
    changed(app);
    fix_thread(app, move |data_dir, progress| {
        let records = run_fix_all(data_dir, &plan, Confirmed::Asked, progress, &cancel)
            .map_err(|e| error_chain(&e))?;
        Ok(FixRun::all(&plan, records))
    });
    Ok(())
}

/// The status of a fix that has just been claimed. Claimed means started: its first step is
/// preparing, whatever the core reports.
fn fixing(title: String, place: &str, labels: Vec<String>) -> Status {
    let now = Timestamp::now();
    Status::Fixing {
        title,
        place: place.to_owned(),
        labels,
        step: FixProgress::Preparing,
        started: now,
        step_started: now,
    }
}

/// Moves a running fix's status on to step `progress`.
fn advance_fix(status: &mut Status, progress: FixProgress) {
    if let Status::Fixing {
        step, step_started, ..
    } = status
    {
        *step = progress;
        *step_started = Timestamp::now();
    }
}

/// Runs a claimed fix or Fix all on its own thread with `run`, which reports its progress and
/// returns how each item ended. Its results then show as [`Status::Fixed`]. A run that fails
/// before any item was recorded (refused under the lock, a panic) sets the status back to idle
/// and sends its reason in a `fix-error` event, which the popover shows as it shows any
/// refused command's error.
fn fix_thread<F>(app: &AppHandle, run: F)
where
    F: FnOnce(&DataDir, &mut dyn FnMut(FixProgress)) -> Result<FixRun, String> + Send + 'static,
{
    let app = app.clone();
    thread::spawn(move || {
        let done = panic::catch_unwind(AssertUnwindSafe(|| {
            let runner = app.state::<Runner>();
            let mut progress = |p: FixProgress| {
                advance_fix(&mut runner.lock().status, p);
                changed(&app);
            };
            run(runner.data_dir(), &mut progress)
        }))
        .unwrap_or_else(|_| Err("the fix stopped unexpectedly".to_owned()));
        let runner = app.state::<Runner>();
        match done {
            Ok(run) => {
                let mut shared = runner.lock();
                shared.status = finished(&shared.status, run);
            }
            Err(error) => {
                runner.set(Status::Idle);
                // Best effort, as for `changed`: no window may be listening.
                drop(app.emit("fix-error", error));
            }
        }
        changed(&app);
    });
}

/// The status a fix leaves when it ends with `run`: its results, under the title and place
/// `status`, the running fix's, showed. Only the fix's own thread changes a
/// [`Status::Fixing`], so `status` is one; anything else is left as it is.
fn finished(status: &Status, run: FixRun) -> Status {
    match status {
        Status::Fixing { title, place, .. } => Status::Fixed {
            title: title.clone(),
            place: place.clone(),
            run,
            finished: Timestamp::now(),
        },
        other => other.clone(),
    }
}

/// Closes the last fix's results, and the popover goes back to where the fix was started.
/// Does nothing unless they show, so a second click, or one that lands after a sweep started,
/// changes nothing.
pub(crate) fn close_fix(app: &AppHandle) {
    let runner = app.state::<Runner>();
    let mut shared = runner.lock();
    if matches!(shared.status, Status::Fixed { .. }) {
        shared.status = Status::Idle;
    }
    drop(shared);
    changed(app);
}

/// The end of the last fix's `agent.log`, while its results show.
///
/// # Errors
///
/// Fails when no fix's results show, or when the log is missing or cannot be read.
pub(crate) fn fix_log(app: &AppHandle) -> Result<LogTail, String> {
    // `status` clones the run out, so the file is read without the lock held.
    let Status::Fixed { run, .. } = app.state::<Runner>().status() else {
        return Err("no fix's results are showing".to_owned());
    };
    run.log_tail().map_err(|e| error_chain(&e))
}

fn plan(app: &AppHandle, key: FindingKey) -> Result<FixPlan, String> {
    let runner = app.state::<Runner>();
    let config = Config::load_or_default(&runner.data_dir().config_file(), runner.home())
        .map_err(|e| e.to_string())?;
    plan_fix(runner.data_dir(), &config, key).map_err(|e| e.to_string())
}

/// Idle when every target got a verdict, otherwise the first that did not, and why.
fn verdicts(reports: &[Report]) -> Status {
    reports
        .iter()
        .find_map(|r| {
            let failure = r.failure.as_ref()?;
            Some(Status::Failed {
                error: format!("{}: {failure}", r.target),
            })
        })
        .unwrap_or(Status::Idle)
}

/// The title and body of the notification for `alerts`, or `None` when there are none.
fn notification(alerts: &[String]) -> Option<(String, String)> {
    let title = match alerts.len() {
        0 => return None,
        1 => "1 new critical or high finding".to_owned(),
        n => format!("{n} new critical or high findings"),
    };
    let mut body = alerts[..alerts.len().min(ALERT_LINES)].join("\n");
    if alerts.len() > ALERT_LINES {
        body.push_str(&format!("\nand {} more", alerts.len() - ALERT_LINES));
    }
    Some((title, body))
}

/// Tells the popover to ask again, and updates the tray icon.
pub(crate) fn changed(app: &AppHandle) {
    // Best effort: no window may be listening yet.
    drop(app.emit("changed", ()));
    tray::refresh(app);
}

/// First removes the unfinished folders of a sweep the app did not let end, off the main
/// thread; then checks every [`SCHEDULE_CHECK`] whether a scheduled sweep is due, and starts
/// it. The config is read each time, so an edit to the schedule applies without a restart; a
/// config that cannot be read is shown by the popover, and the check waits for it to be fixed.
pub(crate) fn schedule(app: AppHandle) {
    thread::spawn(move || {
        // Best effort: an untidy folder is shown nowhere, and every sweep tries again first.
        drop(clean_up_interrupted(app.state::<Runner>().data_dir()));
        loop {
            thread::sleep(SCHEDULE_CHECK);
            let runner = app.state::<Runner>();
            let Ok(config) =
                Config::load_or_default(&runner.data_dir().config_file(), runner.home())
            else {
                continue;
            };
            let on_disk = match last_sweep_started(runner.data_dir()) {
                Ok(on_disk) => on_disk,
                Err(e) => {
                    // Under one lock, so a running sweep's status is never overwritten. The
                    // failure shows until the next sweep sets the status again.
                    let mut shared = runner.lock();
                    // Not over a sweep or fix that runs, nor over a fix's results, which the
                    // user closes; the check runs again every minute.
                    if matches!(shared.status, Status::Idle | Status::Failed { .. }) {
                        shared.status = Status::Failed {
                            error: format!("cannot check the schedule: {e}"),
                        };
                    }
                    drop(shared);
                    changed(&app);
                    continue;
                }
            };
            let last = on_disk.max(runner.lock().started);
            if config.schedule.due(last, Timestamp::now()) {
                // Refused only when a sweep or fix from the popover is running; this check is
                // then skipped.
                start(&app).ok();
            }
        }
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use vigil_core::AgentKind;

    #[test]
    fn a_new_target_finishes_the_one_before_it() {
        let mut status = Status::Sweeping {
            step: "starting".to_owned(),
            current: None,
            done: Vec::new(),
            pending: vec!["mac".to_owned(), "server:web".to_owned()],
            thousandths: 0,
            open_ended: false,
            stopping: false,
            started: Timestamp::UNIX_EPOCH,
            step_started: Timestamp::UNIX_EPOCH,
        };
        advance(&mut status, &Progress::Target { target: "mac" });
        advance(&mut status, &Progress::Inventory);
        let Status::Sweeping {
            thousandths,
            open_ended,
            step_started,
            ..
        } = &status
        else {
            panic!("still sweeping");
        };
        assert_eq!((*thousandths, *open_ended), (20, false));
        assert!(
            *step_started > Timestamp::UNIX_EPOCH,
            "each step restarts the clock"
        );
        advance(
            &mut status,
            &Progress::Agent {
                agent: vigil_core::AgentKind::Grok,
                attempt: 1,
                advisories: 3,
            },
        );
        assert!(matches!(
            status,
            Status::Sweeping {
                thousandths: 500,
                open_ended: true,
                ..
            }
        ));
        advance(
            &mut status,
            &Progress::Target {
                target: "server:web",
            },
        );
        let Status::Sweeping {
            step,
            current,
            done,
            pending,
            thousandths,
            open_ended,
            ..
        } = status
        else {
            panic!("still sweeping");
        };
        assert_eq!(step, "sweeping server:web");
        assert_eq!(
            (thousandths, open_ended),
            (0, false),
            "a new target starts at its beginning"
        );
        assert_eq!(current.as_deref(), Some("server:web"));
        assert_eq!(done, ["mac"]);
        assert_eq!(pending, Vec::<String>::new());

        let mut idle = Status::Idle;
        advance(&mut idle, &Progress::Inventory);
        assert!(
            matches!(idle, Status::Idle),
            "only a running sweep advances"
        );
    }

    /// A fix in its first moments.
    fn fixing() -> Status {
        Status::Fixing {
            title: "t".to_owned(),
            place: "This Mac".to_owned(),
            labels: FixProgress::labels(AgentKind::Grok),
            step: FixProgress::Preparing,
            started: Timestamp::UNIX_EPOCH,
            step_started: Timestamp::UNIX_EPOCH,
        }
    }

    #[test]
    fn a_fix_moves_through_its_steps() {
        let mut status = fixing();
        let dir = PathBuf::from("/fixes/x");
        advance_fix(
            &mut status,
            FixProgress::Agent {
                dir: dir.clone(),
                keys: Vec::new(),
            },
        );
        let Status::Fixing {
            step, step_started, ..
        } = &status
        else {
            panic!("still fixing");
        };
        assert!(matches!(step, FixProgress::Agent { dir: d, .. } if *d == dir));
        assert!(
            *step_started > Timestamp::UNIX_EPOCH,
            "each step restarts the clock"
        );
        advance_fix(&mut status, FixProgress::Recording);
        assert!(matches!(
            status,
            Status::Fixing {
                step: FixProgress::Recording,
                ..
            }
        ));
        let mut idle = Status::Idle;
        advance_fix(&mut idle, FixProgress::Recording);
        assert!(matches!(idle, Status::Idle), "only a running fix advances");
    }

    #[test]
    fn an_exit_waits_while_anything_runs_or_quitting_waits() {
        let busy = fixing();
        assert!(must_wait(Quit::No, &busy), "asked to quit while a fix runs");
        assert!(!must_wait(Quit::No, &Status::Idle));
        assert!(
            must_wait(Quit::Waiting, &Status::Idle),
            "a second request while it waits"
        );
        assert!(!must_wait(Quit::Ready, &busy), "the wait itself exits");
    }

    #[test]
    fn one_run_at_a_time_a_fix_all_included() {
        let runner = Runner::new(DataDir::new("/nowhere"), PathBuf::from("/nowhere"));
        let fix_all = || {
            super::fixing(
                "grok applies 2 fixes in one run".to_owned(),
                "This Mac",
                ["preparing the fixes", "curl", "ffmpeg", "recording"]
                    .map(str::to_owned)
                    .to_vec(),
            )
        };
        runner.claim(fix_all()).unwrap();
        assert_eq!(runner.claim(fix_all()).unwrap_err(), "a fix is running");
        assert_eq!(runner.claim(fixing()).unwrap_err(), "a fix is running");
        let sweep = Status::Sweeping {
            step: "starting".to_owned(),
            current: None,
            done: Vec::new(),
            pending: Vec::new(),
            thousandths: 0,
            open_ended: false,
            stopping: false,
            started: Timestamp::UNIX_EPOCH,
            step_started: Timestamp::UNIX_EPOCH,
        };
        assert_eq!(runner.claim(sweep.clone()).unwrap_err(), "a fix is running");

        runner.set(Status::Idle);
        runner.claim(sweep).unwrap();
        assert_eq!(runner.claim(fix_all()).unwrap_err(), "a sweep is running");
    }

    /// A single fix's record, ended `partial`.
    pub(crate) fn partial_run() -> FixRun {
        FixRun::single(vigil_core::FixRecord {
            key: "00000000000000c1".parse().unwrap(),
            title: "CVE-1 in sqlite 3.45".to_owned(),
            found: Timestamp::UNIX_EPOCH,
            target: "mac".to_owned(),
            agent: AgentKind::Grok,
            started: Timestamp::UNIX_EPOCH,
            finished: Timestamp::UNIX_EPOCH,
            exit_code: Some(0),
            outcome: vigil_core::Outcome::Partial,
            summary: "no newer sqlite release".to_owned(),
            pull_request: None,
            confirmed: Confirmed::Asked,
            dir: PathBuf::from("/fixes/x"),
        })
    }

    #[test]
    fn a_finished_fix_keeps_its_results_until_a_new_run_replaces_them() {
        let runner = Runner::new(DataDir::new("/nowhere"), PathBuf::from("/nowhere"));
        runner.claim(fixing()).unwrap();
        let done = finished(&runner.status(), partial_run());
        let Status::Fixed {
            title, place, run, ..
        } = &done
        else {
            panic!("a running fix ends with its results: {done:?}");
        };
        assert_eq!((title.as_str(), place.as_str()), ("t", "This Mac"));
        assert_eq!(run.summary(), "0 of 1 fixed · 1 partial");
        assert!(!done.is_busy(), "results do not hold the runner");
        assert!(
            matches!(finished(&Status::Idle, partial_run()), Status::Idle),
            "only a running fix ends"
        );

        runner.set(done);
        runner.claim(fixing()).unwrap();
        assert!(
            matches!(runner.status(), Status::Fixing { .. }),
            "a new fix replaces the results"
        );
    }

    #[test]
    fn nothing_new_starts_while_quitting() {
        let runner = Runner::new(DataDir::new("/nowhere"), PathBuf::from("/nowhere"));
        runner.lock().quit = Quit::Waiting;
        let refused = runner.claim(fixing());
        assert_eq!(refused.unwrap_err(), "the app is quitting");
    }

    #[test]
    fn a_notification_names_up_to_three_alerts() {
        assert_eq!(notification(&[]), None);
        let one = vec!["mac: CVE-1".to_owned()];
        assert_eq!(
            notification(&one),
            Some((
                "1 new critical or high finding".to_owned(),
                "mac: CVE-1".to_owned()
            ))
        );
        let five: Vec<String> = (1..=5).map(|n| format!("mac: CVE-{n}")).collect();
        let (title, body) = notification(&five).unwrap();
        assert_eq!(title, "5 new critical or high findings");
        assert_eq!(body, "mac: CVE-1\nmac: CVE-2\nmac: CVE-3\nand 2 more");
        let (_, body) = notification(&five[..3]).unwrap();
        assert!(!body.contains("more"), "{body}");
    }
}
