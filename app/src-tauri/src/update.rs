//! Updates from Vigil's GitHub Releases, through Tauri's updater plugin.
//!
//! [`schedule`] checks the endpoint in `tauri.conf.json` when the app starts and then every
//! [`CHECK_EVERY`]. A newer version is downloaded at once, in the background, and the plugin
//! checks it before handing it over: its minisign signature against the public key in
//! `tauri.conf.json`, and that the signature names the version the endpoint announced
//! (`requireSignedVersion`, so an older signed release cannot be offered as a newer one). The
//! verified package then waits in the runner's state ([`Updates`]), the popover offers Restart
//! to update, and one notification says so.
//!
//! Installing replaces the app bundle on disk, so it happens only when the user clicks, and
//! never while a sweep or fix runs ([`Runner::install_update`]): the owner's decision of
//! 2026-11-12. A failed check (offline, GitHub down, a bad signature) is kept as one line that
//! Settings shows quietly, and written to stderr. It never touches the runner's status, so it
//! never shows as a failure banner and never holds up a sweep.
//!
//! Only an installed release checks ([`enabled`]). The webview has no updater permission: the
//! check, download and install run here, and the UI calls only [`restart_to_update`].

use std::fmt;
use std::path::Path;
use std::thread;
use std::time::Duration;

use jiff::SignedDuration;
use jiff::Timestamp;
use serde::Serialize;
use tauri::AppHandle;
use tauri::Manager as _;
use tauri::async_runtime;
use tauri_plugin_notification::NotificationExt as _;
use tauri_plugin_updater::Update;
use tauri_plugin_updater::UpdaterExt as _;
use vigil_core::error_chain;

use crate::runner;
use crate::runner::Runner;

/// How often a running app checks for an update: the owner's choice (2026-11-12).
const CHECK_EVERY: SignedDuration = SignedDuration::from_hours(12);

/// How soon a failed check is tried again: a Mac that launches Vigil at login is often not
/// online yet, and waiting [`CHECK_EVERY`] after that would miss the launch check. Arbitrary:
/// often enough to catch the network coming up, rare enough to stay quiet while offline.
const RETRY_AFTER_FAILURE: SignedDuration = SignedDuration::from_hours(1);

/// How long the check, and separately the download, may take before it fails. Without it the
/// plugin and reqwest wait forever, and one stalled request (a captive portal, a silent proxy)
/// would stop every later check, since they run one after another on one thread. Arbitrary:
/// generous for a package of about 15 MB on a slow link.
const REQUEST_TIMEOUT: Duration = Duration::from_mins(5);

/// How often the check thread wakes to see whether a check is due. Due is decided on the wall
/// clock rather than by one long sleep, so time the Mac spends asleep counts toward
/// [`CHECK_EVERY`]. Arbitrary: ten minutes late is nothing for an update.
const WAKE_EVERY: Duration = Duration::from_mins(10);

/// What the app knows about updates, kept in the runner's shared state.
#[derive(Debug, Default)]
pub(crate) struct Updates {
    /// When the last check ended, whatever its outcome.
    checked: Option<Timestamp>,
    /// Why the last check or install failed, one line; `None` after a check that succeeded.
    problem: Option<String>,
    /// A downloaded, verified update waiting for the user's restart.
    ready: Option<Ready>,
}

impl Updates {
    /// Whether a check is due at `now`: no update waits already, and none has run yet, or the
    /// last ended [`CHECK_EVERY`] ago, or [`RETRY_AFTER_FAILURE`] ago when it failed.
    pub(crate) fn due(&self, now: Timestamp) -> bool {
        let wait = if self.problem.is_some() {
            RETRY_AFTER_FAILURE
        } else {
            CHECK_EVERY
        };
        self.ready.is_none()
            && self
                .checked
                .is_none_or(|last| now.duration_since(last) >= wait)
    }

    /// Records a check that ended at `at` with `found`. Returns the version it made ready, so
    /// the caller notifies once per update.
    pub(crate) fn record(
        &mut self,
        at: Timestamp,
        found: Result<Option<Ready>, String>,
    ) -> Option<String> {
        self.checked = Some(at);
        match found {
            Ok(None) => {
                self.problem = None;
                None
            }
            Ok(Some(ready)) => {
                self.problem = None;
                let version = ready.update.version.clone();
                self.ready = Some(ready);
                Some(version)
            }
            Err(problem) => {
                self.problem = Some(problem);
                None
            }
        }
    }

    /// Takes the waiting update, to install it.
    pub(crate) fn take_ready(&mut self) -> Option<Ready> {
        self.ready.take()
    }

    /// Keeps `ready` waiting again after its install failed with `problem`, so the user can
    /// retry.
    pub(crate) fn put_back(&mut self, ready: Ready, problem: String) {
        self.ready = Some(ready);
        self.problem = Some(problem);
    }
}

/// A downloaded update whose signature the plugin has checked.
pub(crate) struct Ready {
    update: Update,
    /// The `.app.tar.gz`, as downloaded and verified.
    package: Vec<u8>,
}

impl Ready {
    /// Installs the package over the running app (the plugin swaps the bundles). Blocks for
    /// seconds, or for as long as macOS's administrator prompt stays open when the app's folder
    /// needs it.
    pub(crate) fn install(&self) -> Result<(), String> {
        self.update.install(&self.package).map_err(|e| {
            format!(
                "cannot install Vigil {}: {}",
                self.update.version,
                error_chain(&e)
            )
        })
    }
}

impl fmt::Debug for Ready {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ready")
            .field("version", &self.update.version)
            .field("package_bytes", &self.package.len())
            .finish_non_exhaustive()
    }
}

/// What Settings and the popover show about updates.
#[derive(Debug, Serialize)]
pub(crate) struct UpdateView {
    /// The running version: "0.1.0".
    version: String,
    /// Whether this build checks for updates ([`enabled`]).
    checks: bool,
    /// When the last check ended.
    checked: Option<Timestamp>,
    /// Why the last check or install failed, one line.
    problem: Option<String>,
    /// The version downloaded and verified, waiting for Restart to update.
    ready: Option<String>,
}

/// What the app knows about updates now.
pub(crate) fn view(app: &AppHandle) -> UpdateView {
    let (checked, problem, ready) = app.state::<Runner>().updates(|u| {
        (
            u.checked,
            u.problem.clone(),
            u.ready.as_ref().map(|r| r.update.version.clone()),
        )
    });
    UpdateView {
        version: app.package_info().version.to_string(),
        checks: enabled(),
        checked,
        problem,
        ready,
    }
}

/// Whether this build checks for updates: only a release build running from an app bundle.
/// A debug build and `cargo tauri dev` never check, and neither does a release binary run from
/// `target/`, where the plugin would install the downloaded app over the folder the binary is
/// in (it replaces the executable's folder unless that is a bundle's `Contents/MacOS`).
fn enabled() -> bool {
    !cfg!(debug_assertions) && std::env::current_exe().is_ok_and(|exe| in_app_bundle(&exe))
}

/// Whether `exe` is an app bundle's executable: `<name>.app/Contents/MacOS/<exe>`.
fn in_app_bundle(exe: &Path) -> bool {
    let Some(macos) = exe.parent() else {
        return false;
    };
    let Some(contents) = macos.parent() else {
        return false;
    };
    macos.file_name().is_some_and(|n| n == "MacOS")
        && contents.file_name().is_some_and(|n| n == "Contents")
        && contents
            .parent()
            .and_then(Path::extension)
            .is_some_and(|ext| ext == "app")
}

/// Checks for an update when the app starts and every [`CHECK_EVERY`] after, on its own
/// thread, unless this build does not check ([`enabled`]).
pub(crate) fn schedule(app: AppHandle) {
    if !enabled() {
        return;
    }
    thread::spawn(move || {
        loop {
            if app.state::<Runner>().update_due(Timestamp::now()) {
                check(&app);
            }
            thread::sleep(WAKE_EVERY);
        }
    });
}

/// Checks once, downloading and verifying an update it finds, and records the outcome.
fn check(app: &AppHandle) {
    // The network and the download run outside the runner's lock.
    let found = async_runtime::block_on(fetch(app))
        .map_err(|e| format!("the last update check failed: {}", error_chain(&e)));
    if let Err(problem) = &found {
        log(problem);
    }
    let ready = app
        .state::<Runner>()
        .updates(|u| u.record(Timestamp::now(), found));
    if let Some(version) = ready {
        // Best effort: a notification the user turned off is not an error to show.
        drop(
            app.notification()
                .builder()
                .title(format!("Vigil {version} is ready"))
                .body("Open Vigil and click Restart to update.")
                .show(),
        );
    }
    runner::changed(app);
}

/// Asks the endpoint for a newer version, and downloads it when there is one.
async fn fetch(app: &AppHandle) -> tauri_plugin_updater::Result<Option<Ready>> {
    let updater = app.updater_builder().timeout(REQUEST_TIMEOUT).build()?;
    let Some(mut update) = updater.check().await? else {
        return Ok(None);
    };
    // tauri-plugin-updater 2.14.1 builds the returned update with `timeout: None`
    // (src/updater.rs:735), whatever the builder's timeout.
    update.timeout = Some(REQUEST_TIMEOUT);
    // `download` checks the signature, and the signed version, before it returns the bytes.
    let package = update.download(|_, _| {}, || {}).await?;
    Ok(Some(Ready { update, package }))
}

/// Installs the waiting update and restarts into it, as the user just clicked. Refused while a
/// sweep or fix runs; nothing new starts once it is accepted. An install that fails keeps the
/// update waiting, so the user can try again. Async, so installing never stalls the UI; it
/// holds one of Tauri's async workers while it runs, which is seconds, or as long as macOS's
/// administrator prompt stays open when the app's folder needs it.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn restart_to_update(app: AppHandle) -> Result<(), String> {
    if let Err(problem) = app.state::<Runner>().install_update() {
        log(&problem);
        runner::changed(&app);
        return Err(problem);
    }
    // Through the exit request, which `runner::must_wait_to_quit` now lets pass.
    app.request_restart();
    Ok(())
}

/// Writes one line to stderr, which a terminal running the app shows.
#[expect(
    clippy::print_stderr,
    reason = "the app has no logger; a failed check is otherwise only a quiet line in Settings"
)]
fn log(line: &str) {
    eprintln!("vigil: {line}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_app_bundle_s_executable_counts_as_installed() {
        assert!(in_app_bundle(Path::new(
            "/Applications/Vigil.app/Contents/MacOS/vigil-app"
        )));
        assert!(in_app_bundle(Path::new(
            "/Users/me/Downloads/Vigil.app/Contents/MacOS/vigil-app"
        )));
        for exe in [
            "/Users/me/vigil/target/release/vigil-app",
            "/x/Vigil.app/Contents/Resources/vigil-app",
            "/x/Vigil/Contents/MacOS/vigil-app",
            "/x/Vigil.app/Other/MacOS/vigil-app",
            "Contents/MacOS/vigil-app",
            "vigil-app",
            "/",
        ] {
            assert!(!in_app_bundle(Path::new(exe)), "{exe}");
        }
    }

    #[test]
    fn a_check_is_due_at_start_and_twelve_hours_after_the_last() {
        let start = Timestamp::from_second(1_000_000).unwrap();
        let mut updates = Updates::default();
        assert!(updates.due(start), "at start");
        assert_eq!(updates.record(start, Ok(None)), None);
        assert!(!updates.due(start + SignedDuration::from_hours(11)));
        assert!(updates.due(start + SignedDuration::from_hours(12)));
    }

    #[test]
    fn a_failed_check_is_kept_until_one_succeeds_and_retried_after_an_hour() {
        let start = Timestamp::from_second(1_000_000).unwrap();
        let mut updates = Updates::default();
        let ready = updates.record(start, Err("offline".to_owned()));
        assert_eq!(ready, None);
        assert_eq!(updates.problem.as_deref(), Some("offline"));
        assert!(!updates.due(start + SignedDuration::from_mins(59)));
        let later = start + SignedDuration::from_hours(1);
        assert!(updates.due(later), "offline at login is retried soon");
        updates.record(later, Ok(None));
        assert_eq!(
            (updates.checked, updates.problem.as_deref()),
            (Some(later), None)
        );
        assert!(
            !updates.due(later + SignedDuration::from_hours(11)),
            "a success waits the full twelve hours"
        );
    }
}
