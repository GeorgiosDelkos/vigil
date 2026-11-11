//! Settings, shown inside the popover: commands that return the core's [`SettingsView`], and
//! change the config through [`save_setting`], returning the view as it now is so the UI
//! shows a change without asking again.
//!
//! Detection takes a few seconds (the login shell, `gh` twice, and the model lists of Grok and
//! opencode, each cut off after ten seconds), so it runs once, when the app starts, and again
//! only when the user asks; every view reuses it. It runs outside the lock, so a change never
//! waits for it; a view asked for before the first detection finishes runs its own. A missing
//! config reads as the default one, which the first change writes. The commands marked
//! `async` are plain blocking functions that Tauri runs off the main thread; none of them is
//! a future.

use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::thread;

use tauri::AppHandle;
use tauri::Manager as _;
use tauri_plugin_dialog::DialogExt as _;
use vigil_core::Config;
use vigil_core::Detected;
use vigil_core::NvdAccess;
use vigil_core::Setting;
use vigil_core::SettingsView;
use vigil_core::detect;
use vigil_core::error_chain;
use vigil_core::save_setting;
use vigil_core::settings_view;

use crate::runner;
use crate::runner::Runner;
use crate::tray;

/// What detection found, once it has run.
#[derive(Debug, Default)]
pub(crate) struct Detection(Mutex<Option<Detected>>);

impl Detection {
    /// Detected data is replaced whole, so a poisoned lock still holds a valid value.
    fn lock(&self) -> MutexGuard<'_, Option<Detected>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Runs detection as the app starts, in the background, so the settings open at once and
/// tools are found on the login shell's `PATH` (macOS starts an app with a minimal one). Any
/// macOS prompt it raises (Documents access, the Keychain) shows before the popover opens.
/// Off the main thread, so a slow login profile never delays the tray icon.
pub(crate) fn detect_at_start(app: AppHandle) {
    thread::spawn(move || {
        let found = detect(app.state::<Runner>().home());
        app.state::<Detection>().lock().get_or_insert(found);
    });
}

/// The settings as they are now.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn settings_data(app: AppHandle) -> Result<SettingsView, String> {
    // Detection takes seconds, so the config is read after it, as Look again does: a change
    // saved meanwhile shows.
    if app.state::<Detection>().lock().is_none() {
        detect_now(&app);
    }
    let config = read_config(&app)?;
    Ok(view(&app, &config))
}

/// Detects the Mac again, for a tool installed or a repository created since. The config is
/// read after detection, which takes seconds, so a change saved meanwhile shows.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn detect_again(app: AppHandle) -> Result<SettingsView, String> {
    detect_now(&app);
    let config = read_config(&app)?;
    Ok(view(&app, &config))
}

/// Applies one change to `config.toml`, refreshes the popover and the tray icon, and returns
/// the settings as they now are.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn save(app: AppHandle, setting: Setting) -> Result<SettingsView, String> {
    let config = apply(&app, &setting)?;
    Ok(view(&app, &config))
}

/// Lets the user pick a folder to search for lockfiles and adds it. `None` when the user
/// cancels. The popover is held open while the system's picker has the focus.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn add_folder(app: AppHandle) -> Result<Option<SettingsView>, String> {
    let picked = {
        let _held = tray::hold_popover(&app);
        app.dialog()
            .file()
            .set_title("Add a folder to search for lockfiles")
            .blocking_pick_folder()
            .and_then(|picked| picked.into_path().ok())
    };
    let Some(dir) = picked else {
        return Ok(None);
    };
    let dir = dir
        .to_str()
        .ok_or_else(|| format!("{} is not UTF-8, which config.toml needs", dir.display()))?
        .to_owned();
    let config = apply(&app, &Setting::AddFolder { dir })?;
    Ok(Some(view(&app, &config)))
}

/// Stores the NVD API key in the Keychain, and returns the settings as they now are.
#[tauri::command(async)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri hands command arguments over by value"
)]
pub(crate) fn set_nvd_key(app: AppHandle, key: String) -> Result<SettingsView, String> {
    NvdAccess::save_to_keychain(&key).map_err(|e| e.to_string())?;
    if let Some(found) = app.state::<Detection>().lock().as_mut() {
        found.nvd_key = true;
    }
    let config = read_config(&app)?;
    Ok(view(&app, &config))
}

fn read_config(app: &AppHandle) -> Result<Config, String> {
    let runner = app.state::<Runner>();
    Config::load_or_default(&runner.data_dir().config_file(), runner.home()).map_err(|e| {
        format!(
            "{} Fix config.toml by hand, or delete it to start from the default.",
            error_chain(&e)
        )
    })
}

fn apply(app: &AppHandle, setting: &Setting) -> Result<Config, String> {
    let runner = app.state::<Runner>();
    let config =
        save_setting(runner.data_dir(), runner.home(), setting).map_err(|e| error_chain(&e))?;
    runner::changed(app);
    Ok(config)
}

/// The view of `config` with what detection found, detecting first when it has not run yet.
fn view(app: &AppHandle, config: &Config) -> SettingsView {
    let runner = app.state::<Runner>();
    let home = runner.home();
    let detection = app.state::<Detection>();
    if let Some(found) = detection.lock().as_ref() {
        return settings_view(config, found, home);
    }
    detect_now(app);
    let found = detection.lock();
    let found = found.as_ref().expect("detect_now stores what it found");
    settings_view(config, found, home)
}

/// Detects the Mac, outside the lock, and keeps what it found.
fn detect_now(app: &AppHandle) {
    let found = {
        // A prompt detection raises would take the focus and hide the popover.
        let _held = tray::hold_popover(app);
        detect(app.state::<Runner>().home())
    };
    *app.state::<Detection>().lock() = Some(found);
}
