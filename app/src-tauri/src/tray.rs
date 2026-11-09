//! The menu-bar icon, Vigil's mark: the main view's vortex in brief, three streaks on each of
//! three arms. The colour of its outer streaks shows the worst open finding or a running
//! sweep, a missing arm shows a failure, a left click shows or hides the popover under it, and
//! a right click opens a menu with Quit.

use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use tauri::AppHandle;
use tauri::Emitter as _;
use tauri::Manager as _;
use tauri::Theme;
use tauri::Window;
use tauri::image::Image;
use tauri::menu::Menu;
use tauri::menu::MenuItem;
use tauri::tray::MouseButton;
use tauri::tray::MouseButtonState;
use tauri::tray::TrayIconBuilder;
use tauri::tray::TrayIconEvent;
use tauri_plugin_positioner::Position;
use tauri_plugin_positioner::WindowExt as _;
use vigil_core::Config;
use vigil_core::Severity;
use vigil_core::latest;

use crate::runner;
use crate::runner::Runner;
use crate::runner::Status;

const TRAY_ID: &str = "main";
const POPOVER: &str = "popover";

/// How soon after the popover hid on losing focus a tray click counts as the same gesture.
/// Clicking the icon while the popover is open first takes focus from it, which hides it,
/// and then delivers the click, which would show it again. Arbitrary: longer than the gap
/// between the two events, shorter than a deliberate second click.
const CLICK_AFTER_BLUR: Duration = Duration::from_millis(300);

/// When the popover last hid because it lost focus, and whether it is held open.
#[derive(Debug, Default)]
pub(crate) struct Popover {
    hidden_on_blur: Mutex<Option<Instant>>,
    /// How many holds are alive. Each covers a time a system dialog can take the focus, which
    /// would otherwise hide the popover and the view that caused it: the folder picker, and
    /// the privacy and Keychain prompts macOS shows while detection reads `~/Documents` and
    /// runs `gh`. A count, since detection and the picker can overlap.
    held: AtomicUsize,
}

/// Holds the popover open until dropped.
#[derive(Debug)]
pub(crate) struct Held<'a> {
    app: &'a AppHandle,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        // Relaxed: the count guards no other data; the next blur reads whatever is set by then.
        let left = self
            .app
            .state::<Popover>()
            .held
            .fetch_sub(1, Ordering::Relaxed);
        if left != 1 {
            return;
        }
        // A blur while held was ignored, so the last hold closes a popover that lost the focus
        // meanwhile (the user clicked elsewhere, or a prompt kept it), as that blur would have.
        // On the main thread, where blurs are handled, so this never waits on it, and with the
        // count read again there: a hold taken since keeps the popover open. Best effort: a
        // popover left open closes on the next click elsewhere or on the icon.
        let app = self.app.clone();
        drop(self.app.run_on_main_thread(move || {
            if app.state::<Popover>().held.load(Ordering::Relaxed) == 0
                && let Some(window) = app.get_webview_window(POPOVER)
                && window.is_visible().unwrap_or(false)
                && !window.is_focused().unwrap_or(true)
            {
                drop(window.hide());
            }
        }));
    }
}

/// Keeps the popover open while the result lives, as a system dialog takes the focus.
pub(crate) fn hold_popover(app: &AppHandle) -> Held<'_> {
    app.state::<Popover>().held.fetch_add(1, Ordering::Relaxed);
    Held { app }
}

impl Popover {
    /// The time is a plain value; a poisoned lock still holds a valid one.
    fn last_blur(&self) -> MutexGuard<'_, Option<Instant>> {
        self.hidden_on_blur
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Hides the popover because it lost focus, as a menu closes.
pub(crate) fn hide_on_blur(window: &Window) {
    let popover = window.state::<Popover>();
    if popover.held.load(Ordering::Relaxed) > 0 {
        return;
    }
    *popover.last_blur() = Some(Instant::now());
    // Best effort: a window that will not hide stays until the next click.
    drop(window.hide());
}

/// The icon for each state, 44 by 44 pixels: the menu bar's 22 points at 2x.
#[derive(Debug, Clone, Copy)]
enum Look {
    Clean,
    Low,
    Medium,
    High,
    Sweeping,
    Failed,
}

impl Look {
    fn png(self, bar: Bar) -> &'static [u8] {
        match (self, bar) {
            (Self::Clean, _) => include_bytes!("../icons/tray-clean.png"),
            (Self::Failed, _) => include_bytes!("../icons/tray-failed.png"),
            (Self::Low, Bar::Dark) => include_bytes!("../icons/tray-low.png"),
            (Self::Low, Bar::Light) => include_bytes!("../icons/tray-low-light.png"),
            (Self::Medium, Bar::Dark) => include_bytes!("../icons/tray-medium.png"),
            (Self::Medium, Bar::Light) => include_bytes!("../icons/tray-medium-light.png"),
            (Self::High, Bar::Dark) => include_bytes!("../icons/tray-high.png"),
            (Self::High, Bar::Light) => include_bytes!("../icons/tray-high-light.png"),
            (Self::Sweeping, Bar::Dark) => include_bytes!("../icons/tray-sweeping.png"),
            (Self::Sweeping, Bar::Light) => include_bytes!("../icons/tray-sweeping-light.png"),
        }
    }

    fn tooltip(self) -> &'static str {
        match self {
            Self::Clean => "Vigil: nothing open",
            Self::Low => "Vigil: low findings open",
            Self::Medium => "Vigil: medium findings open",
            Self::High => "Vigil: critical or high findings open",
            Self::Sweeping => "Vigil: sweeping",
            Self::Failed => "Vigil: the last sweep failed",
        }
    }

    /// Whether macOS draws the icon in the menu bar's own colour, as it does the system's.
    /// Only the looks without a colour are: nothing open, and a failure, which its missing arm
    /// tells apart. The others keep their colours (a neutral grey inside, the state's colour
    /// outside), from the palette for the bar's appearance ([`Bar`]).
    fn template(self) -> bool {
        match self {
            Self::Clean | Self::Failed => true,
            Self::Low | Self::Medium | Self::High | Self::Sweeping => false,
        }
    }

    fn image(self, bar: Bar) -> Image<'static> {
        Image::from_bytes(self.png(bar)).expect("the tray icons are valid PNGs built into the app")
    }
}

/// The menu bar's appearance, which picks the coloured icons' palette: neon reads on a dark
/// bar but not on a light one, so a light bar gets deeper colours (the owner's choice,
/// 2026-11-09). The template icons need no palette: macOS tints them.
#[derive(Debug, Clone, Copy)]
enum Bar {
    Dark,
    Light,
}

/// The menu bar's appearance, read from the popover window, which follows the system's. A
/// window that cannot be read counts as dark, the more common bar. Not detected: a menu bar
/// that a bright or dark wallpaper tints against the system appearance; the template icons
/// follow that tint and the coloured ones do not.
fn bar(app: &AppHandle) -> Bar {
    match app.get_webview_window(POPOVER).map(|window| window.theme()) {
        Some(Ok(Theme::Light)) => Bar::Light,
        _ => Bar::Dark,
    }
}

/// The id of the tray menu's Quit item.
const QUIT_ID: &str = "quit";

pub(crate) fn create(app: &AppHandle) -> tauri::Result<()> {
    let look = look(app);
    let bar = bar(app);
    let quit = MenuItem::with_id(app, QUIT_ID, "Quit Vigil", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&quit])?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(look.image(bar))
        .icon_as_template(look.template())
        .tooltip(look.tooltip())
        // Tauri opens a tray menu on a left click by default; a left click toggles the
        // popover instead, so the menu opens on a right click only.
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            // The same quit as the popover's: a running sweep or fix is stopped first.
            if event.id() == QUIT_ID {
                runner::quit(app);
            }
        })
        .on_tray_icon_event(|tray, event| {
            let app = tray.app_handle();
            tauri_plugin_positioner::on_tray_event(app, &event);
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle(app);
            }
        })
        .build(app)?;
    Ok(())
}

/// Sets the icon for the current state.
pub(crate) fn refresh(app: &AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let look = look(app);
    // Best effort: a stale icon is corrected by the next change.
    // One call for both, as tauri's `TrayIcon::set_icon_with_as_template` docs advise:
    // `set_icon` then `set_icon_as_template` redraws twice, flashing the untinted pixels.
    drop(tray.set_icon_with_as_template(Some(look.image(bar(app))), look.template()));
    drop(tray.set_tooltip(Some(look.tooltip())));
}

/// While a sweep runs this returns at once; only an idle app reads the config and reports,
/// which keeps the refresh on every progress step cheap.
fn look(app: &AppHandle) -> Look {
    let runner = app.state::<Runner>();
    match runner.status() {
        Status::Sweeping { .. } | Status::Fixing { .. } => return Look::Sweeping,
        Status::Failed { .. } => return Look::Failed,
        Status::Idle => {}
    }
    let Ok(config) = Config::load_or_default(&runner.data_dir().config_file(), runner.home())
    else {
        return Look::Failed;
    };
    let Ok(targets) = latest(runner.data_dir(), &config) else {
        return Look::Failed;
    };
    let worst = targets
        .iter()
        .flat_map(|t| &t.open)
        .map(|o| o.severity)
        .min();
    match worst {
        None => Look::Clean,
        Some(Severity::Low) => Look::Low,
        Some(Severity::Medium) => Look::Medium,
        Some(Severity::High | Severity::Critical) => Look::High,
    }
}

fn toggle(app: &AppHandle) {
    let Some(window) = app.get_webview_window(POPOVER) else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        drop(window.hide());
        return;
    }
    let just_hidden = app
        .state::<Popover>()
        .last_blur()
        .is_some_and(|at| at.elapsed() < CLICK_AFTER_BLUR);
    if just_hidden {
        return;
    }
    // Best effort: a popover that fails to move still shows.
    drop(window.move_window(Position::TrayBottomCenter));
    drop(window.show());
    drop(window.set_focus());
    // The popover asks for fresh data whenever it is shown. Only the event: refreshing the icon
    // here would read every report on the main thread, where tray clicks arrive.
    drop(app.emit("changed", ()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_light_bar_gets_its_own_coloured_icons_and_the_same_templates() {
        for look in [Look::Low, Look::Medium, Look::High, Look::Sweeping] {
            assert_ne!(look.png(Bar::Dark), look.png(Bar::Light), "{look:?}");
        }
        // Every icon decodes, at the menu bar's 22 points at 2x.
        for look in [
            Look::Clean,
            Look::Low,
            Look::Medium,
            Look::High,
            Look::Sweeping,
            Look::Failed,
        ] {
            for bar in [Bar::Dark, Bar::Light] {
                let image = look.image(bar);
                assert_eq!((image.width(), image.height()), (44, 44), "{look:?}");
            }
        }
        for look in [Look::Clean, Look::Failed] {
            assert_eq!(look.png(Bar::Dark), look.png(Bar::Light), "{look:?}");
        }
    }
}
