//! The menu-bar icon, Vigil's mark: the main view's vortex in brief, three streaks on each of
//! three arms. The colour of its outer streaks shows whether a critical or high finding is
//! open, or a sweep or fix is running ([`Look`]), a missing arm shows a failure, a left click
//! shows or hides the popover under it, and a right click opens a menu with Quit.

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
use vigil_core::popover_view;

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

/// The icon for each state, 44 by 44 pixels: the menu bar's 22 points at 2x, and its tooltip.
///
/// The owner decided on 2026-11-11 that only critical and high findings colour the icon: red
/// for critical, orange for high, and green when neither is open, medium and low included,
/// which stay visible in the popover. A sweep or a fix keeps the cyan sweeping look, and a
/// failed sweep the monochrome mark with an arm missing. So there is no look for medium or low.
///
/// The owner clarified the same day that a failure must not hide an open critical: with a
/// critical or high finding open in the last reports, the icon stays red or orange after a
/// failed sweep, and only the tooltip and the popover's banner tell of the failure. The
/// missing arm shows only when nothing critical or high is open, which is why `Clear` carries
/// no [`LastSweep`]: a failure with nothing to show in colour is `Failed`.
#[derive(Debug, Clone, Copy)]
enum Look {
    Critical(LastSweep),
    High(LastSweep),
    Clear,
    Sweeping,
    Fixing,
    Failed,
}

/// Whether the runner's status is `Failed`: the last sweep stopped, a target in it got no
/// verdict, or the schedule could not be checked. The tooltips say "something failed", not
/// "the last sweep failed", as the failure need not be a sweep's.
#[derive(Debug, Clone, Copy)]
enum LastSweep {
    Succeeded,
    Failed,
}

impl Look {
    /// The look of an app running nothing, whose worst open item is `worst`.
    fn of(worst: Option<Severity>, last: LastSweep) -> Self {
        match (worst, last) {
            (Some(Severity::Critical), _) => Self::Critical(last),
            (Some(Severity::High), _) => Self::High(last),
            (Some(Severity::Medium | Severity::Low) | None, LastSweep::Succeeded) => Self::Clear,
            (Some(Severity::Medium | Severity::Low) | None, LastSweep::Failed) => Self::Failed,
        }
    }

    fn png(self, bar: Bar) -> &'static [u8] {
        match (self, bar) {
            (Self::Failed, _) => include_bytes!("../icons/tray-failed.png"),
            (Self::Critical(_), Bar::Dark) => include_bytes!("../icons/tray-critical.png"),
            (Self::Critical(_), Bar::Light) => include_bytes!("../icons/tray-critical-light.png"),
            (Self::High(_), Bar::Dark) => include_bytes!("../icons/tray-high.png"),
            (Self::High(_), Bar::Light) => include_bytes!("../icons/tray-high-light.png"),
            (Self::Clear, Bar::Dark) => include_bytes!("../icons/tray-clear.png"),
            (Self::Clear, Bar::Light) => include_bytes!("../icons/tray-clear-light.png"),
            (Self::Sweeping | Self::Fixing, Bar::Dark) => {
                include_bytes!("../icons/tray-sweeping.png")
            }
            (Self::Sweeping | Self::Fixing, Bar::Light) => {
                include_bytes!("../icons/tray-sweeping-light.png")
            }
        }
    }

    fn tooltip(self) -> &'static str {
        match self {
            Self::Critical(LastSweep::Succeeded) => "Vigil: critical findings open",
            Self::Critical(LastSweep::Failed) => {
                "Vigil: critical findings open; something failed, open Vigil to see it"
            }
            Self::High(LastSweep::Succeeded) => "Vigil: high findings open",
            Self::High(LastSweep::Failed) => {
                "Vigil: high findings open; something failed, open Vigil to see it"
            }
            Self::Clear => "Vigil: no critical or high findings open",
            Self::Sweeping => "Vigil: sweeping",
            Self::Fixing => "Vigil: fixing",
            Self::Failed => "Vigil: something failed; open Vigil to see it",
        }
    }

    /// Whether macOS draws the icon in the menu bar's own colour, as it does the system's.
    /// Only a failure is, told apart by its missing arm. The others keep their colours (a
    /// neutral grey inside, the state's colour outside), from the palette for the bar's
    /// appearance ([`Bar`]).
    fn template(self) -> bool {
        matches!(self, Self::Failed)
    }

    fn image(self, bar: Bar) -> Image<'static> {
        Image::from_bytes(self.png(bar)).expect("the tray icons are valid PNGs built into the app")
    }
}

/// The menu bar's appearance, which picks the coloured icons' palette: neon reads on a dark
/// bar but not on a light one, so a light bar gets deeper colours (the owner's choice,
/// 2026-11-09). The template icon needs no palette: macOS tints it.
#[derive(Debug, Clone, Copy)]
enum Bar {
    Dark,
    Light,
}

/// The menu bar's appearance, read from the popover window, which follows the system's. A
/// window that cannot be read counts as dark, the more common bar. Not detected: a menu bar
/// that a bright or dark wallpaper tints against the system appearance; the template icon
/// follows that tint and the coloured ones do not.
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

/// While a sweep or fix runs this returns at once; only an app running nothing reads the
/// config and reports, which keeps the refresh on every progress step cheap.
fn look(app: &AppHandle) -> Look {
    let runner = app.state::<Runner>();
    let last = match runner.status() {
        Status::Sweeping { .. } => return Look::Sweeping,
        Status::Fixing { .. } => return Look::Fixing,
        Status::Failed { .. } => LastSweep::Failed,
        Status::Idle => LastSweep::Succeeded,
    };
    let Ok(config) = Config::load_or_default(&runner.data_dir().config_file(), runner.home())
    else {
        return Look::Failed;
    };
    let Ok(targets) = latest(runner.data_dir(), &config) else {
        return Look::Failed;
    };
    // The popover's open items, so a fix reported done colours neither the icon nor the list.
    Look::of(popover_view(targets).worst(), last)
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
    use jiff::Timestamp;
    use vigil_core::Latest;
    use vigil_core::Open;

    use super::*;

    const LOOKS: [Look; 8] = [
        Look::Critical(LastSweep::Succeeded),
        Look::Critical(LastSweep::Failed),
        Look::High(LastSweep::Succeeded),
        Look::High(LastSweep::Failed),
        Look::Clear,
        Look::Sweeping,
        Look::Fixing,
        Look::Failed,
    ];

    #[test]
    fn only_critical_and_high_colour_the_icon() {
        let of = |worst| Look::of(worst, LastSweep::Succeeded);
        assert!(matches!(
            of(Some(Severity::Critical)),
            Look::Critical(LastSweep::Succeeded)
        ));
        assert!(matches!(
            of(Some(Severity::High)),
            Look::High(LastSweep::Succeeded)
        ));
        assert!(matches!(of(Some(Severity::Medium)), Look::Clear));
        assert!(matches!(of(Some(Severity::Low)), Look::Clear));
        assert!(matches!(of(None), Look::Clear));
        assert_eq!(
            of(Some(Severity::Critical)).tooltip(),
            "Vigil: critical findings open"
        );
        assert_eq!(
            of(Some(Severity::High)).tooltip(),
            "Vigil: high findings open"
        );
        assert_eq!(
            of(None).tooltip(),
            "Vigil: no critical or high findings open"
        );
        assert_eq!(
            Look::Failed.tooltip(),
            "Vigil: something failed; open Vigil to see it"
        );
    }

    #[test]
    fn a_failed_sweep_keeps_an_open_critical_or_high_in_colour() {
        let of = |worst| Look::of(worst, LastSweep::Failed);
        let critical = of(Some(Severity::Critical));
        assert!(matches!(critical, Look::Critical(LastSweep::Failed)));
        assert_eq!(
            critical.tooltip(),
            "Vigil: critical findings open; something failed, open Vigil to see it"
        );
        let high = of(Some(Severity::High));
        assert!(matches!(high, Look::High(LastSweep::Failed)));
        assert_eq!(
            high.tooltip(),
            "Vigil: high findings open; something failed, open Vigil to see it"
        );
        // The same coloured icon as after a sweep that succeeded; only the tooltip differs.
        for bar in [Bar::Dark, Bar::Light] {
            let succeeded = Look::of(Some(Severity::Critical), LastSweep::Succeeded);
            assert_eq!(critical.png(bar), succeeded.png(bar));
            let succeeded = Look::of(Some(Severity::High), LastSweep::Succeeded);
            assert_eq!(high.png(bar), succeeded.png(bar));
        }
        // With nothing critical or high open the failure shows as the missing arm.
        assert!(matches!(of(Some(Severity::Medium)), Look::Failed));
        assert!(matches!(of(Some(Severity::Low)), Look::Failed));
        assert!(matches!(of(None), Look::Failed));
    }

    #[test]
    fn the_worst_open_item_of_the_popover_decides() {
        let of = |open| Look::of(popover_view(swept(open)).worst(), LastSweep::Succeeded);
        assert!(matches!(
            of(vec![
                finding(1, Severity::Low),
                finding(2, Severity::Critical)
            ]),
            Look::Critical(LastSweep::Succeeded)
        ));
        assert!(matches!(
            of(vec![
                finding(1, Severity::Medium),
                finding(2, Severity::High)
            ]),
            Look::High(LastSweep::Succeeded)
        ));
        // That a reported fix is not open is the core's `PopoverView::worst`, tested there.
        assert!(matches!(of(Vec::new()), Look::Clear));
    }

    #[test]
    fn a_fix_has_its_own_tooltip_and_the_sweeping_icon() {
        assert_eq!(Look::Fixing.tooltip(), "Vigil: fixing");
        assert_eq!(Look::Sweeping.tooltip(), "Vigil: sweeping");
        for bar in [Bar::Dark, Bar::Light] {
            assert_eq!(Look::Fixing.png(bar), Look::Sweeping.png(bar));
        }
    }

    #[test]
    fn every_icon_decodes_at_the_menu_bars_size() {
        // The menu bar's 22 points at 2x.
        for look in LOOKS {
            for bar in [Bar::Dark, Bar::Light] {
                let image = look.image(bar);
                assert_eq!((image.width(), image.height()), (44, 44), "{look:?}");
            }
        }
    }

    #[test]
    fn a_light_bar_gets_its_own_coloured_icons_and_only_a_failure_is_a_template() {
        for look in LOOKS {
            let same = look.png(Bar::Dark) == look.png(Bar::Light);
            assert_eq!(same, look.template(), "{look:?}");
        }
    }

    /// One target, swept, with `open` open.
    fn swept(open: Vec<Open>) -> Vec<Latest> {
        vec![Latest {
            target: "mac".to_owned(),
            swept: Some(Timestamp::UNIX_EPOCH),
            components: 1,
            open,
            fixed: Vec::new(),
            dismissed: 0,
        }]
    }

    /// An open finding with key `key`, in no component, so each is its own item.
    fn finding(key: u64, severity: Severity) -> Open {
        Open {
            key: format!("{key:016x}")
                .parse()
                .expect("a 16-digit hex number is a finding key"),
            severity,
            title: format!("finding {key}"),
            name: format!("pkg{key}"),
            version: None,
            component: None,
            advisories: Vec::new(),
            place: String::new(),
            known_exploited: false,
            confidence: None,
            evidence: String::new(),
            explanation: String::new(),
            fix: String::new(),
            steps: Vec::new(),
            commands: Vec::new(),
            first_seen: None,
            new: false,
            fix_state: None,
        }
    }
}
