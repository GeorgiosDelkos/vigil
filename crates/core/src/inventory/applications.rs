//! Apps in `/Applications` and `~/Applications` that no Homebrew cask installed.
//!
//! Each app's `Contents/Info.plist` gives its bundle identifier and version; no command runs
//! and no app code runs. An app is looked up only when [`APP_PRODUCTS`] names its NVD product:
//! an app's name is a product name too rarely to guess from ("Grok Bot", "Rex Beta"), and a
//! bare name guessed wrong matches another vendor's software, at an NVD request each. Every
//! other app is a note, so the table grows from what is installed. An app that ships Electron
//! is also looked up as Electron at the framework's version, whether or not the table names
//! the app.
//!
//! An app a cask installed (by its file name, or for a `pkg` cask by a bundle identifier the
//! cask quits) gives only its Electron, as part of the cask: the cask itself is already in the
//! inventory. When `brew` ran and failed, which apps casks installed is not known, so no app is
//! read and each folder holding apps fails: their findings carry over instead of showing twice,
//! once under the cask and once under the app. Accepted: a failed listing of `/Applications`
//! fails only the folder, which covers apps, not casks, so the Electron findings of the casks'
//! apps in it read as resolved for that sweep.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

use crate::feeds::Product;
use crate::inventory::AppSource;
use crate::inventory::ELECTRON;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::InventorySource;
use crate::inventory::Lookup;
use crate::inventory::homebrew::CaskApps;
use crate::paths;

/// Bundle identifiers and their NVD products, sorted by identifier (byte order) for the binary
/// search. An app has several products where NVD files its CVEs under more than one name; each
/// is looked up at the app's version.
///
/// Checked 2026-11-19: each identifier appears in the Homebrew cask that installs the app (its
/// `uninstall` or `zap` stanza), except Apple's, read from the apps on the Mac this was written
/// on; each product is in NVD's CPE dictionary (`cpes/2.0` with `cpeMatchString`) and its CVEs
/// (`cves/2.0` with `virtualMatchString`) are the app's.
///
/// Left out: Vivaldi, Slack, OBS, GitHub Desktop and WhatsApp, which have no product in the
/// dictionary under any name found; Final Cut Pro and Logic Pro, likewise; Apple's other apps
/// (Xcode, GarageBand, iMovie), whose identifiers could not be read from an installed copy;
/// VMware Fusion, whose cask is gone; Microsoft Office, whose NVD entries are versioned by
/// edition (`2019`, `long_term_servicing_channel`), not by the app's `16.x`.
const APP_PRODUCTS: &[(&str, &[&str])] = &[
    // 1Password's CVEs are under its company's two names: CVE-2018-19863 under `agilebits`.
    (
        "com.1password.1password",
        &["1password:1password", "agilebits:1password"],
    ),
    // Reader's CVEs are split between the classic and the continuous (DC) track's products.
    (
        "com.adobe.Reader",
        &["adobe:acrobat_reader", "adobe:acrobat_reader_dc"],
    ),
    ("com.apple.Safari", &["apple:safari"]),
    ("com.apple.iWork.Keynote", &["apple:keynote"]),
    ("com.apple.iWork.Numbers", &["apple:numbers"]),
    ("com.apple.iWork.Pages", &["apple:pages"]),
    ("com.brave.Browser", &["brave:brave"]),
    ("com.docker.docker", &["docker:desktop"]),
    ("com.google.Chrome", &["google:chrome"]),
    ("com.googlecode.iterm2", &["iterm2:iterm2"]),
    ("com.hnc.Discord", &["discord:discord"]),
    ("com.jetbrains.CLion", &["jetbrains:clion"]),
    ("com.jetbrains.WebStorm", &["jetbrains:webstorm"]),
    ("com.jetbrains.goland", &["jetbrains:goland"]),
    ("com.jetbrains.intellij", &["jetbrains:intellij_idea"]),
    ("com.jetbrains.intellij.ce", &["jetbrains:intellij_idea"]),
    ("com.jetbrains.pycharm", &["jetbrains:pycharm"]),
    ("com.jetbrains.pycharm.ce", &["jetbrains:pycharm"]),
    ("com.microsoft.VSCode", &["microsoft:visual_studio_code"]),
    ("com.microsoft.edgemac", &["microsoft:edge_chromium"]),
    ("com.microsoft.teams2", &["microsoft:teams"]),
    ("com.operasoftware.Opera", &["opera:opera_browser"]),
    (
        "com.parallels.desktop.console",
        &["parallels:parallels_desktop"],
    ),
    ("com.philandro.anydesk", &["anydesk:anydesk"]),
    ("com.spotify.client", &["spotify:spotify"]),
    ("com.tdesktop.Telegram", &["telegram:telegram_desktop"]),
    ("com.teamviewer.TeamViewer", &["teamviewer:teamviewer"]),
    // Cursor's identifier is the one its packager, ToDesktop, assigned.
    ("com.todesktop.230313mzl4w4u92", &["anysphere:cursor"]),
    ("org.keepassxc.keepassxc", &["keepassxc:keepassxc"]),
    ("org.libreoffice.script", &["libreoffice:libreoffice"]),
    ("org.m0k.transmission", &["transmissionbt:transmission"]),
    ("org.mozilla.firefox", &["mozilla:firefox"]),
    ("org.mozilla.thunderbird", &["mozilla:thunderbird"]),
    ("org.torproject.torbrowser", &["torproject:tor_browser"]),
    ("org.videolan.vlc", &["videolan:vlc_media_player"]),
    ("org.virtualbox.app.VirtualBox", &["oracle:vm_virtualbox"]),
    (
        "org.whispersystems.signal-desktop",
        &["signal:signal-desktop"],
    ),
    ("org.wireshark.Wireshark", &["wireshark:wireshark"]),
    // Zoom's client is filed under three products as it was renamed: CVE-2020-11469 under
    // `meetings`, CVE-2024-27243 under `workplace`.
    (
        "us.zoom.xos",
        &["zoom:meetings", "zoom:workplace", "zoom:zoom"],
    ),
];

/// Where an app ships Electron, and the `Info.plist` that gives its version.
const ELECTRON_INFO: &str = "Contents/Frameworks/Electron Framework.framework/Resources/Info.plist";

/// The largest `Info.plist` read, in bytes. Arbitrary: Xcode's is under 100 kB, and the limit
/// keeps a planted file from being read whole.
const INFO_LIMIT: u64 = 1024 * 1024;

/// Adds the apps in `root`'s `Applications` and `home`'s. `casks` holds the apps installed
/// casks put in place, or is `None` when `brew` failed, which fails each folder holding apps.
pub(super) fn collect(
    inventory: &mut Inventory,
    root: &Path,
    home: Option<&Path>,
    casks: Option<&CaskApps>,
) {
    // No home folder leaves `~/Applications` out, and nothing fails: `home_dir` falls back to
    // the user database, so this does not happen on a Mac.
    let folders = [
        Some(root.join("Applications")),
        home.map(|h| h.join("Applications")),
    ];
    let mut seen = BTreeSet::new();
    let mut claimed = BTreeSet::new();
    for folder in folders.into_iter().flatten() {
        let apps = apps_in(inventory, &folder);
        // A folder with no apps fails nothing: no finding of an app can be in it.
        let Some(casks) = casks else {
            if !apps.is_empty() {
                let error = InventoryError::NoCaskList {
                    folder: folder.clone(),
                };
                inventory.fail(InventorySource::ApplicationFolder { path: folder }, error);
            }
            continue;
        };
        for app in apps {
            // Two paths to one app (a link in `~/Applications` to one in `/Applications`) are
            // one app, read at the first path.
            let real = fs::canonicalize(&app).unwrap_or_else(|_| app.clone());
            if seen.insert(real) {
                let info = read_info(&app.join("Contents/Info.plist"));
                let cask = cask_of(casks, &folder, &app, info.as_ref().ok(), &mut claimed);
                add(inventory, &app, info, cask);
            }
        }
    }
}

/// The apps directly in `folder`, links to apps included (`Safari.app` links into the system's
/// Cryptex), and those one plain folder down (`Utilities`, a vendor's folder), links there
/// not. Nothing inside an app is listed: its helpers are part of it. A `folder` that is not
/// there holds none.
fn apps_in(inventory: &mut Inventory, folder: &Path) -> Vec<PathBuf> {
    let mut apps = Vec::new();
    for entry in listed(inventory, folder) {
        if is_app(&entry) {
            apps.push(entry);
        } else if fs::symlink_metadata(&entry).is_ok_and(|m| m.is_dir()) {
            let inner = listed(inventory, &entry);
            apps.extend(inner.into_iter().filter(|app| !is_link(app) && is_app(app)));
        }
    }
    apps
}

/// The entries of `folder` that are not hidden, sorted, recording a folder that cannot be
/// listed as a failure of it. One that is not there has none.
fn listed(inventory: &mut Inventory, folder: &Path) -> Vec<PathBuf> {
    let read = || -> io::Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(folder)? {
            let entry = entry?;
            if !entry.file_name().as_encoded_bytes().starts_with(b".") {
                paths.push(entry.path());
            }
        }
        paths.sort();
        Ok(paths)
    };
    match read() {
        Ok(paths) => paths,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            let source = InventorySource::ApplicationFolder {
                path: folder.to_owned(),
            };
            inventory.fail(source, InventoryError::io(folder, e));
            Vec::new()
        }
    }
}

fn is_app(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "app") && fs::metadata(path).is_ok_and(|m| m.is_dir())
}

fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_symlink())
}

/// The token of the cask that installed the app at `app` in `folder`, whose `Info.plist` is
/// `info`. A cask puts its app directly in a folder, known by its file name, or through a
/// `pkg` installer anywhere, known by its identifier; each cask claims one app, the first
/// found. Another copy (an older one kept a folder down) is an app of its own, looked up as
/// one, so its version is not hidden behind the cask's.
fn cask_of<'c>(
    casks: &'c CaskApps,
    folder: &Path,
    app: &Path,
    info: Option<&Info>,
    claimed: &mut BTreeSet<&'c str>,
) -> Option<&'c str> {
    let in_folder = app.parent() == Some(folder);
    let name = in_folder.then(|| app.file_name()?.to_str()).flatten();
    let identifier = info.and_then(|info| info.identifier.as_deref());
    let token = casks.token(name, identifier)?;
    claimed.insert(token).then_some(token)
}

/// Adds the app at `app`, whose `Info.plist` is `info`, and the Electron it ships, or notes
/// why one is not looked up. An app `cask` installed adds only its Electron, as part of the
/// cask: the cask itself is already in the inventory.
fn add(inventory: &mut Inventory, app: &Path, info: Result<Info, String>, cask: Option<&str>) {
    // A browser's shortcut to a web app (Chrome's `~/Applications/Chrome Apps.localized`) runs
    // the browser, which is checked on its own.
    if info
        .as_ref()
        .is_ok_and(|info| info.web_app_shortcut.is_some())
    {
        return;
    }
    let found_in = match cask {
        Some(token) => FoundIn::HomebrewCask {
            token: token.to_owned(),
        },
        None => FoundIn::Application {
            source: if app.join("Contents/_MASReceipt").exists() {
                AppSource::AppStore
            } else {
                AppSource::Direct
            },
            path: app.to_owned(),
        },
    };

    match electron_version(app) {
        Ok(Some(version)) => {
            let product = ELECTRON.parse().expect("ELECTRON is a valid product");
            inventory.add(Lookup::Product(product), version, found_in.clone());
        }
        Ok(None) => {}
        Err(reason) => inventory
            .problems
            .push(InventoryError::ElectronNotLookedUp {
                app: app.to_owned(),
                reason,
            }),
    }
    if cask.is_some() {
        return;
    }

    let not_looked_up = |reason: String| InventoryError::AppNotLookedUp {
        app: app.to_owned(),
        reason,
    };
    let info = match info {
        Ok(info) => info,
        Err(reason) => {
            inventory.problems.push(not_looked_up(reason));
            return;
        }
    };
    let Some(identifier) = info.identifier else {
        let reason = "its Info.plist names no CFBundleIdentifier".to_owned();
        inventory.problems.push(not_looked_up(reason));
        return;
    };
    let Ok(i) = APP_PRODUCTS.binary_search_by_key(&identifier.as_str(), |(id, _)| id) else {
        let reason = format!("no NVD product is known for its bundle identifier {identifier}");
        inventory.problems.push(not_looked_up(reason));
        return;
    };
    let Some(version) = nonempty(info.short_version).or(nonempty(info.version)) else {
        let reason = "its Info.plist names no version".to_owned();
        inventory.problems.push(not_looked_up(reason));
        return;
    };
    for product in APP_PRODUCTS[i].1 {
        let product: Product = product.parse().expect("APP_PRODUCTS holds valid products");
        inventory.add(Lookup::Product(product), &version, found_in.clone());
    }
}

/// The version of the Electron framework the app at `app` ships: `None` when it ships none, an
/// error when its `Info.plist` cannot be read or names no version.
fn electron_version(app: &Path) -> Result<Option<String>, String> {
    let path = app.join(ELECTRON_INFO);
    // Only a file that is not there means no Electron: one that cannot be reached for another
    // reason (no permission) is noted, so its findings do not resolve unexplained.
    match fs::metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        Ok(_) => {}
    }
    match nonempty(read_info(&path)?.version) {
        Some(version) => Ok(Some(version)),
        None => Err(format!("{} names no CFBundleVersion", path.display())),
    }
}

/// `value` unless it is empty: an empty version names none, and would match no range.
fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// The keys read from an `Info.plist`.
#[derive(Debug, Deserialize)]
struct Info {
    #[serde(rename = "CFBundleIdentifier")]
    identifier: Option<String>,
    /// The version people see (`157.0.8103.79`), which NVD's ranges use.
    #[serde(rename = "CFBundleShortVersionString")]
    short_version: Option<String>,
    /// The build version, read when there is no short one; Electron's framework has only this.
    #[serde(rename = "CFBundleVersion")]
    version: Option<String>,
    /// Set only in a Chromium browser's shortcut to a web app.
    #[serde(rename = "CrAppModeShortcutID")]
    web_app_shortcut: Option<plist::Value>,
}

/// Reads the `Info.plist` at `path`, or says why it cannot be read.
fn read_info(path: &Path) -> Result<Info, String> {
    let bytes = paths::read_capped(path, INFO_LIMIT + 1)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() as u64 > INFO_LIMIT {
        return Err(format!(
            "{} is more than the {INFO_LIMIT} bytes read",
            path.display()
        ));
    }
    plist::from_bytes(&bytes).map_err(|e| format!("{} does not parse: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::fs::symlink;

    use super::*;

    /// An app at `app` whose `Info.plist` holds `keys`, as `<key>`/`<string>` pairs.
    fn app(app: &Path, keys: &[(&str, &str)]) {
        let mut body = String::new();
        for (key, value) in keys {
            write!(body, "<key>{key}</key><string>{value}</string>").unwrap();
        }
        info(&app.join("Contents/Info.plist"), &body);
    }

    fn info(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let text = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>{body}\
             </dict></plist>\n"
        );
        fs::write(path, text).unwrap();
    }

    fn chrome(path: &Path) {
        let keys = [
            ("CFBundleIdentifier", "com.google.Chrome"),
            ("CFBundleShortVersionString", "157.0.8103.79"),
            ("CFBundleVersion", "8103.79"),
        ];
        app(path, &keys);
    }

    /// Gives the app at `app` an Electron framework at `version`.
    fn electron(app: &Path, version: &str) {
        let body = format!("<key>CFBundleVersion</key><string>{version}</string>");
        info(&app.join(ELECTRON_INFO), &body);
    }

    /// Collects under `root` and `home` with `casks`.
    fn collected_with(root: &Path, home: &Path, casks: &CaskApps) -> Inventory {
        let mut inventory = Inventory::default();
        collect(&mut inventory, root, Some(home), Some(casks));
        inventory
    }

    /// Collects under `root` and `home`, with no app installed by a cask.
    fn collected(root: &Path, home: &Path) -> Inventory {
        collected_with(root, home, &CaskApps::default())
    }

    /// Each component as "place product version", the path under `tmp`.
    fn summary(inventory: &Inventory, tmp: &Path) -> Vec<String> {
        let tmp = format!("{}/", tmp.display());
        inventory
            .components
            .iter()
            .map(|c| {
                let Lookup::Product(product) = &c.lookup else {
                    panic!("not a product: {c:?}");
                };
                let place = match &c.found_in {
                    FoundIn::Application { source, .. } => format!("{} {source:?}", c.found_in),
                    other => other.to_string(),
                };
                format!("{} {product} {}", place.replace(&tmp, ""), c.version)
            })
            .collect()
    }

    fn problems(inventory: &Inventory, tmp: &Path) -> Vec<String> {
        let tmp = format!("{}/", tmp.display());
        let problems = inventory.problems.iter().map(ToString::to_string);
        problems.map(|p| p.replace(&tmp, "")).collect()
    }

    #[test]
    fn apps_are_read_in_both_folders_and_one_folder_down() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, home) = (tmp.path().join("root"), tmp.path().join("home"));
        let apps = root.join("Applications");
        chrome(&apps.join("Google Chrome.app"));
        // An app inside an app is part of it, not an app of its own.
        chrome(&apps.join("Google Chrome.app/Contents/Frameworks/Helper.app"));
        // A link at the top is followed, as Safari's into the system's Cryptex is.
        let safari = root.join("System/Cryptexes/App/System/Applications/Safari.app");
        let keys = [
            ("CFBundleIdentifier", "com.apple.Safari"),
            ("CFBundleShortVersionString", "27.2"),
        ];
        app(&safari, &keys);
        symlink(&safari, apps.join("Safari.app")).unwrap();
        // One folder down: an App Store app is read, a link there is not.
        let keynote = apps.join("iWork/Keynote.app");
        let keys = [
            ("CFBundleIdentifier", "com.apple.iWork.Keynote"),
            ("CFBundleShortVersionString", "14.2"),
        ];
        app(&keynote, &keys);
        fs::create_dir_all(keynote.join("Contents/_MASReceipt")).unwrap();
        let elsewhere = tmp.path().join("elsewhere/Google Chrome.app");
        chrome(&elsewhere);
        symlink(&elsewhere, apps.join("iWork/Google Chrome.app")).unwrap();
        // Two folders down and hidden folders are not read.
        chrome(&apps.join("Vendor/Old/Google Chrome.app"));
        chrome(&apps.join(".hidden/Google Chrome.app"));
        // A link in `~/Applications` to an app already read is the same app.
        fs::create_dir_all(home.join("Applications")).unwrap();
        symlink(
            apps.join("Google Chrome.app"),
            home.join("Applications/Chrome.app"),
        )
        .unwrap();
        chrome(&home.join("Applications/Mine/Google Chrome.app"));
        // An app the table names that ships Electron gives both.
        let code = home.join("Applications/Code.app");
        let keys = [
            ("CFBundleIdentifier", "com.microsoft.VSCode"),
            ("CFBundleShortVersionString", "1.106.2"),
        ];
        app(&code, &keys);
        electron(&code, "37.7.0");

        let inventory = collected(&root, &home);

        assert_eq!(
            summary(&inventory, tmp.path()),
            [
                "app root/Applications/Google Chrome.app Direct google:chrome 157.0.8103.79",
                "app root/Applications/Safari.app Direct apple:safari 27.2",
                "app root/Applications/iWork/Keynote.app AppStore apple:keynote 14.2",
                "app home/Applications/Code.app Direct electronjs:electron 37.7.0",
                "app home/Applications/Code.app Direct microsoft:visual_studio_code 1.106.2",
                "app home/Applications/Mine/Google Chrome.app Direct google:chrome 157.0.8103.79",
            ]
        );
        assert_eq!(problems(&inventory, tmp.path()), Vec::<String>::new());
    }

    #[test]
    fn a_casks_app_gives_only_its_electron_and_a_failed_brew_reads_none() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, home) = (tmp.path().join("root"), tmp.path().join("home"));
        chrome(&root.join("Applications/Google Chrome.app"));
        // Installed by a `pkg`, so known to its cask only by the identifier it quits.
        let bot = root.join("Applications/Bot.app");
        app(&bot, &[("CFBundleIdentifier", "com.example.bot")]);
        electron(&bot, "43.8.9");
        // Each cask claims one app: these copies are apps of their own.
        chrome(&home.join("Applications/Google Chrome.app"));
        let keys = [
            ("CFBundleIdentifier", "com.google.Chrome"),
            ("CFBundleShortVersionString", "120.0.1"),
        ];
        app(&root.join("Applications/Old/Google Chrome.app"), &keys);
        // A copy that sorts first (`Backup/` before `Docker.app`) does not take the claim.
        let keys = [
            ("CFBundleIdentifier", "com.docker.docker"),
            ("CFBundleShortVersionString", "4.0.0"),
        ];
        app(&root.join("Applications/Backup/Docker.app"), &keys);
        let keys = [
            ("CFBundleIdentifier", "com.docker.docker"),
            ("CFBundleShortVersionString", "4.82.0"),
        ];
        app(&root.join("Applications/Docker.app"), &keys);

        let mut casks = CaskApps::default();
        let docker_cask = ("Docker.app".to_owned(), "docker".to_owned());
        casks.by_name.insert(docker_cask.0, docker_cask.1);
        let chrome_cask = ("Google Chrome.app".to_owned(), "google-chrome".to_owned());
        casks.by_name.insert(chrome_cask.0, chrome_cask.1);
        let bot_cask = ("com.example.bot".to_owned(), "bot".to_owned());
        casks.by_identifier.insert(bot_cask.0, bot_cask.1);
        let inventory = collected_with(&root, &home, &casks);
        assert_eq!(
            summary(&inventory, tmp.path()),
            [
                "app root/Applications/Backup/Docker.app Direct docker:desktop 4.0.0",
                "Homebrew cask bot electronjs:electron 43.8.9",
                "app root/Applications/Old/Google Chrome.app Direct google:chrome 120.0.1",
                "app home/Applications/Google Chrome.app Direct google:chrome 157.0.8103.79",
            ]
        );
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);

        let mut inventory = Inventory::default();
        collect(&mut inventory, &root, Some(&home), None);
        assert!(
            inventory.components.is_empty(),
            "{:?}",
            inventory.components
        );
        let failed: Vec<_> = inventory.failed.iter().map(ToString::to_string).collect();
        let folders = [home.join("Applications"), root.join("Applications")];
        let expected = folders
            .iter()
            .map(|f| format!("app folder {}", f.display()));
        assert_eq!(failed, expected.collect::<Vec<_>>());
        assert!(matches!(
            inventory.problems[..],
            [
                InventoryError::NoCaskList { .. },
                InventoryError::NoCaskList { .. }
            ]
        ));

        // A folder holding no apps fails nothing.
        let empty = tmp.path().join("empty");
        let mut inventory = Inventory::default();
        collect(&mut inventory, &empty, Some(&empty), None);
        assert!(inventory.failed.is_empty(), "{:?}", inventory.failed);
    }

    #[test]
    fn what_cannot_be_looked_up_is_a_note() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, home) = (tmp.path().join("root"), tmp.path().join("home"));
        let apps = root.join("Applications");
        let keys = [
            ("CFBundleIdentifier", "com.example.bot"),
            ("CFBundleShortVersionString", "1.2.0"),
        ];
        app(&apps.join("Bot.app"), &keys);
        electron(&apps.join("Bot.app"), "43.8.9");
        // Only the build version: it is the one read.
        let keys = [
            ("CFBundleIdentifier", "com.google.Chrome"),
            ("CFBundleVersion", "157.0.1"),
        ];
        app(&apps.join("Build.app"), &keys);
        // An empty version is none.
        let keys = [
            ("CFBundleIdentifier", "com.google.Chrome"),
            ("CFBundleShortVersionString", ""),
            ("CFBundleVersion", "157.0.2"),
        ];
        app(&apps.join("Blank.app"), &keys);
        app(
            &apps.join("Unversioned.app"),
            &[("CFBundleIdentifier", "com.google.Chrome")],
        );
        app(&apps.join("Anonymous.app"), &[]);
        fs::create_dir_all(apps.join("Empty.app")).unwrap();
        // An Electron framework with no version, and one that does not parse.
        chrome(&apps.join("Odd.app"));
        info(&apps.join("Odd.app").join(ELECTRON_INFO), "");
        chrome(&apps.join("Broken.app"));
        let broken = apps.join("Broken.app").join(ELECTRON_INFO);
        fs::create_dir_all(broken.parent().unwrap()).unwrap();
        fs::write(&broken, "not a plist").unwrap();
        // A web app shortcut runs its browser, so it is not even a note.
        let keys = [
            ("CFBundleIdentifier", "com.google.Chrome.app.abc"),
            ("CrAppModeShortcutID", "abc"),
        ];
        app(
            &home.join("Applications/Chrome Apps.localized/Mail.app"),
            &keys,
        );
        // A file named like an app is not one.
        fs::write(apps.join("File.app"), "").unwrap();

        let inventory = collected(&root, &home);

        assert_eq!(
            summary(&inventory, tmp.path()),
            [
                "app root/Applications/Blank.app Direct google:chrome 157.0.2",
                "app root/Applications/Bot.app Direct electronjs:electron 43.8.9",
                "app root/Applications/Broken.app Direct google:chrome 157.0.8103.79",
                "app root/Applications/Build.app Direct google:chrome 157.0.1",
                "app root/Applications/Odd.app Direct google:chrome 157.0.8103.79",
            ]
        );
        let problems = problems(&inventory, tmp.path());
        let [anonymous, bot, broken, empty, odd, unversioned] = &problems[..] else {
            panic!("{problems:#?}");
        };
        assert_eq!(
            anonymous,
            "the app root/Applications/Anonymous.app is not looked up: its Info.plist names no \
             CFBundleIdentifier"
        );
        assert_eq!(
            bot,
            "the app root/Applications/Bot.app is not looked up: no NVD product is known for \
             its bundle identifier com.example.bot"
        );
        assert!(
            broken.starts_with("the Electron in root/Applications/Broken.app is not looked up: ")
                && broken.contains("does not parse"),
            "{broken}"
        );
        assert!(
            empty.starts_with("the app root/Applications/Empty.app is not looked up: cannot read"),
            "{empty}"
        );
        assert!(
            odd.starts_with("the Electron in root/Applications/Odd.app is not looked up: ")
                && odd.ends_with("names no CFBundleVersion"),
            "{odd}"
        );
        assert_eq!(
            unversioned,
            "the app root/Applications/Unversioned.app is not looked up: its Info.plist names \
             no version"
        );
        assert!(inventory.failed.is_empty(), "{:?}", inventory.failed);
    }

    #[test]
    fn an_electron_that_cannot_be_reached_is_a_note_not_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, home) = (tmp.path().join("root"), tmp.path().join("home"));
        let code = root.join("Applications/Code.app");
        chrome(&code);
        electron(&code, "37.7.0");
        let framework = code.join("Contents/Frameworks/Electron Framework.framework");
        fs::set_permissions(&framework, fs::Permissions::from_mode(0o000)).unwrap();

        let inventory = collected(&root, &home);
        fs::set_permissions(&framework, fs::Permissions::from_mode(0o755)).unwrap();

        let problems = problems(&inventory, tmp.path());
        let [problem] = &problems[..] else {
            panic!("{problems:#?}");
        };
        assert!(
            problem.starts_with("the Electron in root/Applications/Code.app is not looked up: ")
                && problem.contains("Permission denied"),
            "{problem}"
        );
    }

    #[test]
    fn an_info_plist_is_read_up_to_its_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let plist = |len: u64| {
            let head = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
                        <key>CFBundleVersion</key><string>1</string></dict></plist>";
            let pad = usize::try_from(len).unwrap() - head.len();
            let path = tmp.path().join(format!("{len}.plist"));
            fs::write(&path, format!("{head}{}", " ".repeat(pad))).unwrap();
            path
        };

        let info = read_info(&plist(INFO_LIMIT)).unwrap();
        assert_eq!(info.version.as_deref(), Some("1"));
        let error = read_info(&plist(INFO_LIMIT + 1)).unwrap_err();
        assert!(
            error.ends_with(&format!("is more than the {INFO_LIMIT} bytes read")),
            "{error}"
        );
    }

    #[test]
    fn a_folder_that_cannot_be_listed_fails_and_a_missing_one_holds_no_apps() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, home) = (tmp.path().join("root"), tmp.path().join("home"));
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("Applications"), "").unwrap();

        let inventory = collected(&root, &home);

        assert!(
            inventory.components.is_empty(),
            "{:?}",
            inventory.components
        );
        let failed: Vec<_> = inventory.failed.iter().map(ToString::to_string).collect();
        let folder = home.join("Applications");
        assert_eq!(failed, [format!("app folder {}", folder.display())]);
    }

    #[test]
    fn the_table_is_sorted_and_holds_valid_products() {
        // Strictly, so no identifier is listed twice and the binary search finds the one.
        assert!(APP_PRODUCTS.windows(2).all(|w| w[0].0 < w[1].0));
        for (id, products) in APP_PRODUCTS {
            for product in *products {
                assert!(product.parse::<Product>().is_ok(), "{id}: {product}");
            }
        }
        assert!(ELECTRON.parse::<Product>().is_ok());
    }
}
