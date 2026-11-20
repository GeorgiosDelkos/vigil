//! Programs that can read the keyboard, as Objective-See's ReiKey finds them, written to
//! `mac/keyboard.jsonl`.
//!
//! A program reads key presses through an event tap. Two things are read:
//!
//! - the taps running programs hold now, from `CGGetEventTapList`: those that see key down or
//!   key up, as ReiKey lists them;
//! - the grants in the TCC databases that let a program hold such a tap, or send key presses,
//!   whenever it runs: Accessibility, Input Monitoring and Post Event. A keylogger that is not
//!   running at the sweep is found by its grant.
//!
//! `CGGetEventTapList` is a C function, and `unsafe` is forbidden in this workspace, so
//! `osascript`'s JavaScript bridge calls it ([`TAP_LIST`]). The same script names each
//! process by `proc_pidpath`, the file the kernel started: `ps` shows `argv[0]`, which a
//! process sets itself (`exec -a /System/Library/x` makes `ps` print that). A process whose
//! file was deleted has no path (checked on macOS 27.2: `proc_pidpath` fails once the file is
//! removed, `proc_name` does not), so it is named by `proc_name` as `(no file) <name>`: a
//! keylogger that deletes itself after starting still shows. `ps` gives only each tapping
//! process's command line, as the process tells it, which says what script an interpreter
//! runs.
//!
//! The grants are read with `sqlite3`, and each one's code requirement with `csreq`. The
//! system database needs Full Disk Access; without it the grants are a note
//! ([`InventoryError::FullDiskAccess`]), as Background Task Management's records are.
//!
//! Each program is one line, by path, with its signature, its taps and its grants. A tap on an
//! app's main executable is the app's, so an app's tap and its grant are one line. An issue
//! names it as `{"keyboard": path}` and is keyed by [`Access::identity`].
//!
//! Not read: taps that see no key presses (mouse only); grants denied or not yet answered;
//! grants in other users' databases; the grants a configuration profile allows
//! (`MDMOverrides.plist`). A tap is a moment's state: one a program opens after the sweep is
//! seen at the next. A process id reused between the tap list and `proc_pidpath` names the
//! wrong program; the window is the script's own run, accepted.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::cancel::Cancel;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::InventorySource;
use crate::inventory::command;
use crate::inventory::host::Bundled;
use crate::inventory::host::PLIST_LIMIT;
use crate::inventory::host::Signature;
use crate::inventory::host::bundle_executable;
use crate::inventory::host::checked;
use crate::inventory::host::satisfies;
use crate::paths;

const OSASCRIPT: &str = "/usr/bin/osascript";
const SQLITE: &str = "/usr/bin/sqlite3";
const CSREQ: &str = "/usr/bin/csreq";
const PS: &str = "/bin/ps";

/// The TCC database, under [`super::system_root`] for the system's grants and under the home
/// folder for this user's.
pub(super) const DATABASE: &str = "Library/Application Support/com.apple.TCC/TCC.db";

/// Lists the event taps and names each process in them, as JSON:
/// `{"records": "<hex>", "paths": {"<pid>": "<hex>"}, "names": {"<pid>": "<hex>"}}`, or
/// `{"error": <status>}` when `CGGetEventTapList` fails.
///
/// The records are the `CGEventTapInformation` array, 48 bytes each ([`RECORD_LEN`]); paths
/// and names are bytes too, which need not be UTF-8. The bridge hands back raw memory, and a
/// Latin-1 string maps each byte to one character, so everything is printed as hex. The list
/// is asked for with room for 8 more taps than were counted, and again with twice the room
/// while it fills it, so a tap opened between the count and the list is not cut off.
/// `proc_pidpath` fills at most `PROC_PIDPATHINFO_MAXSIZE` (4096) bytes and `proc_name` 2 *
/// `MAXCOMLEN` + 1 (33; `libproc.h`); a process with neither has exited.
const TAP_LIST: &str = r"
ObjC.import('CoreGraphics');
ObjC.bindFunction('CGGetEventTapList', ['int', ['unsigned int', 'void *', 'unsigned int *']]);
ObjC.bindFunction('proc_pidpath', ['int', ['int', 'void *', 'unsigned int']]);
ObjC.bindFunction('proc_name', ['int', ['int', 'void *', 'unsigned int']]);
function hex(data, length) {
  data.length = length;
  var text = $.NSString.alloc.initWithDataEncoding(data, $.NSISOLatin1StringEncoding).js;
  var out = '';
  for (var i = 0; i < text.length; i++) {
    out += ('0' + text.charCodeAt(i).toString(16)).slice(-2);
  }
  return out;
}
function run() {
  var got = Ref('unsigned int');
  var status = $.CGGetEventTapList(0, null, got);
  if (status !== 0) return JSON.stringify({error: status});
  var room = got[0] + 8;
  var data;
  for (;;) {
    data = $.NSMutableData.dataWithLength(48 * room);
    status = $.CGGetEventTapList(room, data.mutableBytes, got);
    if (status !== 0) return JSON.stringify({error: status});
    if (got[0] < room) break;
    room *= 2;
  }
  var records = hex(data, 48 * got[0]);
  var paths = {};
  var names = {};
  var pid = function (at) {
    return parseInt(records.substr(at * 2 + 6, 2) + records.substr(at * 2 + 4, 2)
      + records.substr(at * 2 + 2, 2) + records.substr(at * 2, 2), 16) | 0;
  };
  for (var at = 0; at < got[0] * 48; at += 48) {
    [pid(at + 24), pid(at + 28)].forEach(function (id) {
      if (id <= 0 || id in paths || id in names) return;
      var path = $.NSMutableData.dataWithLength(4096);
      var length = $.proc_pidpath(id, path.mutableBytes, 4096);
      if (length > 0) {
        paths[id] = hex(path, length);
        return;
      }
      var name = $.NSMutableData.dataWithLength(33);
      length = $.proc_name(id, name.mutableBytes, 33);
      if (length > 0) names[id] = hex(name, length);
    });
  }
  return JSON.stringify({records: records, paths: paths, names: names});
}
";

/// What `CGGetEventTapList` returns to a process with no connection to the window server
/// (`0x10000003`, `MACH_SEND_INVALID_DEST`): a sweep from an ssh session or a launchd daemon.
/// Checked on macOS 27.2 inside a sandbox that denies the window server.
const NO_WINDOW_SERVER: i64 = 0x1000_0003;

/// The size of one `CGEventTapInformation` on a 64-bit Mac (`CGEventTypes.h`, macOS 27.2 SDK):
/// `eventTapID`, `tapPoint` and `options` (`uint32_t` each, at 0, 4 and 8), padding,
/// `eventsOfInterest` (`uint64_t`, at 16), `tappingProcess` and `processBeingTapped`
/// (`pid_t`, at 24 and 28), `enabled` (`bool`, at 32), then three `float` latencies. Checked
/// with `_Static_assert` against the SDK for `arm64` and `x86_64`.
const RECORD_LEN: usize = 48;

/// The events of a key press in an event mask: `kCGEventKeyDown` (10) and `kCGEventKeyUp`
/// (11), bits of `CGEventMaskBit` (`CGEventTypes.h`). Modifier keys alone
/// (`kCGEventFlagsChanged`) do not count, as in ReiKey.
const KEY_EVENTS: u64 = 1 << 10 | 1 << 11;

/// A program that can read the keyboard, one line of `mac/keyboard.jsonl`.
#[derive(Debug, Serialize)]
pub(super) struct Access {
    /// The program's path, or its app's; for a grant TCC records by bundle identifier, the
    /// app's the inventory found that satisfies the grant's requirement, or
    /// `(unplaced) <identifier>` when none does; `(no file) <name>` for a running process whose
    /// file was deleted. An issue names it by this. Text, as an item's path is.
    pub(super) path: String,
    /// The bundle identifier TCC names an app by.
    #[serde(skip_serializing_if = "Option::is_none")]
    identifier: Option<String>,
    /// The program's signature; for an app, its executable's. Absent when there is no file.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    /// The keyboard taps it holds now.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    taps: Vec<Tap>,
    /// What TCC lets it do.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    grants: BTreeSet<Grant>,
}

impl Access {
    /// What keys its issue besides its path: who signed it ([`Signature::identity`]) and its
    /// grants. Its taps are left out: they exist only while the program runs, so a program
    /// with a grant would get a new key whenever a sweep finds it not running, and a dismissal
    /// would not hold. Accepted downside: a dismissed program that starts an active filter
    /// where it held a listen-only tap keeps the dismissal.
    pub(super) fn identity(&self) -> String {
        let signature = self.signature.as_ref().map(Signature::identity);
        let grants: Vec<_> = self
            .grants
            .iter()
            .map(|grant| (grant.service, grant.database, &grant.csreq))
            .collect();
        serde_json::to_string(&(signature, grants)).expect("strings and enums serialize")
    }
}

/// An event tap that sees key presses.
#[derive(Debug, Serialize)]
struct Tap {
    location: Location,
    /// Whether it only listens. Otherwise it is an active filter, which can also change or
    /// drop each key press.
    listen_only: bool,
    /// The one program whose key presses it sees; absent for every program's.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    enabled: bool,
    /// The tapping process's command line, as `ps` prints it: what the process says, which
    /// it can make up, but which shows the script an interpreter runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
}

/// Where a tap sits in the event stream (`CGEventTapLocation`).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Location {
    /// `kCGHIDEventTap`: where events enter the window server, before any session.
    Hid,
    /// `kCGSessionEventTap`: where they enter the login session.
    Session,
    /// `kCGAnnotatedSessionEventTap`: where they reach applications.
    AnnotatedSession,
    /// A value a later macOS added.
    Other,
}

impl Location {
    fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Hid,
            1 => Self::Session,
            2 => Self::AnnotatedSession,
            _ => Self::Other,
        }
    }
}

/// A grant TCC holds for a program, allowed.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Grant {
    service: Service,
    database: Database,
    /// The code requirement as TCC keeps it, compiled, as hex: what keys the grant, since it
    /// reads the same whether `csreq` decoded it on this sweep or not.
    #[serde(skip)]
    csreq: String,
    /// The code requirement TCC holds the grant to, as `csreq -t` prints it
    /// (`identifier "com.apple.screensharing.agent" and anchor apple`): only a program that
    /// satisfies it gets the grant, so it says whose the grant is. `(not decoded) <hex>` when
    /// `csreq` could not decode it. Absent when TCC keeps none.
    #[serde(skip_serializing_if = "Option::is_none")]
    requirement: Option<String>,
    /// Whether only Apple's own code satisfies the requirement ([`apple_only`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    apple_only: bool,
}

/// What a grant allows (TCC's service names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum Service {
    /// `kTCCServiceAccessibility`: control the Mac, including an active keyboard tap.
    Accessibility,
    /// `kTCCServiceListenEvent`, Input Monitoring: a listen-only keyboard tap.
    InputMonitoring,
    /// `kTCCServicePostEvent`: send key presses to other programs.
    PostEvent,
}

impl Service {
    const ALL: [(&str, Self); 3] = [
        ("kTCCServiceAccessibility", Self::Accessibility),
        ("kTCCServiceListenEvent", Self::InputMonitoring),
        ("kTCCServicePostEvent", Self::PostEvent),
    ];
}

/// Which TCC database holds a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum Database {
    /// `/Library/Application Support/com.apple.TCC/TCC.db`.
    System,
    /// This user's, under the home folder.
    User,
}

/// A program found by a tap or a grant, before its signature is read.
#[derive(Debug, Default)]
struct Found {
    /// The file to check: the program, or the app. `None` when there is none.
    file: Option<PathBuf>,
    identifier: Option<String>,
    taps: Vec<Tap>,
    grants: BTreeSet<Grant>,
}

/// Reads the keyboard taps and grants: the system's database under `root`, this user's under
/// `home`. The inventory's apps place the grants TCC records by bundle identifier. Whatever
/// cannot be read fails [`InventorySource::KeyboardAccess`].
pub(super) fn collect(
    inventory: &mut Inventory,
    root: &Path,
    home: Option<&Path>,
    cancel: &Cancel,
) -> Vec<Access> {
    let listed = tap_list(cancel);
    read(inventory, listed, root, home, cancel)
}

/// [`collect`], with the taps already listed.
fn read(
    inventory: &mut Inventory,
    listed: Result<Listed, InventoryError>,
    root: &Path,
    home: Option<&Path>,
    cancel: &Cancel,
) -> Vec<Access> {
    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    match listed.and_then(|listed| taps(&listed)) {
        Ok(taps) => file_taps(&mut found, taps, cancel),
        Err(e) => inventory.fail(InventorySource::KeyboardAccess, e),
    }
    file_grants(inventory, &mut found, root, home, cancel);
    found
        .into_iter()
        .map(|(path, found)| {
            let signature = found.file.map(|file| signature(inventory, file, cancel));
            Access {
                path,
                identifier: found.identifier,
                signature,
                taps: found.taps,
                grants: found.grants,
            }
        })
        .collect()
}

/// Files each tap in `found` under who holds it, with the process's command line.
fn file_taps(found: &mut BTreeMap<String, Found>, taps: Vec<(Holder, i32, Tap)>, cancel: &Cancel) {
    let pids: BTreeSet<i32> = taps.iter().map(|(_, pid, _)| *pid).collect();
    let commands = commands(&pids, cancel);
    for (holder, pid, mut tap) in taps {
        tap.command = commands.get(&pid).cloned();
        let (name, file) = match holder {
            Holder::File(program) => {
                let file = app_of(&program).unwrap_or(program);
                (text(&file), Some(file))
            }
            Holder::NoFile(name) => (format!("(no file) {name}"), None),
        };
        let entry = found.entry(name).or_default();
        entry.file = file;
        entry.taps.push(tap);
    }
}

/// Files the allowed keyboard grants of the system's database under `root` and this user's
/// under `home` in `found`. A cancelled sweep stops at the next grant, with one
/// [`InventoryError::Cancelled`].
fn file_grants(
    inventory: &mut Inventory,
    found: &mut BTreeMap<String, Found>,
    root: &Path,
    home: Option<&Path>,
    cancel: &Cancel,
) {
    let databases = [
        (Database::System, Some(root.join(DATABASE))),
        (Database::User, home.map(|home| home.join(DATABASE))),
    ];
    let mut apps: Option<HashMap<String, Vec<PathBuf>>> = None;
    for (database, path) in databases {
        let Some(path) = path else { continue };
        let rows = match grants(&path, cancel) {
            Ok(rows) => rows,
            Err(e) => {
                inventory.fail(InventorySource::KeyboardAccess, e);
                continue;
            }
        };
        for row in rows {
            if cancel.is_cancelled() {
                let what = "reading the keyboard grants".to_owned();
                inventory.fail(
                    InventorySource::KeyboardAccess,
                    InventoryError::Cancelled { what },
                );
                return;
            }
            let Some(service) = Service::ALL
                .iter()
                .find(|(name, _)| *name == row.service)
                .map(|(_, service)| *service)
            else {
                continue;
            };
            let requirement = match requirement(&row.csreq, cancel) {
                Ok(requirement) => requirement,
                Err(e) => {
                    inventory.fail(InventorySource::KeyboardAccess, e);
                    Some(format!("(not decoded) {}", row.csreq))
                }
            };
            // `client_type` 0: a bundle identifier; 1: an absolute path, where an app's main
            // executable is the app, as for a tap.
            let (name, file, identifier) = if row.client_type == 0 {
                let apps = apps.get_or_insert_with(|| identifiers(&inventory.apps));
                let candidates = apps.get(&row.client).map_or(&[][..], Vec::as_slice);
                match place(inventory, candidates, requirement.as_deref(), cancel) {
                    Some(app) => (text(&app), Some(app), Some(row.client)),
                    None => (format!("(unplaced) {}", row.client), None, Some(row.client)),
                }
            } else {
                let program = PathBuf::from(&row.client);
                let file = app_of(&program).unwrap_or(program);
                (text(&file), Some(file), None)
            };
            let apple_only = requirement.as_deref().is_some_and(apple_only);
            let entry = found.entry(name).or_default();
            entry.file = entry.file.take().or(file);
            entry.identifier = entry.identifier.take().or(identifier);
            entry.grants.insert(Grant {
                service,
                database,
                csreq: row.csreq,
                requirement,
                apple_only,
            });
        }
    }
}

/// The first app in `candidates` (the inventory's apps with the grant's bundle identifier)
/// that satisfies `requirement`, the one TCC gives the grant to. Without a requirement, the
/// first. A look-alike with another app's identifier then does not lend that app's signature
/// to its own grant: none satisfies it, and the grant is unplaced, with the look-alike's
/// requirement. A check that cannot run fails [`InventorySource::KeyboardAccess`].
fn place(
    inventory: &mut Inventory,
    candidates: &[PathBuf],
    requirement: Option<&str>,
    cancel: &Cancel,
) -> Option<PathBuf> {
    let Some(requirement) = requirement else {
        return candidates.first().cloned();
    };
    candidates.iter().find_map(
        |app| match satisfies(&app.to_string_lossy(), requirement, cancel) {
            Ok(true) => Some(app.clone()),
            Ok(false) => None,
            Err(e) => {
                inventory.fail(InventorySource::KeyboardAccess, e);
                None
            }
        },
    )
}

/// Whether `requirement` holds only for Apple's own code: `anchor apple`, alone or after one
/// `identifier`, the shapes Apple's own designated requirements take
/// (`identifier "com.apple.screensharing.agent" and anchor apple`). Nothing looser: a
/// developer chooses an app's designated requirement (`codesign -r`), so
/// `(anchor apple) or identifier "com.evil"` holds for an ad hoc signed `com.evil` too, and the
/// words can sit inside a quoted identifier. `anchor apple generic` is every Developer ID's.
fn apple_only(requirement: &str) -> bool {
    let identified = requirement
        .strip_prefix("identifier \"")
        .and_then(|rest| rest.strip_suffix("\" and anchor apple"))
        .is_some_and(|identifier| !identifier.contains('"'));
    requirement == "anchor apple" || identified
}

/// The app whose main executable is `program`: the `.app` it is directly in, as
/// `Contents/MacOS/<name>` its `Info.plist` names. A tool elsewhere in an app (a helper app
/// inside it is its own app) is its own program.
fn app_of(program: &Path) -> Option<PathBuf> {
    let app = program
        .ancestors()
        .find(|folder| folder.extension().is_some_and(|e| e == "app"))?;
    match bundle_executable(app) {
        Ok(Bundled::Program(executable)) if executable == program => Some(app.to_owned()),
        Ok(_) | Err(_) => None,
    }
}

/// The signature of `file`, a program or an app, whose executable is checked. A check that
/// cannot run fails [`InventorySource::KeyboardAccess`].
fn signature(inventory: &mut Inventory, file: PathBuf, cancel: &Cancel) -> Signature {
    // An app with no executable it names (or an `Info.plist` that does not read) is checked
    // as it is, which shows why.
    let app = file.extension().is_some_and(|e| e == "app");
    let program = match app.then(|| bundle_executable(&file)) {
        Some(Ok(Bundled::Program(program))) => program,
        Some(Ok(Bundled::Codeless(_)) | Err(_)) | None => file,
    };
    let mut failures = Vec::new();
    let checked = checked(program, cancel, &mut failures);
    for e in failures {
        inventory.fail(InventorySource::KeyboardAccess, e);
    }
    checked.signature
}

/// The command lines of the processes `pids`, as `ps` prints them. One that exited is left
/// out (`ps` then exits 1 and prints the others); `ps` failing to run leaves them all out, as
/// they are a hint beside the tap, not what decides it.
fn commands(pids: &BTreeSet<i32>, cancel: &Cancel) -> HashMap<i32, String> {
    if pids.is_empty() {
        return HashMap::new();
    }
    let list: Vec<String> = pids.iter().map(ToString::to_string).collect();
    let list = list.join(",");
    let Ok(output) = super::tool(PS, &["-o", "pid=", "-o", "command=", "-p", &list], cancel) else {
        return HashMap::new();
    };
    output
        .stdout
        .lines()
        .filter_map(|line| {
            let (pid, command) = line.trim_start().split_once(' ')?;
            Some((pid.parse().ok()?, command.trim_start().to_owned()))
        })
        .collect()
}

/// What [`TAP_LIST`] prints.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Listed {
    records: String,
    /// Each process's file, as hex.
    paths: HashMap<i32, String>,
    /// The name of each process that has no file, as hex.
    names: HashMap<i32, String>,
    /// What `CGGetEventTapList` returned when it failed.
    error: Option<i64>,
}

/// Runs [`TAP_LIST`]. In a debug build, `VIGIL_TEST_EVENT_TAPS` names a file to read its output
/// from instead, or no file for no taps: the CLI's end-to-end tests set it, so a sweep there
/// neither lists the taps of the machine it runs on nor checks their programs' signatures,
/// which would slow every sweep as reading its launch items did (see [`super::system_root`]).
fn tap_list(cancel: &Cancel) -> Result<Listed, InventoryError> {
    #[cfg(debug_assertions)]
    if let Some(file) = std::env::var_os("VIGIL_TEST_EVENT_TAPS") {
        let output = match std::fs::read_to_string(&file) {
            Ok(output) => output,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Listed::default()),
            Err(source) => return Err(InventoryError::io(Path::new(&file), source)),
        };
        return serde_json::from_str(&output).map_err(|e| InventoryError::parse("taps", &e));
    }
    let args = ["-l", "JavaScript", "-e", TAP_LIST];
    let output = super::tool(OSASCRIPT, &args, cancel)?;
    if !output.success {
        return Err(InventoryError::Command {
            command: "osascript (event taps)".to_owned(),
            detail: output.detail,
        });
    }
    serde_json::from_str(&output.stdout)
        .map_err(|e| InventoryError::parse("osascript (event taps)", &e))
}

/// Who holds a tap.
#[derive(Debug)]
enum Holder {
    /// The file the process runs.
    File(PathBuf),
    /// A running process whose file was deleted, by its name.
    NoFile(String),
}

/// The keyboard taps in `listed`, each with who holds it and its process id. A tap whose
/// process has neither a file nor a name has exited, and is left out: it is gone. No window
/// server connection is a note ([`InventoryError::NoWindowServer`]): a sweep from an ssh
/// session would otherwise fail on every run and keep the keyboard issues open forever.
fn taps(listed: &Listed) -> Result<Vec<(Holder, i32, Tap)>, InventoryError> {
    match listed.error {
        Some(NO_WINDOW_SERVER) => return Err(InventoryError::NoWindowServer),
        Some(status) => {
            return Err(InventoryError::Command {
                command: "CGGetEventTapList".to_owned(),
                detail: format!("returned {status}"),
            });
        }
        None => {}
    }
    let records = records(&listed.records)
        .map_err(|detail| InventoryError::parse("the event tap list", &detail))?;
    let decoded = |hex: &String| bytes(hex).filter(|bytes| !bytes.is_empty());
    let path = |pid: i32| {
        let bytes = listed.paths.get(&pid).and_then(decoded)?;
        Some(PathBuf::from(OsString::from_vec(bytes)))
    };
    let name = |pid: i32| {
        let bytes = listed.names.get(&pid).and_then(decoded)?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    };
    let taps = records
        .into_iter()
        .filter(|record| record.events & KEY_EVENTS != 0)
        .filter_map(|record| {
            let holder = match (path(record.tapping), name(record.tapping)) {
                (Some(file), _) => Holder::File(file),
                (None, Some(name)) => Holder::NoFile(name),
                (None, None) => return None,
            };
            let target = (record.tapped > 0).then(|| match path(record.tapped) {
                Some(file) => text(&file),
                None => "(exited)".to_owned(),
            });
            let tap = Tap {
                location: Location::from_raw(record.location),
                listen_only: record.options & 1 != 0,
                target,
                enabled: record.enabled,
                command: None,
            };
            Some((holder, record.tapping, tap))
        })
        .collect();
    Ok(taps)
}

/// The fields of one `CGEventTapInformation` that are read.
#[derive(Debug)]
struct Record {
    location: u32,
    /// `CGEventTapOptions`: bit 0 is `kCGEventTapOptionListenOnly`.
    options: u32,
    /// The events it sees, one bit per `CGEventType`.
    events: u64,
    tapping: i32,
    tapped: i32,
    enabled: bool,
}

/// Decodes the hex of `CGEventTapInformation` records ([`RECORD_LEN`]).
fn records(hex: &str) -> Result<Vec<Record>, String> {
    let bytes = bytes(hex).ok_or("the tap list is not hex")?;
    let (records, rest) = bytes.as_chunks::<RECORD_LEN>();
    if !rest.is_empty() {
        return Err(format!(
            "the tap list is {} bytes, not a whole number of {RECORD_LEN}-byte records",
            bytes.len()
        ));
    }
    let u32_at = |record: &[u8; RECORD_LEN], at: usize| {
        u32::from_le_bytes(record[at..at + 4].try_into().expect("four bytes"))
    };
    let records = records
        .iter()
        .map(|record| Record {
            location: u32_at(record, 4),
            options: u32_at(record, 8),
            events: u64::from_le_bytes(record[16..24].try_into().expect("eight bytes")),
            tapping: i32::from_le_bytes(record[24..28].try_into().expect("four bytes")),
            tapped: i32::from_le_bytes(record[28..32].try_into().expect("four bytes")),
            enabled: record[32] != 0,
        })
        .collect();
    Ok(records)
}

/// The bytes `hex` spells, two digits each. `from_str_radix` alone would take a `+` sign.
fn bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|at| {
            hex.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

/// The text of the code requirement `hex` spells, a TCC grant's `csreq`; `None` when it is
/// empty, as `hex(NULL)` is.
fn requirement(hex: &str, cancel: &Cancel) -> Result<Option<String>, InventoryError> {
    if hex.is_empty() {
        return Ok(None);
    }
    let blob = bytes(hex).ok_or_else(|| InventoryError::parse("a TCC csreq", &"not hex"))?;
    // `run_with_input` cannot be cancelled, and there is one run per grant.
    if cancel.is_cancelled() {
        return Err(InventoryError::Cancelled {
            what: CSREQ.to_owned(),
        });
    }
    let output = command::run_with_input(CSREQ, &["-r-", "-t"], &blob, command::TIMEOUT)?
        .ok_or_else(|| InventoryError::Spawn {
            command: CSREQ.to_owned(),
            source: io::Error::new(io::ErrorKind::NotFound, "not found; it ships with macOS"),
        })?;
    if !output.success {
        return Err(InventoryError::Command {
            command: output.command,
            detail: output.detail,
        });
    }
    Ok(Some(output.stdout.trim().to_owned()))
}

/// One allowed grant, as `sqlite3 -json` prints it.
#[derive(Debug, Deserialize)]
struct Row {
    service: String,
    client: String,
    /// 0: `client` is a bundle identifier; 1: an absolute path.
    client_type: i64,
    /// The code requirement, as hex; empty when there is none.
    csreq: String,
}

/// The allowed keyboard grants in the TCC database at `path`: `auth_value` 2 is allowed. A
/// database that is not there has none, as this user's often is not. One macOS keeps this
/// process from reading gives [`InventoryError::FullDiskAccess`], a note, not a failure.
/// `-init /dev/null` keeps a `~/.sqliterc` from running its commands in a process that may
/// have Full Disk Access.
fn grants(path: &Path, cancel: &Cancel) -> Result<Vec<Row>, InventoryError> {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(InventoryError::io(path, source)),
        Ok(_) => {}
    }
    let services = Service::ALL
        .iter()
        .map(|(name, _)| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "select service, client, client_type, hex(csreq) as csreq from access \
         where auth_value = 2 and service in ({services}) order by service, client"
    );
    let file = path.to_string_lossy();
    let args = ["-init", "/dev/null", "-readonly", "-json", &file, &query];
    let output = super::tool(SQLITE, &args, cancel)?;
    if !output.success {
        // TCC refuses this process the file, which sqlite reports as `SQLITE_AUTH`.
        if output.stderr.contains("authorization denied") {
            return Err(InventoryError::FullDiskAccess {
                unread: "the apps allowed to read the keyboard",
                path: path.to_owned(),
            });
        }
        return Err(InventoryError::Command {
            command: output.command,
            detail: output.detail,
        });
    }
    // No rows print nothing, not `[]`.
    if output.stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&output.stdout).map_err(|e| InventoryError::parse(&output.command, &e))
}

/// The apps in `apps` by their bundle identifiers, in the inventory's order. An app whose
/// `Info.plist` cannot be read or names none is left out: its grant is then unplaced.
fn identifiers(apps: &[PathBuf]) -> HashMap<String, Vec<PathBuf>> {
    /// The one key read.
    #[derive(Debug, Deserialize)]
    struct Info {
        #[serde(rename = "CFBundleIdentifier")]
        identifier: Option<String>,
    }
    let mut by_identifier: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for app in apps {
        let Ok(bytes) = paths::read_capped(&app.join("Contents/Info.plist"), PLIST_LIMIT) else {
            continue;
        };
        if let Ok(Info {
            identifier: Some(identifier),
        }) = plist::from_bytes(&bytes)
        {
            by_identifier
                .entry(identifier)
                .or_default()
                .push(app.clone());
        }
    }
    by_identifier
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::fs;
    use std::process::Command;

    use serde_json::json;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut hex, b| {
            write!(hex, "{b:02x}").expect("a String takes any text");
            hex
        })
    }

    /// One `CGEventTapInformation` record, as hex.
    fn record(location: u32, options: u32, events: u64, tapping: i32, tapped: i32) -> String {
        let mut bytes = Vec::new();
        bytes.extend(7_u32.to_le_bytes());
        bytes.extend(location.to_le_bytes());
        bytes.extend(options.to_le_bytes());
        bytes.extend([0; 4]);
        bytes.extend(events.to_le_bytes());
        bytes.extend(tapping.to_le_bytes());
        bytes.extend(tapped.to_le_bytes());
        bytes.push(1);
        bytes.resize(RECORD_LEN, 0);
        hex(&bytes)
    }

    fn listed(records: &[String], paths: &[(i32, &[u8])], names: &[(i32, &str)]) -> Listed {
        Listed {
            records: records.concat(),
            paths: paths.iter().map(|(pid, path)| (*pid, hex(path))).collect(),
            names: names
                .iter()
                .map(|(pid, name)| (*pid, hex(name.as_bytes())))
                .collect(),
            error: None,
        }
    }

    #[test]
    fn only_taps_that_see_key_presses_are_kept_with_who_holds_them() {
        let key_down = 1 << 10;
        let listed = listed(
            &[
                record(0, 0, key_down, 10, 0),
                // Key up only, listen-only, on one program.
                record(1, 1, 1 << 11, 11, 12),
                // Modifier keys alone, and the mouse: not key presses.
                record(1, 1, 1 << 12, 13, 0),
                record(1, 1, 1 << 1, 13, 0),
                // Its program exited while the list was read.
                record(2, 1, key_down, 14, 0),
                // The one it taps exited.
                record(2, 1, key_down, 10, 15),
                record(9, 0, u64::MAX, 10, 0),
                // Running, but its file was deleted; and a file whose name is not UTF-8.
                record(1, 1, key_down, 16, 0),
                record(1, 1, key_down, 17, 0),
            ],
            &[
                (10, b"/bin/a"),
                (11, b"/bin/b"),
                (12, b"/bin/c"),
                (13, b"/bin/m"),
                (17, b"/tmp/\xff"),
            ],
            &[(16, "keylog")],
        );

        let taps = taps(&listed).unwrap();

        let shown: Vec<_> = taps
            .iter()
            .map(|(holder, pid, tap)| {
                let holder = match holder {
                    Holder::File(file) => format!("{}", file.display()),
                    Holder::NoFile(name) => format!("no file: {name}"),
                };
                json!({"holder": holder, "pid": pid, "tap": tap})
            })
            .collect();
        let tap = |holder: &str, pid: i32, location: &str, listen_only: bool, target: &str| {
            let mut tap =
                json!({"enabled": true, "listen_only": listen_only, "location": location});
            if !target.is_empty() {
                tap["target"] = json!(target);
            }
            json!({"holder": holder, "pid": pid, "tap": tap})
        };
        assert_eq!(
            shown,
            [
                tap("/bin/a", 10, "hid", false, ""),
                tap("/bin/b", 11, "session", true, "/bin/c"),
                tap("/bin/a", 10, "annotated_session", true, "(exited)"),
                tap("/bin/a", 10, "other", false, ""),
                tap("no file: keylog", 16, "session", true, ""),
                tap("/tmp/\u{fffd}", 17, "session", true, ""),
            ]
        );
    }

    #[test]
    fn records_decode_only_whole_hex_records() {
        let one = record(1, 1, 1 << 10, 633, 0);
        let [decoded] = &records(&one).unwrap()[..] else {
            panic!("one record");
        };
        let fields = (
            decoded.location,
            decoded.options,
            decoded.events,
            decoded.tapping,
            decoded.tapped,
            decoded.enabled,
        );
        assert_eq!(fields, (1, 1, 1 << 10, 633, 0, true));
        assert!(records("").unwrap().is_empty());
        assert!(
            records(&one[..one.len() - 2])
                .unwrap_err()
                .contains("47 bytes")
        );
        assert_eq!(records("0g").unwrap_err(), "the tap list is not hex");
        assert_eq!(records("abc").unwrap_err(), "the tap list is not hex");
        assert_eq!(bytes("+a"), None, "a sign is not hex");
    }

    #[test]
    fn no_window_server_is_a_note_and_another_failure_is_not() {
        let failed = |error| Listed {
            error: Some(error),
            ..Listed::default()
        };
        let e = taps(&failed(NO_WINDOW_SERVER)).unwrap_err();
        assert!(matches!(e, InventoryError::NoWindowServer));
        assert!(!e.is_failure());
        assert!(taps(&failed(1004)).unwrap_err().is_failure());
    }

    #[test]
    fn the_identity_follows_the_signer_and_the_grants_not_the_taps() {
        let access = |taps: Vec<Tap>, signature, grants: BTreeSet<Grant>| Access {
            path: "/bin/a".to_owned(),
            identifier: None,
            signature: Some(signature),
            taps,
            grants,
        };
        let tap = || Tap {
            location: Location::Session,
            listen_only: true,
            target: None,
            enabled: true,
            command: None,
        };
        let grant = || Grant {
            service: Service::PostEvent,
            database: Database::User,
            csreq: "fade0c00".to_owned(),
            requirement: Some("anchor apple".to_owned()),
            apple_only: true,
        };
        let running = access(vec![tap()], Signature::Apple, [grant()].into());
        let not_running = access(Vec::new(), Signature::Apple, [grant()].into());
        assert_eq!(running.identity(), not_running.identity());
        let replaced = access(Vec::new(), Signature::Missing, [grant()].into());
        assert_ne!(not_running.identity(), replaced.identity());
        let ungranted = access(Vec::new(), Signature::Apple, BTreeSet::new());
        assert_ne!(not_running.identity(), ungranted.identity());
        // A requirement `csreq` could not decode on one sweep keeps the key.
        let undecoded = Grant {
            requirement: Some("(not decoded) fade0c00".to_owned()),
            apple_only: false,
            ..grant()
        };
        let failed = access(Vec::new(), Signature::Apple, [undecoded].into());
        assert_eq!(not_running.identity(), failed.identity());
    }

    #[test]
    fn only_an_anchor_apple_clause_holds_a_grant_to_apples_code() {
        assert!(apple_only("anchor apple"));
        assert!(apple_only(r#"identifier "com.apple.x" and anchor apple"#));
        // Looser shapes a developer can choose, which code other than Apple's satisfies.
        assert!(!apple_only(r#"(anchor apple) or identifier "com.evil""#));
        assert!(!apple_only(
            r#"identifier "x anchor apple y" and anchor apple generic"#
        ));
        assert!(!apple_only(
            r#"identifier "a" or identifier "b" and anchor apple"#
        ));
        assert!(!apple_only(concat!(
            r#"identifier "x" and anchor apple generic and "#,
            r#"certificate leaf[subject.OU] = Q6L2SF6YDW"#,
        )));
        assert!(!apple_only(r#"identifier "anchor applex""#));
        assert!(!apple_only(r#"cdhash H"aa""#));
    }

    /// An app at `app` whose `Info.plist` names `identifier` and the executable `Tool`, a
    /// copy of `program`.
    fn app(app: &Path, identifier: &str, program: &Path) {
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::write(
            app.join("Contents/Info.plist"),
            format!(
                "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
                 <key>CFBundleIdentifier</key><string>{identifier}</string>\
                 <key>CFBundleExecutable</key><string>Tool</string></dict></plist>"
            ),
        )
        .unwrap();
        fs::copy(program, app.join("Contents/MacOS/Tool")).unwrap();
    }

    #[test]
    fn an_apps_main_executable_is_the_app() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = tmp.path().join("Tool.app");
        app(&tool, "com.example.tool", Path::new("/bin/ls"));
        fs::create_dir_all(tool.join("Contents/Resources")).unwrap();

        assert_eq!(
            app_of(&tool.join("Contents/MacOS/Tool")),
            Some(tool.clone())
        );
        assert_eq!(app_of(&tool.join("Contents/Resources/helper")), None);
        assert_eq!(app_of(&tool.join("Contents/MacOS/Other")), None);
        assert_eq!(app_of(Path::new("/bin/ls")), None);
    }

    /// A TCC database with the `access` columns the query reads, each row's `csreq` the
    /// compiled requirement given, or null.
    fn database(path: &Path, rows: &[(&str, &str, i64, i64, Option<&str>)]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut sql = "create table access (service text, client text, client_type integer, \
                       auth_value integer, csreq blob);"
            .to_owned();
        for (service, client, client_type, auth, requirement) in rows {
            let csreq = requirement.map_or("null".to_owned(), |text| {
                format!("x'{}'", compiled(&path.with_extension("csreq"), text))
            });
            sql.push_str(&format!(
                "insert into access values ('{service}', '{client}', {client_type}, {auth}, \
                 {csreq});"
            ));
        }
        let out = Command::new(SQLITE).arg(path).arg(sql).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The compiled code requirement `text`, as hex, written through `blob`.
    fn compiled(blob: &Path, text: &str) -> String {
        let out = Command::new(CSREQ)
            .args(["-r", &format!("={text}"), "-b"])
            .arg(blob)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        hex(&fs::read(blob).unwrap())
    }

    #[test]
    fn allowed_keyboard_grants_are_read_and_placed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let home = tmp.path().join("home");
        let tool = tmp.path().join("Tool.app");
        app(&tool, "com.example.tool", Path::new("/bin/ls"));
        let gone = r#"identifier "com.example.gone" and anchor apple"#;
        database(
            &root.join(DATABASE),
            &[
                ("kTCCServiceAccessibility", "com.example.tool", 0, 2, None),
                (
                    "kTCCServiceListenEvent",
                    "com.example.gone",
                    0,
                    2,
                    Some(gone),
                ),
                ("kTCCServiceListenEvent", "/bin/ls", 1, 2, None),
                // Denied, and a service that is not the keyboard.
                ("kTCCServicePostEvent", "/bin/cat", 1, 0, None),
                ("kTCCServiceCamera", "/bin/cat", 1, 2, None),
            ],
        );
        database(
            &home.join(DATABASE),
            &[("kTCCServicePostEvent", "com.example.tool", 0, 2, None)],
        );
        let mut inventory = Inventory {
            apps: vec![tool.clone()],
            ..Inventory::default()
        };
        // No taps: the test reads none of the machine's.
        let no_taps = Ok(Listed::default());
        let found = read(&mut inventory, no_taps, &root, Some(&home), &Cancel::new());

        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
        let lines: Vec<_> = found.iter().map(|access| json!(access)).collect();
        let apple = json!({"status": "apple"});
        let grant =
            |service: &str, database: &str| json!({"service": service, "database": database});
        let mut held = grant("input_monitoring", "system");
        held["requirement"] = json!(gone);
        held["apple_only"] = json!(true);
        assert_eq!(
            lines,
            [
                json!({
                    "path": "(unplaced) com.example.gone",
                    "identifier": "com.example.gone",
                    "grants": [held],
                }),
                json!({
                    "path": "/bin/ls",
                    "signature": apple,
                    "grants": [grant("input_monitoring", "system")],
                }),
                json!({
                    "path": tool,
                    "identifier": "com.example.tool",
                    "signature": apple,
                    "grants": [grant("accessibility", "system"), grant("post_event", "user")],
                }),
            ]
        );
    }

    #[test]
    fn an_apps_tap_and_its_grants_are_one_line() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let tool = tmp.path().join("Tool.app");
        app(&tool, "com.example.tool", Path::new("/bin/ls"));
        let executable = tool.join("Contents/MacOS/Tool");
        let executable_text = executable.to_str().unwrap();
        database(
            &root.join(DATABASE),
            &[
                ("kTCCServiceAccessibility", "com.example.tool", 0, 2, None),
                ("kTCCServicePostEvent", executable_text, 1, 2, None),
            ],
        );
        let mut inventory = Inventory {
            apps: vec![tool.clone()],
            ..Inventory::default()
        };
        // Held by a process id macOS never gives out, so `ps` has no command line for it.
        let tap = listed(
            &[record(1, 1, 1 << 10, 99_999, 0)],
            &[(99_999, executable_text.as_bytes())],
            &[],
        );

        let found = read(&mut inventory, Ok(tap), &root, None, &Cancel::new());

        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
        let [line] = &found[..] else {
            panic!("{found:#?}");
        };
        assert_eq!(line.path, tool.to_str().unwrap());
        assert_eq!(line.taps.len(), 1);
        let services: Vec<Service> = line.grants.iter().map(|grant| grant.service).collect();
        assert_eq!(services, [Service::Accessibility, Service::PostEvent]);
    }

    #[test]
    fn command_lines_are_read_for_running_processes_only() {
        let own = i32::try_from(std::process::id()).unwrap();
        let read = commands(&[own, 99_999].into(), &Cancel::new());
        assert_eq!(read.len(), 1, "{read:?}");
        let test_binary = std::env::args().next().unwrap();
        assert!(read[&own].starts_with(&test_binary), "{read:?}");
        assert!(commands(&BTreeSet::new(), &Cancel::new()).is_empty());
    }

    #[test]
    fn a_grant_is_placed_at_the_app_that_satisfies_its_requirement() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("main.c"), "int main(void) { return 0; }\n").unwrap();
        let program = tmp.path().join("tool");
        let out = Command::new("/usr/bin/cc")
            .args(["main.c", "-o", "tool"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Two apps that both say they are com.example.tool; only the second is signed as it.
        let first = tmp.path().join("A/Tool.app");
        let second = tmp.path().join("B/Tool.app");
        for (bundle, signed_as) in [
            (&first, "com.example.lookalike"),
            (&second, "com.example.tool"),
        ] {
            app(bundle, "com.example.tool", &program);
            let out = Command::new("/usr/bin/codesign")
                .args(["--force", "-s", "-", "-i", signed_as])
                .arg(bundle)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let mut inventory = Inventory::default();
        let candidates = [first.clone(), second.clone()];
        let cancel = Cancel::new();

        let requirement = Some(r#"identifier "com.example.tool""#);
        let placed = place(&mut inventory, &candidates, requirement, &cancel);
        assert_eq!(placed, Some(second));
        let nobody = Some(r#"identifier "com.example.other""#);
        assert_eq!(place(&mut inventory, &candidates, nobody, &cancel), None);
        assert_eq!(
            place(&mut inventory, &candidates, None, &cancel),
            Some(first)
        );
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
    }

    #[test]
    fn a_requirement_is_decoded_or_says_why_not() {
        let cancel = Cancel::new();
        assert_eq!(requirement("", &cancel).unwrap(), None);
        let tmp = tempfile::tempdir().unwrap();
        let blob = compiled(&tmp.path().join("r.csreq"), "anchor apple");
        assert_eq!(
            requirement(&blob, &cancel).unwrap().as_deref(),
            Some("anchor apple")
        );
        assert!(matches!(
            requirement("zz", &cancel),
            Err(InventoryError::Parse { .. })
        ));
        assert!(matches!(
            requirement("00", &cancel),
            Err(InventoryError::Command { .. })
        ));
        let cancelled = Cancel::new();
        cancelled.cancel();
        assert!(matches!(
            requirement(&blob, &cancelled),
            Err(InventoryError::Cancelled { .. })
        ));
    }

    #[test]
    fn a_database_that_is_not_there_has_no_grants_and_a_broken_one_fails() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            grants(&tmp.path().join("none.db"), &Cancel::new())
                .unwrap()
                .is_empty()
        );
        let broken = tmp.path().join("broken.db");
        fs::write(&broken, "not a database").unwrap();
        let e = grants(&broken, &Cancel::new()).unwrap_err();
        assert!(e.is_failure(), "{e}");
    }

    #[test]
    fn this_macs_taps_are_listed_with_who_holds_them() {
        let listed = tap_list(&Cancel::new()).unwrap();
        assert_eq!(listed.error, None);
        let records = records(&listed.records).unwrap();
        let named = records
            .iter()
            .filter(|record| listed.paths.contains_key(&record.tapping))
            .count();
        // A process may exit between the list and its name; this Mac's Apple taps do not.
        assert!(
            named * 2 >= records.len(),
            "{named} of {} named",
            records.len()
        );
        taps(&listed).unwrap();
    }
}
