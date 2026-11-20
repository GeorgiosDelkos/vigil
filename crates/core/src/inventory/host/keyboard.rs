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
//! process sets itself (`exec -a /System/Library/x` makes `ps` print that). The grants are
//! read with `sqlite3`; the system database needs Full Disk Access, and without it the
//! grants are a note ([`InventoryError::FullDiskAccess`]), as Background Task Management's
//! records are.
//!
//! Each program is one line, by path, with its signature, its taps and its grants. An issue
//! names it as `{"keyboard": path}` and is keyed by [`Access::identity`].
//!
//! Not read: taps that see no key presses (mouse only); grants denied or not yet answered;
//! grants in other users' databases. A tap is a moment's state: one a program opens after the
//! sweep is seen at the next.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io;
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
use crate::paths;

const OSASCRIPT: &str = "/usr/bin/osascript";
const SQLITE: &str = "/usr/bin/sqlite3";
const CSREQ: &str = "/usr/bin/csreq";

/// The TCC database, under [`super::system_root`] for the system's grants and under the home
/// folder for this user's.
pub(super) const DATABASE: &str = "Library/Application Support/com.apple.TCC/TCC.db";

/// Lists the event taps and the file each process in them runs, as JSON:
/// `{"records": "<hex>", "paths": {"<pid>": "<path>"}}`.
///
/// The records are the `CGEventTapInformation` array, 48 bytes each ([`RECORD_LEN`]), as hex:
/// the bridge hands back raw memory, and a Latin-1 string maps each byte to one character.
/// `proc_pidpath` fills at most `PROC_PIDPATHINFO_MAXSIZE` (4096) bytes (`libproc.h`); a
/// process that exited, or a path that is not UTF-8, has no entry.
const TAP_LIST: &str = r"
ObjC.import('CoreGraphics');
ObjC.bindFunction('CGGetEventTapList', ['int', ['unsigned int', 'void *', 'unsigned int *']]);
ObjC.bindFunction('proc_pidpath', ['int', ['int', 'void *', 'unsigned int']]);
function taps(size, data) {
  var got = Ref('unsigned int');
  var status = $.CGGetEventTapList(size, data ? data.mutableBytes : null, got);
  if (status !== 0) throw new Error('CGGetEventTapList returned ' + status);
  return got[0];
}
function run() {
  var size = taps(0, null);
  var data = $.NSMutableData.dataWithLength(48 * size);
  data.length = 48 * Math.min(size, taps(size, data));
  var bytes = $.NSString.alloc.initWithDataEncoding(data, $.NSISOLatin1StringEncoding).js;
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    hex += ('0' + bytes.charCodeAt(i).toString(16)).slice(-2);
  }
  var pid = function (at) {
    return bytes.charCodeAt(at) | bytes.charCodeAt(at + 1) << 8
      | bytes.charCodeAt(at + 2) << 16 | bytes.charCodeAt(at + 3) << 24;
  };
  var paths = {};
  for (var at = 0; at < bytes.length; at += 48) {
    [pid(at + 24), pid(at + 28)].forEach(function (id) {
      if (id <= 0 || id in paths) return;
      var path = $.NSMutableData.dataWithLength(4096);
      var length = $.proc_pidpath(id, path.mutableBytes, 4096);
      if (length <= 0) return;
      path.length = length;
      var text = $.NSString.alloc.initWithDataEncoding(path, $.NSUTF8StringEncoding);
      if (!text.isNil()) paths[id] = text.js;
    });
  }
  return JSON.stringify({records: hex, paths: paths});
}
";

/// The size of one `CGEventTapInformation` on a 64-bit Mac (`CGEventTypes.h`, macOS 27.2 SDK):
/// `eventTapID`, `tapPoint` and `options` (`uint32_t` each, at 0, 4 and 8), padding,
/// `eventsOfInterest` (`uint64_t`, at 16), `tappingProcess` and `processBeingTapped`
/// (`pid_t`, at 24 and 28), `enabled` (`bool`, at 32), then three `float` latencies.
const RECORD_LEN: usize = 48;

/// The events of a key press in an event mask: `kCGEventKeyDown` (10) and `kCGEventKeyUp`
/// (11), bits of `CGEventMaskBit` (`CGEventTypes.h`). Modifier keys alone (`kCGEventFlagsChanged`)
/// do not count, as in ReiKey.
const KEY_EVENTS: u64 = 1 << 10 | 1 << 11;

/// A program that can read the keyboard, one line of `mac/keyboard.jsonl`.
#[derive(Debug, Serialize)]
pub(super) struct Access {
    /// The program's path; for a grant TCC records by bundle identifier, the app's with that
    /// identifier the inventory found, or `(unplaced) <identifier>` when it found none. An
    /// issue names it by this. Text, as an item's path is.
    pub(super) path: String,
    /// The bundle identifier TCC names an app by.
    #[serde(skip_serializing_if = "Option::is_none")]
    identifier: Option<String>,
    /// The program's signature; for an app, its executable's. Absent when it is unplaced.
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
    /// What keys its issue besides its path: who signed it ([`Signature::identity`]), what
    /// its taps can do, and its grants. Whether a tap is enabled is left out, since a program
    /// turns its tap off and on as it runs.
    pub(super) fn identity(&self) -> String {
        let signature = self.signature.as_ref().map(Signature::identity);
        let taps: BTreeSet<_> = self
            .taps
            .iter()
            .map(|tap| (tap.location, tap.listen_only, &tap.target))
            .collect();
        serde_json::to_string(&(signature, taps, &self.grants)).expect("strings and booleans")
    }
}

/// An event tap that sees key presses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Tap {
    location: Location,
    /// Whether it only listens. Otherwise it is an active filter, which can also change or
    /// drop each key press.
    listen_only: bool,
    /// The one program whose key presses it sees; absent for every program's.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    enabled: bool,
}

/// Where a tap sits in the event stream (`CGEventTapLocation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Grant {
    service: Service,
    database: Database,
    /// The code requirement TCC holds the grant to, as `csreq -t` prints it
    /// (`identifier "com.apple.screensharing.agent" and anchor apple`): only a program that
    /// satisfies it gets the grant, so it says who the grant is for when the program cannot be
    /// found. Absent when TCC keeps none.
    #[serde(skip_serializing_if = "Option::is_none")]
    requirement: Option<String>,
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
    /// The file to check: the program, or the app. `None` when unplaced.
    file: Option<PathBuf>,
    identifier: Option<String>,
    taps: Vec<Tap>,
    grants: BTreeSet<Grant>,
}

/// Reads the keyboard taps and grants: the system's database under `root`, this user's under
/// `home`. The apps in `apps` place the grants TCC records by bundle identifier. Whatever
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
        Ok(taps) => {
            for (program, tap) in taps {
                let entry = found.entry(text(&program)).or_default();
                entry.file = Some(program);
                entry.taps.push(tap);
            }
        }
        Err(e) => inventory.fail(InventorySource::KeyboardAccess, e),
    }

    let databases = [(Database::System, Some(root.join(DATABASE)))]
        .into_iter()
        .chain([(Database::User, home.map(|home| home.join(DATABASE)))]);
    let mut apps: Option<HashMap<String, PathBuf>> = None;
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
            let Some(service) = Service::ALL
                .iter()
                .find(|(name, _)| *name == row.service)
                .map(|(_, service)| *service)
            else {
                continue;
            };
            let requirement = match requirement(&row.csreq) {
                Ok(requirement) => requirement,
                Err(e) => {
                    inventory.fail(InventorySource::KeyboardAccess, e);
                    None
                }
            };
            let grant = Grant {
                service,
                database,
                requirement,
            };
            let (name, file, identifier) = match row.client_type {
                // A bundle identifier.
                0 => {
                    let apps = apps.get_or_insert_with(|| identifiers(&inventory.apps));
                    match apps.get(&row.client) {
                        Some(app) => (text(app), Some(app.clone()), Some(row.client)),
                        None => (format!("(unplaced) {}", row.client), None, Some(row.client)),
                    }
                }
                // An absolute path.
                _ => (row.client.clone(), Some(PathBuf::from(&row.client)), None),
            };
            let entry = found.entry(name).or_default();
            entry.file = entry.file.take().or(file);
            entry.identifier = entry.identifier.take().or(identifier);
            entry.grants.insert(grant);
        }
    }

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

/// What [`TAP_LIST`] prints.
#[derive(Debug, Deserialize)]
struct Listed {
    records: String,
    paths: HashMap<i32, PathBuf>,
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
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                r#"{"records": "", "paths": {}}"#.to_owned()
            }
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

/// The keyboard taps in `listed`, each with the program that holds it. A tap whose program has
/// no path (it exited while the list was read) is left out: it is gone.
fn taps(listed: &Listed) -> Result<Vec<(PathBuf, Tap)>, InventoryError> {
    let records = records(&listed.records)
        .map_err(|detail| InventoryError::parse("the event tap list", &detail))?;
    let taps = records
        .into_iter()
        .filter(|record| record.events & KEY_EVENTS != 0)
        .filter_map(|record| {
            let program = listed.paths.get(&record.tapping)?;
            let target = (record.tapped > 0).then(|| match listed.paths.get(&record.tapped) {
                Some(path) => text(path),
                None => "(exited)".to_owned(),
            });
            let tap = Tap {
                location: Location::from_raw(record.location),
                listen_only: record.options & 1 != 0,
                target,
                enabled: record.enabled,
            };
            Some((program.clone(), tap))
        })
        .collect();
    Ok(taps)
}

/// The fields of one `CGEventTapInformation` that are read.
#[derive(Debug, PartialEq, Eq)]
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

/// The bytes `hex` spells, two digits each.
fn bytes(hex: &str) -> Option<Vec<u8>> {
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
fn requirement(hex: &str) -> Result<Option<String>, InventoryError> {
    if hex.is_empty() {
        return Ok(None);
    }
    let blob = bytes(hex).ok_or_else(|| InventoryError::parse("a TCC csreq", &"not hex"))?;
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
         where auth_value = 2 \
         and service in ({services}) order by service, client"
    );
    let file = path.to_string_lossy();
    let output = super::tool(SQLITE, &["-readonly", "-json", &file, &query], cancel)?;
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

/// The apps in `apps` by their bundle identifiers. An app whose `Info.plist` cannot be read or
/// names none is left out: its grant is then unplaced.
fn identifiers(apps: &[PathBuf]) -> HashMap<String, PathBuf> {
    /// The one key read.
    #[derive(Debug, Deserialize)]
    struct Info {
        #[serde(rename = "CFBundleIdentifier")]
        identifier: Option<String>,
    }
    let mut by_identifier = HashMap::new();
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
                .or_insert_with(|| app.clone());
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

    fn listed(records: &[String], paths: &[(i32, &str)]) -> Listed {
        Listed {
            records: records.concat(),
            paths: paths
                .iter()
                .map(|(pid, path)| (*pid, PathBuf::from(path)))
                .collect(),
        }
    }

    #[test]
    fn only_taps_that_see_key_presses_are_kept_with_their_programs() {
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
            ],
            &[
                (10, "/bin/a"),
                (11, "/bin/b"),
                (12, "/bin/c"),
                (13, "/bin/m"),
            ],
        );

        let taps = taps(&listed).unwrap();

        let shown: Vec<_> = taps
            .iter()
            .map(|(program, tap)| json!({"program": program, "tap": tap}))
            .collect();
        let tap = |program: &str, location: &str, listen_only: bool, target: Option<&str>| {
            let mut tap =
                json!({"enabled": true, "listen_only": listen_only, "location": location});
            if let Some(target) = target {
                tap["target"] = json!(target);
            }
            json!({"program": program, "tap": tap})
        };
        assert_eq!(
            shown,
            [
                tap("/bin/a", "hid", false, None),
                tap("/bin/b", "session", true, Some("/bin/c")),
                tap("/bin/a", "annotated_session", true, Some("(exited)")),
                tap("/bin/a", "other", false, None),
            ]
        );
    }

    #[test]
    fn records_decode_only_whole_hex_records() {
        let one = record(1, 1, 1 << 10, 633, 0);
        let decoded = records(&one).unwrap();
        assert_eq!(
            decoded,
            [Record {
                location: 1,
                options: 1,
                events: 1 << 10,
                tapping: 633,
                tapped: 0,
                enabled: true,
            }]
        );
        assert_eq!(records("").unwrap(), []);
        assert!(
            records(&one[..one.len() - 2])
                .unwrap_err()
                .contains("47 bytes")
        );
        assert_eq!(records("0g").unwrap_err(), "the tap list is not hex");
        assert_eq!(records("abc").unwrap_err(), "the tap list is not hex");
    }

    #[test]
    fn the_identity_follows_the_signer_and_what_taps_can_do_not_whether_they_are_on() {
        let access = |enabled: bool, listen_only: bool| Access {
            path: "/bin/a".to_owned(),
            identifier: None,
            signature: Some(Signature::Apple),
            taps: vec![Tap {
                location: Location::Session,
                listen_only,
                target: None,
                enabled,
            }],
            grants: BTreeSet::new(),
        };
        let first = access(true, true);
        assert_eq!(first.identity(), access(false, true).identity());
        assert_ne!(first.identity(), access(true, false).identity());
        let unsigned = Access {
            signature: Some(Signature::Missing),
            ..access(true, true)
        };
        assert_ne!(first.identity(), unsigned.identity());
        let granted = Access {
            grants: [Grant {
                service: Service::PostEvent,
                database: Database::User,
                requirement: None,
            }]
            .into(),
            ..access(true, true)
        };
        assert_ne!(first.identity(), granted.identity());
    }

    /// A TCC database with the `access` columns the query reads. A grant to `com.example.gone`
    /// holds a code requirement, as TCC keeps one.
    fn database(path: &Path, rows: &[(&str, &str, i64, i64)]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut sql = "create table access (service text, client text, client_type integer, \
                       auth_value integer, csreq blob);"
            .to_owned();
        for (service, client, client_type, auth) in rows {
            let csreq = if *client == "com.example.gone" {
                format!("x'{}'", requirement_blob(path, client))
            } else {
                "null".to_owned()
            };
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

    /// The compiled code requirement for `identifier` and Apple's anchor, as hex.
    fn requirement_blob(beside: &Path, identifier: &str) -> String {
        let blob = beside.with_extension("csreq");
        let text = format!("=identifier \"{identifier}\" and anchor apple");
        let out = Command::new(CSREQ)
            .args(["-r", &text, "-b"])
            .arg(&blob)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        hex(&fs::read(&blob).unwrap())
    }

    #[test]
    fn allowed_keyboard_grants_are_read_and_placed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let home = tmp.path().join("home");
        let app = tmp.path().join("Tool.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::write(
            app.join("Contents/Info.plist"),
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>com.example.tool</string>\
             <key>CFBundleExecutable</key><string>Tool</string></dict></plist>",
        )
        .unwrap();
        fs::copy("/bin/ls", app.join("Contents/MacOS/Tool")).unwrap();
        database(
            &root.join(DATABASE),
            &[
                ("kTCCServiceAccessibility", "com.example.tool", 0, 2),
                ("kTCCServiceListenEvent", "com.example.gone", 0, 2),
                ("kTCCServiceListenEvent", "/bin/ls", 1, 2),
                // Denied, and a service that is not the keyboard.
                ("kTCCServicePostEvent", "/bin/cat", 1, 0),
                ("kTCCServiceCamera", "/bin/cat", 1, 2),
            ],
        );
        database(
            &home.join(DATABASE),
            &[("kTCCServicePostEvent", "com.example.tool", 0, 2)],
        );
        let mut inventory = Inventory {
            apps: vec![app.clone()],
            ..Inventory::default()
        };
        // No taps: the test reads none of the machine's.
        let no_taps = Ok(listed(&[], &[]));
        let found = read(&mut inventory, no_taps, &root, Some(&home), &Cancel::new());

        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
        let lines: Vec<_> = found.iter().map(|access| json!(access)).collect();
        let apple = json!({"status": "apple"});
        let grant =
            |service: &str, database: &str| json!({"service": service, "database": database});
        let mut held = grant("input_monitoring", "system");
        held["requirement"] = json!("identifier \"com.example.gone\" and anchor apple");
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
                    "path": app,
                    "identifier": "com.example.tool",
                    "signature": apple,
                    "grants": [grant("accessibility", "system"), grant("post_event", "user")],
                }),
            ]
        );
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
    fn this_macs_taps_are_listed() {
        let listed = tap_list(&Cancel::new()).unwrap();
        let records = records(&listed.records).unwrap();
        for record in &records {
            assert!(record.tapping > 0, "{record:?}");
        }
    }
}
