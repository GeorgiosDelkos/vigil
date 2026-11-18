//! Background Task Management's records: what System Settings > General > Login Items lists.
//!
//! macOS keeps them in `/private/var/db/com.apple.backgroundtaskmanagement`, a folder only a
//! process with Full Disk Access may list. Each file is an `NSKeyedArchiver` archive of the
//! private `ItemRecord` class, read here as the property list it is. Two layouts are known:
//!
//! - one file per user, `BackgroundItems-v18-<user>.btm`, whose `userStore` holds the user's
//!   `records`, beside an index `BackgroundItems-v18.btm` that holds none and is not read, so a
//!   change to it cannot fail the read (macOS 27.2);
//! - one file, `BackgroundItems-v<N>.btm`, whose `store` maps each user to their records
//!   (seen in the v13 and v16 files an upgrade to macOS 27.2 left behind).
//!
//! Only the files of the highest version are read, since an upgrade leaves the older ones in
//! place. The field names and bits follow Objective-See's `DumpBTM`
//! (<https://github.com/objective-see/DumpBTM/blob/19ba38005242afe07ba6e66c29f65663fa9b9917/library/code/dumpBTM.m>)
//! and were checked against this layout on macOS 27.2.
//!
//! Records of launch agents and daemons in the launch folders (the "legacy" bit) are left out:
//! [`super::collect`] reads their property lists from the folders. What is left is what no
//! folder shows: login items inside an app, the agents and daemons an app registered from its
//! own bundle (`SMAppService`), and the apps that open at login. The other records group items
//! by app (`0x2` not enabled) or developer (`0x20`), or name no path: `0x2000` records, named
//! "<App> - background tasks" and pointing at their app, and `0x80` (a Dock tile plugin, seen
//! in the v13 file) are skipped from what they hold on this Mac, not from any documentation.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;

use plist::Dictionary;
use plist::Value;

use crate::inventory::InventoryError;
use crate::inventory::host::ItemKind;
use crate::paths;

/// The folder the records are in, under the system root.
pub(super) const FOLDER: &str = "private/var/db/com.apple.backgroundtaskmanagement";

/// The largest file read. Arbitrary: a Mac with about 25 items has a 25 KB file.
const FILE_LIMIT: u64 = 16 * 1024 * 1024;

// `ItemRecord.type` bits, as DumpBTM's `typeDetails` names them.
const APP: u64 = 0x2;
const LOGIN_ITEM: u64 = 0x4;
const AGENT: u64 = 0x8;
const DAEMON: u64 = 0x10;
const LEGACY: u64 = 0x1_0000;

// `ItemRecord.disposition` bits, as DumpBTM's `dispositionDetails` names them.
const ENABLED: u64 = 0x1;
const ALLOWED: u64 = 0x2;

/// One record that runs something no launch folder shows.
#[derive(Debug)]
pub(super) struct Entry {
    pub(super) kind: ItemKind,
    pub(super) place: Place,
    /// The record's name for it.
    pub(super) name: Option<String>,
    pub(super) switches: Switches,
}

/// Where a record's item is on disk.
#[derive(Debug)]
pub(super) enum Place {
    /// The app bundle, or the property list inside one.
    Found(PathBuf),
    /// A record that could not be placed: `shown` is its identifier and its own text for the
    /// place, so records of different items stay apart, and `why` says what is missing. It is
    /// never an absolute path, which tells it from a launch folder item.
    Unplaced { shown: String, why: String },
}

/// The record's two switches, as System Settings > General > Login Items shows them.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(super) struct Switches {
    /// Whether the app turned it on (registered it, or the user added it to Open at Login).
    pub(super) enabled: bool,
    /// Whether the user lets it run ("Allow in the Background").
    pub(super) allowed: bool,
}

impl Switches {
    /// Whether the item runs: only while both are on.
    pub(super) fn runs(self) -> bool {
        self.enabled && self.allowed
    }
}

/// Reads the records in `folder`, each file on its own. A folder that does not exist (a macOS
/// before 13) has none. One macOS does not let this process list gives a
/// [`InventoryError::FullDiskAccess`]; any other error is pushed to `failures`, and the files
/// that could be read still give their entries.
pub(super) fn read(folder: &Path, failures: &mut Vec<InventoryError>) -> Vec<Entry> {
    let files = match newest_files(folder) {
        Ok(files) => files,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            failures.push(InventoryError::FullDiskAccess {
                path: folder.to_owned(),
            });
            return Vec::new();
        }
        Err(source) => {
            let path = folder.to_owned();
            failures.push(InventoryError::Io { path, source });
            return Vec::new();
        }
    };
    let mut entries = Vec::new();
    for file in files {
        match read_file(&file) {
            Ok(found) => entries.extend(found),
            Err(detail) => failures.push(InventoryError::Parse {
                what: file.display().to_string(),
                detail,
            }),
        }
    }
    entries
}

/// Whether macOS refuses to list the records' folder, which only Full Disk Access allows. A
/// folder that is not there needs no access.
pub(super) fn needs_full_disk_access(folder: &Path) -> bool {
    fs::read_dir(folder).is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied)
}

/// The files of the highest version in `folder`, sorted: its per-user files when it has any,
/// and otherwise its one file.
fn newest_files(folder: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found: Vec<(Version, PathBuf)> = Vec::new();
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        if let Some(version) = version(&entry.file_name()) {
            found.push((version, entry.path()));
        }
    }
    let Some(newest) = found.iter().map(|(version, _)| version.number).max() else {
        return Ok(Vec::new());
    };
    found.retain(|(version, _)| version.number == newest);
    let per_user = found.iter().any(|(version, _)| version.per_user);
    let mut files: Vec<PathBuf> = found
        .into_iter()
        .filter(|(version, _)| version.per_user == per_user)
        .map(|(_, path)| path)
        .collect();
    files.sort();
    Ok(files)
}

/// What a file's name says about it.
#[derive(Debug)]
struct Version {
    number: u32,
    /// Named for one user (`-<user>` after the number).
    per_user: bool,
}

/// The version in a file name `BackgroundItems-v<N>.btm` or `BackgroundItems-v<N>-<user>.btm`.
fn version(name: &OsStr) -> Option<Version> {
    let rest = name.to_str()?.strip_prefix("BackgroundItems-v")?;
    let rest = rest.strip_suffix(".btm")?;
    let (digits, per_user) = rest
        .split_once('-')
        .map_or((rest, false), |(digits, _)| (digits, true));
    let number = digits.parse().ok()?;
    Some(Version { number, per_user })
}

/// The entries of one file, or why it could not be read.
fn read_file(path: &Path) -> Result<Vec<Entry>, String> {
    let bytes =
        paths::read_capped(path, FILE_LIMIT + 1).map_err(|e| format!("cannot read it: {e}"))?;
    if bytes.len() as u64 > FILE_LIMIT {
        return Err(format!("more than the {FILE_LIMIT} bytes read"));
    }
    let root: Value = plist::from_bytes(&bytes).map_err(|e| format!("not a property list: {e}"))?;
    let archive = Archive::new(&root)?;
    let mut entries = Vec::new();
    for records in archive.users()? {
        entries.extend(user_entries(&archive, &records));
    }
    Ok(entries)
}

/// The entries of one user's records. An app's login items and agents name the app by its
/// identifier, which is resolved among the same user's records.
fn user_entries(archive: &Archive<'_>, records: &[&Dictionary]) -> Vec<Entry> {
    let app_of = |identifier: &str| {
        records
            .iter()
            .find(|record| archive.string(record, "identifier").as_deref() == Some(identifier))
            .and_then(|record| archive.url(record))
    };
    let mut entries = Vec::new();
    for record in records {
        let bits = Archive::integer(record, "type");
        let disposition = Archive::integer(record, "disposition");
        let kind = if bits & LEGACY != 0 {
            continue;
        } else if bits & DAEMON != 0 {
            ItemKind::AppLaunchDaemon
        } else if bits & AGENT != 0 {
            ItemKind::AppLaunchAgent
        } else if bits & LOGIN_ITEM != 0 {
            ItemKind::LoginItem
        } else if bits & APP != 0 && disposition & ENABLED != 0 {
            ItemKind::OpenAtLogin
        } else {
            continue;
        };
        let url = archive.url(record);
        let container = archive.string(record, "container");
        let found = match (url.as_deref(), container.as_deref()) {
            (None, _) => Err(("(no location)", "it names no location".to_owned())),
            (Some(url), _) if url.starts_with("file://") => Ok(file_path(url)),
            (Some(relative), Some(container)) => match app_of(container) {
                Some(app) if app.starts_with("file://") => {
                    Ok(file_path(&app).join(decode(relative)))
                }
                _ => Err((
                    relative,
                    format!("its app {container:?} has no file location among the records"),
                )),
            },
            (Some(relative), None) => {
                Err((relative, "its location is relative to no app".to_owned()))
            }
        };
        let place = match found {
            Ok(path) => Place::Found(path),
            Err((text, why)) => {
                let identifier = archive.string(record, "identifier");
                let identifier = identifier.as_deref().unwrap_or("(no identifier)");
                let shown = format!("{identifier}: {text}");
                Place::Unplaced { shown, why }
            }
        };
        entries.push(Entry {
            kind,
            place,
            name: archive.string(record, "name"),
            switches: Switches {
                enabled: disposition & ENABLED != 0,
                allowed: disposition & ALLOWED != 0,
            },
        });
    }
    entries
}

/// The path of a `file://` URL with an empty host, without the trailing `/` a folder's URL
/// has.
fn file_path(url: &str) -> PathBuf {
    let path = url.strip_prefix("file://").unwrap_or(url);
    let path = path
        .strip_suffix('/')
        .filter(|trimmed| !trimmed.is_empty())
        .unwrap_or(path);
    decode(path)
}

/// Decodes a URL path's `%XX` escapes into the bytes they stand for. An escape that is not two
/// hex digits is kept as written.
fn decode(text: &str) -> PathBuf {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escape = bytes
            .get(at + 1..at + 3)
            .filter(|hex| bytes[at] == b'%' && hex.iter().all(u8::is_ascii_hexdigit))
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        if let Some(byte) = escape {
            decoded.push(byte);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    PathBuf::from(OsStr::from_bytes(&decoded))
}

/// An `NSKeyedArchiver` archive: objects refer to each other by index into `$objects`, and
/// index 0 is `$null`, Objective-C's `nil`.
#[derive(Debug)]
struct Archive<'a> {
    top: &'a Dictionary,
    objects: &'a [Value],
}

impl<'a> Archive<'a> {
    fn new(root: &'a Value) -> Result<Self, String> {
        let root = root.as_dictionary().ok_or("not a keyed archive")?;
        if root.get("$archiver").and_then(Value::as_string) != Some("NSKeyedArchiver") {
            return Err("not an NSKeyedArchiver archive".to_owned());
        }
        let top = root.get("$top").and_then(Value::as_dictionary);
        let objects = root.get("$objects").and_then(Value::as_array);
        match (top, objects) {
            (Some(top), Some(objects)) => Ok(Self { top, objects }),
            _ => Err("a keyed archive without $top or $objects".to_owned()),
        }
    }

    /// Each user's records. The index of the per-user layout holds none; it is read only when
    /// no per-user file is beside it, such as before any user has a record.
    fn users(&self) -> Result<Vec<Vec<&'a Dictionary>>, String> {
        if let Some(store) = self.top.get("userStore") {
            let store = self.dictionary(store).ok_or("userStore is not an object")?;
            let records = store
                .get("records")
                .map(|r| self.array(r))
                .unwrap_or_default();
            return Ok(vec![Self::records(&records)]);
        }
        if let Some(store) = self.top.get("store") {
            let store = self.dictionary(store).ok_or("store is not an object")?;
            let users = store
                .get("itemsByUserIdentifier")
                .and_then(|users| self.dictionary(users))
                .and_then(|users| users.get("NS.objects"))
                .and_then(Value::as_array)
                .ok_or("store has no itemsByUserIdentifier")?;
            return Ok(users
                .iter()
                .map(|records| Self::records(&self.array(records)))
                .collect());
        }
        if self.top.contains_key("infoByUserIdentifier") {
            return Ok(Vec::new());
        }
        let keys: Vec<&str> = self.top.keys().map(String::as_str).collect();
        Err(format!(
            "no records where macOS keeps them; its top-level keys are {keys:?}"
        ))
    }

    /// The objects of `values` that are records. Anything else is left out, so a record
    /// macOS writes in another shape is not read rather than read wrong.
    fn records(values: &[&'a Value]) -> Vec<&'a Dictionary> {
        values
            .iter()
            .filter_map(|value| value.as_dictionary())
            .filter(|record| record.contains_key("type") && record.contains_key("disposition"))
            .collect()
    }

    /// The object `value` refers to, or `value` itself when it is not a reference. `None` for
    /// `nil` and for a reference past the end.
    fn object(&self, value: &'a Value) -> Option<&'a Value> {
        let Value::Uid(uid) = value else {
            return Some(value);
        };
        let object = self.objects.get(usize::try_from(uid.get()).ok()?)?;
        (object.as_string() != Some("$null")).then_some(object)
    }

    fn dictionary(&self, value: &'a Value) -> Option<&'a Dictionary> {
        self.object(value)?.as_dictionary()
    }

    /// The members of an `NSArray` or `NSSet`, each followed to its object.
    fn array(&self, value: &'a Value) -> Vec<&'a Value> {
        let members = self
            .dictionary(value)
            .and_then(|array| array.get("NS.objects"))
            .and_then(Value::as_array);
        members
            .into_iter()
            .flatten()
            .filter_map(|member| self.object(member))
            .collect()
    }

    /// A field that is a string, archived inline or as an `NSString` object.
    fn string(&self, record: &Dictionary, key: &str) -> Option<String> {
        let value = self.object(record.get(key)?)?;
        let text = match value {
            Value::String(text) => text,
            other => other.as_dictionary()?.get("NS.string")?.as_string()?,
        };
        Some(text.to_owned())
    }

    /// A field that is an integer; 0 when it is missing or not one.
    fn integer(record: &Dictionary, key: &str) -> u64 {
        record
            .get(key)
            .and_then(Value::as_unsigned_integer)
            .unwrap_or(0)
    }

    /// The record's `url`, an `NSURL`, as its relative text. Its base is left out: macOS 27.2
    /// gives a login item a path inside its app with the base `file:///`, though it means the
    /// app's own URL, as `DumpBTM`'s `toDictionary` joins them.
    fn url(&self, record: &Dictionary) -> Option<String> {
        let url = self.dictionary(record.get("url")?)?;
        self.string(url, "NS.relative")
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    use plist::Uid;

    /// Builds an archive the way `NSKeyedArchiver` lays one out, for tests.
    pub(crate) struct Archiver {
        objects: Vec<Value>,
    }

    /// One `ItemRecord`, by the fields the reader uses.
    pub(crate) struct Record<'a> {
        pub(crate) bits: u64,
        pub(crate) disposition: u64,
        pub(crate) identifier: &'a str,
        pub(crate) name: Option<&'a str>,
        pub(crate) url: Option<&'a str>,
        pub(crate) container: Option<&'a str>,
    }

    impl Archiver {
        pub(crate) fn new() -> Self {
            Self {
                objects: vec![Value::String("$null".to_owned())],
            }
        }

        fn add(&mut self, value: Value) -> Value {
            self.objects.push(value);
            Value::Uid(Uid::new(self.objects.len() as u64 - 1))
        }

        fn null() -> Value {
            Value::Uid(Uid::new(0))
        }

        fn text(&mut self, text: Option<&str>) -> Value {
            match text {
                Some(text) => self.add(Value::String(text.to_owned())),
                None => Self::null(),
            }
        }

        fn class(&mut self, name: &str) -> Value {
            let mut class = Dictionary::new();
            class.insert("$classname".to_owned(), Value::String(name.to_owned()));
            let classes = vec![Value::String(name.to_owned()), Value::from("NSObject")];
            class.insert("$classes".to_owned(), Value::Array(classes));
            self.add(Value::Dictionary(class))
        }

        fn object(&mut self, class: &str, fields: Vec<(&str, Value)>) -> Value {
            let mut object = Dictionary::new();
            object.insert("$class".to_owned(), self.class(class));
            for (key, value) in fields {
                object.insert(key.to_owned(), value);
            }
            self.add(Value::Dictionary(object))
        }

        pub(crate) fn array(&mut self, members: Vec<Value>) -> Value {
            self.object("NSArray", vec![("NS.objects", Value::Array(members))])
        }

        pub(crate) fn record(&mut self, record: &Record<'_>) -> Value {
            // As macOS 27.2 writes them: a path inside an app has the base `file:///`.
            let url = match record.url {
                Some(url) => {
                    let base = if url.starts_with("file://") {
                        Self::null()
                    } else {
                        let root = self.text(Some("file:///"));
                        let fields = vec![("NS.base", Self::null()), ("NS.relative", root)];
                        self.object("NSURL", fields)
                    };
                    let relative = self.text(Some(url));
                    self.object("NSURL", vec![("NS.base", base), ("NS.relative", relative)])
                }
                None => Self::null(),
            };
            let fields = vec![
                ("type", Value::from(record.bits)),
                ("disposition", Value::from(record.disposition)),
                ("identifier", self.text(Some(record.identifier))),
                ("name", self.text(record.name)),
                ("url", url),
                ("container", self.text(record.container)),
                ("executablePath", Self::null()),
            ];
            self.object("ItemRecord", fields)
        }

        /// The archive with `top` as its `$top`.
        pub(crate) fn finish(self, top: Vec<(&str, Value)>) -> Value {
            let mut root = Dictionary::new();
            root.insert("$archiver".to_owned(), Value::from("NSKeyedArchiver"));
            root.insert("$version".to_owned(), Value::from(100_000));
            root.insert("$objects".to_owned(), Value::Array(self.objects));
            let top = top.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
            root.insert("$top".to_owned(), Value::Dictionary(top));
            Value::Dictionary(root)
        }

        /// A per-user file, macOS 27's layout.
        pub(crate) fn user_file(records: &[Record<'_>]) -> Value {
            let mut archiver = Self::new();
            let members = records.iter().map(|r| archiver.record(r)).collect();
            let records = archiver.array(members);
            let user = archiver.text(Some("9AAA223B-56AB-4D42-B7BB-5E61E4615709"));
            let store = archiver.object(
                "Storage",
                vec![("records", records), ("userIdentifier", user)],
            );
            archiver.finish(vec![("userStore", store), ("version", Value::from(18))])
        }
    }

    pub(crate) fn write(path: &Path, archive: &Value) {
        archive.to_file_binary(path).unwrap();
    }

    fn record<'a>(bits: u64, identifier: &'a str, url: Option<&'a str>) -> Record<'a> {
        Record {
            bits,
            disposition: ALLOWED | ENABLED,
            identifier,
            name: Some("Name"),
            url,
            container: None,
        }
    }

    /// The entry's path, which the test expects it to have.
    fn found(entry: &Entry) -> &Path {
        match &entry.place {
            Place::Found(path) => path,
            Place::Unplaced { shown, why } => panic!("{shown} is not placed: {why}"),
        }
    }

    fn read_one(archive: &Value) -> Vec<Entry> {
        let tmp = tempfile::tempdir().unwrap();
        write(&tmp.path().join("BackgroundItems-v18-user.btm"), archive);
        let mut failures = Vec::new();
        let entries = read(tmp.path(), &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
        entries
    }

    #[test]
    fn records_no_launch_folder_shows_are_placed_inside_their_app() {
        let app = "file:///Applications/Grok%20Bot.app/";
        let records = [
            // The app itself: allowed, but it does not open at login.
            Record {
                disposition: ALLOWED,
                ..record(APP, "2.com.example", Some(app))
            },
            Record {
                container: Some("2.com.example"),
                ..record(
                    LOGIN_ITEM,
                    "4.helper",
                    Some("Contents/Library/LoginItems/H.app"),
                )
            },
            Record {
                container: Some("2.com.example"),
                disposition: ENABLED,
                ..record(
                    AGENT,
                    "8.agent",
                    Some("Contents/Library/LaunchAgents/a.plist"),
                )
            },
            Record {
                container: Some("2.com.example"),
                ..record(
                    DAEMON,
                    "16.daemon",
                    Some("Contents/Library/LaunchDaemons/d.plist"),
                )
            },
            record(APP, "2.opens", Some("file:///Applications/Warp.app/")),
            // Read from the launch folders instead.
            record(
                LEGACY | AGENT,
                "8.legacy",
                Some("file:///Library/LaunchAgents/l.plist"),
            ),
            // Turned off by its app, though allowed.
            Record {
                disposition: ALLOWED,
                ..record(LOGIN_ITEM, "4.off", Some("file:///Applications/Off.app/"))
            },
            // A developer's group, and an app's background task, which run nothing themselves.
            record(0x20, "Developer", None),
            record(0x2000, "8192.com.example", None),
        ];
        let entries = read_one(&Archiver::user_file(&records));

        let shown: Vec<(ItemKind, &str, bool, bool)> = entries
            .iter()
            .map(|e| {
                let path = found(e).to_str().unwrap();
                (e.kind, path, e.switches.enabled, e.switches.allowed)
            })
            .collect();
        let inside = "/Applications/Grok Bot.app/Contents/Library";
        assert_eq!(
            shown,
            [
                (
                    ItemKind::LoginItem,
                    &*format!("{inside}/LoginItems/H.app"),
                    true,
                    true
                ),
                (
                    ItemKind::AppLaunchAgent,
                    &*format!("{inside}/LaunchAgents/a.plist"),
                    true,
                    false
                ),
                (
                    ItemKind::AppLaunchDaemon,
                    &*format!("{inside}/LaunchDaemons/d.plist"),
                    true,
                    true
                ),
                (ItemKind::OpenAtLogin, "/Applications/Warp.app", true, true),
                (ItemKind::LoginItem, "/Applications/Off.app", false, true),
            ]
        );
        assert_eq!(entries[0].name.as_deref(), Some("Name"));
    }

    #[test]
    fn a_record_that_cannot_be_placed_is_kept_with_why() {
        let helper = Some("Contents/Library/LoginItems/A.app");
        let records = [
            Record {
                container: Some("2.gone"),
                ..record(LOGIN_ITEM, "4.a", helper)
            },
            // Its app's own location is relative too, so it is no place on disk.
            Record {
                disposition: ALLOWED,
                ..record(APP, "2.relative", Some("A.app"))
            },
            Record {
                container: Some("2.relative"),
                ..record(LOGIN_ITEM, "4.b", helper)
            },
            record(LOGIN_ITEM, "4.c", helper),
            record(LOGIN_ITEM, "4.d", None),
        ];
        let entries = read_one(&Archiver::user_file(&records));
        let shown: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| match &e.place {
                Place::Unplaced { shown, why } => (shown.as_str(), why.as_str()),
                Place::Found(path) => panic!("{} is placed", path.display()),
            })
            .collect();
        // Each is named by its identifier too, so records with the same text stay apart.
        let no_file = "has no file location among the records";
        assert_eq!(
            shown,
            [
                (
                    "4.a: Contents/Library/LoginItems/A.app",
                    &*format!("its app \"2.gone\" {no_file}")
                ),
                (
                    "4.b: Contents/Library/LoginItems/A.app",
                    &*format!("its app \"2.relative\" {no_file}")
                ),
                (
                    "4.c: Contents/Library/LoginItems/A.app",
                    "its location is relative to no app"
                ),
                ("4.d: (no location)", "it names no location"),
            ]
        );
    }

    #[test]
    fn an_object_without_both_record_fields_is_not_a_record() {
        let mut archiver = Archiver::new();
        let app = Some("file:///A.app/");
        let full = archiver.record(&record(APP, "2.a", app));
        // A login item is kept whatever its switches, so only the missing field leaves it out.
        let typed_only = archiver.object("ItemRecord", vec![("type", Value::from(LOGIN_ITEM))]);
        let records = archiver.array(vec![full, typed_only]);
        let store = archiver.object("Storage", vec![("records", records)]);
        let archive = archiver.finish(vec![("userStore", store)]);
        let entries = read_one(&archive);
        let paths: Vec<&Path> = entries.iter().map(found).collect();
        assert_eq!(paths, [Path::new("/A.app")]);
    }

    #[test]
    fn the_older_layout_maps_each_user_to_their_records() {
        let mut archiver = Archiver::new();
        let app = "file:///Applications/A.app/";
        let first = vec![archiver.record(&record(APP, "2.a", Some(app)))];
        // The same identifier for another user, whose own app record is elsewhere: each
        // user's login items resolve among their own records.
        let second = vec![
            archiver.record(&record(APP, "2.b", Some("file:///Users/b/B.app/"))),
            archiver.record(&Record {
                container: Some("2.b"),
                ..record(LOGIN_ITEM, "4.b", Some("Contents/Library/LoginItems/H.app"))
            }),
        ];
        let users = [archiver.array(first), archiver.array(second)];
        let keys = [archiver.text(Some("u1")), archiver.text(Some("u2"))];
        let map = archiver.object(
            "NSDictionary",
            vec![
                ("NS.keys", Value::Array(keys.to_vec())),
                ("NS.objects", Value::Array(users.to_vec())),
            ],
        );
        let store = archiver.object("Storage", vec![("itemsByUserIdentifier", map)]);
        let archive = archiver.finish(vec![("store", store), ("version", Value::from(16))]);

        let entries = read_one(&archive);
        let paths: Vec<&Path> = entries.iter().map(found).collect();
        assert_eq!(
            paths,
            [
                Path::new("/Applications/A.app"),
                Path::new("/Users/b/B.app"),
                Path::new("/Users/b/B.app/Contents/Library/LoginItems/H.app"),
            ]
        );
    }

    #[test]
    fn only_the_newest_files_are_read_and_a_bad_one_does_not_hide_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let old = Archiver::user_file(&[record(APP, "2.old", Some("file:///Old.app/"))]);
        write(&tmp.path().join("BackgroundItems-v16.btm"), &old);
        let new = Archiver::user_file(&[record(APP, "2.new", Some("file:///New.app/"))]);
        write(&tmp.path().join("BackgroundItems-v18-a.btm"), &new);
        // The index beside per-user files is not read, so a change to it fails nothing.
        fs::write(
            tmp.path().join("BackgroundItems-v18.btm"),
            "a changed index",
        )
        .unwrap();
        fs::write(tmp.path().join("BackgroundItems-v18-b.btm"), "not a plist").unwrap();
        let unknown = Archiver::new().finish(vec![("other", Archiver::null())]);
        write(&tmp.path().join("BackgroundItems-v18-c.btm"), &unknown);
        fs::write(tmp.path().join("notes.txt"), "").unwrap();

        let mut failures = Vec::new();
        let entries = read(tmp.path(), &mut failures);
        let paths: Vec<&Path> = entries.iter().map(found).collect();
        assert_eq!(paths, [Path::new("/New.app")]);
        let errors: Vec<String> = failures.iter().map(ToString::to_string).collect();
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(
            errors[0].contains("v18-b.btm: not a property list"),
            "{errors:?}"
        );
        assert!(
            errors[1].contains("v18-c.btm: no records where macOS keeps them")
                && errors[1].contains("[\"other\"]"),
            "{errors:?}"
        );
        assert!(failures.iter().all(InventoryError::is_failure));
    }

    #[test]
    fn an_index_with_no_per_user_file_beside_it_has_no_records() {
        let tmp = tempfile::tempdir().unwrap();
        let users = Value::Dictionary(Dictionary::new());
        let index = Archiver::new().finish(vec![("infoByUserIdentifier", users)]);
        write(&tmp.path().join("BackgroundItems-v18.btm"), &index);
        let mut failures = Vec::new();
        assert!(read(tmp.path(), &mut failures).is_empty());
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn a_folder_that_is_not_there_has_no_records_and_needs_no_access() {
        let tmp = tempfile::tempdir().unwrap();
        let gone = tmp.path().join("gone");
        let mut failures = Vec::new();
        assert!(read(&gone, &mut failures).is_empty());
        assert!(failures.is_empty());
        assert!(!needs_full_disk_access(&gone));
        assert!(!needs_full_disk_access(tmp.path()));
    }

    #[test]
    fn a_folder_macos_will_not_list_is_a_note_and_any_other_error_a_failure() {
        use std::os::unix::fs::PermissionsExt as _;

        // As macOS answers a process without Full Disk Access: permission denied.
        let tmp = tempfile::tempdir().unwrap();
        let locked = tmp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let mut failures = Vec::new();
        let entries = read(&locked, &mut failures);
        let needs = needs_full_disk_access(&locked);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(entries.is_empty() && needs);
        let [note] = &failures[..] else {
            panic!("one note: {failures:?}");
        };
        assert!(matches!(note, InventoryError::FullDiskAccess { .. }));
        assert!(!note.is_failure());
        assert!(
            note.to_string().contains("needs Full Disk Access"),
            "{note}"
        );

        let file = tmp.path().join("file");
        fs::write(&file, "").unwrap();
        let mut failures = Vec::new();
        assert!(read(&file, &mut failures).is_empty());
        let [failure] = &failures[..] else {
            panic!("one failure: {failures:?}");
        };
        assert!(matches!(failure, InventoryError::Io { .. }) && failure.is_failure());
        assert!(!needs_full_disk_access(&file));
    }

    #[test]
    fn a_file_up_to_the_limit_is_read_and_a_larger_one_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        // XML, which can hold no reference (`Uid`), so the store is inline and empty.
        let users = Dictionary::from_iter([("NS.objects".to_owned(), Value::Array(Vec::new()))]);
        let store =
            Dictionary::from_iter([("itemsByUserIdentifier".to_owned(), Value::Dictionary(users))]);
        let archive = Archiver::new().finish(vec![("store", Value::Dictionary(store))]);
        let mut xml = Vec::new();
        archive.to_writer_xml(&mut xml).unwrap();
        // Padded with a comment after the root element to exactly the limit.
        let pad = usize::try_from(FILE_LIMIT).unwrap() - xml.len() - "<!--  -->".len();
        xml.extend(format!("<!-- {} -->", " ".repeat(pad)).bytes());
        let path = tmp.path().join("BackgroundItems-v18.btm");
        fs::write(&path, &xml).unwrap();
        assert_eq!(read_file(&path).map(|entries| entries.len()), Ok(0));

        xml.push(b'\n');
        fs::write(&path, &xml).unwrap();
        let error = read_file(&path).unwrap_err();
        assert_eq!(error, format!("more than the {FILE_LIMIT} bytes read"));
    }

    #[test]
    fn file_names_give_their_version() {
        let v = |name: &str| version(OsStr::new(name)).map(|v| (v.number, v.per_user));
        assert_eq!(v("BackgroundItems-v18.btm"), Some((18, false)));
        assert_eq!(v("BackgroundItems-v18-9AAA-56AB.btm"), Some((18, true)));
        assert_eq!(v("BackgroundItems-v4.btm"), Some((4, false)));
        assert_eq!(v("BackgroundItems-v.btm"), None);
        assert_eq!(v("BackgroundItems-v18.btm.tmp"), None);
        assert_eq!(v("backgrounditems.btm"), None);
    }

    #[test]
    fn url_paths_are_decoded_to_their_bytes() {
        assert_eq!(file_path("file:///A%20B.app/"), Path::new("/A B.app"));
        assert_eq!(file_path("file:///"), Path::new("/"));
        assert_eq!(decode("%E2%9C%93"), Path::new("\u{2713}"));
        assert_eq!(decode("%FF").as_os_str().as_bytes(), [0xFF]);
        assert_eq!(decode("100%"), Path::new("100%"));
        assert_eq!(decode("%zz%2"), Path::new("%zz%2"));
        assert_eq!(
            decode("%+F%-1"),
            Path::new("%+F%-1"),
            "from_str_radix takes a sign"
        );
    }
}
