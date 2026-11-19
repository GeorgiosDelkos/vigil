//! System extensions, from the database `sysextd` keeps in `/Library/SystemExtensions/db.plist`.
//!
//! Each record names the extension's bundle inside the app that shipped it (`originPath`), the
//! copy macOS runs (`stagedBundleURL`, under `/Library/SystemExtensions/<UUID>/`), its `state`
//! (`activated_enabled`, `activated_waiting_for_user`, `terminated_waiting_to_uninstall_on_
//! reboot`, ...), the team the app claimed (`teamID`) and its `categories`: a network,
//! endpoint security or driver extension. The layout is the one KnockKnock
//! ([SystemExtensions.m](https://github.com/objective-see/KnockKnock/blob/914f2c0c2d3f058f40b6d98ed303e8a1a6715eb3/Plugins/SystemExtensions.m#L48))
//! and Datadog's agent
//! ([collector_darwin_sysext.go](https://github.com/DataDog/datadog-agent/blob/c40df5abac12987f9c3682f348f45b0e776442f0/pkg/inventory/software/collector_darwin_sysext.go#L23))
//! read. The Mac this was written on had no system extension, so the tests build that layout.
//!
//! An item is named by `originPath`: an update stages its copy under a new UUID, and naming the
//! item by that copy would show a dismissed extension again after every update. macOS keeps a
//! record per version until the old one is removed at reboot, so one path can have several
//! records; the one that runs is kept ([`read`]).

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::inventory::InventoryError;
use crate::inventory::host::background::file_path;
use crate::paths;

/// The database, under [`super::system_root`].
pub(super) const DATABASE: &str = "Library/SystemExtensions/db.plist";

/// The largest database read. Arbitrary: a record is about 1 kB, and a Mac has a handful.
const DATABASE_LIMIT: u64 = 4 * 1024 * 1024;

/// One system extension.
#[derive(Debug)]
pub(super) struct SystemExtension {
    /// The bundle inside its app, which names the item; the staged copy when the record names
    /// no app.
    pub(super) origin: PathBuf,
    /// The copy that runs, when the record names one.
    pub(super) staged: Option<PathBuf>,
    pub(super) record: Record,
}

impl SystemExtension {
    /// Whether macOS runs it: only an enabled extension runs.
    pub(super) fn runs(&self) -> bool {
        self.record.state.as_deref() == Some("activated_enabled")
    }
}

/// What a record says besides its paths, as the bundle shows it.
#[derive(Debug, Serialize)]
pub(super) struct Record {
    pub(super) identifier: Option<String>,
    /// The team the app's signature named when it asked for the extension. The staged copy's
    /// own signature is checked as well, so this is a claim to compare, not proof.
    pub(super) team: Option<String>,
    pub(super) state: Option<String>,
    pub(super) categories: Vec<String>,
}

/// The parts of the database read. Fields of another type than these fail the whole file:
/// `sysextd` writes it, so a file that does not match is not one to guess at.
#[derive(Debug, Deserialize)]
struct Database {
    #[serde(default)]
    extensions: Vec<RawRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRecord {
    identifier: Option<String>,
    #[serde(rename = "teamID")]
    team_id: Option<String>,
    state: Option<String>,
    #[serde(default)]
    categories: Vec<String>,
    origin_path: Option<String>,
    #[serde(rename = "stagedBundleURL")]
    staged_bundle_url: Option<Url>,
}

/// An archived `NSURL`: `relative` is the whole `file://` URL, with no base.
#[derive(Debug, Deserialize)]
struct Url {
    relative: Option<String>,
}

/// Reads the database at `path`, one extension per path. A database that is not there (no
/// system extension was ever installed) has none. Of the records for one path, the first that
/// is `activated_enabled` is kept, else the first: only an enabled one runs.
pub(super) fn read(path: &Path) -> Result<Vec<SystemExtension>, InventoryError> {
    let bytes = match paths::read_capped(path, DATABASE_LIMIT + 1) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            let path = path.to_owned();
            return Err(InventoryError::Io { path, source });
        }
    };
    let parse_error = |detail: String| InventoryError::Parse {
        what: path.display().to_string(),
        detail,
    };
    if bytes.len() as u64 > DATABASE_LIMIT {
        return Err(parse_error(format!(
            "it is more than the {DATABASE_LIMIT} bytes read"
        )));
    }
    let database: Database = plist::from_bytes(&bytes).map_err(|e| parse_error(e.to_string()))?;

    let mut at: HashMap<PathBuf, usize> = HashMap::new();
    let mut extensions: Vec<SystemExtension> = Vec::new();
    for raw in database.extensions {
        let staged = raw
            .staged_bundle_url
            .and_then(|url| url.relative)
            .filter(|url| url.starts_with("file://"))
            .map(|url| file_path(&url));
        let Some(origin) = raw
            .origin_path
            .map(PathBuf::from)
            .or_else(|| staged.clone())
        else {
            let name = raw.identifier.as_deref().unwrap_or("with no identifier");
            return Err(parse_error(format!(
                "the record {name} names neither its app's copy nor the staged one"
            )));
        };
        let extension = SystemExtension {
            origin,
            staged,
            record: Record {
                identifier: raw.identifier,
                team: raw.team_id,
                state: raw.state,
                categories: raw.categories,
            },
        };
        match at.entry(extension.origin.clone()) {
            Entry::Occupied(index) => {
                let kept = &mut extensions[*index.get()];
                if !kept.runs() && extension.runs() {
                    *kept = extension;
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(extensions.len());
                extensions.push(extension);
            }
        }
    }
    Ok(extensions)
}

#[cfg(test)]
pub(super) mod tests {
    use std::fs;

    use super::*;

    /// A database as `sysextd` writes it, one `<dict>` per record in `records`.
    pub(in crate::inventory::host) fn database(records: &[String]) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>bootUUID</key><string>0</string>\
             <key>extensions</key><array>{}</array>\
             <key>extensionPolicies</key><array/>\
             <key>version</key><integer>1</integer>\
             </dict></plist>\n",
            records.concat()
        )
    }

    /// One record of an endpoint security extension, from `app`, staged at `staged`.
    pub(in crate::inventory::host) fn record(app: &str, staged: &str, state: &str) -> String {
        format!(
            "<dict>\
             <key>categories</key><array>\
             <string>com.apple.system_extension.endpoint_security</string></array>\
             <key>identifier</key><string>com.example.agent</string>\
             <key>originPath</key><string>{app}</string>\
             <key>stagedBundleURL</key><dict><key>relative</key><string>{staged}</string></dict>\
             <key>state</key><string>{state}</string>\
             <key>teamID</key><string>ABCDE12345</string>\
             <key>uniqueID</key><string>1</string>\
             </dict>"
        )
    }

    fn read_text(text: &str) -> Result<Vec<SystemExtension>, InventoryError> {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.plist");
        fs::write(&path, text).unwrap();
        read(&path)
    }

    #[test]
    fn a_record_gives_its_paths_and_what_it_says() {
        let app = "/Applications/A.app/Contents/Library/SystemExtensions/x.systemextension";
        let staged = "file:///Library/SystemExtensions/U-1/My%20X.systemextension/";
        let found = read_text(&database(&[record(app, staged, "activated_enabled")])).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin, Path::new(app));
        let copy = Path::new("/Library/SystemExtensions/U-1/My X.systemextension");
        assert_eq!(found[0].staged.as_deref(), Some(copy));
        assert_eq!(
            serde_json::to_value(&found[0].record).unwrap(),
            serde_json::json!({
                "identifier": "com.example.agent",
                "team": "ABCDE12345",
                "state": "activated_enabled",
                "categories": ["com.apple.system_extension.endpoint_security"],
            })
        );
    }

    #[test]
    fn of_several_records_for_one_app_the_enabled_one_is_kept() {
        let app = "/Applications/A.app/Contents/Library/SystemExtensions/x.systemextension";
        let old = record(
            app,
            "file:///old/",
            "terminated_waiting_to_uninstall_on_reboot",
        );
        let new = record(app, "file:///new/", "activated_enabled");
        let waiting = record(app, "file:///waiting/", "activated_waiting_for_user");
        let other = record("/Applications/B.app/x", "file:///b/", "activated_enabled");

        let found = read_text(&database(&[old.clone(), new, waiting, other])).unwrap();
        let staged: Vec<_> = found.iter().map(|e| e.staged.as_deref()).collect();
        assert_eq!(staged, [Some(Path::new("/new")), Some(Path::new("/b"))]);

        // With none enabled, the first is kept.
        let waiting = record(app, "file:///waiting/", "activated_waiting_for_user");
        let found = read_text(&database(&[old, waiting])).unwrap();
        assert_eq!(found[0].staged.as_deref(), Some(Path::new("/old")));
    }

    #[test]
    fn a_record_without_its_app_is_named_by_its_copy() {
        let staged = "<dict><key>stagedBundleURL</key><dict><key>relative</key>\
                      <string>file:///Library/SystemExtensions/U/x.systemextension/</string>\
                      </dict></dict>";
        let found = read_text(&database(&[staged.to_owned()])).unwrap();
        let copy = Path::new("/Library/SystemExtensions/U/x.systemextension");
        assert_eq!(found[0].origin, copy);
        assert_eq!(found[0].record.categories, Vec::<String>::new());

        // A URL that is not a file's is no path.
        let web = "<dict><key>originPath</key><string>/A.app/x</string>\
                   <key>stagedBundleURL</key><dict><key>relative</key>\
                   <string>https://e.x/x</string></dict></dict>";
        let found = read_text(&database(&[web.to_owned()])).unwrap();
        assert_eq!(found[0].staged, None);
    }

    #[test]
    fn a_database_that_is_missing_has_none_and_one_that_does_not_parse_fails() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read(&tmp.path().join("db.plist")).unwrap().is_empty());
        assert!(read_text(&database(&[])).unwrap().is_empty());

        let pathless = "<dict><key>identifier</key><string>com.e.x</string></dict>";
        let error = read_text(&database(&[pathless.to_owned()])).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("the record com.e.x names neither its app's copy nor the staged one"),
            "{error}"
        );
        let wrong = "<dict><key>originPath</key><integer>1</integer></dict>";
        let error = read_text(&database(&[wrong.to_owned()])).unwrap_err();
        assert!(matches!(error, InventoryError::Parse { .. }), "{error}");

        // Exactly the limit is read; one byte more is not.
        let text = database(&[]);
        let limit = usize::try_from(DATABASE_LIMIT).unwrap();
        let padded = format!(
            "{text}<!-- {} -->",
            " ".repeat(limit - text.len() - "<!--  -->".len())
        );
        assert!(read_text(&padded).unwrap().is_empty());
        let error = read_text(&format!("{padded}\n")).unwrap_err();
        assert!(error.to_string().contains("more than the"), "{error}");

        let folder = tmp.path().join("folder");
        fs::create_dir(&folder).unwrap();
        assert!(matches!(read(&folder), Err(InventoryError::Io { .. })));
    }
}
