//! Lockfiles in project folders: `Cargo.lock`, `package-lock.json`, `npm-shrinkwrap.json`,
//! `uv.lock` and `poetry.lock`.
//!
//! The walk never follows symlinks and skips vendored, build and hidden folders, so it reads
//! each project's own lockfile and not the copies dependencies ship. It also skips folders
//! Finder hides, macOS packages (apps, Photos libraries), `~/Library`, iCloud files and folders
//! not downloaded, and other disks and network shares mounted under a project folder. So a
//! home folder chosen as a project folder does not lead into Mail, Messages or Photos and
//! downloads nothing; macOS still asks once for `~/Desktop`, `~/Documents` and `~/Downloads`,
//! which the user chose by choosing the home folder. It is bounded: a million entries per
//! project folder, ten minutes in all, and the sweep's cancel. Only packages from a
//! registry are kept: workspace members, local paths and git checkouts have no registry
//! advisories under their name.
//!
//! Registries other than the public one are treated differently per ecosystem, on purpose.
//! `Cargo.lock` records crates.io even when the index is mirrored, so any other Cargo registry
//! holds different crates, which are noted and left out. npm and Python lockfiles record the
//! mirror's own URL, and corporate mirrors of npmjs and PyPI are common, so their packages are
//! kept and looked up under the public name.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::os::macos::fs::MetadataExt as _;
use std::panic;
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use serde::Deserialize;

use crate::cancel::Cancel;
use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::InventorySource;
use crate::inventory::Lookup;
use crate::package::Ecosystem;
use crate::package::Package;

/// Folders never entered, besides every hidden one.
pub(crate) const SKIPPED_DIRS: &[&str] = &["node_modules", "target", "vendor", "dist", "build"];

/// Extensions of the macOS packages the walk does not enter: folders Finder shows as one file.
/// An app, bundle or framework holds its vendor's files, not a project's lockfile, and a Photos
/// library is the user's photos, behind a macOS privacy prompt. Kept to the kinds a home
/// folder holds many of.
const PACKAGES: [&str; 4] = ["app", "bundle", "framework", "photoslibrary"];

/// The `st_flags` bit Finder hides a file by (`UF_HIDDEN` in `<sys/stat.h>`). `~/Library` has
/// it, and so do other folders macOS keeps out of sight.
const UF_HIDDEN: u32 = 0x8000;

/// The `st_flags` bit of a file or folder whose contents are not on this Mac (`SF_DATALESS` in
/// `<sys/stat.h>`): iCloud Drive's "Optimize Mac Storage" leaves such placeholders, and
/// reading one, or listing one that is a folder, downloads it. `stat` does not.
const SF_DATALESS: u32 = 0x4000_0000;

/// How many entries the walk lists in one project folder. Arbitrary: a folder of projects lists
/// thousands (about 3,300 under the owner's `~/Documents/Github` on 2026-11-12, with the skipped
/// folders left out), so a million is far past any project tree. A local disk lists that many in
/// seconds: `find` listed 66,000 entries in a quarter of a second on the same Mac, warm.
const ENTRY_LIMIT: usize = 1_000_000;

/// How long the walk of every project folder may take. Arbitrary: [`ENTRY_LIMIT`] entries take
/// seconds on a local disk, so a walk still running after ten minutes is held up by a folder
/// that does not answer.
const WALK_TIMEOUT: Duration = Duration::from_mins(10);

/// How often the walk is checked for having finished, been cancelled or run out of time.
/// Arbitrary: a cancel within a fifth of a second feels immediate.
const POLL: Duration = Duration::from_millis(200);

/// Walks every folder in `roots` and adds every package in every lockfile found. Stops when
/// `cancel` is set or after [`WALK_TIMEOUT`], which is then a problem naming the project folder
/// it stopped in; the folders walked before it still count.
pub(super) fn collect(roots: &[PathBuf], inventory: &mut Inventory, cancel: &Cancel) {
    // `~/Library` is hidden by Finder's flag, which "Show Library Folder" clears, so it is
    // named too: it holds Mail, Messages and iCloud Drive, behind privacy prompts. `~/.Trash`
    // needs no entry, as every dot-named folder is skipped by name.
    let never: Vec<PathBuf> = std::env::home_dir()
        .into_iter()
        .map(|home| home.join("Library"))
        .collect();
    let (walked, stopped) = bounded(cancel, WALK_TIMEOUT, roots, move |root, stop| {
        let bounds = Bounds {
            never: &never,
            stop,
            limit: ENTRY_LIMIT,
        };
        let mut found = Inventory::default();
        walk(root, &bounds, &mut found);
        found
    });
    add_walks(inventory, roots, walked, stopped);
}

/// Adds what [`bounded`] returned for `roots` to `inventory`: each finished walk, then why the
/// walk stopped, if it did. A walk that stopped did so in the root after the last one it
/// finished and walked none after that, so those roots count as unread.
fn add_walks(
    inventory: &mut Inventory,
    roots: &[PathBuf],
    walked: Vec<Inventory>,
    stopped: Option<InventoryError>,
) {
    let unfinished = &roots[walked.len()..];
    for found in walked {
        inventory.components.extend(found.components);
        inventory.problems.extend(found.problems);
        inventory.failed.extend(found.failed);
    }
    if let Some(stopped) = stopped {
        let sources = unfinished
            .iter()
            .map(|root| InventorySource::LockfileWalk { root: root.clone() });
        inventory.failed.extend(sources);
        inventory.problems.push(stopped);
    }
}

/// Runs `walk` on each of `roots` in turn, on its own thread, and returns each finished
/// result, in order. Stops waiting when `cancel` is set or `timeout` passes, returning why,
/// naming the root it stopped in; either also sets the [`Cancel`] `walk` is given, which it
/// checks once per folder.
///
/// On its own thread because a folder on a network share whose server is gone can block a
/// system call for good, which no check between folders reaches. That thread is then left
/// blocked, and the sweep goes on. Accepted: it is one thread, holding nothing the sweep needs,
/// and it ends once the call returns.
fn bounded(
    cancel: &Cancel,
    timeout: Duration,
    roots: &[PathBuf],
    mut walk: impl FnMut(&Path, &Cancel) -> Inventory + Send + 'static,
) -> (Vec<Inventory>, Option<InventoryError>) {
    let mut walked = Vec::new();
    let cancelled = |root: &Path| InventoryError::Cancelled {
        what: format!("the lockfile walk of {}", root.display()),
    };
    let Some(first) = roots.first() else {
        return (walked, None);
    };
    if cancel.is_cancelled() {
        return (walked, Some(cancelled(first)));
    }
    let stop = Cancel::new();
    // One message per root, so a send never blocks; it fails only once the waiter gave up.
    let (tx, rx) = mpsc::sync_channel(roots.len());
    let walker = {
        let (stop, roots) = (stop.clone(), roots.to_vec());
        thread::spawn(move || {
            for root in &roots {
                if tx.send(walk(root, &stop)).is_err() {
                    return;
                }
            }
        })
    };
    let deadline = Instant::now() + timeout;
    while let Some(root) = roots.get(walked.len()) {
        match rx.recv_timeout(POLL) {
            Ok(found) => {
                walked.push(found);
                continue;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => match walker.join() {
                Err(panic) => panic::resume_unwind(panic),
                Ok(()) => unreachable!("the walker sends a result for every root before it ends"),
            },
        }
        if cancel.is_cancelled() {
            stop.cancel();
            return (walked, Some(cancelled(root)));
        }
        if Instant::now() >= deadline {
            stop.cancel();
            let root = root.clone();
            return (
                walked,
                Some(InventoryError::WalkTimedOut {
                    root,
                    limit: timeout,
                }),
            );
        }
    }
    (walked, None)
}

/// What bounds a walk besides the folders it skips by name.
struct Bounds<'a> {
    /// Folders never entered: `~/Library`.
    never: &'a [PathBuf],
    /// Set when the walk is to stop; whoever sets it reports why.
    stop: &'a Cancel,
    /// How many entries the walk lists in one project folder.
    limit: usize,
}

/// Walks `root` and adds every package in every lockfile found, staying on `root`'s device:
/// another device under it is a mounted disk or network share, which can be slow or hang.
fn walk(root: &Path, bounds: &Bounds<'_>, inventory: &mut Inventory) {
    // Listed once here as well as in the walk, so a project folder that cannot be listed at all
    // is told apart from a folder under it.
    let device = match fs::metadata(root).and_then(|meta| fs::read_dir(root).map(|_| meta)) {
        Ok(meta) => meta.st_dev(),
        Err(e) => {
            unopened_root(inventory, root, e);
            return;
        }
    };
    let mut left = bounds.limit;
    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        if bounds.stop.is_cancelled() {
            return;
        }
        let Some(entries) = list(&dir, device, bounds.never, &mut left, inventory) else {
            inventory.problems.push(InventoryError::TooManyEntries {
                root: root.to_owned(),
                limit: bounds.limit,
            });
            return;
        };
        for (path, kind) in entries {
            match kind {
                Entry::Dir => pending.push(path),
                Entry::File => read(&path, inventory),
            }
        }
    }
}

/// What a folder entry is to the walk.
enum Entry {
    /// A folder to enter.
    Dir,
    /// A regular file.
    File,
}

/// Returns `dir`'s entries the walk cares about, sorted by name: folders it enters (see
/// [`entered`]) and regular files. Symlinks, skipped folders and unreadable entries are left
/// out, the last recorded with [`unwalked`]. Each entry read counts against `left`; `None` once
/// that runs out, before the rest of `dir` is read.
fn list(
    dir: &Path,
    device: u64,
    never: &[PathBuf],
    left: &mut usize,
    inventory: &mut Inventory,
) -> Option<Vec<(PathBuf, Entry)>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            unwalked(inventory, dir, e);
            return Some(Vec::new());
        }
    };
    let mut listed = Vec::new();
    for entry in entries {
        *left = left.checked_sub(1)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                unwalked(inventory, dir, e);
                continue;
            }
        };
        // `DirEntry::file_type` does not follow symlinks, so a link is neither a dir nor a
        // file here and is skipped.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                unwalked(inventory, &entry.path(), e);
                continue;
            }
        };
        if file_type.is_file() {
            listed.push((entry.path(), Entry::File));
        } else if file_type.is_dir() {
            let path = entry.path();
            if !named_to_enter(&path) || never.contains(&path) {
                continue;
            }
            // Not followed: `DirEntry::metadata` reads the entry itself, and it is a folder.
            match entry.metadata() {
                Ok(meta) if entered(&meta, device) => listed.push((path, Entry::Dir)),
                Ok(_) => {}
                Err(e) => unwalked(inventory, &path, e),
            }
        }
    }
    listed.sort_by(|a, b| a.0.cmp(&b.0));
    Some(listed)
}

/// Records that `path`, a folder or an entry the walk could not tell, could not be read, so
/// no lockfile at or under it was. One this user may not read is a problem only
/// ([`InventoryError::is_failure`] says why).
fn unwalked(inventory: &mut Inventory, path: &Path, error: std::io::Error) {
    let source = InventorySource::LockfileWalk {
        root: path.to_owned(),
    };
    inventory.fail(source, InventoryError::io(path, error));
}

/// Records that the project folder `root` could not be listed: a failed source whatever the
/// cause, permission included, unlike a folder under it ([`InventoryError::ProjectFolder`]).
fn unopened_root(inventory: &mut Inventory, root: &Path, source: std::io::Error) {
    let error = InventoryError::ProjectFolder {
        root: root.to_owned(),
        source,
    };
    let unwalked = InventorySource::LockfileWalk {
        root: root.to_owned(),
    };
    inventory.fail(unwalked, error);
}

/// Returns whether the walk may enter the folder at `path` by its name: not hidden by a dot,
/// not vendored or built, and not a macOS package.
fn named_to_enter(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let package = path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| PACKAGES.iter().any(|p| p.eq_ignore_ascii_case(ext)));
    !name.starts_with('.') && !SKIPPED_DIRS.contains(&name.as_ref()) && !package
}

/// Returns whether the walk enters a folder with metadata `meta`: not hidden by Finder's flag,
/// on this Mac rather than only in iCloud, and on `device`, the project folder's.
fn entered(meta: &fs::Metadata, device: u64) -> bool {
    meta.st_flags() & (UF_HIDDEN | SF_DATALESS) == 0 && meta.st_dev() == device
}

/// Adds the packages of `path` if it is a lockfile this module reads.
fn read(path: &Path, inventory: &mut Inventory) {
    if !is_lockfile(path) {
        return;
    }
    let found = read_lockfile(path).and_then(|text| {
        parse(path, &text, &mut inventory.problems).expect("checked to be a lockfile name")
    });
    let source = InventorySource::Lockfile {
        path: path.to_owned(),
    };
    inventory.absorb(source, found);
}

/// The lockfile names this module reads.
pub(crate) const NAMES: [&str; 5] = [
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "uv.lock",
    "poetry.lock",
];

fn is_lockfile(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| NAMES.contains(&name))
}

/// Parses `text`, the lockfile at `path` (which may be on another machine), by its file name.
/// Returns `None` when the name is not one of [`NAMES`].
pub(crate) fn parse(
    path: &Path,
    text: &str,
    problems: &mut Vec<InventoryError>,
) -> Option<Result<Vec<Component>, InventoryError>> {
    let name = path.file_name().and_then(OsStr::to_str)?;
    let found = match name {
        "Cargo.lock" => parse_cargo_lock(path, text, problems),
        // npm-shrinkwrap.json is a package-lock.json that a package publishes with itself.
        "package-lock.json" | "npm-shrinkwrap.json" => parse_package_lock(path, text),
        "uv.lock" => parse_uv_lock(path, text),
        "poetry.lock" => parse_poetry_lock(path, text),
        _ => return None,
    };
    Some(found)
}

/// The largest lockfile read, in bytes. Arbitrary: the biggest real lockfiles are a few MB, and
/// a file far past that is not one, so it is reported instead of read into memory.
const LOCKFILE_LIMIT: u64 = 64 * 1024 * 1024;

fn read_lockfile(path: &Path) -> Result<String, InventoryError> {
    let meta = fs::metadata(path).map_err(|e| InventoryError::io(path, e))?;
    if meta.st_flags() & SF_DATALESS != 0 {
        return Err(InventoryError::CloudOnly {
            path: path.to_owned(),
        });
    }
    let len = meta.len();
    if len > LOCKFILE_LIMIT {
        return Err(InventoryError::TooLarge {
            path: path.to_owned(),
            len,
            limit: LOCKFILE_LIMIT,
        });
    }
    fs::read_to_string(path).map_err(|e| InventoryError::io(path, e))
}

fn component(path: &Path, ecosystem: Ecosystem, name: String, version: String) -> Component {
    Component {
        lookup: Lookup::Package(Package { ecosystem, name }),
        version,
        found_in: FoundIn::Lockfile {
            path: path.to_owned(),
        },
    }
}

fn parse_error(path: &Path, detail: &impl ToString) -> InventoryError {
    InventoryError::parse(path.display().to_string(), detail)
}

/// Packages from crates.io, by either index protocol; see the module docs for why another
/// Cargo registry is noted and left out. Workspace members have no source and git ones `git+`.
const CRATES_IO_SOURCES: &[&str] = &[
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

fn parse_cargo_lock(
    path: &Path,
    text: &str,
    notes: &mut Vec<InventoryError>,
) -> Result<Vec<Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Entry>,
    }
    #[derive(Debug, Deserialize)]
    struct Entry {
        name: String,
        version: String,
        source: Option<String>,
    }

    let lock: Lock = toml::from_str(text).map_err(|e| parse_error(path, &e))?;
    let mut components = Vec::new();
    let mut other_registries = BTreeSet::new();
    for p in lock.package {
        match p.source.as_deref() {
            Some(source) if CRATES_IO_SOURCES.contains(&source) => {
                components.push(component(path, Ecosystem::CratesIo, p.name, p.version));
            }
            Some(source) if source.starts_with("registry+") || source.starts_with("sparse+") => {
                other_registries.insert(source.to_owned());
            }
            _ => {}
        }
    }
    notes.extend(
        other_registries
            .into_iter()
            .map(|registry| InventoryError::OtherRegistry {
                path: path.to_owned(),
                registry,
            }),
    );
    Ok(components)
}

/// `lockfileVersion` 2 and 3 list every installed package under `packages`, keyed by its
/// `node_modules/...` path. Version 1 (npm 6 and older) has a different shape and is reported
/// rather than guessed at.
fn parse_package_lock(path: &Path, text: &str) -> Result<Vec<Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Lock {
        lockfile_version: u32,
        #[serde(default)]
        packages: BTreeMap<String, Entry>,
    }
    #[derive(Debug, Deserialize)]
    struct Entry {
        /// Set when the installed name differs from the folder (an npm alias).
        name: Option<String>,
        version: Option<String>,
        #[serde(default)]
        link: bool,
        /// Where it came from: a registry tarball (`https://...`), or a `git+`, `github:`,
        /// `file:` or `link:` spec for a dependency that is not a registry package. Only
        /// registry tarballs, or no `resolved` at all (bundled dependencies), are kept.
        resolved: Option<String>,
    }

    let lock: Lock = serde_json::from_str(text).map_err(|e| parse_error(path, &e))?;
    if lock.lockfile_version < 2 {
        return Err(parse_error(
            path,
            &"lockfileVersion 1 is not supported; upgrade it by running `npm install` with npm 7+",
        ));
    }
    Ok(lock
        .packages
        .into_iter()
        .filter(|(_, entry)| !entry.link)
        .filter(|(_, entry)| {
            entry
                .resolved
                .as_deref()
                .is_none_or(|r| r.starts_with("https://") || r.starts_with("http://"))
        })
        .filter_map(|(key, entry)| {
            // The root project is the "" key; nested copies are `node_modules/a/node_modules/b`.
            let folder_name = key.rsplit_once("node_modules/").map(|(_, name)| name)?;
            let name = entry.name.unwrap_or_else(|| folder_name.to_owned());
            Some(component(path, Ecosystem::Npm, name, entry.version?))
        })
        .collect())
}

/// Packages whose `source` is a `registry`; editable, virtual, path and git ones are local.
fn parse_uv_lock(path: &Path, text: &str) -> Result<Vec<Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Entry>,
    }
    #[derive(Debug, Deserialize)]
    struct Entry {
        name: String,
        version: Option<String>,
        #[serde(default)]
        source: BTreeMap<String, toml::Value>,
    }

    let lock: Lock = toml::from_str(text).map_err(|e| parse_error(path, &e))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| p.source.contains_key("registry"))
        .filter_map(|p| Some(component(path, Ecosystem::PyPI, p.name, p.version?)))
        .collect())
}

/// Packages from PyPI (no `source`) or a private index (`source.type = "legacy"`); `git`,
/// `directory`, `file` and `url` sources are not registry packages.
fn parse_poetry_lock(path: &Path, text: &str) -> Result<Vec<Component>, InventoryError> {
    #[derive(Debug, Deserialize)]
    struct Lock {
        #[serde(default)]
        package: Vec<Entry>,
    }
    #[derive(Debug, Deserialize)]
    struct Entry {
        name: String,
        version: String,
        source: Option<Source>,
    }
    #[derive(Debug, Deserialize)]
    struct Source {
        #[serde(rename = "type")]
        kind: String,
    }

    let lock: Lock = toml::from_str(text).map_err(|e| parse_error(path, &e))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| p.source.as_ref().is_none_or(|s| s.kind == "legacy"))
        .map(|p| component(path, Ecosystem::PyPI, p.name, p.version))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(components: &[Component]) -> Vec<String> {
        components
            .iter()
            .map(|c| match &c.lookup {
                Lookup::Package(p) => {
                    format!("{}:{} {}", p.ecosystem.osv_name(), p.name, c.version)
                }
                Lookup::Product(p) => format!("{p} {}", c.version),
            })
            .collect()
    }

    /// `root` walked with nothing stopping it, never entering `never`.
    fn walked(root: &Path, never: &[PathBuf]) -> Inventory {
        let bounds = Bounds {
            never,
            stop: &Cancel::new(),
            limit: ENTRY_LIMIT,
        };
        let mut inventory = Inventory::default();
        walk(root, &bounds, &mut inventory);
        inventory
    }

    const CARGO_LOCK: &str = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
                              source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";

    /// Writes a `Cargo.lock` at each of `rel` under `root`.
    fn cargo_locks(root: &Path, rel: &[&str]) {
        for rel in rel {
            let path = root.join(rel).join("Cargo.lock");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, CARGO_LOCK).unwrap();
        }
    }

    /// The folders of the lockfiles found, relative to `root`.
    fn found_in(inventory: &Inventory, root: &Path) -> Vec<String> {
        let mut found: Vec<String> = inventory
            .components
            .iter()
            .map(|c| match &c.found_in {
                FoundIn::Lockfile { path } => {
                    let rel = path.strip_prefix(root).unwrap().parent().unwrap();
                    rel.display().to_string()
                }
                other => panic!("unexpected origin {other:?}"),
            })
            .collect();
        found.sort();
        found
    }

    #[test]
    fn walk_skips_packages_finder_hidden_folders_and_the_never_list() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        cargo_locks(
            root,
            &[
                "kept",
                ".Trash",
                "Library",
                "nested/Library",
                "Tool.app",
                "Kit.FRAMEWORK",
                "Photos Library.photoslibrary",
                "plug.bundle",
                "app.d",
                "hidden",
            ],
        );
        let chflags = std::process::Command::new("/usr/bin/chflags")
            .arg("hidden")
            .arg(root.join("hidden"))
            .status()
            .unwrap();
        assert!(chflags.success());

        let inventory = walked(root, &[root.join("Library")]);
        assert_eq!(
            found_in(&inventory, root),
            ["app.d", "kept", "nested/Library"],
            "only the named Library is never entered; packages match their extension only"
        );
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
    }

    #[test]
    fn a_folder_on_another_device_is_not_entered() {
        let tmp = tempfile::tempdir().unwrap();
        let meta = fs::metadata(tmp.path()).unwrap();
        assert!(entered(&meta, meta.st_dev()));
        assert!(
            !entered(&meta, meta.st_dev() + 1),
            "a mounted disk or share"
        );
    }

    #[test]
    fn the_entry_limit_stops_the_walk_with_a_problem() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        cargo_locks(root, &["a", "b"]);
        // The root lists `a` and `b`, each lists its Cargo.lock: four entries in all.
        let walk_with = |limit| {
            let bounds = Bounds {
                never: &[],
                stop: &Cancel::new(),
                limit,
            };
            let mut inventory = Inventory::default();
            walk(root, &bounds, &mut inventory);
            inventory
        };
        let all = walk_with(4);
        assert_eq!(found_in(&all, root), ["a", "b"]);
        assert!(all.problems.is_empty(), "{:?}", all.problems);

        let cut = walk_with(3);
        assert!(
            matches!(&cut.problems[..], [InventoryError::TooManyEntries { root: r, limit: 3 }]
                if r == root),
            "{:?}",
            cut.problems
        );
        assert!(
            !cut.problems[0].is_failure(),
            "the same folders stop there again"
        );
    }

    #[test]
    fn a_stopped_walk_enters_no_more_folders() {
        let tmp = tempfile::tempdir().unwrap();
        cargo_locks(tmp.path(), &["a"]);
        let stop = Cancel::new();
        stop.cancel();
        let bounds = Bounds {
            never: &[],
            stop: &stop,
            limit: ENTRY_LIMIT,
        };
        let mut inventory = Inventory::default();
        walk(tmp.path(), &bounds, &mut inventory);
        assert!(inventory.components.is_empty());
        assert!(
            inventory.problems.is_empty(),
            "whoever stopped it reports why"
        );
    }

    /// A walk that finishes `/fast` at once and blocks in `/stuck`, as on a network share that
    /// does not answer: there it signals `started` with its stop flag, then waits for
    /// `release`, which the test sends only after the waiter gave up. It gives up by itself
    /// after [`SELF_RELEASE`], so a waiter that never gives up (a broken deadline) gets its
    /// result and fails the test's assertions instead of hanging it.
    fn blocked_walk(
        started: mpsc::Sender<Cancel>,
        release: mpsc::Receiver<()>,
    ) -> impl FnMut(&Path, &Cancel) -> Inventory + Send + 'static {
        move |root, stop| {
            if root == Path::new("/stuck") {
                started.send(stop.clone()).unwrap();
                // Released, timed out, or the test ended first: each ends the block.
                let _released = release.recv_timeout(SELF_RELEASE);
            }
            Inventory::default()
        }
    }

    /// How long [`blocked_walk`] blocks at most. Arbitrary: far longer than the waits the
    /// tests expect (one poll, or a 50 ms limit), short enough to fail a test quickly.
    const SELF_RELEASE: Duration = Duration::from_secs(2);

    fn fast_then_stuck() -> Vec<PathBuf> {
        vec![PathBuf::from("/fast"), PathBuf::from("/stuck")]
    }

    #[test]
    fn a_cancel_ends_the_wait_for_a_blocked_walk_and_keeps_what_finished() {
        let (started_tx, started) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let cancel = Cancel::new();
        let canceller = {
            let cancel = cancel.clone();
            thread::spawn(move || {
                let stop: Cancel = started.recv().unwrap();
                cancel.cancel();
                stop
            })
        };
        let walk = blocked_walk(started_tx, release_rx);
        let (walked, stopped) = bounded(&cancel, WALK_TIMEOUT, &fast_then_stuck(), walk);
        assert_eq!(walked.len(), 1, "/fast finished");
        assert!(
            matches!(&stopped, Some(InventoryError::Cancelled { what }) if what.contains("/stuck")),
            "{stopped:?}"
        );
        let stop = canceller.join().unwrap();
        assert!(stop.is_cancelled(), "the walk is told to stop once it can");
        release.send(()).unwrap();

        let not_started = |_: &Path, _: &Cancel| -> Inventory { unreachable!("not started") };
        let (walked, stopped) = bounded(&cancel, WALK_TIMEOUT, &fast_then_stuck(), not_started);
        assert!(walked.is_empty());
        assert!(
            matches!(&stopped, Some(InventoryError::Cancelled { what }) if what.contains("/fast")),
            "{stopped:?}"
        );
    }

    #[test]
    fn a_blocked_walk_times_out_naming_its_folder() {
        let (started_tx, started) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let walk = blocked_walk(started_tx, release_rx);
        let limit = Duration::from_millis(50);
        let (walked, stopped) = bounded(&Cancel::new(), limit, &fast_then_stuck(), walk);
        assert_eq!(walked.len(), 1, "/fast finished");
        let Some(InventoryError::WalkTimedOut { root, limit: l }) = &stopped else {
            panic!("{stopped:?}")
        };
        assert_eq!((root.as_path(), *l), (Path::new("/stuck"), limit));
        assert!(stopped.unwrap().is_failure());
        let stop: Cancel = started.recv().unwrap();
        assert!(stop.is_cancelled());
        release.send(()).unwrap();
    }

    #[test]
    fn a_walk_slower_than_a_poll_but_within_the_limit_finishes() {
        // Longer than one poll, so the waiter checks the deadline at least once before the
        // result; far shorter than the limit.
        let walk = |_: &Path, _: &Cancel| {
            thread::sleep(POLL * 2);
            Inventory::default()
        };
        let roots = [PathBuf::from("/slow")];
        let (walked, stopped) = bounded(&Cancel::new(), WALK_TIMEOUT, &roots, walk);
        assert!(stopped.is_none(), "{stopped:?}");
        assert_eq!(walked.len(), 1);
    }

    #[test]
    fn finished_walks_are_returned_in_order() {
        let roots = [PathBuf::from("/a"), PathBuf::from("/b")];
        let walk = |root: &Path, _: &Cancel| Inventory {
            problems: vec![InventoryError::io(
                root,
                std::io::ErrorKind::NotFound.into(),
            )],
            ..Inventory::default()
        };
        let (walked, stopped) = bounded(&Cancel::new(), WALK_TIMEOUT, &roots, walk);
        assert!(stopped.is_none());
        let names: Vec<String> = walked.iter().map(|w| w.problems[0].to_string()).collect();
        assert_eq!(names, ["cannot read /a", "cannot read /b"]);
        assert!(
            bounded(&Cancel::new(), WALK_TIMEOUT, &[], walk)
                .0
                .is_empty()
        );
    }

    #[test]
    fn every_lockfile_name_has_a_parser() {
        for name in NAMES {
            let path = Path::new("/p").join(name);
            assert!(parse(&path, "", &mut Vec::new()).is_some(), "{name}");
            assert!(is_lockfile(&path), "{name}");
        }
        assert!(parse(Path::new("/p/Gemfile.lock"), "", &mut Vec::new()).is_none());
    }

    #[test]
    fn cargo_lock_keeps_registry_packages() {
        let text = r#"
            version = 4
            [[package]]
            name = "my-app"
            version = "0.1.0"
            [[package]]
            name = "serde"
            version = "1.0.229"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            [[package]]
            name = "forked"
            version = "0.2.0"
            source = "git+https://github.com/x/forked#abc"
            [[package]]
            name = "mirrored"
            version = "0.3.0"
            source = "sparse+https://index.crates.io/"
            [[package]]
            name = "internal"
            version = "1.0.0"
            source = "sparse+https://cargo.example.com/index/"
            [[package]]
            name = "internal-two"
            version = "1.0.0"
            source = "sparse+https://cargo.example.com/index/"
        "#;
        let mut notes = Vec::new();
        let found = parse_cargo_lock(Path::new("/p/Cargo.lock"), text, &mut notes).unwrap();
        let registries: Vec<_> = notes
            .iter()
            .map(|n| match n {
                InventoryError::OtherRegistry { registry, .. } => registry.as_str(),
                other => panic!("unexpected note {other:?}"),
            })
            .collect();
        assert_eq!(
            registries,
            ["sparse+https://cargo.example.com/index/"],
            "noted once"
        );
        assert_eq!(
            names(&found),
            ["crates.io:serde 1.0.229", "crates.io:mirrored 0.3.0"]
        );
        assert!(matches!(
            &found[0].found_in,
            FoundIn::Lockfile { path } if path == Path::new("/p/Cargo.lock")
        ));
        assert!(
            parse_cargo_lock(Path::new("x"), "[[package]]\nname = 1", &mut Vec::new()).is_err()
        );
    }

    #[test]
    fn package_lock_v3() {
        let text = r#"{"name": "app", "lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/@scope/pkg": {"version": "2.0.0", "dev": true},
            "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
            "node_modules/my-alias": {"name": "real-name", "version": "1.2.3"},
            "node_modules/local": {"resolved": "../local", "link": true},
            "node_modules/from-git": {"version": "1", "resolved": "git+ssh://git@x.com/y.git"},
            "node_modules/tarball": {"version": "1.0.0", "resolved": "file:../tarball.tgz"},
            "node_modules/shorthand": {"version": "1.0.0", "resolved": "github:x/y#abc"},
            "node_modules/registry": {"version": "2.0.0", "resolved": "https://r.example/r.tgz"},
            "packages/local": {"version": "0.0.1"}
        }}"#;
        let found = parse_package_lock(Path::new("/p/package-lock.json"), text).unwrap();
        assert_eq!(
            names(&found),
            [
                "npm:@scope/pkg 2.0.0",
                "npm:lodash 3.10.1",
                "npm:lodash 4.17.21",
                "npm:real-name 1.2.3",
                "npm:registry 2.0.0",
            ]
        );
    }

    #[test]
    fn package_lock_v1_is_reported() {
        let text = r#"{"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.0.0"}}}"#;
        let err = parse_package_lock(Path::new("/p/package-lock.json"), text).unwrap_err();
        assert!(err.to_string().contains("lockfileVersion 1"), "{err}");

        let v2 = r#"{"lockfileVersion": 2, "packages": {"node_modules/a": {"version": "1.0.0"}}}"#;
        let found = parse_package_lock(Path::new("/p/package-lock.json"), v2).unwrap();
        assert_eq!(names(&found), ["npm:a 1.0.0"]);
    }

    #[test]
    fn uv_lock_keeps_registry_packages() {
        let text = r#"
            version = 1
            [[package]]
            name = "my-project"
            version = "0.1.0"
            source = { editable = "." }
            [[package]]
            name = "requests"
            version = "2.32.3"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "workspace-member"
            version = "0.1.0"
            source = { virtual = "packages/member" }
        "#;
        let found = parse_uv_lock(Path::new("/p/uv.lock"), text).unwrap();
        assert_eq!(names(&found), ["PyPI:requests 2.32.3"]);
    }

    #[test]
    fn poetry_lock_keeps_pypi_and_private_index() {
        let text = r#"
            [[package]]
            name = "django"
            version = "5.1.2"
            [[package]]
            name = "internal"
            version = "1.0.0"
            [package.source]
            type = "legacy"
            url = "https://pypi.example.com/simple"
            [[package]]
            name = "from-git"
            version = "0.1.0"
            [package.source]
            type = "git"
            url = "https://github.com/x/y"
        "#;
        let found = parse_poetry_lock(Path::new("/p/poetry.lock"), text).unwrap();
        assert_eq!(names(&found), ["PyPI:django 5.1.2", "PyPI:internal 1.0.0"]);
    }

    #[test]
    fn walk_finds_lockfiles_and_skips_vendored_hidden_and_links() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let cargo = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
                     source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let write = |rel: &str, text: &str| {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        write("app/Cargo.lock", cargo);
        write("app/nested/deep/Cargo.lock", cargo);
        write(
            "web/package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1"}}}"#,
        );
        write(
            "py/uv.lock",
            "[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { registry = \"x\" }\n",
        );
        write(
            "poetry/poetry.lock",
            "[[package]]\nname = \"a\"\nversion = \"1\"\n",
        );
        write(
            "published/npm-shrinkwrap.json",
            r#"{"lockfileVersion": 3, "packages": {"node_modules/b": {"version": "1"}}}"#,
        );
        write("app/target/Cargo.lock", cargo);
        write("app/node_modules/x/Cargo.lock", cargo);
        write(".hidden/Cargo.lock", cargo);
        write("broken/Cargo.lock", "not toml [");
        write("other/README.md", "# not a lockfile");
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("Cargo.lock"), cargo).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("linked")).unwrap();

        let inventory = walked(root, &[]);
        let mut paths: Vec<_> = inventory
            .components
            .iter()
            .map(|c| match &c.found_in {
                FoundIn::Lockfile { path } => path.strip_prefix(root).unwrap().to_owned(),
                other => panic!("unexpected origin {other:?}"),
            })
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            [
                Path::new("app/Cargo.lock"),
                Path::new("app/nested/deep/Cargo.lock"),
                Path::new("poetry/poetry.lock"),
                Path::new("published/npm-shrinkwrap.json"),
                Path::new("py/uv.lock"),
                Path::new("web/package-lock.json"),
            ]
        );
        assert!(
            matches!(inventory.problems[..], [InventoryError::Parse { .. }]),
            "{:?}",
            inventory.problems
        );
        let broken = InventorySource::Lockfile {
            path: root.join("broken/Cargo.lock"),
        };
        assert_eq!(inventory.failed, [broken].into());
    }

    #[test]
    fn oversized_lockfile_is_reported_not_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Cargo.lock");
        // A sparse file: the length is set without writing 64 MiB.
        fs::File::create(&path)
            .unwrap()
            .set_len(LOCKFILE_LIMIT + 1)
            .unwrap();
        let err = read_lockfile(&path).unwrap_err();
        assert!(err.to_string().contains("over the"), "{err}");
        assert!(!err.is_failure(), "it is as large on the next sweep");

        fs::File::create(&path)
            .unwrap()
            .set_len(LOCKFILE_LIMIT)
            .unwrap();
        assert!(read_lockfile(&path).is_ok());

        // A real lockfile of a few MiB is well under the limit.
        fs::File::create(&path)
            .unwrap()
            .set_len(2 * 1024 * 1024)
            .unwrap();
        assert!(read_lockfile(&path).is_ok());
    }

    #[test]
    fn unreadable_folder_is_reported_and_the_walk_goes_on() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let locked = tmp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(
            tmp.path().join("Cargo.lock"),
            concat!(
                "[[package]]\nname = \"a\"\nversion = \"1\"\n",
                "source = \"sparse+https://index.crates.io/\"\n",
            ),
        )
        .unwrap();
        let denied = tmp.path().join("denied/Cargo.lock");
        fs::create_dir(denied.parent().unwrap()).unwrap();
        fs::write(&denied, "").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();

        let inventory = walked(tmp.path(), &[]);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(inventory.components.len(), 1);
        assert!(
            matches!(
                inventory.problems[..],
                [InventoryError::Io { .. }, InventoryError::Io { .. }]
            ),
            "{:?}",
            inventory.problems
        );
        assert!(
            inventory.failed.is_empty(),
            "a folder or lockfile this user may not read stays so: {:?}",
            inventory.failed
        );
    }

    #[test]
    fn missing_root_is_reported() {
        let root = Path::new("/nonexistent/vigil");
        let inventory = walked(root, &[]);
        assert!(matches!(
            inventory.problems[..],
            [InventoryError::ProjectFolder { .. }]
        ));
        let unwalked = InventorySource::LockfileWalk { root: root.into() };
        assert_eq!(inventory.failed, [unwalked].into());
    }

    #[test]
    fn a_project_folder_this_user_may_not_read_fails() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("projects");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o000)).unwrap();
        let inventory = walked(&root, &[]);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(&inventory.problems[..], [InventoryError::ProjectFolder { source, .. }]
                if source.kind() == std::io::ErrorKind::PermissionDenied),
            "{:?}",
            inventory.problems
        );
        let unopened = InventorySource::LockfileWalk { root };
        assert_eq!(
            inventory.failed,
            [unopened].into(),
            "access taken away from a chosen folder must not resolve its findings"
        );
    }

    #[test]
    fn a_stopped_walk_counts_its_root_and_those_after_it_as_unread() {
        let roots = ["/a", "/b", "/c"].map(PathBuf::from);
        let first = || {
            let mut found = Inventory::default();
            unwalked(
                &mut found,
                Path::new("/a/x"),
                // EIO, as from a disk or share that fails while read: it may pass.
                std::io::Error::from_raw_os_error(5),
            );
            found
        };
        let walk = |root: &str| InventorySource::LockfileWalk { root: root.into() };

        let mut inventory = Inventory::default();
        let timed_out = InventoryError::WalkTimedOut {
            root: "/b".into(),
            limit: WALK_TIMEOUT,
        };
        add_walks(&mut inventory, &roots, vec![first()], Some(timed_out));
        assert_eq!(
            inventory.failed,
            [walk("/a/x"), walk("/b"), walk("/c")].into()
        );
        assert!(
            matches!(
                inventory.problems[..],
                [
                    InventoryError::Io { .. },
                    InventoryError::WalkTimedOut { .. }
                ]
            ),
            "the walked roots' problems first: {:?}",
            inventory.problems
        );

        let mut inventory = Inventory::default();
        add_walks(&mut inventory, &roots, vec![first()], None);
        assert_eq!(inventory.failed, [walk("/a/x")].into());
    }
}
