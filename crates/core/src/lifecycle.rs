//! What carries over from one sweep to the next: finding keys, dismissals, and what changed
//! since the target's last sweep.
//!
//! A [`FindingKey`] names one finding or issue across sweeps, so a dismissal and the
//! comparison with the last sweep can find it again. Dismissals live in
//! `state/dismissals.json`; every write takes `state/.lock`, so two commands cannot lose each
//! other's changes, and replaces the file whole, so a sweep reading it never sees half of it.
//! A dismissal of a finding holds while its advisory's `modified` time is the one it was
//! dismissed at: a changed advisory (a new affected range, a raised score) shows it again.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use jiff::Timestamp;
use serde::Deserialize;
use serde::Serialize;
use serde::de::IgnoredAny;

use crate::config::Config;
use crate::findings::Severity;
use crate::findings::is_forging;
use crate::fix::Outcome;
use crate::paths::DataDir;
use crate::sweep;

/// The stable id of a finding or issue: 16 hex digits, the same in every sweep that finds it.
///
/// A finding's key hashes the target, its primary advisory, the component's lookup and where
/// it was found, but not the version, so the finding keeps its key until it is fixed. An
/// issue's key hashes the target and its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct FindingKey(u64);

impl FindingKey {
    /// The key of the parts, in order. FNV-1a, 64 bits
    /// (<https://datatracker.ietf.org/doc/html/draft-eastlake-fnv-21#section-6.1.2>): unlike
    /// std's hashers it is fixed, so keys stay valid across builds. A zero byte ends each part,
    /// so `["ab", "c"]` and `["a", "bc"]` differ; the parts are text and hold no zero byte.
    pub(crate) fn new(parts: &[&str]) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in parts.iter().flat_map(|p| p.bytes().chain([0])) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        Self(hash)
    }
}

impl fmt::Display for FindingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl FromStr for FindingKey {
    type Err = ParseFindingKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let error = || ParseFindingKeyError {
            input: s.to_owned(),
        };
        if !hex {
            return Err(error());
        }
        u64::from_str_radix(s, 16).map(Self).map_err(|_| error())
    }
}

impl TryFrom<String> for FindingKey {
    type Error = ParseFindingKeyError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<FindingKey> for String {
    fn from(key: FindingKey) -> Self {
        key.to_string()
    }
}

/// A finding key that is not 16 lowercase hex digits.
#[derive(Debug, thiserror::Error)]
#[error("{input:?} is not a finding key (16 hex digits, as shown in the report)")]
pub struct ParseFindingKeyError {
    input: String,
}

/// Why and when the user dismissed a finding or issue.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dismissal {
    /// The user's reason, one line.
    pub reason: String,
    /// When it was dismissed.
    pub at: Timestamp,
    /// The advisory's `modified` time when it was dismissed; `None` for an issue, or an
    /// advisory without one.
    pub modified: Option<Timestamp>,
}

/// The dismissals in `state/dismissals.json`.
#[derive(Debug, Default)]
pub(crate) struct Dismissals(BTreeMap<FindingKey, Dismissal>);

impl Dismissals {
    /// Reads the dismissals; no file means none.
    pub(crate) fn load(data_dir: &DataDir) -> Result<Self, StateError> {
        read_dismissals(&data_dir.state_dir().join(DISMISSALS)).map(Self)
    }

    /// The dismissal of `key`, when it still holds for an advisory last modified at
    /// `modified`.
    pub(crate) fn get(&self, key: FindingKey, modified: Option<Timestamp>) -> Option<&Dismissal> {
        self.0.get(&key).filter(|d| d.modified == modified)
    }
}

const DISMISSALS: &str = "dismissals.json";

/// Dismisses the finding or issue `key`, as it was in its newest report, for `reason`.
///
/// # Errors
///
/// Returns [`StateError::Reason`] for an empty reason or one with control characters,
/// [`StateError::UnknownKey`] when no report has `key`, and [`StateError::Read`] or
/// [`StateError::Write`] when the state files cannot be used.
pub fn dismiss(data_dir: &DataDir, key: FindingKey, reason: &str) -> Result<Dismissal, StateError> {
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().any(is_forging) {
        return Err(StateError::Reason);
    }
    let newest = newest(&data_dir.sweeps_dir(), key)?.ok_or(StateError::UnknownKey { key })?;
    let dismissal = Dismissal {
        reason: reason.to_owned(),
        at: Timestamp::now(),
        modified: newest.modified,
    };
    update(data_dir, |all| {
        all.insert(key, dismissal.clone());
        Ok(dismissal)
    })
}

/// Removes the dismissal of `key`, so the finding or issue shows again.
///
/// # Errors
///
/// Returns [`StateError::NotDismissed`] when `key` is not dismissed, and [`StateError::Read`]
/// or [`StateError::Write`] when the state files cannot be used.
pub fn undismiss(data_dir: &DataDir, key: FindingKey) -> Result<Dismissal, StateError> {
    update(data_dir, |all| {
        all.remove(&key).ok_or(StateError::NotDismissed { key })
    })
}

/// Runs `change` holding `state/.lock`, which every write to the state folder takes.
pub(crate) fn locked<T>(
    data_dir: &DataDir,
    change: impl FnOnce(&Path) -> Result<T, StateError>,
) -> Result<T, StateError> {
    let state = data_dir.state_dir();
    let write_err = |path: &Path| {
        let path = path.to_owned();
        move |source| StateError::Write { path, source }
    };
    fs::create_dir_all(&state).map_err(write_err(&state))?;
    let lock_path = state.join(".lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(write_err(&lock_path))?;
    // Blocks: every holder writes one small file and lets go within milliseconds.
    lock.lock().map_err(write_err(&lock_path))?;
    change(&state)
}

/// Changes the dismissals under `state/.lock` and writes them back whole, unless `change`
/// fails. Returns what `change` returned.
fn update<T>(
    data_dir: &DataDir,
    change: impl FnOnce(&mut BTreeMap<FindingKey, Dismissal>) -> Result<T, StateError>,
) -> Result<T, StateError> {
    locked(data_dir, |state| write_dismissals(state, change))
}

fn write_dismissals<T>(
    state: &Path,
    change: impl FnOnce(&mut BTreeMap<FindingKey, Dismissal>) -> Result<T, StateError>,
) -> Result<T, StateError> {
    let write_err = |path: &Path| {
        let path = path.to_owned();
        move |source| StateError::Write { path, source }
    };
    let path = state.join(DISMISSALS);
    let mut all = read_dismissals(&path)?;
    let changed = change(&mut all)?;
    let json = serde_json::to_string_pretty(&all)
        .expect("string keys and plain structs always serialize to JSON");
    let partial = state.join(format!(".{DISMISSALS}.partial"));
    fs::File::create(&partial)
        .and_then(|mut file| {
            file.write_all(json.as_bytes())?;
            file.sync_data()
        })
        .and_then(|()| fs::rename(&partial, &path))
        // Syncs the folder too, so a crash after this returns cannot undo the rename.
        .and_then(|()| fs::File::open(state)?.sync_all())
        .map_err(write_err(&path))?;
    Ok(changed)
}

fn read_dismissals(path: &Path) -> Result<BTreeMap<FindingKey, Dismissal>, StateError> {
    let read_err = |source| StateError::Read {
        path: path.to_owned(),
        source,
    };
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|e| read_err(io::Error::new(io::ErrorKind::InvalidData, e))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(read_err(e)),
    }
}

/// What changed for a target since its last sweep with a verdict.
#[derive(Debug, Serialize)]
pub struct Changes {
    /// When that sweep started.
    pub since: Timestamp,
    /// Findings and issues it did not have.
    pub new: Vec<FindingKey>,
    /// Findings and issues it had that are gone: fixed, or no longer judged affecting.
    pub resolved: Vec<FindingKey>,
}

impl Changes {
    /// Compares the current verdict with the newest earlier report in `<sweep>/<dir_name>`
    /// that has a verdict: `active` holds the keys not dismissed now, `all` every key now.
    /// New is what is active now and was not active then (absent, or dismissed and shown
    /// again); resolved is what was active then and is gone now. A key dismissed since is
    /// neither. `None` when no earlier report has a verdict.
    pub(crate) fn since_last(
        sweeps: &Path,
        dir_name: &str,
        active: &BTreeSet<FindingKey>,
        all: &BTreeSet<FindingKey>,
    ) -> Result<Option<Self>, StateError> {
        let Some((_, last)) = newest_verdict(sweeps, dir_name)? else {
            return Ok(None);
        };
        let before: BTreeSet<FindingKey> = last
            .entries()
            .filter(|e| e.dismissed.is_none())
            .map(|e| e.key)
            .collect();
        Ok(Some(Self {
            since: last.started,
            new: active.difference(&before).copied().collect(),
            resolved: before.difference(all).copied().collect(),
        }))
    }
}

/// When each finding and issue in the target's newest report with a verdict was first seen:
/// its own `first_seen`, or that report's start for one saved before the field existed.
pub(crate) fn first_seen(
    sweeps: &Path,
    dir_name: &str,
) -> Result<BTreeMap<FindingKey, Timestamp>, StateError> {
    let Some((_, last)) = newest_verdict(sweeps, dir_name)? else {
        return Ok(BTreeMap::new());
    };
    Ok(last
        .entries()
        .map(|e| (e.key, e.first_seen.unwrap_or(last.started)))
        .collect())
}

/// The newest `<sweep>/<dir_name>/report.json` with a verdict, with its contents.
pub(crate) fn newest_verdict(
    sweeps: &Path,
    dir_name: &str,
) -> Result<Option<(PathBuf, Saved)>, StateError> {
    for sweep in newest_first(sweeps)? {
        let dir = sweep.join(dir_name);
        let Some(saved) = read_saved(&dir)? else {
            continue;
        };
        if saved.failure.is_none() {
            return Ok(Some((dir.join("report.json"), saved)));
        }
    }
    Ok(None)
}

/// A target's open findings and issues, as its newest report with a verdict has them.
#[derive(Debug, Serialize)]
pub struct Latest {
    /// The target: `mac`, `github:owner/name` or `server:name`.
    pub target: String,
    /// When that sweep started; `None` when the target has no report with a verdict yet.
    pub swept: Option<Timestamp>,
    /// How many components that sweep checked.
    pub components: usize,
    /// The findings and issues not dismissed or fixed, most severe first.
    pub open: Vec<Open>,
    /// The ones a fix reported fixed after that sweep, newest fix first. A later sweep that
    /// still finds one lists it as open again: the fix did not hold.
    pub fixed: Vec<Fixed>,
    /// How many are dismissed.
    pub dismissed: usize,
}

/// A finding or issue a fix reported fixed.
#[derive(Debug, Serialize)]
pub struct Fixed {
    /// The finding as the sweep before the fix found it.
    #[serde(flatten)]
    pub open: Open,
    /// When the fix finished.
    pub fixed_at: Timestamp,
    /// The agent's one-line summary of what it did.
    pub summary: String,
    /// The pull request it opened, for a repository.
    pub pull_request: Option<String>,
}

/// One open finding or issue.
#[derive(Debug, Serialize)]
pub struct Open {
    /// Its key, for `dismiss` and `fix`.
    pub key: FindingKey,
    /// How bad it is.
    pub severity: Severity,
    /// One line naming it.
    pub title: String,
    /// The component's name, or the setting or file an issue is about.
    pub name: String,
    /// The installed version; `None` for an issue.
    pub version: Option<String>,
    /// The advisory ids, primary first; empty for an issue.
    pub advisories: Vec<String>,
    /// Where it was found, one line; empty for an issue.
    pub place: String,
    /// Exploited in the wild (CISA KEV).
    pub known_exploited: bool,
    /// What it means, in the agent's words.
    pub explanation: String,
    /// One line: what the fix does.
    pub fix: String,
    /// The fix's exact commands.
    pub commands: Vec<String>,
    /// When a sweep first found it; `None` in a report saved before that was kept.
    pub first_seen: Option<Timestamp>,
    /// Whether the newest sweep is the first to find it since the one before.
    pub new: bool,
}

/// Each configured target's open findings and issues, in sweep order. Whether one is
/// dismissed comes from `state/dismissals.json`, as for `fix`, so a dismissal shows at once.
/// Titles and fix summaries are shown as plain lines: they hold agent text and names from the
/// target.
///
/// # Errors
///
/// Fails when a sweep folder, a report or the dismissals cannot be read.
pub fn latest(data_dir: &DataDir, config: &Config) -> Result<Vec<Latest>, StateError> {
    let sweeps = data_dir.sweeps_dir();
    let dismissals = Dismissals::load(data_dir)?;
    let fixes = last_fixes(data_dir)?;
    let mut all = Vec::new();
    for (target, dir_name) in sweep::configured_targets(config) {
        let Some((_, saved)) = newest_verdict(&sweeps, &dir_name)? else {
            all.push(Latest {
                target,
                swept: None,
                components: 0,
                open: Vec::new(),
                fixed: Vec::new(),
                dismissed: 0,
            });
            continue;
        };
        let (dismissed, kept): (Vec<_>, Vec<_>) = saved
            .entries()
            .partition(|e| dismissals.get(e.key, e.modified).is_some());
        let new = |key: FindingKey| saved.changes.as_ref().is_some_and(|c| c.new.contains(&key));
        let (mut open, mut fixed) = (Vec::new(), Vec::new());
        for entry in kept {
            let shown = open_entry(entry, new(entry.key));
            // Fixed after this sweep found it; a sweep that started after the fix and still
            // lists it would be the newest report, and the fix did not hold.
            match fixes.get(&entry.key) {
                Some(fix) if fix.outcome == Outcome::Fixed && fix.finished > saved.started => {
                    fixed.push(Fixed {
                        open: shown,
                        fixed_at: fix.finished,
                        summary: sweep::plain(&fix.summary),
                        pull_request: fix.pull_request.clone(),
                    });
                }
                _ => open.push(shown),
            }
        }
        open.sort_by_key(|o| o.severity);
        fixed.sort_by_key(|f| std::cmp::Reverse(f.fixed_at));
        all.push(Latest {
            target,
            swept: Some(saved.started),
            components: saved.components,
            open,
            fixed,
            dismissed: dismissed.len(),
        });
    }
    Ok(all)
}

/// The newest fix run of each finding or issue, from `state/fixes.jsonl`.
///
/// A line that does not parse is skipped: `fix::append` leaves a run cut off by a crash as a
/// torn line and starts the next record on a new one, so a torn line is expected and says
/// nothing about any fix.
fn last_fixes(data_dir: &DataDir) -> Result<BTreeMap<FindingKey, FixLine>, StateError> {
    let path = data_dir.state_dir().join("fixes.jsonl");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => return Err(StateError::Read { path, source }),
    };
    let mut last: BTreeMap<FindingKey, FixLine> = BTreeMap::new();
    for line in text.lines() {
        let Ok(fix) = serde_json::from_str::<FixLine>(line) else {
            continue;
        };
        if last
            .get(&fix.key)
            .is_none_or(|seen| seen.finished <= fix.finished)
        {
            last.insert(fix.key, fix);
        }
    }
    Ok(last)
}

/// The fields of a `fixes.jsonl` record that decide whether a finding is fixed.
#[derive(Debug, Deserialize)]
struct FixLine {
    key: FindingKey,
    finished: Timestamp,
    outcome: Outcome,
    summary: String,
    pull_request: Option<String>,
}

/// `entry` as shown. Every text is a plain line: it holds agent text and names from the
/// target. Commands passed the sweep's printable-ASCII check.
fn open_entry(entry: &SavedEntry, new: bool) -> Open {
    let plain = |text: &str| sweep::plain(text);
    Open {
        key: entry.key,
        severity: entry.severity,
        title: plain(&entry.title),
        name: plain(&entry.name),
        version: entry.installed.as_ref().map(|i| plain(&i.version)),
        advisories: entry.advisories.iter().map(|a| plain(a)).collect(),
        place: plain(&entry.place),
        known_exploited: entry.known_exploited,
        explanation: plain(&entry.explanation),
        fix: entry
            .fix
            .as_ref()
            .map_or(String::new(), |f| plain(&f.summary)),
        commands: entry.fix.as_ref().map_or(Vec::new(), |f| {
            f.commands.iter().map(|c| plain(c)).collect()
        }),
        first_seen: entry.first_seen,
        new,
    }
}

/// What later sweeps and commands read back from a saved `report.json`.
#[derive(Debug, Deserialize)]
pub(crate) struct Saved {
    pub(crate) started: Timestamp,
    failure: Option<String>,
    #[serde(default)]
    components: usize,
    findings: Vec<SavedEntry>,
    issues: Vec<SavedEntry>,
    changes: Option<SavedChanges>,
}

#[derive(Debug, Deserialize)]
struct SavedChanges {
    new: Vec<FindingKey>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SavedEntry {
    key: FindingKey,
    severity: Severity,
    /// Empty in a report saved before entries had titles.
    #[serde(default)]
    title: String,
    /// Absent, like `place` and `first_seen`, in a report saved before entries had them.
    #[serde(default)]
    name: String,
    #[serde(default)]
    place: String,
    first_seen: Option<Timestamp>,
    /// A finding's; an issue has none.
    #[serde(default)]
    advisories: Vec<String>,
    #[serde(default)]
    known_exploited: bool,
    #[serde(default)]
    explanation: String,
    installed: Option<SavedInstalled>,
    fix: Option<SavedFix>,
    #[serde(default)]
    modified: Option<Timestamp>,
    /// Only whether it is there matters.
    #[serde(default)]
    dismissed: Option<IgnoredAny>,
}

#[derive(Debug, Clone, Deserialize)]
struct SavedFix {
    summary: String,
    #[serde(default)]
    commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SavedInstalled {
    version: String,
}

impl SavedEntry {
    /// Its advisory's `modified` time, as the report had it.
    pub(crate) fn modified(&self) -> Option<Timestamp> {
        self.modified
    }
}

impl Saved {
    fn entries(&self) -> impl Iterator<Item = &SavedEntry> {
        self.findings.iter().chain(&self.issues)
    }
}

/// When the newest sweep started, with or without a verdict; `None` before the first. For a
/// schedule: a sweep that failed still counts, so it is not retried at once.
///
/// # Errors
///
/// Fails when the sweeps folder cannot be read.
pub fn last_sweep_started(data_dir: &DataDir) -> Result<Option<Timestamp>, StateError> {
    // `newest_first` checks only the shape `YYYYMMDDTHHMMSSZ`; a name that is not a real time
    // (month 13) is skipped, not taken for "never swept", which would make a sweep due at once.
    Ok(newest_first(&data_dir.sweeps_dir())?
        .into_iter()
        .find_map(|path| {
            let name = path.file_name()?.to_str()?;
            let civil = jiff::civil::DateTime::strptime("%Y%m%dT%H%M%S", name.get(..15)?).ok()?;
            civil
                .to_zoned(jiff::tz::TimeZone::UTC)
                .ok()
                .map(|z| z.timestamp())
        }))
}

/// The sweep folders under `sweeps`, newest first. A folder is named by its start second,
/// `20261106T101500Z`, with `-2`, `-3` and so on for later sweeps that started in the same
/// second; other names are not sweeps. Sorting by name alone would put `-10` before `-2`.
fn newest_first(sweeps: &Path) -> Result<Vec<PathBuf>, StateError> {
    let mut found: Vec<((String, u32), PathBuf)> = folders(sweeps)?
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?.to_owned();
            let (stamp, n) = match name.split_once('-') {
                Some((stamp, n)) => (stamp, n.parse().ok()?),
                None => (name.as_str(), 1),
            };
            let is_stamp = stamp.len() == 16
                && stamp.bytes().enumerate().all(|(i, b)| match i {
                    8 => b == b'T',
                    15 => b == b'Z',
                    _ => b.is_ascii_digit(),
                });
            is_stamp.then(|| ((stamp.to_owned(), n), path))
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(found.into_iter().map(|(_, path)| path).collect())
}

/// Reads `<target dir>/report.json`; `None` when the target was not in that sweep.
fn read_saved(target_dir: &Path) -> Result<Option<Saved>, StateError> {
    let path = target_dir.join("report.json");
    let read_err = |source| StateError::Read {
        path: path.clone(),
        source,
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(read_err(e)),
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| read_err(io::Error::new(io::ErrorKind::InvalidData, e)))
}

/// The folders in `dir`; none when `dir` does not exist. Files are skipped: a sweep folder
/// holds target folders, and the sweeps folder holds `.lock` beside the sweeps.
fn folders(dir: &Path) -> Result<Vec<PathBuf>, StateError> {
    let read_err = |source| StateError::Read {
        path: dir.to_owned(),
        source,
    };
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(read_err(e)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(read_err)?;
        if entry.file_type().map_err(read_err)?.is_dir() {
            found.push(entry.path());
        }
    }
    Ok(found)
}

/// The entry for `key` in the newest report that has it.
fn newest(sweeps: &Path, key: FindingKey) -> Result<Option<SavedEntry>, StateError> {
    Ok(newest_report(sweeps, key)?.map(|(_, entry)| entry))
}

/// The newest `report.json` with a verdict that has `key`, with the entry.
pub(crate) fn newest_report(
    sweeps: &Path,
    key: FindingKey,
) -> Result<Option<(PathBuf, SavedEntry)>, StateError> {
    for sweep in newest_first(sweeps)? {
        for target in folders(&sweep)? {
            let Some(saved) = read_saved(&target)?.filter(|s| s.failure.is_none()) else {
                continue;
            };
            if let Some(entry) = saved.entries().find(|e| e.key == key) {
                return Ok(Some((target.join("report.json"), entry.clone())));
            }
        }
    }
    Ok(None)
}

/// Error from reading or changing the lifecycle state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// The dismissal reason is empty or has control characters.
    #[error("the reason must be one line of text")]
    Reason,
    /// No report has the key.
    #[error("no report has finding {key}; copy the key from the newest report")]
    UnknownKey {
        /// The key.
        key: FindingKey,
    },
    /// The key is not dismissed.
    #[error("finding {key} is not dismissed")]
    NotDismissed {
        /// The key.
        key: FindingKey,
    },
    /// A state file could not be read.
    #[error("cannot read {}; fix or delete it", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A state file could not be written.
    #[error("cannot write {}", path.display())]
    Write {
        /// The file or folder.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    #[test]
    fn keys_are_fnv1a_of_the_parts_and_parse_back() {
        // No bytes give the offset basis. The others come from a separate implementation that
        // gives the draft's test vector for "a", 0xaf63dc4c8601ec8c.
        assert_eq!(FindingKey::new(&[]).to_string(), "cbf29ce484222325");
        assert_eq!(FindingKey::new(&[""]).to_string(), "af63bd4c8601b7df");
        assert_eq!(FindingKey::new(&["a"]).to_string(), "089be207b544f1e4");
        assert_ne!(FindingKey::new(&["ab", "c"]), FindingKey::new(&["a", "bc"]));

        let key = FindingKey::new(&["mac", "GHSA-1"]);
        assert_eq!(key.to_string().parse::<FindingKey>().unwrap(), key);
        for bad in [
            "",
            "cbf29ce48422232",
            "CBF29CE484222325",
            "cbf29ce4842223255",
            "+bf29ce484222325",
        ] {
            assert!(bad.parse::<FindingKey>().is_err(), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn every_key_round_trips(n: u64) {
            let key = FindingKey(n);
            prop_assert_eq!(key.to_string().parse::<FindingKey>().unwrap(), key);
        }
    }

    fn save(sweeps: &Path, dir: &str, report: &serde_json::Value) {
        let dir = sweeps.join(dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("report.json"), report.to_string()).unwrap();
    }

    fn report(
        started: &str,
        failure: Option<&str>,
        keys: &[FindingKey],
        modified: &str,
    ) -> serde_json::Value {
        let findings: Vec<_> = keys
            .iter()
            .map(|k| json!({"key": k, "severity": "high", "modified": modified}))
            .collect();
        json!({
            "started": started, "target": "mac", "failure": failure,
            "findings": findings, "issues": [],
        })
    }

    #[test]
    fn a_dismissal_holds_until_the_advisory_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let (kept, other) = (FindingKey(1), FindingKey(2));
        let at = "2026-11-01T00:00:00Z";
        save(
            &data_dir.sweeps_dir(),
            "20261105T000000Z/mac",
            &report("2026-11-05T00:00:00Z", None, &[kept], at),
        );

        // Files beside sweeps and beside targets are not folders to read, even when
        // every folder is searched for a key that is not there.
        fs::write(data_dir.sweeps_dir().join(".lock"), "").unwrap();
        fs::write(data_dir.sweeps_dir().join("20261105T000000Z/stray"), "").unwrap();
        assert!(matches!(
            dismiss(&data_dir, kept, " \n"),
            Err(StateError::Reason)
        ));
        assert!(matches!(
            dismiss(&data_dir, kept, "a\u{202e}b"),
            Err(StateError::Reason)
        ));
        assert!(matches!(
            dismiss(&data_dir, other, "x"),
            Err(StateError::UnknownKey { key }) if key == other
        ));
        let dismissal = dismiss(&data_dir, kept, " accepted ").unwrap();
        assert_eq!(dismissal.reason, "accepted");

        let dismissals = Dismissals::load(&data_dir).unwrap();
        let modified = Some(at.parse().unwrap());
        assert_eq!(dismissals.get(kept, modified), Some(&dismissal));
        assert_eq!(
            dismissals.get(kept, Some("2026-11-02T00:00:00Z".parse().unwrap())),
            None
        );
        assert_eq!(dismissals.get(kept, None), None);
        assert_eq!(dismissals.get(other, modified), None);

        assert_eq!(undismiss(&data_dir, kept).unwrap(), dismissal);
        assert!(matches!(
            undismiss(&data_dir, kept),
            Err(StateError::NotDismissed { .. })
        ));
        assert!(Dismissals::load(&data_dir).unwrap().0.is_empty());
    }

    #[test]
    fn a_broken_dismissals_file_is_an_error_not_an_empty_list() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        assert!(
            Dismissals::load(&data_dir).unwrap().0.is_empty(),
            "no file is no dismissals"
        );
        fs::create_dir_all(data_dir.state_dir().join(DISMISSALS)).unwrap();
        assert!(
            matches!(Dismissals::load(&data_dir), Err(StateError::Read { .. })),
            "a folder in its place is not an empty file"
        );
        fs::remove_dir(data_dir.state_dir().join(DISMISSALS)).unwrap();
        fs::write(data_dir.state_dir().join(DISMISSALS), "{").unwrap();
        assert!(matches!(
            Dismissals::load(&data_dir),
            Err(StateError::Read { .. })
        ));
    }

    #[test]
    fn changes_compare_with_the_newest_report_that_has_a_verdict() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path();
        let [kept, gone, added, again, hidden] = [1, 2, 3, 4, 5].map(FindingKey);
        let at = "2026-11-01T00:00:00Z";
        let since = |active: &[FindingKey], all: &[FindingKey]| {
            let set = |keys: &[FindingKey]| keys.iter().copied().collect::<BTreeSet<_>>();
            Changes::since_last(sweeps, "mac", &set(active), &set(all)).unwrap()
        };
        assert!(since(&[kept], &[kept]).is_none(), "no sweeps yet");
        let none = BTreeSet::new();
        let missing = tmp.path().join("no-sweeps-folder");
        assert!(
            Changes::since_last(&missing, "mac", &none, &none)
                .unwrap()
                .is_none()
        );
        let file = tmp.path().join("a-file");
        fs::write(&file, "").unwrap();
        assert!(
            matches!(
                Changes::since_last(&file, "mac", &none, &none),
                Err(StateError::Read { .. })
            ),
            "a sweeps path that is not a folder is an error, not an empty list"
        );

        // By name `-10` sorts before `-2`; it is the newer sweep.
        let mut last = report("2026-11-04T00:00:00Z", None, &[kept, gone, again], at);
        last["findings"][2]["dismissed"] = json!({"reason": "x", "at": at, "modified": at});
        save(sweeps, "20261104T000000Z-10/mac", &last);
        save(
            sweeps,
            "20261104T000000Z-2/mac",
            &report("2026-11-03T00:00:00Z", None, &[hidden], at),
        );
        let failed = report("2026-11-05T00:00:00Z", Some("agent"), &[], at);
        save(sweeps, "20261105T000000Z/mac", &failed);
        save(
            sweeps,
            "20261106T000000Z/github-o--r",
            &report("2026-11-06T00:00:00Z", None, &[], at),
        );
        save(
            sweeps,
            "not-a-sweep/mac",
            &report("2026-11-07T00:00:00Z", None, &[], at),
        );
        // As long as a start second, but not one.
        save(
            sweeps,
            "notasweepfolder1/mac",
            &report("2026-11-07T00:00:00Z", None, &[], at),
        );

        // Now: one kept, one gone, one added, one shown again, and one dismissed while new.
        let changes = since(&[kept, added, again], &[kept, added, again, hidden]).unwrap();
        assert_eq!(
            changes.since,
            "2026-11-04T00:00:00Z".parse::<Timestamp>().unwrap()
        );
        assert_eq!(changes.new, [added, again]);
        assert_eq!(changes.resolved, [gone]);

        let changes = since(&[], &[kept, gone]).unwrap();
        assert_eq!(
            (changes.new, changes.resolved),
            (vec![], vec![]),
            "dismissed since"
        );

        let broken = sweeps.join("20261104T000000Z-10/mac/report.json");
        fs::write(&broken, "{").unwrap();
        assert!(matches!(
            Changes::since_last(sweeps, "mac", &BTreeSet::new(), &BTreeSet::new()),
            Err(StateError::Read { path, .. }) if path == broken
        ));

        // A report that exists but cannot be read is an error too, not a missing report.
        fs::remove_file(&broken).unwrap();
        fs::create_dir(&broken).unwrap();
        assert!(matches!(
            Changes::since_last(sweeps, "mac", &BTreeSet::new(), &BTreeSet::new()),
            Err(StateError::Read { path, .. }) if path == broken
        ));
    }

    #[test]
    fn first_seen_comes_from_the_newest_verdict_or_its_start() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path();
        assert!(
            first_seen(sweeps, "mac").unwrap().is_empty(),
            "no sweeps yet"
        );
        let [old, unseen] = [1, 2].map(FindingKey);
        let entry = |key: FindingKey| json!({"key": key, "severity": "low", "title": "t"});
        let mut seen = entry(old);
        seen["first_seen"] = json!("2026-10-01T00:00:00Z");
        let report = json!({
            "started": "2026-11-05T00:00:00Z", "target": "mac", "failure": null,
            "findings": [seen], "issues": [entry(unseen)],
        });
        save(sweeps, "20261105T000000Z/mac", &report);
        let failed = json!({"started": "2026-11-06T00:00:00Z", "target": "mac",
            "failure": "agent", "findings": [], "issues": []});
        save(sweeps, "20261106T000000Z/mac", &failed);
        let first = first_seen(sweeps, "mac").unwrap();
        let at = |s: &str| s.parse::<Timestamp>().unwrap();
        assert_eq!(first.get(&old), Some(&at("2026-10-01T00:00:00Z")));
        assert_eq!(
            first.get(&unseen),
            Some(&at("2026-11-05T00:00:00Z")),
            "saved before the field: the report's start; the failed sweep after it is skipped"
        );
    }

    #[test]
    fn latest_lists_open_entries_worst_first_with_state_dismissals_and_plain_text() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "[github]\nrepos = [\"o/r\"]\n").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let sweeps = data_dir.sweeps_dir();
        let [low, high, hidden] = [1, 2, 3].map(FindingKey);
        let entry = |key: FindingKey, severity: &str, title: &str| {
            json!({"key": key, "severity": severity, "title": title,
                "fix": {"summary": "up\ngrade", "steps": [], "commands": []}})
        };
        let report = json!({
            "started": "2026-11-05T00:00:00Z", "target": "mac", "failure": null,
            "findings": [entry(low, "low", "a\u{1b}[2Jb"), entry(hidden, "high", "h")],
            "issues": [entry(high, "critical", "file x\u{202e}y")],
        });
        save(&sweeps, "20261105T000000Z/mac", &report);
        let failed = json!({"started": "2026-11-06T00:00:00Z", "target": "mac",
            "failure": "agent", "findings": [], "issues": []});
        save(&sweeps, "20261106T000000Z/mac", &failed);
        dismiss(&data_dir, hidden, "accepted").unwrap();

        let all = latest(&data_dir, &config).unwrap();
        assert_eq!(all.len(), 2, "every configured target, in sweep order");
        let mac = &all[0];
        assert_eq!(mac.target, "mac");
        assert_eq!(
            mac.swept,
            Some("2026-11-05T00:00:00Z".parse().unwrap()),
            "past the failure"
        );
        assert_eq!(mac.dismissed, 1, "dismissed in state, with no sweep since");
        let open: Vec<_> = mac.open.iter().map(|o| (o.key, o.title.as_str())).collect();
        assert_eq!(
            open,
            [(high, "file x\u{fffd}y"), (low, "a\u{fffd}[2Jb")],
            "worst first"
        );
        assert_eq!(mac.open[0].fix, "up grade", "one line");
        assert_eq!((all[1].target.as_str(), all[1].swept), ("github:o/r", None));
    }

    #[test]
    fn a_finding_fixed_after_its_sweep_moves_to_fixed_until_a_later_sweep_finds_it() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let sweeps = data_dir.sweeps_dir();
        let [fixed, partial, earlier, refixed] = [1, 2, 3, 4].map(FindingKey);
        let keys = [fixed, partial, earlier, refixed];
        save(
            &sweeps,
            "20261105T100000Z/mac",
            &report("2026-11-05T10:00:00Z", None, &keys, "2026-11-01T00:00:00Z"),
        );
        let fix = |key: FindingKey, finished: &str, outcome: &str| {
            json!({"key": key, "target": "mac", "agent": "grok",
                "started": finished, "finished": finished, "exit_code": 0,
                "outcome": outcome, "summary": "upgraded\nit", "pull_request": null,
                "confirmed": "asked", "dir": "/x"})
            .to_string()
        };
        let state = data_dir.state_dir();
        fs::create_dir_all(&state).unwrap();
        let lines = [
            fix(fixed, "2026-11-05T11:00:00Z", "fixed"),
            fix(partial, "2026-11-05T11:00:00Z", "partial"),
            // Fixed before the sweep that still found it: the fix did not hold.
            fix(earlier, "2026-11-05T09:00:00Z", "fixed"),
            // A crash left a torn line; the next record starts on a new one.
            r#"{"key": "#.to_owned(),
            // Fixed, then a later run failed: the newest run decides.
            fix(refixed, "2026-11-05T11:00:00Z", "fixed"),
            fix(refixed, "2026-11-05T12:00:00Z", "failed"),
        ];
        fs::write(state.join("fixes.jsonl"), lines.join("\n") + "\n").unwrap();

        let mac = &latest(&data_dir, &config).unwrap()[0];
        let open: Vec<FindingKey> = mac.open.iter().map(|o| o.key).collect();
        assert_eq!(open, [partial, earlier, refixed]);
        let moved: Vec<FindingKey> = mac.fixed.iter().map(|f| f.open.key).collect();
        assert_eq!(moved, [fixed]);
        assert_eq!(mac.fixed[0].summary, "upgraded it", "one line");
        assert_eq!(
            mac.fixed[0].fixed_at,
            "2026-11-05T11:00:00Z".parse::<Timestamp>().unwrap()
        );

        // A sweep after the fix that still finds it lists it as open again.
        save(
            &sweeps,
            "20261105T130000Z/mac",
            &report("2026-11-05T13:00:00Z", None, &keys, "2026-11-01T00:00:00Z"),
        );
        let mac = &latest(&data_dir, &config).unwrap()[0];
        assert!(mac.fixed.is_empty());
        assert_eq!(mac.open.len(), 4);
    }

    #[test]
    fn the_last_sweep_is_the_newest_folder_with_or_without_a_verdict() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        assert_eq!(
            last_sweep_started(&data_dir).unwrap(),
            None,
            "no sweeps folder"
        );
        for name in [
            "20261105T101500Z",
            "20261106T090000Z-2",
            "20261106T090000Z",
            "notes",
            "20261399T000000Z",
        ] {
            fs::create_dir_all(data_dir.sweeps_dir().join(name)).unwrap();
        }
        let last = last_sweep_started(&data_dir).unwrap();
        assert_eq!(last, Some("2026-11-06T09:00:00Z".parse().unwrap()));
    }
}
