//! What carries over from one sweep to the next: finding keys, dismissals, what changed
//! since the target's last sweep, the findings a degraded sweep could not check again
//! ([`CarriedFinding`], see `unchecked`), and which reported fixes a later sweep confirmed
//! (`state/fixes.jsonl`).
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
use crate::findings::Confidence;
use crate::findings::Severity;
use crate::findings::is_forging;
use crate::fix;
use crate::inventory::FoundIn;
use crate::paths::DataDir;
use crate::sweep;
use crate::unchecked::Unchecked;

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

/// The installed component a finding is in, as the list groups findings.
#[derive(Debug, Serialize)]
pub struct InComponent {
    /// Findings with the same key are in the same component.
    pub key: ComponentKey,
    /// The component's name as the list shows it: a Homebrew formula's own name (`curl`, which
    /// holds the products curl and libcurl), otherwise the finding's component name.
    pub name: String,
}

/// The key of an installed component, 16 hex digits hashed as a [`FindingKey`] is: from the
/// target, its version and where it was found, and its lookup unless that place is one
/// installed thing (a Homebrew formula, a toolchain). So two versions of one package, or one
/// version in two places, are two components, and the NVD products of one formula are one.
/// It is never stored; dismissals and fixes keep using each finding's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ComponentKey(pub(crate) FindingKey);

impl fmt::Display for ComponentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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

/// Runs `change` holding `state/.lock`, which every write to the state folder takes, and the
/// write of the HTML report.
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

/// A finding of a target's last report that a sweep did not find again and could not have:
/// a source that could have produced it failed in that sweep ([`Unchecked::covers`]). The new
/// report keeps it as the last one saved it, so it stays open and its fix unconfirmed until a
/// sweep checks it. Without this, a sweep with OSV offline read as every OSV finding resolved.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct CarriedFinding {
    /// Its key.
    #[serde(skip)]
    pub(crate) key: FindingKey,
    /// How bad the last check found it.
    #[serde(skip)]
    pub(crate) severity: Severity,
    /// One line naming it.
    #[serde(skip)]
    pub(crate) title: String,
    /// When the last sweep that checked it started; it has been carried since.
    #[serde(skip)]
    pub(crate) carried_from: Timestamp,
    /// The user's dismissal, while it holds.
    #[serde(skip)]
    pub(crate) dismissed: Option<Dismissal>,
    /// The entry as the last report saved it, with `carried_from` and `dismissed` set to the
    /// fields above: what is written.
    entry: serde_json::Map<String, serde_json::Value>,
}

/// A report's findings and carried findings with all their fields, for [`carried_over`].
#[derive(Debug, Deserialize)]
struct Entries {
    findings: Vec<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    carried: Vec<serde_json::Map<String, serde_json::Value>>,
}

/// The findings of the target's newest readable report with a verdict in `<sweep>/<dir_name>`
/// that are not in `found`, this sweep's findings, and that a source failed in `unchecked`
/// could have produced, each with its dismissal in `dismissals`. Unreadable reports are passed
/// over; the sweep notes their error with its changes. A finding carried before keeps the time
/// it was first carried from.
pub(crate) fn carried_over(
    sweeps: &Path,
    dir_name: &str,
    unchecked: &Unchecked,
    found: &BTreeSet<FindingKey>,
    dismissals: &Dismissals,
) -> Result<Vec<CarriedFinding>, StateError> {
    if unchecked.is_empty() {
        return Ok(Vec::new());
    }
    // Past an unreadable report, as the popover reads: the findings it shows are those that
    // must not be lost. That report's error is the sweep's note on its changes.
    let (Some((path, last)), _) = newest_readable_verdict(sweeps, dir_name) else {
        return Ok(Vec::new());
    };
    // Read again whole: `Saved` keeps only what the lifecycle uses, and a carried finding is
    // written back with every field it had.
    let invalid = |e: serde_json::Error| StateError::Read {
        path: path.clone(),
        source: io::Error::new(io::ErrorKind::InvalidData, e),
    };
    let text = fs::read_to_string(&path).map_err(|source| StateError::Read {
        path: path.clone(),
        source,
    })?;
    let entries: Entries = serde_json::from_str(&text).map_err(invalid)?;
    let mut carried = Vec::new();
    for mut entry in entries.findings.into_iter().chain(entries.carried) {
        let saved =
            SavedEntry::deserialize(&serde_json::Value::Object(entry.clone())).map_err(invalid)?;
        let lookup = saved
            .installed
            .as_ref()
            .map_or(&serde_json::Value::Null, |i| &i.lookup);
        if found.contains(&saved.key) || !unchecked.covers(lookup) {
            continue;
        }
        let carried_from = saved.carried_from.unwrap_or(last.started);
        let dismissed = dismissals.get(saved.key, saved.modified).cloned();
        let carried_value = serde_json::to_value(carried_from).map_err(invalid)?;
        entry.insert("carried_from".to_owned(), carried_value);
        entry.insert(
            "dismissed".to_owned(),
            serde_json::to_value(&dismissed).map_err(invalid)?,
        );
        carried.push(CarriedFinding {
            key: saved.key,
            severity: saved.severity,
            title: saved.title,
            carried_from,
            dismissed,
            entry,
        });
    }
    Ok(carried)
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

/// Like [`newest_verdict`], except that a report that cannot be read is passed over for the
/// next one, and the first such error is returned beside what was found.
fn newest_readable_verdict(
    sweeps: &Path,
    dir_name: &str,
) -> (Option<(PathBuf, Saved)>, Option<StateError>) {
    let sweeps = match newest_first(sweeps) {
        Ok(sweeps) => sweeps,
        Err(e) => return (None, Some(e)),
    };
    let mut first_error = None;
    for sweep in sweeps {
        let dir = sweep.join(dir_name);
        match read_saved(&dir) {
            Ok(Some(saved)) if saved.failure.is_none() => {
                return (Some((dir.join("report.json"), saved)), first_error);
            }
            Ok(_) => {}
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    (None, first_error)
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
    /// The findings and issues not dismissed, most severe first; each says whether a fix was
    /// reported for it.
    pub open: Vec<Open>,
    /// Confirmed fixes that finished in the last `CONFIRMED_DAYS` days, newest first: a run
    /// reported the finding fixed, and a later sweep no longer finds it.
    pub fixed: Vec<Fixed>,
    /// How many are dismissed.
    pub dismissed: usize,
    /// The sources that failed in that sweep: while any did, the target is not clear.
    pub unchecked: Unchecked,
    /// What could not be read for the target, so what it shows may be incomplete: its newest
    /// report (an older one shows instead), the dismissals, or the fix history.
    pub problem: Option<String>,
}

/// A fix a later sweep confirmed: the finding it fixed is gone.
#[derive(Debug, Serialize)]
pub struct Fixed {
    /// The finding's key.
    pub key: FindingKey,
    /// Its title when the fix was planned.
    pub title: String,
    /// When the fix finished.
    pub fixed_at: Timestamp,
    /// The agent's one-line summary of what it did.
    pub summary: String,
    /// The pull request it opened, for a repository.
    pub pull_request: Option<String>,
}

/// What the fix history says about an open finding.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FixState {
    /// A fix of this very report ended `fixed`; the next sweep confirms it. The finding stays
    /// in [`Latest::open`] so that sweep can. A fix is for the installed component, so the
    /// popover decides over every finding in it: its item shows as fixed, not open
    /// ([`ReportedFix`](crate::popover::ReportedFix)), when one finding has this state without
    /// a pull request and none is [`FixState::NotHeld`] or opened one. A fix that opened a
    /// pull request keeps its item open until a sweep no longer finds it: whether the pull
    /// request was merged is not checked.
    Reported {
        /// When it finished.
        at: Timestamp,
        /// The agent's one-line summary.
        summary: String,
        /// The pull request it opened: the fix lands once that is merged.
        pull_request: Option<String>,
    },
    /// A fix ended `fixed`, but a later sweep still finds it: the fix did not hold.
    NotHeld {
        /// When that fix finished.
        at: Timestamp,
    },
}

/// How long a confirmed fix stays in [`Latest::fixed`]. The user's choice (2026-11-08): recent
/// fixes, so what Vigil fixed stays visible; older ones remain in `state/fixes.jsonl`.
pub(crate) const CONFIRMED_DAYS: i64 = 30;

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
    /// The installed component it is in; `None` for an issue.
    pub component: Option<InComponent>,
    /// The advisory ids, primary first; empty for an issue.
    pub advisories: Vec<String>,
    /// Where it was found, one line; empty for an issue.
    pub place: String,
    /// Exploited in the wild (CISA KEV).
    pub known_exploited: bool,
    /// How sure the agent is that the installed version is affected; `None` for an issue.
    pub confidence: Option<Confidence>,
    /// What the agent checked, in its words; empty in a report saved before it was kept.
    pub evidence: String,
    /// What it means, in the agent's words.
    pub explanation: String,
    /// One line: what the fix does.
    pub fix: String,
    /// The fix's steps, in order.
    pub steps: Vec<String>,
    /// The fix's exact commands.
    pub commands: Vec<String>,
    /// When a sweep first found it; `None` in a report saved before that was kept.
    pub first_seen: Option<Timestamp>,
    /// Whether the newest sweep is the first to find it since the one before.
    pub new: bool,
    /// What the fix history says about it, if anything.
    pub fix_state: Option<FixState>,
}

/// Each configured target's open findings and issues, in sweep order. Whether one is
/// dismissed comes from `state/dismissals.json`, as for `fix`, so a dismissal shows at once.
/// Titles and fix summaries are shown as plain lines: they hold agent text and names from the
/// target.
///
/// Never fails as a whole: what cannot be read is [`Latest::problem`] of the targets it
/// touches, so one broken file neither blanks the other targets nor hides their findings. A
/// target whose newest report cannot be read shows the newest one that can. Dismissals that
/// cannot be read dismiss nothing, and a fix history that cannot be read reports no fix: both
/// show more as open, never less.
pub fn latest(data_dir: &DataDir, config: &Config) -> Vec<Latest> {
    let (state, problems) = State::load_or_empty(data_dir);
    sweep::configured_targets(config)
        .into_iter()
        .map(|(target, dir_name)| {
            let (saved, error) = newest_readable_verdict(&state.sweeps, &dir_name);
            let mut latest = state.latest_from(target, saved.map(|(_, saved)| saved));
            let error = error.map(|e| sweep::plain(&sweep::error_chain(&e)));
            let all: Vec<String> = problems.iter().cloned().chain(error).collect();
            latest.problem = (!all.is_empty()).then(|| all.join("; "));
            latest
        })
        .collect()
}

/// The [`Latest`] of one target, `target` as configured (`mac`, `server:name`), whose sweep
/// folders are named `dir_name`. Reads the same files [`latest`] reads, but fails when any of
/// them cannot be read: Fix all acts on this, and must not act on a guess.
pub(crate) fn latest_of(
    data_dir: &DataDir,
    target: &str,
    dir_name: &str,
) -> Result<Latest, StateError> {
    let state = State::load(data_dir)?;
    let saved = newest_verdict(&state.sweeps, dir_name)?.map(|(_, saved)| saved);
    Ok(state.latest_from(target.to_owned(), saved))
}

/// What [`latest`] reads once for every target: the dismissals and the fix history.
struct State {
    sweeps: PathBuf,
    dismissals: Dismissals,
    /// The last run of each key, which decides: runs are in the order they ran.
    last: BTreeMap<FindingKey, fix::Run>,
    /// Confirmed fixes that finished before this are no longer listed.
    since: Timestamp,
}

impl State {
    fn load(data_dir: &DataDir) -> Result<Self, StateError> {
        Ok(Self::of(
            data_dir,
            Dismissals::load(data_dir)?,
            fix::runs(data_dir)?,
        ))
    }

    /// The state, with no dismissals or no fix history in place of a file that cannot be
    /// read, and a problem for each.
    fn load_or_empty(data_dir: &DataDir) -> (Self, Vec<String>) {
        let mut problems = Vec::new();
        let mut note = |what: &str, e: &StateError| {
            problems.push(sweep::plain(&format!("{what}: {}", sweep::error_chain(e))));
        };
        let dismissals = Dismissals::load(data_dir).unwrap_or_else(|e| {
            note("dismissals, so dismissed findings show", &e);
            Dismissals::default()
        });
        let runs = fix::runs(data_dir).unwrap_or_else(|e| {
            note("the fix history, so no fix shows as reported", &e);
            Vec::new()
        });
        (Self::of(data_dir, dismissals, runs), problems)
    }

    fn of(data_dir: &DataDir, dismissals: Dismissals, runs: Vec<fix::Run>) -> Self {
        Self {
            sweeps: data_dir.sweeps_dir(),
            dismissals,
            last: runs.into_iter().map(|r| (r.key, r)).collect(),
            since: Timestamp::now() - jiff::SignedDuration::from_hours(24 * CONFIRMED_DAYS),
        }
    }

    /// The [`Latest`] of `target` from `saved`, its newest report with a verdict, if any.
    fn latest_from(&self, target: String, saved: Option<Saved>) -> Latest {
        let Some(saved) = saved else {
            return Latest {
                target,
                swept: None,
                components: 0,
                open: Vec::new(),
                fixed: Vec::new(),
                dismissed: 0,
                unchecked: Unchecked::default(),
                problem: None,
            };
        };
        let (dismissed, kept): (Vec<_>, Vec<_>) = saved
            .entries()
            .partition(|e| self.dismissals.get(e.key, e.modified).is_some());
        let new = |key: FindingKey| saved.changes.as_ref().is_some_and(|c| c.new.contains(&key));
        let mut open: Vec<Open> = kept
            .into_iter()
            .map(|e| {
                let state = self
                    .last
                    .get(&e.key)
                    .and_then(|run| fix_state(run, saved.started, e.carried_from));
                open_entry(&target, e, new(e.key), state)
            })
            .collect();
        open.sort_by_key(|o| o.severity);
        let found: BTreeSet<FindingKey> = saved.entries().map(|e| e.key).collect();
        let mut fixed: Vec<Fixed> = self
            .last
            .values()
            .filter(|run| run.target == target && run.finished >= self.since)
            .filter(|run| confirmed(run, &found, saved.started))
            .map(|run| Fixed {
                key: run.key,
                title: sweep::plain(&run.title),
                fixed_at: run.finished,
                summary: sweep::plain(&run.summary),
                pull_request: run.pull_request.clone(),
            })
            .collect();
        fixed.sort_by_key(|f| std::cmp::Reverse(f.fixed_at));
        Latest {
            target,
            swept: Some(saved.started),
            components: saved.components,
            open,
            fixed,
            dismissed: dismissed.len(),
            unchecked: saved.unchecked,
            problem: None,
        }
    }
}

/// What `run`, the last fix run of an open finding in the report that started at `report`,
/// says about it. Decided by which report the run was planned from, never by comparing the
/// run's clock with a report's: a fix of a report no sweep has checked the finding since is
/// reported and awaits the next sweep, and a successful fix of an earlier report means a later
/// sweep still found the finding.
///
/// No sweep has checked a finding since `report`, or for one carried over since `carried_from`
/// (the start of the last sweep that checked it): a fix planned from that report or any later
/// one is still to be confirmed. Report start times order sweeps, as their folder names do.
fn fix_state(
    run: &fix::Run,
    report: Timestamp,
    carried_from: Option<Timestamp>,
) -> Option<FixState> {
    if !run.succeeded() {
        return None;
    }
    let found = run.found?;
    // Planned from a newer report than this one, which is shown because that one cannot be
    // read: nothing is known of the fix here.
    if found > report {
        return None;
    }
    let unchecked_since = carried_from.unwrap_or(report);
    Some(if found >= unchecked_since {
        FixState::Reported {
            at: run.finished,
            summary: sweep::plain(&run.summary),
            pull_request: run.pull_request.clone(),
        }
    } else {
        FixState::NotHeld { at: run.finished }
    })
}

/// Whether `run` is a confirmed fix: it succeeded, and the newest report of its target, which
/// started at `report` and holds the keys in `found`, is a later sweep than the one the fix was
/// planned from and no longer has the finding.
fn confirmed(run: &fix::Run, found: &BTreeSet<FindingKey>, report: Timestamp) -> bool {
    run.succeeded() && run.found.is_some_and(|f| f < report) && !found.contains(&run.key)
}

/// `entry` as shown. Every text is a plain line: it holds agent text and names from the
/// target. Commands passed the sweep's printable-ASCII check.
fn open_entry(target: &str, entry: &SavedEntry, new: bool, fix_state: Option<FixState>) -> Open {
    let plain = |text: &str| sweep::plain(text);
    Open {
        key: entry.key,
        severity: entry.severity,
        title: plain(&entry.title),
        name: plain(&entry.name),
        version: entry.installed.as_ref().map(|i| plain(&i.version)),
        component: entry
            .installed
            .as_ref()
            .map(|i| i.component(target, entry.key, &plain(&entry.name))),
        advisories: entry.advisories.iter().map(|a| plain(a)).collect(),
        place: plain(&entry.place),
        known_exploited: entry.known_exploited,
        confidence: entry.confidence,
        evidence: plain(&entry.evidence),
        explanation: plain(&entry.explanation),
        fix: entry
            .fix
            .as_ref()
            .map_or(String::new(), |f| plain(&f.summary)),
        steps: entry
            .fix
            .as_ref()
            .map_or(Vec::new(), |f| f.steps.iter().map(|s| plain(s)).collect()),
        commands: entry.fix.as_ref().map_or(Vec::new(), |f| {
            f.commands.iter().map(|c| plain(c)).collect()
        }),
        first_seen: entry.first_seen,
        new,
        fix_state,
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
    /// Absent, like `unchecked`, in a report saved before sweeps carried findings over.
    #[serde(default)]
    carried: Vec<SavedEntry>,
    issues: Vec<SavedEntry>,
    changes: Option<SavedChanges>,
    #[serde(default)]
    unchecked: Unchecked,
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
    /// A finding's; an issue has none.
    #[serde(default)]
    confidence: Option<Confidence>,
    #[serde(default)]
    evidence: String,
    #[serde(default)]
    explanation: String,
    installed: Option<SavedInstalled>,
    fix: Option<SavedFix>,
    #[serde(default)]
    modified: Option<Timestamp>,
    /// Only whether it is there matters.
    #[serde(default)]
    dismissed: Option<IgnoredAny>,
    /// When the last sweep that checked it started, for a finding carried over since; `None`
    /// for one this report checked.
    #[serde(default)]
    carried_from: Option<Timestamp>,
}

#[derive(Debug, Clone, Deserialize)]
struct SavedFix {
    summary: String,
    #[serde(default)]
    steps: Vec<String>,
    #[serde(default)]
    commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SavedInstalled {
    version: String,
    /// Kept as the report has them, only to tell components apart; values rather than types,
    /// so a place this build does not know still reads.
    #[serde(default)]
    lookup: serde_json::Value,
    #[serde(default)]
    found_in: serde_json::Value,
}

impl SavedInstalled {
    /// The component in `target` of the finding `key`, whose component is named `name`.
    /// Every report since findings had an `installed` keeps its lookup and place; one without
    /// them would make every finding at a version one component, so such a finding stands
    /// alone instead.
    fn component(&self, target: &str, key: FindingKey, name: &str) -> InComponent {
        let key = if self.lookup.is_null() || self.found_in.is_null() {
            ComponentKey(FindingKey::new(&[target, &key.to_string()]))
        } else {
            component_key(target, &self.lookup, &self.version, &self.found_in)
        };
        let place = FoundIn::deserialize(&self.found_in).ok();
        InComponent {
            key,
            name: place
                .as_ref()
                .and_then(FoundIn::install_name)
                .map_or_else(|| name.to_owned(), sweep::plain),
        }
    }
}

/// The key of the component at `version` that `lookup` and `found_in` name in `target`,
/// given as a report saves them: the one rule for what is one component, for the popover, the
/// report, the CLI and notifications. The lookup counts only where the place holds many
/// things; a place this build cannot read counts as one that does. One report's writer
/// serializes every component the same way, so equal components print as equal text here,
/// whether or not a crate in the build turns on `serde_json`'s `preserve_order`.
pub(crate) fn component_key(
    target: &str,
    lookup: &serde_json::Value,
    version: &str,
    found_in: &serde_json::Value,
) -> ComponentKey {
    let one_install = FoundIn::deserialize(found_in).is_ok_and(|place| place.is_one_install());
    let lookup = if one_install {
        String::new()
    } else {
        lookup.to_string()
    };
    ComponentKey(FindingKey::new(&[
        target,
        &lookup,
        version,
        &found_in.to_string(),
    ]))
}

impl SavedEntry {
    /// Its advisory's `modified` time, as the report had it.
    pub(crate) fn modified(&self) -> Option<Timestamp> {
        self.modified
    }
}

impl Saved {
    fn entries(&self) -> impl Iterator<Item = &SavedEntry> {
        self.findings
            .iter()
            .chain(&self.carried)
            .chain(&self.issues)
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
    use serde_json::Value;
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

        let all = latest(&data_dir, &config);
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

    /// A Mac report whose findings cover every grouping case, for
    /// `findings_are_grouped_by_installed_place_and_version`.
    fn grouping_report() -> serde_json::Value {
        let finding = |key: u64, name: &str, lookup, version: &str, found_in| {
            json!({"key": FindingKey(key), "severity": "high", "name": name,
                "installed": {"lookup": lookup, "version": version, "found_in": found_in}})
        };
        let formula = json!({"kind": "homebrew_formula", "name": "curl"});
        let curl = || json!({"product": "curl"});
        let npm = |name: &str| json!({"package": {"ecosystem": "npm", "name": name}});
        let lockfile = json!({"kind": "lockfile", "path": "/code/app/package-lock.json"});
        let unknown = json!({"kind": "a_place_from_a_later_build"});
        json!({
            "started": "2026-11-05T00:00:00Z", "target": "mac", "failure": null,
            "findings": [
                finding(1, "curl", curl(), "8.11.0", formula.clone()),
                // One formula, two NVD products: one upgrade, one component.
                finding(2, "libcurl", json!({"product": "haxx:libcurl"}), "8.11.0",
                    formula.clone()),
                finding(3, "curl", curl(), "8.10.0", formula.clone()),
                finding(4, "curl", curl(), "8.12.0", formula.clone()),
                finding(5, "curl", curl(), "8.11.0",
                    json!({"kind": "homebrew_formula", "name": "curl-openssl"})),
                // A lockfile holds many packages: the lookup tells them apart.
                finding(6, "lodash", npm("lodash"), "4.17.0", lockfile.clone()),
                finding(7, "lodash", npm("lodash"), "4.17.0", lockfile.clone()),
                finding(8, "minimist", npm("minimist"), "4.17.0", lockfile),
                finding(9, "curl", curl(), "8.11.0", unknown.clone()),
                finding(10, "libcurl", json!({"product": "haxx:libcurl"}), "8.11.0",
                    unknown),
                // Without a lookup and place, nothing says two findings share a component.
                json!({"key": FindingKey(12), "severity": "high", "installed": {"version": "1"}}),
                json!({"key": FindingKey(13), "severity": "high", "installed": {"version": "1"}}),
                // A lookup without a place is not enough either.
                json!({"key": FindingKey(14), "severity": "high",
                    "installed": {"lookup": curl(), "version": "1"}}),
                json!({"key": FindingKey(15), "severity": "high",
                    "installed": {"lookup": curl(), "version": "1"}}),
            ],
            "issues": [{"key": FindingKey(11), "severity": "low"}],
        })
    }

    #[test]
    fn findings_are_grouped_by_installed_place_and_version() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let report = grouping_report();
        save(&data_dir.sweeps_dir(), "20261105T000000Z/mac", &report);
        dismiss(&data_dir, FindingKey(3), "not used").unwrap();

        let mac = latest(&data_dir, &config).remove(0);
        let component = |key: u64| {
            let open = mac.open.iter().find(|o| o.key == FindingKey(key));
            open.map(|o| o.component.as_ref().map(|c| (c.key, c.name.as_str())))
        };
        let (curl_key, name) = component(1).flatten().expect("a finding has a component");
        assert_eq!(name, "curl");
        assert_eq!(
            component(2),
            Some(Some((curl_key, "curl"))),
            "named after the formula"
        );
        assert_eq!(component(3), None, "dismissed, so not open");
        for other in [4, 5, 6, 9] {
            let (key, _) = component(other).flatten().unwrap();
            assert_ne!(key, curl_key, "{other}");
        }
        let (lodash, name) = component(6).flatten().unwrap();
        assert_eq!(name, "lodash", "a lockfile's package keeps its own name");
        assert_eq!(component(7).flatten().map(|c| c.0), Some(lodash));
        assert_ne!(component(8).flatten().map(|c| c.0), Some(lodash));
        let unknown = component(9).flatten().unwrap().0;
        assert_ne!(
            component(10).flatten().map(|c| c.0),
            Some(unknown),
            "an unknown place"
        );
        assert_eq!(component(11), Some(None), "an issue has none");
        let bare = component(12).flatten().unwrap().0;
        assert_ne!(
            component(13).flatten().map(|c| c.0),
            Some(bare),
            "no lookup or place"
        );
        let lookup_only = component(14).flatten().unwrap().0;
        assert_ne!(
            component(15).flatten().map(|c| c.0),
            Some(lookup_only),
            "a lookup but no place"
        );

        let view = crate::popover::popover_view(vec![mac]);
        let sizes: Vec<(&str, usize)> = view
            .items
            .iter()
            .map(|i| (i.name.as_str(), 1 + i.others.len()))
            .collect();
        assert_eq!(
            sizes,
            [
                ("curl", 2),
                ("curl", 1),
                ("curl-openssl", 1),
                ("lodash", 2),
                ("minimist", 1),
                ("curl", 1),
                ("libcurl", 1),
                ("", 1),
                ("", 1),
                ("", 1),
                ("", 1),
                ("", 1)
            ],
            "the dismissed version is gone"
        );
    }

    #[test]
    fn latest_keeps_evidence_confidence_and_steps_as_plain_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let finding = json!({"key": FindingKey(1), "severity": "high", "title": "t",
            "confidence": "likely", "evidence": "4.1\n< 4.2\u{1b}",
            "fix": {"summary": "s", "steps": ["stop\nit", "upgrade"], "commands": ["c"]}});
        let issue = json!({"key": FindingKey(2), "severity": "low", "title": "i",
            "evidence": "e", "fix": {"summary": "s", "commands": []}});
        let report = json!({
            "started": "2026-11-05T00:00:00Z", "target": "mac", "failure": null,
            "findings": [finding], "issues": [issue],
        });
        save(&data_dir.sweeps_dir(), "20261105T000000Z/mac", &report);

        let all = latest(&data_dir, &config);
        let [finding, issue] = &all[0].open[..] else {
            panic!("one finding and one issue: {:?}", all[0].open);
        };
        assert!(matches!(finding.confidence, Some(Confidence::Likely)));
        assert_eq!(finding.evidence, "4.1 < 4.2\u{fffd}");
        assert_eq!(finding.steps, ["stop it", "upgrade"]);
        assert!(issue.confidence.is_none(), "an issue has no confidence");
        assert!(issue.steps.is_empty(), "saved without steps");
    }

    /// One `fixes.jsonl` line: a run of `key` planned from the report that started at `found`,
    /// finished now.
    fn run(key: FindingKey, found: &str, outcome: &str, exit_code: Option<i32>) -> String {
        run_finished(key, found, outcome, exit_code, 0)
    }

    /// [`run`], finished `days_ago` days ago.
    fn run_finished(
        key: FindingKey,
        found: &str,
        outcome: &str,
        exit_code: Option<i32>,
        days_ago: i64,
    ) -> String {
        let finished =
            (Timestamp::now() - jiff::SignedDuration::from_hours(24 * days_ago)).to_string();
        json!({"key": key, "title": "curl \u{1b}[2J is old", "found": found, "target": "mac",
            "agent": "grok", "started": finished, "finished": finished,
            "exit_code": exit_code, "outcome": outcome, "summary": "upgraded\nit",
            "pull_request": null, "confirmed": "asked", "dir": "/x"})
        .to_string()
    }

    fn history(data_dir: &DataDir, lines: &[String]) {
        let state = data_dir.state_dir();
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("fixes.jsonl"), lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn a_reported_fix_is_marked_and_stays_in_open_until_a_later_sweep_confirms_it() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let sweeps = data_dir.sweeps_dir();
        let [fixed, failed, crashed, refixed, old] = [1, 2, 3, 4, 5].map(FindingKey);
        let keys = [fixed, failed, crashed, refixed, old];
        let first = "2026-11-05T10:00:00Z";
        let modified = "2026-11-01T00:00:00Z";
        save(
            &sweeps,
            "20261105T100000Z/mac",
            &report(first, None, &keys, modified),
        );
        history(
            &data_dir,
            &[
                // Inside the window, near its end: listed once confirmed.
                run_finished(fixed, first, "fixed", Some(0), CONFIRMED_DAYS - 1),
                run(failed, first, "failed", Some(0)),
                // The agent reported fixed, then failed: not a fix.
                run(crashed, first, "fixed", Some(1)),
                run(refixed, first, "fixed", Some(0)),
                // The last run decides, in file order.
                run(refixed, first, "partial", Some(0)),
                // Finished just past the window: not listed once confirmed.
                run_finished(old, first, "fixed", Some(0), CONFIRMED_DAYS + 1),
            ],
        );

        let mac = &latest(&data_dir, &config)[0];
        assert_eq!(
            mac.open.len(),
            5,
            "a reported fix is still open and counted"
        );
        let marked: Vec<FindingKey> = mac
            .open
            .iter()
            .filter(|o| matches!(o.fix_state, Some(FixState::Reported { .. })))
            .map(|o| o.key)
            .collect();
        assert_eq!(marked, [fixed, old]);
        assert!(mac.fixed.is_empty(), "no sweep has confirmed it yet");

        // A later sweep: the fixed one is gone, the others are still found.
        let second = "2026-11-05T13:00:00Z";
        // The crashed one is gone too, but its fix did not succeed: not a confirmed fix.
        let rest = [failed, refixed];
        save(
            &sweeps,
            "20261105T130000Z/mac",
            &report(second, None, &rest, modified),
        );
        let mac = &latest(&data_dir, &config)[0];
        let confirmed: Vec<(FindingKey, &str)> = mac
            .fixed
            .iter()
            .map(|f| (f.key, f.title.as_str()))
            .collect();
        assert_eq!(confirmed, [(fixed, "curl \u{fffd}[2J is old")]);
        assert_eq!(mac.fixed[0].summary, "upgraded it", "one line");
        assert!(mac.open.iter().all(|o| o.fix_state.is_none()));
    }

    /// A report of `findings` (key, lookup), each high, with `extra` fields merged in.
    fn report_of(started: &str, findings: &[(FindingKey, Value)], extra: &Value) -> Value {
        let findings: Vec<Value> = findings
            .iter()
            .map(|(key, lookup)| {
                let installed =
                    json!({"version": "1", "lookup": lookup, "found_in": {"kind": "mac_os"}});
                json!({"key": key, "severity": "high", "title": format!("finding {key}"),
                    "advisories": [format!("GHSA-{key}")], "explanation": "kept as saved",
                    "installed": installed})
            })
            .collect();
        let mut report = json!({"started": started, "target": "mac", "failure": null,
            "findings": findings, "issues": []});
        for (field, value) in extra.as_object().unwrap() {
            report[field] = value.clone();
        }
        report
    }

    #[test]
    fn a_finding_a_failed_source_could_have_produced_is_carried_until_a_sweep_checks_it() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let sweeps = data_dir.sweeps_dir();
        let [package, curl, openssl] = [1, 2, 3].map(FindingKey);
        let lodash = json!({"package": {"ecosystem": "npm", "name": "lodash"}});
        let all = [
            (package, lodash.clone()),
            (curl, json!({"product": "curl"})),
            (openssl, json!({"product": "openssl"})),
        ];
        let first = "2026-11-05T10:00:00Z";
        save(
            &sweeps,
            "20261105T100000Z/mac",
            &report_of(first, &all, &json!({})),
        );
        history(&data_dir, &[run(curl, first, "fixed", Some(0))]);

        // NVD failed for curl; the agent found the OSV finding again and not openssl's.
        let nvd_down = Unchecked {
            nvd: ["curl".to_owned()].into(),
            ..Unchecked::default()
        };
        let found = BTreeSet::from([package]);
        let none = Dismissals::default();
        let carried = carried_over(&sweeps, "mac", &nvd_down, &found, &none).unwrap();
        let [c] = &carried[..] else {
            panic!("{carried:?}")
        };
        assert_eq!((c.key, c.severity), (curl, Severity::High));
        assert_eq!(c.carried_from, first.parse::<Timestamp>().unwrap());
        let written = serde_json::to_value(c).unwrap();
        assert_eq!(
            written["explanation"], "kept as saved",
            "every field it had"
        );
        assert_eq!(written["carried_from"], first);
        assert!(written["dismissed"].is_null());
        assert!(
            carried_over(&sweeps, "mac", &Unchecked::default(), &found, &none)
                .unwrap()
                .is_empty(),
            "a sweep that checked everything carries nothing"
        );

        // The degraded sweep's report: curl stays open, its fix still to be confirmed.
        let second = "2026-11-05T13:00:00Z";
        let degraded = json!({"carried": [written], "unchecked": nvd_down});
        let found_again = [(package, lodash.clone())];
        save(
            &sweeps,
            "20261105T130000Z/mac",
            &report_of(second, &found_again, &degraded),
        );
        let mac = &latest(&data_dir, &config)[0];
        let open: Vec<FindingKey> = mac.open.iter().map(|o| o.key).collect();
        assert_eq!(
            open,
            [package, curl],
            "openssl resolved: NVD answered for it"
        );
        let curl_open = mac.open.iter().find(|o| o.key == curl).unwrap();
        assert!(
            matches!(curl_open.fix_state, Some(FixState::Reported { .. })),
            "no sweep checked it since the fix: {:?}",
            curl_open.fix_state
        );
        assert!(
            mac.fixed.is_empty(),
            "not confirmed by a sweep that could not check it"
        );
        assert_eq!(mac.unchecked, nvd_down);
        let active = BTreeSet::from([package, curl]);
        let changes = Changes::since_last(&sweeps, "mac", &active, &active)
            .unwrap()
            .unwrap();
        assert!(changes.resolved.is_empty() && changes.new.is_empty());

        // Carried again: from the sweep that last checked it, not the one that carried it.
        let again = carried_over(&sweeps, "mac", &nvd_down, &found, &none).unwrap();
        assert_eq!(again[0].carried_from, first.parse::<Timestamp>().unwrap());

        // A sweep that checks it and no longer finds it confirms the fix.
        let third = "2026-11-05T16:00:00Z";
        save(
            &sweeps,
            "20261105T160000Z/mac",
            &report_of(third, &found_again, &json!({})),
        );
        let mac = &latest(&data_dir, &config)[0];
        assert_eq!(mac.fixed.len(), 1);
        assert_eq!(mac.fixed[0].key, curl);
    }

    #[test]
    fn an_unreadable_file_is_a_problem_of_its_targets_not_of_all() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "[github]\nrepos = [\"o/r\"]\n").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let sweeps = data_dir.sweeps_dir();
        let lookup = json!({"product": "curl"});
        let first = "2026-11-05T10:00:00Z";
        let critical = (FindingKey(1), lookup);
        let mut older = report_of(first, &[critical], &json!({}));
        older["findings"][0]["severity"] = json!("critical");
        save(&sweeps, "20261105T100000Z/mac", &older);
        save(
            &sweeps,
            "20261105T100000Z/github-o--r",
            &report(first, None, &[FindingKey(2)], "2026-11-01T00:00:00Z"),
        );
        let broken = sweeps.join("20261105T130000Z/mac");
        fs::create_dir_all(&broken).unwrap();
        fs::write(broken.join("report.json"), "{\"started\": ").unwrap();

        let [mac, repo] = &latest(&data_dir, &config)[..] else {
            panic!("two targets")
        };
        assert_eq!(
            mac.swept,
            first.parse().ok(),
            "the newest report that reads"
        );
        assert_eq!(mac.open[0].severity, Severity::Critical, "still shown");
        assert!(
            mac.problem.as_deref().unwrap().contains("report.json"),
            "{:?}",
            mac.problem
        );
        assert!(repo.problem.is_none() && repo.open.len() == 1);
        assert!(
            latest_of(&data_dir, "mac", "mac").is_err(),
            "Fix all refuses"
        );

        // A fix planned from the report that cannot be read says nothing about the older one.
        history(
            &data_dir,
            &[run(FindingKey(1), "2026-11-05T13:00:00Z", "fixed", Some(0))],
        );
        let mac = &latest(&data_dir, &config)[0];
        assert!(
            mac.open[0].fix_state.is_none(),
            "{:?}",
            mac.open[0].fix_state
        );
        assert!(mac.fixed.is_empty());
        // A degraded sweep carries what the newest readable report has.
        let nvd_down = Unchecked {
            nvd: ["curl".to_owned()].into(),
            ..Unchecked::default()
        };
        let none = Dismissals::default();
        let carried = carried_over(&sweeps, "mac", &nvd_down, &BTreeSet::new(), &none).unwrap();
        assert_eq!(carried.len(), 1, "past the unreadable report");

        // Dismissals that cannot be read dismiss nothing, on every target, which says so.
        let state = data_dir.state_dir();
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join(DISMISSALS), "not json").unwrap();
        let all = latest(&data_dir, &config);
        assert!(all[1].problem.as_deref().unwrap().starts_with("dismissals"));
        assert_eq!(all[1].open.len(), 1);
        assert!(
            all[0].problem.as_deref().unwrap().contains("; "),
            "both problems"
        );
    }

    /// Only a later sweep confirms a fix: one planned from the newest report itself is not
    /// confirmed by that report, whatever it holds.
    #[test]
    fn a_fix_of_the_newest_report_is_not_confirmed_by_it() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let started = "2026-11-05T10:00:00Z";
        let report = report(started, None, &[FindingKey(1)], "2026-11-01T00:00:00Z");
        save(&data_dir.sweeps_dir(), "20261105T100000Z/mac", &report);
        history(&data_dir, &[run(FindingKey(2), started, "fixed", Some(0))]);
        assert!(latest(&data_dir, &config)[0].fixed.is_empty());
    }

    #[test]
    fn a_fix_a_later_sweep_still_finds_did_not_hold() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "[github]\nrepos = [\"o/r\"]\n").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let sweeps = data_dir.sweeps_dir();
        let key = FindingKey(1);
        let (first, second) = ("2026-11-05T10:00:00Z", "2026-11-05T13:00:00Z");
        let modified = "2026-11-01T00:00:00Z";
        save(
            &sweeps,
            "20261105T100000Z/mac",
            &report(first, None, &[key], modified),
        );
        save(
            &sweeps,
            "20261105T130000Z/mac",
            &report(second, None, &[key], modified),
        );
        history(&data_dir, &[run(key, first, "fixed", Some(0))]);
        let all = latest(&data_dir, &config);
        assert!(matches!(
            all[0].open[0].fix_state,
            Some(FixState::NotHeld { .. })
        ));
        assert!(
            all[1].fixed.is_empty(),
            "a fix of the Mac is not the repository's"
        );
    }

    #[test]
    fn the_history_survives_a_line_torn_inside_a_character_and_a_zeroed_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let state = data_dir.state_dir();
        fs::create_dir_all(&state).unwrap();
        let good = run(FindingKey(1), "2026-11-05T10:00:00Z", "fixed", Some(0));
        let torn = run(FindingKey(2), "2026-11-05T10:00:00Z", "fixed", Some(0))
            .replace("upgraded", "upgradé");
        // The first of the two bytes of "é": a cut inside the character.
        let cut = &torn.as_bytes()[..=torn.find('é').unwrap()];
        let mut bytes = cut.to_vec();
        bytes.extend_from_slice(b"\n");
        bytes.extend_from_slice(good.as_bytes());
        bytes.extend_from_slice(b"\n\0\0\0");
        fs::write(state.join("fixes.jsonl"), bytes).unwrap();
        let runs = fix::runs(&data_dir).unwrap();
        let keys: Vec<FindingKey> = runs.iter().map(|r| r.key).collect();
        assert_eq!(keys, [FindingKey(1)]);
    }

    #[test]
    fn a_history_that_cannot_be_read_fails_and_a_missing_one_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        assert!(fix::runs(&data_dir).unwrap().is_empty(), "no history yet");
        // A folder where the file should be: reading it fails, and is not taken as no fixes.
        fs::create_dir_all(data_dir.state_dir().join("fixes.jsonl")).unwrap();
        assert!(matches!(fix::runs(&data_dir), Err(StateError::Read { .. })));
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
