//! Stopping a running sweep or fix, and the agent processes it started.
//!
//! [`Cancel`] is a flag shared between the thread that runs a sweep or fix and whoever may
//! stop it: the user, or the app as it quits. The sweep checks it between steps; an agent run
//! checks it while it waits.
//!
//! An agent is started as the leader of its own process group, so stopping it also stops
//! everything it started (a shell, `node`, an MCP server). On a cancel request the group gets
//! `SIGTERM`, and `SIGKILL` after [`GRACE`]. When the agent exits on its own, whatever it left
//! in its group is killed too: nothing a sweep or fix starts outlives it.
//!
//! An app that is force-quit or crashes cannot stop its agent, which keeps running (and
//! spending) with nobody to read its result. So while an agent runs, a `.pid` file beside its
//! log records the group and when the leader started; [`clean_up_interrupted`] stops a
//! recorded agent that is still running, and removes the half-written sweep folders.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::paths::DataDir;
use crate::sweep::Lock;
use crate::sweep::SweepError;

/// How long a stopped agent gets to exit after `SIGTERM` before `SIGKILL`. Arbitrary: long
/// enough for a CLI to flush its log and close its connection, short enough that quitting the
/// app does not hang.
pub(crate) const GRACE: Duration = Duration::from_secs(3);

/// How often a running agent is checked for having exited or been cancelled. Arbitrary: a
/// cancel within a fifth of a second feels immediate, and the check costs nothing.
const POLL: Duration = Duration::from_millis(200);

/// A request to stop a sweep or fix. Clones share the request.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// A request not yet made.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the sweep or fix to stop. It stops at its next check, within [`GRACE`] and a
    /// moment when an agent is running.
    pub fn cancel(&self) {
        // Relaxed: the flag orders no other memory. The thread that sees it only stops; what it
        // cleans up is its own state.
        self.0.store(true, Relaxed);
    }

    /// Whether [`cancel`](Self::cancel) was called.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Relaxed)
    }

    /// Fails with [`SweepError::Cancelled`] once cancelled, for a `?` between steps.
    pub(crate) fn check(&self) -> Result<(), SweepError> {
        if self.is_cancelled() {
            Err(SweepError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// How an agent run ended.
#[derive(Debug)]
pub(crate) enum Ended {
    /// It exited on its own.
    Exited(ExitStatus),
    /// It was stopped by a cancel request.
    Cancelled,
}

/// Makes the process `command` starts the leader of its own process group, so [`watch`] can
/// stop it and everything it starts together. It no longer gets the terminal's Ctrl-C, so a
/// caller on a terminal turns Ctrl-C into a [`Cancel`].
pub(crate) fn own_group(command: &mut Command) -> &mut Command {
    std::os::unix::process::CommandExt::process_group(command, 0)
}

/// Waits for `child`, started with [`own_group`], and records it in `record` while it runs;
/// stops its group when `cancel` is set. Whatever it leaves in its group is killed once it
/// exits.
///
/// # Errors
///
/// Fails when the record cannot be written, after stopping the agent, or when waiting fails.
pub(crate) fn watch(mut child: Child, record: &Path, cancel: &Cancel) -> io::Result<Ended> {
    let group = child.id();
    if let Err(e) = write_record(record, group) {
        stop(&mut child, group);
        return Err(e);
    }
    let ended = wait(&mut child, group, cancel);
    // The leader is gone; anything it started still in the group goes with it. An empty group
    // makes `kill` fail, which is the usual case and nothing to report.
    signal_group(group, "KILL");
    // Best effort: a record left behind names a leader that has exited, which
    // `clean_up_interrupted` tells apart by its start time and removes.
    drop(fs::remove_file(record));
    ended
}

fn wait(child: &mut Child, group: u32, cancel: &Cancel) -> io::Result<Ended> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Ended::Exited(status));
        }
        if cancel.is_cancelled() {
            stop(child, group);
            return Ok(Ended::Cancelled);
        }
        thread::sleep(POLL);
    }
}

/// Stops the group led by `child`: `SIGTERM`, then `SIGKILL` if the leader has not exited
/// after [`GRACE`]. Reaps the leader.
fn stop(child: &mut Child, group: u32) {
    signal_group(group, "TERM");
    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            return;
        }
        thread::sleep(POLL);
    }
    signal_group(group, "KILL");
    // Best effort: after SIGKILL the leader exits; an error here means it was already reaped.
    drop(child.wait());
}

/// Sends `signal` to every process in `group`. std has no `killpg`, and `kill(1)` avoids
/// `unsafe` for it: `kill -s TERM -- -<group>` signals the group.
fn signal_group(group: u32, signal: &str) {
    // Best effort: a group that has emptied makes `kill` fail, and there is nothing else to do
    // about a signal that could not be sent.
    drop(
        Command::new("/bin/kill")
            .args(["-s", signal, "--", &format!("-{group}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

/// Writes `<group> <start time>` for [`clean_up_interrupted`]. The start time, as `ps` prints
/// it, tells the recorded agent apart from a later process that got the same id.
fn write_record(record: &Path, group: u32) -> io::Result<()> {
    let started = start_time(group).unwrap_or_default();
    fs::write(record, format!("{group} {started}\n"))
}

/// When process `pid` started, as `ps -o lstart=` prints it, or `None` when it is not running.
fn start_time(pid: u32) -> Option<String> {
    let output = Command::new("/bin/ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (output.status.success() && !text.is_empty()).then(|| text.to_owned())
}

/// What [`clean_up_interrupted`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cleaned {
    /// Agents still running from an interrupted sweep or fix, now stopped.
    pub agents: usize,
    /// Half-written sweep folders removed: a target with no report, or a sweep with no target.
    pub folders: usize,
}

/// Cleans up after a sweep or fix that ended without cleaning up after itself, as when the app
/// was force-quit or crashed: stops each recorded agent that is still running, and removes
/// each sweep's target folder that has no report, then each sweep folder left empty.
///
/// Does nothing when a sweep or fix is running (from the CLI, say), since its folders are not
/// interrupted. Fix folders are kept whole: they are the history of what a fix did.
///
/// # Errors
///
/// Fails when a folder cannot be read or removed.
pub fn clean_up_interrupted(data_dir: &DataDir) -> Result<Cleaned, SweepError> {
    let _lock = match Lock::acquire(&data_dir.sweeps_dir()) {
        Ok(lock) => lock,
        Err(SweepError::Busy { .. }) => return Ok(Cleaned::default()),
        Err(e) => return Err(e),
    };
    clean_up_holding_lock(data_dir)
}

/// [`clean_up_interrupted`] for a caller that holds the sweeps lock, as a starting sweep does.
pub(crate) fn clean_up_holding_lock(data_dir: &DataDir) -> Result<Cleaned, SweepError> {
    let sweeps = data_dir.sweeps_dir();
    let mut cleaned = Cleaned::default();
    for record in records(&sweeps)?
        .into_iter()
        .chain(records(&data_dir.fixes_dir())?)
    {
        if stop_recorded(&record) {
            cleaned.agents += 1;
        }
        drop(fs::remove_file(&record));
    }
    for sweep in subdirs(&sweeps)? {
        cleaned.folders += remove_unfinished(&sweep)?;
    }
    Ok(cleaned)
}

/// Removes a sweep's target folders that have no report, and the sweep folder when nothing is
/// left in it: what a cancelled or interrupted sweep leaves. Returns how many it removed.
pub(crate) fn remove_unfinished(sweep: &Path) -> Result<usize, SweepError> {
    let mut removed = 0;
    for target in subdirs(sweep)? {
        if !target.join("report.json").exists() {
            remove(&target)?;
            removed += 1;
        }
    }
    let empty = fs::read_dir(sweep).is_ok_and(|mut entries| entries.next().is_none());
    if empty {
        remove(sweep)?;
        removed += 1;
    }
    Ok(removed)
}

/// Stops the group a record names when its leader is still the process that was recorded.
/// Returns whether one was stopped.
fn stop_recorded(record: &Path) -> bool {
    let Ok(text) = fs::read_to_string(record) else {
        return false;
    };
    let Some((group, started)) = text.trim().split_once(' ') else {
        return false;
    };
    let Ok(group) = group.parse::<u32>() else {
        return false;
    };
    // A record without a start time cannot tell its agent from a later process with the same
    // id, so it is not acted on.
    if started.is_empty() || start_time(group).as_deref() != Some(started) {
        return false;
    }
    signal_group(group, "TERM");
    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline && start_time(group).is_some() {
        thread::sleep(POLL);
    }
    signal_group(group, "KILL");
    true
}

/// The `.pid` records one and two levels below `dir`: `<sweep>/<target>/agent-1.pid` and
/// `<fix>/agent.pid`.
fn records(dir: &Path) -> Result<Vec<PathBuf>, SweepError> {
    let mut found = Vec::new();
    for run in subdirs(dir)? {
        for place in std::iter::once(run.clone()).chain(subdirs(&run)?) {
            found.extend(files_with_extension(&place, "pid")?);
        }
    }
    Ok(found)
}

fn subdirs(dir: &Path) -> Result<Vec<PathBuf>, SweepError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(SweepError::Read {
                path: dir.to_owned(),
                source,
            });
        }
    };
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| SweepError::Read {
            path: dir.to_owned(),
            source,
        })?;
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn files_with_extension(dir: &Path, extension: &str) -> Result<Vec<PathBuf>, SweepError> {
    let entries = fs::read_dir(dir).map_err(|source| SweepError::Read {
        path: dir.to_owned(),
        source,
    })?;
    Ok(entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == extension) && p.is_file())
        .collect())
}

fn remove(dir: &Path) -> Result<(), SweepError> {
    fs::remove_dir_all(dir).map_err(|source| SweepError::Write {
        path: dir.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    /// A script at `dir/name` running `body`.
    fn script(dir: &Path, name: &str, body: &str) -> Command {
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut command = Command::new(path);
        command.current_dir(dir);
        command
    }

    fn start(mut command: Command) -> Child {
        own_group(&mut command).spawn().unwrap()
    }

    /// Whether process `pid` still runs. A process just killed can take a moment to go, and
    /// nothing signals it, so this waits up to a deadline for it to.
    fn gone(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if start_time(pid).is_none() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn pid_in(path: &Path) -> u32 {
        fs::read_to_string(path).unwrap().trim().parse().unwrap()
    }

    #[test]
    fn an_agent_that_exits_takes_what_it_started_with_it() {
        let tmp = tempfile::tempdir().unwrap();
        let child = start(script(
            tmp.path(),
            "a",
            "sleep 60 &\necho $! > left.pid\nexit 4",
        ));
        let record = tmp.path().join("agent.pid");
        let ended = watch(child, &record, &Cancel::new()).unwrap();
        assert!(
            matches!(ended, Ended::Exited(s) if s.code() == Some(4)),
            "{ended:?}"
        );
        assert!(
            gone(pid_in(&tmp.path().join("left.pid"))),
            "the background sleep is killed"
        );
        assert!(!record.exists(), "the record goes with the agent");
    }

    #[test]
    fn a_cancel_stops_the_agent_and_its_children() {
        let tmp = tempfile::tempdir().unwrap();
        let ready = tmp.path().join("left.pid");
        let child = start(script(
            tmp.path(),
            "a",
            "sleep 60 &\necho $! > left.pid\nwait",
        ));
        let cancel = Cancel::new();
        let canceller = cancel_when(&ready, &cancel);
        let ended = watch(child, &tmp.path().join("agent.pid"), &cancel).unwrap();
        canceller.join().unwrap();
        assert!(matches!(ended, Ended::Cancelled), "{ended:?}");
        assert!(gone(pid_in(&ready)));
    }

    /// Cancels `cancel` once the script has written `ready` (a line ending in a newline).
    fn cancel_when(ready: &Path, cancel: &Cancel) -> thread::JoinHandle<()> {
        let (ready, cancel) = (ready.to_owned(), cancel.clone());
        thread::spawn(move || {
            while fs::read_to_string(&ready).map_or(true, |t| !t.ends_with('\n')) {
                thread::sleep(Duration::from_millis(10));
            }
            cancel.cancel();
        })
    }

    #[test]
    fn an_agent_that_ignores_sigterm_is_killed_after_the_grace_period() {
        let tmp = tempfile::tempdir().unwrap();
        let ready = tmp.path().join("ready");
        let body = "trap '' TERM\necho yes > ready\nwhile :; do sleep 1; done";
        let child = start(script(tmp.path(), "a", body));
        let pid = child.id();
        let cancel = Cancel::new();
        let canceller = cancel_when(&ready, &cancel);
        let ended = watch(child, &tmp.path().join("agent.pid"), &cancel).unwrap();
        canceller.join().unwrap();
        assert!(matches!(ended, Ended::Cancelled));
        assert!(gone(pid), "SIGKILL ends what ignores SIGTERM");
    }

    /// A data dir with a finished sweep, an interrupted one, an empty one, and a fix folder.
    fn interrupted(data_dir: &DataDir) -> (PathBuf, PathBuf, PathBuf) {
        let sweeps = data_dir.sweeps_dir();
        let finished = sweeps.join("20261108T100000Z/mac");
        let half = sweeps.join("20261108T110000Z/mac");
        let empty = sweeps.join("20261108T120000Z");
        for dir in [&finished, &half, &empty] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(finished.join("report.json"), "{}").unwrap();
        fs::write(half.join("agent-1.log"), "").unwrap();
        fs::create_dir_all(data_dir.fixes_dir().join("20261108T100000Z-k")).unwrap();
        (finished, half, empty)
    }

    #[test]
    fn cleaning_up_stops_a_recorded_agent_and_removes_unfinished_folders() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let (finished, half, empty) = interrupted(&data_dir);

        // An agent the app lost track of, and a record whose process has since been replaced
        // (the start time differs), which must be left alone.
        let mut lost = start(script(tmp.path(), "lost", "exec sleep 60"));
        write_record(&half.join("agent-1.pid"), lost.id()).unwrap();
        let mut other = start(script(tmp.path(), "other", "exec sleep 60"));
        let fix = data_dir.fixes_dir().join("20261108T100000Z-k");
        fs::write(
            fix.join("agent.pid"),
            format!("{} Mon Jan  1 00:00:00 2001\n", other.id()),
        )
        .unwrap();

        let cleaned = clean_up_interrupted(&data_dir).unwrap();
        // The target folder, its sweep folder then empty, and the sweep folder already empty.
        let expected = Cleaned {
            agents: 1,
            folders: 3,
        };
        assert_eq!(cleaned, expected);
        // The test is the lost agent's parent, so it reaps it; launchd does for a real one.
        let status = lost.wait().unwrap();
        assert!(
            std::os::unix::process::ExitStatusExt::signal(&status).is_some(),
            "{status:?}"
        );
        assert!(
            start_time(other.id()).is_some(),
            "a reused pid is not ours to stop"
        );
        assert!(finished.join("report.json").exists());
        assert!(
            !half.exists() && !half.parent().unwrap().exists(),
            "{half:?}"
        );
        assert!(!empty.exists());
        assert!(
            fix.exists() && !fix.join("agent.pid").exists(),
            "fixes stay, records go"
        );

        drop(other.kill());
        drop(other.wait());
        assert_eq!(clean_up_interrupted(&data_dir).unwrap(), Cleaned::default());
    }

    #[test]
    fn cleaning_up_waits_for_nothing_while_a_sweep_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let (_, half, _) = interrupted(&data_dir);
        let _running = Lock::acquire(&data_dir.sweeps_dir()).unwrap();
        assert_eq!(clean_up_interrupted(&data_dir).unwrap(), Cleaned::default());
        assert!(half.exists(), "a running sweep's folder is not interrupted");
    }

    #[test]
    fn a_cancel_is_shared_by_its_clones() {
        let cancel = Cancel::new();
        let clone = cancel.clone();
        assert!(cancel.check().is_ok());
        clone.cancel();
        assert!(cancel.is_cancelled());
        assert!(matches!(cancel.check(), Err(SweepError::Cancelled)));
    }
}
