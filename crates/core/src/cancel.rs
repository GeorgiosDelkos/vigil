//! Stopping a running sweep or fix, and every process it started.
//!
//! [`Cancel`] is a flag shared between the thread that runs a sweep or fix and whoever may
//! stop it: the user, the app as it quits, or Ctrl-C in the CLI. The sweep checks it between
//! steps; an agent run checks it while it waits.
//!
//! Every program a sweep or fix starts (the agent, and each inventory command: `brew`, `gh`,
//! `ssh`) runs under [`supervised`]: a small `sh` watchdog leads a new process group, runs the
//! program in it, and checks once a second that this process (the app or the CLI) is still
//! alive. When it is not, however it ended (quit, `kill`, a crash, a closed terminal), the
//! watchdog stops its group: `SIGTERM`, then `SIGKILL` after [`GRACE`]. So no record of running
//! programs is kept, and nothing has to be found again after a crash.
//!
//! On a cancel, [`watch`] stops the program's group and every descendant of it, including
//! one that left the group (`setsid`, Node's `detached`): `SIGTERM`, then `SIGKILL` after
//! [`GRACE`]. Once the program exits on its own, whatever it left in its group is killed too.
//! A descendant that leaves the group is out of the watchdog's reach, so after a crash it is
//! the one thing that can outlive the app; the agents' own children rarely do this.
//!
//! A sweep folder holds a `.running` marker while its sweep runs. A cancelled sweep removes
//! the folder of the target it stopped in; one that never ended (the app was killed) keeps its
//! marker, and [`clean_up_interrupted`] removes its unfinished target folders later.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt as _;
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

/// How long a stopped program gets to exit after `SIGTERM` before `SIGKILL`, here and in the
/// watchdog. Arbitrary: long enough for a CLI to flush its log and close its connection, short
/// enough that quitting the app does not hang.
pub(crate) const GRACE: Duration = Duration::from_secs(3);

/// How often a running agent is checked for having exited or been cancelled. Arbitrary: a
/// cancel within a fifth of a second feels immediate, and the check costs nothing.
const POLL: Duration = Duration::from_millis(200);

/// The name of the marker a running sweep keeps in its folder.
const RUNNING: &str = ".running";

/// The watchdog's name, its `$0`: the shell starts what it reports with it.
const ARGV0: &str = "vigil-watchdog";

/// The watchdog, run as `sh -c WATCHDOG vigil-watchdog <owner pid> <grace s> <program> <args>`.
///
/// - The program gets this shell's stdin explicitly: `sh` gives a background command
///   `/dev/null` otherwise, and an inventory command may be fed its input on stdin.
/// - The guard loop runs in the background with its output closed, so it never holds the
///   caller's pipes open. It ignores `SIGTERM`, since the `SIGTERM` it sends to the group
///   reaches it too and it must live on to send `SIGKILL`; it is killed once the program exits.
/// - `trap '' TERM INT HUP` comes after the program is started, so the program keeps the default
///   handling (an ignored signal would be inherited), while the watchdog itself outlives a
///   cancel's `SIGTERM` and keeps waiting until the program has exited.
/// - `kill 0` signals the watchdog's own process group, where the program runs.
/// - The program's exit status is the watchdog's (128 plus the signal for one killed by it).
/// - The owner's pid could be reused by another process within the second between checks; the
///   watchdog would then wait for that one. Accepted: macOS has been seen to hand out pids in
///   increasing order (observed, not documented), so reuse that soon needs the range to wrap.
const WATCHDOG: &str = r#"owner=$1; grace=$2; shift 2
"$@" <&0 &
child=$!
( trap '' TERM
  while kill -0 "$owner" 2>/dev/null; do sleep 1; done
  kill -s TERM 0; sleep "$grace"; kill -s KILL 0 ) </dev/null >/dev/null 2>&1 &
guard=$!
trap '' TERM INT HUP
wait "$child"
status=$?
kill -s KILL "$guard" 2>/dev/null
exit "$status"
"#;

/// A request to stop a sweep or fix. Clones share the request.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// A request not yet made.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the sweep or fix to stop. It stops at its next check: within [`GRACE`] while an
    /// agent runs, otherwise once the current request or inventory command returns.
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

/// `command` run under the watchdog, which stops it when this process ends (see the module
/// docs). The program, its arguments, environment and directory are copied; stdio is the
/// caller's to set on the result.
pub(crate) fn supervised(command: &Command) -> Command {
    supervised_by(command, std::process::id())
}

/// [`supervised`], watching process `owner` instead of this one.
fn supervised_by(command: &Command, owner: u32) -> Command {
    let mut watched = Command::new("/bin/sh");
    watched
        .args(["-c", WATCHDOG, ARGV0])
        .arg(owner.to_string())
        .arg(GRACE.as_secs_f64().to_string())
        .arg(command.get_program())
        .args(command.get_args())
        .process_group(0);
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => drop(watched.env(key, value)),
            None => drop(watched.env_remove(key)),
        }
    }
    if let Some(dir) = command.get_current_dir() {
        watched.current_dir(dir);
    }
    watched
}

/// Why the watchdog could not run its program (a removed interpreter, no permission), from its
/// exit status and the start of its stderr, where a spawn of the program itself would have
/// failed; `None` when the program ran.
pub(crate) fn not_run(status: ExitStatus, stderr: &[u8]) -> Option<String> {
    let prefix = format!("{ARGV0}: ");
    if !matches!(status.code(), Some(126 | 127)) || !stderr.starts_with(prefix.as_bytes()) {
        return None;
    }
    let text = String::from_utf8_lossy(stderr);
    Some(text.lines().next().unwrap_or_default().to_owned())
}

/// Waits for `child`, started from [`supervised`], and stops it with its group and every
/// descendant when `cancel` is set. Whatever it leaves in its group is killed once it exits.
///
/// # Errors
///
/// Fails when waiting for it fails, after stopping it.
pub(crate) fn watch(mut child: Child, cancel: &Cancel) -> io::Result<Ended> {
    let group = child.id();
    let ended = loop {
        let polled = match child.try_wait() {
            Ok(polled) => polled,
            Err(e) => {
                stop(&mut child);
                return Err(e);
            }
        };
        if let Some(status) = polled {
            break Ended::Exited(status);
        }
        if cancel.is_cancelled() {
            stop(&mut child);
            break Ended::Cancelled;
        }
        thread::sleep(POLL);
    };
    // The leader is gone; anything it left in the group goes with it. A group id stays taken
    // while a member lives, so this reaches only this group; once the group is empty the id is
    // free, and the `kill` fails or, if another group took the id in these microseconds, could
    // reach it. Closing that needs `waitid` with `WNOWAIT`, which is `unsafe`; accepted.
    signal_group(group, "KILL");
    Ok(ended)
}

/// Stops `child`, the leader of its own group, with its group and every descendant: `SIGTERM`,
/// then `SIGKILL` once it has exited or after [`GRACE`]. Reaps it.
fn stop(child: &mut Child) {
    let group = child.id();
    // Taken first: once the leader exits its children are re-parented and cannot be found.
    let mut tree = descendants(group);
    signal(group, &tree, "TERM");
    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
        // Taken again while the leader lives: a child started since may have left the group.
        tree.extend(descendants(group));
        thread::sleep(POLL);
    }
    signal(group, &tree, "KILL");
    // Best effort: after SIGKILL the leader exits; an error means it was already reaped.
    drop(child.wait());
}

/// Sends `signal` to process group `group` and to each process in `tree`. A pid in `tree` that
/// exited during the grace period could have been reused by then; accepted, as macOS has been
/// seen to hand out pids in increasing order (observed, not documented) and the period is
/// seconds.
fn signal(group: u32, tree: &BTreeSet<u32>, signal: &str) {
    signal_group(group, signal);
    if !tree.is_empty() {
        let pids: Vec<String> = tree.iter().map(u32::to_string).collect();
        kill(&["-s", signal, "--"], &pids);
    }
}

/// Sends `signal` to every process in `group`.
fn signal_group(group: u32, signal: &str) {
    kill(&["-s", signal, "--"], &[format!("-{group}")]);
}

/// Runs `kill(1)`: std has no `kill` or `killpg`, and this avoids `unsafe` for them.
fn kill(options: &[&str], targets: &[String]) {
    // Best effort: a process or group that has already gone makes `kill` fail, which is the
    // usual case, and there is nothing else to do about a signal that could not be sent.
    drop(
        Command::new("/bin/kill")
            .args(options)
            .args(targets)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

/// The processes descended from `root`, from `ps`: its children, theirs, and so on.
fn descendants(root: u32) -> BTreeSet<u32> {
    let Ok(output) = Command::new("/bin/ps")
        .args(["-A", "-o", "pid=,ppid="])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return BTreeSet::new();
    };
    let pairs: Vec<(u32, u32)> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((fields.next()?.parse().ok()?, fields.next()?.parse().ok()?))
        })
        .collect();
    let mut found = BTreeSet::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for &(pid, _) in pairs.iter().filter(|&&(_, ppid)| ppid == parent) {
            if found.insert(pid) {
                frontier.push(pid);
            }
        }
    }
    found
}

/// Marks `sweep` as running; the marker goes when the returned guard is dropped, which a sweep
/// that ends (by returning or panicking) always does, and one whose process is killed never
/// does. A process killed between creating the folder and marking it leaves an empty, unmarked
/// folder; accepted, as the window is one file write.
pub(crate) fn mark_running(sweep: &Path) -> Result<Running, SweepError> {
    let marker = sweep.join(RUNNING);
    fs::write(&marker, "").map_err(|source| SweepError::Write {
        path: marker.clone(),
        source,
    })?;
    Ok(Running {
        marker,
        kept: false,
    })
}

/// The marker of a running sweep, removed on drop.
#[derive(Debug)]
pub(crate) struct Running {
    marker: PathBuf,
    /// Set when removing the unfinished targets failed: the marker stays.
    kept: bool,
}

impl Running {
    /// Removes the sweep's unfinished target folders (see [`remove_unfinished`]), for a sweep
    /// that was cancelled. When a target or the marker cannot be removed, the marker stays, so
    /// the next cleanup finishes the job.
    pub(crate) fn remove_unfinished(mut self, finished: &[PathBuf]) -> Result<(), SweepError> {
        let sweep = self
            .marker
            .parent()
            .expect("the marker is created inside its sweep folder")
            .to_owned();
        let removed = remove_unfinished(&sweep, finished);
        self.kept = removed.is_err();
        removed
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // Best effort: a marker left behind makes the next cleanup remove only target folders
        // without a report, which an ended sweep does not have unless it failed to save one.
        if !self.kept {
            drop(fs::remove_file(&self.marker));
        }
    }
}

/// Removes the sweep folders an interrupted sweep left: in each folder still marked running,
/// the target folders without a report, then the marker, then the folder when nothing is left.
/// A sweep that ended is never touched, even when a report failed to save.
///
/// Does nothing when a sweep or fix is running (from the CLI, say), since its folder is not
/// interrupted.
///
/// # Errors
///
/// Fails when a folder cannot be read or removed.
pub fn clean_up_interrupted(data_dir: &DataDir) -> Result<(), SweepError> {
    let _lock = match Lock::acquire(&data_dir.sweeps_dir()) {
        Ok(lock) => lock,
        Err(SweepError::Busy { .. }) => return Ok(()),
        Err(e) => return Err(e),
    };
    clean_up_holding_lock(data_dir)
}

/// [`clean_up_interrupted`] for a caller that holds the sweeps lock, as a starting sweep does.
pub(crate) fn clean_up_holding_lock(data_dir: &DataDir) -> Result<(), SweepError> {
    for sweep in subdirs(&data_dir.sweeps_dir())? {
        if sweep.join(RUNNING).exists() {
            remove_unfinished(&sweep, &[])?;
        }
    }
    Ok(())
}

/// Removes a sweep's unfinished target folders, its marker, and the folder when nothing is left
/// in it: what a cancelled or interrupted sweep leaves. A target is finished when it is in
/// `finished` (the sweep reported it), or has a report: `report.json`, or `report.md`, which
/// is written just before it. When it cannot list or remove a target folder, or remove the
/// marker, it stops with the marker still there.
fn remove_unfinished(sweep: &Path, finished: &[PathBuf]) -> Result<(), SweepError> {
    for target in subdirs(sweep)? {
        let reported = ["report.json", "report.md"]
            .iter()
            .any(|name| target.join(name).exists());
        if !reported && !finished.contains(&target) {
            remove(&target)?;
        }
    }
    let marker = sweep.join(RUNNING);
    if let Err(source) = fs::remove_file(&marker)
        && source.kind() != io::ErrorKind::NotFound
    {
        return Err(SweepError::Write {
            path: marker,
            source,
        });
    }
    let empty = fs::read_dir(sweep).is_ok_and(|mut entries| entries.next().is_none());
    if empty {
        remove(sweep)?;
    }
    Ok(())
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

    /// A script at `dir/name` running `body`. The scripts sleep 30 s at most: longer than any
    /// wait in these tests (10 s), so a program that is not stopped fails the test, and short
    /// enough that a mutant which stops nothing fails it instead of hanging the run.
    fn script(dir: &Path, name: &str, body: &str) -> Command {
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut command = Command::new(path);
        command.current_dir(dir);
        command
    }

    fn start(command: &Command) -> Child {
        supervised(command).stdin(Stdio::null()).spawn().unwrap()
    }

    /// Whether process `pid` has gone. A killed process can take a moment to go, and nothing
    /// signals it, so this waits up to a deadline for it to.
    fn gone(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let alive = Command::new("/bin/kill")
                .args(["-0", &pid.to_string()])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success();
            if !alive {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// The pid a script wrote to `path`, waiting up to a deadline for the whole line.
    fn pid_in(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(text) = fs::read_to_string(path)
                && text.ends_with('\n')
            {
                return text.trim().parse().unwrap();
            }
            assert!(Instant::now() < deadline, "the script never wrote {path:?}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Cancels `cancel` once the script has written `ready`.
    fn cancel_when(ready: &Path, cancel: &Cancel) -> thread::JoinHandle<()> {
        let (ready, cancel) = (ready.to_owned(), cancel.clone());
        thread::spawn(move || {
            pid_in(&ready);
            cancel.cancel();
        })
    }

    #[test]
    fn a_program_passes_its_status_input_and_environment_through_the_watchdog() {
        let tmp = tempfile::tempdir().unwrap();
        let mut command = script(tmp.path(), "a", "read line\necho \"$line $X\"\nexit 4");
        command.env("X", "there");
        let mut child = supervised(&command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        io::Write::write_all(&mut child.stdin.take().unwrap(), b"hello\n").unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello there\n");
        assert_eq!(out.status.code(), Some(4));
    }

    #[test]
    fn a_program_that_exits_takes_what_it_started_with_it() {
        let tmp = tempfile::tempdir().unwrap();
        let command = script(tmp.path(), "a", "sleep 30 &\necho $! > left.pid\nexit 4");
        let ended = watch(start(&command), &Cancel::new()).unwrap();
        assert!(
            matches!(ended, Ended::Exited(s) if s.code() == Some(4)),
            "{ended:?}"
        );
        assert!(
            gone(pid_in(&tmp.path().join("left.pid"))),
            "the background sleep is killed"
        );
    }

    #[test]
    fn a_cancel_stops_the_program_its_children_and_those_that_left_its_group() {
        let tmp = tempfile::tempdir().unwrap();
        // perl, which macOS ships, stands in for a Node child spawned with `detached: true`.
        let body = "perl -MPOSIX -e 'POSIX::setsid(); exec \"sleep\", \"30\"' &\n\
                    echo $! > away.pid\nsleep 30 &\necho $! > left.pid\nwait";
        let child = start(&script(tmp.path(), "a", body));
        let cancel = Cancel::new();
        let canceller = cancel_when(&tmp.path().join("left.pid"), &cancel);
        let ended = watch(child, &cancel).unwrap();
        canceller.join().unwrap();
        assert!(matches!(ended, Ended::Cancelled), "{ended:?}");
        assert!(gone(pid_in(&tmp.path().join("left.pid"))));
        assert!(
            gone(pid_in(&tmp.path().join("away.pid"))),
            "out of the group, still found"
        );
    }

    #[test]
    fn a_program_gets_the_grace_period_to_exit_after_sigterm() {
        let tmp = tempfile::tempdir().unwrap();
        // It needs a moment after SIGTERM, then records that it got it, then exits.
        let body = "trap 'sleep 1; echo done > graceful; exit 0' TERM\n\
                    echo $$ > ready\nsleep 30 &\nwait";
        let child = start(&script(tmp.path(), "a", body));
        let cancel = Cancel::new();
        let canceller = cancel_when(&tmp.path().join("ready"), &cancel);
        let ended = watch(child, &cancel).unwrap();
        canceller.join().unwrap();
        assert!(matches!(ended, Ended::Cancelled));
        assert!(
            tmp.path().join("graceful").exists(),
            "it was not killed before it could end"
        );
    }

    #[test]
    fn a_program_that_ignores_sigterm_is_killed_after_the_grace_period() {
        let tmp = tempfile::tempdir().unwrap();
        let body = "trap '' TERM\necho $$ > ready\nsleep 30";
        let child = start(&script(tmp.path(), "a", body));
        let cancel = Cancel::new();
        let canceller = cancel_when(&tmp.path().join("ready"), &cancel);
        let ended = watch(child, &cancel).unwrap();
        canceller.join().unwrap();
        assert!(matches!(ended, Ended::Cancelled));
        assert!(
            gone(pid_in(&tmp.path().join("ready"))),
            "SIGKILL ends what ignores SIGTERM"
        );
    }

    #[test]
    fn the_watchdog_stops_its_program_once_its_owner_is_gone() {
        let tmp = tempfile::tempdir().unwrap();
        // A short-lived process stands in for the app; it ends as if it crashed.
        let mut owner = Command::new("/bin/sleep").arg("1").spawn().unwrap();
        let command = script(tmp.path(), "a", "sleep 30 &\necho $! > left.pid\nwait");
        let mut child = supervised_by(&command, owner.id())
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let left = pid_in(&tmp.path().join("left.pid"));
        owner.wait().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success(), "{status:?}");
        assert!(gone(left));
    }

    #[test]
    fn the_watchdog_kills_what_ignores_sigterm_once_its_owner_is_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let mut owner = Command::new("/bin/sleep").arg("1").spawn().unwrap();
        let body = "trap '' TERM\necho $$ > ready\nsleep 30";
        let command = script(tmp.path(), "a", body);
        let mut child = supervised_by(&command, owner.id())
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let program = pid_in(&tmp.path().join("ready"));
        owner.wait().unwrap();
        let ended = gone(program);
        if !ended {
            // Without this, the test run would hang on the program it failed to stop.
            drop(
                Command::new("/bin/kill")
                    .args(["-9", "--", &format!("-{}", child.id())])
                    .status(),
            );
        }
        drop(child.wait());
        assert!(ended, "SIGKILL follows the grace period");
    }

    #[test]
    fn cleaning_up_removes_only_what_an_interrupted_sweep_left() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let sweeps = data_dir.sweeps_dir();
        // Interrupted: one target finished, one not.
        let interrupted = sweeps.join("20261108T110000Z");
        fs::create_dir_all(interrupted.join("mac")).unwrap();
        fs::write(interrupted.join("mac/report.json"), "{}").unwrap();
        fs::create_dir_all(interrupted.join("github-o--r/bundle")).unwrap();
        fs::write(interrupted.join(RUNNING), "").unwrap();
        // Interrupted before any target finished.
        let early = sweeps.join("20261108T120000Z");
        fs::create_dir_all(early.join("mac")).unwrap();
        fs::write(early.join(RUNNING), "").unwrap();
        // Ended, though a report failed to save: its folder is kept as it is.
        let ended = sweeps.join("20261108T100000Z/mac");
        fs::create_dir_all(&ended).unwrap();
        fs::write(ended.join("report.md"), "# report").unwrap();
        // Interrupted between the markdown report and the JSON one: the target is kept.
        let between = sweeps.join("20261108T130000Z");
        fs::create_dir_all(between.join("mac")).unwrap();
        fs::write(between.join("mac/report.md"), "# report").unwrap();
        fs::write(between.join(RUNNING), "").unwrap();

        clean_up_interrupted(&data_dir).unwrap();
        assert!(interrupted.join("mac/report.json").exists());
        assert!(!interrupted.join("github-o--r").exists());
        assert!(!interrupted.join(RUNNING).exists());
        assert!(!early.exists(), "nothing was left in it");
        assert!(ended.join("report.md").exists());
        assert!(between.join("mac/report.md").exists());
    }

    #[test]
    fn a_cancel_keeps_the_targets_its_sweep_finished() {
        let tmp = tempfile::tempdir().unwrap();
        let sweep = tmp.path().join("20261108T110000Z");
        // The sweep reported this one, though its report failed to save.
        fs::create_dir_all(sweep.join("mac")).unwrap();
        fs::create_dir_all(sweep.join("github-o--r/bundle")).unwrap();
        let running = mark_running(&sweep).unwrap();
        running.remove_unfinished(&[sweep.join("mac")]).unwrap();
        assert!(sweep.join("mac").exists());
        assert!(!sweep.join("github-o--r").exists());
    }

    #[test]
    fn a_cancel_whose_cleanup_fails_leaves_the_marker_for_the_next() {
        let tmp = tempfile::tempdir().unwrap();
        let sweep = tmp.path().join("20261108T110000Z");
        let target = sweep.join("github-o--r");
        fs::create_dir_all(target.join("bundle")).unwrap();
        let running = mark_running(&sweep).unwrap();
        // A folder whose entries cannot be removed.
        fs::set_permissions(&target, fs::Permissions::from_mode(0o555)).unwrap();
        let failed = running.remove_unfinished(&[]);
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(failed.is_err());
        assert!(
            sweep.join(RUNNING).exists(),
            "the next cleanup still sees it"
        );
    }

    #[test]
    fn cleaning_up_waits_for_nothing_while_a_sweep_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let running = data_dir.sweeps_dir().join("20261108T110000Z");
        fs::create_dir_all(running.join("mac")).unwrap();
        fs::write(running.join(RUNNING), "").unwrap();
        let _held = Lock::acquire(&data_dir.sweeps_dir()).unwrap();
        clean_up_interrupted(&data_dir).unwrap();
        assert!(
            running.join("mac").exists(),
            "a running sweep's folder is not interrupted"
        );
    }

    #[test]
    fn removing_a_folder_already_gone_succeeds_but_one_that_cannot_be_read_fails() {
        let tmp = tempfile::tempdir().unwrap();
        remove_unfinished(&tmp.path().join("gone"), &[]).unwrap();

        let sweep = tmp.path().join("20261108T110000Z");
        fs::create_dir_all(sweep.join("mac")).unwrap();
        // The marker went already (a cancel and a cleanup racing): that is not an error.
        remove_unfinished(&sweep, &[]).unwrap();
        assert!(!sweep.exists());

        let locked = tmp.path().join("locked");
        fs::create_dir_all(locked.join("mac")).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = remove_unfinished(&locked, &[]);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(unreadable, Err(SweepError::Read { .. })),
            "{unreadable:?}"
        );
    }

    #[test]
    fn the_marker_goes_when_its_guard_does() {
        let tmp = tempfile::tempdir().unwrap();
        let running = mark_running(tmp.path()).unwrap();
        assert!(tmp.path().join(RUNNING).exists());
        drop(running);
        assert!(!tmp.path().join(RUNNING).exists());
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
