//! Runs a listing command and returns its stdout.
//!
//! Commands run from `/` with stdin closed and a time limit, and stop when the caller's
//! [`Cancel`] is set. From `/`, no project file in
//! the caller's folder (`rust-toolchain.toml`, `.nvmrc`, `.python-version`) changes which tool
//! version answers, and rustup cannot decide to install a toolchain a project pins. Closed
//! stdin and the time limit keep a tool that prompts or hangs from stopping the sweep.
//!
//! Tools are found on [`search_path`]: the process's `PATH`, unless the menu-bar app set the
//! login shell's with [`use_search_path`]. An app started at login or from Finder gets only
//! `/usr/bin:/bin:/usr/sbin:/sbin`, without Homebrew, nvm or `~/.local/bin`, so without this
//! a sweep from the app would find no `brew`, `npm` or `gh`. It is process-wide, set once at
//! startup, because every collector runs tools and threading it through each would change
//! every signature for one caller; the CLI, started from a terminal, never sets it.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::PoisonError;
use std::sync::RwLock;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::cancel;
use crate::cancel::Cancel;
use crate::inventory::InventoryError;

/// How much of a failing command's stderr goes into the error, in characters. Arbitrary.
const STDERR_LIMIT: usize = 300;

/// How long one listing command may run. Arbitrary: `brew info --installed` takes a few
/// seconds with a hundred formulae; a minute means the tool is stuck.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(60);

/// The most bytes read from a command's stdout or stderr. Arbitrary: far above any listing seen
/// (`brew info` prints a few MB, a server's inventory tens), and low enough that a command
/// printing without end, such as a compromised server, cannot exhaust memory.
const OUTPUT_LIMIT: u64 = 256 * 1024 * 1024;

/// How often a running command is checked for having exited. Arbitrary; short enough that
/// fast commands return promptly.
const POLL: Duration = Duration::from_millis(20);

/// A command that ran to completion.
#[derive(Debug)]
pub(crate) struct Output {
    /// Whether it exited with status 0.
    pub(crate) success: bool,
    pub(crate) stdout: String,
    /// The exit status and the start of stderr, for an error message.
    pub(crate) detail: String,
    /// The command line, for an error message.
    pub(crate) command: String,
}

/// Runs `program` and returns stdout, or `None` when it is not installed. A non-zero exit is
/// an error, and so is a `cancel` that stops it.
pub(crate) fn run(
    program: &str,
    args: &[&str],
    cancel: &Cancel,
) -> Result<Option<String>, InventoryError> {
    let Some(output) = run_any_status(program, args, cancel)? else {
        return Ok(None);
    };
    if output.success {
        Ok(Some(output.stdout))
    } else {
        Err(InventoryError::Command {
            command: output.command,
            detail: output.detail,
        })
    }
}

/// Runs `program` and returns its output whatever the exit status, or `None` when it is not
/// installed. For tools that print a complete answer and still exit non-zero. A `cancel` that
/// stops it is an error.
pub(crate) fn run_any_status(
    program: &str,
    args: &[&str],
    cancel: &Cancel,
) -> Result<Option<Output>, InventoryError> {
    let Some(raw) = run_raw(program, args, b"", TIMEOUT, cancel)? else {
        return Ok(None);
    };
    let stdout =
        String::from_utf8(raw.stdout).map_err(|e| InventoryError::parse(&raw.command, &e))?;
    Ok(Some(Output {
        success: raw.success,
        stdout,
        detail: raw.detail,
        command: raw.command,
    }))
}

/// Runs `program` with `input` on stdin and returns its output whatever the exit status, or
/// `None` when it is not installed. Waits up to `timeout`.
///
/// Stdout is decoded lossily: the callers read output that mixes many files (a server's
/// inventory, the user's shell startup files), where one file's bad byte must not discard the
/// rest.
///
/// Not cancellable: each caller runs one command bounded by `timeout`. A sweep checks its
/// cancel before a server's collection; finding an agent was not cancellable before either.
pub(crate) fn run_with_input(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
) -> Result<Option<Output>, InventoryError> {
    let Some(raw) = run_raw(program, args, input, timeout, &Cancel::new())? else {
        return Ok(None);
    };
    Ok(Some(Output {
        success: raw.success,
        stdout: String::from_utf8_lossy(&raw.stdout).into_owned(),
        detail: raw.detail,
        command: raw.command,
    }))
}

/// [`Output`] before stdout is decoded.
struct RawOutput {
    success: bool,
    stdout: Vec<u8>,
    detail: String,
    command: String,
}

/// The login shell's `PATH`, once detection read it. Replaced by each later detection, so a
/// tool installed since ("Look again") is found by the next sweep as the settings show it.
static SEARCH_PATH: RwLock<Option<OsString>> = RwLock::new(None);

/// Makes every tool the core runs from now on be found on `path` instead of the process's
/// `PATH`.
pub(crate) fn use_search_path(path: OsString) {
    // A poisoned lock holds a whole value: it is only ever replaced whole.
    *SEARCH_PATH.write().unwrap_or_else(PoisonError::into_inner) = Some(path);
}

/// Where tools are looked up: the login shell's `PATH` when set, otherwise the process's.
fn search_path() -> Option<OsString> {
    let set = SEARCH_PATH
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    set.or_else(|| env::var_os("PATH"))
}

/// Runs `program` with `input` on stdin, which is closed once it is written (at once when
/// `input` is empty). Does not start it once `cancel` is set, and stops it when `cancel` is set
/// while it runs.
fn run_raw(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    cancel: &Cancel,
) -> Result<Option<RawOutput>, InventoryError> {
    let command = command_line(program, args);
    if cancel.is_cancelled() {
        return Err(InventoryError::Cancelled { what: command });
    }
    // The watchdog shell always starts, so a program that is nowhere on PATH is found out
    // here: it is "not installed". A path to a file that cannot run is installed, and broken.
    if which(program).is_none() {
        if program.contains('/') && Path::new(program).exists() {
            let source = io::Error::from(io::ErrorKind::PermissionDenied);
            return Err(InventoryError::Spawn { command, source });
        }
        return Ok(None);
    }
    let mut command_builder = Command::new(program);
    // On Unix the child's `PATH` is also where `program` is searched, so this finds it too.
    if let Some(path) = search_path() {
        command_builder.env("PATH", path);
    }
    command_builder.args(args).current_dir("/");
    // Under the watchdog, which leads its own process group, so a timeout stops the helpers
    // the tool starts as well, and the tool stops when the app or CLI ends.
    let child = cancel::supervised(&command_builder)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(source) => return Err(InventoryError::Spawn { command, source }),
    };
    // Written on its own thread, so a program that answers before reading all of its input
    // cannot stall on a full stdout pipe while this side blocks on a full stdin pipe. A write
    // error means the program exited or closed stdin early, which its exit status reports.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    if input.is_empty() {
        drop(stdin);
    } else {
        let input = input.to_vec();
        thread::spawn(move || drop(stdin.write_all(&input)));
    }
    let (status, stdout, stderr) = wait(child, &command, timeout, cancel)?;
    if let Some(reason) = cancel::not_run(status, &stderr) {
        let source = io::Error::other(reason);
        return Err(InventoryError::Spawn { command, source });
    }

    let stderr: String = String::from_utf8_lossy(&stderr)
        .chars()
        .take(STDERR_LIMIT)
        .collect();
    Ok(Some(RawOutput {
        success: status.success(),
        stdout,
        detail: format!("{status}: {}", stderr.trim()),
        command,
    }))
}

/// Waits for `child` and its output up to `timeout`, reading stdout and stderr on their own
/// threads so a full pipe cannot stall it. A tool still running at the deadline or when
/// `cancel` is set, or a helper it left behind that keeps its output open, is stopped with its
/// whole process group.
fn wait(
    mut child: Child,
    command: &str,
    timeout: Duration,
    cancel: &Cancel,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), InventoryError> {
    // Each reader sends its result once the pipe closes. The channel holds that one message, so
    // the send never blocks. A reader whose pipe is still held by a helper that left the process
    // group stays blocked until that helper exits: one thread and descriptor, accepted, since
    // it takes a tool that escapes its own group.
    fn reader(pipe: Option<impl io::Read + Send + 'static>) -> mpsc::Receiver<io::Result<Vec<u8>>> {
        let (tx, rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let read = match pipe {
                // Past the limit the pipe is dropped, so the program gets SIGPIPE or EPIPE on
                // its next write instead of filling memory here.
                Some(pipe) => match pipe.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes) {
                    Ok(_) if bytes.len() as u64 > OUTPUT_LIMIT => Err(io::Error::other(format!(
                        "printed more than {OUTPUT_LIMIT} bytes"
                    ))),
                    Ok(_) => Ok(bytes),
                    Err(e) => Err(e),
                },
                None => Ok(bytes),
            };
            // The receiver is gone only when the command was already abandoned.
            drop(tx.send(read));
        });
        rx
    }
    let stdout = reader(child.stdout.take());
    let stderr = reader(child.stderr.take());
    let deadline = Instant::now() + timeout;

    let status = loop {
        let polled = match child.try_wait() {
            Ok(polled) => polled,
            Err(source) => {
                // Stopped first, so a tool that cannot be waited for does not run on.
                stop(&mut child);
                return Err(InventoryError::Spawn {
                    command: command.to_owned(),
                    source,
                });
            }
        };
        if let Some(status) = polled {
            break status;
        }
        if cancel.is_cancelled() {
            stop(&mut child);
            let command = command.to_owned();
            return Err(InventoryError::Cancelled { what: command });
        }
        if Instant::now() >= deadline {
            stop(&mut child);
            let detail = format!("still running after {timeout:?}; stopped");
            return Err(failed(command, detail));
        }
        thread::sleep(POLL);
    };
    let left = || deadline.saturating_duration_since(Instant::now());
    let (Ok(stdout), Ok(stderr)) = (stdout.recv_timeout(left()), stderr.recv_timeout(left()))
    else {
        stop(&mut child);
        let detail = "exited, but something it started kept its output open; stopped";
        return Err(failed(command, detail.to_owned()));
    };
    // A failed read means the output may be cut short, which would parse as a shorter list.
    let read_err = |source| InventoryError::Spawn {
        command: command.to_owned(),
        source,
    };
    Ok((status, stdout.map_err(read_err)?, stderr.map_err(read_err)?))
}

/// Stops `child` and everything in its process group.
///
/// The group is killed with `kill`, because sending a signal to a group needs `libc` and an
/// `unsafe` call, and this crate has neither. Every step is best effort: the command is
/// abandoned either way, and a failed kill means the process already exited.
///
/// Process ids can be reused, which bounds what the kill can hit. On a timeout the leader is not
/// yet reaped, so the group id stays reserved and only the group is killed. When the leader has
/// exited and been reaped (the "kept its output open" case), the id is free once the rest of
/// the group also exits, which can happen at any point before the deadline if something outside
/// the group holds the output; a new group could take the id in that time and be killed.
/// Accepted: it takes a tool that escapes its own group, and an id reused within a minute is
/// rare.
fn stop(child: &mut Child) {
    let group = format!("-{}", child.id());
    let kill = Command::new("/bin/kill")
        .args(["-KILL", &group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    drop(kill);
    drop(child.kill());
    drop(child.wait());
}

fn failed(command: &str, detail: String) -> InventoryError {
    InventoryError::Command {
        command: command.to_owned(),
        detail,
    }
}

/// Returns the file `program` runs: itself if it names a path, else the first match on `PATH`.
pub(crate) fn which(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        return executable(Path::new(program)).then(|| PathBuf::from(program));
    }
    let path = search_path()?;
    env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| executable(candidate))
}

/// Whether `path` is a file someone may execute, as a shell's lookup requires: a directory or
/// a plain file of the same name earlier on `PATH` is skipped.
fn executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn command_line(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {

    use super::*;

    fn script(dir: &Path, body: &str) -> String {
        let path = dir.join("tool");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    #[test]
    fn output_past_the_limit_fails_instead_of_filling_memory() {
        let over = (OUTPUT_LIMIT + 1).to_string();
        let script = format!("head -c {over} /dev/zero");
        let err = run_with_input("sh", &["-c", &script], b"", Duration::from_secs(60)).unwrap_err();
        let InventoryError::Spawn { source, .. } = err else {
            panic!("{err:?}")
        };
        assert!(source.to_string().contains("printed more than"), "{source}");

        // The limit's reason: a server inventory of tens of MB must fit.
        let large = run_with_input(
            "sh",
            &["-c", "head -c 67108864 /dev/zero"],
            b"",
            Duration::from_secs(60),
        );
        assert_eq!(large.unwrap().unwrap().stdout.len(), 64 << 20);

        let at = format!("head -c {OUTPUT_LIMIT} /dev/zero");
        let output = run_with_input("sh", &["-c", &at], b"", Duration::from_secs(60));
        assert_eq!(output.unwrap().unwrap().stdout.len() as u64, OUTPUT_LIMIT);
    }

    #[test]
    fn input_reaches_stdin_and_stdout_is_decoded_lossily() {
        let output = run_with_input("sh", &["-s"], b"printf 'a\\377b'", Duration::from_secs(5));
        assert_eq!(output.unwrap().unwrap().stdout, "a\u{fffd}b");
        let strict = run_any_status("printf", &["a\\377b"], &Cancel::new());
        assert!(
            matches!(strict, Err(InventoryError::Parse { .. })),
            "{strict:?}"
        );
    }

    #[test]
    fn returns_stdout() {
        assert_eq!(
            run("echo", &["a", "b"], &Cancel::new()).unwrap().as_deref(),
            Some("a b\n")
        );
    }

    #[test]
    fn missing_program_is_none() {
        assert!(
            run("vigil-no-such-tool", &[], &Cancel::new())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn runs_from_root_with_stdin_closed() {
        assert_eq!(
            run("pwd", &[], &Cancel::new()).unwrap().as_deref(),
            Some("/\n")
        );
        assert_eq!(
            run("cat", &[], &Cancel::new()).unwrap().as_deref(),
            Some("")
        );
    }

    #[test]
    fn failure_names_the_command_and_stderr() {
        let err = run("sh", &["-c", "echo boom >&2; exit 3"], &Cancel::new()).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("`sh -c echo boom >&2; exit 3` failed"),
            "{message}"
        );
        assert!(message.contains("boom"), "{message}");
    }

    #[test]
    fn any_status_keeps_stdout_of_a_failure() {
        let output = run_any_status(
            "sh",
            &["-c", "echo '{}'; echo bad >&2; exit 1"],
            &Cancel::new(),
        )
        .unwrap()
        .unwrap();
        assert!(!output.success);
        assert_eq!(output.stdout, "{}\n");
        assert!(output.detail.contains("bad"), "{}", output.detail);
    }

    #[test]
    fn hung_command_is_stopped() {
        let err = run_with_input("sleep", &["30"], b"", Duration::from_millis(200)).unwrap_err();
        assert!(err.to_string().contains("still running"), "{err}");
    }

    #[test]
    fn a_cancel_stops_a_running_command_and_starts_no_other() {
        let tmp = tempfile::tempdir().unwrap();
        let started = tmp.path().join("started");
        let script = format!("touch '{}'; sleep 30", started.display());
        let cancel = Cancel::new();
        let canceller = {
            let cancel = cancel.clone();
            let started = started.clone();
            thread::spawn(move || {
                // Waits for the command to run, so the cancel reaches the wait loop.
                while !started.exists() {
                    thread::sleep(Duration::from_millis(10));
                }
                cancel.cancel();
            })
        };
        // Without the cancel this would be the 60 s limit's "still running" error.
        let err = run("sh", &["-c", &script], &cancel).unwrap_err();
        canceller.join().unwrap();
        assert!(matches!(err, InventoryError::Cancelled { .. }), "{err:?}");

        fs::remove_file(&started).unwrap();
        let err = run("sh", &["-c", &script], &cancel).unwrap_err();
        assert!(matches!(err, InventoryError::Cancelled { .. }), "{err:?}");
        assert!(!started.exists(), "a cancelled sweep starts no command");
    }

    /// The tool exits at once, but a helper it started keeps stdout open for 30 s.
    #[test]
    fn helper_holding_output_open_is_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let pidfile = tmp.path().join("pid");
        let script = format!("sleep 30 & echo $! > '{}'; echo done", pidfile.display());
        let err = run_with_input("sh", &["-c", &script], b"", Duration::from_secs(5)).unwrap_err();
        assert!(err.to_string().contains("kept its output open"), "{err}");

        // The helper was in the tool's process group, so the group kill reached it.
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        let ps = Command::new("ps")
            .args(["-o", "stat=", "-p", pid.trim()])
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&ps.stdout);
        assert!(
            // Gone, a zombie (Z), or still being torn down after SIGKILL (E); ps may put a
            // flag such as ? before the state letter.
            stat.trim().is_empty() || stat.contains(['Z', 'E']),
            "helper survived: {stat}"
        );
    }

    #[test]
    fn non_utf8_output_is_a_parse_error() {
        let err = run("printf", &["\\377"], &Cancel::new()).unwrap_err();
        assert!(matches!(err, InventoryError::Parse { .. }), "{err:?}");
    }

    /// A program that exists but cannot run is an error, not "not installed".
    #[test]
    fn unrunnable_program_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tool");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        let err = run(path.to_str().unwrap(), &[], &Cancel::new()).unwrap_err();
        assert!(matches!(err, InventoryError::Spawn { .. }), "{err:?}");
    }

    /// A script whose interpreter was removed fails with `NotFound`, but it is installed.
    #[test]
    fn broken_shebang_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let program = script(tmp.path(), "#!/nonexistent/python3\n");
        let err = run(&program, &[], &Cancel::new()).unwrap_err();
        assert!(matches!(err, InventoryError::Spawn { .. }), "{err:?}");
    }

    #[test]
    fn which_looks_on_the_newest_search_path() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for dir in [&first, &second] {
            let probe = dir.path().join("vigil-probe");
            fs::write(&probe, "").unwrap();
            fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        // SEARCH_PATH is the process's and is left set, and tests run in parallel: each path
        // keeps /bin and /usr/bin, so every test that runs a tool by name (sh, echo, cat, ...)
        // still finds it.
        let set = |dir: &Path| {
            use_search_path(
                env::join_paths([dir, Path::new("/bin"), Path::new("/usr/bin")]).unwrap(),
            );
        };
        set(first.path());
        assert_eq!(which("vigil-probe"), Some(first.path().join("vigil-probe")));
        set(second.path());
        assert_eq!(
            which("vigil-probe"),
            Some(second.path().join("vigil-probe")),
            "replaced, as after Look again"
        );
    }

    #[test]
    fn which_finds_programs() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        fs::write(&plain, "").unwrap();
        assert_eq!(which(plain.to_str().unwrap()), None, "not executable");
        assert_eq!(which(dir.path().to_str().unwrap()), None, "a directory");
        assert!(which("sh").is_some());
        assert_eq!(which("/bin/sh"), Some(PathBuf::from("/bin/sh")));
        assert_eq!(which("vigil-no-such-tool"), None);
        assert_eq!(which("/nonexistent/tool"), None);
    }
}
