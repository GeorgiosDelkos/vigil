//! Runs a script in the user's shell with the `PATH` their terminal has.
//!
//! The menu-bar app starts with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, so agents and tools are
//! looked up through `$SHELL`. A login shell (`-lc`) is not enough: zsh started that way reads
//! `.zshenv`, `.zprofile` and `.zlogin` but not `.zshrc`, and the Claude Code and Grok
//! installers, nvm, oh-my-zsh, bun and conda commonly add their folders in `.zshrc`. On a Mac
//! seen 2026-11-13, `zsh -lc 'command -v claude grok'` found neither and `zsh -ilc` found
//! both. So the script runs in an interactive login shell first, as VS Code resolves the shell
//! environment, and that `PATH` is also the one tools are found on.
//!
//! Decision: always the interactive shell first, falling back to `-lc` when it fails, times
//! out after [`INTERACTIVE_TIMEOUT`], or exits before the script's [`END_MARK`]. Rejected:
//! `-lc` first and `-ilc` only when an agent is not found, which costs one shell start fewer
//! for users whose `.zprofile` has everything, but leaves the tool search path without the
//! `.zshrc` entries, so bun or conda read as not installed.
//!
//! Only zsh and bash, known by the file name of `$SHELL`, run interactively. Other shells keep
//! `-lc`, since their flags differ (fish has no `+m`) and nobody has checked them.
//!
//! An interactive shell started without a terminal needs care:
//! - stdin is closed, so a `.zshrc` that reads input gets end of file instead of waiting;
//! - startup files print (a Java stub on stderr, prompt themes' escape codes on stdout), so
//!   the script marks its answer and the callers read only the marked lines;
//! - zsh runs with `+m` (no job control). Interactive zsh opens `/dev/tty` when it has one,
//!   which the CLI started from a terminal does, and with job control it waits to become the
//!   terminal's foreground group. The command runs in its own process group, so it would stop
//!   there until the time limit; with `+m` it answered in half a second (checked 2026-11-13
//!   under a pseudo-terminal). bash with stdin not a terminal starts no job control, and
//!   answered at once under the same check.
//!
//! This runs the user's own `.zshrc` or `.bashrc`, as their terminal does; `-lc` already ran
//! their `.zprofile`.

use std::path::Path;
use std::time::Duration;

use crate::inventory::InventoryError;
use crate::inventory::command;
use crate::inventory::command::Output;

/// Starts a script's answer, on a line followed by the shell's `PATH`; see [`is_path_mark`].
pub(crate) const PATH_MARK: &str = "__vigil_path__";

/// Ends a script's answer. A shell whose stdout has no line equal to it did not run the
/// script to the end, so the answer comes from the login shell instead.
pub(crate) const END_MARK: &str = "__vigil_end__";

/// How long the interactive shell may take before the login shell answers instead. Sourced:
/// VS Code gives resolving the shell environment 10 seconds
/// (<https://github.com/microsoft/vscode/blob/1.95.0/src/vs/platform/shell/node/shellEnv.ts#L70>).
/// A `.zshrc` with oh-my-zsh and nvm starts in one or two seconds; one that waits on the
/// network or a prompt is cut off here instead of at the one-minute command limit.
const INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Runs `script` in `shell` as the user's terminal would: interactive and login, falling back
/// to a login shell alone (see the module docs). Returns the output of whichever answered, or
/// `None` when `shell` is not installed. Stdout is decoded lossily, so a startup file that
/// prints bytes that are not UTF-8 does not discard the answer.
///
/// Blocks for up to [`INTERACTIVE_TIMEOUT`] plus the one-minute command limit. Runs the user's
/// startup files.
///
/// # Errors
///
/// Fails when the login shell fails, after the interactive one did.
pub(crate) fn run(shell: &str, script: &str) -> Result<Option<Output>, InventoryError> {
    run_within(shell, script, INTERACTIVE_TIMEOUT)
}

/// [`run`] with the interactive shell's time limit given, so tests can wait less.
fn run_within(
    shell: &str,
    script: &str,
    interactive_limit: Duration,
) -> Result<Option<Output>, InventoryError> {
    if let Some(flags) = interactive_flags(shell) {
        let args = [flags, &[script]].concat();
        // Anything else is not returned: a broken `.zshrc` or a slow prompt is the user's
        // terminal setup, and the login shell can still answer. If it cannot either (or the
        // shell is not installed), its result is the one reported.
        if let Ok(Some(output)) = command::run_with_input(shell, &args, b"", interactive_limit)
            && finished(&output.stdout)
        {
            return Ok(Some(output));
        }
    }
    command::run_with_input(shell, &["-lc", script], b"", command::TIMEOUT)
}

/// The flags that start `shell` as an interactive login shell running the next argument, or
/// `None` for a shell other than zsh and bash.
fn interactive_flags(shell: &str) -> Option<&'static [&'static str]> {
    match Path::new(shell).file_name()?.to_str()? {
        "zsh" => Some(&["-i", "+m", "-l", "-c"]),
        "bash" => Some(&["-i", "-l", "-c"]),
        _ => None,
    }
}

/// Whether `line` is the one the script's [`PATH_MARK`] ends. A startup file that prints
/// without a final newline (a prompt theme's escape codes) leaves its text on the same line,
/// before the mark. The later marks follow the script's own newlines, so they stand alone.
pub(crate) fn is_path_mark(line: &str) -> bool {
    line.trim_end().ends_with(PATH_MARK)
}

/// Whether the script ran to its [`END_MARK`].
fn finished(stdout: &str) -> bool {
    stdout.lines().any(|line| line.trim() == END_MARK)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// Writes an executable shell script named `name` into `dir`, standing in for a shell.
    fn fake_shell(dir: &Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    /// A shell that prints its flags, then the end mark, so a test sees how it was started.
    fn echoing_shell(dir: &Path, name: &str) -> String {
        let body = format!(
            "while [ \"$#\" -gt 1 ]; do printf '%s ' \"$1\"; shift; done\n\
             printf '\\n%s\\n' {END_MARK}\n"
        );
        fake_shell(dir, name, &body)
    }

    fn first_line(output: Option<Output>) -> String {
        let stdout = output.unwrap().stdout;
        stdout.lines().next().unwrap().trim().to_owned()
    }

    #[test]
    fn zsh_and_bash_run_interactive_and_other_shells_as_login_shells() {
        let tmp = tempfile::tempdir().unwrap();
        let zsh = echoing_shell(tmp.path(), "zsh");
        let bash = echoing_shell(tmp.path(), "bash");
        let fish = echoing_shell(tmp.path(), "fish");

        assert_eq!(first_line(run(&zsh, "x").unwrap()), "-i +m -l -c");
        assert_eq!(first_line(run(&bash, "x").unwrap()), "-i -l -c");
        assert_eq!(first_line(run(&fish, "x").unwrap()), "-lc");
    }

    #[test]
    fn the_interactive_answer_wins() {
        let tmp = tempfile::tempdir().unwrap();
        // Only the interactive shell, which reads `.zshrc`, has the agent's folder.
        let zsh = fake_shell(
            tmp.path(),
            "zsh",
            &format!(
                "case \"$1\" in -i) echo /from/zshrc ;; *) echo /from/zprofile ;; esac\n\
                 echo {END_MARK}\n"
            ),
        );
        assert_eq!(first_line(run(&zsh, "x").unwrap()), "/from/zshrc");
    }

    #[test]
    fn an_interactive_shell_that_stops_early_falls_back_to_the_login_shell() {
        let tmp = tempfile::tempdir().unwrap();
        // A `.zshrc` that ends the shell before the script runs: exit 0, no end mark.
        let zsh = fake_shell(
            tmp.path(),
            "zsh",
            &format!(
                "case \"$1\" in -i) echo welcome; exit 0 ;; esac\n\
                 echo /from/zprofile\necho {END_MARK}\n"
            ),
        );
        assert_eq!(first_line(run(&zsh, "x").unwrap()), "/from/zprofile");
    }

    #[test]
    fn a_hanging_interactive_shell_falls_back_at_the_limit() {
        let tmp = tempfile::tempdir().unwrap();
        // Answers only after 5 s: a limit that is not applied lets this answer through, which
        // fails the assertion instead of only slowing the test.
        let zsh = fake_shell(
            tmp.path(),
            "zsh",
            &format!(
                "case \"$1\" in -i) sleep 5; echo /from/zshrc; echo {END_MARK}; exit ;; esac\n\
                 echo /from/zprofile\necho {END_MARK}\n"
            ),
        );
        let output = run_within(&zsh, "x", Duration::from_millis(300)).unwrap();
        assert_eq!(first_line(output), "/from/zprofile");
    }

    #[test]
    fn a_missing_shell_is_none_and_a_failing_one_reports_the_login_shell() {
        assert!(run("/nonexistent/zsh", "x").unwrap().is_none());

        let tmp = tempfile::tempdir().unwrap();
        let zsh = fake_shell(tmp.path(), "zsh", "echo \"$1\"; exit 3\n");
        let output = run(&zsh, "x").unwrap().unwrap();
        assert_eq!(output.stdout.trim(), "-lc", "the login shell's answer");
        assert!(!output.success);
    }
}
