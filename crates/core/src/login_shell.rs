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
//! Decision: the interactive shell first on every lookup without a terminal (below), falling
//! back to `-lc` when it fails, times out after [`INTERACTIVE_TIMEOUT`], or exits before the
//! script's [`END_MARK`]. Rejected: `-lc` first and `-ilc` only when an agent is not found,
//! which costs one shell start fewer for users whose `.zprofile` has everything, but leaves
//! the tool search path without the `.zshrc` entries, so bun or conda read as not installed.
//!
//! Only zsh and bash, known by the file name of `$SHELL`, run interactively. Other shells keep
//! `-lc`, since their flags differ and nobody has checked them.
//!
//! A process with a controlling terminal (the CLI run from a terminal) keeps `-lc` too, as VS
//! Code skips resolving the environment when started from one. Its `PATH` already has the
//! `.zshrc` entries, which `-lc` keeps. An interactive shell there would run `.zshrc` against
//! that terminal (checked 2026-11-13 under a pseudo-terminal): output to `/dev/tty` reaches
//! the user's screen, Apple Terminal's `/etc/zshrc_Apple_Terminal` writes session files for
//! the parent's session, and a read from `/dev/tty` or zsh's job control stops the shell,
//! which runs in its own background process group, until the time limit.
//!
//! An interactive shell started without a terminal needs care:
//! - stdin is closed, so a `.zshrc` that reads input gets end of file instead of waiting;
//! - startup files print (a Java stub on stderr, prompt themes' escape codes on stdout), so
//!   the script marks its answer and the callers read only the marked lines.
//!
//! Not handled: a background job that a startup file starts without redirecting its output
//! keeps the output pipe open after the shell exits, so the command waits for the time limit
//! and the interactive answer is lost. `-lc` has had the same limit with `.zprofile`; telling
//! that job from a tool still writing its output would change how every command is read.
//!
//! This runs the user's own `.zshrc`, or for bash their `.bash_profile` with the interactive
//! part of a `.bashrc` it sources, as their terminal does; `-lc` already ran `.zprofile`.

use std::fs;
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

/// How [`run_with`] starts the shell.
#[derive(Debug, Clone, Copy)]
enum Start {
    /// Interactive first, when the shell is zsh or bash, for up to this long.
    Interactive(Duration),
    /// A login shell only.
    Login,
}

/// Runs `script`, which looks up `programs` with `command -v`, in `shell` as the user's
/// terminal would: interactive and login, falling back to a login shell alone, or only a login
/// shell when this process has a terminal (see the module docs). Every alias, and any function
/// named after one of `programs`, is removed before `script` runs (see
/// [`clear_definitions`]). Returns the output of whichever shell answered, or `None` when
/// `shell` is not installed. Stdout is decoded lossily, so a startup file that prints bytes
/// that are not UTF-8 does not discard the answer.
///
/// Blocks for up to [`INTERACTIVE_TIMEOUT`] plus the one-minute command limit. Runs the user's
/// startup files.
///
/// # Errors
///
/// Fails when the login shell fails, after the interactive one did.
pub(crate) fn run(
    shell: &str,
    programs: &[&str],
    script: &str,
) -> Result<Option<Output>, InventoryError> {
    // Opening `/dev/tty` fails with ENXIO when the process has no controlling terminal. Any
    // other failure (no file descriptors left, a sandbox) is taken as no terminal as well.
    let start = if fs::File::open("/dev/tty").is_ok() {
        Start::Login
    } else {
        Start::Interactive(INTERACTIVE_TIMEOUT)
    };
    run_with(shell, programs, script, start)
}

/// [`run`] with how to start the shell given, so tests do not depend on having a terminal.
fn run_with(
    shell: &str,
    programs: &[&str],
    script: &str,
    start: Start,
) -> Result<Option<Output>, InventoryError> {
    let script = format!("{}{script}", clear_definitions(programs));
    let script = script.as_str();
    if let Start::Interactive(limit) = start
        && runs_interactive(shell)
    {
        let args = ["-i", "-l", "-c", script];
        // Anything else is not returned: a broken `.zshrc` or a slow prompt is the user's
        // terminal setup, and the login shell can still answer. If it cannot either (or the
        // shell is not installed), its result is the one reported.
        if let Ok(Some(output)) = command::run_with_input(shell, &args, b"", limit)
            && finished(&output.stdout)
        {
            return Ok(Some(output));
        }
    }
    command::run_with_input(shell, &["-lc", script], b"", command::TIMEOUT)
}

/// Whether `shell` is zsh or bash, which this module starts interactive.
fn runs_interactive(shell: &str) -> bool {
    let name = Path::new(shell).file_name().and_then(|n| n.to_str());
    matches!(name, Some("zsh" | "bash"))
}

/// Shell text that removes every alias, and any function named after one of `programs`, so
/// a `command -v` after it prints where the program is on `PATH`. An interactive shell has
/// the aliases and functions its startup files define, and `command -v` prints those instead
/// (`alias claude='claude --model opus'`), which the callers would read as not installed.
/// The names are the callers' constants, so they need no quoting.
fn clear_definitions(programs: &[&str]) -> String {
    format!(
        "unalias -a 2>/dev/null; unset -f {} 2>/dev/null; ",
        programs.join(" ")
    )
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

    /// The app's start, whether or not the test runs in a terminal.
    const INTERACTIVE: Start = Start::Interactive(INTERACTIVE_TIMEOUT);

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

        assert_eq!(
            first_line(run_with(&zsh, &[], "x", INTERACTIVE).unwrap()),
            "-i -l -c"
        );
        assert_eq!(
            first_line(run_with(&bash, &[], "x", INTERACTIVE).unwrap()),
            "-i -l -c"
        );
        assert_eq!(
            first_line(run_with(&fish, &[], "x", INTERACTIVE).unwrap()),
            "-lc"
        );
        assert_eq!(
            first_line(run_with(&zsh, &[], "x", Start::Login).unwrap()),
            "-lc",
            "a process with a terminal"
        );
    }

    #[test]
    fn run_clears_definitions_before_the_script() {
        let tmp = tempfile::tempdir().unwrap();
        // fish is only started as `-lc <script>`, so `$2` is the script `run_with` built.
        let fish = fake_shell(
            tmp.path(),
            "fish",
            &format!("printf '%s\\n' \"$2\" {END_MARK}\n"),
        );
        let output = run_with(&fish, &["claude"], "the-script", INTERACTIVE)
            .unwrap()
            .unwrap();
        assert_eq!(
            output.stdout.lines().next().unwrap(),
            format!("{}the-script", clear_definitions(&["claude"]))
        );
    }

    #[test]
    fn cleared_aliases_and_functions_leave_the_program_on_path() {
        let script = format!(
            "alias ls='ls -G'; ls() {{ :; }}; {}command -v ls",
            clear_definitions(&["no-such-program", "ls"])
        );
        // zsh, the default shell, and sh, which is bash in POSIX mode on macOS and prints
        // aliases from `command -v` as zsh does.
        for shell in ["/bin/zsh", "/bin/sh"] {
            if !Path::new(shell).exists() {
                continue;
            }
            let output = command::run(shell, &["-c", &script], &crate::cancel::Cancel::new());
            let found = output.unwrap().unwrap();
            assert!(found.trim().starts_with('/'), "{shell} printed {found:?}");
        }
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
        assert_eq!(
            first_line(run_with(&zsh, &[], "x", INTERACTIVE).unwrap()),
            "/from/zshrc"
        );
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
        assert_eq!(
            first_line(run_with(&zsh, &[], "x", INTERACTIVE).unwrap()),
            "/from/zprofile"
        );
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
        let output = run_with(
            &zsh,
            &[],
            "x",
            Start::Interactive(Duration::from_millis(300)),
        )
        .unwrap();
        assert_eq!(first_line(output), "/from/zprofile");
    }

    #[test]
    fn a_missing_shell_is_none_and_a_failing_one_reports_the_login_shell() {
        assert!(run("/nonexistent/zsh", &[], "x").unwrap().is_none());

        let tmp = tempfile::tempdir().unwrap();
        // A shell this module never starts interactive answers the same with or without a
        // terminal, so `run` itself can be checked here.
        let fish = echoing_shell(tmp.path(), "fish");
        assert_eq!(first_line(run(&fish, &[], "x").unwrap()), "-lc");

        let zsh = fake_shell(tmp.path(), "zsh", "echo \"$1\"; exit 3\n");
        let output = run_with(&zsh, &[], "x", INTERACTIVE).unwrap().unwrap();
        assert_eq!(output.stdout.trim(), "-lc", "the login shell's answer");
        assert!(!output.success);
    }
}
