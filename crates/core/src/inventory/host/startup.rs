//! Files that run commands without a launch item: the shells' startup files, crontabs, and
//! `periodic`'s scripts.
//!
//! Each file goes to the agent as its lines, with its secrets masked ([`mask`]): these files
//! often hold tokens (`export GITHUB_TOKEN=...`), and the bundle is kept with each sweep's
//! history (owner's decision, 2026-11-18, over a path-and-hash listing the agent would open
//! itself, and over whole files). Every command stays as written.
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

use crate::inventory::command;
use crate::inventory::host::account::Account;
use crate::inventory::host::stamp;
use crate::inventory::host::startup::mask::lines;

mod mask;

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
    /// Its lines, secrets masked as the module docs say.
    lines: Vec<String>,
    /// Whether the file was over [`FILE_LIMIT`], so only its whole lines within it are shown.
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

    /// What keys an issue about it: its shown lines, so changing a masked token does not show a
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
        files.extend(user_crontab(root, account));
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

/// The part of `bytes` shown, and whether it was over [`FILE_LIMIT`]. Over the limit, only the
/// whole lines within it are shown (a line whose newline is the byte just past it included): a
/// line cut part way would show a token cut below its shape's length, or a cut character as
/// U+FFFD.
fn capped(bytes: &[u8]) -> (&[u8], bool) {
    if bytes.len() <= FILE_LIMIT {
        return (bytes, false);
    }
    let end = bytes[..=FILE_LIMIT]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |at| at + 1);
    (&bytes[..end], true)
}

/// The file at `path`, `None` when it is not there. `root_run` is the account to check
/// replaceability against, for a file that runs as root.
fn read(kind: FileKind, path: &Path, root_run: Option<&Account>) -> Option<StartupFile> {
    match read_following(path) {
        Ok(bytes) => {
            let (shown, truncated) = capped(&bytes);
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
        // A planted link to a terminal must not become the sweep's controlling terminal.
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
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
fn user_crontab(root: &Path, account: &Account) -> Option<StartupFile> {
    let tool = root.join("usr/bin/crontab");
    let path = format!("/usr/lib/cron/tabs/{}", account.name);
    let file = |error, lines, truncated| StartupFile {
        path: path.clone(),
        kind: FileKind::Crontab,
        error,
        lines,
        truncated,
        stamp: None,
        replaceable: false,
    };
    // Decoded lossily, as files are: one byte that is not UTF-8 must not drop every job.
    // Not cancellable: `crontab -l` prints a file and exits, bounded by the timeout.
    let run = command::run_with_input(&tool.to_string_lossy(), &["-l"], b"", command::TIMEOUT);
    match run {
        Ok(None) => None,
        Ok(Some(output)) if output.success => {
            // Capped as a file is, so a planted crontab cannot fill every bundle.
            let (shown, truncated) = capped(output.stdout.as_bytes());
            // `capped` cuts after a newline, so the text stays whole UTF-8.
            let shown = std::str::from_utf8(shown).expect("cut at a newline");
            Some(file(None, lines(shown), truncated))
        }
        // What crontab(1) says, and exits 1 with, when the user has no crontab.
        Ok(Some(output)) if output.stderr.starts_with("crontab: no crontab for") => None,
        Ok(Some(output)) => Some(file(Some(output.detail), Vec::new(), false)),
        Err(e) => Some(file(Some(e.to_string()), Vec::new(), false)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let files = collect(&root, Some(&home), None);
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

        let account = Account::current(&crate::cancel::Cancel::new())
            .unwrap()
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let tool = tmp.path().join("usr/bin/crontab");
        fs::create_dir_all(tool.parent().unwrap()).unwrap();
        let crontab = |script: &str| {
            fs::write(&tool, format!("#!/bin/sh\n{script}\n")).unwrap();
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
            user_crontab(tmp.path(), &account)
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
        // Decoded lossily, so a byte that is not UTF-8 keeps the other jobs; capped as a file.
        let lossy = crontab("printf 'a\\377b\\n@reboot /tmp/x\\n'").unwrap();
        assert_eq!(lossy.lines, ["a\u{FFFD}b", "@reboot /tmp/x"]);
        // The line across the limit is left out whole, never cut in a character's middle.
        let script = format!(
            "printf '@reboot /tmp/x\\n'; head -c {} /dev/zero | tr '\\\\0' z; \
             printf '\\342\\234\\223tail'",
            FILE_LIMIT - 16
        );
        let long = crontab(&script).unwrap();
        assert!(long.truncated);
        assert_eq!(long.lines, ["@reboot /tmp/x"]);
        // A crontab of exactly the limit is whole.
        let script = format!(
            "head -c {} /dev/zero | tr '\\\\0' z; printf '\\n'",
            FILE_LIMIT - 1
        );
        let full = crontab(&script).unwrap();
        assert!(!full.truncated);
        assert_eq!(full.lines.concat().len(), FILE_LIMIT - 1);
        fs::remove_file(&tool).unwrap();
        assert!(user_crontab(tmp.path(), &account).is_none(), "no tool");
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
        // A token across the limit is left out with its line, not shown cut below its shape.
        let token = format!("ghp_{}", "A".repeat(40));
        fs::write(&path, "a\n".repeat(limit / 2 - 4) + &token + "\n").unwrap();
        let cut = read(FileKind::ShellStartup, &path, None).unwrap();
        assert!(cut.truncated);
        assert_eq!(cut.lines.len(), limit / 2 - 4);
        assert!(
            !cut.lines.concat().contains("ghp_"),
            "{:?}",
            cut.lines.last()
        );
        // A line whose newline is the byte just past the limit is whole, and kept.
        fs::write(&path, "z".repeat(limit) + "\nb\n").unwrap();
        let edge = read(FileKind::ShellStartup, &path, None).unwrap();
        assert!(edge.truncated);
        assert_eq!(edge.lines, ["z".repeat(limit)]);
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
