//! What the app checks itself around a repository fix, rather than leave to the prompt.
//!
//! The fix agent runs with full access, so these are checks around it, not a sandbox:
//!
//! - Before the user is asked, [`foreign_command`] refuses a confirmed command that addresses
//!   another repository through `gh` or a GitHub URL.
//! - The agent runs with [`ENV`]: git hooks and package-manager lifecycle scripts off, so
//!   cloning the repository, installing its packages or committing runs none of its code.
//! - Before the agent runs, [`Watch::start`] records the default branch and its head; after
//!   it, [`Watch::check`] fails when another branch became the default or that head moved, or
//!   when the pull request the agent reported is not open from the run's branch into the
//!   default branch of this repository. A change to files reported done without a pull request
//!   is caught by the caller, which knows the fix ([`settings_only`]).

use serde_json::Value;

use crate::inventory::command;
use crate::sweep;

/// The environment a repository fix's agent runs with. Every git command it runs, `gh repo
/// clone` included, reads `GIT_CONFIG_COUNT` and its pairs as command-line configuration
/// (git 2.31 and later), which wins over the clone's own config, so no hook runs; `/dev/null`
/// holds no hooks. npm and pnpm read `npm_config_ignore_scripts`, and Yarn 2 and later
/// `YARN_ENABLE_SCRIPTS`, so installing the repository's packages runs none of their
/// lifecycle scripts. The agent could still unset them: they keep the repository's own code
/// from running by accident, not an agent that means to run it.
pub(super) const ENV: [(&str, &str); 5] = [
    ("GIT_CONFIG_COUNT", "1"),
    ("GIT_CONFIG_KEY_0", "core.hooksPath"),
    ("GIT_CONFIG_VALUE_0", "/dev/null"),
    ("npm_config_ignore_scripts", "true"),
    ("YARN_ENABLE_SCRIPTS", "false"),
];

/// Why `command`, a confirmed command of a fix of `repo`, may address another repository, or
/// `None` when it addresses only `repo`.
///
/// Defence in depth, conservative on purpose: the agent that runs the fix has full access, so
/// this only keeps a confirmed command (written by the sweep's agent from untrusted input)
/// from naming another repository in plain sight. A command that might reach one is refused,
/// and a fix it refuses wrongly is left to the user to run by hand. The command is split into
/// words as a shell would (quotes and backslashes), and into parts at `;`, `&`, `|`,
/// parentheses and line breaks. Then:
///
/// - no word names a `GH_*`, `GITHUB_*` or `GIT_*` variable, set or not (`GH_REPO`, `GH_HOST`,
///   a token, `GIT_DIR`, or the `GIT_CONFIG_*` that turns hooks off), as `read`, `export` and
///   `printf -v` set one without `=`;
/// - no word holds a character the shell expands (`$`, a backquote, `*`, `?`, `[`, `{`, `}`,
///   but a lone `{` or `}` is a group), as its expansion cannot be checked;
/// - no word is a shell or runs the words it reads (`sh`, `bash`, `eval`, `source`, `xargs`,
///   `parallel`, `alias`, and a `.` with a word after it), which could run text no rule here
///   can read, such as `printf ... | sh`; a word with spaces in it passes these rules itself;
/// - every word that names a checked program (`gh`, `git`, `curl`, `wget`, `cd`, `pushd`) is
///   checked as a call of it with the words after it, so no wrapper or argument before it
///   hides the real call. In those calls every GitHub address (`github.com/<owner>/<name>`,
///   `github.com:<owner>/<name>`, any case) names `repo` with no `..` or `%` after it, and every
///   API address (`api.github.com/...`) is under `/repos/<repo>` ([`under_repo`]);
/// - `gh` runs only `api`, `secret`, `variable`, `workflow`, `pr`, `issue`, `label`, `release`
///   or `repo edit`, never with `--hostname`, `--org`, `-o` or `--owner`. `gh api` calls one
///   path under `repos/<repo>` (so no `graphql`, `user` or `orgs/...`). Every other
///   subcommand names `repo` with `-R` or `--repo` (`gh repo edit` with its argument), as `gh`
///   otherwise takes the repository from the folder it runs in, and names no other
///   `owner/name`;
/// - `cd` and `pushd`, and `git`'s `-C`, `--git-dir` and `--work-tree`, go only to a relative
///   folder with no `..`: the agent works in the clone. `git` takes no `-c` or `--config-env`
///   before its subcommand, which can make it run a shell.
///
/// Unchecked: other programs and interpreters. `go get github.com/<module>` names a module, not
/// a repository to change; a script in the clone, one the command writes and then runs
/// (`printf ... > f; ./f`), or `python -c` can reach GitHub another way, the accepted risk of a
/// full-access agent. A checked program's name counts as a call even as
/// an argument (`npm install gh`), which refuses such a fix wrongly. Owner and name compare
/// case-insensitively, as GitHub does.
pub(super) fn foreign_command(command: &str, repo: &str) -> Option<String> {
    let parts = shell_parts(command);
    let words = || parts.iter().flatten();
    if let Some(word) = words().find(|w| names_checked_variable(w)) {
        let name = word.split_once('=').map_or(word.as_str(), |(name, _)| name);
        return Some(format!("it names {name}"));
    }
    if let Some(word) = words().find(|w| expands(w)) {
        return Some(format!("`{word}` cannot be checked before it runs"));
    }
    if let Some(word) = words().find(|w| is_shell(w)) {
        return Some(format!("it runs {word}, whose input cannot be checked"));
    }
    // `.` reads commands from the file named after it; a `.` with no word after it is a
    // folder (`git add .`). Refusing every `. <word>` also refuses `cp -r . ../x`, left to the
    // user to run by hand, and needs no list of what may come before a command.
    if parts
        .iter()
        .any(|part| part.iter().rev().skip(1).any(|w| w == "."))
    {
        return Some("it runs ., whose input cannot be checked".to_owned());
    }
    words()
        .filter(|w| w.contains(char::is_whitespace))
        .find_map(|w| foreign_command(w, repo))
        .or_else(|| {
            parts
                .iter()
                .flat_map(|part| checked_calls(part))
                .find_map(|(program, args)| foreign_call(program, args, repo))
        })
}

/// Whether `word` names a `GH_*`, `GITHUB_*` or `GIT_*` variable, alone or in an assignment:
/// those can point `gh` or `git` at another repository, host or folder, or turn hooks back on.
fn names_checked_variable(word: &str) -> bool {
    let name = word.split_once('=').map_or(word, |(name, _)| name);
    ["GH_", "GITHUB_", "GIT_"]
        .iter()
        .any(|p| name.starts_with(p))
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Whether the shell would expand `word` into something else: a variable, a command's output,
/// a glob or a brace list. A lone `{` or `}` groups commands and expands nothing.
fn expands(word: &str) -> bool {
    word.contains(['$', '`', '*', '?', '[', '{', '}']) && !matches!(word, "{" | "}")
}

/// Whether `word` runs a shell or makes one read more commands.
///
/// `xargs` and `parallel` run the words they read as a command, and `alias` makes a new name
/// for one.
fn is_shell(word: &str) -> bool {
    matches!(
        file_name(word),
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "ash"
            | "mksh"
            | "fish"
            | "csh"
            | "tcsh"
            | "eval"
            | "source"
            | "xargs"
            | "parallel"
            | "alias"
    )
}

/// The file name of the program `word` names: what follows its last `/`.
fn file_name(word: &str) -> &str {
    word.rsplit('/')
        .next()
        .expect("rsplit yields at least one piece")
}

/// The programs this rule checks, each found by its file name.
const CHECKED: [&str; 6] = ["gh", "git", "curl", "wget", "cd", "pushd"];

/// Every call of a checked program in `part`: each word that names one, with the words after
/// it as its arguments. All of them, so a checked name used as an argument (`sudo -u git gh`)
/// cannot hide the call after it.
fn checked_calls(part: &[String]) -> impl Iterator<Item = (&str, &[String])> {
    part.iter().enumerate().filter_map(|(at, word)| {
        let name = file_name(word);
        CHECKED.contains(&name).then(|| (name, &part[at + 1..]))
    })
}

/// Why the call of the checked `program` with `args` may address another repository.
fn foreign_call(program: &str, args: &[String], repo: &str) -> Option<String> {
    if matches!(program, "cd" | "pushd") {
        let target = args.first().map_or("", String::as_str);
        return outside_clone(target)
            .then(|| format!("it changes to {target:?}, outside the clone"));
    }
    if let Some(why) = args.iter().find_map(|word| foreign_address(word, repo)) {
        return Some(why);
    }
    match program {
        "gh" => foreign_gh(args, repo),
        "git" => foreign_git(args),
        _ => None,
    }
}

/// Whether the folder `target` may be outside the clone: empty, absolute, from home, an
/// option, or with a `..` segment.
fn outside_clone(target: &str) -> bool {
    target.is_empty()
        || target.starts_with(['/', '~', '-'])
        || target.split('/').any(|segment| segment == "..")
}

/// Why the `git` call with `args` may work outside the clone or run a shell. Only git's own
/// options are read, the ones before the subcommand, so `git switch -c b` and `git log -C`
/// pass: `-C`, `--git-dir` and `--work-tree` must name a folder inside the clone
/// ([`outside_clone`]), and `-c` and `--config-env` are refused, as configuration can make git
/// run a shell (`alias.x=!...`, `core.sshCommand`, `credential.helper=!...`).
fn foreign_git(args: &[String]) -> Option<String> {
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        if !arg.starts_with('-') {
            return None;
        }
        if matches!(arg.as_str(), "-c" | "--config-env") || arg.starts_with("--config-env=") {
            return Some(format!("it runs git with {arg}, which can run a shell"));
        }
        let value = match arg.as_str() {
            "-C" | "--git-dir" | "--work-tree" => words.next().map_or("", String::as_str),
            _ => match arg
                .strip_prefix("--git-dir=")
                .or_else(|| arg.strip_prefix("--work-tree="))
            {
                Some(value) => value,
                None => continue,
            },
        };
        if outside_clone(value) {
            return Some(format!("it runs git in {value:?}, outside the clone"));
        }
    }
    None
}

/// Why the GitHub addresses in `word` may not be `repo`'s.
fn foreign_address(word: &str, repo: &str) -> Option<String> {
    let lower = word.to_ascii_lowercase();
    lower.match_indices("github.com").find_map(|(at, _)| {
        let rest = &lower[at + "github.com".len()..];
        let api = lower[..at].ends_with("api.");
        // A fully qualified host (`github.com.`) reaches the same server.
        let rest = rest.strip_prefix('.').unwrap_or(rest);
        let path = rest.strip_prefix(['/', ':'])?;
        if api {
            return under_repo(path, repo)
                .err()
                .map(|why| format!("it calls the API at {why}"));
        }
        // git and curl remove dot segments before the request: `o/r/../../x/y` reaches x/y.
        if path.contains('%') || path.split(['/', '?']).any(|s| s == ".." || s == ".") {
            return Some(format!(
                "it names github.com/{path}, which may lead elsewhere"
            ));
        }
        let named = path
            .split(['/', '?', '#'])
            .take(2)
            .collect::<Vec<_>>()
            .join("/");
        let named = named.trim_end_matches(".git");
        (!named.eq_ignore_ascii_case(repo)).then(|| format!("it names github.com/{named}"))
    })
}

/// Checks that the API `path` is under `repos/<repo>`, with a leading `/` allowed, holds no
/// `..` segment or `%` escape that could move it elsewhere, and is not `forks`, `generate` or
/// `transfer`, which make another repository or give this one away; the error names the path.
/// The `?` of a query is handled as a second guard: [`foreign_command`] already refuses every
/// word with `?`, as the shell could glob it.
fn under_repo(path: &str, repo: &str) -> Result<(), String> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let prefix = format!("repos/{repo}");
    let under = path
        .get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
        && matches!(path.as_bytes().get(prefix.len()), None | Some(b'/' | b'?'));
    let segments = || path.split(['/', '?']);
    let moves = path.contains('%') || segments().any(|s| s == ".." || s == ".");
    // `transfer` moves the repository to another owner; the others make a new one.
    let creates = segments().nth(3).is_some_and(|s| {
        ["forks", "generate", "transfer"]
            .iter()
            .any(|c| s.eq_ignore_ascii_case(c))
    });
    if !under || moves {
        Err(format!("{path}, not under {prefix}"))
    } else if creates {
        Err(format!(
            "{path}, which makes another repository or moves this one"
        ))
    } else {
        Ok(())
    }
}

/// Why the `gh` call with `args` may address another repository.
fn foreign_gh(args: &[String], repo: &str) -> Option<String> {
    if let Some(flag) = args.iter().find(|a| {
        let name = a.split_once('=').map_or(a.as_str(), |(name, _)| name);
        matches!(name, "--hostname" | "--org" | "-o" | "--owner")
    }) {
        return Some(format!("it runs gh with {flag}"));
    }
    let sub = args.first().map_or("", String::as_str);
    if sub == "api" {
        return foreign_api(&args[1..], repo);
    }
    let edit = sub == "repo" && args.get(1).is_some_and(|a| a == "edit");
    let allowed = [
        "secret", "variable", "workflow", "pr", "issue", "label", "release",
    ];
    if !edit && !allowed.contains(&sub) {
        return Some(format!(
            "it runs gh {sub}, which a fix of one repository does not need"
        ));
    }
    let mut named = edit && args.get(2).is_some_and(|a| a.eq_ignore_ascii_case(repo));
    for (i, arg) in args.iter().enumerate() {
        let value = match arg.as_str() {
            "-R" | "--repo" => args.get(i + 1).map_or("", String::as_str),
            _ => match arg.strip_prefix("--repo=") {
                Some(value) => value,
                None => match arg.strip_prefix("-R") {
                    Some(value) if !value.is_empty() => value,
                    _ => continue,
                },
            },
        };
        if !value.eq_ignore_ascii_case(repo) {
            return Some(format!("it runs gh with --repo {value}"));
        }
        named = true;
    }
    if let Some(other) = args
        .iter()
        .find(|a| is_slug(a) && !a.eq_ignore_ascii_case(repo))
    {
        return Some(format!("it runs gh {sub} on {other}"));
    }
    (!named).then(|| format!("it runs gh {sub} without --repo {repo}"))
}

/// Whether `word` looks like an `owner/name`: two non-empty parts of name characters.
fn is_slug(word: &str) -> bool {
    let name = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    word.split_once('/')
        .is_some_and(|(owner, rest)| name(owner) && name(rest))
}

/// Why the `gh api` call with `args` may address another repository: its one path must be
/// under `repos/<repo>` ([`under_repo`]).
fn foreign_api(args: &[String], repo: &str) -> Option<String> {
    // The `gh api` flags that take a value as the next word (gh 2.x, `gh api --help`). A short
    // flag with its value attached (`-XPUT`) is one word.
    const VALUED: [&str; 16] = [
        "-X",
        "--method",
        "-f",
        "--raw-field",
        "-F",
        "--field",
        "-H",
        "--header",
        "-q",
        "--jq",
        "-t",
        "--template",
        "--input",
        "-p",
        "--preview",
        "--cache",
    ];
    let mut paths = Vec::new();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if VALUED.contains(&word.as_str()) {
            words.next();
        } else if !word.starts_with('-') {
            paths.push(word);
        }
    }
    match paths.as_slice() {
        [path] => under_repo(path, repo)
            .err()
            .map(|why| format!("it runs gh api on {why}")),
        _ => Some("it runs gh api without exactly one path".to_owned()),
    }
}

/// `command` split as a shell splits it: into parts at `;`, `&`, `|`, parentheses and line
/// breaks, and each part into words, with quotes removed and a backslash keeping the next
/// character. Enough for the checks above, not a shell: no expansion is done, and the words
/// that would expand are refused by the callers.
fn shell_parts(command: &str) -> Vec<Vec<String>> {
    let mut parts = vec![Vec::new()];
    let mut word: Option<String> = None;
    let mut quote = None;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            // Inside single quotes a backslash is a plain character, which the last arm keeps.
            (Some('"') | None, '\\') => {
                if let Some(next) = chars.next() {
                    word.get_or_insert_default().push(next);
                }
            }
            (None, '\'' | '"') => {
                quote = Some(c);
                word.get_or_insert_default();
            }
            (None, c) if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')') => {
                let part = parts.last_mut().expect("parts starts with one part");
                part.extend(word.take());
                if !c.is_whitespace() || c == '\n' {
                    parts.push(Vec::new());
                }
            }
            (_, c) => word.get_or_insert_default().push(c),
        }
    }
    parts
        .last_mut()
        .expect("parts starts with one part")
        .extend(word);
    parts.retain(|part| !part.is_empty());
    parts
}

/// A repository's default branch before a fix ran, to check the run against afterwards.
#[derive(Debug)]
pub(super) struct Watch {
    /// The repository as config.toml names it.
    repo: String,
    default_branch: String,
    /// The commit at the head of the default branch.
    head: String,
}

impl Watch {
    /// Reads `repo`'s default branch and its head with `gh`, the program to run.
    ///
    /// # Errors
    ///
    /// Fails, with why, when `gh` cannot read them.
    pub(super) fn start(gh: &str, repo: &str) -> Result<Self, String> {
        let default_branch = default_branch_of(gh, repo)?;
        let head = head(gh, repo, &default_branch)?;
        Ok(Self {
            repo: repo.to_owned(),
            default_branch,
            head,
        })
    }

    /// Checks the repository after the fix: the same branch is still the default and has the
    /// head it had, and `pull_request`, when the agent reported one, is open from `branch` of
    /// this repository into the default branch.
    ///
    /// # Errors
    ///
    /// Fails, with why, when something differs or cannot be read.
    pub(super) fn check(
        &self,
        gh: &str,
        branch: &str,
        pull_request: Option<&str>,
    ) -> Result<(), String> {
        let Self {
            repo,
            default_branch,
            head: before,
        } = self;
        // Read again: an agent that made its own branch the default would leave the old
        // default branch's head where it was.
        let now_default = default_branch_of(gh, repo)?;
        if now_default != *default_branch {
            return Err(format!(
                "the default branch of {repo} changed during the fix, from {default_branch} to \
                 {}; check the repository's settings",
                sweep::plain(&now_default)
            ));
        }
        let now = head(gh, repo, default_branch)?;
        if now != *before {
            return Err(format!(
                "the default branch {default_branch} of {repo} moved during the fix, from {} to \
                 {}; check what was pushed to it",
                short(before),
                short(&now)
            ));
        }
        let Some(url) = pull_request else {
            return Ok(());
        };
        let number = url.rsplit('/').next().unwrap_or_default();
        let pr = api(gh, &format!("repos/{repo}/pulls/{number}"))?;
        let field = |path: &str| pr.pointer(path).and_then(Value::as_str).unwrap_or_default();
        let wrong = if field("/state") != "open" {
            Some(format!("is {}, not open", field("/state")))
        } else if field("/head/ref") != branch {
            Some(format!("is from {}, not {branch}", field("/head/ref")))
        } else if !field("/head/repo/full_name").eq_ignore_ascii_case(repo) {
            Some(format!("is from {}", field("/head/repo/full_name")))
        } else if field("/base/ref") != default_branch
            || !field("/base/repo/full_name").eq_ignore_ascii_case(repo)
        {
            Some(format!(
                "is into {}:{}, not {repo}:{default_branch}",
                field("/base/repo/full_name"),
                field("/base/ref")
            ))
        } else {
            None
        };
        match wrong {
            Some(why) => Err(format!("the pull request {url} {}", sweep::plain(&why))),
            None => Ok(()),
        }
    }
}

/// The name of `repo`'s default branch.
fn default_branch_of(gh: &str, repo: &str) -> Result<String, String> {
    let meta = api(gh, &format!("repos/{repo}"))?;
    meta["default_branch"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("GitHub named no default branch of {repo}"))
}

/// Whether the fix with `commands` only changes settings: every command is one `gh` call
/// other than `gh pr` (`gh api`, `gh secret`, `gh workflow disable`, ...), which opens no pull
/// request. A fix without commands is done by its steps, on files. Strict, as a wrong yes lets
/// a change to files pass without its pull request: the command's first word must be `gh`, so
/// `python fix.py gh secret ...`, `sudo gh ...` or a `./gh` in the clone count as changing
/// files.
pub(super) fn settings_only(commands: &[String]) -> bool {
    !commands.is_empty()
        && commands.iter().all(|command| {
            matches!(shell_parts(command).as_slice(), [part]
                if part.first().is_some_and(|w| w == "gh")
                    && part.get(1).is_some_and(|sub| sub != "pr"))
        })
}

/// The commit at the head of `branch` of `repo`.
fn head(gh: &str, repo: &str, branch: &str) -> Result<String, String> {
    // A branch name goes into the API path as it is, so only names that need no escaping are
    // read; a default branch named otherwise is rare enough to refuse. The refs endpoint takes
    // the ref as the rest of the path, so `release/1.0` reads as one branch, which
    // `branches/<name>` does not.
    if !branch
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(format!(
            "the default branch of {repo} has a name the app does not read: {}",
            sweep::plain(branch)
        ));
    }
    let answer = api(gh, &format!("repos/{repo}/git/ref/heads/{branch}"))?;
    answer
        .pointer("/object/sha")
        .and_then(Value::as_str)
        .filter(|sha| !sha.is_empty() && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned)
        .ok_or_else(|| format!("GitHub named no head commit of {repo}'s branch {branch}"))
}

/// The JSON `gh api` answers for `path`.
fn api(gh: &str, path: &str) -> Result<Value, String> {
    let text = command::run(gh, &["api", path])
        .map_err(|e| sweep::error_chain(&e))?
        .ok_or_else(|| "gh is not installed".to_owned())?;
    serde_json::from_str(&text)
        .map_err(|e| format!("unexpected answer from GitHub for {path}: {e}"))
}

/// The first 7 characters of a commit hash, as git shows it.
fn short(sha: &str) -> &str {
    sha.get(..7).unwrap_or(sha)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn commands_on_this_repository_pass() {
        for command in [
            "gh api -X PUT repos/o/r/branches/main/protection --input p.json",
            "gh api --method PATCH /repos/O/R -f allow_auto_merge=false",
            "gh api -XPUT 'repos/o/r/vulnerability-alerts'",
            "gh api -H 'Accept: application/vnd.github+json' repos/o/r",
            "gh secret delete TOKEN -R o/r",
            "gh workflow disable ci.yml --repo=o/r",
            "gh repo edit o/r --enable-wiki=false",
            "sudo gh pr list --repo O/r",
            "git clone https://github.com/o/r.git && npm install lodash@4.17.21",
            "git clone git@github.com:O/R.git",
            "cd repo && npm install lodash@4.17.21",
            "cd repo && git add . && git commit -m 'Pin lodash'",
            "git switch -c vigil-fix && git log -C -1",
            "curl https://api.github.com/repos/o/r/hooks",
            "go get github.com/gin-gonic/gin@v1.9.1",
            "pip install 'requests>=2.32'",
        ] {
            assert_eq!(foreign_command(command, "o/r"), None, "{command}");
        }
    }

    /// Commands that may reach another repository, each with a part of why it is refused.
    const REFUSED: &[(&str, &str)] = &[
        ("git push https://github.com./x/y.git", "github.com/x/y"),
        (
            "curl https://api.github.com./repos/x/y",
            "the API at repos/x/y",
        ),
        (
            "printf 'g%s repo delete x/y --yes' h | xargs env",
            "it runs xargs",
        ),
        ("printf 'gh repo delete x/y' | . /dev/stdin", "it runs ."),
        ("alias g=gh", "it runs alias"),
        (
            "printf 'gh repo delete x/y' | { . /dev/stdin; }",
            "it runs .",
        ),
        (
            "printf 'gh repo delete x/y' | command . /dev/stdin",
            "it runs .",
        ),
        ("printf x | if . /dev/stdin; then :; fi", "it runs ."),
        (
            "git -c 'alias.x=!gh repo delete x/y' x",
            "it runs git with -c",
        ),
        (
            "git --config-env=core.pager=P log",
            "it runs git with --config-env",
        ),
        (
            "gh api -X POST repos/o/r/transfer -f new_owner=x",
            "moves this one",
        ),
        (
            "gh api repos/o/other/hooks",
            "repos/o/other/hooks, not under",
        ),
        ("gh api -X DELETE repos/o/r2", "repos/o/r2, not under"),
        ("gh api repos/o/rx", "not under repos/o/r"),
        ("gh api /repos/o/r.x/hooks", "not under repos/o/r"),
        ("gh api repos/o/r/../../x/y/hooks", "not under repos/o/r"),
        ("gh api repos/o/r/%2e%2e/x", "not under repos/o/r"),
        (
            "curl https://api.github.com/repos/x/y",
            "the API at repos/x/y",
        ),
        (
            "curl -X DELETE https://api.github.com/repos/o/r/../../x/y",
            "the API at",
        ),
        ("curl https://api.github.com/user", "the API at user"),
        ("git push https://github.com/x/y.git", "github.com/x/y"),
        ("git push https://GitHub.com/x/y.git", "github.com/x/y"),
        (
            "git push git@github.com:x/y.git HEAD:main",
            "github.com/x/y",
        ),
        (
            "gh pr merge https://github.com/x/y/pull/1 -R o/r",
            "github.com/x/y",
        ),
        ("gh secret set T -R x/y", "--repo x/y"),
        ("gh secret set T --repo x/y", "--repo x/y"),
        ("gh secret set T --repo=x/y", "--repo x/y"),
        ("gh secret set T -Rx/y", "--repo x/y"),
        ("gh secret set T --org acme", "with --org"),
        ("gh secret set T -o acme -R o/r", "with -o"),
        ("gh issue transfer 1 x/y -R o/r", "on x/y"),
        ("gh pr list", "without --repo o/r"),
        (
            "cd ~/code/other && gh repo edit --visibility public",
            "outside the clone",
        ),
        ("cd ../other", "outside the clone"),
        ("cd /tmp", "outside the clone"),
        ("GH_REPO=x/y gh secret set T", "it names GH_REPO"),
        ("export GITHUB_TOKEN=t", "it names GITHUB_TOKEN"),
        ("gh api user", "not under repos/o/r"),
        ("gh api graphql -f query=q", "not under repos/o/r"),
        ("gh api orgs/acme/members", "not under repos/o/r"),
        ("gh api --hostname ghe.example repos/o/r", "with --hostname"),
        ("gh api -f a=b", "exactly one path"),
        ("gh api repos/o/r orgs/x", "exactly one path"),
        ("gh api repos/$REPO", "cannot be checked"),
        ("gh api -f x=$HOME repos/o/r", "cannot be checked"),
        ("true; gh api `cat p`", "cannot be checked"),
        ("echo x | /usr/local/bin/gh api user", "not under repos/o/r"),
        ("\\gh api user", "not under repos/o/r"),
        ("gh repo delete x/y --yes", "gh repo, which"),
        ("sudo -u root gh repo delete x/y --yes", "gh repo, which"),
        ("env -i gh api -X DELETE repos/x/y", "not under repos/o/r"),
        ("time gh api -X DELETE repos/x/y", "not under repos/o/r"),
        ("{ gh repo delete x/y --yes; }", "gh repo, which"),
        ("! gh repo delete x/y --yes", "gh repo, which"),
        (
            "if true; then gh repo delete x/y --yes; fi",
            "gh repo, which",
        ),
        ("echo `gh repo delete x/y --yes`", "cannot be checked"),
        (
            "sh -c 'gh repo delete x/y --yes'",
            "whose input cannot be checked",
        ),
        (
            "eval 'gh api -X DELETE repos/x/y'",
            "whose input cannot be checked",
        ),
        ("sudo -u git gh repo delete x/y --yes", "gh repo, which"),
        ("env -u cd gh repo delete x/y --yes", "gh repo, which"),
        ("{gh,repo,delete,x/y,--yes}", "cannot be checked"),
        (
            "/opt/homebrew/bin/g[h] repo delete x/y --yes",
            "cannot be checked",
        ),
        ("read GIT_DIR", "it names GIT_DIR"),
        ("pushd ~/other", "outside the clone"),
        (
            "printf 'g%s repo delete x/y' h | sh",
            "whose input cannot be checked",
        ),
        ("git -C /Users/me/other push --force", "outside the clone"),
        ("git --git-dir=../other/.git push", "outside the clone"),
        ("GIT_DIR=/tmp/x/.git git push", "it names GIT_DIR"),
        (
            "GIT_CONFIG_COUNT=0 git commit -m x",
            "it names GIT_CONFIG_COUNT",
        ),
        (
            "git push https://github.com/o/r/../../x/y.git",
            "may lead elsewhere",
        ),
        ("gh api -X POST repos/o/r/forks", "makes another repository"),
        (
            "gh api -X POST repos/o/r/generate",
            "makes another repository",
        ),
        ("gh extension install x/y", "gh extension, which"),
        ("gh alias set z 'api orgs/acme/members'", "it runs alias"),
        ("gh auth token", "gh auth, which"),
    ];

    #[test]
    fn commands_that_may_reach_another_repository_are_refused() {
        for &(command, why) in REFUSED {
            let found = foreign_command(command, "o/r");
            assert!(
                found.as_deref().is_some_and(|f| f.contains(why)),
                "{command}: {found:?}"
            );
        }
    }

    #[test]
    fn only_gh_calls_without_a_pull_request_are_a_settings_fix() {
        let fix = |commands: &[&str]| {
            settings_only(&commands.iter().map(|&c| c.to_owned()).collect::<Vec<_>>())
        };
        assert!(fix(&["gh api -X PUT repos/o/r/vulnerability-alerts"]));
        assert!(fix(&["gh api repos/o/r -f a=b"]));
        assert!(
            !fix(&["sudo -E gh api repos/o/r/x"]),
            "only a command that is gh itself"
        );
        assert!(!fix(&["python fix.py gh secret set T -R o/r"]));
        assert!(
            !fix(&["./gh secret set T -R o/r"]),
            "a gh in the clone is a script"
        );
        assert!(fix(&[
            "gh secret delete T -R o/r",
            "gh workflow disable ci.yml -R o/r"
        ]));
        assert!(!fix(&[]), "a fix done by its steps changes files");
        assert!(!fix(&["npm install lodash@4.17.21"]));
        assert!(!fix(&["gh api repos/o/r && npm install x"]), "two parts");
        assert!(
            !fix(&["gh pr create -R o/r"]),
            "a pull request is a change to files"
        );
    }

    proptest::proptest! {
        /// Whatever wrapper or shell keyword comes first, a `gh` that deletes another
        /// repository is found.
        #[test]
        fn no_prefix_hides_a_checked_program(
            prefix in proptest::collection::vec(
                proptest::sample::select(vec![
                    "sudo", "-u", "root", "env", "-i", "time", "nohup", "{", "!", "if", "then",
                    "exec", "command", "nice", "-n", "5", "A=b", "git", "curl",
                ]),
                0..6,
            )
        ) {
            let command = format!("{} gh repo delete x/y --yes", prefix.join(" "));
            let why = foreign_command(&command, "o/r");
            proptest::prop_assert!(
                why.as_deref().is_some_and(|why| why.contains("gh repo, which")),
                "{}: {:?}", command, why
            );
        }

        /// Whatever comes before it, a `.` that sources a file is refused.
        #[test]
        fn no_prefix_hides_a_sourced_file(
            prefix in proptest::collection::vec(
                proptest::sample::select(vec![
                    "{", "!", "if", "command", "-p", "time", "2>/dev/null", "<", "/dev/stdin",
                    "coproc", "A=b", "builtin",
                ]),
                0..6,
            )
        ) {
            let command = format!("printf x | {} . /dev/stdin", prefix.join(" "));
            let why = foreign_command(&command, "o/r");
            proptest::prop_assert!(
                why.as_deref().is_some_and(|why| why.contains("it runs .")),
                "{}: {:?}", command, why
            );
        }
    }

    #[test]
    fn commands_split_into_words_and_parts_as_a_shell_splits_them() {
        let parts = shell_parts("a 'b c'\"d\"\\ e; f|g&&h (i)\nj \"k\\\"l\" 'm\\n'");
        let parts: Vec<Vec<&str>> = parts
            .iter()
            .map(|p| p.iter().map(String::as_str).collect())
            .collect();
        assert_eq!(
            parts,
            [
                vec!["a", "b cd e"],
                vec!["f"],
                vec!["g"],
                vec!["h"],
                vec!["i"],
                vec!["j", "k\"l", "m\\n"]
            ]
        );
        assert_eq!(
            shell_parts("''"),
            [vec![String::new()]],
            "an empty word is a word"
        );
        assert_eq!(shell_parts(" ; "), Vec::<Vec<String>>::new());
    }

    /// A fake `gh` in `dir` answering each API path, its last argument, from `answers`.
    fn fake_gh(dir: &std::path::Path, answers: &[(&str, &str)]) -> String {
        let mut script = "#!/bin/sh\nfor last; do :; done\ncase \"$last\" in\n".to_owned();
        for (path, answer) in answers {
            script.push_str(&format!("  {path}) echo '{answer}' ;;\n"));
        }
        script.push_str("  *) echo \"no $last\" >&2; exit 1 ;;\nesac\n");
        let gh = dir.join("gh");
        fs::write(&gh, script).unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o755)).unwrap();
        gh.to_str().unwrap().to_owned()
    }

    const META: (&str, &str) = ("repos/o/r", r#"{"default_branch": "main"}"#);
    const HEAD: (&str, &str) = (
        "repos/o/r/git/ref/heads/main",
        r#"{"object": {"sha": "abc1234ff"}}"#,
    );

    fn pull(state: &str, head: &str, head_repo: &str, base: &str) -> String {
        format!(
            r#"{{"state": "{state}",
             "head": {{"ref": "{head}", "repo": {{"full_name": "{head_repo}"}}}},
             "base": {{"ref": "{base}", "repo": {{"full_name": "O/R"}}}}}}"#
        )
    }

    #[test]
    fn a_pull_request_must_be_open_from_the_run_s_branch_into_the_default_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let url = Some("https://github.com/o/r/pull/7");
        let check = |pr: &str| {
            let gh = fake_gh(tmp.path(), &[META, HEAD, ("repos/o/r/pulls/7", pr)]);
            let watch = Watch::start(&gh, "o/r").unwrap();
            watch.check(&gh, "vigil/fix-k-1", url)
        };
        assert_eq!(check(&pull("open", "vigil/fix-k-1", "O/r", "main")), Ok(()));
        for (pr, why) in [
            (
                pull("closed", "vigil/fix-k-1", "o/r", "main"),
                "is closed, not open",
            ),
            (
                pull("open", "vigil/fix-k-0", "o/r", "main"),
                "is from vigil/fix-k-0",
            ),
            (pull("open", "vigil/fix-k-1", "x/r", "main"), "is from x/r"),
            (
                pull("open", "vigil/fix-k-1", "o/r", "dev"),
                "into O/R:dev, not o/r:main",
            ),
        ] {
            let err = check(&pr).unwrap_err();
            assert!(err.contains(why), "{err}");
            assert!(err.starts_with("the pull request https://github.com/o/r/pull/7"));
        }

        let gh = fake_gh(tmp.path(), &[META, HEAD]);
        let watch = Watch::start(&gh, "o/r").unwrap();
        assert_eq!(
            watch.check(&gh, "b", None),
            Ok(()),
            "a setting fix has no pull request"
        );
        let err = watch.check(&gh, "b", url).unwrap_err();
        assert!(err.contains("no repos/o/r/pulls/7"), "{err}");
    }

    #[test]
    fn a_default_branch_that_moved_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = fake_gh(tmp.path(), &[META, HEAD]);
        let watch = Watch::start(&gh, "o/r").unwrap();
        let moved = (
            "repos/o/r/git/ref/heads/main",
            r#"{"object": {"sha": "def5678aa"}}"#,
        );
        let gh = fake_gh(tmp.path(), &[META, moved]);
        let err = watch.check(&gh, "b", None).unwrap_err();
        assert_eq!(
            err,
            "the default branch main of o/r moved during the fix, from abc1234 to def5678; \
             check what was pushed to it"
        );

        // Another branch made the default, its old head left where it was.
        let switched = ("repos/o/r", r#"{"default_branch": "vigil/fix-k-1"}"#);
        let gh = fake_gh(tmp.path(), &[switched, HEAD]);
        let err = watch.check(&gh, "b", None).unwrap_err();
        assert!(
            err.starts_with(
                "the default branch of o/r changed during the fix, from main to vigil/fix-k-1"
            ),
            "{err}"
        );

        // A default branch with a slash in its name is read as one ref.
        let release = ("repos/o/r", r#"{"default_branch": "release/1.0"}"#);
        let release_head = (
            "repos/o/r/git/ref/heads/release/1.0",
            r#"{"object": {"sha": "abc1234ff"}}"#,
        );
        let gh = fake_gh(tmp.path(), &[release, release_head]);
        assert!(Watch::start(&gh, "o/r").is_ok());

        let odd = ("repos/o/r", r#"{"default_branch": "a b"}"#);
        let err = Watch::start(&fake_gh(tmp.path(), &[odd]), "o/r").unwrap_err();
        assert!(err.contains("a name the app does not read"), "{err}");
        let err = Watch::start(&fake_gh(tmp.path(), &[]), "o/r").unwrap_err();
        assert!(err.contains("no repos/o/r"), "{err}");
    }
}
