//! What the app checks itself around a repository fix, rather than leave to the prompt.
//!
//! The fix agent runs with full access, so these are checks around it, not a sandbox:
//!
//! - Before the user is asked, [`foreign_command`] refuses a confirmed command that addresses
//!   another repository through `gh` or a GitHub URL.
//! - The agent runs with [`ENV`]: git hooks and package-manager lifecycle scripts off, so
//!   cloning the repository, installing its packages or committing runs none of its code.
//! - Before the agent runs, [`Watch::start`] records the default branch's head; after it,
//!   [`Watch::check`] fails when that head moved, or when the pull request the agent reported
//!   is not open from the run's branch into the default branch of this repository.

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
/// Conservative, not a shell parser: a command that might reach another repository is refused,
/// and a fix whose commands this refuses wrongly is left to the user to run by hand. The rules:
///
/// - every `repos/<owner>/<name>` and `github.com/<owner>/<name>` in it names `repo`;
/// - no `GH_REPO` or `GH_HOST` is set in it;
/// - in each `gh` invocation (from a `gh` word to the next `;`, `&`, `|`, parenthesis or line
///   break), no word holds `$` or a backquote, whose expansion cannot be checked; `-R` and
///   `--repo` name `repo`; `gh api` calls one path under `repos/<repo>` on github.com (no
///   `--hostname`, so no `graphql`, `user` or `orgs/...`); and `gh repo` subcommands name no
///   other `owner/name`.
///
/// Owner and name compare case-insensitively, as GitHub does.
pub(super) fn foreign_command(command: &str, repo: &str) -> Option<String> {
    let words: Vec<&str> = command.split_whitespace().map(unquote).collect();
    for word in &words {
        for marker in ["repos/", "github.com/"] {
            if let Some(other) = names_other(word, marker, repo) {
                return Some(format!("it names {marker}{other}"));
            }
        }
        if word.starts_with("GH_REPO=") || word.starts_with("GH_HOST=") {
            return Some(format!(
                "it sets {}",
                word.split_once('=').map_or(*word, |(name, _)| name)
            ));
        }
    }
    command
        .split([';', '&', '|', '(', ')', '\n'])
        .find_map(|part| foreign_gh(part, repo))
}

/// Why the `gh` invocation in `part`, one piece of a command between separators, may address
/// another repository.
fn foreign_gh(part: &str, repo: &str) -> Option<String> {
    let words: Vec<&str> = part.split_whitespace().map(unquote).collect();
    let at = words
        .iter()
        .position(|w| *w == "gh" || w.ends_with("/gh"))?;
    let args = &words[at + 1..];
    if let Some(word) = args.iter().find(|w| w.contains(['$', '`'])) {
        return Some(format!("`{word}` cannot be checked before it runs"));
    }
    for (i, arg) in args.iter().enumerate() {
        let value = match *arg {
            "-R" | "--repo" => args.get(i + 1).copied().unwrap_or_default(),
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
    }
    match args.first().copied() {
        Some("api") => foreign_api(&args[1..], repo),
        Some("repo") => args
            .iter()
            .skip(2)
            .find(|a| !a.starts_with('-') && a.contains('/') && !a.eq_ignore_ascii_case(repo))
            .map(|other| format!("it runs gh repo on {other}")),
        _ => None,
    }
}

/// Why the `gh api` call with `args` may address another repository: its one path must be
/// under `repos/<repo>`, with a leading `/` allowed.
fn foreign_api(args: &[&str], repo: &str) -> Option<String> {
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
        if word.starts_with("--hostname") {
            return Some("it runs gh api on another host".to_owned());
        }
        if VALUED.contains(word) {
            words.next();
        } else if !word.starts_with('-') {
            paths.push(*word);
        }
    }
    let prefix = format!("repos/{repo}");
    match paths.as_slice() {
        [path] => {
            let path = path.strip_prefix('/').unwrap_or(path);
            let under = path
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
                && matches!(path.as_bytes().get(prefix.len()), None | Some(b'/' | b'?'));
            (!under).then(|| format!("it runs gh api on {path}, not under {prefix}"))
        }
        _ => Some("it runs gh api without exactly one path".to_owned()),
    }
}

/// `word` without the quotes a shell would remove around it.
fn unquote(word: &str) -> &str {
    word.trim_matches(['\'', '"'])
}

/// The `owner/name` after each `marker` in `word` that is not `repo`, if any. An API URL,
/// `api.github.com/repos/...`, is left to the `repos/` marker.
fn names_other<'w>(word: &'w str, marker: &str, repo: &str) -> Option<&'w str> {
    word.match_indices(marker).find_map(|(at, _)| {
        let rest = &word[at + marker.len()..];
        if marker == "github.com/" && rest.starts_with("repos/") {
            return None;
        }
        let end = rest
            .char_indices()
            .filter(|&(_, c)| c == '/')
            .nth(1)
            .map_or(rest.len(), |(i, _)| i);
        let named = rest[..end].trim_end_matches(".git");
        let named = named.split(['?', '#']).next().unwrap_or(named);
        (!named.eq_ignore_ascii_case(repo)).then_some(named)
    })
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
        let meta = api(gh, &format!("repos/{repo}"))?;
        let default_branch = meta["default_branch"]
            .as_str()
            .ok_or_else(|| format!("GitHub named no default branch of {repo}"))?
            .to_owned();
        let head = head(gh, repo, &default_branch)?;
        Ok(Self {
            repo: repo.to_owned(),
            default_branch,
            head,
        })
    }

    /// Checks the repository after the fix: its default branch still has the head it had, and
    /// `pull_request`, when the agent reported one, is open from `branch` of this repository
    /// into the default branch.
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

/// The commit at the head of `branch` of `repo`.
fn head(gh: &str, repo: &str, branch: &str) -> Result<String, String> {
    // A branch name goes into the API path as it is, so only names that need no escaping are
    // read; a default branch named otherwise is rare enough to refuse.
    if !branch
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(format!(
            "the default branch of {repo} has a name the app does not read: {}",
            sweep::plain(branch)
        ));
    }
    let answer = api(gh, &format!("repos/{repo}/branches/{branch}"))?;
    answer
        .pointer("/commit/sha")
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
            "gh secret delete TOKEN -R o/r",
            "gh workflow disable ci.yml --repo=o/r",
            "gh repo edit o/r --enable-wiki=false",
            "git clone https://github.com/o/r.git && npm install lodash@4.17.21",
            "npm install lodash@4.17.21",
            "curl https://api.github.com/repos/o/r/hooks",
            "gh pr list",
        ] {
            assert_eq!(foreign_command(command, "o/r"), None, "{command}");
        }
    }

    #[test]
    fn commands_that_may_reach_another_repository_are_refused() {
        for (command, why) in [
            ("gh api repos/o/other/hooks", "repos/o/other"),
            ("gh api -X DELETE repos/o/r2", "repos/o/r2"),
            ("curl https://api.github.com/repos/x/y", "repos/x/y"),
            ("git push https://github.com/x/y.git", "github.com/x/y"),
            (
                "gh pr merge https://github.com/x/y/pull/1",
                "github.com/x/y",
            ),
            ("gh secret set T -R x/y", "--repo x/y"),
            ("gh secret set T --repo x/y", "--repo x/y"),
            ("gh secret set T --repo=x/y", "--repo x/y"),
            ("gh secret set T -Rx/y", "--repo x/y"),
            ("GH_REPO=x/y gh secret set T", "GH_REPO"),
            ("gh api user", "not under repos/o/r"),
            ("gh api graphql -f query=q", "not under repos/o/r"),
            ("gh api orgs/acme/members", "not under repos/o/r"),
            ("gh api repos/o/rx", "repos/o/rx"),
            ("gh api /repos/o/r.x/hooks", "repos/o/r.x"),
            ("gh api --hostname ghe.example repos/o/r", "another host"),
            ("gh api -f a=b", "exactly one path"),
            ("gh api repos/o/r orgs/x", "exactly one path"),
            ("gh api repos/$REPO", "repos/$REPO"),
            ("gh api -f x=$HOME repos/o/r", "cannot be checked"),
            ("true; gh api `cat p`", "cannot be checked"),
            ("echo x | /usr/local/bin/gh api user", "not under repos/o/r"),
            ("gh repo delete x/y --yes", "gh repo on x/y"),
        ] {
            let found = foreign_command(command, "o/r");
            assert!(
                found.as_deref().is_some_and(|f| f.contains(why)),
                "{command}: {found:?}"
            );
        }
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
        "repos/o/r/branches/main",
        r#"{"commit": {"sha": "abc1234ff"}}"#,
    );

    fn pull(state: &str, head: &str, head_repo: &str, base: &str) -> String {
        format!(
            r#"{{"state": "{state}", "head": {{"ref": "{head}", "repo": {{"full_name": "{head_repo}"}}}},
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
            "repos/o/r/branches/main",
            r#"{"commit": {"sha": "def5678aa"}}"#,
        );
        let gh = fake_gh(tmp.path(), &[META, moved]);
        let err = watch.check(&gh, "b", None).unwrap_err();
        assert_eq!(
            err,
            "the default branch main of o/r moved during the fix, from abc1234 to def5678; \
             check what was pushed to it"
        );

        let odd = ("repos/o/r", r#"{"default_branch": "a b"}"#);
        let err = Watch::start(&fake_gh(tmp.path(), &[odd]), "o/r").unwrap_err();
        assert!(err.contains("a name the app does not read"), "{err}");
        let err = Watch::start(&fake_gh(tmp.path(), &[]), "o/r").unwrap_err();
        assert!(err.contains("no repos/o/r"), "{err}");
    }
}
