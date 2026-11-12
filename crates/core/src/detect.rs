//! What this Mac already has, for the settings to start from: the agents and tools on
//! the login shell's `PATH`, the models the agents list, the `gh` login and its repositories,
//! the hosts in `~/.ssh/config`, the usual project folders, and whether an NVD key is in the
//! Keychain.
//!
//! Nothing here changes anything; every part that cannot be read comes back empty, since a
//! settings view that fails to open over one missing tool helps no one.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::panic;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use serde::Deserialize;

use crate::agent::AgentKind;
use crate::cancel::Cancel;
use crate::config::ModelName;
use crate::inventory::command;

/// The agents a sweep can run, in the order the settings list them.
const AGENTS: [AgentKind; 5] = [
    AgentKind::Claude,
    AgentKind::Grok,
    AgentKind::Gemini,
    AgentKind::Opencode,
    AgentKind::Codex,
];

/// The tools a Mac sweep reads, plus `gh` and `ssh`, which repository and server sweeps use:
/// each program and its name as people know it.
const TOOLS: [(&str, &str); 10] = [
    ("brew", "Homebrew"),
    ("npm", "npm"),
    ("node", "Node"),
    ("uv", "uv"),
    ("pipx", "pipx"),
    ("cargo", "cargo"),
    ("rustup", "rustup"),
    ("python3", "Python"),
    ("gh", "gh"),
    ("ssh", "ssh"),
];

/// Folders people keep projects in, relative to the home folder. Arbitrary: the common names
/// on macOS; a folder that does not exist is not suggested. None is inside `~/Documents`:
/// detection runs as the app starts, and looking there raises macOS's Documents privacy prompt
/// before the user has chosen anything. A project folder there is one the user picks, and
/// macOS asks when Vigil first reads it.
const PROJECT_FOLDERS: [&str; 5] = ["code", "Code", "Projects", "Developer", "src"];

/// How many of the user's repositories `gh repo list` returns. Arbitrary: enough to pick from
/// without a long wait.
const REPO_LIMIT: &str = "100";

/// How long an agent may take to list its models. Arbitrary: `opencode models` answered in
/// about a second on 2026-11-07; a list that takes longer is skipped rather than holding up
/// the settings.
const MODELS_TIMEOUT: Duration = Duration::from_secs(10);

const PATH_MARK: &str = "__vigil_path__";
const BIN_MARK: &str = "__vigil_bin__";
const END_MARK: &str = "__vigil_end__";

/// What the settings start from.
#[derive(Debug)]
pub struct Detected {
    /// Each agent, and where the login shell finds it.
    pub agents: Vec<(AgentKind, Option<PathBuf>)>,
    /// The models each found agent lists, for the agents whose CLI lists them (Grok and
    /// opencode); opencode's are `provider/model`.
    pub models: Vec<(AgentKind, Vec<String>)>,
    /// Each tool, and where the login shell finds it.
    pub tools: Vec<Tool>,
    /// The `gh` login, or `None` when gh is missing or not logged in.
    pub gh_login: Option<String>,
    /// The user's repositories, as gh lists them (newest push first); empty without a gh login.
    pub repos: Vec<RepoInfo>,
    /// The concrete hosts in `~/.ssh/config`.
    pub ssh_hosts: Vec<SshHost>,
    /// Usual project folders that exist.
    pub folders: Vec<PathBuf>,
    /// Whether an NVD API key is in the Keychain.
    pub nvd_key: bool,
}

/// A tool and where it was found.
#[derive(Debug)]
pub struct Tool {
    /// Its program (`brew`).
    pub program: &'static str,
    /// Its name as people know it (`Homebrew`).
    pub name: &'static str,
    /// Its path, or `None` when the login shell does not find it.
    pub path: Option<PathBuf>,
}

/// One of the user's repositories.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInfo {
    /// `owner/name`.
    pub name_with_owner: String,
    /// Whether it is private.
    pub is_private: bool,
}

/// A host from `~/.ssh/config`.
#[derive(Debug, PartialEq, Eq)]
pub struct SshHost {
    /// The alias, as `ssh <alias>` takes it.
    pub alias: String,
    /// Its `HostName`, when the config sets one.
    pub host_name: Option<String>,
}

/// Detects what this Mac has. Takes a few seconds: it runs the login shell, `gh` twice, the
/// model lists of Grok and opencode side by side (each cut off after [`MODELS_TIMEOUT`]) and
/// the Keychain lookup.
///
/// Every tool the core runs from then on is found on the login shell's `PATH`, as in the
/// user's terminal and as the settings show it: the menu-bar app starts with macOS's minimal
/// one. When the shell gives no answer, the `PATH` in use stays.
pub fn detect(home: &Path) -> Detected {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_owned());
    detect_with(&shell, home, crate::feeds::NvdAccess::has_keychain_key)
}

/// [`detect`] with the login shell and the Keychain check given, so tests use stand-ins.
fn detect_with(shell: &str, home: &Path, nvd_key: impl FnOnce() -> bool) -> Detected {
    let answer = login_shell(shell);
    if let Some(answer) = &answer {
        command::use_search_path(answer.path.clone());
    }
    let found = |program: &str| answer.as_ref().and_then(|a| a.binary(program));
    let agents: Vec<(AgentKind, Option<PathBuf>)> =
        AGENTS.iter().map(|&a| (a, found(a.binary()))).collect();
    // Each list takes a second or more and may reach the network, so they run side by side.
    let models = thread::scope(|scope| {
        let lists: Vec<_> = agents
            .iter()
            .filter_map(|(agent, path)| Some((*agent, path.as_deref()?)))
            .map(|(agent, path)| scope.spawn(move || Some((agent, listed_models(agent, path)?))))
            .collect();
        lists
            .into_iter()
            // Listing only parses text, so a panic there is a bug to surface, not "no list".
            .filter_map(|list| list.join().unwrap_or_else(|p| panic::resume_unwind(p)))
            .collect()
    });
    let tools: Vec<Tool> = TOOLS
        .iter()
        .map(|&(program, name)| Tool {
            program,
            name,
            path: found(program),
        })
        .collect();
    let gh = tools
        .iter()
        .find(|t| t.program == "gh")
        .and_then(|t| t.path.clone());
    let gh_login = gh.as_deref().and_then(gh_login);
    let repos = match (&gh, &gh_login) {
        (Some(gh), Some(_)) => gh_repos(gh),
        _ => Vec::new(),
    };
    let ssh_hosts = fs::read_to_string(home.join(".ssh/config"))
        .map_or_else(|_| Vec::new(), |text| ssh_hosts(&text));
    let folders = project_folders(home);
    Detected {
        agents,
        models,
        tools,
        gh_login,
        repos,
        ssh_hosts,
        folders,
        nvd_key: nvd_key(),
    }
}

/// The models `agent` at `binary` lists, or `None` when its CLI has no list (Claude Code takes
/// aliases, Gemini CLI none, and codex's `debug models` is experimental) or the list fails or
/// takes longer than [`MODELS_TIMEOUT`].
fn listed_models(agent: AgentKind, binary: &Path) -> Option<Vec<String>> {
    let read: fn(&str) -> Vec<String> = match agent {
        AgentKind::Grok => grok_models,
        AgentKind::Opencode => opencode_models,
        AgentKind::Claude | AgentKind::Codex | AgentKind::Gemini => return None,
    };
    let out =
        command::run_with_input(binary.to_str()?, &["models"], b"", MODELS_TIMEOUT).ok()??;
    out.success.then(|| read(&out.stdout))
}

/// Reads `grok models`, which lists one model per line after "Available models:", marked `*`
/// for the default and `-` for the rest (checked with grok on 2026-11-07).
fn grok_models(out: &str) -> Vec<String> {
    out.lines()
        .skip_while(|l| !l.trim_start().starts_with("Available models"))
        .filter_map(|l| {
            let rest = l.trim().strip_prefix(['*', '-'])?;
            let name = rest.split_whitespace().next()?;
            name.parse::<ModelName>().is_ok().then(|| name.to_owned())
        })
        .collect()
}

/// Reads `opencode models`, which prints one `provider/model` per line. A provider is a plain
/// word, so a URL or a warning that happens to hold a `/` is not taken for a model.
fn opencode_models(out: &str) -> Vec<String> {
    out.lines()
        .map(str::trim)
        .filter(|l| {
            l.split_once('/').is_some_and(|(provider, model)| {
                !provider.is_empty()
                    && !model.is_empty()
                    && provider
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            }) && l.parse::<ModelName>().is_ok()
        })
        .map(str::to_owned)
        .collect()
}

/// The usual project folders that exist, each once. The default macOS file system ignores
/// case, so `code` and `Code` can be one folder; folders are told apart by device and inode.
fn project_folders(home: &Path) -> Vec<PathBuf> {
    let mut seen = Vec::new();
    let mut folders = Vec::new();
    for folder in PROJECT_FOLDERS.iter().map(|f| home.join(f)) {
        let Ok(meta) = fs::metadata(&folder) else {
            continue;
        };
        let id = (meta.dev(), meta.ino());
        if meta.is_dir() && !seen.contains(&id) {
            seen.push(id);
            folders.push(folder);
        }
    }
    folders
}

/// The login shell's answer: its `PATH`, and each program it found.
#[derive(Debug)]
struct Answer {
    path: OsString,
    binaries: Vec<(String, PathBuf)>,
}

impl Answer {
    fn binary(&self, name: &str) -> Option<PathBuf> {
        self.binaries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.clone())
    }
}

fn login_shell(shell: &str) -> Option<Answer> {
    let names: Vec<&str> = AGENTS
        .iter()
        .map(|a| a.binary())
        .chain(TOOLS.iter().map(|&(program, _)| program))
        .collect();
    // The names are this module's constants, so they need no quoting.
    let script = format!(
        "printf '%s\\n' {PATH_MARK} \"$PATH\"; for b in {}; do printf '{BIN_MARK}%s\\t%s\\n' \
         \"$b\" \"$(command -v \"$b\")\"; done; printf '%s\\n' {END_MARK}",
        names.join(" ")
    );
    let output = command::run_any_status(shell, &["-lc", &script], &Cancel::new()).ok()??;
    parse_answer(&output.stdout)
}

/// Reads the marked lines of the login shell's answer. Lines before the `PATH` mark (startup
/// files that print) are ignored; a program found as anything but an absolute path (an alias,
/// a function) counts as not found.
fn parse_answer(stdout: &str) -> Option<Answer> {
    let mut lines = stdout.lines().skip_while(|l| l.trim() != PATH_MARK).skip(1);
    let path = OsString::from(lines.next()?);
    let mut binaries = Vec::new();
    for line in lines {
        if line.trim() == END_MARK {
            return Some(Answer { path, binaries });
        }
        let Some((name, found)) = line.strip_prefix(BIN_MARK).and_then(|l| l.split_once('\t'))
        else {
            continue;
        };
        if Path::new(found).is_absolute() {
            binaries.push((name.to_owned(), PathBuf::from(found)));
        }
    }
    None
}

fn gh_login(gh: &Path) -> Option<String> {
    let gh = gh.to_str()?;
    let login = command::run(gh, &["api", "user", "--jq", ".login"], &Cancel::new()).ok()??;
    plain_login(&login)
}

/// `gh`'s answer as a GitHub login, which is letters, digits and dashes; anything else (an
/// error page, a prompt) is no login.
fn plain_login(answer: &str) -> Option<String> {
    let login = answer.trim();
    let plain = !login.is_empty()
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    plain.then(|| login.to_owned())
}

fn gh_repos(gh: &Path) -> Vec<RepoInfo> {
    let Some(gh) = gh.to_str() else {
        return Vec::new();
    };
    let fields = "nameWithOwner,isPrivate";
    let args = ["repo", "list", "--limit", REPO_LIMIT, "--json", fields];
    command::run(gh, &args, &Cancel::new())
        .ok()
        .flatten()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// The concrete hosts in an ssh config: each `Host` alias without a pattern character (`*`,
/// `?`, `!`), with the `HostName` of its block. `Match` blocks and `Include`d files are not
/// read; a host there can still be typed in.
fn ssh_hosts(config: &str) -> Vec<SshHost> {
    let mut hosts: Vec<SshHost> = Vec::new();
    let mut block: Vec<usize> = Vec::new();
    for line in config.lines() {
        let line = without_comment(line).trim();
        let Some((keyword, rest)) = line.split_once(|c: char| c.is_whitespace() || c == '=') else {
            continue;
        };
        let rest = rest
            .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
            .trim();
        match keyword.to_ascii_lowercase().as_str() {
            "host" => {
                block.clear();
                for alias in rest.split_whitespace() {
                    let concrete = !alias.contains(['*', '?', '!']);
                    if concrete && !hosts.iter().any(|h| h.alias == alias) {
                        block.push(hosts.len());
                        hosts.push(SshHost {
                            alias: alias.to_owned(),
                            host_name: None,
                        });
                    }
                }
            }
            "match" => block.clear(),
            "hostname" if !rest.is_empty() => {
                for &i in &block {
                    hosts[i].host_name.get_or_insert_with(|| rest.to_owned());
                }
            }
            _ => {}
        }
    }
    hosts
}

/// `line` up to a comment: a word starting with `#` and the rest of the line, as OpenSSH reads
/// it, so `Host web # prod` names only `web`.
fn without_comment(line: &str) -> &str {
    let mut at_word_start = true;
    for (i, c) in line.char_indices() {
        if c == '#' && at_word_start {
            return &line[..i];
        }
        at_word_start = c.is_whitespace() || c == '=';
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn models_are_listed_by_the_agents_that_list_them() {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str, body: &str| {
            let path = dir.path().join(name);
            script(&path, body);
            path
        };
        let grok = at(
            "grok",
            r#"[ "$1" = models ] && printf 'Available models:\n  * grok-4.7 (default)\n'"#,
        );
        let failing = at("failing", "echo 'Available models:'; echo '- x'; exit 1");
        assert_eq!(
            listed_models(AgentKind::Grok, &grok),
            Some(vec!["grok-4.7".to_owned()])
        );
        assert_eq!(listed_models(AgentKind::Grok, &failing), None);
        assert_eq!(listed_models(AgentKind::Claude, &grok), None);
        assert_eq!(
            listed_models(AgentKind::Opencode, &at("oc", "echo ollama/qwen3")),
            Some(vec!["ollama/qwen3".to_owned()])
        );
    }

    #[test]
    fn grok_and_opencode_model_lists_are_read_line_by_line() {
        let grok = "You are logged in with grok.com.\n\nDefault model: grok-4.7\n\n\
                    Available models:\n  * grok-4.7 (default)\n  - grok-4.6\n  - $(id)\n";
        assert_eq!(grok_models(grok), ["grok-4.7", "grok-4.6"]);
        assert_eq!(grok_models("- before the list\n"), Vec::<String>::new());
        let opencode = "opencode/big-pickle\nollama/gemma4:e4b\n\nWarning: x\n-a/b\n\
                        https://opencode.ai/x\n/lone\nempty/\n";
        assert_eq!(
            opencode_models(opencode),
            ["opencode/big-pickle", "ollama/gemma4:e4b"]
        );
    }

    #[test]
    fn the_login_shell_answer_is_read_between_its_marks() {
        let stdout = format!(
            "Welcome to zsh\n{PATH_MARK}\n/opt/homebrew/bin:/usr/bin\n\
             {BIN_MARK}claude\t/Users/me/.local/bin/claude\n\
             {BIN_MARK}codex\t\n\
             {BIN_MARK}ll\tll: aliased to ls -l\n\
             {END_MARK}\n"
        );
        let answer = parse_answer(&stdout).unwrap();
        assert_eq!(answer.path, OsString::from("/opt/homebrew/bin:/usr/bin"));
        assert_eq!(
            answer.binary("claude"),
            Some(PathBuf::from("/Users/me/.local/bin/claude"))
        );
        assert_eq!(answer.binary("codex"), None, "not found");
        assert_eq!(answer.binary("ll"), None, "an alias is not a program");
        assert!(
            parse_answer(&format!("{PATH_MARK}\n/usr/bin\n")).is_none(),
            "no end mark"
        );
        assert!(parse_answer("nothing marked\n").is_none());
    }

    /// Writes an executable shell script.
    fn script(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn detection_reads_the_login_shell_gh_ssh_and_folders() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let home = tmp.path().join("home");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(home.join("code")).unwrap();
        fs::write(home.join("Projects"), "").unwrap();
        fs::write(home.join(".ssh/config"), "Host web\n  HostName 10.0.0.5\n").unwrap();
        let gh = bin.join("gh");
        script(
            &gh,
            "case \"$1\" in\n\
             api) echo me-1 ;;\n\
             repo) echo '[{\"nameWithOwner\":\"me-1/app\",\"isPrivate\":true}]' ;;\n\
             esac\n",
        );
        // The answer's PATH keeps /bin and /usr/bin: detection makes it the process's search
        // path, and other tests running at the same time run tools by name.
        let shell = bin.join("shell");
        script(
            &shell,
            &format!(
                "printf '%s\\n' {PATH_MARK} '/bin:/usr/bin'\n\
                 printf '{BIN_MARK}claude\\t/opt/claude\\n{BIN_MARK}gh\\t{}\\n'\n\
                 printf '%s\\n' {END_MARK}\n",
                gh.display()
            ),
        );
        let found = detect_with(shell.to_str().unwrap(), &home, || true);
        assert_eq!(
            found.agents[0],
            (AgentKind::Claude, Some(PathBuf::from("/opt/claude")))
        );
        assert_eq!(found.agents[1], (AgentKind::Grok, None));
        let gh_tool = found.tools.iter().find(|t| t.program == "gh").unwrap();
        assert_eq!(gh_tool.path.as_deref(), Some(gh.as_path()));
        assert_eq!(found.gh_login.as_deref(), Some("me-1"));
        assert_eq!(found.repos.len(), 1);
        assert_eq!(found.repos[0].name_with_owner, "me-1/app");
        assert!(found.repos[0].is_private);
        assert_eq!(found.ssh_hosts[0].alias, "web");
        assert_eq!(
            found.folders,
            [home.join("code")],
            "Projects is a file, and Code is code on a disk that ignores case"
        );
        assert!(found.nvd_key);

        let nothing = detect_with("/nonexistent/shell", &tmp.path().join("none"), || false);
        assert!(nothing.agents.iter().all(|(_, path)| path.is_none()));
        assert_eq!(nothing.gh_login, None);
        assert!(nothing.repos.is_empty() && nothing.ssh_hosts.is_empty());
        assert!(!nothing.nvd_key);
    }

    #[test]
    fn without_a_gh_login_no_repositories_are_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = tmp.path().join("gh");
        script(
            &gh,
            "case \"$1\" in\n\
             api) echo 'not logged in: run gh auth login' ;;\n\
             *) echo '[{\"nameWithOwner\":\"o/r\",\"isPrivate\":false}]' ;;\n\
             esac\n",
        );
        let shell = tmp.path().join("shell");
        script(
            &shell,
            &format!(
                "printf '%s\\n' {PATH_MARK} '/bin:/usr/bin'\n\
                 printf '{BIN_MARK}gh\\t{}\\n%s\\n' {END_MARK}\n",
                gh.display()
            ),
        );
        let found = detect_with(shell.to_str().unwrap(), tmp.path(), || false);
        assert_eq!(found.gh_login, None);
        assert!(found.repos.is_empty());
    }

    #[test]
    fn a_login_is_letters_digits_and_dashes() {
        assert_eq!(plain_login("  me-1\n").as_deref(), Some("me-1"));
        assert_eq!(plain_login(""), None);
        assert_eq!(plain_login("\n"), None);
        assert_eq!(plain_login("not logged in"), None);
        assert_eq!(plain_login("a_b"), None);
    }

    #[test]
    fn ssh_hosts_are_the_concrete_aliases_with_their_host_names() {
        let config = "\
Include ~/.orbstack/ssh/config
Host *
  ServerAliveInterval 30
Host web web-alias
  HostName 10.0.0.5
  User ops
host db-1
  hostname=db.internal
Host spaced
  HostName = 10.0.0.8
Host *.corp !gate
  User me
Match host staging
  HostName ignored
Host web
  HostName shadowed
# Host commented-out
Host db-2 # the new database
  HostName 10.0.0.7 # behind the VPN
Host db-3
  HostName=#none
Match host db-3
  HostName 10.9.9.9
";
        assert_eq!(
            ssh_hosts(config),
            [
                SshHost {
                    alias: "web".to_owned(),
                    host_name: Some("10.0.0.5".to_owned())
                },
                SshHost {
                    alias: "web-alias".to_owned(),
                    host_name: Some("10.0.0.5".to_owned())
                },
                SshHost {
                    alias: "db-1".to_owned(),
                    host_name: Some("db.internal".to_owned())
                },
                SshHost {
                    alias: "spaced".to_owned(),
                    host_name: Some("10.0.0.8".to_owned())
                },
                SshHost {
                    alias: "db-2".to_owned(),
                    host_name: Some("10.0.0.7".to_owned())
                },
                SshHost {
                    alias: "db-3".to_owned(),
                    host_name: None
                },
            ]
        );
    }
}
