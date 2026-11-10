//! Fixing one finding or issue after the user confirms it (spec, "Fix flow").
//!
//! The fix the sweep's agent wrote is the plan. [`plan_fix`] reads it from the target's newest
//! report and checks everything that can be checked before the user is asked: the finding is
//! still current and not dismissed, its fix passes the sweep's text checks, the target is
//! still configured, and the agent is installed. The user confirms what [`FixPlan`] shows, and
//! [`run_fix`] has the agent carry it out with full access in its own folder,
//! `fixes/<start time>-<key>/`. Every run that starts is appended to `state/fixes.jsonl`,
//! whatever its outcome. A fix holds the sweeps lock, so no sweep or other fix runs while it
//! changes the target.
//!
//! The agent gets the fix and what it is about (advisories or subject, the component, the
//! severity), not the sweep's evidence and explanation: those were written from advisory text
//! and target files, which are untrusted, and the user confirmed the fix, not them.

use std::fmt;
use std::fs;
use std::io;
use std::io::Read as _;
use std::io::Seek as _;
use std::io::SeekFrom;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use jiff::Timestamp;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;

use crate::agent::AgentError;
use crate::agent::AgentKind;
use crate::agent::Located;
use crate::agent::PROMPT_LINE;
use crate::cancel::Cancel;
use crate::config::Config;
use crate::findings;
use crate::findings::Fix;
use crate::findings::is_forging;
use crate::lifecycle;
use crate::lifecycle::Dismissals;
use crate::lifecycle::FindingKey;
use crate::lifecycle::StateError;
use crate::paths::DataDir;
use crate::prompts;
use crate::prompts::Prompt;
use crate::server;
use crate::sweep;
use crate::sweep::Lock;
use crate::sweep::SweepError;

/// Ends the heredoc that carries a command to a server's `sh`. Quoted, so this Mac's shell
/// expands nothing in the command; a confirmed command is one line, and one that is exactly
/// this word is refused, so none can end the heredoc early.
const HEREDOC_END: &str = "VIGIL_END";

/// The JSON Schema of `result.json`, written into each fix folder for the agent.
const RESULT_SCHEMA: &str = include_str!("fix-result.schema.json");

/// The fix history's file in `state/`, written by [`append`] and read by [`runs`].
const FIXES_FILE: &str = "fixes.jsonl";

/// A checked fix, ready to show the user and, once confirmed, to run.
#[derive(Debug)]
pub struct FixPlan {
    key: FindingKey,
    /// The `report.json` it was read from.
    report: PathBuf,
    target: String,
    /// Where it runs, for the user: "this Mac", or the repository or the ssh command.
    destination: String,
    /// When the sweep that found it started.
    found: Timestamp,
    /// The finding's one-line title, for the fix history.
    title: String,
    fix: Fix,
    /// What the agent is given in `fix.json`.
    brief: Value,
    /// The prompt's "Where to work" section.
    access: String,
    agent: AgentKind,
    located: Located,
}

impl FixPlan {
    /// The target it fixes: `mac`, `github:owner/name` or `server:name`.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Where the agent will work, as the user should read it before confirming.
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// When the sweep that found it started.
    pub fn found(&self) -> Timestamp {
        self.found
    }

    /// The fix the sweep's agent wrote, which the user confirms.
    pub fn fix(&self) -> &Fix {
        &self.fix
    }

    /// The agent that will run it.
    pub fn agent(&self) -> AgentKind {
        self.agent
    }
}

/// Reads the fix for `key` from the newest report of its target and checks it can run.
///
/// # Errors
///
/// Fails when no report has `key`, a newer sweep of its target no longer has it, it is
/// dismissed, its fix is malformed, its target is no longer configured, or no agent is
/// configured or found.
pub fn plan_fix(data_dir: &DataDir, config: &Config, key: FindingKey) -> Result<FixPlan, FixError> {
    let path = current_report(data_dir, key)?;
    let read_err = |source| FixError::Read {
        path: path.clone(),
        source,
    };
    let invalid = |e: serde_json::Error| read_err(io::Error::new(io::ErrorKind::InvalidData, e));
    let report: Saved =
        serde_json::from_str(&fs::read_to_string(&path).map_err(read_err)?).map_err(invalid)?;
    let entry = report
        .findings
        .into_iter()
        .chain(report.issues)
        .find(|e| e["key"] == key.to_string())
        .ok_or(StateError::UnknownKey { key })?;
    let fix = Fix::deserialize(&entry["fix"]).map_err(invalid)?;
    let mut problems = Vec::new();
    findings::check_fix("fix", &fix, &mut problems);
    if fix.commands.iter().any(|c| c.trim() == HEREDOC_END) {
        problems.push(format!("fix.commands: {HEREDOC_END} is reserved"));
    }
    if !problems.is_empty() {
        return Err(FixError::Malformed { key, problems });
    }

    let (destination, access) = access(config, &report.target, key)?;
    let (agent, located) = sweep::locate_configured(config)?;
    let brief = json!({
        "key": key,
        "target": report.target,
        "severity": entry["severity"],
        "advisories": entry.get("advisories"),
        "installed": entry.get("installed"),
        "subject": entry.get("subject"),
        "fix": entry["fix"],
    });
    Ok(FixPlan {
        key,
        report: path,
        target: report.target,
        destination,
        found: report.started,
        title: sweep::plain(entry["title"].as_str().unwrap_or_default()),
        fix,
        brief,
        access,
        agent,
        located,
    })
}

/// The report a fix of `key` comes from: the newest one that has it, which must be the newest
/// report of its target with a verdict, while the key is not dismissed in
/// `state/dismissals.json`. Checked when the plan is made and again under the lock, since a
/// sweep or a dismissal can land while the user reads the question.
fn current_report(data_dir: &DataDir, key: FindingKey) -> Result<PathBuf, FixError> {
    let sweeps = data_dir.sweeps_dir();
    let (path, entry) =
        lifecycle::newest_report(&sweeps, key)?.ok_or(StateError::UnknownKey { key })?;
    let dir_name = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .expect("a report sits in a target folder named in UTF-8");
    let (newest, newest_saved) = lifecycle::newest_verdict(&sweeps, dir_name)?
        .expect("newest_report returns only reports with a verdict, so there is one");
    if newest != path {
        return Err(FixError::Stale {
            key,
            since: newest_saved.started,
        });
    }
    if Dismissals::load(data_dir)?
        .get(key, entry.modified())
        .is_some()
    {
        return Err(FixError::Dismissed { key });
    }
    Ok(path)
}

/// The parts of a saved `report.json` a fix needs.
#[derive(Debug, Deserialize)]
struct Saved {
    started: Timestamp,
    target: String,
    findings: Vec<Value>,
    issues: Vec<Value>,
}

/// One fix run, as appended to `state/fixes.jsonl`.
#[derive(Debug, Serialize)]
pub struct FixRecord {
    /// The finding or issue.
    pub key: FindingKey,
    /// Its one-line title when the fix was planned.
    pub title: String,
    /// When the sweep the fix was planned from started: which report it fixes.
    pub found: Timestamp,
    /// Where the fix ran.
    pub target: String,
    /// The agent that ran it.
    pub agent: AgentKind,
    /// When it started.
    pub started: Timestamp,
    /// When it finished.
    pub finished: Timestamp,
    /// The agent's exit code; `None` when a signal ended it or it did not start.
    pub exit_code: Option<i32>,
    /// What the agent reported, or `unknown` when it wrote no valid `result.json`.
    pub outcome: Outcome,
    /// The agent's one-line summary, or why its result was not read.
    pub summary: String,
    /// The pull request the agent opened, for a repository.
    pub pull_request: Option<String>,
    /// How the user confirmed it.
    pub confirmed: Confirmed,
    /// The fix's folder: prompt, `fix.json`, agent log and result.
    pub dir: PathBuf,
}

/// How a fix ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Done and checked.
    Fixed,
    /// Some of it was done.
    Partial,
    /// Nothing changed.
    Failed,
    /// The agent wrote no valid `result.json`.
    Unknown,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fixed => "fixed",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        })
    }
}

/// What the agent writes in `result.json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentResult {
    outcome: Outcome,
    summary: String,
    #[serde(default)]
    pull_request: Option<String>,
}

/// How the user confirmed a fix, kept in its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirmed {
    /// The user answered yes to the question.
    Asked,
    /// A script passed `--yes`, having shown the fix itself.
    YesFlag,
}

/// What a fix is doing, for a progress display. The steps come in this order.
#[derive(Debug, Clone)]
pub enum FixProgress {
    /// Writing the fix folder: the prompt, the brief and the result schema.
    Preparing,
    /// The agent is applying the fix, with full access, writing its output to `log`.
    Agent {
        /// Its log, which [`last_activity`] reads while it runs.
        log: PathBuf,
    },
    /// Reading the agent's result and recording the run.
    Recording,
}

impl FixProgress {
    /// Which step this is, from 0: the position of its label in [`Self::labels`].
    pub fn step(&self) -> usize {
        match self {
            Self::Preparing => 0,
            Self::Agent { .. } => 1,
            Self::Recording => 2,
        }
    }

    /// The labels of a fix's steps by `agent`, in order: "grok is applying the fix".
    pub fn labels(agent: AgentKind) -> [String; 3] {
        [
            "preparing the fix".to_owned(),
            format!("{agent} is applying the fix"),
            "recording the result".to_owned(),
        ]
    }
}

/// How many bytes of a log's end [`last_activity`] reads. Arbitrary: a few lines of an
/// agent's output, read every few seconds while a fix runs.
const ACTIVITY_TAIL: u64 = 4096;

/// How long a line [`last_activity`] returns. Arbitrary: about two lines of the popover.
const ACTIVITY_CHARS: usize = 160;

/// The last line the agent wrote to `log` that holds any text, as one plain line (control
/// characters replaced) of at most [`ACTIVITY_CHARS`] characters; `None` before it has written
/// any, or when the log cannot be read. Only the last [`ACTIVITY_TAIL`] bytes are read, so
/// text further back is not found, and a line that starts before them is shown from where
/// they start. The text is the agent's own and untrusted: it is only ever shown, never
/// acted on.
pub fn last_activity(log: &Path) -> Option<String> {
    let mut file = fs::File::open(log).ok()?;
    let len = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(ACTIVITY_TAIL)))
        .ok()?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).ok()?;
    let text = String::from_utf8_lossy(&tail);
    let line = text.lines().rev().map(str::trim).find(|l| !l.is_empty())?;
    Some(sweep::plain(line).chars().take(ACTIVITY_CHARS).collect())
}

/// Runs the confirmed `plan` with full access and records the run in `state/fixes.jsonl`.
/// Call it only after the user confirmed what the plan shows. Calls `progress` at each step,
/// with the sweeps lock held, so it should return quickly.
///
/// Blocks until the agent finishes; there is no time limit. An agent that cannot start is
/// recorded as `unknown` with the reason, like one that writes no result, and so is one that
/// `cancel` stops (the app quitting, or Ctrl-C in the CLI): it may have done part of the fix.
///
/// # Errors
///
/// Fails before the agent runs when a sweep or fix is running, when a sweep or dismissal
/// landed after `plan` was made ([`FixError::Stale`], [`FixError::Dismissed`],
/// [`FixError::Changed`]), or when the fix folder cannot be written; and after it when the
/// record cannot be appended.
pub fn run_fix(
    data_dir: &DataDir,
    plan: &FixPlan,
    confirmed: Confirmed,
    progress: &mut dyn FnMut(FixProgress),
    cancel: &Cancel,
) -> Result<FixRecord, FixError> {
    let _lock = Lock::acquire(&data_dir.sweeps_dir())?;
    if current_report(data_dir, plan.key)? != plan.report {
        return Err(FixError::Changed { key: plan.key });
    }
    progress(FixProgress::Preparing);
    let started = Timestamp::now();
    let fixes = data_dir.fixes_dir();
    fs::create_dir_all(&fixes).map_err(|source| FixError::Write {
        path: fixes.clone(),
        source,
    })?;
    let stamp = format!("{}-{}", started.strftime("%Y%m%dT%H%M%SZ"), plan.key);
    let dir = sweep::create_unique_dir(&fixes, &stamp)?;
    let prompt =
        prompts::render(data_dir, Prompt::Fix, &plan.target)?.replace("{{access}}", &plan.access);
    let brief = serde_json::to_string_pretty(&plan.brief).expect("a JSON value serializes");
    for (name, text) in [
        ("PROMPT.md", prompt.as_str()),
        ("fix.json", brief.as_str()),
        ("result.schema.json", RESULT_SCHEMA),
    ] {
        let path = dir.join(name);
        fs::write(&path, text).map_err(|source| FixError::Write { path, source })?;
    }

    let log = dir.join("agent.log");
    progress(FixProgress::Agent { log: log.clone() });
    let ran = plan.agent.run(
        &plan.agent.fix_command(&plan.located, &dir, PROMPT_LINE),
        &log,
        cancel,
    );
    progress(FixProgress::Recording);
    let repo = plan.target.strip_prefix("github:");
    let (exit_code, result) = match ran {
        Ok(status) => (status.code(), read_result(&dir.join("result.json"), repo)),
        Err(e @ (AgentError::Cancelled { .. } | AgentError::Watch { .. })) => (
            None,
            Err(format!(
                "the agent was stopped partway and may have made part of the fix: {}",
                sweep::error_chain(&e)
            )),
        ),
        Err(e) => (
            None,
            Err(format!("the agent did not run: {}", sweep::error_chain(&e))),
        ),
    };
    let (outcome, summary, pull_request) = match result {
        Ok(result) => (result.outcome, result.summary, result.pull_request),
        // The reason can quote the agent's file (a serde error names its fields).
        Err(why) => (Outcome::Unknown, why.replace(is_forging, " "), None),
    };
    let record = FixRecord {
        key: plan.key,
        title: plan.title.clone(),
        found: plan.found,
        target: plan.target.clone(),
        agent: plan.agent,
        started,
        finished: Timestamp::now(),
        exit_code,
        outcome,
        summary,
        pull_request,
        confirmed,
        dir,
    };
    append(data_dir, &record)?;
    Ok(record)
}

/// Where `target`, which must still be configured, is shown to the user, and the "Where to
/// work" section of the prompt.
fn access(config: &Config, target: &str, key: FindingKey) -> Result<(String, String), FixError> {
    let unknown = || FixError::UnknownTarget {
        target: target.to_owned(),
    };
    if target == "mac" {
        let access = "This Mac. Run the commands here, as the user.".to_owned();
        return Ok(("this Mac".to_owned(), access));
    }
    if let Some(slug) = target.strip_prefix("github:") {
        let repo = config
            .repos
            .iter()
            .find(|r| r.to_string() == slug)
            .ok_or_else(unknown)?;
        let access = format!(
            "The GitHub repository {repo}, with the user's `gh` login.\n\n\
             - A change to files: clone it into this folder (`gh repo clone {repo} repo`), \
             create the branch `vigil/fix-{key}` from the default branch, make the \
             change, commit it with a message that names the advisory or issue, push the \
             branch, and open a pull request with `gh pr create`. Never push to the default \
             branch.\n\
             - A repository setting: run the confirmed `gh api` commands."
        );
        return Ok((
            format!("the GitHub repository {repo}, as a pull request"),
            access,
        ));
    }
    if let Some(name) = target.strip_prefix("server:") {
        let server = config
            .servers
            .iter()
            .find(|s| s.name.to_string() == name)
            .ok_or_else(unknown)?;
        let ssh = server::ssh_command_line(&server.conn);
        let access = format!(
            "The server {name}. You are on this Mac; run every command on the server as\n\n\
             ```sh\n{ssh} sh -s <<'{HEREDOC_END}'\n<command>\n{HEREDOC_END}\n```\n\n\
             with the command on its own line, exactly as confirmed, and exactly these ssh \
             options; connect to no other host. Never put a command inside quotes on the ssh \
             line: a quote in the command would end them and run the rest on this Mac. Use \
             `sudo` where the confirmed command does; if sudo asks for a password, stop and \
             write `failed`."
        );
        return Ok((format!("the server {name}, through `{ssh}`"), access));
    }
    Err(unknown())
}

/// Reads and checks `result.json`, or says why it cannot be used. A pull request is only
/// accepted for a repository fix, as a pull request of that repository.
fn read_result(path: &Path, repo: Option<&str>) -> Result<AgentResult, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("no result.json: {e}"))?;
    let result: AgentResult =
        serde_json::from_str(&text).map_err(|e| format!("result.json: {e}"))?;
    if result.outcome == Outcome::Unknown {
        return Err("result.json: outcome must be fixed, partial or failed".to_owned());
    }
    let summary = result.summary.trim();
    if summary.is_empty() || summary.chars().any(is_forging) {
        return Err("result.json: summary must be one line of text".to_owned());
    }
    if let Some(url) = &result.pull_request {
        let number = repo
            .and_then(|r| url.strip_prefix(&format!("https://github.com/{r}/pull/")))
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if number.is_none() {
            return Err(format!(
                "result.json: pull_request must be a pull request of {}",
                repo.unwrap_or("the repository; this target has none")
            ));
        }
    }
    Ok(AgentResult {
        summary: summary.to_owned(),
        ..result
    })
}

/// One recorded fix run, as the lifecycle reads it back.
#[derive(Debug, Deserialize)]
pub(crate) struct Run {
    pub(crate) key: FindingKey,
    pub(crate) target: String,
    /// When the sweep it was planned from started; missing in records written before it was,
    /// which therefore mark nothing and are never listed as confirmed.
    #[serde(default)]
    pub(crate) found: Option<Timestamp>,
    #[serde(default)]
    pub(crate) title: String,
    pub(crate) finished: Timestamp,
    exit_code: Option<i32>,
    outcome: Outcome,
    pub(crate) summary: String,
    pub(crate) pull_request: Option<String>,
}

impl Run {
    /// Whether the run counts as a fix: the agent reported `fixed` and exited 0, as `vigil
    /// fix` requires to call it a success.
    pub(crate) fn succeeded(&self) -> bool {
        self.outcome == Outcome::Fixed && self.exit_code == Some(0)
    }
}

/// Every fix run in `state/fixes.jsonl`, in the order they were appended, which is the order
/// they ran: appends hold the state lock, and a fix holds the sweeps lock.
///
/// Read as bytes and parsed line by line: a crash can cut the last record anywhere, even
/// inside a multi-byte character, and [`append`] then starts the next record on a new line.
/// A line that does not parse is that torn record, and is skipped; the run it held is lost.
pub(crate) fn runs(data_dir: &DataDir) -> Result<Vec<Run>, StateError> {
    let path = data_dir.state_dir().join(FIXES_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(StateError::Read { path, source }),
    };
    Ok(bytes
        .split(|&b| b == b'\n')
        .filter_map(|line| serde_json::from_slice::<Run>(line).ok())
        .collect())
}

/// Appends `record` to `state/fixes.jsonl` as one line, under the state lock. A last line cut
/// short by a crash gets its line break first, so the new record is not glued onto it; the
/// folder is synced too, as the dismissals writer does.
fn append(data_dir: &DataDir, record: &FixRecord) -> Result<(), FixError> {
    let line = serde_json::to_string(record).expect("a fix record serializes");
    lifecycle::locked(data_dir, |state| {
        let path = state.join(FIXES_FILE);
        let written = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| {
                let torn = if file.metadata()?.len() > 0 {
                    let mut last = [0];
                    file.seek(SeekFrom::End(-1))?;
                    file.read_exact(&mut last)?;
                    last[0] != b'\n'
                } else {
                    false
                };
                let start = if torn { "\n" } else { "" };
                file.write_all(format!("{start}{line}\n").as_bytes())?;
                file.sync_data()?;
                // Always, not only when the file is new: fixes are rare, and a test cannot
                // tell the two apart, so the cheaper rule would go unchecked.
                fs::File::open(state)?.sync_all()
            });
        written.map_err(|source| StateError::Write { path, source })
    })?;
    Ok(())
}

/// Error from planning or running a fix.
#[derive(Debug, thiserror::Error)]
pub enum FixError {
    /// A newer sweep of the target no longer has the finding.
    #[error("a sweep at {since} no longer found {key}; nothing to fix")]
    Stale {
        /// The key.
        key: FindingKey,
        /// When that sweep started.
        since: Timestamp,
    },
    /// A sweep found the key again while the user was asked; the shown fix may be out of date.
    #[error("a sweep ran while {key} was being confirmed; run `fix {key}` again to see its fix")]
    Changed {
        /// The key.
        key: FindingKey,
    },
    /// The finding is dismissed.
    #[error("{key} is dismissed; undismiss it to fix it")]
    Dismissed {
        /// The key.
        key: FindingKey,
    },
    /// The fix in the report fails the sweep's checks (the report was edited).
    #[error("the fix for {key} is malformed: {}", problems.join("; "))]
    Malformed {
        /// The key.
        key: FindingKey,
        /// What is wrong.
        problems: Vec<String>,
    },
    /// The report's target is no longer in config.toml.
    #[error("{target} is not in config.toml any more; add it back to fix it")]
    UnknownTarget {
        /// The target.
        target: String,
    },
    /// The agent, the lock or the prompt failed, as they would for a sweep.
    #[error(transparent)]
    Sweep(#[from] SweepError),
    /// The agent could not be found or started.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// The state could not be read or written.
    #[error(transparent)]
    State(#[from] StateError),
    /// A report could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A fix file could not be written.
    #[error("cannot write {}", path.display())]
    Write {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, toml).unwrap();
        Config::load(&path, Path::new("/home")).unwrap()
    }

    #[test]
    fn each_target_gets_its_own_instructions_and_must_be_configured() {
        let config = config(
            "[github]\nrepos = [\"o/r\"]\n\n[[servers]]\nname = \"web\"\n\
             host = \"10.0.0.5\"\nuser = \"ops\"\nidentity_file = \"/k/id_ed\"\n",
        );
        let key = FindingKey::new(&["x"]);
        let (shown, mac) = access(&config, "mac", key).unwrap();
        assert_eq!(shown, "this Mac");
        assert!(mac.starts_with("This Mac."), "{mac}");

        let (shown, repo) = access(&config, "github:o/r", key).unwrap();
        assert_eq!(shown, "the GitHub repository o/r, as a pull request");
        assert!(repo.contains("`gh repo clone o/r repo`"), "{repo}");
        assert!(repo.contains(&format!("`vigil/fix-{key}`")), "{repo}");
        assert!(repo.contains("Never push to the default branch"), "{repo}");

        let (shown, server) = access(&config, "server:web", key).unwrap();
        let ssh = "ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes";
        assert!(
            shown.starts_with(&format!("the server web, through `{ssh}")),
            "{shown}"
        );
        assert!(
            shown.ends_with("-- 10.0.0.5`"),
            "the user sees the host: {shown}"
        );
        assert!(
            server.contains(
                "-l ops -i /k/id_ed -o IdentitiesOnly=yes -- 10.0.0.5 sh -s \
                 <<'VIGIL_END'\n<command>\nVIGIL_END\n"
            ),
            "{server}"
        );

        for gone in ["github:o/gone", "server:db", "laptop", "github:", "server:"] {
            assert!(
                matches!(
                    access(&config, gone, key),
                    Err(FixError::UnknownTarget { .. })
                ),
                "{gone}"
            );
        }
    }

    #[test]
    fn the_result_must_be_a_known_outcome_with_a_plain_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("result.json");
        let read = |json: &str, repo: Option<&str>| {
            fs::write(&path, json).unwrap();
            read_result(&path, repo)
        };
        let pr = r#"{"outcome": "partial", "summary": " half done ",
            "pull_request": "https://github.com/o/r/pull/12"}"#;
        let ok = read(pr, Some("o/r")).unwrap();
        assert_eq!(ok.outcome, Outcome::Partial);
        assert_eq!(ok.summary, "half done");
        assert_eq!(
            ok.pull_request.as_deref(),
            Some("https://github.com/o/r/pull/12")
        );
        let plain = read(r#"{"outcome": "fixed", "summary": "x"}"#, None).unwrap();
        assert!(plain.pull_request.is_none());

        let with_pr = |url: &str| {
            format!(r#"{{"outcome": "fixed", "summary": "x", "pull_request": "{url}"}}"#)
        };
        let bad = [
            (
                r#"{"outcome": "unknown", "summary": "x"}"#.to_owned(),
                Some("o/r"),
                "outcome",
            ),
            (
                r#"{"outcome": "fixed", "summary": " "}"#.to_owned(),
                None,
                "one line",
            ),
            (
                r#"{"outcome": "fixed", "summary": "a\nb"}"#.to_owned(),
                None,
                "one line",
            ),
            (
                r#"{"outcome": "fixed", "summary": "x", "e": 1}"#.to_owned(),
                None,
                "unknown field",
            ),
            (
                with_pr("https://github.com/o/r/pull/12"),
                None,
                "this target has none",
            ),
            (
                with_pr("https://github.com/o/other/pull/1"),
                Some("o/r"),
                "a pull request of o/r",
            ),
            (
                with_pr("https://github.com/o/r/pull/1x"),
                Some("o/r"),
                "a pull request of o/r",
            ),
            (
                with_pr("https://github.com/o/r/pull/"),
                Some("o/r"),
                "a pull request of o/r",
            ),
        ];
        for (json, repo, why) in bad {
            let err = read(&json, repo).unwrap_err();
            assert!(err.contains(why), "{json}: {err}");
        }
        fs::remove_file(&path).unwrap();
        assert!(
            read_result(&path, None)
                .unwrap_err()
                .starts_with("no result.json")
        );
    }

    /// A Mac report of `key` started at `started`, in the sweep folder `stamp`.
    fn save_report(data_dir: &DataDir, stamp: &str, started: &str, key: FindingKey) -> PathBuf {
        let dir = data_dir.sweeps_dir().join(stamp).join("mac");
        fs::create_dir_all(&dir).unwrap();
        let report = json!({
            "started": started, "target": "mac", "failure": null, "issues": [],
            "findings": [{"key": key, "severity": "high", "modified": "2026-11-01T00:00:00Z",
                "fix": {"summary": "s", "steps": [], "commands": ["true"]}}],
        });
        fs::write(dir.join("report.json"), report.to_string()).unwrap();
        dir.join("report.json")
    }

    #[test]
    fn a_sweep_or_dismissal_during_the_question_stops_the_fix() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let key = FindingKey::new(&["k"]);
        let report = save_report(&data_dir, "20261105T000000Z", "2026-11-05T00:00:00Z", key);
        let plan = FixPlan {
            key,
            report,
            target: "mac".to_owned(),
            destination: "this Mac".to_owned(),
            found: "2026-11-05T00:00:00Z".parse().unwrap(),
            title: "t".to_owned(),
            fix: Fix::deserialize(&json!({"summary": "s", "steps": [], "commands": []})).unwrap(),
            brief: json!({}),
            access: String::new(),
            agent: AgentKind::Claude,
            located: Located::at(Path::new("/no/such/agent")),
        };
        let unrun = || !data_dir.state_dir().join("fixes.jsonl").exists();

        lifecycle::dismiss(&data_dir, key, "accepted").unwrap();
        let err = run_fix(
            &data_dir,
            &plan,
            Confirmed::Asked,
            &mut |_| {},
            &Cancel::new(),
        )
        .unwrap_err();
        assert!(matches!(err, FixError::Dismissed { .. }), "{err:?}");
        lifecycle::undismiss(&data_dir, key).unwrap();

        save_report(&data_dir, "20261106T000000Z", "2026-11-06T00:00:00Z", key);
        let err = run_fix(
            &data_dir,
            &plan,
            Confirmed::Asked,
            &mut |_| {},
            &Cancel::new(),
        )
        .unwrap_err();
        assert!(matches!(err, FixError::Changed { .. }), "{err:?}");
        assert!(unrun(), "nothing ran and nothing was recorded");

        let gone = data_dir.sweeps_dir().join("20261107T000000Z/mac");
        fs::create_dir_all(&gone).unwrap();
        let empty = json!({"started": "2026-11-07T00:00:00Z", "target": "mac",
            "failure": null, "findings": [], "issues": []});
        fs::write(gone.join("report.json"), empty.to_string()).unwrap();
        let err = run_fix(
            &data_dir,
            &plan,
            Confirmed::Asked,
            &mut |_| {},
            &Cancel::new(),
        )
        .unwrap_err();
        assert!(matches!(err, FixError::Stale { .. }), "{err:?}");
        assert!(unrun());
    }

    fn record(n: u8) -> FixRecord {
        FixRecord {
            key: FindingKey::new(&[&n.to_string()]),
            title: "t".to_owned(),
            found: Timestamp::UNIX_EPOCH,
            target: "mac".to_owned(),
            agent: AgentKind::Claude,
            started: Timestamp::UNIX_EPOCH,
            finished: Timestamp::UNIX_EPOCH,
            exit_code: Some(0),
            outcome: Outcome::Fixed,
            summary: format!("run {n}"),
            pull_request: None,
            confirmed: Confirmed::Asked,
            dir: PathBuf::from("/f"),
        }
    }

    #[test]
    fn the_last_activity_is_the_agent_s_last_line_with_text_as_one_short_line() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("agent.log");
        assert_eq!(last_activity(&log), None, "no log yet");
        fs::write(&log, "").unwrap();
        assert_eq!(last_activity(&log), None, "nothing written yet");
        fs::write(&log, "reading fix.json\nupgrading curl \u{1b}[2J\n\n  \n").unwrap();
        assert_eq!(
            last_activity(&log).as_deref(),
            Some("upgrading curl \u{fffd}[2J")
        );
        let long = format!("{}\n{}\n", "x".repeat(10_000), "y".repeat(500));
        fs::write(&log, long).unwrap();
        assert_eq!(last_activity(&log), Some("y".repeat(ACTIVITY_CHARS)));
    }

    #[test]
    fn records_append_one_per_line_even_after_a_torn_last_line() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        append(&data_dir, &record(1)).unwrap();
        let path = data_dir.state_dir().join("fixes.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str("{\"key\": \"cut sh\0\0");
        fs::write(&path, &text).unwrap();
        append(&data_dir, &record(2)).unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(text.ends_with('\n'));
        for (line, n) in [(lines[0], 1), (lines[2], 2)] {
            let value: Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["summary"], format!("run {n}"));
        }
        assert_eq!(
            lines[1], "{\"key\": \"cut sh\0\0",
            "a tail of zeros is torn too"
        );
    }
}
