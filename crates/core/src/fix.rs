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
//!
//! Fix all (the owner's decision, 2026-11-11: one run, one confirm): [`plan_fix_all`] plans the
//! fix of every item [`popover::fix_all_items`] takes on one target, the user confirms them in
//! one question, and [`run_fix_all`] has one agent apply them in order in one folder,
//! `fixes/<start time>-all/`, reporting each in `results.jsonl`. Each item is recorded as a
//! single fix is, so everything that reads `state/fixes.jsonl` sees one run per finding.

use std::collections::BTreeMap;
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
use crate::popover;
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

/// The JSON Schema of each line of a Fix all's `results.jsonl`, written into its folder.
const FIX_ALL_RESULT_SCHEMA: &str = include_str!("fix-all-result.schema.json");

/// Where a Fix all's agent reports each fix as it finishes it, one JSON object per line.
const RESULTS_FILE: &str = "results.jsonl";

/// The agent's output in its fix folder.
const AGENT_LOG: &str = "agent.log";

/// The fix history's file in `state/`, written by [`append`] and read by [`runs`].
const FIXES_FILE: &str = "fixes.jsonl";

/// A checked fix, ready to show the user and, once confirmed, to run.
#[derive(Debug)]
pub struct FixPlan {
    finding: Planned,
    setup: Setup,
}

impl FixPlan {
    /// The target it fixes: `mac`, `github:owner/name` or `server:name`.
    pub fn target(&self) -> &str {
        &self.finding.target
    }

    /// Where the agent will work, as the user should read it before confirming.
    pub fn destination(&self) -> &str {
        &self.setup.destination
    }

    /// When the sweep that found it started.
    pub fn found(&self) -> Timestamp {
        self.finding.found
    }

    /// The fix the sweep's agent wrote, which the user confirms.
    pub fn fix(&self) -> &Fix {
        &self.finding.fix
    }

    /// The agent that will run it.
    pub fn agent(&self) -> AgentKind {
        self.setup.agent
    }
}

/// One finding's checked fix, as read from its report.
#[derive(Debug)]
struct Planned {
    key: FindingKey,
    /// The `report.json` it was read from.
    report: PathBuf,
    target: String,
    /// When the sweep that found it started.
    found: Timestamp,
    /// The finding's one-line title, for the fix history.
    title: String,
    fix: Fix,
    /// What the agent is given for it, in `fix.json` or as an entry of `fixes.json`.
    brief: Value,
}

/// How and where an agent run fixes a target: the same for every item of a Fix all.
#[derive(Debug)]
struct Setup {
    /// Where it runs, for the user: "this Mac", or the repository or the ssh command.
    destination: String,
    /// The prompt's "Where to work" section.
    access: String,
    agent: AgentKind,
    located: Located,
}

/// Reads the fix for `key` from the newest report of its target and checks it can run.
///
/// # Errors
///
/// Fails when no report has `key`, a newer sweep of its target no longer has it, it is
/// dismissed, its fix is malformed, its target is no longer configured, or no agent is
/// configured or found.
pub fn plan_fix(data_dir: &DataDir, config: &Config, key: FindingKey) -> Result<FixPlan, FixError> {
    let finding = plan_finding(data_dir, key)?;
    let setup = setup(config, &finding.target, key)?;
    Ok(FixPlan { finding, setup })
}

/// Where a fix of `target` runs and with which agent, which must be installed. `key` names a
/// repository fix's branch.
fn setup(config: &Config, target: &str, key: FindingKey) -> Result<Setup, FixError> {
    let (destination, access) = access(config, target, key)?;
    let (agent, located) = sweep::locate_configured(config)?;
    Ok(Setup {
        destination,
        access,
        agent,
        located,
    })
}

/// Reads the fix for `key` from the newest report of its target, and checks it as the sweep
/// checked it.
fn plan_finding(data_dir: &DataDir, key: FindingKey) -> Result<Planned, FixError> {
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

    let brief = json!({
        "key": key,
        "target": report.target,
        "severity": entry["severity"],
        "advisories": entry.get("advisories"),
        "installed": entry.get("installed"),
        "subject": entry.get("subject"),
        "fix": entry["fix"],
    });
    Ok(Planned {
        key,
        report: path,
        target: report.target,
        found: report.started,
        title: sweep::plain(entry["title"].as_str().unwrap_or_default()),
        fix,
        brief,
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

/// One line the agent appends to a Fix all's `results.jsonl`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultLine {
    key: FindingKey,
    outcome: Outcome,
    summary: String,
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
    /// The agent is applying the fix, or a Fix all's fixes, with full access, in the fix folder
    /// `dir`, writing its output to `agent.log` there.
    Agent {
        /// The fix folder, which [`Self::activity`] and [`Self::step`] read while it runs.
        dir: PathBuf,
        /// The keys it fixes, in order: one for a single fix.
        keys: Vec<FindingKey>,
    },
    /// Reading the agent's result and recording the run.
    Recording,
}

impl FixProgress {
    /// Which step this is: the index of its label in `labels`, the run's [`Self::labels`] or
    /// [`FixAllPlan::labels`]. While the agent runs a Fix all, its step is the first item, in
    /// order, that `results.jsonl` has no valid line for, which this reads; once all have one,
    /// the last item stays the step until the agent exits, as it may still be checking it.
    pub fn step(&self, labels: &[String]) -> usize {
        match self {
            Self::Preparing => 0,
            Self::Agent { keys, .. } if keys.len() < 2 => 1,
            Self::Agent { dir, keys } => {
                let reported = read_results(&dir.join(RESULTS_FILE));
                let at = keys.iter().position(|key| !reported.contains_key(key));
                1 + at.unwrap_or(keys.len() - 1)
            }
            Self::Recording => labels.len().saturating_sub(1),
        }
    }

    /// The agent's last line of output while it runs ([`last_activity`]); `None` in the other
    /// steps.
    pub fn activity(&self) -> Option<String> {
        match self {
            Self::Agent { dir, .. } => last_activity(&dir.join(AGENT_LOG)),
            Self::Preparing | Self::Recording => None,
        }
    }

    /// The labels of a fix's steps by `agent`, in order: "grok is applying the fix".
    pub fn labels(agent: AgentKind) -> Vec<String> {
        vec![
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
fn last_activity(log: &Path) -> Option<String> {
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
    // One agent at a time (the owner's rule, 2026-11-11): no sweep, fix or Fix all runs while
    // this one changes the target.
    let _lock = Lock::acquire(&data_dir.sweeps_dir())?;
    let finding = &plan.finding;
    if !still_current(data_dir, finding)? {
        return Err(FixError::Changed { key: finding.key });
    }
    progress(FixProgress::Preparing);
    let started = Timestamp::now();
    let prompt = prompts::render(data_dir, Prompt::Fix, &finding.target)?
        .replace("{{access}}", &plan.setup.access);
    let brief = serde_json::to_string_pretty(&finding.brief).expect("a JSON value serializes");
    let dir = fix_dir(
        data_dir,
        started,
        &finding.key.to_string(),
        &[
            ("PROMPT.md", &prompt),
            ("fix.json", &brief),
            ("result.schema.json", RESULT_SCHEMA),
        ],
    )?;

    progress(FixProgress::Agent {
        dir: dir.clone(),
        keys: vec![finding.key],
    });
    let ran = run_agent(&plan.setup, &dir, cancel);
    progress(FixProgress::Recording);
    let repo = finding.target.strip_prefix("github:");
    let (outcome, summary, pull_request) = match ran
        .stopped
        .clone()
        .map_or_else(|| read_result(&dir.join("result.json"), repo), Err)
    {
        Ok(result) => (result.outcome, result.summary, result.pull_request),
        // The reason can quote the agent's file (a serde error names its fields).
        Err(why) => (Outcome::Unknown, why.replace(is_forging, " "), None),
    };
    let record = FixRecord {
        key: finding.key,
        title: finding.title.clone(),
        found: finding.found,
        target: finding.target.clone(),
        agent: plan.setup.agent,
        started,
        finished: Timestamp::now(),
        exit_code: ran.exit_code,
        outcome,
        summary,
        pull_request,
        confirmed,
        dir,
    };
    append(data_dir, std::slice::from_ref(&record))?;
    Ok(record)
}

/// Whether `finding` still comes from the newest report of its target; fails when it is gone
/// or dismissed. Run under the sweeps lock, as a sweep or dismissal can land while the user
/// reads the question.
fn still_current(data_dir: &DataDir, finding: &Planned) -> Result<bool, FixError> {
    Ok(current_report(data_dir, finding.key)? == finding.report)
}

/// Creates a new fix folder `fixes/<started>-<name>[-n]/` holding `files`, by name and text.
fn fix_dir(
    data_dir: &DataDir,
    started: Timestamp,
    name: &str,
    files: &[(&str, &str)],
) -> Result<PathBuf, FixError> {
    let fixes = data_dir.fixes_dir();
    fs::create_dir_all(&fixes).map_err(|source| FixError::Write {
        path: fixes.clone(),
        source,
    })?;
    let stamp = format!("{}-{name}", started.strftime("%Y%m%dT%H%M%SZ"));
    let dir = sweep::create_unique_dir(&fixes, &stamp)?;
    for (file, text) in files {
        let path = dir.join(file);
        fs::write(&path, text).map_err(|source| FixError::Write { path, source })?;
    }
    Ok(dir)
}

/// How the agent's run ended.
struct Ran {
    /// Its exit code; `None` when a signal ended it or it did not start.
    exit_code: Option<i32>,
    /// Why its results cannot be trusted whole, when it was stopped or did not start.
    stopped: Option<String>,
}

/// Runs `setup`'s agent with full access in `dir`, with the one-line prompt pointing at
/// `PROMPT.md` there, until it exits or `cancel` stops it.
fn run_agent(setup: &Setup, dir: &Path, cancel: &Cancel) -> Ran {
    let command = setup.agent.fix_command(&setup.located, dir, PROMPT_LINE);
    match setup.agent.run(&command, &dir.join(AGENT_LOG), cancel) {
        Ok(status) => Ran {
            exit_code: status.code(),
            stopped: None,
        },
        Err(e @ (AgentError::Cancelled { .. } | AgentError::Watch { .. })) => Ran {
            exit_code: None,
            stopped: Some(format!(
                "the agent was stopped partway and may have made part of the fix: {}",
                sweep::error_chain(&e)
            )),
        },
        Err(e) => Ran {
            exit_code: None,
            stopped: Some(format!("the agent did not run: {}", sweep::error_chain(&e))),
        },
    }
}

/// A checked Fix all of one target: every open item [`popover::fix_all_items`] takes, each
/// with its lead's fix, for one confirmation and one agent run.
///
/// The owner's decision (2026-11-11): one run, one confirm. The user confirms all the listed
/// fixes at once; one agent applies them in order, reports each in `results.jsonl` and goes on
/// past a failure; each is recorded in `state/fixes.jsonl` on its own, exactly as a single fix
/// is, so the reported-fix display and the next sweep's check keep working per item.
#[derive(Debug)]
pub struct FixAllPlan {
    target: String,
    /// Where and with which agent it runs: one setup for the whole batch.
    setup: Setup,
    /// Never empty, all from one report: [`plan_fix_all`] refuses anything else.
    items: Vec<FixAllItem>,
}

impl FixAllPlan {
    /// The target it fixes: `mac` or `server:name`.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Where the agent will work, as the user should read it before confirming.
    pub fn destination(&self) -> &str {
        &self.setup.destination
    }

    /// When the sweep that found the items started; they come from one report.
    pub fn found(&self) -> Timestamp {
        self.items
            .first()
            .expect("plan_fix_all refuses a plan without items")
            .finding
            .found
    }

    /// The agent that will run it.
    pub fn agent(&self) -> AgentKind {
        self.setup.agent
    }

    /// The items, in the order the agent applies them: the order the popover ranks them.
    pub fn items(&self) -> &[FixAllItem] {
        &self.items
    }

    /// One line saying what the run does: "grok applies 3 fixes in one run".
    pub fn title(&self) -> String {
        format!(
            "{} applies {} fixes in one run",
            self.agent(),
            self.items.len()
        )
    }

    /// The labels of its steps, in order: preparing, one per item ("fixing curl 8.1.2"),
    /// recording. [`FixProgress::step`] says which runs.
    pub fn labels(&self) -> Vec<String> {
        std::iter::once("preparing the fixes".to_owned())
            .chain(
                self.items
                    .iter()
                    .map(|item| format!("fixing {}", item.name)),
            )
            .chain(std::iter::once("recording the results".to_owned()))
            .collect()
    }

    /// The batch error for `item`, which a sweep or a dismissal changed since it was planned.
    fn changed(&self, item: &FixAllItem) -> FixError {
        FixError::Item {
            name: item.name.clone(),
            why: Box::new(FixError::ListChanged {
                target: self.target.clone(),
            }),
        }
    }
}

/// One item of a [`FixAllPlan`].
#[derive(Debug)]
pub struct FixAllItem {
    /// "curl 8.1.2", or an issue's subject: what the progress and the confirmation name.
    name: String,
    finding: Planned,
}

impl FixAllItem {
    /// What it is: the component and its version, or the issue's subject.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key of the finding that leads it, whose fix it runs.
    pub fn key(&self) -> FindingKey {
        self.finding.key
    }

    /// The fix the sweep's agent wrote, which the user confirms.
    pub fn fix(&self) -> &Fix {
        &self.finding.fix
    }
}

/// Plans a Fix all of `target`: the fix of every open item [`popover::fix_all_items`] takes,
/// each checked as [`plan_fix`] checks one, and the agent found once for all of them.
///
/// # Errors
///
/// Fails when `target` is a repository ([`FixError::FixAllRepository`]) or not configured
/// ([`FixError::NotATarget`]), has no item to fix ([`FixError::NothingToFixAll`]), when any
/// item's fix cannot be planned ([`FixError::Item`], naming it), when a sweep landed while the
/// items were read, or when no agent is configured or found.
pub fn plan_fix_all(
    data_dir: &DataDir,
    config: &Config,
    target: &str,
) -> Result<FixAllPlan, FixError> {
    if target.starts_with("github:") {
        return Err(FixError::FixAllRepository {
            target: target.to_owned(),
        });
    }
    let latest = lifecycle::latest(data_dir, config)?
        .into_iter()
        .find(|t| t.target == target)
        .ok_or_else(|| FixError::NotATarget {
            target: target.to_owned(),
        })?;
    let open = popover::items(target, latest.open).open;
    let items = popover::fix_all_items(target, &open)
        .map(|item| {
            let name = match &item.lead.version {
                Some(version) => format!("{} {version}", item.name),
                None => item.name.clone(),
            };
            let name = sweep::plain(&name);
            match plan_finding(data_dir, item.lead.key) {
                Ok(finding) => Ok(FixAllItem { name, finding }),
                Err(why) => Err(FixError::Item {
                    name,
                    why: Box::new(why),
                }),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let first = items.first().ok_or_else(|| FixError::NothingToFixAll {
        target: target.to_owned(),
    })?;
    let setup = setup(config, target, first.finding.key)?;
    let plan = FixAllPlan {
        target: target.to_owned(),
        setup,
        items,
    };
    // Each item reads the newest report that has its key; a sweep that landed between them
    // would mix two reports.
    let found = plan.found();
    if let Some(other) = plan.items.iter().find(|item| item.finding.found != found) {
        return Err(plan.changed(other));
    }
    Ok(plan)
}

/// Runs the confirmed Fix all `plan` as one agent run with full access, and records each item
/// in `state/fixes.jsonl` as [`run_fix`] records one. Call it only after the user confirmed
/// what the plan shows. Calls `progress` at each step, with the sweeps lock held.
///
/// Every item is checked again under the lock first, and one that a sweep or a dismissal
/// changed refuses the whole run, naming it: the user confirmed the list as shown, and running
/// part of it would be a list nobody confirmed. An item the agent reported nothing for is
/// recorded as `unknown`, with why when the agent was stopped or did not start.
///
/// # Errors
///
/// Fails before the agent runs when a sweep or fix is running, when any item changed since
/// `plan` was made ([`FixError::Item`]), or when the fix folder cannot be written; and after it
/// when the records cannot be appended.
pub fn run_fix_all(
    data_dir: &DataDir,
    plan: &FixAllPlan,
    confirmed: Confirmed,
    progress: &mut dyn FnMut(FixProgress),
    cancel: &Cancel,
) -> Result<Vec<FixRecord>, FixError> {
    // One agent at a time (the owner's rule, 2026-11-11): the whole batch is one agent run
    // under the sweeps lock, so no sweep, fix or other Fix all runs beside it.
    let _lock = Lock::acquire(&data_dir.sweeps_dir())?;
    for item in &plan.items {
        let current = still_current(data_dir, &item.finding).map_err(|why| FixError::Item {
            name: item.name.clone(),
            why: Box::new(why),
        })?;
        if !current {
            return Err(plan.changed(item));
        }
    }
    progress(FixProgress::Preparing);
    let started = Timestamp::now();
    let prompt = prompts::render(data_dir, Prompt::FixAll, &plan.target)?
        .replace("{{access}}", &plan.setup.access);
    let briefs: Vec<&Value> = plan.items.iter().map(|item| &item.finding.brief).collect();
    let briefs = serde_json::to_string_pretty(&briefs).expect("JSON values serialize");
    let dir = fix_dir(
        data_dir,
        started,
        "all",
        &[
            ("PROMPT.md", &prompt),
            ("fixes.json", &briefs),
            ("result.schema.json", FIX_ALL_RESULT_SCHEMA),
        ],
    )?;

    progress(FixProgress::Agent {
        dir: dir.clone(),
        keys: plan.items.iter().map(FixAllItem::key).collect(),
    });
    let ran = run_agent(&plan.setup, &dir, cancel);
    progress(FixProgress::Recording);
    let mut results = read_results(&dir.join(RESULTS_FILE));
    let finished = Timestamp::now();
    let records: Vec<FixRecord> = plan
        .items
        .iter()
        .map(|item| {
            let finding = &item.finding;
            let (outcome, summary) = match results.remove(&finding.key) {
                Some(result) => (result.outcome, result.summary),
                None => (
                    Outcome::Unknown,
                    ran.stopped.as_deref().map_or_else(
                        || format!("the agent reported nothing for it in {RESULTS_FILE}"),
                        |why| why.replace(is_forging, " "),
                    ),
                ),
            };
            FixRecord {
                key: finding.key,
                title: finding.title.clone(),
                found: finding.found,
                target: plan.target.clone(),
                agent: plan.setup.agent,
                started,
                finished,
                exit_code: ran.exit_code,
                outcome,
                summary,
                pull_request: None,
                confirmed,
                dir: dir.clone(),
            }
        })
        .collect();
    append(data_dir, &records)?;
    Ok(records)
}
/// How a Fix all went, for the user: `fixed` when every item was (reported `fixed` with exit
/// code 0, as `vigil fix` counts success), `failed` when none was, `partial` otherwise; and one
/// line, "2 of 3 fixed", naming each item that was not with its outcome and summary.
pub fn fix_all_outcome(records: &[FixRecord]) -> (Outcome, String) {
    let fixed = |r: &&FixRecord| r.outcome == Outcome::Fixed && r.exit_code == Some(0);
    let done = records.iter().filter(fixed).count();
    let outcome = match done {
        0 => Outcome::Failed,
        n if n == records.len() => Outcome::Fixed,
        _ => Outcome::Partial,
    };
    let mut line = format!("{done} of {} fixed", records.len());
    for record in records.iter().filter(|r| !fixed(r)) {
        line.push_str(&format!(
            "; {}: {}, {}",
            record.title, record.outcome, record.summary
        ));
    }
    (outcome, line)
}

/// The valid lines of a Fix all's `results.jsonl`, by key; the last line of a key wins, as the
/// agent may report a fix again after checking it. A line that does not parse, or fails the
/// checks a single result gets, is left out, so its fix is recorded as `unknown`. Empty when
/// the file is missing or cannot be read.
fn read_results(path: &Path) -> BTreeMap<FindingKey, AgentResult> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    text.lines()
        .filter_map(|line| {
            let line: ResultLine = serde_json::from_str(line).ok()?;
            let result = AgentResult {
                outcome: line.outcome,
                summary: line.summary,
                pull_request: None,
            };
            Some((line.key, check_result(result, None).ok()?))
        })
        .collect()
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
    check_result(result, repo)
}

/// Checks what the agent reported for one fix, and trims its summary.
fn check_result(result: AgentResult, repo: Option<&str>) -> Result<AgentResult, String> {
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

/// Appends `records` to `state/fixes.jsonl`, one line each, in one write under the state lock.
/// A last line cut short by a crash gets its line break first, so the new record is not glued
/// onto it; the folder is synced too, as the dismissals writer does.
fn append(data_dir: &DataDir, records: &[FixRecord]) -> Result<(), FixError> {
    let lines: String = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("a fix record serializes") + "\n")
        .collect();
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
                file.write_all(format!("{start}{lines}").as_bytes())?;
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
    /// One item of a Fix all cannot be fixed now, so nothing was run.
    #[error("nothing was run: {name}: {why}")]
    Item {
        /// The item, as the confirmation names it.
        name: String,
        /// Why, shown in this error's message rather than as its source, so the item it
        /// names is never left out of what the user reads.
        why: Box<Self>,
    },
    /// A sweep or a dismissal changed a Fix all's items while the list was being confirmed.
    #[error(
        "a sweep or dismissal changed it while the list was being confirmed; run `fix all {target}` again to see the current fixes"
    )]
    ListChanged {
        /// The target.
        target: String,
    },
    /// Fix all was asked for a target that is not in config.toml.
    #[error(
        "{target} is not a configured target; use mac or server:<name> as config.toml names it"
    )]
    NotATarget {
        /// The target.
        target: String,
    },
    /// Fix all is not offered for a repository.
    #[error(
        "{target} is a repository, where each fix opens its own pull request; fix its items \
         one by one"
    )]
    FixAllRepository {
        /// The target.
        target: String,
    },
    /// The target has no open item whose fix has commands to run.
    #[error("{target} has no open item with a fix to run; nothing to fix")]
    NothingToFixAll {
        /// The target.
        target: String,
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
        save_report_of(data_dir, stamp, started, &[key])
    }

    /// A Mac report of `keys`, started at `started`, in the sweep folder `stamp`.
    fn save_report_of(
        data_dir: &DataDir,
        stamp: &str,
        started: &str,
        keys: &[FindingKey],
    ) -> PathBuf {
        let dir = data_dir.sweeps_dir().join(stamp).join("mac");
        fs::create_dir_all(&dir).unwrap();
        let findings: Vec<Value> = keys
            .iter()
            .map(|key| {
                json!({"key": key, "severity": "high", "modified": "2026-11-01T00:00:00Z",
                    "fix": {"summary": "s", "steps": [], "commands": ["true"]}})
            })
            .collect();
        let report = json!({
            "started": started, "target": "mac", "failure": null, "issues": [],
            "findings": findings,
        });
        fs::write(dir.join("report.json"), report.to_string()).unwrap();
        dir.join("report.json")
    }

    /// The fix of `key` from `report`, found by the sweep of 2026-11-05.
    fn finding_of(key: FindingKey, report: PathBuf) -> Planned {
        Planned {
            key,
            report,
            target: "mac".to_owned(),
            found: "2026-11-05T00:00:00Z".parse().unwrap(),
            title: format!("t {key}"),
            fix: Fix::deserialize(&json!({"summary": "s", "steps": [], "commands": []})).unwrap(),
            brief: json!({"key": key}),
        }
    }

    /// The Mac with an agent that is not installed, so a test that gets past the checks fails
    /// to start it.
    fn nowhere() -> Setup {
        Setup {
            destination: "this Mac".to_owned(),
            access: String::new(),
            agent: AgentKind::Claude,
            located: Located::at(Path::new("/no/such/agent")),
        }
    }

    fn plan_of(key: FindingKey, report: PathBuf) -> FixPlan {
        FixPlan {
            finding: finding_of(key, report),
            setup: nowhere(),
        }
    }

    /// A Fix all of `keys`, all found by the sweep in `report`.
    fn fix_all_of(keys: &[FindingKey], report: &Path) -> FixAllPlan {
        FixAllPlan {
            target: "mac".to_owned(),
            setup: nowhere(),
            items: keys
                .iter()
                .enumerate()
                .map(|(n, &key)| FixAllItem {
                    name: format!("item {n}"),
                    finding: finding_of(key, report.to_owned()),
                })
                .collect(),
        }
    }

    #[test]
    fn a_fix_all_waits_for_no_one_and_refuses_while_another_run_holds_the_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let keys = [FindingKey::new(&["a"]), FindingKey::new(&["b"])];
        let report = save_report_of(&data_dir, "20261105T000000Z", "2026-11-05T00:00:00Z", &keys);
        let plan = fix_all_of(&keys, &report);

        // As a sweep or a single fix holds it.
        let held = Lock::acquire(&data_dir.sweeps_dir()).unwrap();
        let mut steps = 0;
        let err = run_fix_all(
            &data_dir,
            &plan,
            Confirmed::Asked,
            &mut |_| steps += 1,
            &Cancel::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, FixError::Sweep(SweepError::Busy { .. })),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("a sweep or fix is running"),
            "{err}"
        );
        assert_eq!(steps, 0, "nothing started");
        assert!(!data_dir.fixes_dir().exists());
        drop(held);

        // Holding it, a Fix all keeps a sweep or fix out until it has recorded its run.
        let mut tried = None;
        let records = run_fix_all(
            &data_dir,
            &plan,
            Confirmed::Asked,
            &mut |p| {
                if matches!(p, FixProgress::Agent { .. }) {
                    tried = Some(Lock::acquire(&data_dir.sweeps_dir()).map(drop));
                }
            },
            &Cancel::new(),
        )
        .unwrap();
        assert!(
            matches!(tried, Some(Err(SweepError::Busy { .. }))),
            "{tried:?}"
        );
        assert_eq!(records.len(), 2);
        for record in &records {
            assert_eq!(record.outcome, Outcome::Unknown);
            assert!(
                record.summary.starts_with("the agent did not run"),
                "{}",
                record.summary
            );
        }
    }

    #[test]
    fn a_fix_all_with_one_item_changed_runs_nothing_and_names_it() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let keys = [FindingKey::new(&["a"]), FindingKey::new(&["b"])];
        let report = save_report_of(&data_dir, "20261105T000000Z", "2026-11-05T00:00:00Z", &keys);
        let plan = fix_all_of(&keys, &report);
        let run = || {
            run_fix_all(
                &data_dir,
                &plan,
                Confirmed::Asked,
                &mut |_| {},
                &Cancel::new(),
            )
            .unwrap_err()
        };

        lifecycle::dismiss(&data_dir, keys[1], "accepted").unwrap();
        let err = run();
        assert!(
            matches!(&err, FixError::Item { name, why }
                if name == "item 1" && matches!(**why, FixError::Dismissed { .. })),
            "{err:?}"
        );
        assert!(
            err.to_string().starts_with(&format!(
                "nothing was run: item 1: {} is dismissed",
                keys[1]
            )),
            "{err}"
        );
        lifecycle::undismiss(&data_dir, keys[1]).unwrap();

        save_report_of(&data_dir, "20261106T000000Z", "2026-11-06T00:00:00Z", &keys);
        let err = run();
        assert!(
            matches!(&err, FixError::Item { name, why }
                if name == "item 0" && matches!(**why, FixError::ListChanged { .. })),
            "{err:?}"
        );
        assert!(
            err.to_string()
                .ends_with("run `fix all mac` again to see the current fixes"),
            "the next step is the batch's: {err}"
        );
        assert!(!data_dir.state_dir().join("fixes.jsonl").exists());
        assert!(!data_dir.fixes_dir().exists(), "no fix folder either");
    }

    #[test]
    fn results_keep_the_last_valid_line_of_each_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("results.jsonl");
        assert!(read_results(&path).is_empty(), "no file yet");
        let [a, b, c] = [&["a"], &["b"], &["c"]].map(|p| FindingKey::new(p));
        let lines = [
            format!(r#"{{"key": "{a}", "outcome": "failed", "summary": "first try"}}"#),
            "not json".to_owned(),
            format!(r#"{{"key": "{a}", "outcome": "fixed", "summary": " again "}}"#),
            format!(r#"{{"key": "{b}", "outcome": "unknown", "summary": "x"}}"#),
            format!(r#"{{"key": "{c}", "outcome": "fixed", "summary": "x", "pr": 1}}"#),
            format!(r#"{{"key": "{c}", "outcome": "fixed", "summary": ""}}"#),
        ];
        fs::write(&path, lines.join("\n")).unwrap();
        let results = read_results(&path);
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[&a].outcome, Outcome::Fixed);
        assert_eq!(results[&a].summary, "again");
    }

    #[test]
    fn a_fix_all_s_step_is_the_first_item_not_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let [a, b, c] = [&["a"], &["b"], &["c"]].map(|p| FindingKey::new(p));
        let agent = FixProgress::Agent {
            dir: tmp.path().to_owned(),
            keys: vec![a, b, c],
        };
        let labels = ["prepare", "a", "b", "c", "record"].map(str::to_owned);
        assert_eq!(FixProgress::Preparing.step(&labels), 0);
        assert_eq!(agent.step(&labels), 1, "nothing reported yet");
        let report = |keys: &[FindingKey]| {
            let lines: Vec<String> = keys
                .iter()
                .map(|k| format!(r#"{{"key": "{k}", "outcome": "fixed", "summary": "s"}}"#))
                .collect();
            fs::write(tmp.path().join(RESULTS_FILE), lines.join("\n")).unwrap();
        };
        report(&[a]);
        assert_eq!(agent.step(&labels), 2);
        // Out of order, and a key not in the run: the first item not reported runs.
        report(&[c, FindingKey::new(&["other"])]);
        assert_eq!(agent.step(&labels), 1);
        report(&[a, c]);
        assert_eq!(agent.step(&labels), 2);
        report(&[a, b, c]);
        assert_eq!(
            agent.step(&labels),
            3,
            "the last stays the step until the agent exits"
        );
        assert_eq!(FixProgress::Recording.step(&labels), 4);

        let single = FixProgress::Agent {
            dir: tmp.path().to_owned(),
            keys: vec![c],
        };
        let labels = FixProgress::labels(AgentKind::Grok);
        assert_eq!(single.step(&labels), 1, "a single fix has one agent step");
        assert_eq!(FixProgress::Recording.step(&labels), 2);
    }

    #[test]
    fn a_fix_all_names_each_item_as_a_step() {
        let keys = [FindingKey::new(&["a"]), FindingKey::new(&["b"])];
        let plan = fix_all_of(&keys, Path::new("/r"));
        assert_eq!(
            plan.labels(),
            [
                "preparing the fixes",
                "fixing item 0",
                "fixing item 1",
                "recording the results"
            ]
        );
        assert_eq!(plan.title(), "claude applies 2 fixes in one run");
        assert_eq!(plan.agent(), AgentKind::Claude);
        assert_eq!(plan.items()[1].key(), keys[1]);
    }

    #[test]
    fn a_fix_all_s_outcome_counts_fixes_that_held_and_names_the_rest() {
        let fixed = record(1);
        let mut failed = record(2);
        failed.outcome = Outcome::Failed;
        failed.title = "curl is old".to_owned();
        let mut crashed = record(3);
        crashed.exit_code = Some(1);
        assert_eq!(
            fix_all_outcome(&[record(1), record(4)]),
            (Outcome::Fixed, "2 of 2 fixed".to_owned())
        );
        assert_eq!(
            fix_all_outcome(&[fixed, failed]),
            (
                Outcome::Partial,
                "1 of 2 fixed; curl is old: failed, run 2".to_owned()
            )
        );
        let (outcome, line) = fix_all_outcome(&[crashed]);
        assert_eq!(
            outcome,
            Outcome::Failed,
            "fixed with a failing exit is not fixed"
        );
        assert_eq!(line, "0 of 1 fixed; t: fixed, run 3");
    }

    #[test]
    fn a_sweep_or_dismissal_during_the_question_stops_the_fix() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path());
        let key = FindingKey::new(&["k"]);
        let report = save_report(&data_dir, "20261105T000000Z", "2026-11-05T00:00:00Z", key);
        let plan = plan_of(key, report);
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
        append(&data_dir, &[record(1)]).unwrap();
        let path = data_dir.state_dir().join("fixes.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str("{\"key\": \"cut sh\0\0");
        fs::write(&path, &text).unwrap();
        append(&data_dir, &[record(2)]).unwrap();

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
