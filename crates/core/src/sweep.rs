//! One sweep: this Mac, then each configured GitHub repository, then each server, each with
//! its own inventory, advisories, agent verdict and report.
//!
//! Flow per target (spec, "Sweep flow"): collect the inventory; fetch OSV advisories for its
//! packages and NVD CVEs for its products (the KEV catalog once per sweep); link each advisory
//! to the components whose query returned it; write the bundle; run the chosen agent in it;
//! validate `findings.json`, retrying once with the problems appended; write `report.json` and
//! `report.md`.
//!
//! A source that fails is recorded in the report and the sweep goes on with the rest. Only one
//! sweep runs at a time: the running sweep holds an advisory lock (`flock`) on `.lock` in the
//! sweeps folder, which the system releases when the process ends, however it ends.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use jiff::Timestamp;
use serde::Serialize;

use crate::agent::AgentError;
use crate::agent::AgentKind;
use crate::agent::Located;
use crate::agent::PROMPT_LINE;
use crate::bundle;
use crate::bundle::BundleError;
use crate::cancel;
use crate::cancel::Cancel;
use crate::config::Config;
use crate::config::History;
use crate::config::RepoSlug;
use crate::config::Server;
use crate::feeds::FeedError;
use crate::feeds::Feeds;
use crate::feeds::Kev;
use crate::feeds::NvdAccess;
use crate::feeds::OsvAdvisory;
use crate::feeds::OsvQuery;
use crate::feeds::Product;
use crate::feeds::cpe;
use crate::findings;
use crate::findings::Finding;
use crate::findings::Fix;
use crate::findings::Issue;
use crate::findings::Known;
use crate::findings::Severity;
use crate::findings::Subject;
use crate::findings::Verdict;
use crate::findings::is_forging;
use crate::github;
use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::Lookup;
use crate::lifecycle;
use crate::lifecycle::CarriedFinding;
use crate::lifecycle::Changes;
use crate::lifecycle::ComponentKey;
use crate::lifecycle::Dismissal;
use crate::lifecycle::Dismissals;
use crate::lifecycle::FindingKey;
use crate::matching;
use crate::matching::Linked;
use crate::matching::Match;
use crate::matching::OsvRecord;
use crate::paths;
use crate::paths::DataDir;
use crate::prompts;
use crate::prompts::Prompt;
use crate::server;
use crate::unchecked;
use crate::unchecked::OsvUnchecked;
use crate::unchecked::Unchecked;

/// How often [`Lock::acquire`] tries, and how long it waits between tries. Arbitrary: 100 ms in
/// all is far longer than starting a process takes, and nothing a user would notice.
const LOCK_TRIES: u32 = 5;
const LOCK_RETRY: Duration = Duration::from_millis(20);

/// How many sweep or fix folders may share one start second before the run gives up. Arbitrary:
/// sweeps run one at a time and each takes seconds at least, so two is already rare.
const SAME_SECOND_LIMIT: u32 = 100;

/// What the sweep is doing, for a progress display.
#[derive(Debug)]
pub enum Progress<'a> {
    /// Starting a target: `mac`, `github:owner/name` or `server:name`.
    Target {
        /// The target.
        target: &'a str,
    },
    /// Listing what is installed.
    Inventory,
    /// Fetching advisories for this many packages and products.
    Advisories {
        /// OSV packages.
        packages: usize,
        /// NVD products, each its own paced request.
        products: usize,
    },
    /// Fetching NVD CVEs for one product.
    Product {
        /// Its position, from 1.
        done: usize,
        /// How many there are.
        total: usize,
        /// The product.
        product: &'a str,
    },
    /// The agent is running; `attempt` is 1, or 2 after rejected findings.
    Agent {
        /// The agent.
        agent: AgentKind,
        /// Which try this is.
        attempt: u8,
        /// How many advisories the bundle gives it.
        advisories: usize,
    },
}

impl Progress<'_> {
    /// How far into its target the sweep is when this event arrives, in thousandths, for a
    /// progress bar: listing what is installed up to 50, fetching advisories up to 500, and the
    /// agent the rest, from 800 on its second try. Each NVD product has an equal slot, and its
    /// event, sent as its request starts, is the middle of the slot: the bar moves as each
    /// request starts instead of only after it ends.
    ///
    /// The shares are rough and arbitrary, from sweeps of one Mac on 2026-11-08: listing
    /// takes seconds, NVD one paced request per product, the agent minutes. A bar that moves
    /// steadily matters more here than one that is exact; the agent's share is shown as
    /// [`open_ended`](Self::open_ended).
    pub fn thousandths(&self) -> usize {
        match self {
            Self::Target { .. } => 0,
            Self::Inventory => 20,
            Self::Advisories { .. } => 50,
            Self::Product { done, total, .. } => {
                50 + 450 * (2 * done).saturating_sub(1) / (2 * total.max(&1))
            }
            Self::Agent { attempt: 1, .. } => 500,
            Self::Agent { .. } => 800,
        }
    }

    /// Whether the step this event starts has no known length: the agent's run, which takes
    /// seconds or many minutes, so a progress bar shows it moving instead of filling.
    pub fn open_ended(&self) -> bool {
        matches!(self, Self::Agent { .. })
    }
}

impl fmt::Display for Progress<'_> {
    /// One line for a progress display: "sweeping mac", "NVD 3/12: openssl".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target { target } => write!(f, "sweeping {target}"),
            Self::Inventory => f.write_str("listing what is installed"),
            Self::Advisories { packages, products } => write!(
                f,
                "fetching advisories for {packages} packages and {products} NVD products"
            ),
            Self::Product {
                done,
                total,
                product,
            } => write!(f, "NVD {done}/{total}: {product}"),
            Self::Agent {
                agent,
                attempt: 1,
                advisories: 0,
            } => write!(f, "{agent} is reviewing the target"),
            Self::Agent {
                agent,
                attempt: 1,
                advisories: 1,
            } => write!(f, "{agent} is judging 1 advisory"),
            Self::Agent {
                agent,
                attempt: 1,
                advisories,
            } => write!(f, "{agent} is judging {advisories} advisories"),
            Self::Agent { agent, .. } => write!(f, "{agent} is fixing its rejected findings"),
        }
    }
}

/// The result of a sweep, as written to `report.json`.
#[derive(Debug, Serialize)]
pub struct Report {
    /// When the sweep started.
    pub started: Timestamp,
    /// When it finished.
    pub finished: Timestamp,
    /// What was swept: `mac`, `github:owner/name` or `server:name`.
    pub target: String,
    /// The agent that judged the advisories.
    pub agent: AgentKind,
    /// How many components went into the bundle.
    pub components: usize,
    /// How many advisories went into the bundle.
    pub advisories: usize,
    /// How many advisories were fetched for the target but left out of the bundle because
    /// Vigil's version comparison shows that none of their components is affected: every
    /// version is outside the affected ranges, or an NVD CVE names the product only as a
    /// platform. Advisories in CISA's KEV catalog count like any other.
    pub out_of_range: usize,
    /// The affected components, most severe first.
    pub findings: Vec<ReportFinding>,
    /// Findings of the target's last report that this sweep did not find and could not check
    /// again, because a source that could have produced them failed (see [`Unchecked`]). Each
    /// stays open, as that report saved it, until a sweep checks it. Every reader of a report's
    /// `findings` reads these too: they are open findings, only not checked again.
    pub carried: Vec<CarriedFinding>,
    /// Risky settings and files, most severe first.
    pub issues: Vec<ReportIssue>,
    /// What changed since this target's last sweep with a verdict; `None` without a verdict
    /// now or then.
    pub changes: Option<Changes>,
    /// Whether this is the target's first sweep with a verdict, so everything in it is new.
    /// False when an earlier report exists but could not be read: then nothing is known to
    /// be new, and nothing is notified again.
    ///
    /// With `changes` it says one of three things, and only these: changes known
    /// (`changes: Some`, `first_verdict: false`), first verdict (`None`, `true`), or not known
    /// (`None`, `false`, which is also every report without a verdict). `sweep_target` sets
    /// both in one place. They stay two fields, not one enum, because they are the shape of
    /// `report.json` that its readers use.
    pub first_verdict: bool,
    /// What could not be checked: failed sources, unknown products, tools not installed.
    pub problems: Vec<String>,
    /// The sources that failed for this target, as a record readers can act on: while it is
    /// not empty the target is not clear. `problems` says why each failed.
    pub unchecked: Unchecked,
    /// Why the agent's verdict is missing, when it is.
    pub failure: Option<String>,
    /// The target's folder: bundle, agent logs and this report.
    pub dir: PathBuf,
}

impl Report {
    /// An empty report for `target`, finished now.
    fn new(started: Timestamp, target: String, agent: AgentKind, dir: PathBuf) -> Self {
        Self {
            started,
            finished: Timestamp::now(),
            target,
            agent,
            components: 0,
            advisories: 0,
            out_of_range: 0,
            findings: Vec::new(),
            carried: Vec::new(),
            issues: Vec::new(),
            changes: None,
            first_verdict: false,
            problems: Vec::new(),
            unchecked: Unchecked::default(),
            failure: None,
            dir,
        }
    }
}

/// A finding with the component it names spelled out.
#[derive(Debug, Serialize)]
pub struct ReportFinding {
    /// Its key, the same in every sweep that finds it.
    pub key: FindingKey,
    /// One line naming it: the advisories, the component and where it was found.
    pub title: String,
    /// The component's name, without its ecosystem (`lodash`, `openssl`).
    pub name: String,
    /// Where it was found, one line (`lockfile ~/code/shop/package-lock.json`).
    pub place: String,
    /// When a sweep of this target first found it, in the run of reports that has had it
    /// since.
    pub first_seen: Timestamp,
    /// The agent's finding.
    #[serde(flatten)]
    pub finding: Finding,
    /// The affected component.
    pub installed: Component,
    /// When the primary advisory was last modified, when its source says.
    pub modified: Option<Timestamp>,
    /// The user's dismissal, while it holds.
    pub dismissed: Option<Dismissal>,
}

/// An issue with its key.
#[derive(Debug, Serialize)]
pub struct ReportIssue {
    /// Its key, the same in every sweep that finds it.
    pub key: FindingKey,
    /// One line naming it: its subject.
    pub title: String,
    /// The setting key or file path it is about.
    pub name: String,
    /// When a sweep of this target first found it.
    pub first_seen: Timestamp,
    /// The agent's issue.
    #[serde(flatten)]
    pub issue: Issue,
    /// The user's dismissal.
    pub dismissed: Option<Dismissal>,
}

/// Sweeps the targets `targets` names (this Mac, the repositories in `config.repos`, the
/// servers in `config.servers`) one after the other, with the agent named in `config`, and
/// returns one report per target swept.
///
/// Blocks for the whole sweep: inventory commands, `gh api` calls, every feed request (NVD is
/// paced, so the first sweep of a Mac with a hundred Homebrew formulae takes over ten minutes
/// without an API key), and the agent, which has no time limit. Calls `progress` as it goes.
///
/// Stops when `cancel` is set: between targets, between NVD requests, and while the agent runs
/// (stopping it and everything it started). The targets already swept keep their reports; the
/// folder of the one it stopped in is removed.
///
/// # Errors
///
/// Fails before anything runs when `targets` names no configured target, and before any agent
/// runs when no agent is configured or found, another sweep is running, or the sweep folder
/// cannot be written; and stops when a prompt or bundle cannot be
/// read or written; [`SweepError::Cancelled`] when cancelled. Failures of one target (a
/// repository that cannot be read, the agent, its findings, the report files) are recorded in
/// that target's report instead.
pub fn sweep(
    data_dir: &DataDir,
    config: &Config,
    targets: Targets<'_>,
    progress: &mut dyn FnMut(Progress<'_>),
    cancel: &Cancel,
) -> Result<Vec<Report>, SweepError> {
    if let Targets::Only(only) = targets
        && !configured_targets(config).iter().any(|(t, _)| t == only)
    {
        return Err(SweepError::UnknownTarget {
            target: only.to_owned(),
        });
    }
    let wanted = |target: &str| match targets {
        Targets::All => true,
        Targets::Only(only) => only == target,
    };
    let (agent, located) = locate_configured(config)?;
    let sweeps = data_dir.sweeps_dir();
    let _lock = Lock::acquire(&sweeps)?;
    let mut notes = Vec::new();
    // Best effort: a folder an interrupted sweep left is untidy, not a reason to stop.
    if let Err(e) = cancel::clean_up_holding_lock(data_dir) {
        notes.push(format!(
            "cleaning up after an interrupted sweep: {}",
            error_chain(&e)
        ));
    }
    let dir = create_sweep_dir(&sweeps, Timestamp::now())?;
    let running = cancel::mark_running(&dir)?;
    // After the sweep folder exists, so a failure to create it does not lose the one note an
    // edited prompt gets. A sweep that ends without a report (cancelled, a target error, or no
    // target run) still loses it; the `.default.md` file it points to stays as the lasting
    // record.
    prompts::update(data_dir, &mut notes);

    let feeds = Feeds::new(data_dir, nvd_access(&mut notes));
    let kev = match feeds.kev() {
        Ok(kev) => Some(kev),
        Err(e) => {
            notes.push(format!(
                "CISA KEV catalog, so known_exploited is unknown and crowded OS packages keep \
                 every advisory: {}",
                error_chain(&e)
            ));
            None
        }
    };
    let dismissals = Dismissals::load(data_dir).unwrap_or_else(|e| {
        notes.push(format!(
            "dismissals, so dismissed findings show again: {}",
            error_chain(&e)
        ));
        Dismissals::default()
    });
    let shared = Shared {
        data_dir,
        dismissals: &dismissals,
        sources: Sources {
            feeds: &feeds,
            history: config.history,
            kev: kev.as_ref(),
            cancel,
        },
        agent,
        located: &located,
        notes: &notes,
    };

    let mut reports = Vec::new();
    let mut each_target = || {
        cancel.check()?;
        if wanted("mac") {
            progress(Progress::Target { target: "mac" });
            progress(Progress::Inventory);
            let mac = collect_mac(&config.project_dirs);
            reports.push(shared.sweep_target(&dir, mac, progress)?);
        }
        for repo in config.repos.iter().filter(|r| wanted(&repo_target(r))) {
            cancel.check()?;
            reports.push(shared.sweep_repo(&dir, repo, progress)?);
        }
        for server in config.servers.iter().filter(|s| wanted(&server_target(s))) {
            cancel.check()?;
            reports.push(shared.sweep_server(&dir, server, progress)?);
        }
        Ok(())
    };
    match each_target() {
        Ok(()) => Ok(reports),
        Err(SweepError::Cancelled) => {
            let finished: Vec<PathBuf> = reports.iter().map(|r| r.dir.clone()).collect();
            // Ignored: the cancel is what the caller asked about. A folder that could not be
            // removed keeps the marker, and the next sweep or app start removes it.
            drop(running.remove_unfinished(&finished));
            Err(SweepError::Cancelled)
        }
        Err(e) => Err(e),
    }
}

/// What a sweep should raise a notification for: the findings and issues that are critical
/// or high, not dismissed, and new since their target's last sweep with a verdict, one line
/// per component (as the popover counts them) and per issue. A component with one such finding
/// reads `target: title`, one with more `target: component version, place: N advisories`. On a
/// target's first sweep with a verdict, every such one is new; when the last report could not
/// be read, none is.
pub fn alerts(reports: &[Report]) -> Vec<String> {
    let mut alerts = Vec::new();
    for report in reports.iter().filter(|r| r.failure.is_none()) {
        let new = |key: FindingKey| match &report.changes {
            Some(changes) => changes.new.contains(&key),
            None => report.first_verdict,
        };
        let serious = |severity: Severity| severity <= Severity::High;
        let findings: Vec<&ReportFinding> = report
            .findings
            .iter()
            .filter(|f| f.dismissed.is_none() && serious(f.finding.severity) && new(f.key))
            .collect();
        let components = by_component(&report.target, &findings)
            .into_iter()
            .map(|group| {
                let installed = &group[0].installed;
                if group.len() == 1 {
                    return group[0].title.clone();
                }
                plain(&format!(
                    "{} {}, {}: {} advisories",
                    group_name(installed),
                    installed.version,
                    installed.found_in,
                    group.len()
                ))
            });
        let issues = report
            .issues
            .iter()
            .filter(|i| i.dismissed.is_none() && serious(i.issue.severity) && new(i.key))
            .map(|i| i.title.clone());
        alerts.extend(
            components
                .chain(issues)
                .map(|t| format!("{}: {t}", report.target)),
        );
    }
    alerts
}

/// Which targets a sweep covers.
#[derive(Debug, Clone, Copy)]
pub enum Targets<'a> {
    /// This Mac, every configured repository and every configured server.
    All,
    /// One of them, by its report name: `mac`, `github:owner/name` or `server:name`.
    Only(&'a str),
}

/// The report names of every configured target, in the order a sweep takes them: `mac`, then
/// `github:owner/name` for each repository, then `server:name` for each server.
pub fn target_names(config: &Config) -> Vec<String> {
    configured_targets(config)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// Every configured target, in sweep order, by report name and folder name.
pub(crate) fn configured_targets(config: &Config) -> Vec<(String, String)> {
    let mut targets = vec![("mac".to_owned(), "mac".to_owned())];
    for repo in &config.repos {
        targets.push((repo_target(repo), github_dir_name(repo)));
    }
    for server in &config.servers {
        targets.push((server_target(server), server_dir_name(server)));
    }
    targets
}

/// A repository's report name, `github:owner/name`, matched exactly by `--target`.
fn repo_target(repo: &RepoSlug) -> String {
    format!("github:{repo}")
}

/// A server's report name, `server:name`.
fn server_target(server: &Server) -> String {
    format!("server:{}", server.name)
}

fn server_dir_name(server: &Server) -> String {
    format!("server-{}", server.name)
}

/// What every target of one sweep shares.
#[derive(Debug)]
struct Shared<'a> {
    data_dir: &'a DataDir,
    dismissals: &'a Dismissals,
    sources: Sources<'a>,
    agent: AgentKind,
    located: &'a Located,
    /// Problems that hold for every target (no NVD key, no KEV catalog).
    notes: &'a [String],
}

/// Where advisories come from, and which of them count.
#[derive(Debug, Clone, Copy)]
struct Sources<'a> {
    feeds: &'a Feeds,
    history: History,
    /// The KEV catalog, or `None` when it could not be read.
    kev: Option<&'a Kev>,
    /// Whether to stop.
    cancel: &'a Cancel,
}

/// One target, collected and ready for its bundle.
#[derive(Debug)]
struct Collected {
    /// The report's `target`: `mac`, `github:owner/name` or `server:name`.
    target: String,
    /// Its folder in the sweep folder.
    dir_name: String,
    /// What the prompt calls it: "this Mac (macOS 27.2)".
    title: String,
    /// Which prompt it uses.
    prompt: Prompt,
    components: Vec<Component>,
    /// Extra bundle files, by path in the bundle.
    files: Vec<(String, String)>,
    /// The settings an issue may name.
    settings: Vec<String>,
    problems: Vec<String>,
}

/// This Mac's inventory as a target.
fn collect_mac(project_dirs: &[PathBuf]) -> Collected {
    let inventory = Inventory::collect_mac(project_dirs);
    let mut problems: Vec<String> = inventory.problems.iter().map(error_chain).collect();
    if !inventory.not_installed.is_empty() {
        let tools = inventory.not_installed.join(", ");
        problems.push(format!("not installed, so not checked: {tools}"));
    }
    Collected {
        target: "mac".to_owned(),
        dir_name: "mac".to_owned(),
        title: target_name(&inventory),
        prompt: Prompt::Mac,
        components: inventory.components,
        files: Vec::new(),
        settings: Vec::new(),
        problems,
    }
}

/// `github-<owner>--<name>`. Owners never contain `--`, so the first one ends the owner and
/// no two repositories share a folder.
fn github_dir_name(repo: &RepoSlug) -> String {
    format!("github-{}", repo.to_string().replacen('/', "--", 1))
}

impl Shared<'_> {
    /// Collects `repo` with `gh` and sweeps it. A repository that cannot be read gets a report
    /// with the reason and no agent run.
    fn sweep_repo(
        &self,
        sweep_dir: &Path,
        repo: &RepoSlug,
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> Result<Report, SweepError> {
        let target = repo_target(repo);
        let dir_name = github_dir_name(repo);
        progress(Progress::Target { target: &target });
        progress(Progress::Inventory);
        let started = Timestamp::now();
        let collected = match github::collect("gh", repo) {
            Ok(collected) => collected,
            Err(e) => return self.uncollected(&sweep_dir.join(dir_name), started, target, &e),
        };
        let collected = Collected {
            target,
            dir_name,
            title: format!("the GitHub repository {repo}"),
            prompt: Prompt::GitHub,
            components: collected.components,
            files: collected.files,
            settings: collected.settings,
            problems: collected.problems,
        };
        self.sweep_target(sweep_dir, collected, progress)
    }

    /// Collects `server` over ssh and sweeps it. A server that cannot be read gets a report
    /// with the reason and no agent run.
    fn sweep_server(
        &self,
        sweep_dir: &Path,
        server: &Server,
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> Result<Report, SweepError> {
        let target = server_target(server);
        // `server-` keeps a server named `mac` from sharing the Mac's folder.
        let dir_name = server_dir_name(server);
        progress(Progress::Target { target: &target });
        progress(Progress::Inventory);
        let started = Timestamp::now();
        let collected = match server::collect("ssh", server) {
            Ok(collected) => collected,
            Err(e) => return self.uncollected(&sweep_dir.join(dir_name), started, target, &e),
        };
        let collected = Collected {
            target,
            dir_name,
            title: format!("the server {}", server.name),
            prompt: Prompt::Server,
            components: collected.components,
            files: collected.files,
            settings: Vec::new(),
            problems: collected.problems,
        };
        self.sweep_target(sweep_dir, collected, progress)
    }

    /// Saves the report of a target that could not be collected: the reason, and no agent run.
    fn uncollected(
        &self,
        dir: &Path,
        started: Timestamp,
        target: String,
        error: &impl std::error::Error,
    ) -> Result<Report, SweepError> {
        fs::create_dir_all(dir).map_err(|source| SweepError::Write {
            path: dir.to_owned(),
            source,
        })?;
        let mut report = Report::new(started, target, self.agent, dir.to_owned());
        report.failure = Some(plain(&error_chain(error)));
        save_report(dir, &mut report);
        Ok(report)
    }

    /// Fetches the target's advisories, writes its bundle, runs the agent and saves the
    /// report in `<sweep>/<target folder>`.
    fn sweep_target(
        &self,
        sweep_dir: &Path,
        collected: Collected,
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> Result<Report, SweepError> {
        let started = Timestamp::now();
        let dir = sweep_dir.join(&collected.dir_name);
        let mut problems = self.notes.to_vec();
        problems.extend(collected.problems);
        let fetched = fetch(self.sources, &collected.components, &mut problems, progress);
        self.sources.cancel.check()?;
        let entries: Vec<_> = fetched
            .linked
            .iter()
            .map(|(advisory, components)| bundle::Entry {
                advisory,
                components,
            })
            .collect();
        let prompt = prompts::render(self.data_dir, collected.prompt, &collected.title)?;
        let contents = bundle::Contents {
            prompt: &prompt,
            components: &collected.components,
            entries: &entries,
            files: &collected.files,
            settings: &collected.settings,
        };
        let known = bundle::write(&dir.join("bundle"), &contents, self.sources.kev)?;

        let judged = self.judge(&dir, &known, progress);
        // A cancelled agent fails its run; that is no verdict to record.
        self.sources.cancel.check()?;
        let (verdict, failure) = match judged {
            Ok(verdict) => (verdict, None),
            Err(failure) => (Verdict::default(), Some(plain(&failure))),
        };
        let (mut findings, mut issues) = self.keyed(
            &collected.target,
            &collected.components,
            verdict,
            &fetched.linked,
        );
        // Each keeps the first-seen time the target's last report gave it, or is new now.
        let sweeps = self.data_dir.sweeps_dir();
        let seen = lifecycle::first_seen(&sweeps, &collected.dir_name).unwrap_or_else(|e| {
            problems.push(format!(
                "when findings were first seen: {}",
                error_chain(&e)
            ));
            BTreeMap::new()
        });
        let first = |key: FindingKey| seen.get(&key).copied().unwrap_or(started);
        for f in &mut findings {
            f.first_seen = first(f.key);
        }
        for i in &mut issues {
            i.first_seen = first(i.key);
        }
        // Without a verdict nothing is carried or compared: the lifecycle skips such a report.
        let (carried, changes, first_verdict) = if failure.is_some() {
            (Vec::new(), None, false)
        } else {
            let dir_name = &collected.dir_name;
            let carried = self.carry_over(dir_name, &fetched.unchecked, &findings, &mut problems);
            let shown: Vec<(FindingKey, bool)> = (findings.iter())
                .map(|f| (f.key, f.dismissed.is_some()))
                .chain(carried.iter().map(|c| (c.key, c.dismissed.is_some())))
                .chain(issues.iter().map(|i| (i.key, i.dismissed.is_some())))
                .collect();
            let (changes, first_verdict) = self.changes(dir_name, &shown, &mut problems);
            (carried, changes, first_verdict)
        };

        let mut report = Report::new(started, collected.target, self.agent, dir.clone());
        report.components = collected.components.len();
        report.advisories = entries.len();
        report.out_of_range = fetched.out_of_range;
        report.findings = findings;
        report.carried = carried;
        report.issues = issues;
        report.changes = changes;
        report.first_verdict = first_verdict;
        report.problems = problems.iter().map(|p| plain(p)).collect();
        report.unchecked = fetched.unchecked;
        report.failure = failure;
        save_report(&dir, &mut report);
        Ok(report)
    }

    /// The findings of the target's newest readable report with a verdict that this sweep,
    /// which found `findings`, could not check again ([`lifecycle::carried_over`]); none, with a
    /// note, when the report it picked cannot be read again whole.
    fn carry_over(
        &self,
        dir_name: &str,
        unchecked: &Unchecked,
        findings: &[ReportFinding],
        problems: &mut Vec<String>,
    ) -> Vec<CarriedFinding> {
        let found = findings.iter().map(|f| f.key).collect();
        let sweeps = self.data_dir.sweeps_dir();
        lifecycle::carried_over(&sweeps, dir_name, unchecked, &found, self.dismissals)
            .unwrap_or_else(|e| {
                problems.push(format!(
                    "the last sweep's findings, so those of failed sources were not kept: {}",
                    error_chain(&e)
                ));
                Vec::new()
            })
    }

    /// What changed since the target's last sweep with a verdict, for a verdict that shows
    /// `shown` (each key and whether it is dismissed), and whether this is the target's first
    /// verdict: the two fields of [`Report`] that only make sense together. Not known, with a
    /// note, when the earlier reports cannot be read.
    fn changes(
        &self,
        dir_name: &str,
        shown: &[(FindingKey, bool)],
        problems: &mut Vec<String>,
    ) -> (Option<Changes>, bool) {
        let all = shown.iter().map(|(key, _)| *key).collect();
        let active = shown
            .iter()
            .filter(|(_, d)| !d)
            .map(|(key, _)| *key)
            .collect();
        let sweeps = self.data_dir.sweeps_dir();
        match Changes::since_last(&sweeps, dir_name, &active, &all) {
            Ok(changes) => {
                let first_verdict = changes.is_none();
                (changes, first_verdict)
            }
            Err(e) => {
                problems.push(format!("changes since the last sweep: {}", error_chain(&e)));
                (None, false)
            }
        }
    }

    /// Runs the agent and validates its findings, once more with the problems if they are
    /// rejected. Returns why there is no verdict otherwise.
    ///
    /// A `findings.json` that passes counts even when the agent then exits non-zero: the verdict is
    /// in the file. An agent that cannot start, or exits non-zero without a file, is not retried,
    /// since the same command would fail the same way.
    fn judge(
        &self,
        dir: &Path,
        known: &Known,
        progress: &mut dyn FnMut(Progress<'_>),
    ) -> Result<Verdict, String> {
        let agent = self.agent;
        let bundle = dir.join("bundle");
        let findings_path = bundle.join("findings.json");
        let rejected_path = bundle.join("findings.rejected.json");
        let mut prompt = PROMPT_LINE.to_owned();
        let mut last = Vec::new();
        for attempt in 1..=2 {
            progress(Progress::Agent {
                agent,
                attempt,
                advisories: known.advisories.len(),
            });
            let log = dir.join(format!("agent-{attempt}.log"));
            let status = agent
                .run(
                    &agent.sweep_command(self.located, &bundle, &prompt),
                    &log,
                    self.sources.cancel,
                )
                .map_err(|e| error_chain(&e))?;
            let (problems, previous) = match fs::read_to_string(&findings_path) {
                Ok(text) => match findings::validate(&text, known) {
                    Ok(valid) => return Ok(valid),
                    Err(problems) => (problems, "was rejected and moved to findings.rejected.json"),
                },
                Err(_) if !status.success() => {
                    return Err(format!(
                        "{agent} exited with {status} without writing findings.json; see {} (is it \
                         logged in?)",
                        log.display()
                    ));
                }
                Err(e) => (
                    vec![format!("findings.json could not be read: {e}")],
                    "is missing",
                ),
            };
            // Kept for the agent to correct, and so that it cannot pass for the next answer.
            if let Err(e) = fs::rename(&findings_path, &rejected_path)
                && e.kind() != io::ErrorKind::NotFound
            {
                return Err(format!("cannot set aside the rejected findings.json: {e}"));
            }
            prompt = format!(
                "{PROMPT_LINE} Your findings.json {previous}; fix these problems and write \
                 findings.json again:\n- {}",
                problems
                    .iter()
                    .map(|p| plain(p))
                    .collect::<Vec<_>>()
                    .join("\n- ")
            );
            last = problems;
        }
        Err(format!(
            "{agent}'s findings were rejected twice: {}",
            last.join("; ")
        ))
    }

    /// Keys the verdict's findings and issues, marks the dismissed ones, and sorts each list
    /// most severe first.
    fn keyed(
        &self,
        target: &str,
        components: &[Component],
        verdict: Verdict,
        fetched: &[Linked],
    ) -> (Vec<ReportFinding>, Vec<ReportIssue>) {
        let modified: BTreeMap<&str, Option<Timestamp>> = fetched
            .iter()
            .map(|(a, _)| (a.id.as_str(), a.modified))
            .collect();
        let primaries: Vec<(&str, &Component)> = verdict
            .findings
            .iter()
            .map(|v| (v.advisory.as_str(), &components[v.component]))
            .collect();
        let keys = finding_keys(target, &primaries);
        let mut findings: Vec<ReportFinding> = verdict
            .findings
            .into_iter()
            .zip(keys)
            .map(|(valid, key)| {
                let modified = modified.get(valid.advisory.as_str()).copied().flatten();
                let installed = components[valid.component].clone();
                // Names, versions and paths come from the target; one plain line.
                let title = plain(&format!(
                    "{} in {} {}, {}",
                    valid.finding.advisories.join(", "),
                    component_name(&installed),
                    installed.version,
                    installed.found_in
                ));
                let name = match &installed.lookup {
                    Lookup::Package(p) => p.name.clone(),
                    Lookup::Product(p) => p.to_string(),
                };
                ReportFinding {
                    key,
                    title,
                    name: plain(&name),
                    place: plain(&installed.found_in.to_string()),
                    // Set by the caller from the last report; see `sweep_target`.
                    first_seen: Timestamp::UNIX_EPOCH,
                    finding: valid.finding,
                    installed,
                    modified,
                    dismissed: self.dismissals.get(key, modified).cloned(),
                }
            })
            .collect();
        findings.sort_by_key(|f| f.finding.severity);
        let mut issues: Vec<ReportIssue> = verdict
            .issues
            .into_iter()
            .map(|issue| {
                // Data, not the `Display` text, so rewording that keeps every key.
                let (kind, name) = match &issue.subject {
                    Subject::Setting(key) => ("setting", key),
                    Subject::File(path) => ("file", path),
                };
                let key = FindingKey::new(&[target, kind, name]);
                ReportIssue {
                    key,
                    title: plain(&issue.subject.to_string()),
                    name: plain(name),
                    first_seen: Timestamp::UNIX_EPOCH,
                    issue,
                    dismissed: self.dismissals.get(key, None).cloned(),
                }
            })
            .collect();
        issues.sort_by_key(|i| i.issue.severity);
        (findings, issues)
    }
}

/// The key of each finding, given as its primary advisory and component: the target, the
/// advisory, the component's lookup and where it was found. These parts come from data, not
/// display text, so rewording a message keeps every key. An OS package is keyed by its source
/// package alone: the binary packages built from it change with installs and renames
/// (`libssl3` became `libssl3t64`) while the finding stays. Findings that would share a key
/// (two versions of one package in one lockfile, both affected) get the version too, so each
/// has its own; a fix of one then changes the other's key, which is accepted.
fn finding_keys(target: &str, findings: &[(&str, &Component)]) -> Vec<FindingKey> {
    let parts: Vec<[String; 3]> = findings
        .iter()
        .map(|(advisory, c)| {
            let lookup = match &c.lookup {
                Lookup::Package(p) => format!("{}:{}", p.ecosystem.osv_name(), p.name),
                Lookup::Product(p) => format!("product:{p}"),
            };
            let found_in = match &c.found_in {
                FoundIn::MacOs => "macos".to_owned(),
                FoundIn::HomebrewFormula { name } => format!("homebrew_formula:{name}"),
                FoundIn::HomebrewCask { token } => format!("homebrew_cask:{token}"),
                FoundIn::Rustup { toolchain } => format!("rustup:{toolchain}"),
                FoundIn::CargoInstall => "cargo_install".to_owned(),
                FoundIn::Node => "node".to_owned(),
                FoundIn::NpmGlobal => "npm_global".to_owned(),
                FoundIn::Python => "python".to_owned(),
                FoundIn::UvTool => "uv_tool".to_owned(),
                FoundIn::Pipx => "pipx".to_owned(),
                FoundIn::VersionManager { manager, path } => path_key(manager.name(), path),
                FoundIn::Lockfile { path } => path_key("lockfile", path),
                FoundIn::OsPackage { .. } => "os_package".to_owned(),
                FoundIn::DependencyGraph { repo } => format!("dependency_graph:{repo}"),
            };
            [(*advisory).to_owned(), lookup, found_in]
        })
        .collect();
    let mut counts: BTreeMap<&[String; 3], usize> = BTreeMap::new();
    for p in &parts {
        *counts.entry(p).or_default() += 1;
    }
    parts
        .iter()
        .zip(findings)
        .map(|(p, (_, c))| {
            let [advisory, lookup, found_in] = p;
            let mut key = vec![
                target,
                advisory.as_str(),
                lookup.as_str(),
                found_in.as_str(),
            ];
            if counts[p] > 1 {
                key.push(&c.version);
            }
            FindingKey::new(&key)
        })
        .collect()
}

/// `<kind>:<path>`. A path that is not UTF-8 is spelled by its bytes, as `<kind>-bytes:<hex>`:
/// lossy text would give two such paths one key.
fn path_key(kind: &str, path: &Path) -> String {
    match path.to_str() {
        Some(path) => format!("{kind}:{path}"),
        None => format!("{kind}-bytes:{:x?}", path.as_os_str().as_encoded_bytes()),
    }
}

/// Creates `<sweeps>/<start time>`, or `<start time>-2` and so on when an earlier sweep
/// started in the same second.
fn create_sweep_dir(sweeps: &Path, started: Timestamp) -> Result<PathBuf, SweepError> {
    create_unique_dir(sweeps, &started.strftime("%Y%m%dT%H%M%SZ").to_string())
}

/// Creates `<parent>/<stamp>`, or `<stamp>-2` and so on when that exists: a run never reuses
/// an earlier run's folder, whose files it would mix with its own.
pub(crate) fn create_unique_dir(parent: &Path, stamp: &str) -> Result<PathBuf, SweepError> {
    let mut last = None;
    for n in 1..=SAME_SECOND_LIMIT {
        let name = if n == 1 {
            stamp.to_owned()
        } else {
            format!("{stamp}-{n}")
        };
        let path = parent.join(name);
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some((path, e)),
            Err(source) => return Err(SweepError::Write { path, source }),
        }
    }
    let (path, source) = last.expect("the loop runs at least once");
    Err(SweepError::Write { path, source })
}

/// The API key from the Keychain, or anonymous access with a note when it cannot be read. Read
/// on every sweep: a Mac inventory always has macOS itself, an NVD product.
fn nvd_access(problems: &mut Vec<String>) -> NvdAccess {
    NvdAccess::from_keychain().unwrap_or_else(|e| {
        problems.push(format!(
            "NVD API key, so NVD is queried without one: {}",
            error_chain(&e)
        ));
        NvdAccess::Anonymous
    })
}

/// A target's advisories, ready for its bundle.
#[derive(Debug)]
struct Fetched {
    /// Every advisory with the components whose lookup returned it, by index, and how its
    /// affected versions relate to each one's version; out-of-range pairs already left out.
    linked: Vec<Linked>,
    /// How many advisories the version comparison left out.
    out_of_range: usize,
    /// The sources that failed.
    unchecked: Unchecked,
}

/// Fetches every advisory for the inventory (see [`Fetched`]; [`matching::keep_candidates`]
/// leaves out the out-of-range pairs), noting in `problems` what could not be fetched or was
/// fetched only from the cache.
fn fetch(
    sources: Sources<'_>,
    components: &[Component],
    problems: &mut Vec<String>,
    progress: &mut dyn FnMut(Progress<'_>),
) -> Fetched {
    let mut packages: BTreeMap<OsvQuery, Vec<usize>> = BTreeMap::new();
    let mut products: BTreeMap<String, (Product, Vec<usize>)> = BTreeMap::new();
    for (i, component) in components.iter().enumerate() {
        match &component.lookup {
            Lookup::Package(p) => packages
                .entry(OsvQuery::new(p.clone(), &component.version))
                .or_default()
                .push(i),
            Lookup::Product(p) => {
                let entry = products
                    .entry(p.to_string())
                    .or_insert_with(|| (p.clone(), Vec::new()));
                entry.1.push(i);
            }
        }
    }
    progress(Progress::Advisories {
        packages: packages.len(),
        products: products.len(),
    });

    let (mut linked, osv) = fetch_osv(sources, components, &packages, problems);
    let (nvd_linked, nvd) = fetch_nvd(sources, components, &products, problems, progress);
    linked.extend(nvd_linked);
    let out_of_range = matching::keep_candidates(&mut linked);
    Fetched {
        linked,
        out_of_range,
        unchecked: Unchecked {
            kev: sources.kev.is_none(),
            osv,
            nvd,
        },
    }
}

/// OSV advisories, linked by the queries that returned them, and what of OSV failed. The
/// record's own `affected` names do not decide the link: OSV matches names the way each
/// ecosystem compares them (PyPI's `Django` is `django`), and the query result already carries
/// that match.
fn fetch_osv(
    sources: Sources<'_>,
    components: &[Component],
    packages: &BTreeMap<OsvQuery, Vec<usize>>,
    problems: &mut Vec<String>,
) -> (Vec<Linked>, Option<OsvUnchecked>) {
    if packages.is_empty() {
        return (Vec::new(), None);
    }
    let list: Vec<OsvQuery> = packages.keys().cloned().collect();
    let osv = match sources.feeds.osv(&list, sources.history, sources.kev) {
        Ok(osv) => osv,
        Err(e) => {
            problems.push(format!("OSV: {}", error_chain(&e)));
            return (Vec::new(), Some(OsvUnchecked::All));
        }
    };
    for failure in &osv.failures {
        problems.push(format!("OSV record: {}", error_chain(&failure.error)));
    }
    if let Some(first) = osv.stale.first() {
        let ids: Vec<&str> = osv.stale.iter().map(|s| s.id.as_str()).collect();
        problems.push(format!(
            "OSV could not be asked for {}, so their cached copies were used: {}",
            ids.join(", "),
            error_chain(&first.error)
        ));
    }
    for crowded in &osv.crowded {
        let package = &crowded.query.package;
        let version = crowded.query.version.as_deref().unwrap_or("any version");
        problems.push(format!(
            "{} ({}) {version} matches {} OSV advisories; only the {} for a CVE in CISA KEV \
             were kept",
            package.name,
            package.ecosystem.osv_name(),
            crowded.matched,
            crowded.kept,
        ));
    }
    let unchecked = (!osv.failures.is_empty()).then(|| {
        let packages = (osv.failures.iter())
            .flat_map(|f| &f.packages)
            .map(|p| unchecked::package_key(&p.ecosystem.osv_name(), &p.name))
            .collect();
        OsvUnchecked::Packages(packages)
    });
    let mut fetched = Vec::with_capacity(osv.advisories.len());
    for OsvAdvisory { advisory, queries } in osv.advisories {
        let record = OsvRecord::parse(&advisory.record);
        let mut matches = BTreeMap::new();
        for query in &queries {
            for &i in packages.get(query).into_iter().flatten() {
                let verdict = record.verdict(&query.package, &components[i].version);
                matches.insert(i, verdict);
            }
        }
        fetched.push((advisory, matches));
    }
    (fetched, unchecked)
}

/// NVD CVEs per product, merged by CVE id, each linked to the components of its products with
/// the verdict of its CPE matches (see `feeds::cpe`), and the products whose CVEs could not be
/// fetched and had none cached. What failed, came from the cache, or names a product NVD does
/// not know goes into `problems`, one line per kind where many products share it.
fn fetch_nvd(
    sources: Sources<'_>,
    components: &[Component],
    products: &BTreeMap<String, (Product, Vec<usize>)>,
    problems: &mut Vec<String>,
    progress: &mut dyn FnMut(Progress<'_>),
) -> (Vec<Linked>, BTreeSet<String>) {
    let mut found: BTreeMap<String, Linked> = BTreeMap::new();
    let mut gaps = NvdGaps::default();
    for (done, (name, (product, indexes))) in products.iter().enumerate() {
        // The caller sees the request and stops; what was fetched is not used.
        if sources.cancel.is_cancelled() {
            break;
        }
        progress(Progress::Product {
            done: done + 1,
            total: products.len(),
            product: name,
        });
        let cves = match sources.feeds.nvd(product, sources.history) {
            Ok(cves) => cves,
            Err(e) => {
                gaps.fail(name, &e, problems);
                continue;
            }
        };
        match &cves.stale {
            Some(e) => gaps.use_cache(name, e),
            // No CVEs can mean a clean product or a name NVD does not know; tell them apart.
            None if cves.advisories.is_empty() => match sources.feeds.nvd_product_known(product) {
                Ok(true) => {}
                Ok(false) => gaps.unknown.push(name),
                Err(e) => {
                    problems.push(format!("NVD product check {name}: {}", error_chain(&e)));
                }
            },
            None => {}
        }
        for advisory in cves.advisories {
            let matches = cpe::Matches::parse(&advisory.record);
            let verdicts: Vec<(usize, Match)> = indexes
                .iter()
                .map(|&i| (i, matches.verdict(product, &components[i].version)))
                .collect();
            let entry = found
                .entry(advisory.id.clone())
                .or_insert_with(|| (advisory, BTreeMap::new()));
            entry.1.extend(verdicts);
        }
    }
    gaps.note(problems);
    (found.into_values().collect(), gaps.failed)
}

/// What NVD could not answer for a target's products.
#[derive(Debug, Default)]
struct NvdGaps<'a> {
    /// Products with nothing fetched and nothing cached in the last week.
    failed: BTreeSet<String>,
    /// Those of them not asked because NVD refused an earlier request, noted together.
    refused: Vec<&'a str>,
    /// The first reason a cached copy was used, and every product it was used for.
    stale: Option<(String, Vec<&'a str>)>,
    /// Products NVD's CPE dictionary does not know.
    unknown: Vec<&'a str>,
}

impl<'a> NvdGaps<'a> {
    fn fail(&mut self, name: &'a str, error: &FeedError, problems: &mut Vec<String>) {
        self.failed.insert(name.to_owned());
        if matches!(error, FeedError::NvdRefused { .. }) {
            self.refused.push(name);
        } else {
            problems.push(format!("NVD product {name}: {}", error_chain(error)));
        }
    }

    fn use_cache(&mut self, name: &'a str, error: &FeedError) {
        let (_, names) = self
            .stale
            .get_or_insert_with(|| (error_chain(error), Vec::new()));
        names.push(name);
    }

    fn note(&self, problems: &mut Vec<String>) {
        if !self.refused.is_empty() {
            problems.push(format!(
                "NVD refused a request (its rate limit), so it was not asked about {}, which \
                 had nothing recent cached; add an NVD API key, or check the one set",
                self.refused.join(", ")
            ));
        }
        if let Some((reason, names)) = &self.stale {
            problems.push(format!(
                "NVD could not be asked about {}, so their cached CVEs were used: {reason}",
                names.join(", ")
            ));
        }
        if !self.unknown.is_empty() {
            problems.push(format!(
                "NVD knows no product named {}, so these were not checked",
                self.unknown.join(", ")
            ));
        }
    }
}

/// The agent the config names, found on the login shell's `PATH`, set to run the model the
/// config gives it. Sweeps and fixes both start their agent through this, so neither can
/// forget the model.
///
/// # Errors
///
/// [`SweepError::NoAgent`] when none is chosen, [`SweepError::AgentNotFound`] when the login
/// shell does not find it, and the error from running the shell.
pub(crate) fn locate_configured(config: &Config) -> Result<(AgentKind, Located), SweepError> {
    let agent = config.agent.ok_or(SweepError::NoAgent)?;
    let located = agent
        .locate(config.models.get(&agent))?
        .ok_or(SweepError::AgentNotFound { agent })?;
    Ok((agent, located))
}

/// `text` as one line: `\n`, `\r` and `\t` become spaces, and every other control or
/// invisible character ([`is_forging`]) becomes U+FFFD. For messages that quote the agent (a
/// rejected id, a serde error naming its field) and reach the terminal, `report.json` or the
/// agent's next prompt.
pub(crate) fn plain(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if is_forging(c) => '\u{fffd}',
            c => c,
        })
        .collect()
}

/// "this Mac (macOS 27.2)", or "this Mac" when the version is unknown.
fn target_name(inventory: &Inventory) -> String {
    inventory
        .components
        .iter()
        .find(|c| matches!(c.found_in, FoundIn::MacOs))
        .map_or_else(
            || "this Mac".to_owned(),
            |c| format!("this Mac (macOS {})", c.version),
        )
}

/// Writes the report files, or notes in the report why they could not be written: the verdict
/// is worth more than its files, so a report that cannot be saved is still returned.
fn save_report(dir: &Path, report: &mut Report) {
    if let Err(e) = write_report(dir, report) {
        report
            .problems
            .push(format!("report files: {}", error_chain(&e)));
    }
}

/// Writes `report.json` and `report.md`, each to a temporary name, synced, and then renamed,
/// so neither a reader nor a crash leaves half a report.
fn write_report(dir: &Path, report: &Report) -> Result<(), SweepError> {
    let json = serde_json::to_string_pretty(report).map_err(|e| SweepError::Write {
        path: dir.join("report.json"),
        source: io::Error::other(e),
    })?;
    // Markdown first: if it fails, no `report.json` is left that lacks the failure the returned
    // report carries.
    for (name, text) in [
        ("report.md", report_markdown(report)),
        ("report.json", json),
    ] {
        let path = dir.join(name);
        paths::replace_file(&path, &text).map_err(|source| SweepError::Write { path, source })?;
    }
    Ok(())
}

/// The report for a person: findings first, most severe first, then what was not checked.
///
/// Agent text, component names and paths are escaped (see [`escape`]), so none of them can add
/// headings, link syntax or code blocks, or send terminal escape sequences. A bare URL stays
/// visible text, though a renderer that autolinks may make it clickable.
pub fn report_markdown(report: &Report) -> String {
    let mut out = format!(
        "# Sweep of {} ({})\n\nAgent: {}. {} components, {} advisories checked, {} left out \
         as out of range.\n\n",
        report.target,
        report.started,
        report.agent,
        report.components,
        report.advisories,
        report.out_of_range
    );
    out.push_str(&headline(report));
    if let Some(changes) = &report.changes {
        out.push_str(&format!(
            "Since the sweep of {}: {} new, {} resolved.\n\n",
            changes.since,
            changes.new.len(),
            changes.resolved.len()
        ));
    }
    let (findings, dismissed_findings): (Vec<&ReportFinding>, Vec<&ReportFinding>) =
        report.findings.iter().partition(|f| f.dismissed.is_none());
    let (issues, dismissed_issues): (Vec<&ReportIssue>, Vec<&ReportIssue>) =
        report.issues.iter().partition(|i| i.dismissed.is_none());
    for group in by_component(&report.target, &findings) {
        let first = group[0];
        let advisories = if group.len() == 1 {
            "1 advisory".to_owned()
        } else {
            format!("{} advisories", group.len())
        };
        out.push_str(&format!(
            "## {} {} {}\n\nFound in {}. {advisories}.\n\n",
            first.finding.severity.to_string().to_uppercase(),
            escape(&group_name(&first.installed)),
            escape(&first.installed.version),
            escape(&first.installed.found_in.to_string()),
        ));
        for f in group {
            out.push_str(&finding_markdown(f.key, &f.finding));
        }
    }
    if !issues.is_empty() {
        out.push_str("## Settings and files\n\n");
        for issue in issues {
            out.push_str(&issue_markdown(issue.key, &issue.issue));
        }
    }
    out.push_str(&carried_markdown(&report.carried));
    let dismissed = dismissed_findings
        .iter()
        .map(|f| {
            let what = &f.title;
            let reason = &f
                .dismissed
                .as_ref()
                .expect("partitioned on dismissed")
                .reason;
            (f.key, f.finding.severity, what, reason)
        })
        .chain(dismissed_issues.iter().map(|i| {
            let what = &i.title;
            let reason = &i
                .dismissed
                .as_ref()
                .expect("partitioned on dismissed")
                .reason;
            (i.key, i.issue.severity, what, reason)
        }));
    let mut dismissed = dismissed.peekable();
    if dismissed.peek().is_some() {
        out.push_str("## Dismissed\n\n");
        for (key, severity, what, reason) in dismissed {
            out.push_str(&format!(
                "- {severity} {} (key {key}): {}\n",
                escape(what),
                escape(reason)
            ));
        }
        out.push('\n');
    }
    if !report.problems.is_empty() {
        out.push_str("## Not checked\n\n");
        for problem in &report.problems {
            out.push_str(&format!("- {}\n", escape(problem)));
        }
    }
    out
}

/// The section listing the findings carried over from an earlier sweep; nothing without any.
fn carried_markdown(carried: &[CarriedFinding]) -> String {
    if carried.is_empty() {
        return String::new();
    }
    let mut out = "## Not checked again\n\nA source that could have found these failed in this \
                   sweep (see the end), so each stays open as an earlier sweep found it.\n\n"
        .to_owned();
    for c in carried {
        let dismissed = if c.dismissed.is_some() {
            ", dismissed"
        } else {
            ""
        };
        out.push_str(&format!(
            "- {} {} (key {}{dismissed}), found by the sweep of {}\n",
            c.severity,
            escape(&c.title),
            c.key,
            c.carried_from
        ));
    }
    out.push('\n');
    out
}

/// The sentence under the title: no verdict, a clean result, or a clean result with gaps.
fn headline(report: &Report) -> String {
    if let Some(failure) = &report.failure {
        return format!("**No verdict:** {}\n\n", escape(failure));
    }
    let nothing_found = report.findings.iter().all(|f| f.dismissed.is_some())
        && report.carried.iter().all(|c| c.dismissed.is_some())
        && report.issues.iter().all(|i| i.dismissed.is_some());
    match (nothing_found, report.problems.is_empty()) {
        (true, true) => "Nothing affected or risky was found.\n\n".to_owned(),
        (true, false) => "Nothing affected or risky was found in what was checked; some things \
                          were not checked (see the end).\n\n"
            .to_owned(),
        (false, _) => String::new(),
    }
}

/// Groups the findings of `target` by component, by the rule the popover uses
/// ([`lifecycle::component_key`]), in the order of each group's first finding. Findings are
/// sorted most severe first, so each group starts with its worst finding and the groups come
/// worst first.
fn by_component<'a>(target: &str, findings: &[&'a ReportFinding]) -> Vec<Vec<&'a ReportFinding>> {
    let key = |f: &ReportFinding| {
        let installed = &f.installed;
        let serialized = "a component serializes to JSON, as its report does";
        lifecycle::component_key(
            target,
            &serde_json::to_value(&installed.lookup).expect(serialized),
            &installed.version,
            &serde_json::to_value(&installed.found_in).expect(serialized),
        )
    };
    let mut groups: Vec<(ComponentKey, Vec<&ReportFinding>)> = Vec::new();
    for &f in findings {
        let key = key(f);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, group)) => group.push(f),
            None => groups.push((key, vec![f])),
        }
    }
    groups.into_iter().map(|(_, group)| group).collect()
}

/// A group's name: the place's own (a Homebrew formula, which can hold several products), or
/// the component's.
fn group_name(component: &Component) -> String {
    component
        .found_in
        .install_name()
        .map_or_else(|| component_name(component), str::to_owned)
}

fn finding_markdown(key: FindingKey, finding: &Finding) -> String {
    let exploited = if finding.known_exploited {
        ", known exploited"
    } else {
        ""
    };
    let mut out = format!(
        "### {} {} ({}{exploited})\n\nKey: {key}\n\nWhy: {}\n\nEvidence: {}\n\nFix: {}\n",
        finding.severity,
        escape(&finding.advisories.join(", ")),
        finding.confidence,
        escape(&finding.explanation),
        escape(&finding.evidence),
        escape(&finding.fix.summary),
    );
    out.push_str(&commands_markdown(&finding.fix));
    out
}

fn issue_markdown(key: FindingKey, issue: &Issue) -> String {
    let mut out = format!(
        "### {} {}\n\nKey: {key}\n\nWhy: {}\n\nEvidence: {}\n\nFix: {}\n",
        issue.severity,
        escape(&issue.subject.to_string()),
        escape(&issue.explanation),
        escape(&issue.evidence),
        escape(&issue.fix.summary),
    );
    out.push_str(&commands_markdown(&issue.fix));
    out
}

/// The fix's commands as one `sh` block, then a blank line. The steps are left out: the
/// commands are what to run, and the steps belong to the fix plan (spec, "Fix flow").
fn commands_markdown(fix: &Fix) -> String {
    let mut out = String::new();
    if !fix.commands.is_empty() {
        // Longer than any backtick run in the commands, so none can close the block early.
        let longest = fix
            .commands
            .iter()
            .flat_map(|c| c.split(|ch| ch != '`'))
            .map(str::len)
            .max()
            .unwrap_or(0);
        let fence = "`".repeat(longest.max(2) + 1);
        out.push_str(&format!("\n{fence}sh\n"));
        for command in &fix.commands {
            out.push_str(&plain(command));
            out.push('\n');
        }
        out.push_str(&format!("{fence}\n"));
    }
    out.push('\n');
    out
}

/// Makes `text` one plain Markdown line: whitespace runs (line breaks too) become one space,
/// control and invisible formatting characters ([`is_forging`]) become U+FFFD, and the
/// characters that start inline Markdown (code, emphasis, links, HTML) are backslash-escaped.
/// Each use sits after a label or a heading marker, never at the start of a line, so no block
/// syntax (a heading, a list) can begin.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, word) in text.split_whitespace().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        for c in word.chars() {
            if is_forging(c) {
                out.push('\u{fffd}');
                continue;
            }
            if matches!(
                c,
                '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '~' | '|' | '#' | '&'
            ) {
                out.push('\\');
            }
            out.push(c);
        }
    }
    out
}

fn component_name(component: &Component) -> String {
    match &component.lookup {
        Lookup::Package(p) => format!("{} ({})", p.name, p.ecosystem.osv_name()),
        Lookup::Product(p) => p.to_string(),
    }
}

/// Renders an error and its sources as `outer: inner`.
pub fn error_chain(error: &(impl std::error::Error + ?Sized)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(e) = source {
        text.push_str(&format!(": {e}"));
        source = e.source();
    }
    text
}

/// The running sweep's hold on `.lock` in the sweeps folder. The system releases it when the
/// file closes: on drop, or when the process ends, so a crashed sweep leaves nothing stale.
/// The file is never deleted: a sweep that deleted it could let the next one lock a new file of
/// the same name while a third still holds the old one.
#[derive(Debug)]
pub(crate) struct Lock {
    _file: fs::File,
}

impl Lock {
    pub(crate) fn acquire(sweeps: &Path) -> Result<Self, SweepError> {
        let path = sweeps.join(".lock");
        let write_err = |source| SweepError::Write {
            path: path.clone(),
            source,
        };
        fs::create_dir_all(sweeps).map_err(|source| SweepError::Write {
            path: sweeps.to_owned(),
            source,
        })?;
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(write_err)?;
        // A few tries, briefly apart: a process another thread is starting holds a copy of
        // every open file until it runs its program, so a lock released a moment ago can still
        // look held. A sweep that really holds it holds it for minutes.
        for _ in 0..LOCK_TRIES {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(fs::TryLockError::WouldBlock) => thread::sleep(LOCK_RETRY),
                Err(fs::TryLockError::Error(e)) => return Err(write_err(e)),
            }
        }
        Err(SweepError::Busy { lock: path })
    }
}

/// The sweeps lock, for a command outside a sweep that asks NVD (`vigil advisories`). NVD
/// requests are paced within one process only, so one made while a sweep runs would add to
/// the sweep's and can push both past NVD's rate limit; holding the lock makes them take
/// turns. Released on drop.
#[derive(Debug)]
#[must_use = "the lock is released as soon as this is dropped"]
pub struct SweepsLock {
    _lock: Lock,
}

impl SweepsLock {
    /// Takes the lock a sweep takes.
    ///
    /// # Errors
    ///
    /// [`SweepError::Busy`] while a sweep or fix holds it, and [`SweepError::Write`] when the
    /// lock file cannot be opened.
    pub fn acquire(data_dir: &DataDir) -> Result<Self, SweepError> {
        Lock::acquire(&data_dir.sweeps_dir()).map(|lock| Self { _lock: lock })
    }
}

/// Error that stops a sweep before the agent runs.
#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    /// `--target` names no configured target.
    #[error(
        "{target} is not a configured target; use mac, github:<owner>/<name> or \
         server:<name> from config.toml"
    )]
    UnknownTarget {
        /// The name given.
        target: String,
    },
    /// config.toml names no agent.
    #[error(
        "no agent chosen; set `agent` in config.toml (claude, grok, codex, gemini or opencode)"
    )]
    NoAgent,
    /// The chosen agent is not installed.
    #[error(
        "{agent} is not installed (the login shell cannot find it); install it or choose another \
         agent"
    )]
    AgentNotFound {
        /// The agent.
        agent: AgentKind,
    },
    /// Looking the agent up failed.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// The sweep was cancelled, by the user or the app as it quit.
    #[error("the sweep was cancelled")]
    Cancelled,
    /// Another sweep, fix or Fix all holds the lock.
    #[error("a sweep or fix is running (it holds {}); wait for it to finish", lock.display())]
    Busy {
        /// The lock file.
        lock: PathBuf,
    },
    /// The bundle could not be written.
    #[error(transparent)]
    Bundle(#[from] BundleError),
    /// A sweep file could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A sweep file or folder could not be written.
    #[error("cannot write {}", path.display())]
    Write {
        /// The file or folder.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    use serde_json::Value;
    use serde_json::json;

    use super::*;
    use crate::inventory::VersionManager;

    #[test]
    fn no_agent_is_found_until_one_is_chosen() {
        let err = locate_configured(&Config::default_for_tests()).unwrap_err();
        assert!(matches!(err, SweepError::NoAgent), "{err}");
    }

    #[test]
    fn target_names_list_the_mac_then_repositories_then_servers() {
        let text = "[github]\nrepos = [\"o/a\", \"o/b\"]\n\
                    [[servers]]\nname = \"web\"\nssh = \"web\"\n";
        let config =
            Config::from_text(Path::new("/c/config.toml"), text, Path::new("/home")).unwrap();
        assert_eq!(
            target_names(&config),
            ["mac", "github:o/a", "github:o/b", "server:web"]
        );
    }
    use crate::feeds::Endpoints;
    use crate::feeds::test_server::Request;
    use crate::feeds::test_server::TestServer;
    use crate::package::Ecosystem;
    use crate::package::Package;

    fn component(lookup: &str, version: &str) -> Component {
        let lookup = if lookup.contains(':') {
            Lookup::Package(lookup.parse().unwrap())
        } else {
            Lookup::Product(lookup.parse().unwrap())
        };
        Component {
            lookup,
            version: version.to_owned(),
            found_in: FoundIn::MacOs,
        }
    }

    /// OSV knows GHSA-1 for lodash and PYSEC-1 for django (whose record spells it `Django`);
    /// NVD knows four CVEs for curl, CVE-9 for every version, CVE-8 for versions before 7, and
    /// CVE-7 and CVE-6 for versions before 6, and nothing for a made-up product that is also
    /// missing from the CPE dictionary.
    fn feeds_server() -> TestServer {
        TestServer::start(|request: &Request| match request.path() {
            "/v1/querybatch" => {
                let body: Value = serde_json::from_str(&request.body).unwrap();
                let results: Vec<Value> = body["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| {
                        let id = match q["package"]["name"].as_str().unwrap() {
                            "lodash" => "GHSA-1",
                            _ => "PYSEC-1",
                        };
                        json!({"vulns": [{"id": id, "modified": "2026-01-01T00:00:00Z"}]})
                    })
                    .collect();
                (200, json!({ "results": results }).to_string())
            }
            "/v1/vulns/GHSA-1" => (200, osv_record("GHSA-1", "npm", "lodash")),
            "/v1/vulns/PYSEC-1" => (200, osv_record("PYSEC-1", "PyPI", "Django")),
            "/rest/json/cves/2.0" => {
                let curl =
                    request.query("virtualMatchString").as_deref() == Some("cpe:2.3:*:*:curl");
                let before = |id: &str, version: &str| {
                    json!({"cve": {
                        "id": id,
                        "published": "2026-01-01T00:00:00.000",
                        "configurations": [{"nodes": [{"cpeMatch": [{
                            "vulnerable": true,
                            "criteria": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": version,
                        }]}]}],
                    }})
                };
                let cves = if curl {
                    json!([
                        {"cve": {"id": "CVE-9", "published": "2026-01-01T00:00:00.000"}},
                        before("CVE-8", "7.0.0"),
                        before("CVE-7", "6.0.0"),
                        before("CVE-6", "6.0.0"),
                    ])
                } else {
                    json!([])
                };
                let page = json!({
                    "startIndex": 0,
                    "totalResults": cves.as_array().unwrap().len(),
                    "timestamp": "2026-11-01T00:00:00.000",
                    "vulnerabilities": cves
                });
                (200, page.to_string())
            }
            "/rest/json/cpes/2.0" => (200, json!({"totalResults": 0}).to_string()),
            other => (404, format!("unexpected {other}")),
        })
    }

    fn osv_record(id: &str, ecosystem: &str, name: &str) -> String {
        json!({
            "id": id,
            "modified": "2026-01-01T00:00:00Z",
            "affected": [{"package": {"ecosystem": ecosystem, "name": name}}]
        })
        .to_string()
    }

    #[test]
    fn links_each_advisory_to_its_components_and_notes_unknown_products() {
        let server = feeds_server();
        let tmp = tempfile::tempdir().unwrap();
        let feeds = Feeds::with_endpoints(
            tmp.path().to_owned(),
            NvdAccess::Anonymous,
            Endpoints {
                osv: server.url.clone(),
                nvd: server.url.clone(),
                kev: server.url.clone(),
            },
        )
        .without_pacing();
        let inventory = Inventory {
            components: vec![
                component("npm:lodash", "4.17.20"),
                component("curl", "8.0.0"),
                component("npm:lodash", "4.17.21"),
                component("made-up-product", "1"),
                component("pypi:django", "4.2"),
                component("curl", "6.5.0"),
            ],
            ..Inventory::default()
        };
        let history = Config::default_for_tests().history;
        let kev = Kev::from_ids(&["CVE-7"]);
        let mut problems = Vec::new();
        let mut seen = Vec::new();
        let cancel = Cancel::new();
        let sources = Sources {
            feeds: &feeds,
            history,
            kev: Some(&kev),
            cancel: &cancel,
        };
        let Fetched {
            linked: fetched,
            out_of_range: dropped,
            unchecked,
        } = fetch(sources, &inventory.components, &mut problems, &mut |p| {
            seen.push(format!("{p:?}"));
        });
        assert_eq!(unchecked, Unchecked::default(), "every source answered");
        assert_eq!(
            fetched[0].1[&0],
            Match::Unknown("an affected entry gives neither ranges nor versions".to_owned()),
            "each pair carries its verdict"
        );
        assert_eq!(dropped, 2, "CVE-6 and CVE-7");
        let linked: Vec<(&str, Vec<usize>)> = fetched
            .iter()
            .map(|(a, c)| (a.id.as_str(), c.keys().copied().collect()))
            .collect();
        assert_eq!(
            linked,
            [
                ("GHSA-1", vec![0, 2]),
                ("PYSEC-1", vec![4]),
                ("CVE-8", vec![5]),
                ("CVE-9", vec![1, 5]),
            ],
            "linked by query, so `Django` reaches django; an NVD CVE only to the versions it \
             may affect, so CVE-6 and CVE-7, which affect neither curl, are left out, though \
             CVE-7 is exploited in the wild"
        );
        assert_eq!(
            problems,
            ["NVD knows no product named made-up-product, so these were not checked"]
        );
        assert!(seen[0].contains("packages: 2, products: 2"), "{seen:?}");
        assert!(seen[1].contains("done: 1, total: 2"), "{seen:?}");

        // A cancel stops before the next NVD product, each a paced request.
        let stopped = Cancel::new();
        stopped.cancel();
        let mut seen = Vec::new();
        let cancelled = Sources {
            cancel: &stopped,
            ..sources
        };
        fetch(
            cancelled,
            &inventory.components,
            &mut Vec::new(),
            &mut |p| {
                seen.push(format!("{p:?}"));
            },
        );
        assert!(!seen.iter().any(|s| s.starts_with("Product")), "{seen:?}");

        // Without the KEV catalog the same advisories are left out.
        let unknown = Sources {
            kev: None,
            ..sources
        };
        let without = fetch(unknown, &inventory.components, &mut Vec::new(), &mut |_| {});
        assert_eq!(without.out_of_range, 2);
        assert!(
            without.unchecked.kev,
            "a missing catalog is a failed source"
        );
    }

    #[test]
    fn failed_sources_are_recorded_by_name_and_noted_once_per_kind() {
        // OSV is down, and NVD refuses everything after its first answer, a rate limit.
        let server = TestServer::start(|request: &Request| match request.path() {
            "/v1/querybatch" => (500, "down".to_owned()),
            _ => (429, "slow down".to_owned()),
        });
        let tmp = tempfile::tempdir().unwrap();
        let endpoints = Endpoints {
            osv: server.url.clone(),
            nvd: server.url.clone(),
            kev: server.url.clone(),
        };
        let feeds = Feeds::with_endpoints(tmp.path().to_owned(), NvdAccess::Anonymous, endpoints)
            .without_pacing();
        let components = [
            component("npm:lodash", "4.17.20"),
            component("curl", "8.0.0"),
            component("openssl", "3.0.0"),
            component("xz", "5.6.0"),
            component("zlib", "1.3"),
        ];
        // xz's CVEs were fetched three hours ago, so the cache stands in for it.
        let fetched_at = Timestamp::now() - jiff::SignedDuration::from_hours(3);
        fs::create_dir_all(tmp.path().join("nvd")).unwrap();
        let cache = json!({"fetched_at": fetched_at, "cves": {}});
        fs::write(tmp.path().join("nvd/xz.json"), cache.to_string()).unwrap();
        let cancel = Cancel::new();
        let kev = Kev::from_ids(&[]);
        let sources = Sources {
            feeds: &feeds,
            history: Config::default_for_tests().history,
            kev: Some(&kev),
            cancel: &cancel,
        };
        let mut problems = Vec::new();
        let fetched = fetch(sources, &components, &mut problems, &mut |_| {});
        assert!(fetched.linked.is_empty());
        let names = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect();
        assert_eq!(
            fetched.unchecked,
            Unchecked {
                kev: false,
                osv: Some(OsvUnchecked::All),
                nvd: names(&["curl", "openssl", "zlib"]),
            }
        );
        assert_eq!(problems.len(), 4, "{problems:?}");
        assert!(problems[0].starts_with("OSV: "), "{problems:?}");
        assert!(
            problems[1].starts_with("NVD product curl: "),
            "{problems:?}"
        );
        assert_eq!(
            problems[2],
            "NVD refused a request (its rate limit), so it was not asked about openssl, zlib, \
             which had nothing recent cached; add an NVD API key, or check the one set"
        );
        assert!(
            problems[3].starts_with(
                "NVD could not be asked about xz, so their cached CVEs were used: NVD refused"
            ),
            "{problems:?}"
        );
    }

    #[test]
    fn finding_keys_survive_upgrades_and_package_lists_but_not_collisions() {
        let os = |version: &str, packages: &[&str]| Component {
            found_in: FoundIn::OsPackage {
                packages: packages.iter().map(|p| (*p).to_owned()).collect(),
            },
            lookup: Lookup::Package(Package {
                ecosystem: Ecosystem::Debian { release: 12 },
                name: "openssl".to_owned(),
            }),
            version: version.to_owned(),
        };
        let before = finding_keys("server:web", &[("DSA-1", &os("3.0.1", &["libssl3"]))]);
        let after = finding_keys(
            "server:web",
            &[("DSA-1", &os("3.0.2", &["libssl3t64", "openssl"]))],
        );
        assert_eq!(
            before, after,
            "a version bump or a renamed binary package keeps the key"
        );
        assert_ne!(
            before,
            finding_keys("server:db", &[("DSA-1", &os("3.0.1", &[]))])
        );
        assert_ne!(
            before,
            finding_keys("server:web", &[("DSA-2", &os("3.0.1", &[]))])
        );

        let lock = |version: &str, path: &str| Component {
            found_in: FoundIn::Lockfile {
                path: PathBuf::from(path),
            },
            ..component("crates.io:syn", version)
        };
        let (one, two) = (
            lock("1.0.109", "/p/Cargo.lock"),
            lock("2.0.1", "/p/Cargo.lock"),
        );
        let keys = finding_keys("mac", &[("GHSA-1", &one), ("GHSA-1", &two)]);
        assert_ne!(keys[0], keys[1], "two versions in one lockfile");
        let other = lock("1.0.109", "/q/Cargo.lock");
        let keys = finding_keys("mac", &[("GHSA-1", &one), ("GHSA-1", &other)]);
        assert_ne!(keys[0], keys[1], "one version in two lockfiles");
        assert_eq!(
            keys[0],
            finding_keys("mac", &[("GHSA-1", &one)])[0],
            "no collision, no version"
        );

        let nvm = |version: &str| Component {
            found_in: FoundIn::VersionManager {
                manager: VersionManager::Nvm,
                path: PathBuf::from(format!("/Users/me/.nvm/versions/node/v{version}")),
            },
            ..component("node.js", version)
        };
        let (old, new) = (nvm("22.22.2"), nvm("22.23.4"));
        let keys = finding_keys("mac", &[("CVE-1", &old), ("CVE-1", &new)]);
        assert_ne!(keys[0], keys[1], "two versions in one version manager");
        assert_eq!(
            keys[0],
            finding_keys("mac", &[("CVE-1", &old)])[0],
            "removing the other version keeps the key"
        );

        // Not UTF-8, and differing only in bytes that lossy text would replace alike.
        let raw = |bytes: &[u8]| Component {
            found_in: FoundIn::Lockfile {
                path: PathBuf::from(OsStr::from_bytes(bytes)),
            },
            ..component("crates.io:syn", "1.0.109")
        };
        let (ff, fe) = (raw(b"/p/\xff/Cargo.lock"), raw(b"/p/\xfe/Cargo.lock"));
        let keys = finding_keys("mac", &[("GHSA-1", &ff), ("GHSA-1", &fe)]);
        assert_ne!(keys[0], keys[1]);
    }

    fn report_finding(id: &str, severity: &str, kev: bool, lookup: &str) -> ReportFinding {
        ReportFinding {
            key: FindingKey::new(&[id, lookup]),
            title: format!("{id} in {lookup}"),
            name: lookup.to_owned(),
            place: "macOS".to_owned(),
            first_seen: Timestamp::UNIX_EPOCH,
            modified: None,
            dismissed: None,
            finding: serde_json::from_value(json!({
                "advisories": [id],
                "component": "c1",
                "severity": severity,
                "known_exploited": kev,
                "confidence": "confirmed",
                "evidence": "in range",
                "explanation": "Bad.",
                "fix": {"summary": "Upgrade", "steps": [], "commands": [format!("upgrade {id}")]}
            }))
            .unwrap(),
            installed: component(lookup, "1.0"),
        }
    }

    fn report(findings: Vec<ReportFinding>, problems: &[&str]) -> Report {
        Report {
            started: "2026-11-05T10:00:00Z".parse().unwrap(),
            finished: "2026-11-05T10:05:00Z".parse().unwrap(),
            target: "mac".into(),
            agent: AgentKind::Claude,
            components: 2,
            advisories: 1,
            out_of_range: 3,
            findings,
            carried: Vec::new(),
            issues: Vec::new(),
            changes: None,
            first_verdict: false,
            problems: problems.iter().map(|p| (*p).to_owned()).collect(),
            unchecked: Unchecked::default(),
            failure: None,
            dir: PathBuf::from("/tmp/s"),
        }
    }

    #[test]
    fn progress_moves_forward_through_a_target_and_marks_the_agent_open_ended() {
        let product = |done| Progress::Product {
            done,
            total: 4,
            product: "openssl",
        };
        let agent = |attempt| Progress::Agent {
            agent: AgentKind::Grok,
            attempt,
            advisories: 3,
        };
        let steps = [
            Progress::Target { target: "mac" },
            Progress::Inventory,
            Progress::Advisories {
                packages: 1,
                products: 4,
            },
            product(1),
            product(2),
            product(4),
            agent(1),
            agent(2),
        ];
        let shares: Vec<usize> = steps.iter().map(Progress::thousandths).collect();
        assert_eq!(shares, [0, 20, 50, 106, 218, 443, 500, 800]);
        let open: Vec<bool> = steps.iter().map(Progress::open_ended).collect();
        assert_eq!(open, [false, false, false, false, false, false, true, true]);

        let none = Progress::Product {
            done: 0,
            total: 0,
            product: "x",
        };
        assert_eq!(none.thousandths(), 50, "no products cannot divide by zero");
        let only = Progress::Product {
            done: 1,
            total: 1,
            product: "apple:macos",
        };
        assert_eq!(
            only.thousandths(),
            275,
            "a single product is half done as it starts"
        );
    }

    #[test]
    fn progress_reads_as_one_line_per_step() {
        let lines = [
            (Progress::Target { target: "mac" }, "sweeping mac"),
            (Progress::Inventory, "listing what is installed"),
            (
                Progress::Advisories {
                    packages: 3,
                    products: 2,
                },
                "fetching advisories for 3 packages and 2 NVD products",
            ),
            (
                Progress::Product {
                    done: 1,
                    total: 2,
                    product: "openssl",
                },
                "NVD 1/2: openssl",
            ),
            (
                Progress::Agent {
                    agent: AgentKind::Claude,
                    attempt: 1,
                    advisories: 154,
                },
                "claude is judging 154 advisories",
            ),
            (
                Progress::Agent {
                    agent: AgentKind::Claude,
                    attempt: 1,
                    advisories: 1,
                },
                "claude is judging 1 advisory",
            ),
            (
                Progress::Agent {
                    agent: AgentKind::Claude,
                    attempt: 1,
                    advisories: 0,
                },
                "claude is reviewing the target",
            ),
            (
                Progress::Agent {
                    agent: AgentKind::Claude,
                    attempt: 2,
                    advisories: 154,
                },
                "claude is fixing its rejected findings",
            ),
        ];
        for (progress, line) in lines {
            assert_eq!(progress.to_string(), line);
        }
    }

    #[test]
    fn alerts_are_new_open_and_critical_or_high() {
        let unread = report(
            vec![
                report_finding("GHSA-1", "critical", false, "npm:a"),
                report_finding("GHSA-2", "medium", false, "npm:b"),
            ],
            &[],
        );
        assert!(
            alerts(&[unread]).is_empty(),
            "the last report could not be read: none is new"
        );
        let first = Report {
            first_verdict: true,
            ..report(
                vec![
                    report_finding("GHSA-1", "critical", false, "npm:a"),
                    report_finding("GHSA-2", "medium", false, "npm:b"),
                ],
                &[],
            )
        };
        assert_eq!(
            alerts(&[first]),
            ["mac: GHSA-1 in npm:a"],
            "a first sweep: all are new"
        );

        let mut first = report(
            vec![
                report_finding("GHSA-1", "critical", false, "npm:a"),
                report_finding("GHSA-3", "high", false, "npm:c"),
                report_finding("GHSA-4", "high", false, "npm:d"),
            ],
            &[],
        );
        let [old, new, hidden] = [0, 1, 2].map(|i| first.findings[i].key);
        first.findings[2].dismissed = Some(Dismissal {
            reason: "x".to_owned(),
            at: Timestamp::UNIX_EPOCH,
            modified: None,
        });
        first.changes = Some(Changes {
            since: Timestamp::UNIX_EPOCH,
            new: vec![new, hidden],
            resolved: vec![],
        });
        assert!(!first.changes.as_ref().unwrap().new.contains(&old));
        let issue = |severity: &str, title: &str| ReportIssue {
            key: FindingKey::new(&[title]),
            title: title.to_owned(),
            name: "f".to_owned(),
            first_seen: Timestamp::UNIX_EPOCH,
            issue: serde_json::from_value(json!({
                "subject": {"file": "f"}, "severity": severity, "evidence": "e",
                "explanation": "x", "fix": {"summary": "s", "steps": [], "commands": []}
            }))
            .unwrap(),
            dismissed: None,
        };
        first.issues = vec![issue("high", "file f"), issue("low", "file g")];
        let changes = first.changes.as_mut().unwrap();
        changes.new.extend(first.issues.iter().map(|i| i.key));
        let failed = Report {
            failure: Some("agent".to_owned()),
            ..report(
                vec![report_finding("GHSA-9", "critical", false, "npm:z")],
                &[],
            )
        };
        assert_eq!(
            alerts(&[first, failed]),
            ["mac: GHSA-3 in npm:c", "mac: file f"]
        );
    }

    #[test]
    fn alerts_name_a_component_once_with_how_many_advisories() {
        let first = Report {
            first_verdict: true,
            ..report(
                vec![
                    report_finding("GHSA-1", "critical", false, "npm:a"),
                    report_finding("GHSA-2", "high", false, "npm:a"),
                    report_finding("GHSA-3", "low", false, "npm:a"),
                    report_finding("GHSA-4", "high", false, "npm:b"),
                ],
                &[],
            )
        };
        let name = component_name(&first.findings[0].installed);
        assert_eq!(
            alerts(&[first]),
            [
                format!("mac: {name} 1.0, macOS: 2 advisories"),
                "mac: GHSA-4 in npm:b".to_owned()
            ],
            "the low one is not counted"
        );

        // One Homebrew formula mapped to two NVD products is one upgrade: one line, under
        // the formula's name.
        let mut first = Report {
            first_verdict: true,
            ..report(
                vec![
                    report_finding("CVE-1", "high", false, "curl"),
                    report_finding("CVE-2", "high", false, "libcurl"),
                ],
                &[],
            )
        };
        for f in &mut first.findings {
            f.installed.found_in = FoundIn::HomebrewFormula {
                name: "curl".to_owned(),
            };
        }
        assert_eq!(
            alerts(&[first]),
            ["mac: curl 1.0, Homebrew formula curl: 2 advisories"]
        );
    }

    #[test]
    fn markdown_lists_findings_then_gaps() {
        let text = report_markdown(&report(
            vec![
                report_finding("GHSA-1", "high", true, "npm:lodash"),
                report_finding("GHSA-2", "medium", false, "npm:lodash"),
                report_finding("CVE-3", "low", false, "curl"),
            ],
            &["OSV: offline"],
        ));
        assert!(
            text.contains("## HIGH lodash (npm) 1.0\n\nFound in macOS. 2 advisories."),
            "{text}"
        );
        assert!(
            text.contains("### high GHSA-1 (confirmed, known exploited)"),
            "{text}"
        );
        assert!(text.contains("### medium GHSA-2 (confirmed)"), "{text}");
        assert!(
            text.contains("## LOW curl 1.0\n\nFound in macOS. 1 advisory."),
            "{text}"
        );
        assert!(text.contains("```sh\nupgrade GHSA-1\n```"), "{text}");
        assert_eq!(
            text.matches("## HIGH").count(),
            1,
            "one section per component"
        );
        let lodash = text.find("## HIGH lodash").unwrap();
        assert!(lodash < text.find("## LOW curl").unwrap(), "worst first");
        assert!(text.contains("## Not checked\n\n- OSV: offline"), "{text}");
        assert!(!text.contains("No affected"), "{text}");
    }

    /// An agent at `path` that reports GHSA-1 in component `c1` whenever the bundle has it,
    /// until the file `fixed` exists.
    fn ghsa_agent(path: &Path, fixed: &Path) -> Located {
        let finding = r#"{"findings": [{"advisories": ["GHSA-1"], "component": "c1",
            "severity": "critical", "known_exploited": false, "confidence": "confirmed",
            "evidence": "e", "explanation": "x",
            "fix": {"summary": "upgrade lodash", "steps": [], "commands": []}}]}"#;
        let script = format!(
            "#!/bin/sh\nif [ ! -e '{}' ] && grep -q GHSA-1 advisories.jsonl; then\n\
             echo '{finding}' > findings.json\nelse\necho '{{\"findings\": []}}' > findings.json\n\
             fi\n",
            fixed.display()
        );
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        Located::at(path)
    }

    /// Three sweeps of one Mac with lodash: OSV up, then down, then up again with lodash
    /// fixed.
    #[test]
    fn a_finding_of_a_failed_source_stays_open_until_a_sweep_checks_it() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering::Relaxed;

        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        // Relaxed: each flag is set between sweeps, before the request it decides is sent.
        let osv_down = Arc::new(AtomicBool::new(false));
        let server = {
            let osv_down = Arc::clone(&osv_down);
            TestServer::start(move |request: &Request| match request.path() {
                _ if osv_down.load(Relaxed) => (503, "down".to_owned()),
                "/v1/querybatch" => {
                    let vulns = json!([{"id": "GHSA-1", "modified": "2026-01-01T00:00:00Z"}]);
                    (200, json!({"results": [{"vulns": vulns}]}).to_string())
                }
                _ => (200, osv_record("GHSA-1", "npm", "lodash")),
            })
        };
        let endpoints = Endpoints {
            osv: server.url.clone(),
            nvd: server.url.clone(),
            kev: server.url.clone(),
        };
        let feeds = Feeds::with_endpoints(data_dir.feeds_dir(), NvdAccess::Anonymous, endpoints);
        let fixed = tmp.path().join("fixed");
        let located = ghsa_agent(&tmp.path().join("agent"), &fixed);
        let kev = Kev::from_ids(&[]);
        let cancel = Cancel::new();
        let dismissals = Dismissals::default();
        let shared = Shared {
            data_dir: &data_dir,
            dismissals: &dismissals,
            sources: Sources {
                feeds: &feeds,
                history: Config::default_for_tests().history,
                kev: Some(&kev),
                cancel: &cancel,
            },
            agent: AgentKind::Claude,
            located: &located,
            notes: &[],
        };
        let sweep = |stamp: &str| {
            let collected = Collected {
                target: "mac".to_owned(),
                dir_name: "mac".to_owned(),
                title: "this Mac".to_owned(),
                prompt: Prompt::Mac,
                components: vec![component("npm:lodash", "4.17.20")],
                files: Vec::new(),
                settings: Vec::new(),
                problems: Vec::new(),
            };
            let dir = data_dir.sweeps_dir().join(stamp);
            fs::create_dir_all(&dir).unwrap();
            shared.sweep_target(&dir, collected, &mut |_| {}).unwrap()
        };
        let config = Config::default_for_tests();
        let mac = || lifecycle::latest(&data_dir, &config).remove(0);

        let first = sweep("20261105T100000Z");
        let [found] = &first.findings[..] else {
            panic!("{:?}", first.findings)
        };
        let key = found.key;
        let run = json!({"key": key, "title": "lodash", "found": first.started, "target": "mac",
            "agent": "claude", "started": first.started, "finished": first.started,
            "exit_code": 0, "outcome": "fixed", "summary": "upgraded lodash",
            "pull_request": null, "confirmed": "asked", "dir": "/x"});
        fs::create_dir_all(data_dir.state_dir()).unwrap();
        fs::write(data_dir.state_dir().join("fixes.jsonl"), format!("{run}\n")).unwrap();

        // OSV is down: the finding is carried, stays open, and its fix waits.
        osv_down.store(true, Relaxed);
        let second = sweep("20261105T130000Z");
        assert!(second.findings.is_empty());
        assert_eq!(second.unchecked.osv, Some(OsvUnchecked::All));
        let carried: Vec<FindingKey> = second.carried.iter().map(|c| c.key).collect();
        assert_eq!(carried, [key]);
        let changes = second.changes.as_ref().unwrap();
        assert!(changes.resolved.is_empty() && changes.new.is_empty());
        let open = mac();
        assert_eq!(open.open.len(), 1, "still open");
        assert!(matches!(
            open.open[0].fix_state,
            Some(lifecycle::FixState::Reported { .. })
        ));
        assert!(
            open.fixed.is_empty(),
            "not confirmed by a sweep that could not check it"
        );

        // OSV is back and lodash is fixed: resolved, and the fix confirmed.
        osv_down.store(false, Relaxed);
        fs::write(&fixed, "").unwrap();
        let third = sweep("20261105T160000Z");
        assert!(third.carried.is_empty() && third.unchecked.is_empty());
        assert_eq!(third.changes.as_ref().unwrap().resolved, [key]);
        let done = mac();
        assert!(done.open.is_empty());
        assert_eq!(done.fixed.len(), 1);
        assert_eq!(done.fixed[0].key, key);
    }

    #[test]
    fn a_report_lists_and_saves_what_it_carried_over() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path().join("sweeps");
        let last = sweeps.join("20261105T100000Z/mac");
        fs::create_dir_all(&last).unwrap();
        let previous = report(vec![report_finding("CVE-3", "high", false, "curl")], &[]);
        write_report(&last, &previous).unwrap();
        let nvd_down = Unchecked {
            nvd: ["curl".to_owned()].into(),
            ..Unchecked::default()
        };
        let carried = lifecycle::carried_over(
            &sweeps,
            "mac",
            &nvd_down,
            &BTreeSet::new(),
            &Dismissals::default(),
        )
        .unwrap();
        assert_eq!(carried.len(), 1, "written by this build, read back whole");

        let mut now = report(Vec::new(), &["NVD product curl: refused"]);
        now.started = "2026-11-05T13:00:00Z".parse().unwrap();
        now.carried = carried;
        now.unchecked = nvd_down.clone();
        let text = report_markdown(&now);
        assert!(text.contains("## Not checked again"), "{text}");
        assert!(
            text.contains("found by the sweep of 2026-11-05T10:00:00Z"),
            "{text}"
        );
        assert!(!text.contains("Nothing affected"), "{text}");

        let dir = sweeps.join("20261105T130000Z/mac");
        fs::create_dir_all(&dir).unwrap();
        write_report(&dir, &now).unwrap();
        let json: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("report.json")).unwrap()).unwrap();
        assert_eq!(json["carried"][0]["carried_from"], "2026-11-05T10:00:00Z");
        assert_eq!(json["unchecked"]["nvd"], json!(["curl"]));
        let again = lifecycle::carried_over(
            &sweeps,
            "mac",
            &nvd_down,
            &BTreeSet::new(),
            &Dismissals::default(),
        )
        .unwrap();
        assert_eq!(
            again[0].carried_from, previous.started,
            "from the last check"
        );
    }

    #[test]
    fn markdown_lists_issues_in_their_own_section() {
        let issue: Issue = serde_json::from_value(json!({
            "subject": {"setting": "default_branch_protection"},
            "severity": "medium",
            "evidence": "Branch not protected",
            "explanation": "Anyone with push access can rewrite main.",
            "fix": {"summary": "Protect main", "steps": [], "commands": ["gh api -X PUT x"]}
        }))
        .unwrap();
        let with_issue = Report {
            issues: vec![ReportIssue {
                key: FindingKey::new(&["issue"]),
                title: "setting default_branch_protection".to_owned(),
                name: "default_branch_protection".to_owned(),
                first_seen: Timestamp::UNIX_EPOCH,
                issue,
                dismissed: None,
            }],
            ..report(vec![], &[])
        };
        let text = report_markdown(&with_issue);
        assert!(text.contains("## Settings and files\n\n"), "{text}");
        assert!(
            text.contains(&format!(
                "### medium setting default\\_branch\\_protection\n\nKey: {}\n\nWhy: Anyone",
                FindingKey::new(&["issue"])
            )),
            "{text}"
        );
        assert!(text.contains("```sh\ngh api -X PUT x\n```"), "{text}");
        assert!(
            !text.contains("Nothing affected or risky"),
            "an issue is a result: {text}"
        );
    }

    #[test]
    fn headline_says_what_the_verdict_covers() {
        let clean = report_markdown(&report(vec![], &[]));
        assert!(
            clean.contains("Nothing affected or risky was found."),
            "{clean}"
        );
        assert!(
            clean.contains("1 advisories checked, 3 left out as out of range."),
            "{clean}"
        );
        let json = serde_json::to_value(report(vec![], &[])).unwrap();
        assert_eq!(json["out_of_range"], 3, "report.json counts them too");
        let gaps = report_markdown(&report(vec![], &["OSV: offline"]));
        assert!(gaps.contains("some things were not checked"), "{gaps}");
        assert!(
            !gaps.contains("Nothing affected or risky was found."),
            "{gaps}"
        );
        let failed = Report {
            failure: Some("claude exited".into()),
            ..report(vec![], &[])
        };
        let failed = report_markdown(&failed);
        assert!(failed.contains("**No verdict:** claude exited"), "{failed}");
        assert!(!failed.contains("Nothing affected or risky"), "{failed}");
    }

    #[test]
    fn agent_text_cannot_forge_markdown() {
        let mut forged = report_finding("GHSA-1", "low", false, "npm:lodash");
        forged.finding.explanation = "Fine.\n\n## Not checked\n\n- [click](http://x) `x`".into();
        forged.finding.fix.commands = vec!["echo ```".into(), "echo ok".into()];
        let text = report_markdown(&report(vec![forged], &[]));
        assert!(
            text.contains("Fine. \\#\\# Not checked - \\[click\\](http://x) \\`x\\`"),
            "{text}"
        );
        assert!(!text.contains("\n## Not checked"), "{text}");
        assert!(
            text.contains("\n````sh\necho ```\necho ok\n````\n"),
            "{text}"
        );
        assert_eq!(escape("a\u{1b}[2Jb"), "a\u{fffd}\\[2Jb");
        assert_eq!(escape("  two\n words "), "two words");
        assert_eq!(escape("bidi \u{202e}x"), "bidi \u{fffd}x");
        assert_eq!(escape("&#x202e;"), "\\&\\#x202e;", "no entity reference");
        assert_eq!(plain("id \u{1b}[2J\n"), "id \u{fffd}[2J ");
        assert_eq!(plain("a\tb\r\nc\u{2028}d"), "a b  c\u{fffd}d");

        // The explanation follows a label, so it cannot start a list or a rule.
        let mut listy = report_finding("GHSA-1", "low", false, "npm:lodash");
        listy.finding.explanation = "- one\n1. two\n---".into();
        let text = report_markdown(&report(vec![listy], &[]));
        assert!(text.contains("\nWhy: - one 1. two ---\n"), "{text}");
    }

    #[test]
    fn a_report_that_cannot_be_saved_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        let mut report = report(vec![], &[]);
        save_report(&tmp.path().join("missing"), &mut report);
        assert_eq!(report.problems.len(), 1, "{:?}", report.problems);
        assert!(
            report.problems[0].starts_with("report files: cannot write"),
            "{:?}",
            report.problems
        );
        save_report(tmp.path(), &mut report);
        assert_eq!(report.problems.len(), 1, "saved");
        assert!(tmp.path().join("report.md").exists());
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = Lock::acquire(tmp.path()).unwrap();
        let err = Lock::acquire(tmp.path()).unwrap_err();
        assert!(matches!(err, SweepError::Busy { .. }), "{err:?}");
        assert!(
            err.to_string().contains("a sweep or fix is running"),
            "{err}"
        );
        drop(lock);
        // Other tests spawn processes. This check failed once in the full suite right after the
        // drop. The likely cause, not confirmed: a child another test is starting holds a copy of
        // every open file, the lock included, until it execs. So the lock may take a moment to
        // come free.
        let again = (0..100).find_map(|_| {
            Lock::acquire(tmp.path()).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            })
        });
        assert!(again.is_some(), "the lock is free once dropped");
    }

    #[test]
    fn sweeps_in_the_same_second_get_their_own_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let at: Timestamp = "2026-11-05T10:00:00Z".parse().unwrap();
        let first = create_sweep_dir(tmp.path(), at).unwrap();
        let second = create_sweep_dir(tmp.path(), at).unwrap();
        let third = create_sweep_dir(tmp.path(), at).unwrap();
        assert_eq!(first, tmp.path().join("20261105T100000Z"));
        assert_eq!(second, tmp.path().join("20261105T100000Z-2"));
        assert_eq!(third, tmp.path().join("20261105T100000Z-3"));

        for n in 4..=SAME_SECOND_LIMIT {
            create_sweep_dir(tmp.path(), at).unwrap_or_else(|e| panic!("{n}: {e}"));
        }
        let err = create_sweep_dir(tmp.path(), at).unwrap_err();
        let exists = io::ErrorKind::AlreadyExists;
        assert!(
            matches!(&err, SweepError::Write { source, .. } if source.kind() == exists),
            "{err:?}"
        );

        // Any other failure stops at the first name instead of trying the next.
        let missing = tmp.path().join("missing");
        let err = create_sweep_dir(&missing, at).unwrap_err();
        let first = missing.join("20261105T100000Z");
        assert!(
            matches!(&err, SweepError::Write { path, .. } if *path == first),
            "{err:?}"
        );
    }

    #[test]
    fn report_files_replace_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let report = report(vec![], &[]);
        write_report(tmp.path(), &report).unwrap();
        let json: Value =
            serde_json::from_str(&fs::read_to_string(tmp.path().join("report.json")).unwrap())
                .unwrap();
        assert_eq!(json["target"], "mac");
        let md = fs::read_to_string(tmp.path().join("report.md")).unwrap();
        assert_eq!(md, report_markdown(&report));
        let left: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(left.len(), 2, "no partial files left");

        let err = write_report(&tmp.path().join("missing"), &report).unwrap_err();
        assert!(matches!(err, SweepError::Write { .. }), "{err:?}");
    }

    #[test]
    fn error_chain_joins_sources() {
        let err = SweepError::Read {
            path: PathBuf::from("/x"),
            source: io::Error::other("disk on fire"),
        };
        assert_eq!(error_chain(&err), "cannot read /x: disk on fire");
    }

    #[test]
    fn unwritable_sweeps_folder_is_a_write_error() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let in_place = Lock::acquire(tmp.path());
        let sweeps = tmp.path().join("sweeps");
        let missing = Lock::acquire(&sweeps);
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let denied = io::ErrorKind::PermissionDenied;
        let lock = tmp.path().join(".lock");
        let Err(SweepError::Write { path, source }) = &in_place else {
            panic!("{in_place:?}");
        };
        assert_eq!((path, source.kind()), (&lock, denied));
        assert!(
            matches!(&missing, Err(SweepError::Write { path, .. }) if *path == sweeps),
            "the folder, not the lock: {missing:?}"
        );
    }
}

#[cfg(test)]
mod markdown_properties {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    // Written out again, not shared with `escape`, so a character dropped from one is caught.
    const SPECIAL: [char; 12] = ['\\', '`', '*', '_', '[', ']', '<', '>', '~', '|', '#', '&'];

    proptest! {
        /// Escaped text is one line with no invisible characters, and every Markdown character
        /// in it is backslash-escaped.
        #[test]
        fn escaped_text_is_one_inert_line(text in any::<String>()) {
            let escaped = escape(&text);
            prop_assert!(!escaped.contains(['\n', '\r']));
            prop_assert!(!escaped.chars().any(is_forging));
            let mut chars = escaped.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    prop_assert!(chars.next().is_some_and(|n| SPECIAL.contains(&n)));
                } else {
                    prop_assert!(!SPECIAL.contains(&c), "unescaped {:?} in {:?}", c, escaped);
                }
            }
        }

        /// Whatever the agent writes, a finding renders as one heading and labelled paragraphs.
        #[test]
        fn a_finding_keeps_its_shape(
            explanation in any::<String>(),
            evidence in any::<String>(),
            summary in any::<String>(),
            commands in prop::collection::vec("[ -~]{0,20}", 0..3),
        ) {
            let finding: Finding = serde_json::from_value(json!({
                "advisories": ["GHSA-1"],
                "component": "c1",
                "severity": "low",
                "known_exploited": false,
                "confidence": "likely",
                "evidence": evidence,
                "explanation": explanation,
                "fix": {"summary": summary, "steps": [], "commands": commands}
            }))
            .unwrap();
            let text = finding_markdown(FindingKey::new(&[]), &finding);
            let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
            prop_assert!(lines[0].starts_with("### low GHSA-1 (likely)"));
            for (line, label) in lines[1..5].iter().zip(["Key:", "Why:", "Evidence:", "Fix:"]) {
                prop_assert!(line.starts_with(label), "{:?}", line);
            }

            // The commands, if any, sit in one block that nothing inside can close: a closing
            // fence is a line of at least as many backticks as the opening one.
            let body: Vec<&str> = text
                .lines()
                .skip_while(|l| !l.starts_with("Fix:"))
                .skip(2)
                .collect();
            if commands.is_empty() {
                prop_assert_eq!(lines.len(), 5, "{:?}", text);
            } else {
                let fence = body[0].strip_suffix("sh").unwrap();
                prop_assert!(fence.len() >= 3 && fence.bytes().all(|b| b == b'`'));
                let listed: Vec<&str> = commands.iter().map(String::as_str).collect();
                prop_assert_eq!(&body[1..=commands.len()], listed.as_slice());
                prop_assert_eq!(body[commands.len() + 1], fence);
                for command in &commands {
                    let closes = command.trim().len() >= fence.len()
                        && command.trim().bytes().all(|b| b == b'`');
                    prop_assert!(!closes, "{:?} closes {:?}", command, fence);
                }
            }
        }
    }
}
