//! Command-line interface to Vigil.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;
use clap::ArgGroup;
use clap::Parser;
use clap::Subcommand;
use vigil_core::Cancel;
use vigil_core::Config;
use vigil_core::Confirmed;
use vigil_core::DataDir;
use vigil_core::Feeds;
use vigil_core::FindingKey;
use vigil_core::History;
use vigil_core::Inventory;
use vigil_core::Latest;
use vigil_core::LoadConfigError;
use vigil_core::NvdAccess;
use vigil_core::OsvQuery;
use vigil_core::Outcome;
use vigil_core::Package;
use vigil_core::Product;
use vigil_core::Progress;
use vigil_core::SshConn;
use vigil_core::SweepError;
use vigil_core::Targets;
use vigil_core::dismiss;
use vigil_core::latest;
use vigil_core::plan_fix;
use vigil_core::report_markdown;
use vigil_core::run_fix;
use vigil_core::sweep;
use vigil_core::undismiss;

/// Sweep this Mac, GitHub repos and servers for known vulnerabilities.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Data directory [default: ~/Library/Application Support/io.github.georgiosdelkos.vigil].
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the data directory and a default config.toml.
    Init,
    /// Validate config.toml and print what a sweep would cover.
    Config,
    /// Fetch advisories for packages and NVD products, one JSON object per line.
    ///
    /// Uses `history.since` from config.toml. An NVD API key stored in the Keychain with
    /// `security add-generic-password -s io.github.georgiosdelkos.vigil -a nvd-api-key -w <key>`
    /// raises NVD's rate limit from 5 to 50 requests per 30 seconds.
    #[command(group(
        ArgGroup::new("what")
            .required(true)
            .multiple(true)
            .args(["packages", "products"])
    ))]
    Advisories {
        /// A package as ecosystem:name, such as npm:lodash or crates.io:serde. Repeatable.
        #[arg(long = "package", value_name = "ECOSYSTEM:NAME")]
        packages: Vec<Package>,
        /// An NVD product, `name` (any vendor) or `vendor:name`, such as openssl or github:cli.
        /// Repeatable.
        #[arg(long = "product", value_name = "[VENDOR:]NAME")]
        products: Vec<Product>,
    },
    /// List what is installed on this Mac, one JSON object per line.
    ///
    /// Reads macOS, Homebrew, global toolchains, and lockfiles under `mac.project_dirs` from
    /// config.toml. Anything that could not be read is reported on stderr.
    Inventory,
    /// Sweep this Mac, the repositories in `repos` and the servers in `servers`: inventory,
    /// advisories, the chosen agent's verdict, and a report per target.
    ///
    /// Prints the reports on stdout and progress on stderr. The reports and the agent's
    /// bundles are kept under the data directory's `sweeps` folder. Repositories are read with
    /// `gh api` and your gh login. Exits non-zero when a target got no valid verdict.
    Sweep {
        /// Sweep only this target: mac, github:<owner>/<name> or server:<name>.
        #[arg(long, value_name = "TARGET")]
        target: Option<String>,
    },
    /// List each target's open findings and issues from its newest sweep, with their keys.
    Findings {
        /// One JSON object per target instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Hide a finding or issue from reports, for a reason.
    ///
    /// The key is shown under each finding in the report. A finding shows again when its
    /// advisory changes, or after `undismiss`.
    Dismiss {
        /// The finding's key.
        key: FindingKey,
        /// Why it does not apply or is accepted, one line.
        #[arg(long)]
        reason: String,
    },
    /// Show a dismissed finding or issue again from the next sweep on.
    Undismiss {
        /// The finding's key.
        key: FindingKey,
    },
    /// Show the fix for a finding or issue, and run it with the chosen agent once confirmed.
    ///
    /// The agent gets full access: on this Mac it runs the commands, for a repository it
    /// opens a pull request, for a server it runs them over ssh. Each run is recorded in the
    /// data directory's state/fixes.jsonl.
    Fix {
        /// The finding's key, as shown in the report.
        key: FindingKey,
        /// Run without asking; for scripts that already showed the fix to the user.
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Looked up only when needed, so `--data-dir X init` works without HOME.
    let home = || std::env::home_dir().context("cannot find the home directory; set HOME");
    let data_dir = match cli.data_dir {
        Some(dir) => DataDir::new(dir),
        None => DataDir::for_home(&home()?),
    };

    match cli.command {
        Command::Init => {
            let path = data_dir.init()?;
            print(&format!("wrote {}", path.display()));
        }
        Command::Config => print(&summary(&load_config(&data_dir, &home()?)?)),
        Command::Advisories { packages, products } => {
            let config = load_config(&data_dir, &home()?)?;
            advisories(&data_dir, config.history, &packages, &products)?;
        }
        Command::Inventory => {
            let config = load_config(&data_dir, &home()?)?;
            inventory(&Inventory::collect_mac(&config.project_dirs))?;
        }
        Command::Sweep { target } => {
            let targets = target.as_deref().map_or(Targets::All, Targets::Only);
            run_sweep(&data_dir, &load_config(&data_dir, &home()?)?, targets)?;
        }
        Command::Findings { json } => {
            let all = latest(&data_dir, &load_config(&data_dir, &home()?)?)?;
            if json {
                for target in &all {
                    print(&serde_json::to_string(target).context("write JSON")?);
                }
            } else {
                print(&findings_text(&all));
            }
        }
        Command::Dismiss { key, reason } => {
            dismiss(&data_dir, key, &reason)?;
            print(&format!(
                "dismissed {key}; it is left out of reports from the next sweep"
            ));
        }
        Command::Fix { key, yes } => {
            let config = load_config(&data_dir, &home()?)?;
            fix(&data_dir, &config, key, yes)?;
        }
        Command::Undismiss { key } => {
            undismiss(&data_dir, key)?;
            print(&format!("{key} shows again from the next sweep"));
        }
    }
    Ok(())
}

/// A cancel request that Ctrl-C makes. The agent runs in its own process group, so the
/// terminal's Ctrl-C reaches only this process, which then stops the agent and everything it
/// started and cleans up: a few seconds at most. A second Ctrl-C exits at once, and so does a
/// closed terminal or `kill`; the core's watchdog then stops the agent within a few seconds,
/// and the next sweep removes the unfinished folder.
fn cancel_on_ctrl_c() -> anyhow::Result<Cancel> {
    let cancel = Cancel::new();
    let handler = cancel.clone();
    ctrlc::set_handler(move || {
        if handler.is_cancelled() {
            // 128 + SIGINT, the shell's code for a command stopped by Ctrl-C.
            std::process::exit(130);
        }
        status("stopping; Ctrl-C again to quit at once");
        handler.cancel();
    })
    .context("handle Ctrl-C")?;
    Ok(cancel)
}

/// Sweeps `targets` and prints each report; fails when any target swept has no valid verdict.
fn run_sweep(data_dir: &DataDir, config: &Config, targets: Targets<'_>) -> anyhow::Result<()> {
    let cancel = cancel_on_ctrl_c()?;
    let reports = match sweep(
        data_dir,
        config,
        targets,
        &mut |p| show_progress(&p),
        &cancel,
    ) {
        // The sweep has stopped its agent and removed its unfinished folder; 130 is the code
        // a shell gives a command stopped by Ctrl-C, as a second Ctrl-C exits.
        Err(SweepError::Cancelled) => {
            status("the sweep was cancelled");
            std::process::exit(130);
        }
        swept => swept?,
    };
    let mut failures = Vec::new();
    for report in &reports {
        print(&report_markdown(report));
        if let Some(failure) = &report.failure {
            failures.push(format!("{}: {failure}", report.target));
        }
    }
    if !failures.is_empty() {
        anyhow::bail!("sweep incomplete: {}", failures.join("; "));
    }
    Ok(())
}

/// The open findings per target, one line each, most severe first.
fn findings_text(all: &[Latest]) -> String {
    let mut out = String::new();
    for target in all {
        let Some(swept) = target.swept else {
            out.push_str(&format!("{}: no sweep with a verdict yet\n", target.target));
            continue;
        };
        let dismissed = match target.dismissed {
            0 => String::new(),
            n => format!(", {n} dismissed"),
        };
        out.push_str(&format!(
            "{} (swept {swept}): {} open{dismissed}\n",
            target.target,
            target.open.len()
        ));
        for open in &target.open {
            out.push_str(&format!(
                "  {:<8} {}  {}\n           fix: {}\n",
                open.severity, open.key, open.title, open.fix
            ));
        }
    }
    out
}

/// Shows the fix for `key`, asks to run it unless `yes`, and runs it. Fails when it is not
/// confirmed, so a script can tell nothing ran, and when the agent did not report it fixed or
/// exited with an error.
fn fix(data_dir: &DataDir, config: &Config, key: FindingKey, yes: bool) -> anyhow::Result<()> {
    let plan = plan_fix(data_dir, config, key)?;
    // The summary may hold line breaks (sweep prose allows them); one line here, so it cannot
    // pass for a command line in what the user confirms.
    let summary = plan
        .fix()
        .summary
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut text = format!(
        "Fix {key} on {} (found by the sweep of {}): {summary}\n",
        plan.destination(),
        plan.found()
    );
    for step in &plan.fix().steps {
        text.push_str(&format!("  - {step}\n"));
    }
    for command in &plan.fix().commands {
        text.push_str(&format!("  $ {command}\n"));
    }
    print(&text);
    if !yes {
        status(&format!(
            "Run this fix now with {}, with full access? [y/N]",
            plan.agent()
        ));
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("read the answer")?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            anyhow::bail!("not confirmed; nothing was run");
        }
    }
    let confirmed = if yes {
        Confirmed::YesFlag
    } else {
        Confirmed::Asked
    };
    let record = run_fix(data_dir, &plan, confirmed, &cancel_on_ctrl_c()?, &mut |p| {
        status(&p.to_string());
    })?;
    let pull_request = record
        .pull_request
        .as_ref()
        .map_or(String::new(), |url| format!("\npull request: {url}"));
    print(&format!(
        "{}: {}{pull_request}\n(log and files in {})",
        record.outcome,
        record.summary,
        record.dir.display()
    ));
    if record.outcome != Outcome::Fixed || record.exit_code != Some(0) {
        let exit = record
            .exit_code
            .map_or("no exit code".to_owned(), |c| format!("exit code {c}"));
        anyhow::bail!("the fix did not finish: {}, agent {exit}", record.outcome);
    }
    Ok(())
}

/// Prints every advisory each source could fetch, as it arrives, and reports every failure on
/// stderr. One failing source or record never hides the rest; the command still exits
/// non-zero at the end so a script notices the gap.
fn advisories(
    data_dir: &DataDir,
    history: History,
    packages: &[Package],
    products: &[Product],
) -> anyhow::Result<()> {
    // Reading the Keychain can prompt the user, so only when NVD will be queried.
    let nvd = if products.is_empty() {
        NvdAccess::Anonymous
    } else {
        NvdAccess::from_keychain()?
    };
    let feeds = Feeds::new(data_dir, nvd);
    let mut failures = 0;
    let mut fail = |what: &str, error: &dyn std::error::Error| {
        failures += 1;
        warn(&format!("{what}: {}", error_chain(error)));
    };

    let kev = feeds.kev();
    if let Err(e) = &kev {
        fail("CISA KEV catalog, known_exploited is null", e);
    }
    let kev = kev.as_ref().ok();

    if !packages.is_empty() {
        // Packages given here are language packages, which OSV is asked about by name.
        let queries: Vec<OsvQuery> = packages
            .iter()
            .map(|package| OsvQuery {
                package: package.clone(),
                version: None,
            })
            .collect();
        match feeds.osv(&queries, history, kev) {
            Ok(osv) => {
                for found in &osv.advisories {
                    print(&found.advisory.to_json_line(kev));
                }
                for e in &osv.failures {
                    fail("OSV record", e);
                }
                for crowded in &osv.crowded {
                    warn(&format!(
                        "{} matches {} advisories; only the {} in CISA KEV are printed",
                        crowded.query.package.name, crowded.matched, crowded.kept
                    ));
                }
            }
            Err(e) => fail("OSV", &e),
        }
    }
    for product in products {
        match feeds.nvd(product, history) {
            Ok(found) => {
                for advisory in &found {
                    print(&advisory.to_json_line(kev));
                }
            }
            Err(e) => fail(&format!("NVD product {product}"), &e),
        }
    }

    incomplete(failures)
}

/// Prints each component as a JSON line and reports problems and missing tools on stderr.
///
/// Exits non-zero when anything could not be collected or printed, so a script sees the list is
/// incomplete. Lasting facts about this Mac that the next run would report again do not count:
/// a Homebrew name with no NVD product, crates from a registry other than crates.io, and a
/// problem npm reports in a global tree it still lists.
fn inventory(inventory: &Inventory) -> anyhow::Result<()> {
    let mut failures = 0;
    for component in &inventory.components {
        // A path that is not UTF-8 (possible on network or FAT volumes) cannot be JSON.
        match serde_json::to_string(component) {
            Ok(line) => print(&line),
            Err(e) => {
                failures += 1;
                warn(&format!(
                    "cannot print a component found in {:?}: {e}",
                    component.found_in
                ));
            }
        }
    }
    for problem in &inventory.problems {
        if problem.is_failure() {
            failures += 1;
        }
        warn(&error_chain(problem));
    }
    if !inventory.not_installed.is_empty() {
        warn(&format!(
            "not installed, so not checked: {}",
            inventory.not_installed.join(", ")
        ));
    }
    if failures > 0 {
        anyhow::bail!("{failures} inventory problem(s); the list above is incomplete");
    }
    Ok(())
}

/// Fails when any feed request failed, so a script sees that the printed output has gaps.
fn incomplete(failures: usize) -> anyhow::Result<()> {
    if failures > 0 {
        anyhow::bail!("{failures} feed request(s) failed; the output above is incomplete");
    }
    Ok(())
}

/// Renders an error and its sources as `outer: inner: innermost`.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(e) = source {
        text.push_str(&format!(": {e}"));
        source = e.source();
    }
    text
}

fn load_config(data_dir: &DataDir, home: &Path) -> anyhow::Result<Config> {
    Config::load(&data_dir.config_file(), home).map_err(|e| match e {
        LoadConfigError::Missing { .. } => anyhow::Error::new(e).context("run `vigil init` first"),
        e => e.into(),
    })
}

/// Renders the parts of `config` a sweep acts on, one line each.
fn summary(config: &Config) -> String {
    let agent = config.agent.map_or_else(
        || "none (set `agent` in config.toml)".to_owned(),
        |a| a.to_string(),
    );
    let schedule = config.schedule.to_string();
    let history = match config.history {
        History::All => "all".to_owned(),
        History::Since(since) => format!("since {}", since.date()),
    };

    let mut out = format!("agent: {agent}\nschedule: {schedule}\nhistory: {history}\n");
    for dir in &config.project_dirs {
        out.push_str(&format!("mac project dir: {}\n", dir.display()));
    }
    for repo in &config.repos {
        out.push_str(&format!("github repo: {repo}\n"));
    }
    for server in &config.servers {
        let conn = match &server.conn {
            SshConn::Alias(alias) => format!("ssh alias {alias}"),
            SshConn::Direct {
                host,
                user,
                port,
                identity_file,
            } => {
                let mut conn = format!("host {host}");
                if let Some(user) = user {
                    conn.push_str(&format!(", user {user}"));
                }
                if let Some(port) = port {
                    conn.push_str(&format!(", port {port}"));
                }
                if let Some(key) = identity_file {
                    conn.push_str(&format!(", key {}", key.display()));
                }
                conn
            }
        };
        out.push_str(&format!("server: {} ({conn})\n", server.name));
        for dir in &server.dirs {
            out.push_str(&format!("server {} dir: {}\n", server.name, dir.as_str()));
        }
    }
    out
}

#[expect(
    clippy::print_stdout,
    reason = "the CLI's one output function for results"
)]
fn print(text: &str) {
    println!("{}", text.trim_end());
}

/// Prints one progress line of a sweep on stderr.
fn show_progress(progress: &Progress<'_>) {
    status(&progress.to_string());
}

#[expect(
    clippy::print_stderr,
    reason = "the CLI's one output function for progress"
)]
fn status(text: &str) {
    eprintln!("{text}");
}

#[expect(
    clippy::print_stderr,
    reason = "the CLI's one output function for warnings"
)]
fn warn(text: &str) {
    eprintln!("warning: {text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_chain_joins_sources() {
        let inner = std::io::Error::other("disk on fire");
        let outer = anyhow::Error::new(inner).context("reading cache");
        let outer: &dyn std::error::Error = outer.as_ref();
        assert_eq!(error_chain(outer), "reading cache: disk on fire");
    }

    #[test]
    fn any_failure_makes_the_output_incomplete() {
        assert!(incomplete(0).is_ok());
        let err = incomplete(3).unwrap_err();
        assert_eq!(
            err.to_string(),
            "3 feed request(s) failed; the output above is incomplete"
        );
    }

    /// A path that is not UTF-8 cannot be JSON: it is reported and fails the command.
    #[test]
    fn unprintable_component_is_a_failure() {
        use std::os::unix::ffi::OsStringExt as _;

        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/p/\xff/Cargo.lock".to_vec()));
        let inventory = Inventory {
            components: vec![vigil_core::Component {
                lookup: vigil_core::Lookup::Package("npm:a".parse().unwrap()),
                version: "1".into(),
                found_in: vigil_core::FoundIn::Lockfile { path },
            }],
            ..Inventory::default()
        };
        let err = super::inventory(&inventory).unwrap_err();
        assert_eq!(
            err.to_string(),
            "1 inventory problem(s); the list above is incomplete"
        );
        assert!(super::inventory(&Inventory::default()).is_ok());
    }

    #[test]
    fn advisories_needs_a_package_or_product() {
        let err = Cli::try_parse_from(["vigil", "advisories"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        let cli = Cli::try_parse_from(["vigil", "advisories", "--product", "zlib"]);
        assert!(cli.is_ok());
    }
}
