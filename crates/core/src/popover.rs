//! What the menu-bar popover shows, worked out from each target's [`Latest`] so the app's UI
//! only lays it out: the open items ranked by risk, their counts, the headline, and one line
//! per target.
//!
//! An item is what the user acts on: an installed component with every open finding in it
//! (ffmpeg 8.1.2 with its 33 advisories is one item, with one fix), or an issue on its own.
//! Everything the popover counts is items, so one upgrade counts once; findings stay the unit
//! of keys, dismissals and fixes. The owner chose this on 2026-11-10, after a sweep listed
//! 113 findings that were 12 components.
//!
//! The ranking puts what needs the user first: exploited in the wild (CISA KEV), then by
//! severity, then the newest. Findings inside an item are ranked the same way, and the first
//! leads it: its fix is the item's. An item "needs you" when any of its findings is
//! exploited, or its worst is critical or high.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::Serialize;

use crate::findings::Severity;
use crate::lifecycle::Fixed;
use crate::lifecycle::Latest;
use crate::lifecycle::Open;

/// The popover's content.
#[derive(Debug, Serialize)]
pub struct PopoverView {
    /// Every open item across targets, ranked by risk.
    pub items: Vec<Listed>,
    /// Confirmed fixes that finished in the last 30 days, newest first. A fix only reported
    /// is still in `items`, marked by its lead's `fix_state`.
    pub fixed: Vec<FixedListed>,
    /// How many items need the user.
    pub needs_you: usize,
    /// How many items hold a finding exploited in the wild.
    pub exploited: usize,
    /// How many items there are at each worst severity.
    pub counts: Counts,
    /// The top line: "2 findings need you", "All clear".
    pub headline: String,
    /// When the newest sweep of any target started.
    pub last_swept: Option<Timestamp>,
    /// The line under the headline while no sweep time is known, saying what Sweep does; the
    /// headline already says "Not swept yet", so the line under it does not repeat it. None
    /// once a sweep time is known, when the line says how long ago that was.
    pub first_sweep_hint: Option<String>,
    /// Whether a sweep ran and nothing is open.
    pub all_clear: bool,
    /// How many targets there are: "1 target", "3 targets".
    pub target_count: String,
    /// One line per target, in sweep order.
    pub targets: Vec<TargetLine>,
    /// How many findings are dismissed across targets. Findings, not items: a dismissal is
    /// of one advisory.
    pub dismissed: usize,
}

/// One item the list shows: an installed component with the open findings in it, or an issue
/// on its own.
#[derive(Debug, Serialize)]
pub struct Listed {
    /// Its id in the list: the component's key, or the issue's finding key. It stays while
    /// findings in it are dismissed, so an open detail keeps showing it.
    pub id: String,
    /// Its target, as [`target_label`] shows it.
    pub target: String,
    /// Its name: the component's (a Homebrew formula's own name, which can hold several
    /// products), or the issue's subject.
    pub name: String,
    /// The finding that leads it: exploited first, then the worst, then the newest. Its
    /// version, place and fix are the item's, and Fix runs its key.
    pub lead: Open,
    /// The other findings in the same component, ranked the same way; empty for an issue.
    pub others: Vec<Open>,
    /// The worst severity of its findings.
    pub severity: Severity,
    /// Whether any of its findings is exploited in the wild.
    pub known_exploited: bool,
    /// Whether it needs the user now.
    pub needs_you: bool,
    /// When a sweep first found any of its findings.
    pub first_seen: Option<Timestamp>,
    /// Whether the newest sweep is the first to find any of its findings.
    pub new: bool,
    /// "33 advisories" when it holds more than one finding; `None` for one.
    pub advisory_count: Option<String>,
    /// What the Fix confirmation adds when it holds more than one finding: the fix is the
    /// component's, and the next sweep checks every advisory again. `None` for one.
    pub fix_scope: Option<String>,
}

impl Listed {
    /// Its findings, ranked: the lead, then the others.
    pub fn findings(&self) -> impl Iterator<Item = &Open> {
        std::iter::once(&self.lead).chain(&self.others)
    }
}

/// A fixed finding, with its target.
#[derive(Debug, Serialize)]
pub struct FixedListed {
    /// The finding and its fix.
    #[serde(flatten)]
    pub fixed: Fixed,
    /// Its target, as [`target_label`] shows it.
    pub target: String,
}

/// How many open items there are at each worst severity.
#[derive(Debug, Default, Serialize)]
pub struct Counts {
    /// Critical.
    pub critical: usize,
    /// High.
    pub high: usize,
    /// Medium.
    pub medium: usize,
    /// Low.
    pub low: usize,
}

impl Counts {
    fn of<'a>(items: impl IntoIterator<Item = &'a Listed>) -> Self {
        let mut counts = Self::default();
        for item in items {
            *match item.severity {
                Severity::Critical => &mut counts.critical,
                Severity::High => &mut counts.high,
                Severity::Medium => &mut counts.medium,
                Severity::Low => &mut counts.low,
            } += 1;
        }
        counts
    }
}

/// A target's line.
#[derive(Debug, Serialize)]
pub struct TargetLine {
    /// Its name as shown.
    pub label: String,
    /// What it is, for its icon.
    pub kind: TargetKind,
    /// When its newest sweep with a verdict started.
    pub swept: Option<Timestamp>,
    /// What that sweep checked, one phrase: "139 components checked" (or "1 component
    /// checked"), or "no components listed" when it listed none (a repository without a
    /// dependency graph, for one); `None` before a sweep. Components, not packages: on the Mac
    /// the count holds the OS and toolchains too, and a package once per place it is installed.
    pub checked: Option<String>,
    /// Its open items by worst severity.
    pub counts: Counts,
    /// How many open items it has.
    pub open: usize,
    /// How many findings are dismissed.
    pub dismissed: usize,
}

/// What a target is.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    /// This Mac.
    Mac,
    /// A GitHub repository.
    Repo,
    /// A server.
    Server,
}

/// The popover's content for the targets' latest findings.
pub fn popover_view(latest: Vec<Latest>) -> PopoverView {
    let last_swept = latest.iter().filter_map(|t| t.swept).max();
    let dismissed = latest.iter().map(|t| t.dismissed).sum();
    let mut targets = Vec::new();
    let mut fixed = Vec::new();
    let mut all = Vec::new();
    for mut target in latest {
        let label = target_label(&target.target).to_owned();
        let listed = items(&label, std::mem::take(&mut target.open));
        targets.push(target_line(&target, &listed));
        fixed.extend(target.fixed.into_iter().map(|fixed| FixedListed {
            fixed,
            target: label.clone(),
        }));
        all.extend(listed);
    }
    fixed.sort_by_key(|f| Reverse(f.fixed.fixed_at));
    // Stable, so items that tie keep their targets' sweep order.
    all.sort_by_key(|item| risk(item.known_exploited, item.severity, item.first_seen));

    let needs_you = all.iter().filter(|item| item.needs_you).count();
    PopoverView {
        needs_you,
        exploited: all.iter().filter(|item| item.known_exploited).count(),
        counts: Counts::of(&all),
        headline: headline(needs_you, all.len(), last_swept),
        all_clear: all.is_empty() && last_swept.is_some(),
        first_sweep_hint: last_swept
            .is_none()
            .then(|| "Sweep checks your targets against the newest advisories.".to_owned()),
        target_count: match targets.len() {
            1 => "1 target".to_owned(),
            n => format!("{n} targets"),
        },
        items: all,
        fixed,
        last_swept,
        targets,
        dismissed,
    }
}

/// One target's open findings and issues as items, ranked by risk: one per installed
/// component, holding every finding in it, and one per issue. `target` is the label each item
/// carries.
pub fn items(target: &str, open: Vec<Open>) -> Vec<Listed> {
    let mut groups: Vec<Vec<Open>> = Vec::new();
    let mut by_component = BTreeMap::new();
    for finding in open {
        let Some(component) = finding.component.as_ref().map(|c| c.key) else {
            groups.push(vec![finding]);
            continue;
        };
        let at = *by_component.entry(component).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[at].push(finding);
    }
    let mut items: Vec<Listed> = groups
        .into_iter()
        .map(|findings| listed(target, findings))
        .collect();
    items.sort_by_key(|item| risk(item.known_exploited, item.severity, item.first_seen));
    items
}

/// The item of `findings`, one or more in one component, or one issue.
fn listed(target: &str, mut findings: Vec<Open>) -> Listed {
    findings.sort_by_key(|f| risk(f.known_exploited, f.severity, f.first_seen));
    let mut findings = findings.into_iter();
    let lead = findings
        .next()
        .expect("items makes each group around a finding it then adds");
    let others: Vec<Open> = findings.collect();
    let all = || std::iter::once(&lead).chain(&others);
    let severity = others
        .iter()
        .map(|f| f.severity)
        .fold(lead.severity, Ord::min);
    let known_exploited = all().any(|f| f.known_exploited);
    let name = lead
        .component
        .as_ref()
        .map_or_else(|| lead.name.clone(), |c| c.name.clone());
    let count = 1 + others.len();
    let (advisory_count, fix_scope) = if others.is_empty() {
        (None, None)
    } else {
        let component = match &lead.version {
            Some(version) => format!("{name} {version}"),
            None => name.clone(),
        };
        (
            Some(format!("{count} advisories")),
            Some(format!(
                "This fix is for the component, {component}, which all {count} advisories are \
                 in; the next sweep checks each of them again."
            )),
        )
    };
    Listed {
        id: lead
            .component
            .as_ref()
            .map_or_else(|| lead.key.to_string(), |c| c.key.to_string()),
        target: target.to_owned(),
        name,
        severity,
        known_exploited,
        needs_you: known_exploited || matches!(severity, Severity::Critical | Severity::High),
        first_seen: all().filter_map(|f| f.first_seen).min(),
        new: all().any(|f| f.new),
        advisory_count,
        fix_scope,
        lead,
        others,
    }
}

/// The sort key that ranks by risk: exploited first, then the most severe, then the newest,
/// with one never seen last.
fn risk(
    exploited: bool,
    severity: Severity,
    first_seen: Option<Timestamp>,
) -> (Reverse<bool>, Severity, Reverse<Option<Timestamp>>) {
    (Reverse(exploited), severity, Reverse(first_seen))
}

/// A target's name as shown: `mac` reads "This Mac", `github:o/r` reads `o/r`, and
/// `server:web` reads `web`.
pub fn target_label(target: &str) -> &str {
    if target == "mac" {
        return "This Mac";
    }
    target
        .strip_prefix("github:")
        .or_else(|| target.strip_prefix("server:"))
        .unwrap_or(target)
}

fn target_kind(target: &str) -> TargetKind {
    if target.starts_with("github:") {
        TargetKind::Repo
    } else if target.starts_with("server:") {
        TargetKind::Server
    } else {
        TargetKind::Mac
    }
}

/// The line of `latest`, whose open findings are `items`.
fn target_line(latest: &Latest, items: &[Listed]) -> TargetLine {
    TargetLine {
        label: target_label(&latest.target).to_owned(),
        kind: target_kind(&latest.target),
        swept: latest.swept,
        checked: latest.swept.map(|_| checked(latest.components)),
        counts: Counts::of(items),
        open: items.len(),
        dismissed: latest.dismissed,
    }
}

fn checked(components: usize) -> String {
    match components {
        0 => "no components listed".to_owned(),
        1 => "1 component checked".to_owned(),
        n => format!("{n} components checked"),
    }
}

fn headline(needs_you: usize, open: usize, last_swept: Option<Timestamp>) -> String {
    match (needs_you, open) {
        (0, 0) if last_swept.is_none() => "Not swept yet".to_owned(),
        (1, _) => "1 finding needs you".to_owned(),
        (0, 0) => "All clear".to_owned(),
        (0, n) => format!("{n} open, none urgent"),
        (n, _) => format!("{n} findings need you"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::ComponentKey;
    use crate::lifecycle::FindingKey;
    use crate::lifecycle::InComponent;

    fn open(key: u64, severity: Severity, exploited: bool, first_seen: Option<i64>) -> Open {
        Open {
            key: format!("{key:016x}").parse().unwrap(),
            severity,
            title: format!("finding {key}"),
            name: "pkg".to_owned(),
            version: None,
            component: None,
            advisories: Vec::new(),
            place: String::new(),
            known_exploited: exploited,
            confidence: None,
            evidence: String::new(),
            explanation: String::new(),
            fix: format!("fix {key}"),
            steps: Vec::new(),
            commands: Vec::new(),
            first_seen: first_seen.map(|s| Timestamp::from_second(s).unwrap()),
            new: false,
            fix_state: None,
        }
    }

    fn target(name: &str, swept: Option<i64>, open: Vec<Open>, dismissed: usize) -> Latest {
        Latest {
            target: name.to_owned(),
            swept: swept.map(|s| Timestamp::from_second(s).unwrap()),
            components: 7,
            open,
            fixed: Vec::new(),
            dismissed,
        }
    }

    fn keys(view: &PopoverView) -> Vec<String> {
        view.items.iter().map(|f| f.lead.title.clone()).collect()
    }

    /// `finding` as found in the component `name` at `version`.
    fn in_component(mut finding: Open, name: &str, version: &str) -> Open {
        finding.name = name.to_owned();
        finding.version = Some(version.to_owned());
        finding.component = Some(InComponent {
            key: ComponentKey(FindingKey::new(&[name, version])),
            name: name.to_owned(),
        });
        finding
    }

    fn titles(findings: &[Open]) -> Vec<&str> {
        findings.iter().map(|f| f.title.as_str()).collect()
    }

    #[test]
    fn findings_in_one_component_are_one_item_led_by_the_worst() {
        let ffmpeg = |key, severity, seen| {
            in_component(open(key, severity, false, Some(seen)), "ffmpeg", "8.1.2")
        };
        let listed = items(
            "This Mac",
            vec![
                ffmpeg(1, Severity::Medium, 30),
                ffmpeg(2, Severity::Critical, 10),
                ffmpeg(3, Severity::Critical, 20),
            ],
        );
        let [item] = &listed[..] else {
            panic!("one component, one item: {listed:?}");
        };
        assert_eq!(item.lead.title, "finding 3", "the newest of the worst");
        assert_eq!(titles(&item.others), ["finding 2", "finding 1"]);
        assert_eq!(item.severity, Severity::Critical);
        assert!(item.needs_you && !item.known_exploited && !item.new);
        assert_eq!(
            item.first_seen,
            Some(Timestamp::from_second(10).unwrap()),
            "the earliest"
        );
        assert_eq!(item.advisory_count.as_deref(), Some("3 advisories"));
        assert_eq!(
            item.fix_scope.as_deref(),
            Some(
                "This fix is for the component, ffmpeg 8.1.2, which all 3 advisories are in; \
                 the next sweep checks each of them again."
            )
        );
        assert_eq!(item.lead.fix, "fix 3", "one fix, the lead's");
        assert_eq!(
            item.id,
            FindingKey::new(&["ffmpeg", "8.1.2"]).to_string(),
            "the component's key"
        );
        assert_eq!(item.target, "This Mac");
    }

    #[test]
    fn two_versions_of_a_package_are_two_items_and_issues_stay_apart() {
        let sqlite =
            |key, version| in_component(open(key, Severity::High, false, None), "sqlite", version);
        let listed = items(
            "This Mac",
            vec![
                sqlite(1, "3.51.3"),
                sqlite(2, "3.53.2"),
                sqlite(3, "3.51.3"),
                open(4, Severity::Low, false, None),
                open(5, Severity::Low, false, None),
            ],
        );
        let shape: Vec<(Option<&str>, usize)> = listed
            .iter()
            .map(|i| (i.lead.version.as_deref(), 1 + i.others.len()))
            .collect();
        assert_eq!(
            shape,
            [
                (Some("3.51.3"), 2),
                (Some("3.53.2"), 1),
                (None, 1),
                (None, 1)
            ]
        );
        let single = &listed[1];
        assert_eq!((&single.advisory_count, &single.fix_scope), (&None, &None));
        assert_eq!(listed[2].id, "0000000000000004", "an issue's id is its key");
        assert!(!listed[2].needs_you, "low and not exploited");
    }

    #[test]
    fn an_exploited_finding_leads_over_a_worse_one_and_marks_the_item() {
        let pnpm = |key, severity, exploited| {
            in_component(open(key, severity, exploited, None), "pnpm", "10.33.0")
        };
        let mut new = pnpm(1, Severity::Low, false);
        new.new = true;
        let listed = items(
            "This Mac",
            vec![
                pnpm(2, Severity::Critical, false),
                pnpm(3, Severity::Medium, true),
                new,
            ],
        );
        let [item] = &listed[..] else {
            panic!("one component, one item: {listed:?}");
        };
        assert_eq!(item.lead.title, "finding 3");
        assert_eq!(titles(&item.others), ["finding 2", "finding 1"]);
        assert_eq!(
            item.severity,
            Severity::Critical,
            "the worst, not the lead's"
        );
        assert!(item.known_exploited && item.needs_you);
        assert!(item.new, "one of them is new");
        assert_eq!(item.first_seen, None, "none was seen");
    }

    #[test]
    fn counts_are_of_items_at_their_worst_severity() {
        let ffmpeg = |key, severity| in_component(open(key, severity, false, None), "ffmpeg", "8");
        let openssl = |key, severity, exploited| {
            in_component(open(key, severity, exploited, None), "openssl", "3")
        };
        let view = popover_view(vec![target(
            "mac",
            Some(100),
            vec![
                ffmpeg(1, Severity::Critical),
                ffmpeg(2, Severity::High),
                ffmpeg(3, Severity::Low),
                openssl(4, Severity::Medium, true),
                openssl(5, Severity::Medium, false),
                open(6, Severity::Low, false, None),
            ],
            4,
        )]);
        assert_eq!(keys(&view), ["finding 4", "finding 1", "finding 6"]);
        let c = &view.counts;
        assert_eq!((c.critical, c.high, c.medium, c.low), (1, 0, 1, 1));
        assert_eq!((view.needs_you, view.exploited), (2, 1));
        assert_eq!(view.headline, "2 findings need you");
        let line = &view.targets[0];
        assert_eq!(
            (line.open, line.counts.critical, line.counts.medium),
            (3, 1, 1)
        );
        assert_eq!((line.counts.high, line.counts.low), (0, 1));
        assert_eq!(line.dismissed, 4, "dismissals stay findings");
    }

    #[test]
    fn a_component_whose_findings_are_all_dismissed_is_gone() {
        // `latest` leaves dismissed findings out of `open`, so nothing is left to group.
        let kept = in_component(open(1, Severity::High, false, None), "glib", "2.88.1");
        let view = popover_view(vec![target("mac", Some(1), vec![kept], 2)]);
        assert_eq!(keys(&view), ["finding 1"]);
        let view = popover_view(vec![target("mac", Some(1), Vec::new(), 3)]);
        assert!(view.items.is_empty() && view.all_clear);
        assert_eq!(view.targets[0].open, 0);
    }

    #[test]
    fn fixed_findings_are_listed_apart_and_counted_nowhere_else() {
        let fixed = |key: u64, at: i64| Fixed {
            key: format!("{key:016x}").parse().unwrap(),
            title: format!("finding {key}"),
            fixed_at: Timestamp::from_second(at).unwrap(),
            summary: "upgraded".to_owned(),
            pull_request: None,
        };
        let mut mac = target("mac", Some(100), Vec::new(), 0);
        mac.fixed = vec![fixed(1, 200)];
        let mut repo = target("github:o/r", Some(100), Vec::new(), 0);
        repo.fixed = vec![fixed(2, 300)];
        let view = popover_view(vec![mac, repo]);
        let listed: Vec<(&str, &str)> = view
            .fixed
            .iter()
            .map(|f| (f.fixed.title.as_str(), f.target.as_str()))
            .collect();
        assert_eq!(
            listed,
            [("finding 2", "o/r"), ("finding 1", "This Mac")],
            "newest fix first"
        );
        assert!(view.items.is_empty());
        assert_eq!((view.needs_you, view.counts.critical), (0, 0));
        assert!(view.all_clear, "nothing is open");
    }

    #[test]
    fn items_rank_exploited_then_by_severity_then_newest() {
        let view = popover_view(vec![
            target(
                "mac",
                Some(100),
                vec![
                    open(1, Severity::Low, false, Some(10)),
                    open(2, Severity::High, false, Some(10)),
                    open(3, Severity::High, false, Some(20)),
                ],
                0,
            ),
            target(
                "github:o/r",
                Some(200),
                vec![
                    open(4, Severity::Medium, true, None),
                    open(5, Severity::Critical, false, None),
                    open(6, Severity::High, false, None),
                ],
                2,
            ),
        ]);
        assert_eq!(
            keys(&view),
            [
                "finding 4",
                "finding 5",
                "finding 3",
                "finding 2",
                "finding 6",
                "finding 1"
            ],
            "exploited first; among the highs the newest first, one never seen last"
        );
        assert_eq!(view.items[0].target, "o/r");
        assert_eq!(view.items[2].target, "This Mac");
        let urgent: Vec<bool> = view.items.iter().map(|f| f.needs_you).collect();
        assert_eq!(urgent, [true, true, true, true, true, false]);
        assert_eq!(view.needs_you, 5);
        assert_eq!(view.exploited, 1);
        let c = &view.counts;
        assert_eq!((c.critical, c.high, c.medium, c.low), (1, 3, 1, 1));
        assert_eq!(view.headline, "5 findings need you");
        assert_eq!(view.last_swept, Some(Timestamp::from_second(200).unwrap()));
        assert_eq!(view.dismissed, 2);
    }

    #[test]
    fn each_target_has_a_line_with_its_own_counts() {
        let view = popover_view(vec![
            target("mac", None, Vec::new(), 0),
            target(
                "server:web",
                Some(5),
                vec![open(1, Severity::Medium, false, None)],
                1,
            ),
        ]);
        let mac = &view.targets[0];
        assert_eq!(
            (mac.label.as_str(), mac.swept, mac.open),
            ("This Mac", None, 0)
        );
        assert!(matches!(mac.kind, TargetKind::Mac));
        let web = &view.targets[1];
        assert_eq!((web.label.as_str(), web.open, web.dismissed), ("web", 1, 1));
        assert!(matches!(web.kind, TargetKind::Server));
        assert_eq!(web.counts.medium, 1);
        assert_eq!(web.checked.as_deref(), Some("7 components checked"));
        assert_eq!(mac.checked, None, "not swept");
        assert_eq!(view.last_swept, Some(Timestamp::from_second(5).unwrap()));
        assert!(matches!(target_kind("github:o/r"), TargetKind::Repo));
    }

    #[test]
    fn a_target_says_how_many_components_it_checked() {
        assert_eq!(checked(0), "no components listed");
        assert_eq!(checked(1), "1 component checked");
        assert_eq!(checked(139), "139 components checked");
    }

    #[test]
    fn the_headline_names_what_needs_the_user() {
        assert_eq!(headline(0, 0, Some(Timestamp::UNIX_EPOCH)), "All clear");
        assert_eq!(headline(0, 0, None), "Not swept yet");
        assert_eq!(
            headline(0, 1, Some(Timestamp::UNIX_EPOCH)),
            "1 open, none urgent"
        );
        assert_eq!(
            headline(0, 3, Some(Timestamp::UNIX_EPOCH)),
            "3 open, none urgent"
        );
        assert_eq!(
            headline(1, 4, Some(Timestamp::UNIX_EPOCH)),
            "1 finding needs you"
        );
        assert_eq!(headline(2, 4, None), "2 findings need you");
        let view = popover_view(Vec::new());
        assert_eq!(view.headline, "Not swept yet");
        assert_eq!(view.last_swept, None);
        assert_eq!(
            view.first_sweep_hint.as_deref(),
            Some("Sweep checks your targets against the newest advisories.")
        );
        assert!(!view.all_clear, "nothing was swept yet");
        assert_eq!(view.target_count, "0 targets");
        let swept = popover_view(vec![target("mac", Some(1), Vec::new(), 0)]);
        assert!(swept.all_clear);
        assert_eq!(swept.first_sweep_hint, None);
        assert_eq!(swept.target_count, "1 target");
        let open = popover_view(vec![target(
            "mac",
            Some(1),
            vec![open(1, Severity::Low, false, None)],
            0,
        )]);
        assert!(!open.all_clear);
    }

    #[test]
    fn target_labels_drop_the_kind() {
        assert_eq!(target_label("mac"), "This Mac");
        assert_eq!(target_label("github:o/r"), "o/r");
        assert_eq!(target_label("server:web"), "web");
        assert_eq!(target_label("other"), "other");
    }
}
