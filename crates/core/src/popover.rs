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
//!
//! An item whose fix the agent reported done is not open. The owner verified such a fix by
//! hand and decided on 2026-11-11, replacing the 2026-11-08 rule that kept it counted, that it
//! shows green and says it is fixed. It is a [`ReportedFix`], kept apart from the open
//! [`Listed`] items, so nothing counts it by mistake. The next sweep still confirms it: one
//! that still finds it marks it "Still found after a fix" and it is open again, and one that
//! no longer finds it lists it under [`PopoverView::fixed`].
//!
//! A fix is for the installed component, so the fix history of every finding in an item
//! decides, not the lead's alone (decided 2026-11-11): `vigil fix` takes any finding's key, and
//! a dismissal can change which finding leads. An item is a reported fix when at least one of
//! its findings has a fix reported done without a pull request, and none has a fix a later
//! sweep still found ([`PendingFix::NotHeld`]) or a fix that opened a pull request
//! ([`PendingFix::PullRequest`]); otherwise it stays open and counted, whole. A pull request
//! keeps the item open until a sweep no longer finds it: Vigil does not check whether it was
//! merged. A component's findings are never split between open and fixed: a fix that upgraded
//! or removed the component fixed all of them, and splitting would leave its other advisories
//! red after the version is gone, which is what the owner reported. An issue is an item of
//! one finding.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::Serialize;

use crate::findings::Severity;
use crate::lifecycle::FixState;
use crate::lifecycle::Fixed;
use crate::lifecycle::Latest;
use crate::lifecycle::Open;

/// The popover's content.
#[derive(Debug, Serialize)]
pub struct PopoverView {
    /// Every open item across targets, ranked by risk.
    pub items: Vec<Listed>,
    /// The list tab the main view's centre opens: Fixed when nothing is open but fixes wait
    /// for the next sweep, so the user lands on them; Needs you otherwise.
    pub list_tab: ListTab,
    /// What the main view's centre shows when nothing is open but fixes wait for the next
    /// sweep: their number over "to confirm", as it shows what needs the user (the owner's
    /// choice, 2026-11-11). `None` otherwise.
    pub to_confirm: Option<Figure>,
    /// Items whose fix the agent reported done, newest fix first; the next sweep confirms
    /// them. Not open, so counted nowhere else.
    pub reported: Vec<ReportedFix>,
    /// Confirmed fixes that finished in the last 30 days, newest first.
    pub fixed: Vec<FixedListed>,
    /// How many items need the user.
    pub needs_you: usize,
    /// How many items hold a finding exploited in the wild.
    pub exploited: usize,
    /// How many items there are at each worst severity.
    pub counts: Counts,
    /// The top line: "2 findings need you", "1 fix to confirm", "All clear".
    pub headline: String,
    /// When the newest sweep of any target started.
    pub last_swept: Option<Timestamp>,
    /// The line under the headline while no sweep time is known, saying what Sweep does; the
    /// headline already says "Not swept yet", so the line under it does not repeat it. None
    /// once a sweep time is known, when the line says how long ago that was.
    pub first_sweep_hint: Option<String>,
    /// Whether a sweep ran, nothing is open, and no reported fix waits for the next sweep.
    pub all_clear: bool,
    /// How many targets there are: "1 target", "3 targets".
    pub target_count: String,
    /// One line per target, in sweep order.
    pub targets: Vec<TargetLine>,
    /// How many findings are dismissed across targets. Findings, not items: a dismissal is
    /// of one advisory.
    pub dismissed: usize,
}

impl PopoverView {
    /// The worst severity among the open items, for the tray icon; `None` when nothing is open.
    /// Reported fixes are not open, so they never colour it.
    pub fn worst(&self) -> Option<Severity> {
        self.items.iter().map(|item| item.severity).min()
    }
}

/// A number with the words under it, as the main view's centre shows it.
#[derive(Debug, Serialize)]
pub struct Figure {
    /// The number.
    pub count: usize,
    /// What it counts: "to confirm".
    pub label: String,
}

/// A tab of the popover's list.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListTab {
    /// What needs the user.
    Needs,
    /// The reported and the confirmed fixes.
    Fixed,
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
    /// Its target as configured, the [`TargetLine::key`] of its target's line.
    pub target_key: String,
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
    /// What keeps a fix of it from counting as done, when a finding in it has one.
    pub pending_fix: Option<PendingFix>,
}

/// What keeps an item's fix from counting as done. A fix that did not hold wins over a pull
/// request: it is the more urgent to know.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingFix {
    /// A fix ended `fixed`, but a later sweep still found its finding.
    NotHeld,
    /// A fix opened a pull request. The item stays open until a sweep no longer finds it:
    /// whether the pull request was merged is not checked.
    PullRequest,
}

impl Listed {
    /// Its findings, ranked: the lead, then the others.
    pub fn findings(&self) -> impl Iterator<Item = &Open> {
        std::iter::once(&self.lead).chain(&self.others)
    }
}

/// One target's items: the open ones, and those whose fix the agent reported done.
#[derive(Debug)]
pub struct Items {
    /// The open items, ranked by risk.
    pub open: Vec<Listed>,
    /// The items whose fix was reported, ranked the same way.
    pub reported: Vec<ReportedFix>,
}

/// An item with a fix reported done on the target, as the module docs set out; the next sweep
/// confirms it.
#[derive(Debug, Serialize)]
pub struct ReportedFix {
    /// The item as the sweep found it, with every finding in it; its `advisory_count` says
    /// how many, so none is hidden unnamed.
    pub item: Listed,
    /// What its row says: "Fixed · the next sweep confirms it".
    pub status: String,
    /// The agent's one-line summary of the newest fix reported for it.
    pub summary: String,
    /// When that fix finished.
    pub fixed_at: Timestamp,
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
    /// The target as configured: `mac`, `github:owner/name` or `server:name`. Its items carry
    /// it as [`Listed::target_key`], so the UI lists one target's items by this key, not by a
    /// label two targets can share (`github:web` and `server:web` both read `web`).
    pub key: String,
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
    /// How many of its items have a fix the next sweep confirms, as its status line says:
    /// "1 fix to confirm"; `None` when none has.
    pub to_confirm: Option<String>,
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
    let mut reported = Vec::new();
    let mut all = Vec::new();
    for mut target in latest {
        let label = target_label(&target.target).to_owned();
        let listed = items(&target.target, std::mem::take(&mut target.open));
        targets.push(target_line(&target, &listed));
        fixed.extend(target.fixed.into_iter().map(|fixed| FixedListed {
            fixed,
            target: label.clone(),
        }));
        all.extend(listed.open);
        reported.extend(listed.reported);
    }
    fixed.sort_by_key(|f| Reverse(f.fixed.fixed_at));
    reported.sort_by_key(|r| Reverse(r.fixed_at));
    // Stable, so items that tie keep their targets' sweep order.
    all.sort_by_key(|item| risk(item.known_exploited, item.severity, item.first_seen));

    let needs_you = all.iter().filter(|item| item.needs_you).count();
    // One test for both fields, so the centre's number and the tab it opens cannot disagree.
    let only_reported = all.is_empty() && !reported.is_empty();
    PopoverView {
        list_tab: if only_reported {
            ListTab::Fixed
        } else {
            ListTab::Needs
        },
        to_confirm: only_reported.then(|| Figure {
            count: reported.len(),
            label: "to confirm".to_owned(),
        }),
        needs_you,
        exploited: all.iter().filter(|item| item.known_exploited).count(),
        counts: Counts::of(&all),
        headline: headline(needs_you, all.len(), reported.len(), last_swept),
        all_clear: all.is_empty() && reported.is_empty() && last_swept.is_some(),
        first_sweep_hint: last_swept
            .is_none()
            .then(|| "Sweep checks your targets against the newest advisories.".to_owned()),
        target_count: match targets.len() {
            1 => "1 target".to_owned(),
            n => format!("{n} targets"),
        },
        items: all,
        reported,
        fixed,
        last_swept,
        targets,
        dismissed,
    }
}

/// One target's open findings and issues as items, ranked by risk: one per installed
/// component, holding every finding in it, and one per issue, with the items whose fix was
/// reported set apart. `target` is the target as configured (`mac`, `github:owner/name`).
pub fn items(target: &str, open: Vec<Open>) -> Items {
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
    let mut split = Items {
        open: Vec::new(),
        reported: Vec::new(),
    };
    for item in items {
        match reported_fix(item) {
            Ok(fix) => split.reported.push(fix),
            Err(item) => split.open.push(item),
        }
    }
    split
}

/// `item` as a reported fix when, over all its findings, a fix was reported done and nothing
/// keeps it from counting (see the module docs); `item` back, whole, when it stays open.
#[expect(
    clippy::result_large_err,
    reason = "the one caller moves either variant into a Vec at once; boxing the item would \
              allocate for nothing"
)]
fn reported_fix(item: Listed) -> Result<ReportedFix, Listed> {
    if item.pending_fix.is_some() {
        return Err(item);
    }
    let newest = item
        .findings()
        .filter_map(|f| match &f.fix_state {
            Some(FixState::Reported {
                at,
                summary,
                pull_request: None,
            }) => Some((*at, summary.clone())),
            Some(FixState::Reported { .. } | FixState::NotHeld { .. }) | None => None,
        })
        .max_by_key(|(at, _)| *at);
    let Some((fixed_at, summary)) = newest else {
        return Err(item);
    };
    Ok(ReportedFix {
        item,
        status: "Fixed · the next sweep confirms it".to_owned(),
        summary,
        fixed_at,
    })
}

/// What keeps a fix of `findings` from counting as done, if anything.
fn pending_fix<'a>(findings: impl Iterator<Item = &'a Open>) -> Option<PendingFix> {
    let mut pending = None;
    for finding in findings {
        match finding.fix_state {
            Some(FixState::NotHeld { .. }) => return Some(PendingFix::NotHeld),
            Some(FixState::Reported {
                pull_request: Some(_),
                ..
            }) => pending = Some(PendingFix::PullRequest),
            Some(FixState::Reported {
                pull_request: None, ..
            })
            | None => {}
        }
    }
    pending
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
        target: target_label(target).to_owned(),
        target_key: target.to_owned(),
        name,
        severity,
        known_exploited,
        needs_you: known_exploited || matches!(severity, Severity::Critical | Severity::High),
        first_seen: all().filter_map(|f| f.first_seen).min(),
        new: all().any(|f| f.new),
        advisory_count,
        fix_scope,
        pending_fix: pending_fix(all()),
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

/// The line of `latest`, whose findings are `items`.
fn target_line(latest: &Latest, items: &Items) -> TargetLine {
    TargetLine {
        key: latest.target.clone(),
        label: target_label(&latest.target).to_owned(),
        kind: target_kind(&latest.target),
        swept: latest.swept,
        checked: latest.swept.map(|_| checked(latest.components)),
        counts: Counts::of(&items.open),
        open: items.open.len(),
        to_confirm: (!items.reported.is_empty()).then(|| to_confirm(items.reported.len())),
        dismissed: latest.dismissed,
    }
}

/// "1 fix to confirm", "2 fixes to confirm".
fn to_confirm(fixes: usize) -> String {
    match fixes {
        1 => "1 fix to confirm".to_owned(),
        n => format!("{n} fixes to confirm"),
    }
}

fn checked(components: usize) -> String {
    match components {
        0 => "no components listed".to_owned(),
        1 => "1 component checked".to_owned(),
        n => format!("{n} components checked"),
    }
}

/// The top line. With nothing open but fixes reported, it says how many the next sweep
/// confirms: "All clear" would claim more than the agent's word, and a count of open items
/// would call fixed ones open.
fn headline(
    needs_you: usize,
    open: usize,
    reported: usize,
    last_swept: Option<Timestamp>,
) -> String {
    match (needs_you, open) {
        (0, 0) if last_swept.is_none() => "Not swept yet".to_owned(),
        (1, _) => "1 finding needs you".to_owned(),
        (0, 0) if reported == 0 => "All clear".to_owned(),
        (0, 0) => to_confirm(reported),
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
        )
        .open;
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
        )
        .open;
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
        )
        .open;
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

    /// `finding` with a fix reported at second `at`, which opened `pull_request` if any.
    fn fix_reported(mut finding: Open, at: i64, pull_request: Option<&str>) -> Open {
        finding.fix_state = Some(FixState::Reported {
            at: Timestamp::from_second(at).unwrap(),
            summary: format!("fixed {}", finding.title),
            pull_request: pull_request.map(str::to_owned),
        });
        finding
    }

    #[test]
    fn a_reported_fix_is_not_open_and_counted_nowhere() {
        let node = in_component(
            open(1, Severity::Critical, true, None),
            "node.js",
            "22.22.2",
        );
        let view = popover_view(vec![target(
            "github:o/r",
            Some(100),
            vec![
                fix_reported(node, 50, None),
                fix_reported(open(2, Severity::High, false, None), 60, Some("pr 7")),
                open(3, Severity::Low, false, None),
            ],
            0,
        )]);

        assert_eq!(
            keys(&view),
            ["finding 2", "finding 3"],
            "a fix with an open pull request has not landed, so it stays open"
        );
        let [reported] = &view.reported[..] else {
            panic!("one fix reported: {:?}", view.reported);
        };
        assert_eq!(reported.item.name, "node.js");
        assert_eq!(reported.item.target, "o/r");
        assert_eq!(reported.status, "Fixed · the next sweep confirms it");
        assert_eq!(reported.summary, "fixed finding 1");
        assert_eq!(reported.fixed_at, Timestamp::from_second(50).unwrap());

        assert_eq!((view.needs_you, view.exploited), (1, 0));
        let c = &view.counts;
        assert_eq!((c.critical, c.high, c.medium, c.low), (0, 1, 0, 1));
        assert_eq!(view.headline, "1 finding needs you");
        let line = &view.targets[0];
        assert_eq!(
            (line.open, line.counts.critical, line.counts.high),
            (2, 0, 1)
        );
        assert!(!view.all_clear);
        assert_eq!(line.to_confirm.as_deref(), Some("1 fix to confirm"));
        assert!(matches!(view.list_tab, ListTab::Needs), "something is open");
        assert!(view.to_confirm.is_none(), "the centre counts what is open");
    }

    #[test]
    fn with_only_reported_fixes_left_the_headline_counts_fixes_to_confirm() {
        let one = popover_view(vec![target(
            "mac",
            Some(100),
            vec![fix_reported(open(1, Severity::High, false, None), 10, None)],
            0,
        )]);
        assert!(one.items.is_empty());
        assert_eq!(one.headline, "1 fix to confirm");
        assert!(!one.all_clear, "not clear until a sweep confirms the fix");
        assert_eq!((one.needs_you, one.targets[0].open), (0, 0));
        assert_eq!(
            one.targets[0].to_confirm.as_deref(),
            Some("1 fix to confirm")
        );
        assert!(
            matches!(one.list_tab, ListTab::Fixed),
            "the centre opens the fixes"
        );
        let figure = one
            .to_confirm
            .as_ref()
            .expect("only reported fixes are left");
        assert_eq!((figure.count, figure.label.as_str()), (1, "to confirm"));

        let two = popover_view(vec![target(
            "mac",
            Some(100),
            vec![
                fix_reported(open(1, Severity::High, false, None), 10, None),
                fix_reported(open(2, Severity::Low, false, None), 20, None),
            ],
            0,
        )]);
        assert_eq!(two.headline, "2 fixes to confirm");
        let figure = two
            .to_confirm
            .as_ref()
            .expect("only reported fixes are left");
        assert_eq!((figure.count, figure.label.as_str()), (2, "to confirm"));
        assert_eq!(
            two.targets[0].to_confirm.as_deref(),
            Some("2 fixes to confirm")
        );
        let titles: Vec<&str> = two
            .reported
            .iter()
            .map(|r| r.item.lead.title.as_str())
            .collect();
        assert_eq!(titles, ["finding 2", "finding 1"], "newest fix first");
    }

    /// `listed` as one item, open or reported, and whether it is reported.
    fn one(listed: &Items) -> (&Listed, bool) {
        match (&listed.open[..], &listed.reported[..]) {
            ([item], []) => (item, false),
            ([], [fix]) => (&fix.item, true),
            _ => panic!("one item: {listed:?}"),
        }
    }

    #[test]
    fn a_fix_of_any_finding_in_a_component_fixes_the_whole_item() {
        let node = |key, severity| in_component(open(key, severity, false, None), "node", "22");

        let listed = items(
            "This Mac",
            vec![
                node(1, Severity::Critical),
                fix_reported(node(2, Severity::Low), 10, None),
                node(3, Severity::High),
            ],
        );
        let (item, reported) = one(&listed);
        assert!(reported, "a fix run on a key that does not lead");
        assert_eq!(item.lead.title, "finding 1", "every finding stays in it");
        assert_eq!(titles(&item.others), ["finding 3", "finding 2"]);
        assert_eq!(item.advisory_count.as_deref(), Some("3 advisories"));
        assert!(item.pending_fix.is_none());

        // The lead dismissed after the fix: the fixed finding is still there, so it is fixed.
        let listed = items(
            "This Mac",
            vec![
                fix_reported(node(2, Severity::Low), 10, None),
                node(3, Severity::High),
            ],
        );
        assert!(one(&listed).1, "which finding leads does not matter");

        // The fixed finding itself dismissed: its fix history goes with it, and nothing says
        // the rest was fixed, so they stay open until a sweep checks them.
        let listed = items("This Mac", vec![node(3, Severity::High)]);
        assert!(!one(&listed).1);

        let listed = items(
            "This Mac",
            vec![
                fix_reported(node(1, Severity::High), 10, None),
                fix_reported(node(2, Severity::Low), 30, None),
            ],
        );
        let fix = &listed.reported[0];
        assert_eq!(
            (fix.summary.as_str(), fix.fixed_at),
            ("fixed finding 2", Timestamp::from_second(30).unwrap()),
            "the newest fix speaks for the item"
        );
    }

    #[test]
    fn a_fix_that_did_not_hold_or_has_not_landed_keeps_the_whole_item_open() {
        let node = |key, severity| in_component(open(key, severity, false, None), "node", "22");
        let mut not_held = node(2, Severity::Low);
        not_held.fix_state = Some(FixState::NotHeld {
            at: Timestamp::UNIX_EPOCH,
        });
        let listed = items(
            "This Mac",
            vec![
                fix_reported(node(1, Severity::High), 10, None),
                not_held,
                fix_reported(node(3, Severity::Low), 20, Some("pr 7")),
            ],
        );
        let (item, reported) = one(&listed);
        assert!(!reported, "a later sweep proved a fix did not hold");
        assert_eq!(1 + item.others.len(), 3, "open whole, not split");
        assert!(
            matches!(item.pending_fix, Some(PendingFix::NotHeld)),
            "{item:?}"
        );

        let listed = items(
            "This Mac",
            vec![
                fix_reported(node(1, Severity::High), 10, None),
                fix_reported(node(2, Severity::Low), 20, Some("pr 7")),
            ],
        );
        let (item, reported) = one(&listed);
        assert!(
            !reported,
            "a pull request keeps it open until a sweep confirms it"
        );
        assert!(
            matches!(item.pending_fix, Some(PendingFix::PullRequest)),
            "{item:?}"
        );

        let listed = items("This Mac", vec![node(1, Severity::High)]);
        assert!(
            one(&listed).0.pending_fix.is_none(),
            "no fix, nothing pending"
        );
    }

    #[test]
    fn an_issue_is_its_own_item_of_one_finding() {
        let listed = items(
            "o/r",
            vec![
                fix_reported(open(1, Severity::High, false, None), 10, None),
                open(2, Severity::High, false, None),
            ],
        );
        assert_eq!(keys_of(&listed.open), ["finding 2"]);
        assert_eq!(listed.reported[0].item.lead.title, "finding 1");
        assert_eq!(listed.reported[0].item.advisory_count, None);
    }

    fn keys_of(items: &[Listed]) -> Vec<&str> {
        items.iter().map(|i| i.lead.title.as_str()).collect()
    }

    #[test]
    fn the_worst_open_item_colours_the_tray_and_a_reported_fix_does_not() {
        let view = popover_view(vec![target(
            "mac",
            Some(100),
            vec![
                fix_reported(open(1, Severity::Critical, false, None), 10, None),
                open(2, Severity::Medium, false, None),
            ],
            0,
        )]);
        assert_eq!(view.worst(), Some(Severity::Medium));
        let view = popover_view(vec![target(
            "mac",
            Some(100),
            vec![fix_reported(
                open(1, Severity::Critical, false, None),
                10,
                None,
            )],
            0,
        )]);
        assert_eq!(view.worst(), None);
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
    fn items_and_reported_fixes_carry_their_target_lines_key() {
        let view = popover_view(vec![
            target(
                "github:web",
                Some(5),
                vec![
                    open(1, Severity::High, false, None),
                    fix_reported(open(2, Severity::Low, false, None), 4, None),
                ],
                0,
            ),
            target(
                "server:web",
                Some(5),
                vec![open(3, Severity::Critical, false, None)],
                0,
            ),
        ]);

        let lines: Vec<(&str, &str)> = view
            .targets
            .iter()
            .map(|t| (t.key.as_str(), t.label.as_str()))
            .collect();
        assert_eq!(lines, [("github:web", "web"), ("server:web", "web")]);
        let items: Vec<(&str, &str, &str)> = view
            .items
            .iter()
            .map(|i| {
                (
                    i.lead.title.as_str(),
                    i.target_key.as_str(),
                    i.target.as_str(),
                )
            })
            .collect();
        assert_eq!(
            items,
            [
                ("finding 3", "server:web", "web"),
                ("finding 1", "github:web", "web"),
            ],
            "one label, told apart by key"
        );
        let [reported] = &view.reported[..] else {
            panic!("one fix reported: {:?}", view.reported);
        };
        assert_eq!(reported.item.target_key, "github:web");
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
        assert_eq!(headline(0, 0, 0, Some(Timestamp::UNIX_EPOCH)), "All clear");
        assert_eq!(headline(0, 0, 0, None), "Not swept yet");
        assert_eq!(
            headline(0, 1, 0, Some(Timestamp::UNIX_EPOCH)),
            "1 open, none urgent"
        );
        assert_eq!(
            headline(0, 3, 0, Some(Timestamp::UNIX_EPOCH)),
            "3 open, none urgent"
        );
        assert_eq!(
            headline(1, 4, 0, Some(Timestamp::UNIX_EPOCH)),
            "1 finding needs you"
        );
        assert_eq!(headline(2, 4, 0, None), "2 findings need you");
        let swept = Some(Timestamp::UNIX_EPOCH);
        assert_eq!(headline(0, 0, 1, swept), "1 fix to confirm");
        assert_eq!(headline(0, 0, 3, swept), "3 fixes to confirm");
        assert_eq!(
            headline(0, 2, 1, swept),
            "2 open, none urgent",
            "open comes first"
        );
        assert_eq!(headline(0, 0, 1, None), "Not swept yet");
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
        assert_eq!(open.targets[0].to_confirm, None, "no fix reported");
        assert!(matches!(open.list_tab, ListTab::Needs));
        assert!(matches!(popover_view(Vec::new()).list_tab, ListTab::Needs));
        assert!(swept.to_confirm.is_none(), "all clear");
    }

    #[test]
    fn target_labels_drop_the_kind() {
        assert_eq!(target_label("mac"), "This Mac");
        assert_eq!(target_label("github:o/r"), "o/r");
        assert_eq!(target_label("server:web"), "web");
        assert_eq!(target_label("other"), "other");
    }
}
