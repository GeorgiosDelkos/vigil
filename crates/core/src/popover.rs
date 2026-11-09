//! What the menu-bar popover shows, worked out from each target's [`Latest`] so the app's UI
//! only lays it out: the open findings ranked by risk, their counts, the headline, and one
//! line per target.
//!
//! The ranking puts what needs the user first: exploited in the wild (CISA KEV), then by
//! severity, then the newest. A finding "needs you" when it is exploited, critical or high.

use jiff::Timestamp;
use serde::Serialize;

use crate::findings::Severity;
use crate::lifecycle::Fixed;
use crate::lifecycle::Latest;
use crate::lifecycle::Open;

/// The popover's content.
#[derive(Debug, Serialize)]
pub struct PopoverView {
    /// Every open finding across targets, ranked by risk.
    pub findings: Vec<Listed>,
    /// Confirmed fixes that finished in the last 30 days, newest first. A fix only reported
    /// is still in `findings`, marked by its `fix_state`.
    pub fixed: Vec<FixedListed>,
    /// How many of them need the user.
    pub needs_you: usize,
    /// How many are exploited in the wild.
    pub exploited: usize,
    /// How many there are of each severity.
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
    /// How many findings are dismissed across targets.
    pub dismissed: usize,
}

/// An open finding with where it was found.
#[derive(Debug, Serialize)]
pub struct Listed {
    /// The finding.
    #[serde(flatten)]
    pub open: Open,
    /// Its target, as [`target_label`] shows it.
    pub target: String,
    /// Whether it needs the user now.
    pub needs_you: bool,
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

/// How many open findings there are of each severity.
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
    fn of<'a>(open: impl IntoIterator<Item = &'a Open>) -> Self {
        let mut counts = Self::default();
        for o in open {
            *match o.severity {
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
    /// What that sweep checked, one phrase: "139 packages checked", or "no packages listed"
    /// when it found none (a repository without a dependency graph, for one); `None` before
    /// a sweep.
    pub checked: Option<String>,
    /// Its open findings by severity.
    pub counts: Counts,
    /// How many open findings it has.
    pub open: usize,
    /// How many are dismissed.
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
pub fn popover_view(mut latest: Vec<Latest>) -> PopoverView {
    let targets: Vec<TargetLine> = latest.iter().map(target_line).collect();
    let last_swept = latest.iter().filter_map(|t| t.swept).max();
    let dismissed = latest.iter().map(|t| t.dismissed).sum();
    let mut fixed: Vec<FixedListed> = latest
        .iter_mut()
        .flat_map(|t| {
            let label = target_label(&t.target).to_owned();
            std::mem::take(&mut t.fixed)
                .into_iter()
                .map(move |fixed| FixedListed {
                    fixed,
                    target: label.clone(),
                })
        })
        .collect();
    fixed.sort_by_key(|f| std::cmp::Reverse(f.fixed.fixed_at));

    let mut findings: Vec<Listed> = latest
        .into_iter()
        .flat_map(|t| {
            let label = target_label(&t.target).to_owned();
            t.open.into_iter().map(move |open| Listed {
                needs_you: needs_you(&open),
                target: label.clone(),
                open,
            })
        })
        .collect();
    // Stable, so findings that tie keep their targets' sweep order.
    findings.sort_by(|a, b| {
        (b.open.known_exploited.cmp(&a.open.known_exploited))
            .then(a.open.severity.cmp(&b.open.severity))
            .then(b.open.first_seen.cmp(&a.open.first_seen))
    });

    let needs_you = findings.iter().filter(|f| f.needs_you).count();
    PopoverView {
        needs_you,
        exploited: findings.iter().filter(|f| f.open.known_exploited).count(),
        counts: Counts::of(findings.iter().map(|f| &f.open)),
        headline: headline(needs_you, findings.len(), last_swept),
        all_clear: findings.is_empty() && last_swept.is_some(),
        first_sweep_hint: last_swept
            .is_none()
            .then(|| "Sweep checks your targets against the newest advisories.".to_owned()),
        target_count: match targets.len() {
            1 => "1 target".to_owned(),
            n => format!("{n} targets"),
        },
        findings,
        fixed,
        last_swept,
        targets,
        dismissed,
    }
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

fn target_line(latest: &Latest) -> TargetLine {
    TargetLine {
        label: target_label(&latest.target).to_owned(),
        kind: target_kind(&latest.target),
        swept: latest.swept,
        checked: latest.swept.map(|_| checked(latest.components)),
        counts: Counts::of(&latest.open),
        open: latest.open.len(),
        dismissed: latest.dismissed,
    }
}

fn checked(components: usize) -> String {
    match components {
        0 => "no packages listed".to_owned(),
        1 => "1 package checked".to_owned(),
        n => format!("{n} packages checked"),
    }
}

fn needs_you(open: &Open) -> bool {
    open.known_exploited || matches!(open.severity, Severity::Critical | Severity::High)
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

    fn open(key: u64, severity: Severity, exploited: bool, first_seen: Option<i64>) -> Open {
        Open {
            key: format!("{key:016x}").parse().unwrap(),
            severity,
            title: format!("finding {key}"),
            name: "pkg".to_owned(),
            version: None,
            advisories: Vec::new(),
            place: String::new(),
            known_exploited: exploited,
            explanation: String::new(),
            fix: String::new(),
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
        view.findings.iter().map(|f| f.open.title.clone()).collect()
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
        assert!(view.findings.is_empty());
        assert_eq!((view.needs_you, view.counts.critical), (0, 0));
        assert!(view.all_clear, "nothing is open");
    }

    #[test]
    fn findings_rank_exploited_then_by_severity_then_newest() {
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
        assert_eq!(view.findings[0].target, "o/r");
        assert_eq!(view.findings[2].target, "This Mac");
        let urgent: Vec<bool> = view.findings.iter().map(|f| f.needs_you).collect();
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
        assert_eq!(web.checked.as_deref(), Some("7 packages checked"));
        assert_eq!(mac.checked, None, "not swept");
        assert_eq!(view.last_swept, Some(Timestamp::from_second(5).unwrap()));
        assert!(matches!(target_kind("github:o/r"), TargetKind::Repo));
    }

    #[test]
    fn a_target_says_how_many_packages_it_checked() {
        assert_eq!(checked(0), "no packages listed");
        assert_eq!(checked(1), "1 package checked");
        assert_eq!(checked(139), "139 packages checked");
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
