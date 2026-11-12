//! Whether an advisory's affected versions cover the installed version of a component it was
//! fetched for, so the agent judges applicability instead of comparing versions by hand.
//!
//! Each pair of advisory and component gets a [`Match`]: in range, out of range, or unknown,
//! with a short reason the bundle shows the agent. The rule throughout is conservative: a
//! verdict is `OutOfRange` only when every part of the record that names the component was
//! read with certainty and puts the version outside. Anything else (a version or bound the
//! ordering does not define, a range type that needs a repository, a record that does not
//! parse) is `Unknown`. A false `OutOfRange` hides a vulnerability, which is the failure this
//! module is designed against; a false `Unknown` costs the agent one look at a record.
//!
//! OSV records are read here; NVD CPE matches in `feeds::cpe`, which applies the same rule.
//! [`keep_candidates`] then drops the out-of-range pairs from the bundle.

mod version;

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::value::RawValue;

use crate::feeds::Advisory;
use crate::package::Ecosystem;
use crate::package::Package;

/// How an advisory's affected versions relate to one installed version, and why.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub(crate) enum Match {
    /// The version is inside an affected range or listed as affected.
    InRange(String),
    /// The version could not be placed with certainty; the agent reads the record.
    Unknown(String),
    /// Every part of the record that names the component puts the version outside.
    OutOfRange(String),
}

impl Match {
    /// The name the bundle gives it: `in_range`, `unknown` or `out_of_range`.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::InRange(_) => "in_range",
            Self::Unknown(_) => "unknown",
            Self::OutOfRange(_) => "out_of_range",
        }
    }

    /// Why, in a few words for the agent: `2.88.1 < versionEndExcluding 2.89.0`.
    pub(crate) fn why(&self) -> &str {
        match self {
            Self::InRange(why) | Self::Unknown(why) | Self::OutOfRange(why) => why,
        }
    }

    /// Combines the verdicts of the parts of one record (ranges, configurations) that each
    /// could make the version affected: in range when any is, else unknown when any is,
    /// else out of range. The first of the winning kind gives the reason. `None` when there
    /// are none.
    pub(crate) fn any(verdicts: impl IntoIterator<Item = Self>) -> Option<Self> {
        let rank = |m: &Self| match m {
            Self::InRange(_) => 2,
            Self::Unknown(_) => 1,
            Self::OutOfRange(_) => 0,
        };
        verdicts.into_iter().fold(None, |best, m| match best {
            Some(b) if rank(&b) >= rank(&m) => Some(b),
            _ => Some(m),
        })
    }
}

/// An advisory and the components it was fetched for, by inventory index, each with its
/// verdict.
pub(crate) type Linked = (Advisory, BTreeMap<usize, Match>);

/// Drops from each advisory the components whose version is out of range, then the
/// advisories left with none, and returns how many advisories that dropped.
///
/// Advisories in CISA's KEV catalog are treated like any other: one whose every component is
/// provably out of range is dropped too (the owner's decision, 2026-11-10; until then every
/// KEV entry reached the agent, and on one Mac 104 of 281 advisories were KEV CVEs for macOS
/// releases long fixed). An advisory linked to no component at all is kept, since nothing
/// shows it out of range; `sweep::fetch` never produces one, as every advisory comes from a
/// component's lookup.
pub(crate) fn keep_candidates(fetched: &mut Vec<Linked>) -> usize {
    let before = fetched.len();
    fetched.retain_mut(|(_, matches)| {
        if matches.is_empty() {
            return true;
        }
        matches.retain(|_, m| !matches!(m, Match::OutOfRange(_)));
        !matches.is_empty()
    });
    before - fetched.len()
}

/// The `affected` entries of one OSV record, read once and judged against each installed
/// version.
#[derive(Debug)]
pub(crate) struct OsvRecord {
    /// `None` when the record does not parse: then nothing about it is certain.
    affected: Option<Vec<Affected>>,
}

impl OsvRecord {
    /// Reads the record.
    pub(crate) fn parse(record: &RawValue) -> Self {
        let affected = serde_json::from_str::<Record>(record.get())
            .ok()
            .map(|r| r.affected);
        Self { affected }
    }

    /// Judges `package` installed at `version`, following the evaluation in the OSV schema
    /// (<https://github.com/ossf/osv-schema/blob/7e336cc6dabe2f414d8e65f1955d1f1aa4b17d39/docs/schema.md#evaluation>):
    /// the version is affected when an `affected` entry for the package lists it in
    /// `versions` or one of its `ranges` covers it. A package of an ecosystem queried by
    /// version (an OS package) is in range without the record being read: OSV returned the
    /// record for that version, matched in the ecosystem's own ordering.
    pub(crate) fn verdict(&self, package: &Package, version: &str) -> Match {
        let ecosystem = package.ecosystem;
        if ecosystem.queried_by_version() {
            return Match::InRange(format!(
                "OSV matched {version} by {}'s own version ordering",
                ecosystem.osv_name()
            ));
        }
        let Some(affected) = &self.affected else {
            return Match::Unknown("the record does not parse as OSV".to_owned());
        };
        // OSV writes Go versions without the `v` Go puts in front (`v1.2.3`).
        let version = match ecosystem {
            Ecosystem::Go => version.strip_prefix('v').unwrap_or(version),
            _ => version,
        };
        let verdicts = affected
            .iter()
            .filter(|a| a.names(package))
            .map(|a| a.verdict(ecosystem, version));
        Match::any(verdicts).unwrap_or_else(|| {
            Match::Unknown(format!(
                "no affected entry names {} {}",
                ecosystem.osv_name(),
                package.name
            ))
        })
    }
}

/// The part of an OSV record this module reads.
#[derive(Debug, Deserialize)]
struct Record {
    #[serde(default)]
    affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    /// Absent in an entry that holds only `GIT` ranges.
    package: Option<AffectedPackage>,
    #[serde(default)]
    ranges: Vec<Range>,
    versions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct AffectedPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct Range {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<Event>,
}

/// One event. The schema allows exactly one of the four per event; [`Event::single`] checks.
#[derive(Debug, Deserialize)]
struct Event {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

/// What an event says, named as in the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventKind {
    Introduced,
    Fixed,
    LastAffected,
    Limit,
}

impl EventKind {
    fn name(self) -> &'static str {
        match self {
            Self::Introduced => "introduced",
            Self::Fixed => "fixed",
            Self::LastAffected => "last_affected",
            Self::Limit => "limit",
        }
    }
}

impl Event {
    /// The event's kind and version, or `None` unless exactly one is given.
    fn single(&self) -> Option<(EventKind, &str)> {
        let mut given = [
            (EventKind::Introduced, &self.introduced),
            (EventKind::Fixed, &self.fixed),
            (EventKind::LastAffected, &self.last_affected),
            (EventKind::Limit, &self.limit),
        ]
        .into_iter()
        .filter_map(|(kind, text)| Some((kind, text.as_deref()?)));
        let first = given.next()?;
        given.next().is_none().then_some(first)
    }
}

impl Affected {
    /// Whether this entry is about `package`. Ecosystems compare without case. Names compare
    /// as the ecosystem treats them: PyPI normalizes case and runs of `-`, `_` and `.`
    /// (<https://github.com/pypa/packaging.python.org/blob/f4b5123d448fefac85db85058668ae64f89ad05c/source/specifications/name-normalization.rst>),
    /// crates.io treats `-` and `_` as one; others compare without case. A name of `*` means
    /// every package of the ecosystem.
    fn names(&self, package: &Package) -> bool {
        let Some(named) = &self.package else {
            return false;
        };
        if !named
            .ecosystem
            .eq_ignore_ascii_case(&package.ecosystem.osv_name())
        {
            return false;
        }
        let normal = |name: &str| -> String {
            let lower = name.to_ascii_lowercase();
            match package.ecosystem {
                Ecosystem::PyPI => lower
                    .split(['-', '_', '.'])
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join("-"),
                Ecosystem::CratesIo => lower.replace('_', "-"),
                _ => lower,
            }
        };
        named.name == "*" || normal(&named.name) == normal(&package.name)
    }

    fn verdict(&self, ecosystem: Ecosystem, version: &str) -> Match {
        // An empty list adds nothing, like a missing one.
        let listed = self
            .versions
            .as_deref()
            .filter(|list| !list.is_empty())
            .map(|list| listed(Scheme::of(ecosystem), list, version));
        let ranges = self.ranges.iter().map(|r| r.verdict(ecosystem, version));
        Match::any(listed.into_iter().chain(ranges)).unwrap_or_else(|| {
            Match::Unknown("an affected entry gives neither ranges nor versions".to_owned())
        })
    }
}

impl Range {
    fn verdict(&self, ecosystem: Ecosystem, version: &str) -> Match {
        let scheme = match self.kind.as_str() {
            "SEMVER" => Scheme::SemVer,
            "ECOSYSTEM" => Scheme::of(ecosystem),
            "GIT" => return Match::Unknown("a GIT range is commits, not versions".to_owned()),
            other => return Match::Unknown(format!("a {other} range is not one Vigil reads")),
        };
        evaluate(scheme, &self.events, version)
    }
}

/// The version ordering a range is evaluated in.
#[derive(Debug, Clone, Copy)]
enum Scheme {
    SemVer,
    Pep440,
    /// Plain dotted numbers only, for RubyGems, whose `Gem::Version` orders them the same way
    /// (`1.2` equals `1.2.0`), and for the OS ecosystems, whose records are never evaluated
    /// here since OSV matched them. Anything else (`1.0.0.pre`) is unknown.
    Dotted,
}

/// A version parsed in one [`Scheme`]. A range or a `versions` list is read in one scheme, so
/// keys of different variants are never compared.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    SemVer(version::SemVer),
    Pep440(version::Pep440),
    Dotted(version::Dotted),
}

impl Key {
    /// Whether `self`, an installed version, is the version `listed` in a `versions` list: the
    /// same key, or for PEP 440 a local build of a listed public version
    /// ([`version::Pep440::is_listed_as`]). SemVer build metadata needs no such rule: it is
    /// not part of the key.
    fn is_listed_as(&self, listed: &Self) -> bool {
        match (self, listed) {
            (Self::Pep440(installed), Self::Pep440(listed)) => installed.is_listed_as(listed),
            _ => self == listed,
        }
    }
}

impl Scheme {
    /// The ordering of `ecosystem`'s own versions.
    fn of(ecosystem: Ecosystem) -> Self {
        match ecosystem {
            // Go modules are SemVer with a `v` (<https://go.dev/ref/mod#versions>), and Go
            // rejects `1.2`, so dotted numbers would wrongly make it `1.2.0`. An Actions tag
            // is SemVer by convention, and a bare major (`4`) is a moving tag, not `4.0.0`.
            Ecosystem::CratesIo | Ecosystem::Npm | Ecosystem::Go | Ecosystem::GitHubActions => {
                Self::SemVer
            }
            Ecosystem::PyPI => Self::Pep440,
            Ecosystem::RubyGems
            | Ecosystem::Debian { .. }
            | Ecosystem::Ubuntu { .. }
            | Ecosystem::Alpine { .. } => Self::Dotted,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SemVer => "SemVer",
            Self::Pep440 => "PEP 440",
            Self::Dotted => "dotted-number",
        }
    }

    fn parse(self, text: &str) -> Option<Key> {
        match self {
            Self::SemVer => version::semver(text).map(Key::SemVer),
            Self::Pep440 => version::pep440(text).map(Key::Pep440),
            Self::Dotted => version::dotted(text).map(Key::Dotted),
        }
    }

    /// The verdict for a version this scheme does not read.
    fn unreadable(self, version: &str) -> Match {
        Match::Unknown(format!("{version} is not a {} version", self.name()))
    }
}

/// Where an event sits in a range's timeline: the schema's `introduced: "0"` comes before
/// every version and a `limit` containing `*` after every version.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Bound {
    First,
    At(Key),
    Infinity,
}

/// Evaluates one range for `version`, as `IncludedInRanges` and `BeforeLimits` in the
/// schema's evaluation: the events sorted, and the last one the version has reached decides.
fn evaluate(scheme: Scheme, events: &[Event], version: &str) -> Match {
    let Some(installed) = scheme.parse(version) else {
        return scheme.unreadable(version);
    };
    let installed = Bound::At(installed);
    let timeline = match timeline(scheme, events) {
        Ok(timeline) => timeline,
        Err(unknown) => return unknown,
    };

    let limits: Vec<_> = timeline
        .iter()
        .filter(|(_, kind, _)| *kind == EventKind::Limit)
        .collect();
    // The lowest limit above the version: the one the reason can name truthfully.
    let below = limits.iter().find(|(limit, _, _)| installed < *limit);
    if below.is_none()
        && let Some(highest) = limits.last()
    {
        return Match::OutOfRange(format!("{version} >= limit {}", highest.2));
    }

    let mut last = None;
    for (i, (bound, kind, _)) in timeline.iter().enumerate() {
        let reached = match kind {
            EventKind::Introduced | EventKind::Fixed => installed >= *bound,
            EventKind::LastAffected => installed > *bound,
            EventKind::Limit => false,
        };
        if reached {
            last = Some(i);
        }
    }
    describe(&timeline, last, below.map(|(_, _, text)| *text), version)
}

/// The range's events sorted by version, each with its kind and its text as written, or the
/// unknown verdict when they cannot be ordered with certainty.
fn timeline(scheme: Scheme, events: &[Event]) -> Result<Vec<(Bound, EventKind, &str)>, Match> {
    let mut timeline = Vec::with_capacity(events.len());
    for event in events {
        let (kind, text) = event.single().ok_or_else(|| {
            Match::Unknown("an event does not give exactly one version".to_owned())
        })?;
        let bound = match (kind, text) {
            (EventKind::Introduced, "0") => Bound::First,
            (EventKind::Limit, text) if text.contains('*') => Bound::Infinity,
            (_, text) => Bound::At(
                scheme
                    .parse(text)
                    .ok_or_else(|| scheme.unreadable(&format!("{} {text}", kind.name())))?,
            ),
        };
        timeline.push((bound, kind, text));
    }
    timeline.sort_by(|a, b| a.0.cmp(&b.0));
    // Two events at one version have no order the schema defines.
    if let Some(pair) = timeline.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(Match::Unknown(format!("two events at {}", pair[0].2)));
    }
    // The schema requires one, and without it the evaluation would call every version
    // unaffected.
    if !timeline.iter().any(|(_, k, _)| *k == EventKind::Introduced) {
        return Err(Match::Unknown(
            "a range without an introduced event".to_owned(),
        ));
    }
    Ok(timeline)
}

/// The verdict for a range whose last reached event is `timeline[last]`, with the events
/// around the version as its reason. `limit` is the lowest limit above the version, if any.
fn describe(
    timeline: &[(Bound, EventKind, &str)],
    last: Option<usize>,
    limit: Option<&str>,
    version: &str,
) -> Match {
    let Some(last) = last else {
        let (_, _, first) = timeline
            .iter()
            .find(|(_, k, _)| *k == EventKind::Introduced)
            .expect("timeline rejects a range without an introduced event");
        return Match::OutOfRange(format!("{version} < introduced {first}"));
    };
    let (_, kind, text) = &timeline[last];
    match kind {
        EventKind::Introduced => {
            // Every event after `last` is above the version, so the first fix is the nearest.
            // The slice starts at `last` itself, an introduced event that `find_map` skips.
            let fix = timeline[last..]
                .iter()
                .find_map(|(_, kind, text)| match kind {
                    EventKind::Fixed => Some(format!(" and < fixed {text}")),
                    EventKind::LastAffected => Some(format!(" and <= last_affected {text}")),
                    EventKind::Introduced | EventKind::Limit => None,
                })
                .unwrap_or_default();
            // Not `map_or_default`, which beta clippy suggests: it is not stable yet.
            let limit = match limit {
                Some(l) => format!(" and < limit {l}"),
                None => String::new(),
            };
            Match::InRange(format!("{version} >= introduced {text}{fix}{limit}"))
        }
        EventKind::Fixed => Match::OutOfRange(format!("{version} >= fixed {text}")),
        EventKind::LastAffected => Match::OutOfRange(format!("{version} > last_affected {text}")),
        EventKind::Limit => unreachable!("a limit is never the last event reached"),
    }
}

/// Whether `version` is in an entry's `versions` list: the same text, or the same version in
/// the ecosystem's ordering (`1.0` and `1.0.0` in PyPI), which in PyPI includes a local build of a
/// listed version (`2.0.1+cu118` of `2.0.1`). It is out of range only when it and
/// every listed version parse, so none can be another spelling of it.
fn listed(scheme: Scheme, list: &[String], version: &str) -> Match {
    if list.iter().any(|v| v == version) {
        return Match::InRange(format!("{version} is listed in versions"));
    }
    let Some(installed) = scheme.parse(version) else {
        return scheme.unreadable(version);
    };
    let mut unreadable = None;
    for text in list {
        match scheme.parse(text) {
            Some(key) if installed.is_listed_as(&key) => {
                return Match::InRange(format!("{version} is listed in versions as {text}"));
            }
            Some(_) => {}
            None => unreadable = unreadable.or(Some(text)),
        }
    }
    match unreadable {
        Some(text) => Match::Unknown(format!(
            "versions lists {text}, which is not a {} version",
            scheme.name()
        )),
        None => Match::OutOfRange(format!(
            "{version} is not among the {} listed versions",
            list.len()
        )),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use serde_json::Value;
    use serde_json::json;

    use crate::feeds::Source;

    fn raw(record: &Value) -> Box<RawValue> {
        RawValue::from_string(record.to_string()).unwrap()
    }

    fn package(text: &str) -> Package {
        text.parse().unwrap()
    }

    /// The verdict of a record with one affected entry, `entry`, for the package `named`.
    fn judge(named: &str, mut entry: Value, version: &str) -> Match {
        let named = package(named);
        entry["package"] = json!({"ecosystem": named.ecosystem.osv_name(), "name": named.name});
        let record = json!({"id": "GHSA-1", "affected": [entry]});
        OsvRecord::parse(&raw(&record)).verdict(&named, version)
    }

    /// One `SEMVER` range for `npm:npm` with `events`, as GitHub's records in OSV write it.
    fn npm(events: &Value, version: &str) -> Match {
        let entry = json!({"ranges": [{"type": "SEMVER", "events": events}]});
        judge("npm:npm", entry, version)
    }

    fn in_range(why: &str) -> Match {
        Match::InRange(why.to_owned())
    }

    fn out(why: &str) -> Match {
        Match::OutOfRange(why.to_owned())
    }

    fn is_in(m: &Match) -> bool {
        matches!(m, Match::InRange(_))
    }

    fn is_out(m: &Match) -> bool {
        matches!(m, Match::OutOfRange(_))
    }

    fn is_unknown(m: &Match) -> bool {
        matches!(m, Match::Unknown(_))
    }

    #[test]
    fn introduced_and_fixed_bound_the_range() {
        // GHSA-4328-8hgf-7wjr.
        let events = json!([{"introduced": "0"}, {"fixed": "6.13.4"}]);
        assert_eq!(
            npm(&events, "6.13.3"),
            in_range("6.13.3 >= introduced 0 and < fixed 6.13.4")
        );
        assert_eq!(npm(&events, "6.13.4"), out("6.13.4 >= fixed 6.13.4"));
        assert!(
            is_in(&npm(&events, "6.13.4-rc.1")),
            "a pre-release comes before its release"
        );

        // GHSA-hj9c-8jmm-8c52.
        let events = json!([{"introduced": "7.9.0"}, {"fixed": "8.11.0"}]);
        assert_eq!(npm(&events, "7.8.9"), out("7.8.9 < introduced 7.9.0"));
        assert_eq!(
            npm(&events, "7.9.0"),
            in_range("7.9.0 >= introduced 7.9.0 and < fixed 8.11.0")
        );
    }

    #[test]
    fn last_affected_includes_itself() {
        let events = json!([{"introduced": "1.0.0"}, {"last_affected": "1.4.2"}]);
        assert_eq!(
            npm(&events, "1.4.2"),
            in_range("1.4.2 >= introduced 1.0.0 and <= last_affected 1.4.2")
        );
        assert_eq!(npm(&events, "1.4.3"), out("1.4.3 > last_affected 1.4.2"));
    }

    #[test]
    fn limits_cap_the_range() {
        let events = json!([{"introduced": "0"}, {"limit": "2.0.0"}]);
        assert_eq!(
            npm(&events, "1.9.9"),
            in_range("1.9.9 >= introduced 0 and < limit 2.0.0")
        );
        assert_eq!(npm(&events, "2.0.0"), out("2.0.0 >= limit 2.0.0"));

        let either = json!([{"introduced": "0"}, {"limit": "1.0.0"}, {"limit": "3.0.0"}]);
        assert!(is_in(&npm(&either, "2.0.0")), "below one of the limits");
        let star = json!([{"introduced": "0"}, {"limit": "*"}]);
        assert!(is_in(&npm(&star, "99.0.0")), "`*` is infinity");

        // The reason names only bounds that hold: the version is past the first limit.
        let mixed = json!([
            {"introduced": "1.0.0"}, {"limit": "2.0.0"}, {"fixed": "4.0.0"}, {"limit": "5.0.0"}
        ]);
        assert_eq!(
            npm(&mixed, "3.0.0"),
            in_range("3.0.0 >= introduced 1.0.0 and < fixed 4.0.0 and < limit 5.0.0")
        );
        assert_eq!(npm(&mixed, "5.0.0"), out("5.0.0 >= limit 5.0.0"));
    }

    #[test]
    fn every_range_and_entry_counts() {
        // GHSA-m5h6-hr3q-22h5 has two affected entries for npm.
        let entry = |introduced: &str, fixed: &str| {
            json!({
                "package": {"ecosystem": "npm", "name": "npm"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": introduced}, {"fixed": fixed}
                ]}]
            })
        };
        let other = json!({
            "package": {"ecosystem": "crates.io", "name": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
        });
        let affected = [entry("0", "2.15.1"), entry("3.0.0", "3.8.3"), other];
        let record = OsvRecord::parse(&raw(&json!({ "affected": affected })));
        let npm = package("npm:npm");
        assert_eq!(
            record.verdict(&npm, "3.8.2"),
            in_range("3.8.2 >= introduced 3.0.0 and < fixed 3.8.3")
        );
        assert_eq!(
            record.verdict(&npm, "2.15.1"),
            out("2.15.1 >= fixed 2.15.1"),
            "the first entry's reason; the crates.io entry is another package"
        );

        let two_ranges = json!({"ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]},
        ]});
        assert!(is_in(&judge("npm:x", two_ranges.clone(), "2.0.5")));
        assert!(is_out(&judge("npm:x", two_ranges, "1.5.0")));
    }

    #[test]
    fn listed_versions_are_affected() {
        // GHSA-wpqr-6v78-jr5g lists its one affected preview.
        let entry = json!({"versions": ["0.40.0-preview.2"]});
        let gemini = "npm:@google/gemini-cli";
        assert_eq!(
            judge(gemini, entry.clone(), "0.40.0-preview.2"),
            in_range("0.40.0-preview.2 is listed in versions")
        );
        assert_eq!(
            judge(gemini, entry, "0.40.0"),
            out("0.40.0 is not among the 1 listed versions")
        );
        assert_eq!(
            judge(
                "pypi:django",
                json!({"versions": ["4.2.0", "4.2.1"]}),
                "4.2"
            ),
            in_range("4.2 is listed in versions as 4.2.0"),
            "another spelling of the same PEP 440 version"
        );
        let torch = json!({"versions": ["2.0.1"]});
        assert_eq!(
            judge("pypi:torch", torch.clone(), "2.0.1+cu118"),
            in_range("2.0.1+cu118 is listed in versions as 2.0.1"),
            "a local build of a listed public version"
        );
        assert!(is_out(&judge("pypi:torch", torch, "2.0.2+cu118")));
        let local = json!({"versions": ["2.0.1+cu117"]});
        assert!(
            is_out(&judge("pypi:torch", local.clone(), "2.0.1+cu118")),
            "a listed local label names that build only"
        );
        assert!(is_out(&judge("pypi:torch", local.clone(), "2.0.1")));
        assert!(is_in(&judge("pypi:torch", local, "2.0.1+CU117")));
        let odd = json!({"versions": ["4.2.0", "nightly"]});
        assert!(is_unknown(&judge("pypi:django", odd, "4.3")));
        assert!(
            is_unknown(&judge("npm:x", json!({"versions": []}), "1.0.0")),
            "an empty list says nothing"
        );

        let both = json!({
            "versions": ["1.0.0"],
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}]
        });
        assert!(is_in(&judge("npm:x", both.clone(), "1.0.0")));
        assert!(is_out(&judge("npm:x", both, "1.5.0")));
    }

    #[test]
    fn ecosystem_ranges_use_the_ecosystem_ordering() {
        let ecosystem =
            |events: Value| json!({"ranges": [{"type": "ECOSYSTEM", "events": events}]});
        let django = ecosystem(json!([{"introduced": "4.2a1"}, {"fixed": "4.2.17"}]));
        assert!(is_in(&judge("pypi:Django", django.clone(), "4.2.16")));
        assert!(is_in(&judge("pypi:Django", django.clone(), "4.2rc1")));
        assert!(is_out(&judge("pypi:Django", django, "4.2.17.post1")));

        let gem = ecosystem(json!([{"introduced": "0"}, {"fixed": "2.3.1"}]));
        assert!(is_in(&judge("rubygems:rack", gem.clone(), "2.3.0")));
        assert!(is_out(&judge("rubygems:rack", gem.clone(), "2.4")));
        assert_eq!(
            judge("rubygems:rack", gem, "2.3.0.pre"),
            Match::Unknown("2.3.0.pre is not a dotted-number version".to_owned()),
            "RubyGems' own ordering is not implemented"
        );
    }

    #[test]
    fn go_versions_lose_their_v() {
        let entry = json!({"ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "0.33.0"}
        ]}]});
        let net = "go:golang.org/x/net";
        assert!(is_in(&judge(net, entry.clone(), "v0.32.0")));
        assert!(is_out(&judge(net, entry, "v0.33.0")));

        // Go rejects `1.2`, so it is not `1.2.0` there.
        let ecosystem = json!({"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.2"}
        ]}]});
        assert!(is_unknown(&judge(net, ecosystem, "v1.2.0")));
        // An Actions major tag moves; it is not 4.0.0.
        let action = json!({"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "4.0.1"}
        ]}]});
        assert!(is_unknown(&judge(
            "github actions:actions/checkout",
            action,
            "4"
        )));
    }

    #[test]
    fn names_match_as_the_ecosystem_spells_them() {
        let verdict = |ecosystem: &str, name: &str, installed: &str| {
            let record = json!({"affected": [{
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }]});
            OsvRecord::parse(&raw(&record)).verdict(&package(installed), "1.0.0")
        };
        assert!(is_in(&verdict(
            "PyPI",
            "Zope.Interface",
            "pypi:zope-interface"
        )));
        assert!(is_in(&verdict(
            "pypi",
            "zope__interface",
            "pypi:zope.interface"
        )));
        assert!(is_in(&verdict("PyPI", "*", "pypi:anything")));
        assert!(is_in(&verdict(
            "crates.io",
            "serde_json",
            "crates.io:serde-json"
        )));
        assert_eq!(
            verdict("PyPI", "other", "pypi:zope"),
            Match::Unknown("no affected entry names PyPI zope".to_owned()),
            "OSV returned it for the package, so a name that does not match is not out of range"
        );
        assert!(is_unknown(&verdict("npm", "zope", "pypi:zope")));
    }

    #[test]
    fn what_cannot_be_read_is_unknown() {
        let semver = |events: Value| json!({"ranges": [{"type": "SEMVER", "events": events}]});
        let unknown =
            |events: Value, version: &str| is_unknown(&judge("npm:x", semver(events), version));
        let fixed = json!([{"introduced": "0"}, {"fixed": "1.2.3"}]);
        assert!(unknown(fixed.clone(), "^1.2.0"), "a manifest range");
        assert!(unknown(fixed, "unknown"));
        assert!(unknown(
            json!([{"introduced": "0"}, {"fixed": "1.2"}]),
            "2.0.0"
        ));
        assert!(unknown(
            json!([{"introduced": "0", "fixed": "1.0.0"}]),
            "2.0.0"
        ));
        assert!(unknown(json!([{}]), "2.0.0"));
        assert!(
            unknown(json!([{"fixed": "1.0.0"}]), "2.0.0"),
            "no introduced"
        );
        assert_eq!(
            judge(
                "npm:x",
                semver(json!([{"introduced": "1.0.0"}, {"fixed": "1.0.0"}])),
                "2.0.0"
            ),
            Match::Unknown("two events at 1.0.0".to_owned())
        );
        assert_eq!(
            judge(
                "npm:x",
                semver(json!([{"introduced": "0"}, {"fixed": "1.x"}])),
                "2.0.0"
            ),
            Match::Unknown("fixed 1.x is not a SemVer version".to_owned())
        );

        let git = json!({"ranges": [{"type": "GIT", "repo": "r", "events": [
            {"introduced": "0"}, {"fixed": "a1b2c3"}
        ]}]});
        assert!(is_unknown(&judge("npm:x", git, "2.0.0")));
        let other = json!({"ranges": [{"type": "OTHER", "events": [{"introduced": "0"}]}]});
        assert!(is_unknown(&judge("npm:x", other, "2.0.0")));
        assert!(
            is_unknown(&judge("npm:x", json!({}), "2.0.0")),
            "neither ranges nor versions"
        );

        let broken = OsvRecord::parse(&raw(&json!({"affected": "no"})));
        assert!(is_unknown(&broken.verdict(&package("npm:x"), "1.0.0")));
    }

    #[test]
    fn os_packages_were_matched_by_osv() {
        let debian = Package {
            ecosystem: Ecosystem::Debian { release: 12 },
            name: "openssl".to_owned(),
        };
        let record = OsvRecord::parse(&raw(&json!({"affected": []})));
        assert_eq!(
            record.verdict(&debian, "3.0.15-1~deb12u1"),
            in_range("OSV matched 3.0.15-1~deb12u1 by Debian:12's own version ordering")
        );
    }

    #[test]
    fn the_strongest_verdict_wins() {
        let unknown = Match::Unknown("u".to_owned());
        let all = [out("a"), unknown.clone(), in_range("b"), in_range("c")];
        assert_eq!(Match::any(all), Some(in_range("b")));
        assert_eq!(
            Match::any([out("a"), unknown.clone(), out("d")]),
            Some(unknown)
        );
        assert_eq!(Match::any([out("a"), out("d")]), Some(out("a")));
        assert_eq!(Match::any([]), None);
    }

    fn advisory(id: &str) -> Advisory {
        Advisory {
            source: Source::Osv,
            id: id.to_owned(),
            aliases: vec![format!("CVE-{id}")],
            modified: None,
            record: raw(&json!({})),
        }
    }

    #[test]
    fn candidates_keep_in_range_and_unknown_pairs_only() {
        let unknown = Match::Unknown("u".to_owned());
        let mut fetched = vec![
            (
                advisory("1"),
                [(0, in_range("i")), (1, unknown), (2, out("o"))].into(),
            ),
            (advisory("2"), [(0, out("o")), (1, out("o"))].into()),
            (advisory("3"), BTreeMap::new()),
        ];
        assert_eq!(keep_candidates(&mut fetched), 1);
        let kept: Vec<(&str, Vec<usize>)> = fetched
            .iter()
            .map(|(a, m)| (a.id.as_str(), m.keys().copied().collect()))
            .collect();
        assert_eq!(
            kept,
            [("1", vec![0, 1]), ("3", vec![])],
            "an advisory with no component is not shown out of range"
        );
    }

    proptest! {
        /// A version no ordering reads is never out of range, whatever the range.
        #[test]
        fn unreadable_versions_are_never_out_of_range(
            version in "[0-9a-z^~<>=*. -]{0,8}",
            fixed in "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}",
            kind in prop::sample::select(vec!["SEMVER", "ECOSYSTEM"]),
            ecosystem in prop::sample::select(vec!["npm", "pypi", "rubygems", "crates.io"]),
        ) {
            let readable = version::semver(&version).is_some()
                || version::pep440(&version).is_some()
                || version::dotted(&version).is_some();
            prop_assume!(!readable);
            let entry = json!({"ranges": [{"type": kind, "events": [
                {"introduced": "0"}, {"fixed": fixed}
            ]}]});
            let verdict = judge(&format!("{ecosystem}:x"), entry, &version);
            prop_assert!(is_unknown(&verdict), "{:?}", verdict);
        }

        /// An `introduced`/`fixed` range covers exactly the versions from one up to the other,
        /// here in the ordering of dotted numbers.
        #[test]
        fn a_range_covers_what_lies_between_its_events(
            installed in prop::collection::vec(0_u64..5, 1..4),
            introduced in prop::collection::vec(0_u64..5, 1..4),
            fixed in prop::collection::vec(0_u64..5, 1..4),
        ) {
            let text = |v: &[u64]| v.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
            let key = |v: &[u64]| version::dotted(&text(v)).unwrap();
            prop_assume!(key(&introduced) < key(&fixed));
            let entry = json!({"ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": text(&introduced)}, {"fixed": text(&fixed)}
            ]}]});
            let verdict = judge("rubygems:x", entry, &text(&installed));
            let inside = key(&introduced) <= key(&installed) && key(&installed) < key(&fixed);
            prop_assert_eq!(is_in(&verdict), inside, "{:?}", verdict);
            prop_assert_eq!(is_out(&verdict), !inside, "{:?}", verdict);
        }
    }
}
