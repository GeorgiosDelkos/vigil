//! Whether an NVD CVE's CPE matches cover the version installed, as a [`Match`] with its
//! reason, under the conservative rule in `matching`.
//!
//! NVD returns every CVE whose configurations name a product, at any version, and also those
//! that name it only as the platform another product runs on. For macOS that is over 7000
//! CVEs, nearly all of them fixed long ago or in other software (measured on one Mac,
//! 2026-11-08: 10304 advisories in a bundle). The agent still decides what is affected; this
//! only finds the CVEs that cannot be, and says unknown whenever it cannot tell:
//!
//! - a CVE is in range when any match that marks the product vulnerable covers the version;
//! - a range covers a version unless one of its bounds puts the version cleanly outside, and
//!   is unknown when a bound does not compare cleanly. `1.0.2` against `1.0.2k`, `r3222`
//!   against `0.164` and `1.2.3-1` against `1.2.3` do not (a patch or a pre-release, a
//!   different scheme);
//! - a match that names one version (`openssl:1.1.1:w`, the release `1.1.1w`) covers that
//!   version, any update of it when the update is `*` (`macos:15:*` covers `15.1`), and is
//!   unknown for an installed version that cannot be read as one (a cask's `1.2,345` or
//!   `latest`). It does not cover another version (`1.1.1` is not `1.1.1w`), or anything when
//!   it names a snapshot without digits (`ffmpeg:cvs`). An installed version is taken as
//!   written: macOS's `10.15.7` is not `10.15.7` with `security_update_2020-001`, although
//!   `sw_vers` cannot show that update; a CVE needing one names an old release anyway;
//! - a match whose version is `-` (not applicable), a match in a negated node, a record that
//!   does not parse, and a record whose matches never name the product are all unknown.
//!
//! A CVE whose matches name the product only as not vulnerable is out of range: the product
//! is the platform there (Firefox on macOS). The software that is vulnerable is matched under
//! its own name only when it is in the inventory (macOS, Homebrew, toolchains, lockfiles), so
//! a CVE for an app installed some other way (Zoom from its own installer) no longer reaches
//! the agent through macOS. The user chose this (2026-11-08): those platform matches were
//! 4031 of the 10304 advisories, nearly all for software not installed. Since 2026-11-10 (the
//! owner's decision) this holds for CVEs in CISA's KEV catalog too (`matching::keep_candidates`).
//!
//! Matches inside an AND configuration are judged one by one, so a CVE that needs a
//! vulnerable product on a particular platform is a candidate whatever the platform; its
//! reason says the platform is the agent's to judge from the bundle.

use std::borrow::Cow;
use std::cmp::Ordering;

use serde::Deserialize;
use serde_json::value::RawValue;

use crate::feeds::Product;
use crate::matching::Match;

/// The CPE matches of one NVD CVE record, read once and judged against each installed version.
#[derive(Debug)]
pub(crate) struct Matches {
    /// The configurations, or `None` when the record did not parse: then the CVE may affect
    /// every version.
    configurations: Option<Vec<Configuration>>,
}

impl Matches {
    /// Reads the matches.
    pub(crate) fn parse(record: &RawValue) -> Self {
        let configurations = serde_json::from_str::<Record>(record.get())
            .ok()
            .map(|r| r.configurations);
        Self { configurations }
    }

    /// Judges `product` installed at `version`.
    pub(crate) fn verdict(&self, product: &Product, version: &str) -> Match {
        let Some(configurations) = &self.configurations else {
            return Match::Unknown("the record does not parse as an NVD CVE".to_owned());
        };
        let mut named = false;
        let mut verdicts = Vec::new();
        for configuration in configurations {
            let platform = configuration.needs_more_than_one();
            for node in &configuration.nodes {
                for cpe in &node.cpe_match {
                    let Some(name) = Cpe::parse(&cpe.criteria) else {
                        // A name that cannot be read could be the product.
                        verdicts.push(Match::Unknown("a CPE match does not parse".to_owned()));
                        continue;
                    };
                    if !product.is_named_by(&unescape(name.vendor), &unescape(name.product)) {
                        continue;
                    }
                    named = true;
                    // A negated node matches the versions outside its range; judging that
                    // needs the whole configuration, so the agent does.
                    if node.negate {
                        verdicts.push(Match::Unknown("a negated node names it".to_owned()));
                    } else if cpe.vulnerable {
                        let verdict = cpe.covers(&name, version);
                        verdicts.push(if platform {
                            on_platform(verdict)
                        } else {
                            verdict
                        });
                    }
                }
            }
        }
        if !named {
            return Match::Unknown(format!("no CPE match names {product}"));
        }
        Match::any(verdicts).unwrap_or_else(|| {
            Match::OutOfRange(format!(
                "names {product} only as not vulnerable: the platform of other software"
            ))
        })
    }
}

/// Adds to a candidate's reason that its configuration needs another CPE too (usually the
/// platform), which only the agent can judge.
fn on_platform(verdict: Match) -> Match {
    const NOTE: &str = "; its configuration ANDs other CPEs (a platform): judge them";
    match verdict {
        Match::InRange(why) => Match::InRange(format!("{why}{NOTE}")),
        Match::Unknown(why) => Match::Unknown(format!("{why}{NOTE}")),
        out @ Match::OutOfRange(_) => out,
    }
}

/// The part of an NVD CVE record this module reads.
#[derive(Debug, Deserialize)]
struct Record {
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    operator: Option<String>,
    #[serde(default)]
    nodes: Vec<Node>,
}

impl Configuration {
    /// Whether a match here holds only together with another: the configuration or one of its
    /// nodes ANDs several.
    fn needs_more_than_one(&self) -> bool {
        let and = |operator: &Option<String>| operator.as_deref() == Some("AND");
        (and(&self.operator) && self.nodes.len() > 1)
            || self
                .nodes
                .iter()
                .any(|n| and(&n.operator) && n.cpe_match.len() > 1)
    }
}

#[derive(Debug, Deserialize)]
struct Node {
    operator: Option<String>,
    #[serde(default)]
    negate: bool,
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
}

/// One CPE match. `vulnerable` is required, as in NVD's schema: a match without it is not
/// read as a platform, the record fails to parse and the CVE is unknown.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

/// How an installed version must relate to a range bound to be inside the range.
#[derive(Debug, Clone, Copy)]
enum Relation {
    AtLeast,
    Above,
    AtMost,
    Below,
}

impl Relation {
    /// Whether the installed version, ordered `order` against the bound, is inside.
    fn holds(self, order: Ordering) -> bool {
        match self {
            Self::AtLeast => order.is_ge(),
            Self::Above => order.is_gt(),
            Self::AtMost => order.is_le(),
            Self::Below => order.is_lt(),
        }
    }

    /// The symbol written when the relation holds, and when it does not.
    fn symbols(self) -> (&'static str, &'static str) {
        match self {
            Self::AtLeast => (">=", "<"),
            Self::Above => (">", "<="),
            Self::AtMost => ("<=", ">"),
            Self::Below => ("<", ">="),
        }
    }
}

impl CpeMatch {
    /// Whether this match covers `installed`.
    fn covers(&self, name: &Cpe<'_>, installed: &str) -> Match {
        let version = unescape(name.version);
        let update = unescape(name.update);
        let any_update = matches!(&*update, "*" | "");
        if version == "-" {
            return Match::Unknown("the match's version is - (not applicable)".to_owned());
        }
        if version != "*" {
            let named = if any_update || update == "-" {
                version.into_owned()
            } else {
                format!("{version}{update}")
            };
            return match covers_named(&named, any_update, installed) {
                Some(true) => Match::InRange(format!("the match names {named}")),
                Some(false) => Match::OutOfRange(format!("{installed} is not {named}")),
                None => Match::Unknown(format!("cannot tell {installed} from {named}")),
            };
        }
        // An update of every version (`*:beta`) is not a range this can test.
        if !any_update && update != "-" {
            return Match::Unknown(format!("the match names update {update} of every version"));
        }
        let bounds = [
            (
                "versionStartIncluding",
                &self.version_start_including,
                Relation::AtLeast,
            ),
            (
                "versionStartExcluding",
                &self.version_start_excluding,
                Relation::Above,
            ),
            (
                "versionEndIncluding",
                &self.version_end_including,
                Relation::AtMost,
            ),
            (
                "versionEndExcluding",
                &self.version_end_excluding,
                Relation::Below,
            ),
        ];
        // One bound that excludes the version is enough, whatever the others say.
        let mut inside = Vec::new();
        let mut unclear = None;
        for (key, bound, relation) in bounds {
            let Some(bound) = bound else {
                continue;
            };
            let (holds, fails) = relation.symbols();
            match compare(installed, bound) {
                Some(order) if !relation.holds(order) => {
                    return Match::OutOfRange(format!("{installed} {fails} {key} {bound}"));
                }
                Some(_) => inside.push(format!("{installed} {holds} {key} {bound}")),
                None => {
                    unclear = unclear.or_else(|| {
                        Some(format!("{installed} does not compare with {key} {bound}"))
                    });
                }
            }
        }
        match unclear {
            Some(why) => Match::Unknown(why),
            None if inside.is_empty() => {
                Match::InRange("every version (* without bounds)".to_owned())
            }
            None => Match::InRange(inside.join(" and ")),
        }
    }
}

/// Whether a match naming the version `named` covers `installed`: the same version, any update
/// of it when `any_update`, and `None` when `installed` cannot be read as a version. A name
/// without digits (`cvs`, `nightly`) is a snapshot, never a release that is installed.
fn covers_named(named: &str, any_update: bool, installed: &str) -> Option<bool> {
    if named.contains(['*', '?']) {
        // A CPE wildcard inside a value: not a version this can read.
        return None;
    }
    if installed.eq_ignore_ascii_case(named) {
        return Some(true);
    }
    if !named.contains(|c: char| c.is_ascii_digit()) {
        return Some(false);
    }
    if any_update && is_prefix(named, installed) {
        return Some(true);
    }
    same_version(named, installed)
}

/// Whether two versions are the same one, read as runs (`1.2` is `1.2.0`, `007` is `7`), or
/// `None` when either cannot be read, `installed` has no digits (a cask's `latest`), or digits
/// meet letters at the same place before any difference (`1.8.0update401` against
/// `1.8.0_401`). Unlike [`compare`], a run one side lacks is only equal when it is a zero:
/// `1.1.1w` is another release than `1.1.1`, whatever their order.
fn same_version(named: &str, installed: &str) -> Option<bool> {
    let (named, installed) = (runs(named)?, runs(installed)?);
    if !installed.iter().any(|r| r.digits) {
        return None;
    }
    let zero = |r: &Run| r.digits && r.text.trim_start_matches('0').is_empty();
    for i in 0..named.len().max(installed.len()) {
        let same = match (named.get(i), installed.get(i)) {
            // Digits against letters at the same place (`1.8.0update401` against `1.8.0_401`)
            // are two ways of writing that cannot be told apart.
            (Some(a), Some(b)) => a.same(b)?,
            (Some(r), None) | (None, Some(r)) => zero(r),
            (None, None) => unreachable!("i is below the longer length"),
        };
        if !same {
            return Some(false);
        }
    }
    Some(true)
}

/// Whether the runs of `short` begin the runs of `long`: `15` begins `15.1`, `1.1.1` begins
/// `1.1.1w`.
fn is_prefix(short: &str, long: &str) -> bool {
    let (Some(short), Some(long)) = (runs(short), runs(long)) else {
        return false;
    };
    short.len() <= long.len()
        && short
            .iter()
            .zip(&long)
            .all(|(s, l)| s.same(l) == Some(true))
}

/// The fields of a CPE 2.3 formatted string this module reads:
/// `cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:...`, still escaped.
#[derive(Debug)]
struct Cpe<'a> {
    vendor: &'a str,
    product: &'a str,
    version: &'a str,
    update: &'a str,
}

impl<'a> Cpe<'a> {
    /// Returns the fields, or `None` for a string that is not CPE 2.3. Fields are split at
    /// each `:` that a backslash does not escape.
    fn parse(criteria: &'a str) -> Option<Self> {
        let rest = criteria.strip_prefix("cpe:2.3:")?;
        let mut fields = Vec::new();
        let (mut start, mut escaped) = (0, false);
        for (i, c) in rest.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                ':' => {
                    fields.push(&rest[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        fields.push(&rest[start..]);
        let [_part, vendor, product, version, update, ..] = fields[..] else {
            return None;
        };
        Some(Self {
            vendor,
            product,
            version,
            update,
        })
    }
}

/// A CPE field with its escapes removed: `\x` is `x`, so `\\` is one backslash.
fn unescape(field: &str) -> Cow<'_, str> {
    if !field.contains('\\') {
        return Cow::Borrowed(field);
    }
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Compares two version strings, or returns `None` when they do not compare cleanly.
///
/// Each version is read as runs of digits and runs of letters, split at `.`, `-`, `_` and `+`:
/// `1.0.2k` is `1 0 2 k` and `1.0.0rc10` is `1 0 0 rc 10`. Digit runs compare as numbers,
/// and letter runs only as the release stages [`stage`] knows (`dev` < `alpha` < `rc` < `ga`).
/// Where one side has ended, a missing run counts as `0`, so `1.2` equals `1.2.0` and is before
/// `1.2.0.1`. The result is `None` when, at the first difference, one side has digits and the
/// other letters (`r3222` against `0.164`), the letters differ and one is no known stage
/// (`1.0.RC1` against `1.0.GA` is `rc` before `ga`, but `1.0.2k` against `1.0.2l` is unknown:
/// vendors order such letters their own way), when the side that goes on has letters (`1.0.2k`
/// against `1.0.2`) or a run after `-` or `+` (`1.2.3-1` is a revision after `1.2.3` or a
/// pre-release before it), and for an empty version or any other character.
fn compare(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (runs(a)?, runs(b)?);
    for i in 0..a.len().max(b.len()) {
        let order = match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => x.compare(y)?,
            (Some(x), None) => x.compare_with_nothing()?,
            (None, Some(y)) => y.compare_with_nothing()?.reverse(),
            (None, None) => unreachable!("i is below the longer length"),
        };
        if order != Ordering::Equal {
            return Some(order);
        }
    }
    Some(Ordering::Equal)
}

/// One run of a version string, lowercased.
#[derive(Debug)]
struct Run {
    text: String,
    digits: bool,
    /// Whether `-` or `+` comes right before it: a revision, a pre-release or build metadata.
    qualifier: bool,
}

impl Run {
    /// The order of two runs: digits as numbers, the same letters as equal, and other letters
    /// only when both are release stages ([`stage`]). Alphabetical order was wrong for words
    /// (`rc` after `ga`, `dev` after `a`), and a wrong order can put a vulnerable version out
    /// of range.
    fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self.digits, other.digits) {
            (true, true) => Some(compare_digits(&self.text, &other.text)),
            (false, false) if self.text == other.text => Some(Ordering::Equal),
            (false, false) => Some(stage(&self.text)?.cmp(&stage(&other.text)?)),
            _ => None,
        }
    }

    /// Whether two runs are the same, which unlike their order is known for any two words:
    /// `w` is not `v`, whichever comes first. `None` for digits against letters.
    fn same(&self, other: &Self) -> Option<bool> {
        match (self.digits, other.digits) {
            (false, false) if self.text != other.text => {
                Some(stage(&self.text).is_some_and(|s| Some(s) == stage(&other.text)))
            }
            _ => self.compare(other).map(Ordering::is_eq),
        }
    }

    /// How this run compares with a version that has already ended.
    fn compare_with_nothing(&self) -> Option<Ordering> {
        (self.digits && !self.qualifier).then(|| compare_digits(&self.text, "0"))
    }
}

/// Where a lowercased letter run stands among the release stages that vendors spell alike, from
/// a development build to the release; `None` for any other word. Spellings of one stage share
/// a rank: `a` and `alpha`, `c`, `cr` (candidate release) and `rc`, `ga`, `final` and `release`.
/// The order is PEP 440's for `dev`, `a`, `b` and `rc`, and Maven's for `alpha`, `beta`,
/// `cr` and `rc`, and `ga`, `final` and `release`; `pre` and `preview`, which neither defines,
/// sit between beta and candidate, where vendors use them. Any word not listed (`k`, `update`,
/// `patch`) makes a comparison unknown.
fn stage(text: &str) -> Option<u8> {
    match text {
        "dev" => Some(0),
        "a" | "alpha" => Some(1),
        "b" | "beta" => Some(2),
        "pre" | "preview" => Some(3),
        "c" | "cr" | "rc" => Some(4),
        "ga" | "final" | "release" => Some(5),
        _ => None,
    }
}

/// Splits a version into runs, or returns `None` when it is empty or holds a character other
/// than ASCII letters, digits and the separators.
fn runs(version: &str) -> Option<Vec<Run>> {
    let mut runs: Vec<Run> = Vec::new();
    let mut previous: Option<char> = None;
    for c in version.chars() {
        let continues = previous.is_some_and(|p| {
            (p.is_ascii_digit() && c.is_ascii_digit())
                || (p.is_ascii_alphabetic() && c.is_ascii_alphabetic())
        });
        if matches!(c, '.' | '-' | '_' | '+') {
            previous = Some(c);
            continue;
        }
        if !c.is_ascii_alphanumeric() {
            return None;
        }
        match runs.last_mut() {
            Some(run) if continues => run.text.push(c.to_ascii_lowercase()),
            _ => runs.push(Run {
                text: c.to_ascii_lowercase().to_string(),
                digits: c.is_ascii_digit(),
                qualifier: matches!(previous, Some('-' | '+')),
            }),
        }
        previous = Some(c);
    }
    (!runs.is_empty()).then_some(runs)
}

/// Compares two digit runs as numbers, without parsing: a run can be longer than any integer
/// type holds (a date written as `20260107`, or longer).
fn compare_digits(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use serde_json::Value;
    use serde_json::json;

    impl Matches {
        /// Whether the CVE stays a candidate for the component.
        fn may_affect(&self, product: &Product, version: &str) -> bool {
            !matches!(self.verdict(product, version), Match::OutOfRange(_))
        }
    }

    fn nodes(nodes: &Value) -> Matches {
        let record = json!({"id": "CVE-1", "configurations": [{"nodes": nodes}]});
        let raw = RawValue::from_string(record.to_string()).unwrap();
        Matches::parse(&raw)
    }

    fn record(matches: &[Value]) -> Matches {
        nodes(&json!([{"operator": "OR", "cpeMatch": matches}]))
    }

    fn vulnerable(criteria: &str) -> Value {
        json!({"vulnerable": true, "criteria": criteria})
    }

    fn named(version: &str) -> Matches {
        record(&[vulnerable(&format!(
            "cpe:2.3:a:ffmpeg:ffmpeg:{version}:*:*:*:*:*:*"
        ))])
    }

    fn product(name: &str) -> Product {
        name.parse().unwrap()
    }

    #[test]
    fn versions_compare_by_number_and_letter() {
        use Ordering::{Equal, Greater, Less};
        let cases = [
            ("27.2", "14.5", Some(Greater)),
            ("3.6.4", "3.6.5", Some(Less)),
            ("3.10", "3.9", Some(Greater)),
            ("1.2", "1.2.0", Some(Equal)),
            ("1.2.0.1", "1.2", Some(Greater)),
            ("1.0.2a", "1.0.2b", Some(Less)),
            ("1.0.RC1", "1.0.GA", Some(Less)),
            ("2.0.0dev1", "2.0.0a1", Some(Less)),
            ("1.0-alpha", "1.0-a", Some(Equal)),
            ("1.0.final", "1.0.ga", Some(Equal)),
            ("1.0.2k", "1.0.2l", None),
            ("1.0.update", "1.0.ga", None),
            ("1.0.2k", "1.0.2k", Some(Equal)),
            ("1.0-beta", "1.0-pre", Some(Less)),
            ("1.0-preview", "1.0-rc", Some(Less)),
            ("3.0.0-beta1", "3.0.0-rc1", Some(Less)),
            ("1.0.0rc2", "1.0.0rc10", Some(Less)),
            ("3.12.0rc2", "3.12.0rc10", Some(Less)),
            ("2026-09-25", "2026-10-01", Some(Less)),
            ("007", "7", Some(Equal)),
            ("99999999999999999999999", "9", Some(Greater)),
            ("1.0.2", "1.0.2k", None),
            ("r3222", "0.164", None),
            ("1.2.3-1", "1.2.3", None),
            ("1.2.3", "1.2.3+1", None),
            ("1.2,345", "1.2", None),
            ("", "1.0", None),
        ];
        for (a, b, expected) in cases {
            assert_eq!(compare(a, b), expected, "{a} against {b}");
        }
    }

    /// Sameness is known for any two words, unlike their order.
    #[test]
    fn versions_are_the_same_by_number_word_and_stage() {
        let cases = [
            ("1.1.1w", "1.1.1w", Some(true)),
            ("1.1.1w", "1.1.1v", Some(false)),
            ("1.0alpha1", "1.0a1", Some(true)),
            ("1.0a1", "1.0b1", Some(false)),
            ("1.0.final", "1.0.GA", Some(true)),
            ("1.2", "1.2.0", Some(true)),
            ("1.8.0update401", "1.8.0_401", None),
        ];
        for (named, installed, expected) in cases {
            assert_eq!(
                same_version(named, installed),
                expected,
                "{named} and {installed}"
            );
        }
        assert!(is_prefix("1.1.1", "1.1.1w") && !is_prefix("1.1.1v", "1.1.1w"));
    }

    #[test]
    fn ranges_keep_only_versions_inside_them() {
        let openssl = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "3.6.0",
            "versionEndExcluding": "3.6.5",
        })]);
        let affects = |v| openssl.may_affect(&product("openssl"), v);
        assert!(affects("3.6.4"));
        assert!(affects("3.6.0"));
        assert!(!affects("3.6.5"));
        assert!(!affects("3.5.9"));
        assert!(
            affects("3.6.5-1"),
            "a revision of the bound may be before it"
        );
        assert!(
            affects(""),
            "an empty version is not a version outside the range"
        );

        let up_to = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionStartExcluding": "1.0",
            "versionEndIncluding": "1.1",
        })]);
        let affects = |v| up_to.may_affect(&product("openssl"), v);
        assert!(affects("1.1"));
        assert!(!affects("1.0"));
        assert!(!affects("1.1.1"));

        let letters = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.0.2",
            "versionEndExcluding": "1.0.2zh",
        })]);
        assert!(
            letters.may_affect(&product("openssl"), "1.0.2zi"),
            "letters that are no release stage have no known order, so kept"
        );
        assert!(
            letters.may_affect(&product("openssl"), "1.0.2zg"),
            "unclear, so kept"
        );

        // Alphabetically `rc` is after `ga` and `dev` after `a`, which put these out of range.
        let before_ga = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:jboss:jboss:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "1.0.GA",
        })]);
        assert!(before_ga.may_affect(&product("jboss"), "1.0.RC1"));
        assert!(
            !before_ga.may_affect(&product("jboss"), "1.0.final"),
            "the same stage"
        );
        let before_alpha = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:x:x:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.0.0a1",
        })]);
        assert!(before_alpha.may_affect(&product("x"), "2.0.0dev1"));
        assert!(!before_alpha.may_affect(&product("x"), "2.0.0b1"));

        let every_beta = record(&[vulnerable("cpe:2.3:a:openssl:openssl:*:beta:*:*:*:*:*:*")]);
        assert!(every_beta.may_affect(&product("openssl"), "9.9"));
        let old_betas = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:beta:*:*:*:*:*:*",
            "versionEndExcluding": "1.0",
        })]);
        assert!(
            old_betas.may_affect(&product("openssl"), "3.0"),
            "an update of every version is not a range this can rule out"
        );
    }

    #[test]
    fn a_named_version_covers_itself_its_updates_and_what_it_cannot_tell_apart() {
        let macos_9 = record(&[vulnerable("cpe:2.3:o:apple:macos:9:*:*:*:*:*:*:*")]);
        assert!(!macos_9.may_affect(&product("apple:macos"), "27.2"));
        assert!(macos_9.may_affect(&product("apple:macos"), "9.0"));
        let macos_15 = record(&[vulnerable("cpe:2.3:o:apple:macos:15:*:*:*:*:*:*:*")]);
        assert!(
            macos_15.may_affect(&product("apple:macos"), "15.1"),
            "a release line"
        );

        let ffmpeg = product("ffmpeg");
        assert!(!named("cvs").may_affect(&ffmpeg, "8.1.2"), "a snapshot");
        assert!(
            !named("0.59r").may_affect(&ffmpeg, "8.1.2"),
            "another version"
        );
        assert!(
            !named("8.1.2k").may_affect(&ffmpeg, "8.1.2"),
            "another release"
        );
        assert!(
            named("8.1.2.0").may_affect(&ffmpeg, "8.1.2"),
            "the same version"
        );
        assert!(
            named("8.1.2").may_affect(&ffmpeg, "8.1.2,1234"),
            "a cask build"
        );
        assert!(
            named("8.1.2").may_affect(&ffmpeg, "latest"),
            "a cask's moving version"
        );
        assert!(named(r"8.1.2\-1").may_affect(&ffmpeg, "8.1.2-1"));
        assert!(
            named(r"12.1\(11\)e").may_affect(&ffmpeg, "12.1(11)e"),
            "same string"
        );
        assert!(
            named("8.1.*").may_affect(&ffmpeg, "8.1.2"),
            "a wildcard in the value"
        );
    }

    #[test]
    fn the_update_field_is_part_of_the_named_release() {
        let release = |criteria: &str, name: &str, installed: &str| {
            record(&[vulnerable(criteria)]).may_affect(&product(name), installed)
        };
        let w = "cpe:2.3:a:openssl:openssl:1.1.1:w:*:*:*:*:*:*";
        assert!(release(w, "openssl", "1.1.1w"));
        assert!(!release(w, "openssl", "1.1.1"));
        assert!(!release(w, "openssl", "1.1.1v"));
        let rc1 = "cpe:2.3:a:python:python:3.13.0:rc1:*:*:*:*:*:*";
        assert!(release(rc1, "python", "3.13.0rc1"));
        let jdk = "cpe:2.3:a:oracle:jdk:1.8.0:update_401:*:*:*:*:*:*";
        assert!(
            release(jdk, "jdk", "1.8.0_401"),
            "another way of writing it"
        );
        let p1 = "cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*";
        assert!(release(p1, "openssh", "9.8p1"));
        let any = "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*";
        assert!(release(any, "openssl", "1.1.1w"), "any update of 1.1.1");
        let point = "cpe:2.3:a:openssl:openssl:1.2:-:*:*:*:*:*:*";
        assert!(!release(point, "openssl", "1.2.5"), "1.2.5 is not 1.2");
        assert!(release(point, "openssl", "1.2.0"), "1.2.0 is");
        let none = "cpe:2.3:a:openssl:openssl:1.1.1:-:*:*:*:*:*:*";
        assert!(
            !release(none, "openssl", "1.1.1w"),
            "1.1.1 without an update"
        );
    }

    #[test]
    fn a_product_named_only_as_the_platform_is_dropped() {
        let firefox_on_macos = record(&[
            json!({
                "vulnerable": true,
                "criteria": "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "60.0",
            }),
            json!({"vulnerable": false, "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"}),
        ]);
        assert!(!firefox_on_macos.may_affect(&product("apple:macos"), "27.2"));
        assert!(firefox_on_macos.may_affect(&product("mozilla:firefox"), "59.1"));
    }

    #[test]
    fn a_negated_node_keeps_the_cve() {
        let negated = nodes(&json!([{"operator": "OR", "negate": true, "cpeMatch": [{
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "1.0",
        }]}]));
        assert!(negated.may_affect(&product("openssl"), "3.6.4"));
    }

    #[test]
    fn matches_in_an_and_configuration_are_judged_one_by_one() {
        let on_windows = nodes(&json!([
            {"operator": "OR", "cpeMatch": [{
                "vulnerable": true,
                "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "3.7.0",
            }]},
            {"operator": "OR", "cpeMatch": [
                {"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}
            ]},
        ]));
        assert!(on_windows.may_affect(&product("openssl"), "3.6.4"));
        assert!(!on_windows.may_affect(&product("openssl"), "3.7.0"));
    }

    #[test]
    fn verdicts_say_why() {
        let openssl = product("openssl");
        let bounded = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "3.6.0",
            "versionEndExcluding": "3.6.5",
        })]);
        assert_eq!(
            bounded.verdict(&openssl, "3.6.4"),
            Match::InRange(
                "3.6.4 >= versionStartIncluding 3.6.0 and 3.6.4 < versionEndExcluding 3.6.5"
                    .to_owned()
            )
        );
        assert_eq!(
            bounded.verdict(&openssl, "3.6.5"),
            Match::OutOfRange("3.6.5 >= versionEndExcluding 3.6.5".to_owned())
        );
        assert_eq!(
            bounded.verdict(&openssl, "3.6.5-1"),
            Match::Unknown("3.6.5-1 does not compare with versionEndExcluding 3.6.5".to_owned())
        );
        let excluding = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionStartExcluding": "1.0",
            "versionEndIncluding": "1.1",
        })]);
        assert_eq!(
            excluding.verdict(&openssl, "1.0"),
            Match::OutOfRange("1.0 <= versionStartExcluding 1.0".to_owned())
        );
        assert_eq!(
            excluding.verdict(&openssl, "1.2"),
            Match::OutOfRange("1.2 > versionEndIncluding 1.1".to_owned())
        );
        assert_eq!(
            record(&[vulnerable("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")])
                .verdict(&openssl, "3.6.4"),
            Match::InRange("every version (* without bounds)".to_owned())
        );
        assert_eq!(
            named("8.1.2").verdict(&product("ffmpeg"), "8.1.3"),
            Match::OutOfRange("8.1.3 is not 8.1.2".to_owned())
        );
        assert_eq!(
            record(&[]).verdict(&openssl, "3.6.4"),
            Match::Unknown("no CPE match names openssl".to_owned())
        );
    }

    #[test]
    fn a_version_of_dash_is_unknown() {
        let na = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:-:*:*:*:*:*:*:*",
            "versionEndExcluding": "1.0",
        })]);
        assert_eq!(
            na.verdict(&product("openssl"), "3.6.4"),
            Match::Unknown("the match's version is - (not applicable)".to_owned()),
            "not ruled out by its bound"
        );
    }

    #[test]
    fn an_and_configuration_leaves_the_platform_to_the_agent() {
        let record = json!({"id": "CVE-1", "configurations": [{"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [{
                "vulnerable": true,
                "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "3.7.0",
            }]},
            {"operator": "OR", "cpeMatch": [
                {"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}
            ]},
        ]}]});
        let matches = Matches::parse(&RawValue::from_string(record.to_string()).unwrap());
        assert_eq!(
            matches.verdict(&product("openssl"), "3.6.4"),
            Match::InRange(
                "3.6.4 < versionEndExcluding 3.7.0; its configuration ANDs other CPEs (a \
                 platform): judge them"
                    .to_owned()
            )
        );
        assert_eq!(
            matches.verdict(&product("openssl"), "3.7.0"),
            Match::OutOfRange("3.7.0 >= versionEndExcluding 3.7.0".to_owned())
        );
        assert_eq!(
            matches.verdict(&product("microsoft:windows"), "11"),
            Match::OutOfRange(
                "names microsoft:windows only as not vulnerable: the platform of other software"
                    .to_owned()
            )
        );

        let one_node = json!({"id": "CVE-2", "configurations": [{"nodes": [
            {"operator": "AND", "cpeMatch": [
                vulnerable("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
                {"vulnerable": false, "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"},
            ]},
        ]}]});
        let matches = Matches::parse(&RawValue::from_string(one_node.to_string()).unwrap());
        let verdict = matches.verdict(&product("openssl"), "3.6.4");
        assert!(verdict.why().ends_with("judge them"), "{verdict:?}");
        assert!(
            on_platform(Match::Unknown("u".to_owned()))
                .why()
                .ends_with("judge them"),
            "an unknown candidate gets the note too"
        );

        let alone = json!({"id": "CVE-3", "configurations": [{"operator": "AND", "nodes": [
            {"operator": "AND", "cpeMatch": [
                vulnerable("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
            ]},
        ]}]});
        let matches = Matches::parse(&RawValue::from_string(alone.to_string()).unwrap());
        assert_eq!(
            matches.verdict(&product("openssl"), "3.6.4"),
            Match::InRange("every version (* without bounds)".to_owned()),
            "an AND of one CPE needs nothing else"
        );
    }

    #[test]
    fn the_vendor_must_match_when_given() {
        // The same vendor's other product does not name this one, so the record never does and
        // is kept.
        let safari = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "10.0",
        })]);
        assert!(safari.may_affect(&product("apple:macos"), "27.2"));

        let jenkins_git = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:jenkins:git:*:*:*:*:*:jenkins:*:*",
            "versionEndIncluding": "4.11.3",
        })]);
        let git_scm = record(&[json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:git-scm:git:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.50.0",
        })]);
        // Without a vendor, Jenkins' git plugin counts as git.
        assert!(jenkins_git.may_affect(&product("git"), "2.56.0"));
        assert!(!git_scm.may_affect(&product("git-scm:git"), "2.56.0"));
        assert!(git_scm.may_affect(&product("git-scm:git"), "2.49.1"));
        // A record that names git only under another vendor never names `git-scm:git`, so it
        // is kept; NVD does not return one for a query that gives the vendor.
        assert!(jenkins_git.may_affect(&product("git-scm:git"), "2.56.0"));
    }

    #[test]
    fn unreadable_records_and_names_are_kept() {
        let broken = RawValue::from_string("[1, 2]".to_owned()).unwrap();
        assert!(Matches::parse(&broken).may_affect(&product("openssl"), "3.6.4"));

        let no_flag = json!({"id": "CVE-1", "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.0"}
        ]}]}]});
        let no_flag = RawValue::from_string(no_flag.to_string()).unwrap();
        assert!(
            Matches::parse(&no_flag).may_affect(&product("openssl"), "3.6.4"),
            "`vulnerable` is required, so the record does not parse"
        );

        let empty = RawValue::from_string(r#"{"id": "CVE-1"}"#.to_owned()).unwrap();
        let empty = Matches::parse(&empty);
        assert!(empty.may_affect(&product("openssl"), "3.6.4"));

        let truncated = record(&[vulnerable("cpe:2.3:a:openssl")]);
        assert!(truncated.may_affect(&product("openssl"), "3.6.4"));
    }

    #[test]
    fn escaped_characters_stay_inside_their_field() {
        let adobe_on_macos = record(&[
            vulnerable(r"cpe:2.3:a:adobe:air_sdk_\&_compiler:*:*:*:*:*:*:*:*"),
            json!({"vulnerable": false, "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"}),
        ]);
        assert!(!adobe_on_macos.may_affect(&product("apple:macos"), "27.2"));

        let colon = Cpe::parse(r"cpe:2.3:a:ven\:dor:prod:1.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(
            (colon.vendor, colon.product, colon.version, colon.update),
            (r"ven\:dor", "prod", "1.0", "*")
        );
        assert_eq!(unescape(r"a\\b\-c"), r"a\b-c");

        let escaped_vendor = record(&[json!({
            "vulnerable": true,
            "criteria": r"cpe:2.3:a:git\-scm:git:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.50.0",
        })]);
        assert!(!escaped_vendor.may_affect(&product("git-scm:git"), "2.56.0"));
    }

    proptest! {
        /// `compare` is antisymmetric wherever it answers, and a version that reads equals
        /// itself.
        #[test]
        fn compare_is_consistent(a in "[0-9a-c.,+-]{0,8}", b in "[0-9a-c.,+-]{0,8}") {
            prop_assert!(matches!(compare(&a, &a), Some(Ordering::Equal) | None));
            prop_assert_eq!(compare(&a, &b), compare(&b, &a).map(Ordering::reverse));
        }

        /// Plain dotted numbers compare like the lists of numbers they are.
        #[test]
        fn dotted_numbers_compare_as_lists(
            a in prop::collection::vec(0_u32..1000, 1..5),
            b in prop::collection::vec(0_u32..1000, 1..5),
        ) {
            let text = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(".");
            let pad = |v: &[u32]| {
                let mut v = v.to_vec();
                v.resize(5, 0);
                v
            };
            prop_assert_eq!(compare(&text(&a), &text(&b)), Some(pad(&a).cmp(&pad(&b))));
        }

        /// Two different words that are not both release stages never order versions, so no
        /// bound written with one puts a version written with the other out of range.
        #[test]
        fn unknown_letters_never_put_a_version_out_of_range(
            installed in "[a-z]{1,8}",
            bound in "[a-z]{1,8}",
            number in 0_u8..10,
        ) {
            prop_assume!(
                installed != bound && (stage(&installed).is_none() || stage(&bound).is_none())
            );
            let (installed, bound) = (format!("1.0.{installed}{number}"), format!("1.0.{bound}"));
            prop_assert_eq!(compare(&installed, &bound), None);
            for limit in ["versionEndExcluding", "versionEndIncluding", "versionStartIncluding"] {
                let matches = record(&[json!({
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:x:x:*:*:*:*:*:*:*:*",
                    limit: bound,
                })]);
                prop_assert!(matches.may_affect(&product("x"), &installed), "{limit} {bound}");
            }
        }

        /// A range with one upper bound keeps exactly the versions not cleanly at or above it.
        #[test]
        fn an_upper_bound_keeps_what_is_not_cleanly_past_it(
            installed in "[0-9a-c.+-]{0,8}",
            bound in "[0-9]{1,2}(\\.[0-9]{1,2}){0,2}",
        ) {
            let matches = record(&[json!({
                "vulnerable": true,
                "criteria": "cpe:2.3:a:x:x:*:*:*:*:*:*:*:*",
                "versionEndExcluding": bound,
            })]);
            let past = compare(&installed, &bound).is_some_and(Ordering::is_ge);
            prop_assert_eq!(matches.may_affect(&product("x"), &installed), !past);
        }
    }
}
