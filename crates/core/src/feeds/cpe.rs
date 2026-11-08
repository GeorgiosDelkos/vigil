//! Whether an NVD CVE can affect the version installed, read from the CPE matches in its
//! configurations.
//!
//! NVD returns every CVE whose configurations name a product, at any version, and also those
//! that name it only as the platform another product runs on. For macOS that is over 7000
//! CVEs, nearly all of them fixed long ago or in other software (measured on one Mac,
//! 2026-11-08: 10304 advisories in a bundle). The agent still decides what is affected; this
//! only drops the CVEs that cannot be, and keeps a CVE whenever it cannot tell:
//!
//! - a CVE is kept when any match that marks the product vulnerable could cover the version;
//! - a range covers a version unless one of its bounds puts the version cleanly outside.
//!   `1.0.2` against `1.0.2k`, `r3222` against `0.164` and `1.2.3-1` against `1.2.3` do not
//!   compare cleanly (a patch or a pre-release, a different scheme), so such a bound does not;
//! - a match that names one version (`openssl:1.1.1:w`, the release `1.1.1w`) covers that
//!   version, any update of it when the update is `*` (`macos:15:*` covers `15.1`), and an
//!   installed version that cannot be read as one (a cask's `1.2,345` or `latest`). It does
//!   not cover another version (`1.1.1` is not `1.1.1w`), or anything when it names a
//!   snapshot without digits (`ffmpeg:cvs`). An installed version is taken as written: macOS's
//!   `10.15.7` is not `10.15.7` with `security_update_2020-001`, although `sw_vers` cannot show
//!   that update; a CVE needing one names an old release anyway;
//! - a match in a negated node, a record that does not parse, and a record whose matches never
//!   name the product all keep the CVE.
//!
//! A CVE whose matches name the product only as not vulnerable is dropped: the product is the
//! platform there (Firefox on macOS). The software that is vulnerable is matched under its own
//! name only when it is in the inventory (macOS, Homebrew, toolchains, lockfiles), so a CVE
//! for an app installed some other way (Zoom from its own installer) no longer reaches the
//! agent through macOS. The user chose this (2026-11-08): those platform matches were 4031 of
//! the 10304 advisories, nearly all for software not installed. CVEs in CISA's KEV catalog,
//! and every CVE when the catalog could not be read, skip this filter (`sweep::fetch_nvd`).
//!
//! Matches inside an AND configuration are judged one by one, so a CVE that needs a
//! vulnerable product on a particular platform is kept whatever the platform. The agent reads
//! the structure from the bundle.

use std::borrow::Cow;
use std::cmp::Ordering;

use serde::Deserialize;
use serde_json::value::RawValue;

use crate::feeds::Product;

/// The CPE matches of one NVD CVE record, read once and tested against each installed version.
#[derive(Debug)]
pub(crate) struct Matches {
    /// The configuration nodes, or `None` when the record did not parse: then the CVE may
    /// affect every version.
    nodes: Option<Vec<Node>>,
}

impl Matches {
    /// Reads the matches.
    pub(crate) fn parse(record: &RawValue) -> Self {
        let nodes = serde_json::from_str::<Record>(record.get())
            .ok()
            .map(|r| r.configurations.into_iter().flat_map(|c| c.nodes).collect());
        Self { nodes }
    }

    /// Returns whether the CVE may affect `product` installed at `version`.
    pub(crate) fn may_affect(&self, product: &Product, version: &str) -> bool {
        let Some(nodes) = &self.nodes else {
            return true;
        };
        let mut named = false;
        for node in nodes {
            for cpe in &node.cpe_match {
                let Some(name) = Cpe::parse(&cpe.criteria) else {
                    // A name that cannot be read could be the product.
                    return true;
                };
                if !product.is_named_by(&unescape(name.vendor), &unescape(name.product)) {
                    continue;
                }
                named = true;
                // A negated node matches the versions outside its range; judging that needs
                // the whole configuration, so the agent does.
                if node.negate {
                    return true;
                }
                if cpe.vulnerable && cpe.covers(&name, version) != Some(false) {
                    return true;
                }
            }
        }
        !named
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
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
struct Node {
    #[serde(default)]
    negate: bool,
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
}

/// One CPE match. `vulnerable` is required, as in NVD's schema: a match without it is not
/// read as a platform, the record fails to parse and the CVE is kept.
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

impl CpeMatch {
    /// Whether this match covers `installed`, or `None` when that cannot be told.
    fn covers(&self, name: &Cpe<'_>, installed: &str) -> Option<bool> {
        let version = unescape(name.version);
        let update = unescape(name.update);
        let any_update = matches!(&*update, "*" | "");
        if !matches!(&*version, "*" | "-") {
            let named = if any_update || update == "-" {
                version.into_owned()
            } else {
                format!("{version}{update}")
            };
            return covers_named(&named, any_update, installed);
        }
        // An update of every version (`*:beta`) is not a range this can test.
        if !any_update && update != "-" {
            return None;
        }
        // Whether each bound given puts `installed` outside, or `None` where it does not
        // compare. One bound that excludes it is enough, whatever the others say.
        let check = |bound: &Option<String>, is_outside: fn(Ordering) -> bool| {
            bound
                .as_deref()
                .map(|b| compare(installed, b).map(is_outside))
        };
        let verdicts = [
            check(&self.version_start_including, Ordering::is_lt),
            check(&self.version_start_excluding, Ordering::is_le),
            check(&self.version_end_including, Ordering::is_gt),
            check(&self.version_end_excluding, Ordering::is_ge),
        ];
        let mut given = verdicts.iter().flatten();
        if given.clone().any(|o| *o == Some(true)) {
            return Some(false);
        }
        given.all(Option::is_some).then_some(true)
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
            (Some(a), Some(b)) => a.compare(b)? == Ordering::Equal,
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
    short.len() <= long.len() && short.iter().zip(&long).all(|(s, l)| s.same_as(l))
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
/// `1.0.2k` is `1 0 2 k` and `1.0.0rc10` is `1 0 0 rc 10`. Digit runs compare as numbers and
/// letter runs alphabetically (`alpha` < `beta` < `rc`). Where one side has ended, a missing
/// run counts as `0`, so `1.2` equals `1.2.0` and is before `1.2.0.1`. The result is `None`
/// when, at the first difference, one side has digits and the other letters (`r3222` against
/// `0.164`), when the side that goes on has letters (`1.0.2k` against `1.0.2`) or a run after
/// `-` or `+` (`1.2.3-1` is a revision after `1.2.3` or a pre-release before it), and for an
/// empty version or any other character.
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
    fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self.digits, other.digits) {
            (true, true) => Some(compare_digits(&self.text, &other.text)),
            (false, false) => Some(self.text.cmp(&other.text)),
            _ => None,
        }
    }

    /// How this run compares with a version that has already ended.
    fn compare_with_nothing(&self) -> Option<Ordering> {
        (self.digits && !self.qualifier).then(|| compare_digits(&self.text, "0"))
    }

    fn same_as(&self, other: &Self) -> bool {
        self.compare(other) == Some(Ordering::Equal)
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
            !letters.may_affect(&product("openssl"), "1.0.2zi"),
            "past the end, though `1.0.2zi` does not compare with the start `1.0.2`"
        );
        assert!(
            letters.may_affect(&product("openssl"), "1.0.2zg"),
            "unclear, so kept"
        );

        let every_beta = record(&[vulnerable("cpe:2.3:a:openssl:openssl:*:beta:*:*:*:*:*:*")]);
        assert!(every_beta.may_affect(&product("openssl"), "9.9"));
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
    fn the_vendor_must_match_when_given() {
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
