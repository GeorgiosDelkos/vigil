//! Whether an NVD CVE can affect the version installed, read from the CPE matches in its
//! configurations.
//!
//! NVD returns every CVE whose configurations name a product, at any version, and also those
//! that name it only as the platform another product runs on. For macOS that is over 7000
//! CVEs, nearly all of them fixed long ago or in other software (measured on one Mac,
//! 2026-11-08: 10304 advisories in a bundle, 154 left by this filter). The agent still
//! decides what is affected; this only drops the CVEs that cannot be, so it errs towards
//! keeping:
//!
//! - a CVE is kept when any match that marks the product vulnerable could cover the version;
//! - a version that does not compare cleanly with a range's bound (`1.0.2` against `1.0.2k`,
//!   `r3222` against `0.164`) counts as inside the range. A match that names one version
//!   (`ffmpeg:0.4.6`, `ffmpeg:cvs`) covers only a version equal to it, and a version that does
//!   not compare is not equal;
//! - a record that does not parse, or whose matches never name the product, is kept;
//! - a CVE whose matches name the product only as not vulnerable is dropped: the product is
//!   the platform there (Firefox on macOS), and the vulnerable software is matched under its
//!   own name when it is installed.
//!
//! Matches inside an AND configuration are judged one by one, so a CVE that needs a
//! vulnerable product on a particular platform is kept whatever the platform. The agent reads
//! the structure from the bundle.

use std::cmp::Ordering;

use serde::Deserialize;
use serde_json::value::RawValue;

use crate::feeds::Product;

/// Returns whether the NVD CVE `record` may affect `product` installed at `version`.
pub(crate) fn may_affect(record: &RawValue, product: &Product, version: &str) -> bool {
    let Ok(record) = serde_json::from_str::<Record>(record.get()) else {
        return true;
    };
    let mut named = false;
    for cpe in record
        .configurations
        .iter()
        .flat_map(|c| &c.nodes)
        .flat_map(|n| &n.cpe_match)
    {
        let Some(name) = Cpe::parse(&cpe.criteria) else {
            // A name we cannot read could be the product.
            return true;
        };
        if !name.is(product) {
            continue;
        }
        named = true;
        if cpe.vulnerable && cpe.covers(name.version, version) != Some(false) {
            return true;
        }
    }
    !named
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
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    #[serde(default)]
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

impl CpeMatch {
    /// Whether this match covers `installed`, or `None` when a range's bound does not compare.
    ///
    /// A CPE that names one version matches only it, and NVD gives such a match no range. A
    /// CPE with `*` or `-` (not applicable) as its version matches every version within the
    /// bounds given, or every version when there are none.
    fn covers(&self, cpe_version: &str, installed: &str) -> Option<bool> {
        if cpe_version != "*" && cpe_version != "-" {
            // CPE escapes punctuation (`12.1\(11\)e`); the escaped character is the version's.
            let named = cpe_version.replace('\\', "");
            return Some(compare(installed, &named) == Some(Ordering::Equal));
        }
        let bounds = [
            (
                &self.version_start_including,
                Ordering::is_ge as fn(Ordering) -> bool,
            ),
            (&self.version_start_excluding, Ordering::is_gt),
            (&self.version_end_including, Ordering::is_le),
            (&self.version_end_excluding, Ordering::is_lt),
        ];
        let mut covered = true;
        for (bound, holds) in bounds {
            if let Some(bound) = bound {
                covered &= holds(compare(installed, bound)?);
            }
        }
        Some(covered)
    }
}

/// The fields of a CPE 2.3 formatted string this module reads:
/// `cpe:2.3:<part>:<vendor>:<product>:<version>:...`, still escaped (`air_sdk_\&_compiler`).
#[derive(Debug)]
struct Cpe<'a> {
    vendor: &'a str,
    product: &'a str,
    version: &'a str,
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
        let [_part, vendor, product, version, ..] = fields[..] else {
            return None;
        };
        Some(Self {
            vendor,
            product,
            version,
        })
    }

    /// Whether this names `product`.
    fn is(&self, product: &Product) -> bool {
        product.is_named_by(self.vendor, self.product)
    }
}

/// Compares two version strings, or returns `None` when they do not compare cleanly.
///
/// Each version is read as runs of digits and runs of letters, split at `.`, `-`, `_` and `+`:
/// `1.0.2k` is `1 0 2 k`. Digit runs compare as numbers and letter runs alphabetically
/// (`alpha` < `beta` < `rc`). A missing run counts as `0`, so `1.2` equals `1.2.0`. The
/// result is `None` when, at the first difference, one side has digits and the other letters
/// (`r3222` against `0.164`), when the shorter side ends where the longer has letters (`1.0.2`
/// against `1.0.2k`, which could be a patch or a pre-release), and for any other character.
fn compare(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (runs(a)?, runs(b)?);
    for i in 0..a.len().max(b.len()) {
        let order = match (a.get(i), b.get(i)) {
            (Some(Run::Number(x)), Some(Run::Number(y))) => compare_digits(x, y),
            (Some(Run::Letters(x)), Some(Run::Letters(y))) => x.cmp(y),
            (Some(Run::Number(x)), None) => compare_digits(x, "0"),
            (None, Some(Run::Number(y))) => compare_digits("0", y),
            _ => return None,
        };
        if order != Ordering::Equal {
            return Some(order);
        }
    }
    Some(Ordering::Equal)
}

/// One run of a version string, lowercased.
#[derive(Debug)]
enum Run {
    Number(String),
    Letters(String),
}

/// Splits a version into runs, or returns `None` when it holds a character other than ASCII
/// letters, digits and the separators.
fn runs(version: &str) -> Option<Vec<Run>> {
    let mut runs: Vec<Run> = Vec::new();
    let mut previous: Option<char> = None;
    for c in version.chars() {
        let same_kind = previous.is_some_and(|p| {
            (p.is_ascii_digit() && c.is_ascii_digit())
                || (p.is_ascii_alphabetic() && c.is_ascii_alphabetic())
        });
        match (c, runs.last_mut()) {
            ('.' | '-' | '_' | '+', _) => {}
            (c, Some(Run::Number(run) | Run::Letters(run))) if same_kind => {
                run.push(c.to_ascii_lowercase());
            }
            (c, _) if c.is_ascii_digit() => runs.push(Run::Number(c.to_string())),
            (c, _) if c.is_ascii_alphabetic() => {
                runs.push(Run::Letters(c.to_ascii_lowercase().to_string()));
            }
            _ => return None,
        }
        previous = Some(c);
    }
    Some(runs)
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

    fn record(matches: &[serde_json::Value]) -> Box<RawValue> {
        let record = serde_json::json!({"id": "CVE-1", "configurations": [
            {"nodes": [{"operator": "OR", "cpeMatch": matches}]}
        ]});
        RawValue::from_string(record.to_string()).unwrap()
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
            ("2026-09-25", "2026-10-01", Some(Less)),
            ("007", "7", Some(Equal)),
            ("99999999999999999999999", "9", Some(Greater)),
            ("1.0.2", "1.0.2k", None),
            ("r3222", "0.164", None),
            ("1.2,345", "1.2", None),
        ];
        for (a, b, expected) in cases {
            assert_eq!(compare(a, b), expected, "{a} against {b}");
        }
    }

    #[test]
    fn ranges_keep_only_versions_inside_them() {
        let openssl = record(&[serde_json::json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "3.6.0",
            "versionEndExcluding": "3.6.5",
        })]);
        assert!(may_affect(&openssl, &product("openssl"), "3.6.4"));
        assert!(may_affect(&openssl, &product("openssl"), "3.6.0"));
        assert!(!may_affect(&openssl, &product("openssl"), "3.6.5"));
        assert!(!may_affect(&openssl, &product("openssl"), "3.5.9"));

        let up_to = record(&[serde_json::json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionStartExcluding": "1.0",
            "versionEndIncluding": "1.1",
        })]);
        assert!(may_affect(&up_to, &product("openssl"), "1.1"));
        assert!(!may_affect(&up_to, &product("openssl"), "1.0"));
        assert!(!may_affect(&up_to, &product("openssl"), "1.1.1"));
    }

    #[test]
    fn a_named_version_matches_only_itself() {
        let macos_9 = record(&[serde_json::json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:o:apple:macos:9:*:*:*:*:*:*:*",
        })]);
        assert!(!may_affect(&macos_9, &product("apple:macos"), "27.2"));
        assert!(may_affect(&macos_9, &product("apple:macos"), "9.0"));

        // A snapshot name, or a version with letters where the installed one has none, is
        // another version.
        let named = |version: &str| {
            record(&[serde_json::json!({
                "vulnerable": true,
                "criteria": format!("cpe:2.3:a:ffmpeg:ffmpeg:{version}:*:*:*:*:*:*:*"),
            })])
        };
        assert!(!may_affect(&named("cvs"), &product("ffmpeg"), "8.1.2"));
        assert!(!may_affect(&named("8.1.2k"), &product("ffmpeg"), "8.1.2"));
        assert!(may_affect(
            &named(r"8.1.2\-1"),
            &product("ffmpeg"),
            "8.1.2-1"
        ));
    }

    #[test]
    fn any_version_and_unclear_versions_are_kept() {
        let every = record(&[serde_json::json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*",
        })]);
        assert!(may_affect(&every, &product("apple:macos"), "27.2"));

        let lettered = record(&[serde_json::json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "1.0.2k",
        })]);
        assert!(may_affect(&lettered, &product("openssl"), "1.0.2"));
        assert!(!may_affect(&lettered, &product("openssl"), "3.6.4"));
    }

    #[test]
    fn a_product_named_only_as_the_platform_is_dropped() {
        let firefox_on_macos = record(&[
            serde_json::json!({
                "vulnerable": true,
                "criteria": "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "60.0",
            }),
            serde_json::json!({
                "vulnerable": false,
                "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*",
            }),
        ]);
        assert!(!may_affect(
            &firefox_on_macos,
            &product("apple:macos"),
            "27.2"
        ));
        assert!(may_affect(
            &firefox_on_macos,
            &product("mozilla:firefox"),
            "59.1"
        ));
    }

    #[test]
    fn the_vendor_must_match_when_given() {
        let jenkins_git = record(&[serde_json::json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:jenkins:git:*:*:*:*:*:jenkins:*:*",
            "versionEndIncluding": "4.11.3",
        })]);
        let git_scm = record(&[serde_json::json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:git-scm:git:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.50.0",
        })]);
        // Without a vendor, Jenkins' git plugin counts as git.
        assert!(may_affect(&jenkins_git, &product("git"), "2.56.0"));
        assert!(!may_affect(&git_scm, &product("git-scm:git"), "2.56.0"));
        assert!(may_affect(&git_scm, &product("git-scm:git"), "2.49.1"));
        // A record that names git only under another vendor never names `git-scm:git`, so it
        // is kept; NVD does not return one for a query that gives the vendor.
        assert!(may_affect(&jenkins_git, &product("git-scm:git"), "2.56.0"));
    }

    #[test]
    fn unreadable_records_and_names_are_kept() {
        let broken = RawValue::from_string("[1, 2]".to_owned()).unwrap();
        assert!(may_affect(&broken, &product("openssl"), "3.6.4"));

        let empty = RawValue::from_string(r#"{"id": "CVE-1"}"#.to_owned()).unwrap();
        assert!(may_affect(&empty, &product("openssl"), "3.6.4"));

        let truncated = record(&[serde_json::json!({
            "vulnerable": true,
            "criteria": "cpe:2.3:a:openssl",
        })]);
        assert!(may_affect(&truncated, &product("openssl"), "3.6.4"));
    }

    #[test]
    fn escaped_characters_stay_inside_their_field() {
        let adobe_on_macos = record(&[
            serde_json::json!({
                "vulnerable": true,
                "criteria": r"cpe:2.3:a:adobe:air_sdk_\&_compiler:*:*:*:*:*:*:*:*",
            }),
            serde_json::json!({
                "vulnerable": false,
                "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*",
            }),
        ]);
        assert!(!may_affect(
            &adobe_on_macos,
            &product("apple:macos"),
            "27.2"
        ));

        let colon = Cpe::parse(r"cpe:2.3:a:ven\:dor:prod:1.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(
            (colon.vendor, colon.product, colon.version),
            (r"ven\:dor", "prod", "1.0")
        );
    }

    proptest! {
        /// `compare` is an order wherever it answers: reflexive and antisymmetric.
        #[test]
        fn compare_is_consistent(a in "[0-9a-c.]{0,8}", b in "[0-9a-c.]{0,8}") {
            prop_assert_eq!(compare(&a, &a), Some(Ordering::Equal));
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
    }
}
