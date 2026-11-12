//! Version orderings: SemVer 2.0, PEP 440, and plain dotted numbers.
//!
//! Each parser returns a key whose `Ord` is the scheme's precedence, or `None` for text the
//! scheme does not define. A caller that gets `None` cannot tell where the version falls and
//! says so; nothing here guesses.

/// A SemVer 2.0 version. The fields are in precedence order, so the derived `Ord` is
/// precedence (section 11 of <https://semver.org/spec/v2.0.0.html>); build metadata takes no
/// part and is not kept.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SemVer {
    core: [u64; 3],
    /// True without a pre-release: a release follows all of its pre-releases.
    release: bool,
    pre: Vec<Identifier>,
}

/// A pre-release identifier. Numeric ones come first and compare as numbers; the variant
/// order makes that the derived `Ord`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Identifier {
    Numeric(u64),
    Alphanumeric(String),
}

/// A PEP 440 version, as the key `packaging` sorts by (`_cmpkey` in
/// <https://github.com/pypa/packaging/blob/d8e3b31b734926ebbcaff654279f6855a73e052f/src/packaging/version.py>): fields in
/// precedence order, so the derived `Ord` is PEP 440's.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Pep440 {
    epoch: u64,
    /// The release numbers without trailing zeros: `1.0` is `1`.
    release: Vec<u64>,
    pre: Pre,
    /// `None` sorts before every post-release.
    post: Option<u64>,
    /// True without a dev-release: a version follows all of its dev-releases.
    final_dev: bool,
    dev: u64,
    /// `None` sorts before every local version of the same public version.
    local: Option<Vec<LocalPart>>,
}

/// Where a PEP 440 pre-release puts a version among its release's versions.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Pre {
    /// A dev-release of the release itself (`1.0.dev1`), before its alphas.
    DevOfRelease,
    /// `a`, `b` or `rc` (ranked 0, 1, 2) and its number.
    Labeled(u8, u64),
    /// No pre-release.
    None,
}

/// A part of a local version label. PEP 440 sorts numeric parts after alphanumeric ones.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LocalPart {
    Alphanumeric(String),
    Numeric(u64),
}

/// Dotted numbers without trailing zeros, so `1.2` and `1.2.0` are the same version.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Dotted(Vec<u64>);

impl Pep440 {
    /// Whether `self`, an installed version, is the version `listed` names. A listed version
    /// without a local label matches every local build of it, as PEP 440's version matching
    /// says (<https://peps.python.org/pep-0440/#version-matching>): `2.0.1+cu118` is `2.0.1`.
    /// A listed version with a label matches that label only.
    pub(crate) fn is_listed_as(&self, listed: &Self) -> bool {
        // Every field but `local`, named, so a field added later cannot be left out here.
        fn public(v: &Pep440) -> (u64, &[u64], &Pre, Option<u64>, bool, u64) {
            let Pep440 {
                epoch,
                release,
                pre,
                post,
                final_dev,
                dev,
                local: _,
            } = v;
            (*epoch, release, pre, *post, *final_dev, *dev)
        }
        public(self) == public(listed) && (listed.local.is_none() || self.local == listed.local)
    }
}

/// Parses a SemVer 2.0 version (`1.2.3-rc.1+build`), strictly: no `v`, no leading zeros in
/// numbers, no empty identifiers. Numbers above `u64::MAX` are not read.
pub(crate) fn semver(text: &str) -> Option<SemVer> {
    let text = match text.split_once('+') {
        Some((version, build)) => {
            identifiers(build)?;
            version
        }
        None => text,
    };
    let (core, pre) = match text.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (text, None),
    };
    let numbers: Vec<u64> = core.split('.').map(number).collect::<Option<_>>()?;
    let core = <[u64; 3]>::try_from(numbers).ok()?;
    let pre = match pre {
        Some(pre) => identifiers(pre)?
            .into_iter()
            .map(|id| match number(id) {
                Some(n) => Some(Identifier::Numeric(n)),
                // All digits but not a number: a leading zero, or too large.
                None if id.bytes().all(|b| b.is_ascii_digit()) => None,
                None => Some(Identifier::Alphanumeric(id.to_owned())),
            })
            .collect::<Option<Vec<_>>>()?,
        None => Vec::new(),
    };
    Some(SemVer {
        core,
        release: pre.is_empty(),
        pre,
    })
}

/// Dot-separated identifiers of ASCII letters, digits and `-`, none empty.
fn identifiers(text: &str) -> Option<Vec<&str>> {
    text.split('.')
        .map(|id| {
            let ok = !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
            ok.then_some(id)
        })
        .collect()
}

/// A SemVer numeric identifier: digits, without a leading zero unless it is `0`.
fn number(text: &str) -> Option<u64> {
    let leading_zero = text.len() > 1 && text.starts_with('0');
    if leading_zero {
        return None;
    }
    digits(text)
}

/// Parses a PEP 440 version in any spelling the spec accepts (`v1.0`, `1.0-RC1`, `1.0.post`,
/// `1.0-1`, `1!2.0.dev3+ubuntu.1`), following the regular expression in its appendix
/// (<https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions>).
pub(crate) fn pep440(text: &str) -> Option<Pep440> {
    let lower = text.trim().to_ascii_lowercase();
    let (public, local) = match lower.split_once('+') {
        Some((public, local)) => (public, Some(local_parts(local)?)),
        None => (lower.as_str(), None),
    };
    let mut rest = public.strip_prefix('v').unwrap_or(public);

    let epoch = match rest.split_once('!') {
        Some((epoch, after)) => {
            rest = after;
            digits(epoch)?
        }
        None => 0,
    };
    let release_end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rest.len());
    // A dot right before a suffix belongs to the suffix (`1.0.post1`).
    let release_text = rest[..release_end].trim_end_matches('.');
    rest = &rest[release_text.len()..];
    let mut release: Vec<u64> = release_text.split('.').map(digits).collect::<Option<_>>()?;
    drop_trailing_zeros(&mut release);

    let pre = suffix(
        &mut rest,
        &["alpha", "a", "beta", "b", "preview", "pre", "c", "rc"],
    );
    let post = suffix(&mut rest, &["post", "rev", "r"])
        .map(|(_, n)| n)
        .or_else(|| implicit_post(&mut rest));
    let dev = suffix(&mut rest, &["dev"]).map(|(_, n)| n);
    if !rest.is_empty() {
        return None;
    }
    // A missing number is 0 (`1.0.post` is `1.0.post0`).
    let number = |text: &str| {
        if text.is_empty() {
            Some(0)
        } else {
            digits(text)
        }
    };
    let pre = match pre {
        Some((label, n)) => Some((label, number(n)?)),
        None => None,
    };
    let post = match post {
        Some(n) => Some(number(n)?),
        None => None,
    };
    let dev = match dev {
        Some(n) => Some(number(n)?),
        None => None,
    };

    let pre = match (pre, post, dev) {
        (Some((label, n)), _, _) => {
            let rank = match label {
                "alpha" | "a" => 0,
                "beta" | "b" => 1,
                _ => 2,
            };
            Pre::Labeled(rank, n)
        }
        (None, None, Some(_)) => Pre::DevOfRelease,
        (None, _, _) => Pre::None,
    };
    Some(Pep440 {
        epoch,
        release,
        pre,
        post,
        final_dev: dev.is_none(),
        dev: dev.unwrap_or(0),
        local,
    })
}

/// Takes one PEP 440 suffix off the front of `rest`: an optional `.`, `-` or `_`, one of
/// `labels` (a label that begins another comes after it), another optional separator, and an
/// optional number. Returns the label and the number's digits (empty when there is none), or
/// `None` when no label is there.
fn suffix<'t, 'l>(rest: &mut &'t str, labels: &[&'l str]) -> Option<(&'l str, &'t str)> {
    let text = rest.strip_prefix(['.', '-', '_']).unwrap_or(rest);
    let label = labels.iter().find(|l| text.starts_with(**l))?;
    let after = &text[label.len()..];
    let numbered = after.strip_prefix(['.', '-', '_']).unwrap_or(after);
    let end = numbered
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(numbered.len());
    if end == 0 {
        // No number: a separator after the label belongs to what follows.
        *rest = after;
        return Some((label, ""));
    }
    *rest = &numbered[end..];
    Some((label, &numbered[..end]))
}

/// Takes PEP 440's implicit post-release spelling (`-1` in `1.0-1`) off the front of `rest`
/// and returns its digits, or `None` when it is not there.
fn implicit_post<'t>(rest: &mut &'t str) -> Option<&'t str> {
    let after = rest.strip_prefix('-')?;
    let end = after
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after.len());
    if end == 0 {
        return None;
    }
    *rest = &after[end..];
    Some(&after[..end])
}

/// A local version label (`ubuntu.1`, `cu118`), split at `.`, `-` and `_`.
fn local_parts(text: &str) -> Option<Vec<LocalPart>> {
    text.split(['.', '-', '_'])
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric()) {
                None
            } else if part.bytes().all(|b| b.is_ascii_digit()) {
                digits(part).map(LocalPart::Numeric)
            } else {
                Some(LocalPart::Alphanumeric(part.to_owned()))
            }
        })
        .collect()
}

/// Parses ASCII digits as a number, leading zeros allowed (`007` is 7), or `None` when empty,
/// not all digits, or above `u64::MAX`.
fn digits(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Drops the zeros at the end of a release (`1.2.0.0` is `1.2`), so spellings compare equal.
///
/// Not a `while last() == Some(&0)` loop: its `!=` mutant never ends, and CI counts the
/// timeout as a failure.
fn drop_trailing_zeros(numbers: &mut Vec<u64>) {
    let len = numbers.iter().rposition(|&n| n != 0).map_or(0, |i| i + 1);
    numbers.truncate(len);
}

/// Parses digits separated by single dots (`1.2.10`).
pub(crate) fn dotted(text: &str) -> Option<Dotted> {
    let mut numbers: Vec<u64> = text.split('.').map(digits).collect::<Option<_>>()?;
    drop_trailing_zeros(&mut numbers);
    Some(Dotted(numbers))
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::*;

    use proptest::prelude::*;

    /// The parsers, by name, as one comparison each.
    type Compare = fn(&str, &str) -> Option<Ordering>;

    const SCHEMES: [(&str, Compare); 3] = [
        ("semver", |a, b| Some(semver(a)?.cmp(&semver(b)?))),
        ("pep440", |a, b| Some(pep440(a)?.cmp(&pep440(b)?))),
        ("dotted", |a, b| Some(dotted(a)?.cmp(&dotted(b)?))),
    ];

    fn compare(scheme: &str, a: &str, b: &str) -> Option<Ordering> {
        let (_, cmp) = SCHEMES.iter().find(|(name, _)| *name == scheme).unwrap();
        cmp(a, b)
    }

    /// Asserts that `versions` are in strictly increasing order, pair by pair.
    fn assert_increasing(scheme: &str, versions: &[&str]) {
        for (i, a) in versions.iter().enumerate() {
            for b in &versions[i + 1..] {
                assert_eq!(compare(scheme, a, b), Some(Ordering::Less), "{a} < {b}");
                assert_eq!(compare(scheme, b, a), Some(Ordering::Greater), "{b} > {a}");
            }
        }
    }

    #[test]
    fn semver_follows_the_spec_examples() {
        // Section 11 of SemVer 2.0.0, then core versions.
        assert_increasing(
            "semver",
            &[
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-alpha.beta",
                "1.0.0-beta",
                "1.0.0-beta.2",
                "1.0.0-beta.11",
                "1.0.0-rc.1",
                "1.0.0",
                "1.0.1",
                "1.1.0",
                "2.0.0",
                "10.0.0",
            ],
        );
        assert_eq!(
            compare("semver", "1.0.0+build.1", "1.0.0+other"),
            Some(Ordering::Equal),
            "build metadata takes no part"
        );
        assert!(
            semver("1.2.3-0a").is_some(),
            "alphanumeric, so not a number with a leading zero"
        );
        assert!(
            semver("1.2.3-alpha-1").is_some(),
            "`-` inside a pre-release"
        );
    }

    #[test]
    fn semver_rejects_what_the_spec_does_not_define() {
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "01.2.3",
            "1.2.3-01",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3+",
            "1.2.3+a_b",
            "^1.2.3",
            "1.2.3 ",
            "unknown",
            "99999999999999999999.0.0",
        ] {
            assert!(semver(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn pep440_follows_the_spec_ordering() {
        // The order PEP 440 gives in "Summary of permitted suffixes and relative ordering",
        // with local versions and an epoch added.
        assert_increasing(
            "pep440",
            &[
                "1.0.dev456",
                "1.0a1",
                "1.0a2.dev456",
                "1.0a12.dev456",
                "1.0a12",
                "1.0b1.dev456",
                "1.0b2",
                "1.0b2.post345.dev456",
                "1.0b2.post345",
                "1.0rc1.dev456",
                "1.0rc1",
                "1.0",
                "1.0+abc.5",
                "1.0+abc.7",
                "1.0+5",
                "1.0.post456.dev34",
                "1.0.post456",
                "1.0.15",
                "1.1.dev1",
                "1!0.1",
            ],
        );
    }

    #[test]
    fn pep440_reads_every_spelling_of_one_version() {
        for (a, b) in [
            ("1.0", "1.0.0"),
            ("v1.0", "1.0"),
            ("1.0RC1", "1.0rc1"),
            ("1.0c1", "1.0rc1"),
            ("1.0-preview.2", "1.0rc2"),
            ("1.0alpha", "1.0a0"),
            ("1.0.beta.1", "1.0b1"),
            ("1.0-1", "1.0.post1"),
            ("1.0.post", "1.0.post0"),
            ("1.0-r2", "1.0.post2"),
            ("1.0_dev", "1.0.dev0"),
            ("0!1.0", "1.0"),
            ("007.1", "7.1"),
            (" 1.0 ", "1.0"),
        ] {
            assert_eq!(compare("pep440", a, b), Some(Ordering::Equal), "{a} = {b}");
        }
        for bad in [
            "",
            "1.0-",
            "1.0.x",
            "1..0",
            "1.0.",
            "1.0+",
            "1.0+a..b",
            "1.0+a@b",
            "1.0abc",
            "^1.0",
            "latest",
            "1.0.post99999999999999999999",
        ] {
            assert!(pep440(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn dotted_numbers_ignore_trailing_zeros_and_nothing_else() {
        assert_eq!(compare("dotted", "1.2", "1.2.0"), Some(Ordering::Equal));
        assert_eq!(compare("dotted", "1.10", "1.9"), Some(Ordering::Greater));
        assert_eq!(compare("dotted", "1", "1.0.1"), Some(Ordering::Less));
        for bad in ["", "1.2a", "v1", "1.2-1", "1..2", ".1", "1.", "1,2", "+1"] {
            assert!(dotted(bad).is_none(), "{bad:?}");
        }
    }

    /// A SemVer core and pre-release identifiers, numbers as `Ok` and words as `Err`, so the
    /// derived order of `Result` (numbers first) is the model's.
    type Parts = ([u64; 3], Vec<Result<u64, String>>);

    fn semver_parts() -> impl Strategy<Value = Parts> {
        let id = prop_oneof![
            (0_u64..20).prop_map(Ok),
            "[a-z][a-z0-9-]{0,3}".prop_map(Err),
        ];
        (
            (0_u64..4, 0_u64..4, 0_u64..4),
            prop::collection::vec(id, 0..3),
        )
            .prop_map(|((a, b, c), pre)| ([a, b, c], pre))
    }

    fn semver_text((core, pre): &Parts) -> String {
        let core = format!("{}.{}.{}", core[0], core[1], core[2]);
        if pre.is_empty() {
            return core;
        }
        let pre: Vec<String> = pre
            .iter()
            .map(|id| match id {
                Ok(n) => n.to_string(),
                Err(s) => s.clone(),
            })
            .collect();
        format!("{core}-{}", pre.join("."))
    }

    proptest! {
        /// SemVer precedence matches a model of the spec's rules: the core, then a release
        /// after its pre-releases, then identifiers in order, numbers before words, and a
        /// shorter list first when it begins the longer.
        #[test]
        fn semver_matches_the_model(a in semver_parts(), b in semver_parts()) {
            let key = |(core, pre): &Parts| (*core, pre.is_empty(), pre.clone());
            let expected = key(&a).cmp(&key(&b));
            let actual = compare("semver", &semver_text(&a), &semver_text(&b));
            prop_assert_eq!(actual, Some(expected));
        }

        /// A listed version matches what PEP 440 calls equal, plus every local build of it when
        /// it has no local label of its own; nothing else.
        #[test]
        fn a_listed_version_matches_its_local_builds(
            installed in "[0-9]{1,2}(\\.[0-9]){0,2}(rc[0-9])?(\\+[a-z0-9]{1,4})?",
            listed in "[0-9]{1,2}(\\.[0-9]){0,2}(rc[0-9])?(\\+[a-z0-9]{1,4})?",
        ) {
            let (Some(a), Some(b)) = (pep440(&installed), pep440(&listed)) else {
                return Ok(());
            };
            let public = |text: &str| text.split('+').next().map(str::to_owned);
            let (a_public, b_public) = (public(&installed).unwrap(), public(&listed).unwrap());
            let same_public = pep440(&a_public) == pep440(&b_public);
            let expected = if listed.contains('+') { a == b } else { same_public };
            prop_assert_eq!(a.is_listed_as(&b), expected);
        }

        /// Every scheme is a total order wherever both sides parse: reflexive, antisymmetric
        /// and transitive.
        #[test]
        fn every_scheme_is_a_total_order(
            a in "[0-9a-z.!+_-]{0,10}",
            b in "[0-9a-z.!+_-]{0,10}",
            c in "[0-9a-z.!+_-]{0,10}",
        ) {
            for (_, cmp) in SCHEMES {
                if let Some(order) = cmp(&a, &b) {
                    prop_assert_eq!(cmp(&a, &a), Some(Ordering::Equal));
                    prop_assert_eq!(cmp(&b, &a), Some(order.reverse()));
                    if cmp(&b, &c) == Some(order) {
                        prop_assert_eq!(cmp(&a, &c), Some(order));
                    }
                }
            }
        }

        /// PEP 440 and dotted numbers order release numbers like lists with trailing zeros
        /// dropped.
        #[test]
        fn releases_compare_as_lists(
            a in prop::collection::vec(0_u64..30, 1..4),
            b in prop::collection::vec(0_u64..30, 1..4),
        ) {
            let text = |v: &[u64]| v.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
            let trim = |v: &[u64]| {
                let mut v = v.to_vec();
                while v.last() == Some(&0) {
                    v.pop();
                }
                v
            };
            let expected = trim(&a).cmp(&trim(&b));
            prop_assert_eq!(compare("pep440", &text(&a), &text(&b)), Some(expected));
            prop_assert_eq!(compare("dotted", &text(&a), &text(&b)), Some(expected));
        }
    }
}
