//! The agent's verdict: `findings.json`, and the strict checks it must pass.
//!
//! The agent lists only advisories it judges to affect an installed version. Everything it
//! names must exist in the bundle and fit together: an advisory id (or alias) it did not
//! receive, a component id that is not in the inventory, or an advisory that was not fetched
//! for the finding's component is an error, so a made-up finding cannot reach the user.
//! Known-exploited comes from the CISA catalog whenever the catalog was read, and such a
//! finding is at least `high`.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

use crate::bundle::component_id;

/// The JSON Schema of `findings.json`, written into each bundle for the agent.
pub(crate) const SCHEMA: &str = include_str!("findings.schema.json");

/// What the agent wrote.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Findings {
    findings: Vec<Finding>,
    /// Optional, unlike in the schema: a prompt copied to the data directory before issues
    /// existed asks for `{"findings": []}`, and a Mac sweep has no issues.
    #[serde(default)]
    issues: Vec<Issue>,
}

/// One advisory that affects one installed component.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// The advisory ids this finding is about; the first is the primary one.
    pub advisories: Vec<String>,
    /// The id of the affected component in `inventory.jsonl` (`c12`).
    pub component: String,
    /// How bad it is on this machine.
    pub severity: Severity,
    /// Whether the issue is exploited in the wild (CISA KEV).
    pub known_exploited: bool,
    /// How sure the agent is that the installed version is affected.
    pub confidence: Confidence,
    /// What the agent checked: the installed version against the affected range, a config.
    pub evidence: String,
    /// What the issue means for the user, in plain language.
    pub explanation: String,
    /// How to fix it. Never run during a sweep.
    pub fix: Fix,
}

/// A risky setting or file that no advisory names: no branch protection, an unpinned action.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    /// What the issue is about.
    pub subject: Subject,
    /// How bad it is for this target.
    pub severity: Severity,
    /// What the agent checked.
    pub evidence: String,
    /// What the issue means for the user, in plain language.
    pub explanation: String,
    /// How to fix it. Never run during a sweep.
    pub fix: Fix,
}

/// What an [`Issue`] is about: a key of the bundle's `github/settings.json`, or a bundle file.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Subject {
    /// A setting, by its key in `github/settings.json`.
    Setting(String),
    /// A file, by its path in the bundle (`github/workflows/ci.yml`).
    File(String),
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setting(key) => write!(f, "setting {key}"),
            Self::File(path) => write!(f, "file {path}"),
        }
    }
}

/// A suggested fix.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fix {
    /// One line: what the fix does.
    pub summary: String,
    /// The steps, in order.
    pub steps: Vec<String>,
    /// The exact shell commands, in order; may be empty when the fix is manual.
    pub commands: Vec<String>,
}

/// Severity on this machine, most severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Exploitable for serious harm now.
    Critical,
    /// Serious; fix soon.
    High,
    /// Fix when convenient.
    Medium,
    /// Little risk here.
    Low,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        })
    }
}

/// How sure the agent is.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The installed version is in the affected range, or the agent verified the issue.
    Confirmed,
    /// Probably affected, but the agent could not be sure (a missing range, a vendor build).
    Likely,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Confirmed => "confirmed",
            Self::Likely => "likely",
        })
    }
}

/// What a finding may refer to, from the bundle.
#[derive(Debug, Default)]
pub(crate) struct Known {
    /// How many components `inventory.jsonl` holds; their ids are `c1` to `c{components}`.
    pub(crate) components: usize,
    /// Each advisory id and the indexes of the components it was fetched for.
    pub(crate) advisories: BTreeMap<String, BTreeSet<usize>>,
    /// Each alias (a GHSA's CVE) and the advisory ids that list it.
    pub(crate) aliases: BTreeMap<String, BTreeSet<String>>,
    /// The advisory ids in the CISA KEV catalog, or `None` when it could not be read.
    pub(crate) exploited: Option<BTreeSet<String>>,
    /// The setting keys an issue may name.
    pub(crate) settings: BTreeSet<String>,
    /// The bundle files an issue may name, by path in the bundle.
    pub(crate) files: BTreeSet<String>,
}

/// A `findings.json` that passed validation.
#[derive(Debug, Default)]
pub(crate) struct Verdict {
    pub(crate) findings: Vec<Valid>,
    pub(crate) issues: Vec<Issue>,
}

/// A finding that passed validation, with the index of its component and its primary advisory:
/// the smallest id of the bundle advisories its listed ids resolved to. That advisory keys the
/// finding, so it does not depend on what the agent listed first: a GHSA's CVE in one sweep,
/// the GHSA in the next.
#[derive(Debug)]
pub(crate) struct Valid {
    pub(crate) finding: Finding,
    pub(crate) component: usize,
    pub(crate) advisory: String,
}

/// Parses and checks `findings.json` against what the bundle offered, and sets
/// known-exploited from the catalog. Every problem is reported, not only the first.
pub(crate) fn validate(text: &str, known: &Known) -> Result<Verdict, Vec<String>> {
    let findings: Findings =
        serde_json::from_str(text).map_err(|e| vec![format!("findings.json: {e}")])?;

    let mut problems = Vec::new();
    let valid = check_findings(findings.findings, known, &mut problems);
    let mut subjects = BTreeSet::new();
    for (i, issue) in findings.issues.iter().enumerate() {
        let at = format!("issues[{i}]");
        // The subject keys the issue across sweeps (see `lifecycle`), so it names one issue.
        let subject = plain_subject(&issue.subject);
        if !subjects.insert(subject.clone()) {
            problems.push(format!(
                "{at}.subject: {subject} is already an issue; merge them"
            ));
        }
        let known_subject = match &issue.subject {
            Subject::Setting(key) => known.settings.contains(key),
            Subject::File(path) => known.files.contains(path),
        };
        if !known_subject {
            problems.push(format!(
                "{at}.subject: {} is not in this bundle (settings are the keys of \
                 github/settings.json, files are bundle paths such as github/workflows/ci.yml)",
                plain_subject(&issue.subject)
            ));
        }
        check_text(
            &at,
            &issue.evidence,
            &issue.explanation,
            &issue.fix,
            &mut problems,
        );
    }
    if problems.is_empty() {
        Ok(Verdict {
            findings: valid,
            issues: findings.issues,
        })
    } else {
        Err(problems)
    }
}

/// The subject quoted, so an agent's text cannot shape the message.
fn plain_subject(subject: &Subject) -> String {
    match subject {
        Subject::Setting(key) => format!("setting {key:?}"),
        Subject::File(path) => format!("file {path:?}"),
    }
}

/// Checks the advisory findings, adding every problem, and returns the valid ones.
fn check_findings(findings: Vec<Finding>, known: &Known, problems: &mut Vec<String>) -> Vec<Valid> {
    let mut valid = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, mut finding) in findings.into_iter().enumerate() {
        let at = format!("findings[{i}]");
        let before = problems.len();
        let component = component_index(&at, &finding.component, known, problems);
        let advisories = resolve(&at, &finding.advisories, component, known, problems);
        if let Some(component) = component {
            for advisory in &advisories {
                if !seen.insert((advisory.clone(), component)) {
                    problems.push(format!(
                        "{at}: {advisory} on {} is already a finding; merge them",
                        component_id(component)
                    ));
                }
            }
        }
        let fix = &finding.fix;
        check_text(&at, &finding.evidence, &finding.explanation, fix, problems);
        let Some(component) = component.filter(|_| problems.len() == before) else {
            continue;
        };

        // When the catalog was read it decides, in both directions, from the advisories linked
        // to this component; without it the agent's word is kept but cannot raise the severity.
        if let Some(exploited) = &known.exploited {
            finding.known_exploited = advisories.iter().any(|a| exploited.contains(a));
            if finding.known_exploited {
                finding.severity = finding.severity.min(Severity::High);
            }
        }
        let advisory = advisories
            .into_iter()
            .min()
            .expect("a finding without problems resolved at least one advisory");
        valid.push(Valid {
            finding,
            component,
            advisory,
        });
    }
    valid
}

/// Parses `c<n>` into the component's index, reporting an id not in the inventory.
fn component_index(at: &str, id: &str, known: &Known, problems: &mut Vec<String>) -> Option<usize> {
    let index = id
        .strip_prefix('c')
        .filter(|n| !n.starts_with('0'))
        .and_then(|n| n.parse::<usize>().ok())
        .filter(|n| (1..=known.components).contains(n))
        .map(|n| n - 1);
    if index.is_none() {
        problems.push(format!("{at}.component: {id:?} is not in inventory.jsonl"));
    }
    index
}

/// Resolves each listed id to the advisories it names that were fetched for `component`, in
/// listed order and each once. An id names itself when it is an advisory, and every advisory
/// that lists it as an alias, so a GHSA and its CVE may be listed together, as the prompt asks,
/// even when the CVE is also an NVD entry of its own for another component. Reports an empty
/// list, a repeated id, an unknown id, and an id none of whose advisories was fetched for the
/// component. Without a valid component only unknown ids can be reported.
fn resolve(
    at: &str,
    listed: &[String],
    component: Option<usize>,
    known: &Known,
    problems: &mut Vec<String>,
) -> Vec<String> {
    if listed.is_empty() {
        problems.push(format!("{at}.advisories is empty"));
    }
    let mut linked: Vec<String> = Vec::new();
    for (i, id) in listed.iter().enumerate() {
        if listed[..i].contains(id) {
            problems.push(format!("{at}.advisories: {id:?} is listed twice"));
            continue;
        }
        let named: Vec<&String> = known
            .advisories
            .get_key_value(id)
            .map(|(k, _)| k)
            .into_iter()
            .chain(known.aliases.get(id).into_iter().flatten())
            .collect();
        if named.is_empty() {
            problems.push(format!(
                "{at}.advisories: {id:?} is not in advisories.jsonl"
            ));
            continue;
        }
        let Some(component) = component else {
            continue;
        };
        let fetched_for = |a: &&String| {
            known
                .advisories
                .get(*a)
                .is_some_and(|c| c.contains(&component))
        };
        let mut any = false;
        for advisory in named.into_iter().filter(fetched_for) {
            any = true;
            if !linked.contains(advisory) {
                linked.push(advisory.clone());
            }
        }
        if !any {
            problems.push(format!(
                "{at}.advisories: {id} was not fetched for {} (see `components` in \
                 advisories.jsonl)",
                component_id(component)
            ));
        }
    }
    linked
}

/// Text must say something, and holds no control or invisible formatting characters: it is
/// shown in a terminal and in Markdown, where an escape sequence or a stray line break could
/// forge output, and fix commands go to the user for approval, where a bidirectional override
/// could make a command read differently from what it runs.
fn check_text(at: &str, evidence: &str, explanation: &str, fix: &Fix, problems: &mut Vec<String>) {
    for (field, value) in [("evidence", evidence), ("explanation", explanation)] {
        check_prose(&format!("{at}.{field}"), value, problems);
    }
    check_fix(&format!("{at}.fix"), fix, problems);
}

fn check_prose(at: &str, value: &str, problems: &mut Vec<String>) {
    if value.trim().is_empty() {
        problems.push(format!("{at} is empty"));
    }
    if value.chars().any(|c| is_forging(c) && c != '\n') {
        problems.push(format!("{at} has control or invisible characters"));
    }
}

/// Checks a fix as [`check_text`] does; also for a fix read back from a report to run it.
pub(crate) fn check_fix(at: &str, fix: &Fix, problems: &mut Vec<String>) {
    check_prose(&format!("{at}.summary"), &fix.summary, problems);
    if fix.steps.iter().any(|l| l.chars().any(is_forging)) {
        problems.push(format!(
            "{at}.steps: each step is one line, without control or invisible characters"
        ));
    }
    // Commands are what the user approves to run, so they are held to the strictest form: a
    // look-alike or joiner character would make `lo\u{2060}dash` read as `lodash`.
    let printable = |c: &String| c.bytes().all(|b| (b' '..=b'~').contains(&b));
    if !fix.commands.iter().all(printable) {
        problems.push(format!(
            "{at}.commands: each command is one line of printable ASCII"
        ));
    }
}

/// Whether `c` can change how text displays without showing itself: a control character, a
/// bidirectional formatting character (the "Trojan Source" set,
/// <https://trojansource.codes/trojan-source.pdf>), or an invisible one: zero-width spaces and
/// joiners, invisible operators, the soft hyphen, the combining grapheme joiner, the Hangul
/// fillers, the byte-order mark, the Mongolian vowel separator and free variation selectors,
/// the line and paragraph separators, and the tag block and the variation selectors, which can
/// carry hidden text.
/// U+FE0F stays allowed: it follows emoji in ordinary prose.
pub(crate) fn is_forging(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{061c}'
                | '\u{feff}'
                | '\u{00ad}'
                | '\u{034f}'
                | '\u{2060}'..='\u{2064}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{3164}'
                | '\u{ffa0}'
                | '\u{e0000}'..='\u{e007f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{180b}'..='\u{180f}'
                | '\u{fe00}'..='\u{fe0e}'
                | '\u{e0100}'..='\u{e01ef}'
        )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// c1 is lodash with GHSA-1 (alias CVE-1); c2 is openssl with CVE-2, CVE-KEV, and CVE-1 as an
    /// NVD entry of its own.
    fn known(kev: Option<&[&str]>) -> Known {
        Known {
            components: 2,
            advisories: [
                ("GHSA-1".to_owned(), [0].into()),
                ("CVE-2".to_owned(), [1].into()),
                ("CVE-KEV".to_owned(), [1].into()),
                ("CVE-1".to_owned(), [1].into()),
            ]
            .into(),
            aliases: [("CVE-1".to_owned(), ["GHSA-1".to_owned()].into())].into(),
            exploited: kev.map(|ids| ids.iter().map(|id| (*id).to_owned()).collect()),
            settings: ["default_branch_protection".to_owned()].into(),
            files: ["github/workflows/ci.yml".to_owned()].into(),
        }
    }

    fn finding(
        advisories: &[&str],
        component: &str,
        severity: &str,
        kev: bool,
    ) -> serde_json::Value {
        json!({
            "advisories": advisories,
            "component": component,
            "severity": severity,
            "known_exploited": kev,
            "confidence": "confirmed",
            "evidence": "4.17.20 < 4.17.21",
            "explanation": "Prototype pollution.",
            "fix": {"summary": "Upgrade", "steps": ["Upgrade lodash"], "commands": ["npm i lodash"]}
        })
    }

    fn check(findings: &[serde_json::Value], known: &Known) -> Result<Vec<Valid>, Vec<String>> {
        let text = json!({ "findings": findings, "issues": [] }).to_string();
        validate(&text, known).map(|verdict| verdict.findings)
    }

    fn issue(subject: &serde_json::Value) -> serde_json::Value {
        json!({
            "subject": subject,
            "severity": "medium",
            "evidence": "main is not protected",
            "explanation": "Anyone with push access can rewrite it.",
            "fix": {"summary": "Protect main", "steps": [], "commands": []}
        })
    }

    #[test]
    fn issues_name_a_setting_or_a_bundle_file() {
        let known = known(None);
        let text = json!({
            "findings": [],
            "issues": [
                issue(&json!({"setting": "default_branch_protection"})),
                issue(&json!({"file": "github/workflows/ci.yml"}))
            ]
        });
        let verdict = validate(&text.to_string(), &known).unwrap();
        assert_eq!(verdict.issues.len(), 2);
        assert!(matches!(
            &verdict.issues[0].subject,
            Subject::Setting(key) if key == "default_branch_protection"
        ));

        let mut bad = issue(&json!({"file": "../etc/passwd"}));
        bad["explanation"] = json!("x\u{1b}[2J");
        let text = json!({
            "findings": [],
            "issues": [issue(&json!({"setting": "made_up"})), bad]
        });
        let problems = validate(&text.to_string(), &known).unwrap_err();
        assert_eq!(
            problems,
            [
                "issues[0].subject: setting \"made_up\" is not in this bundle (settings are the \
                 keys of github/settings.json, files are bundle paths such as \
                 github/workflows/ci.yml)",
                "issues[1].subject: file \"../etc/passwd\" is not in this bundle (settings are \
                 the keys of github/settings.json, files are bundle paths such as \
                 github/workflows/ci.yml)",
                "issues[1].explanation has control or invisible characters",
            ]
        );

        for subject in [json!({"both": 1}), json!({"setting": "a", "file": "b"})] {
            let text = json!({"findings": [], "issues": [issue(&subject)]});
            assert!(validate(&text.to_string(), &known).is_err());
        }
        let ci = json!({"file": "github/workflows/ci.yml"});
        let text = json!({"findings": [], "issues": [issue(&ci), issue(&ci)]});
        assert_eq!(
            validate(&text.to_string(), &known).unwrap_err(),
            ["issues[1].subject: file \"github/workflows/ci.yml\" is already an issue; merge them"]
        );

        let older = validate(r#"{"findings": []}"#, &known).unwrap();
        assert!(
            older.issues.is_empty(),
            "a prompt from before issues still works"
        );
        assert_eq!(Subject::File("a".into()).to_string(), "file a");
    }

    #[test]
    fn accepts_valid_findings_and_aliases() {
        let kev = known(Some(&[]));
        let valid = check(
            &[finding(&["GHSA-1", "CVE-1"], "c1", "medium", false)],
            &kev,
        )
        .unwrap();
        assert_eq!(valid[0].component, 0);
        assert_eq!(valid[0].finding.severity, Severity::Medium);
        assert_eq!(valid[0].advisory, "GHSA-1");
        let valid = check(&[finding(&["CVE-1"], "c1", "low", false)], &kev).unwrap();
        assert_eq!(valid.len(), 1, "an alias alone names its advisory");
        assert_eq!(
            valid[0].advisory, "GHSA-1",
            "the primary is a bundle advisory"
        );
        for listed in [["CVE-KEV", "CVE-2"], ["CVE-2", "CVE-KEV"]] {
            let valid = check(&[finding(&listed, "c2", "low", false)], &kev).unwrap();
            assert_eq!(
                valid[0].advisory, "CVE-2",
                "the smallest, whatever the order"
            );
        }
        let valid = check(&[finding(&["CVE-1"], "c2", "low", false)], &kev).unwrap();
        assert_eq!(
            valid[0].component, 1,
            "and an advisory of the same id names itself"
        );
        assert!(check(&[], &kev).unwrap().is_empty());
    }

    #[test]
    fn known_exploited_follows_the_catalog_both_ways() {
        let kev = known(Some(&["CVE-KEV"]));
        let up = check(&[finding(&["CVE-KEV"], "c2", "low", false)], &kev).unwrap();
        assert!(up[0].finding.known_exploited);
        assert_eq!(up[0].finding.severity, Severity::High);
        let keep = check(&[finding(&["CVE-KEV"], "c2", "critical", false)], &kev).unwrap();
        assert_eq!(keep[0].finding.severity, Severity::Critical);

        let down = check(&[finding(&["CVE-2"], "c2", "medium", true)], &kev).unwrap();
        assert!(
            !down[0].finding.known_exploited,
            "the agent cannot claim what KEV denies"
        );
        assert_eq!(down[0].finding.severity, Severity::Medium);

        let unknown = known(None);
        let claimed = check(&[finding(&["CVE-2"], "c2", "medium", true)], &unknown).unwrap();
        assert!(claimed[0].finding.known_exploited, "kept without a catalog");
        assert_eq!(
            claimed[0].finding.severity,
            Severity::Medium,
            "but not raised"
        );
    }

    #[test]
    fn rejects_mislinked_unknown_and_repeated() {
        let kev = known(Some(&[]));
        let problems = check(
            &[
                finding(&["GHSA-1"], "c2", "high", false),
                finding(&["CVE-MADE-UP"], "c9", "high", false),
                finding(&["GHSA-1", "GHSA-1"], "c1", "high", false),
                finding(&["GHSA-1"], "c1", "low", false),
                finding(&["CVE-2"], "c01", "low", false),
                finding(&["GHSA-1", "CVE-2"], "c1", "low", false),
            ],
            &kev,
        )
        .unwrap_err();
        assert_eq!(
            problems,
            [
                "findings[0].advisories: GHSA-1 was not fetched for c2 (see `components` in \
                 advisories.jsonl)",
                r#"findings[1].component: "c9" is not in inventory.jsonl"#,
                r#"findings[1].advisories: "CVE-MADE-UP" is not in advisories.jsonl"#,
                r#"findings[2].advisories: "GHSA-1" is listed twice"#,
                "findings[3]: GHSA-1 on c1 is already a finding; merge them",
                r#"findings[4].component: "c01" is not in inventory.jsonl"#,
                "findings[5].advisories: CVE-2 was not fetched for c1 (see `components` in \
                 advisories.jsonl)",
                "findings[5]: GHSA-1 on c1 is already a finding; merge them",
            ]
        );
    }

    #[test]
    fn rejects_empty_and_control_text() {
        let kev = known(Some(&[]));
        let mut bad = finding(&[], "c1", "low", false);
        bad["evidence"] = json!(" ");
        bad["explanation"] = json!("ok\u{1b}[2J");
        bad["fix"]["commands"] = json!(["npm i\nrm -rf ~"]);
        bad["fix"]["steps"] = json!(["Upgrade lo\u{2060}dash"]);
        bad["fix"]["summary"] = json!("Upgrade \u{202e}tsal");
        let problems = check(&[bad], &kev).unwrap_err();
        assert_eq!(
            problems,
            [
                "findings[0].advisories is empty",
                "findings[0].evidence is empty",
                "findings[0].explanation has control or invisible characters",
                "findings[0].fix.summary has control or invisible characters",
                "findings[0].fix.steps: each step is one line, without control or invisible \
                 characters",
                "findings[0].fix.commands: each command is one line of printable ASCII",
            ]
        );
        let mut fine = finding(&["GHSA-1"], "c1", "low", false);
        fine["explanation"] = json!("Two lines\nare fine in prose.");
        fine["fix"]["steps"] = json!(["Mettre à jour lodash"]);
        assert!(check(&[fine], &kev).is_ok());
    }

    #[test]
    fn rejects_bad_shapes() {
        for text in [
            "not json",
            r#"{"findings": [{"advisories": []}]}"#,
            r#"{"findings": [], "extra": 1}"#,
        ] {
            let problems = validate(text, &known(None)).unwrap_err();
            assert_eq!(problems.len(), 1, "{text}");
            assert!(problems[0].starts_with("findings.json: "), "{problems:?}");
        }
        assert!(check(&[finding(&["GHSA-1"], "c1", "severe", false)], &known(None)).is_err());
    }

    #[test]
    fn separators_and_variation_selectors_are_forging() {
        let edges = [
            '\u{2028}',
            '\u{2029}',
            '\u{180b}',
            '\u{180f}',
            '\u{fe00}',
            '\u{fe0e}',
            '\u{e0100}',
            '\u{e01ef}',
        ];
        for c in edges {
            assert!(is_forging(c), "{:04x}", u32::from(c));
        }
        assert!(
            !is_forging('\u{fe0f}'),
            "the emoji presentation selector stays allowed"
        );
        assert!(!is_forging('\u{e01f0}'), "past the last variation selector");
    }

    #[test]
    fn display_words() {
        assert_eq!(Confidence::Confirmed.to_string(), "confirmed");
        assert_eq!(Confidence::Likely.to_string(), "likely");
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Low.to_string(), "low");
    }

    #[test]
    fn schema_is_valid_json_naming_every_field() {
        let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
        let item = &schema["properties"]["findings"]["items"];
        let required: Vec<_> = item["required"].as_array().unwrap().iter().collect();
        for field in [
            "advisories",
            "component",
            "severity",
            "known_exploited",
            "confidence",
            "evidence",
            "explanation",
            "fix",
        ] {
            assert!(required.iter().any(|r| *r == field), "{field}");
        }
        assert_eq!(item["additionalProperties"], false);
    }
}
