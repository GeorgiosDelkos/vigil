//! The folder an agent works in for one target: prompt, inventory, advisories and schema.
//!
//! `advisories.jsonl` is an index, one compact line per advisory, so a product with hundreds of
//! CVEs still fits in the agent's context; each line names `records/<source>-<id>.json`, the
//! full record as the source served it, for when the agent needs detail. Layout: spec, "Bundle
//! and findings".

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use serde_json::Value;
use serde_json::json;

use crate::feeds::Advisory;
use crate::feeds::Kev;
use crate::feeds::Source;
use crate::feeds::cache_key;
use crate::findings::Known;
use crate::findings::SCHEMA;
use crate::inventory::Component;
use crate::matching::Match;

/// The longest summary kept in the index, in characters. Arbitrary: enough for the first
/// sentence or two; the full text is in the record.
const SUMMARY_LIMIT: usize = 400;

/// The most explicit affected versions kept on an index line. Arbitrary: short lists (often
/// the only affected set, as in malicious-package records) stay, and a longer one is replaced
/// by its length and a pointer to the record, so the agent knows to open it.
const VERSIONS_LIMIT: usize = 50;

/// One advisory and the components it is a candidate for, by index, each with how the
/// advisory's affected versions relate to its version.
#[derive(Debug)]
pub(crate) struct Entry<'a> {
    pub(crate) advisory: &'a Advisory,
    pub(crate) components: &'a BTreeMap<usize, Match>,
}

/// What goes into one target's bundle.
#[derive(Debug)]
pub(crate) struct Contents<'a> {
    /// The rendered prompt, written as `PROMPT.md`.
    pub(crate) prompt: &'a str,
    /// The inventory; components get ids `c1`, `c2`, ... in this order.
    pub(crate) components: &'a [Component],
    /// The advisories and the components each was fetched for.
    pub(crate) entries: &'a [Entry<'a>],
    /// Target files by path in the bundle, all under [`TARGET_FILES`].
    pub(crate) files: &'a [(String, String)],
    /// The setting keys an issue may name.
    pub(crate) settings: &'a [String],
}

/// The folder of a bundle that holds a target's own files, so they cannot replace the
/// bundle's fixed files (`PROMPT.md`, `inventory.jsonl`, ...).
const TARGET_FILES: [&str; 2] = ["github", "server"];

/// Writes the bundle into `dir` (created if needed) and returns what findings may refer to.
///
/// `kev` is `None` when the catalog could not be read; `known_exploited` is then `null` in the
/// index.
pub(crate) fn write(
    dir: &Path,
    contents: &Contents<'_>,
    kev: Option<&Kev>,
) -> Result<Known, BundleError> {
    let Contents {
        prompt,
        components,
        entries,
        files,
        settings,
    } = *contents;
    let io_err = |path: &Path| {
        let path = path.to_owned();
        move |source| BundleError::Write { path, source }
    };
    let records = dir.join("records");
    fs::create_dir_all(&records).map_err(io_err(&records))?;

    let mut inventory = String::new();
    for (i, component) in components.iter().enumerate() {
        let mut line = serde_json::to_value(component)
            .map_err(|e| io_err(&dir.join("inventory.jsonl"))(io::Error::other(e)))?;
        line["id"] = Value::String(component_id(i));
        inventory.push_str(&line.to_string());
        inventory.push('\n');
    }

    let mut known = Known {
        components: components.len(),
        exploited: kev.map(|_| BTreeSet::new()),
        ..Known::default()
    };
    let mut index = String::new();
    for entry in entries {
        let advisory = entry.advisory;
        // Ids name files. The feeds check them already; this keeps an id that slipped past a
        // feed from naming a path outside the bundle.
        let id = cache_key(&advisory.id)
            .map_err(|_| BundleError::BadId {
                id: advisory.id.clone(),
            })?
            .to_owned();
        let record_name = format!("records/{}-{id}.json", advisory.source.name());
        let record_path = dir.join(&record_name);
        fs::write(&record_path, advisory.record.get()).map_err(io_err(&record_path))?;

        let exploited = kev.map(|kev| advisory.is_known_exploited(kev));
        if exploited == Some(true)
            && let Some(set) = &mut known.exploited
        {
            set.insert(id.clone());
        }
        let mut line = compact(advisory);
        line["known_exploited"] = json!(exploited);
        let components: Vec<Value> = entry
            .components
            .iter()
            .map(|(i, verdict)| {
                let id = component_id(*i);
                json!({"component": id, "match": verdict.name(), "why": verdict.why()})
            })
            .collect();
        line["components"] = json!(components);
        line["record"] = json!(record_name);
        index.push_str(&line.to_string());
        index.push('\n');

        for alias in &advisory.aliases {
            known
                .aliases
                .entry(alias.clone())
                .or_default()
                .insert(id.clone());
        }
        known
            .advisories
            .entry(id)
            .or_default()
            .extend(entry.components.keys());
    }

    for (name, text) in [
        ("PROMPT.md", prompt),
        ("inventory.jsonl", &inventory),
        ("advisories.jsonl", &index),
        ("findings.schema.json", SCHEMA),
    ] {
        let path = dir.join(name);
        fs::write(&path, text).map_err(io_err(&path))?;
    }
    write_target_files(dir, files)?;
    known.files = files.iter().map(|(name, _)| name.clone()).collect();
    known.settings = settings.iter().cloned().collect();
    Ok(known)
}

/// Writes each target file at its path in `dir`, after checking the path: under
/// [`TARGET_FILES`], each part made of ASCII letters, digits, `.`, `-` and `_`, none starting
/// with `.`, so no path can leave the folder or replace a fixed file.
fn write_target_files(dir: &Path, files: &[(String, String)]) -> Result<(), BundleError> {
    for (name, text) in files {
        let parts: Vec<&str> = name.split('/').collect();
        let safe = parts.len() >= 2
            && TARGET_FILES.contains(&parts[0])
            && parts.iter().all(|p| cache_key(p).is_ok());
        if !safe {
            return Err(BundleError::BadPath { path: name.clone() });
        }
        let path = dir.join(name);
        let parent = path
            .parent()
            .expect("a checked path has at least two parts");
        fs::create_dir_all(parent)
            .and_then(|()| fs::write(&path, text))
            .map_err(|source| BundleError::Write { path, source })?;
    }
    Ok(())
}

/// The id of the `i`th component in a bundle.
pub(crate) fn component_id(i: usize) -> String {
    format!("c{}", i + 1)
}

/// The index line for one advisory: the fields that decide whether it applies.
fn compact(advisory: &Advisory) -> Value {
    let record: Value = serde_json::from_str(advisory.record.get()).unwrap_or(Value::Null);
    let (summary, severity, affected) = match advisory.source {
        Source::Osv => osv_fields(&record),
        Source::Nvd => nvd_fields(&record),
    };
    json!({
        "id": advisory.id,
        "source": advisory.source.name(),
        "aliases": advisory.aliases,
        "summary": truncate(&summary),
        "severity": severity,
        "affected": affected,
    })
}

/// OSV: `summary` (or the start of `details`), `severity` (CVSS vectors) or the GitHub
/// `database_specific.severity`, and each `affected` package with its ranges and its explicit
/// `versions`. A version is affected when it is in a range or in `versions`, and some records
/// have only the list, so it is kept; a long list is replaced by its length.
fn osv_fields(record: &Value) -> (String, Value, Value) {
    let summary = record["summary"]
        .as_str()
        .or_else(|| record["details"].as_str())
        .unwrap_or_default()
        .to_owned();
    let severity = if record["severity"].is_array() {
        record["severity"].clone()
    } else {
        record["database_specific"]["severity"].clone()
    };
    let affected = record["affected"]
        .as_array()
        .into_iter()
        .flatten()
        .map(osv_affected)
        .collect();
    (summary, severity, Value::Array(affected))
}

fn osv_affected(affected: &Value) -> Value {
    let mut line = json!({"package": affected["package"], "ranges": affected["ranges"]});
    match affected["versions"].as_array() {
        Some(versions) if versions.len() > VERSIONS_LIMIT => {
            line["versions_count"] = json!(versions.len());
            line["versions_note"] = json!("too many to list here; read the record");
        }
        Some(versions) => line["versions"] = json!(versions),
        None => {}
    }
    line
}

/// NVD: the English description, the newest CVSS metric present (v4.0, v3.1, v3.0, then v2),
/// preferring NVD's own `Primary` score over a vendor's `Secondary` one, and the
/// configurations with their AND/OR structure. A CVE that needs a vulnerable product on a
/// particular platform is not a plain version range, and flattening the matches would hide that.
fn nvd_fields(record: &Value) -> (String, Value, Value) {
    let summary = record["descriptions"]
        .as_array()
        .and_then(|list| list.iter().find(|d| d["lang"] == "en"))
        .and_then(|d| d["value"].as_str())
        .unwrap_or_default()
        .to_owned();
    let metrics = &record["metrics"];
    let severity = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]
    .iter()
    .find_map(|key| {
        let list = metrics[key].as_array()?;
        list.iter()
            .find(|m| m["type"] == "Primary")
            .or(list.first())
    })
    .map_or(Value::Null, |metric| {
        let data = &metric["cvssData"];
        json!({
            "version": data["version"],
            "score": data["baseScore"],
            "severity": data["baseSeverity"].as_str().or(metric["baseSeverity"].as_str()),
            "vector": data["vectorString"],
        })
    });
    let configurations = record["configurations"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|config| {
            let nodes: Vec<Value> = config["nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .map(nvd_node)
                .collect();
            json!({"operator": config["operator"], "nodes": nodes})
        })
        .collect();
    (summary, severity, Value::Array(configurations))
}

/// A configuration node with its CPE matches, without their database ids.
fn nvd_node(node: &Value) -> Value {
    let matches: Vec<Value> = node["cpeMatch"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|cpe| {
            let mut kept = serde_json::Map::new();
            for key in [
                "vulnerable",
                "criteria",
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
            ] {
                if !cpe[key].is_null() {
                    kept.insert(key.to_owned(), cpe[key].clone());
                }
            }
            Value::Object(kept)
        })
        .collect();
    json!({"operator": node["operator"], "negate": node["negate"], "cpeMatch": matches})
}

fn truncate(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= SUMMARY_LIMIT {
        return text.to_owned();
    }
    let cut: String = text.chars().take(SUMMARY_LIMIT).collect();
    format!("{cut}...")
}

/// The bundle could not be written.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// A file or folder could not be written.
    #[error("cannot write the agent bundle file {}", path.display())]
    Write {
        /// The file or folder.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A target file's path is not one the bundle accepts (see [`Contents::files`]).
    #[error("the bundle file name {path:?} is not allowed")]
    BadPath {
        /// The path.
        path: String,
    },
    /// An advisory id is not a safe file name. The feeds reject such ids, so only a damaged
    /// feed cache can hold one.
    #[error(
        "advisory id {id:?} is not a safe file name; delete the data directory's feeds folder to \
         fetch it again"
    )]
    BadId {
        /// The id.
        id: String,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::value::RawValue;

    use super::*;
    use crate::inventory::FoundIn;
    use crate::inventory::Lookup;
    use crate::matching::Linked;
    use crate::matching::OsvRecord;
    use crate::matching::keep_candidates;

    fn contents<'a>(
        prompt: &'a str,
        components: &'a [Component],
        entries: &'a [Entry<'a>],
    ) -> Contents<'a> {
        Contents {
            prompt,
            components,
            entries,
            files: &[],
            settings: &[],
        }
    }

    fn advisory(source: Source, id: &str, aliases: &[&str], record: &Value) -> Advisory {
        Advisory {
            source,
            id: id.to_owned(),
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            modified: None,
            record: RawValue::from_string(record.to_string()).unwrap(),
        }
    }

    fn osv_record(versions: &[String]) -> Value {
        json!({
            "id": "GHSA-1",
            "summary": "Prototype pollution in lodash",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "4.17.21"}
                ]}],
                "versions": versions
            }]
        })
    }

    fn versions(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("1.{i}")).collect()
    }

    fn nvd_record() -> Value {
        json!({
            "id": "CVE-2",
            "descriptions": [
                {"lang": "es", "value": "No"},
                {"lang": "en", "value": "Overflow in openssl"}
            ],
            "metrics": {"cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 5.0,
                 "baseSeverity": "MEDIUM", "vectorString": "V"}},
                {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8,
                 "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}
            ]},
            "configurations": [{"operator": "AND", "nodes": [
                {"operator": "OR", "negate": false, "cpeMatch": [
                    {"vulnerable": true, "criteria": "cpe:2.3:a:openssl:openssl:*",
                     "versionEndExcluding": "3.0.8", "matchCriteriaId": "x"}
                ]},
                {"operator": "OR", "negate": false, "cpeMatch": [
                    {"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-"}
                ]}
            ]}]
        })
    }

    #[test]
    fn osv_index_line_keeps_ranges_and_short_version_lists() {
        let record = osv_record(&versions(1));
        let line = compact(&advisory(Source::Osv, "GHSA-1", &["CVE-1"], &record));
        assert_eq!(line["summary"], "Prototype pollution in lodash");
        assert_eq!(line["severity"], "HIGH");
        assert_eq!(line["aliases"], json!(["CVE-1"]));
        assert_eq!(line["source"], "osv");
        let affected = &line["affected"][0];
        assert_eq!(affected["package"]["name"], "lodash");
        assert_eq!(
            affected["versions"],
            json!(["1.0"]),
            "listed versions are affected too"
        );

        let record = osv_record(&versions(VERSIONS_LIMIT));
        let line = compact(&advisory(Source::Osv, "GHSA-1", &[], &record));
        let listed = line["affected"][0]["versions"].as_array().unwrap();
        assert_eq!(listed.len(), VERSIONS_LIMIT);

        let record = osv_record(&versions(VERSIONS_LIMIT + 1));
        let line = compact(&advisory(Source::Osv, "GHSA-1", &[], &record));
        let affected = &line["affected"][0];
        assert!(affected.get("versions").is_none());
        assert_eq!(affected["versions_count"], VERSIONS_LIMIT + 1);
        let note = affected["versions_note"].as_str().unwrap();
        assert!(note.contains("read the record"), "{note}");
    }

    #[test]
    fn nvd_index_line_keeps_structure_and_primary_score() {
        let line = compact(&advisory(Source::Nvd, "CVE-2", &[], &nvd_record()));
        assert_eq!(line["summary"], "Overflow in openssl");
        assert_eq!(line["severity"]["score"], 9.8, "NVD's primary score");
        assert_eq!(line["severity"]["severity"], "CRITICAL");
        let config = &line["affected"][0];
        assert_eq!(config["operator"], "AND");
        let first = &config["nodes"][0]["cpeMatch"][0];
        assert_eq!(first["versionEndExcluding"], "3.0.8");
        assert!(first.get("matchCriteriaId").is_none());
        let platform = &config["nodes"][1]["cpeMatch"][0];
        assert_eq!(
            platform["vulnerable"], false,
            "the platform condition stays"
        );

        let only_secondary = json!({"metrics": {"cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 5.0}}
        ]}});
        let line = compact(&advisory(Source::Nvd, "CVE-3", &[], &only_secondary));
        assert_eq!(line["severity"]["score"], 5.0);
    }

    #[test]
    fn missing_fields_become_empty() {
        let line = compact(&advisory(
            Source::Nvd,
            "CVE-3",
            &[],
            &json!({"id": "CVE-3"}),
        ));
        assert_eq!(line["summary"], "");
        assert!(line["severity"].is_null());
        assert_eq!(line["affected"], json!([]));
        let line = compact(&advisory(
            Source::Osv,
            "X-1",
            &[],
            &json!({"details": "Long"}),
        ));
        assert_eq!(line["summary"], "Long");
        assert_eq!(line["affected"], json!([]));
    }

    #[test]
    fn long_summaries_are_cut() {
        let long = "a".repeat(SUMMARY_LIMIT + 10);
        assert_eq!(truncate(&long).chars().count(), SUMMARY_LIMIT + 3);
        assert_eq!(truncate("  short  "), "short");
        let exact = "b".repeat(SUMMARY_LIMIT);
        assert_eq!(truncate(&exact), exact);
    }

    #[test]
    fn writes_every_file_and_returns_what_findings_may_name() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("bundle");
        let components = vec![Component {
            lookup: Lookup::Package("npm:lodash".parse().unwrap()),
            version: "4.17.20".into(),
            found_in: FoundIn::NpmGlobal,
        }];
        let osv = advisory(Source::Osv, "GHSA-1", &["CVE-1"], &osv_record(&[]));
        let nvd = advisory(Source::Nvd, "CVE-1", &[], &nvd_record());
        let in_range = [(0, Match::InRange("4.17.20 < fixed 4.17.21".to_owned()))].into();
        let entries = [
            Entry {
                advisory: &osv,
                components: &in_range,
            },
            Entry {
                advisory: &nvd,
                components: &BTreeMap::new(),
            },
        ];

        let known = write(&dir, &contents("Do the sweep", &components, &entries), None).unwrap();
        assert_eq!(known.components, 1);
        assert_eq!(known.advisories["GHSA-1"], [0].into());
        assert_eq!(
            known.aliases["CVE-1"],
            ["GHSA-1".to_owned()].into(),
            "kept although CVE-1 is an advisory of its own here"
        );
        assert!(known.exploited.is_none(), "no catalog");

        let read = |name: &str| fs::read_to_string(dir.join(name)).unwrap();
        assert_eq!(read("PROMPT.md"), "Do the sweep");
        assert_eq!(read("findings.schema.json"), SCHEMA);
        let inventory: Value = serde_json::from_str(read("inventory.jsonl").trim()).unwrap();
        assert_eq!(inventory["id"], "c1");
        let index = read("advisories.jsonl");
        let lines: Vec<Value> = index
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            lines[0]["components"],
            json!([{"component": "c1", "match": "in_range", "why": "4.17.20 < fixed 4.17.21"}])
        );
        assert_eq!(lines[0]["record"], "records/osv-GHSA-1.json");
        assert_eq!(
            lines[1]["record"], "records/nvd-CVE-1.json",
            "sources never share a file"
        );
        assert!(
            lines[0]["known_exploited"].is_null(),
            "unknown without a KEV catalog"
        );
        let record: Value = serde_json::from_str(&read("records/osv-GHSA-1.json")).unwrap();
        assert_eq!(record, osv_record(&[]));
    }

    #[test]
    fn out_of_range_advisories_are_left_out_counted_and_the_rest_annotated() {
        let lodash = |version: &str| Component {
            lookup: Lookup::Package("npm:lodash".parse().unwrap()),
            version: version.into(),
            found_in: FoundIn::NpmGlobal,
        };
        let components = [lodash("4.17.20"), lodash("4.17.21")];
        let mut old = osv_record(&[]);
        old["affected"][0]["ranges"][0]["events"][1]["fixed"] = json!("4.0.0");
        let records = [
            ("GHSA-1", osv_record(&[]), "CVE-1"),
            ("GHSA-2", old.clone(), "CVE-2"),
            ("GHSA-3", old, "CVE-3"),
        ];
        let mut fetched: Vec<Linked> = records
            .iter()
            .map(|(id, record, alias)| {
                let advisory = advisory(Source::Osv, id, &[alias], record);
                let parsed = OsvRecord::parse(&advisory.record);
                let package = "npm:lodash".parse().unwrap();
                let matches = (0..components.len())
                    .map(|i| (i, parsed.verdict(&package, &components[i].version)))
                    .collect();
                (advisory, matches)
            })
            .collect();
        let kev = Kev::from_ids(&["CVE-3"]);

        let dropped = keep_candidates(&mut fetched);
        assert_eq!(
            dropped, 2,
            "GHSA-2 and GHSA-3: both versions are past their fix, though CVE-3 is exploited"
        );
        let entries: Vec<Entry<'_>> = fetched
            .iter()
            .map(|(advisory, components)| Entry {
                advisory,
                components,
            })
            .collect();
        let tmp = tempfile::tempdir().unwrap();
        let contents = contents("p", &components, &entries);
        let known = write(tmp.path(), &contents, Some(&kev)).unwrap();
        assert_eq!(known.advisories["GHSA-1"], [0].into(), "4.17.21 is fixed");
        assert!(!known.advisories.contains_key("GHSA-2"));
        assert!(
            !known.advisories.contains_key("GHSA-3"),
            "in KEV, but provably out of range"
        );

        let index = fs::read_to_string(tmp.path().join("advisories.jsonl")).unwrap();
        let lines: Vec<Value> = index
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0]["components"],
            json!([{
                "component": "c1",
                "match": "in_range",
                "why": "4.17.20 >= introduced 0 and < fixed 4.17.21"
            }])
        );
    }

    #[test]
    fn known_exploited_comes_from_the_catalog() {
        let tmp = tempfile::tempdir().unwrap();
        let exploited = advisory(Source::Osv, "GHSA-1", &["CVE-1"], &osv_record(&[]));
        let other = advisory(Source::Nvd, "CVE-2", &[], &nvd_record());
        let entries = [
            Entry {
                advisory: &exploited,
                components: &BTreeMap::new(),
            },
            Entry {
                advisory: &other,
                components: &BTreeMap::new(),
            },
        ];
        let kev = Kev::from_ids(&["CVE-1"]);
        let known = write(tmp.path(), &contents("p", &[], &entries), Some(&kev)).unwrap();
        assert_eq!(known.exploited, Some(["GHSA-1".to_owned()].into()));
        let index = fs::read_to_string(tmp.path().join("advisories.jsonl")).unwrap();
        let lines: Vec<Value> = index
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[0]["known_exploited"], true);
        assert_eq!(lines[1]["known_exploited"], false);
    }

    #[test]
    fn unsafe_ids_never_name_a_path() {
        let tmp = tempfile::tempdir().unwrap();
        let evil = advisory(Source::Nvd, "../../escape", &[], &json!({}));
        let entries = [Entry {
            advisory: &evil,
            components: &BTreeMap::new(),
        }];
        let err = write(&tmp.path().join("b"), &contents("p", &[], &entries), None).unwrap_err();
        assert!(
            matches!(&err, BundleError::BadId { id } if id == "../../escape"),
            "{err:?}"
        );
        assert!(!tmp.path().join("escape.json").exists());
        assert!(!tmp.path().join("nvd-../../escape.json").exists());
    }

    #[test]
    fn target_files_stay_under_their_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let files = [
            ("github/settings.json".to_owned(), "{}".to_owned()),
            ("github/workflows/ci.yml".to_owned(), "on: push".to_owned()),
        ];
        let settings = ["rulesets".to_owned()];
        let mut with_files = contents("p", &[], &[]);
        with_files.files = &files;
        with_files.settings = &settings;
        let known = write(tmp.path(), &with_files, None).unwrap();
        let read = |name: &str| fs::read_to_string(tmp.path().join(name)).unwrap();
        assert_eq!(read("github/workflows/ci.yml"), "on: push");
        assert_eq!(
            known.files,
            [
                "github/settings.json".to_owned(),
                "github/workflows/ci.yml".to_owned()
            ]
            .into()
        );
        assert_eq!(known.settings, ["rulesets".to_owned()].into());

        for bad in [
            "PROMPT.md",
            "github",
            "github/../PROMPT.md",
            "github/.hidden",
            "github//x",
            "other/x",
        ] {
            let files = [(bad.to_owned(), "x".to_owned())];
            let mut bad_contents = contents("p", &[], &[]);
            bad_contents.files = &files;
            let err = write(&tmp.path().join("b"), &bad_contents, None).unwrap_err();
            assert!(
                matches!(&err, BundleError::BadPath { path } if path == bad),
                "{err:?}"
            );
        }
        assert_eq!(read("PROMPT.md"), "p", "never replaced");
    }

    #[test]
    fn unwritable_dir_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("file");
        fs::write(&blocker, "").unwrap();
        let err = write(&blocker.join("bundle"), &contents("p", &[], &[]), None).unwrap_err();
        assert!(
            err.to_string().contains("cannot write the agent bundle"),
            "{err}"
        );
    }
}
