//! OSV.dev: `POST /v1/querybatch` for ids by package name, `GET /v1/vulns/{id}` for records.
//!
//! API: <https://google.github.io/osv.dev/api/>. A batch holds at most 1000 queries, and a
//! query whose result set is large comes back with a `next_page_token` to send again.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use jiff::Timestamp;
use serde::Deserialize;
use serde::Serialize;
use serde_json::value::RawValue;

use crate::config::History;
use crate::feeds::Advisory;
use crate::feeds::Crowded;
use crate::feeds::FeedError;
use crate::feeds::Feeds;
use crate::feeds::Kev;
use crate::feeds::OsvAdvisories;
use crate::feeds::OsvAdvisory;
use crate::feeds::OsvQuery;
use crate::feeds::RecordFailure;
use crate::feeds::Source;
use crate::feeds::cache_key;
use crate::feeds::http::decode;
use crate::feeds::in_window;

/// OSV's documented maximum number of queries in one `querybatch` request.
const BATCH: usize = 1000;

/// The most advisories one query may bring before only the known-exploited ones are kept
/// ([`thin_crowded`]). Arbitrary: well above any language package seen (a few dozen), and
/// small enough that an agent can read every index line of the rest.
const CROWDED: usize = 200;

pub(super) fn fetch(
    feeds: &Feeds,
    queries: &[OsvQuery],
    history: History,
    kev: Option<&Kev>,
) -> Result<OsvAdvisories, FeedError> {
    let mut ids = query_ids(feeds, queries)?;
    // querybatch's `modified` is the record's. Dropping by it before fetching, and before the
    // crowded queries are counted, relies on `modified` never being earlier than `published`:
    // the schema calls it the time the entry was last modified
    // (<https://github.com/ossf/osv-schema/blob/7e336cc6dabe/docs/schema.md#modified-field>)
    // but does not state the ordering. A record that broke it would be dropped here although
    // the window would keep it.
    ids.retain(|_, queried| {
        queried
            .modified
            .is_none_or(|modified| in_window(None, Some(modified), history))
    });
    // Without the catalog nothing is known to be exploited, so thinning would keep nothing of a
    // crowded query: every advisory stays instead, and the sweep notes the missing catalog.
    let crowded = kev.map_or_else(Vec::new, |kev| thin_crowded(&mut ids, kev));
    let mut advisories = Vec::with_capacity(ids.len());
    let mut failures = Vec::new();
    let mut stale = Vec::new();
    for (id, queried) in ids {
        let packages = || queried.queries.iter().map(|q| q.package.clone()).collect();
        // One bad record must not hide the others: keep going and report it.
        let Record {
            header,
            raw,
            stale: why,
        } = match record(feeds, &id, queried.modified) {
            Ok(fetched) => fetched,
            Err(error) => {
                failures.push(RecordFailure {
                    id,
                    packages: packages(),
                    error,
                });
                continue;
            }
        };
        if let Some(error) = why {
            stale.push(RecordFailure {
                id,
                packages: packages(),
                error,
            });
        }
        if in_window(header.published, Some(header.modified), history) {
            let mut aliases = header.aliases;
            aliases.extend(header.upstream);
            let advisory = Advisory {
                source: Source::Osv,
                id: header.id,
                aliases,
                modified: Some(header.modified),
                record: raw,
            };
            advisories.push(OsvAdvisory {
                advisory,
                queries: queried.queries.into_iter().collect(),
            });
        }
    }
    Ok(OsvAdvisories {
        advisories,
        failures,
        stale,
        crowded,
    })
}

/// Keeps, for a versioned query (an OS package) that matched more than [`CROWDED`] advisories,
/// only those for a CVE in the KEV catalog, and returns those queries. Only the kernel does
/// this in practice: Debian 12's `linux` at one version matched over 1000 advisories
/// (2026-11-06), far more than an agent can weigh, and the known-exploited ones matter first.
/// Queries by name are never thinned: their advisories are named `GHSA-...` or `RUSTSEC-...`,
/// so the CVE could not be read from the id.
///
/// A record is not fetched to learn its CVE. The CVE is read from the id: OS advisories are
/// named after it (`DEBIAN-CVE-2024-1086`, `UBUNTU-CVE-...`, `ALPINE-CVE-...`). Advisories that
/// group several CVEs under their own id (`DSA-...`, `USN-...`) are dropped for such a query.
fn thin_crowded(ids: &mut BTreeMap<String, Queried>, kev: &Kev) -> Vec<Crowded> {
    let mut counts: BTreeMap<&OsvQuery, usize> = BTreeMap::new();
    for queried in ids.values() {
        for query in &queried.queries {
            *counts.entry(query).or_default() += 1;
        }
    }
    let crowded: BTreeSet<OsvQuery> = counts
        .into_iter()
        .filter(|(query, n)| query.package.ecosystem.queried_by_version() && *n > CROWDED)
        .map(|(q, _)| q.clone())
        .collect();
    if crowded.is_empty() {
        return Vec::new();
    }

    let exploited = |id: &str| {
        let cve = id.find("CVE-").map(|at| &id[at..]);
        cve.is_some_and(|cve| kev.contains(cve))
    };
    let mut report: BTreeMap<OsvQuery, Crowded> = BTreeMap::new();
    ids.retain(|id, queried| {
        let keep = exploited(id);
        queried.queries.retain(|query| {
            if !crowded.contains(query) {
                return true;
            }
            let entry = report.entry(query.clone()).or_insert_with(|| Crowded {
                query: query.clone(),
                matched: 0,
                kept: 0,
            });
            entry.matched += 1;
            entry.kept += usize::from(keep);
            keep
        });
        !queried.queries.is_empty()
    });
    report.into_values().collect()
}

/// What querybatch said about one advisory: its latest `modified` time and the queries that
/// returned it.
#[derive(Debug, Default)]
struct Queried {
    modified: Option<Timestamp>,
    queries: BTreeSet<OsvQuery>,
}

/// Returns every advisory id for `queries`, with the queries each was returned for. That
/// link is what OSV matched, so it holds even when a record spells a name differently from
/// the lockfile (`Django` and `django`).
fn query_ids(feeds: &Feeds, queries: &[OsvQuery]) -> Result<BTreeMap<String, Queried>, FeedError> {
    let url = format!("{}/v1/querybatch", feeds.endpoints.osv);
    let unique: BTreeSet<&OsvQuery> = queries.iter().collect();
    let mut pending: Vec<(&OsvQuery, Option<String>)> =
        unique.into_iter().map(|q| (q, None)).collect();
    let mut ids = BTreeMap::new();
    let mut seen_tokens = BTreeSet::new();

    while !pending.is_empty() {
        let batch: Vec<_> = pending.drain(..pending.len().min(BATCH)).collect();
        let request = BatchRequest {
            queries: batch
                .iter()
                .map(|(query, page_token)| Query {
                    package: QueryPackage {
                        name: &query.package.name,
                        ecosystem: query.package.ecosystem.osv_name(),
                    },
                    version: query.version.as_deref(),
                    page_token: page_token.as_deref(),
                })
                .collect(),
        };
        let response: BatchResponse = decode(&url, &feeds.http.post_json(&url, &request)?)?;
        if response.results.len() != batch.len() {
            return Err(FeedError::Unexpected {
                url,
                what: "querybatch returned a different number of results than queries",
            });
        }

        for ((query, _), result) in batch.into_iter().zip(response.results) {
            for vuln in result.vulns {
                let queried: &mut Queried = ids.entry(vuln.id).or_default();
                queried.modified = queried.modified.max(vuln.modified);
                queried.queries.insert(query.clone());
            }
            // A repeated token would loop forever.
            match result.next_page_token {
                Some(token) if token.is_empty() => {}
                Some(token) if !seen_tokens.insert((query, token.clone())) => {
                    return Err(FeedError::Unexpected {
                        url,
                        what: "querybatch repeated a page token",
                    });
                }
                Some(token) => pending.push((query, Some(token))),
                None => {}
            }
        }
    }
    Ok(ids)
}

/// One OSV record, and why it is the cached copy when OSV could not be asked for a newer one.
#[derive(Debug)]
struct Record {
    header: Header,
    raw: Box<RawValue>,
    stale: Option<FeedError>,
}

/// Returns the record for `id`, from the cache unless OSV says it changed since. When asking
/// fails, a cached copy is returned with the error as `stale`: an older record is closer to the
/// truth than none, and dropping it would hide the advisory for that sweep.
fn record(feeds: &Feeds, id: &str, modified: Option<Timestamp>) -> Result<Record, FeedError> {
    let key = cache_key(id)?;
    let cached: Option<Box<RawValue>> = feeds.cache.read("osv", key)?;
    let cached = cached.and_then(|raw| {
        let header = serde_json::from_str::<Header>(raw.get()).ok()?;
        (header.id == id).then_some((header, raw))
    });
    let cached = match cached {
        Some((header, raw)) if modified.is_some_and(|m| header.modified >= m) => {
            return Ok(Record {
                header,
                raw,
                stale: None,
            });
        }
        other => other,
    };

    let url = format!("{}/v1/vulns/{key}", feeds.endpoints.osv);
    match request_record(feeds, &url, id) {
        Ok((header, raw)) => {
            feeds.cache.write("osv", key, &raw)?;
            Ok(Record {
                header,
                raw,
                stale: None,
            })
        }
        Err(error) => match cached {
            Some((header, raw)) => Ok(Record {
                header,
                raw,
                stale: Some(error),
            }),
            None => Err(error),
        },
    }
}

/// GETs the record for `id` from `url` and checks that it is that record.
fn request_record(
    feeds: &Feeds,
    url: &str,
    id: &str,
) -> Result<(Header, Box<RawValue>), FeedError> {
    let text = feeds.http.get(url, &[], &[])?;
    let raw: Box<RawValue> = decode(url, &text)?;
    let header: Header = decode(url, raw.get())?;
    if header.id != id {
        return Err(FeedError::Unexpected {
            url: url.to_owned(),
            what: "the record's id differs from the id requested",
        });
    }
    Ok((header, raw))
}

#[derive(Debug, Serialize)]
struct BatchRequest<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Debug, Serialize)]
struct Query<'a> {
    package: QueryPackage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct QueryPackage<'a> {
    name: &'a str,
    ecosystem: Cow<'static, str>,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

/// OSV omits `vulns` for a package with no advisories.
#[derive(Debug, Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
    next_page_token: Option<String>,
}

/// OSV documents `modified` on every result; without it the cached record is fetched again.
#[derive(Debug, Deserialize)]
struct VulnRef {
    id: String,
    modified: Option<Timestamp>,
}

/// The fields of an OSV record this module reads; the rest stays in the raw record.
#[derive(Debug, Deserialize)]
struct Header {
    id: String,
    modified: Timestamp,
    published: Option<Timestamp>,
    #[serde(default)]
    aliases: Vec<String>,
    /// The upstream ids an OS advisory tracks (`DEBIAN-CVE-2024-1086` has `CVE-2024-1086`
    /// here, and no aliases). They are kept as aliases, so the KEV flag and a finding's CVE
    /// resolve to the OS record.
    #[serde(default)]
    upstream: Vec<String>,
}

#[cfg(test)]
mod tests {
    use crate::config::Since;
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;
    use crate::feeds::Endpoints;
    use crate::feeds::NvdAccess;
    use crate::feeds::test_server::Request;
    use crate::feeds::test_server::TestServer;
    use crate::package::Package;

    fn feeds(server: &TestServer, dir: &std::path::Path) -> Feeds {
        Feeds::with_endpoints(
            dir.to_owned(),
            NvdAccess::Anonymous,
            Endpoints {
                osv: server.url.clone(),
                nvd: String::new(),
                kev: String::new(),
            },
        )
    }

    fn record_json(id: &str, modified: &str, published: &str) -> String {
        serde_json::json!({
            "id": id,
            "modified": modified,
            "published": published,
            "aliases": [format!("CVE-{id}")],
            "summary": "s",
        })
        .to_string()
    }

    fn pkg(text: &str) -> OsvQuery {
        OsvQuery {
            package: text.parse().unwrap(),
            version: None,
        }
    }

    /// Answers querybatch with `ids` for every query, and each record with `modified`.
    fn osv_server(modified: Arc<Mutex<String>>) -> TestServer {
        TestServer::start(move |request: &Request| match request.path() {
            "/v1/querybatch" => {
                let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
                let count = body["queries"].as_array().unwrap().len();
                let m = modified.lock().unwrap().clone();
                let result = serde_json::json!({"vulns": [
                    {"id": "A-1", "modified": m},
                    {"id": "B-2", "modified": m},
                ]})
                .to_string();
                let results = vec![result; count].join(",");
                (200, format!(r#"{{"results":[{results}]}}"#))
            }
            path => {
                let id = path.trim_start_matches("/v1/vulns/");
                let m = modified.lock().unwrap().clone();
                let published = if id == "A-1" {
                    "2020-01-01T00:00:00Z"
                } else {
                    "2025-06-01T00:00:00Z"
                };
                (200, record_json(id, &m, published))
            }
        })
    }

    #[test]
    fn fetches_records_once_until_modified() {
        let modified = Arc::new(Mutex::new("2026-01-01T00:00:00Z".to_owned()));
        let server = osv_server(Arc::clone(&modified));
        let tmp = tempfile::tempdir().unwrap();
        let feeds = feeds(&server, tmp.path());
        let packages = [pkg("npm:lodash"), pkg("crates.io:serde"), pkg("npm:lodash")];

        let advisories = feeds.osv(&packages, History::All, None).unwrap().advisories;
        let ids: Vec<_> = advisories.iter().map(|a| a.advisory.id.as_str()).collect();
        assert_eq!(ids, ["A-1", "B-2"]);
        assert_eq!(advisories[0].advisory.aliases, ["CVE-A-1"]);
        assert!(matches!(advisories[0].advisory.source, Source::Osv));
        assert!(
            advisories[0]
                .advisory
                .record
                .get()
                .contains(r#""summary":"s""#)
        );
        let matched = &advisories[0].queries;
        assert_eq!(matched.len(), 2, "each queried package once: {matched:?}");
        assert!(matched.contains(&pkg("npm:lodash")) && matched.contains(&pkg("crates.io:serde")));

        let requests = server.requests();
        let batch: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(
            batch,
            serde_json::json!({"queries": [
                {"package": {"name": "serde", "ecosystem": "crates.io"}},
                {"package": {"name": "lodash", "ecosystem": "npm"}},
            ]})
        );
        assert_eq!(requests.len(), 3, "one batch and two records");

        feeds.osv(&packages, History::All, None).unwrap();
        assert_eq!(server.requests().len(), 4, "records came from the cache");

        *modified.lock().unwrap() = "2026-02-01T00:00:00Z".to_owned();
        feeds.osv(&packages, History::All, None).unwrap();
        assert_eq!(server.requests().len(), 7, "both records changed upstream");
    }

    /// A-1 was published in 2020 and B-2 in 2025; both were modified 2026-01-01.
    #[test]
    fn history_window_uses_published_or_modified() {
        let server = osv_server(Arc::new(Mutex::new("2026-01-01T00:00:00Z".to_owned())));
        let tmp = tempfile::tempdir().unwrap();
        let feeds = feeds(&server, tmp.path());
        let ids = |year, month| -> Vec<String> {
            let since = History::Since(Since::new(jiff::civil::date(year, month, 1)).unwrap());
            let advisories = feeds
                .osv(&[pkg("npm:lodash")], since, None)
                .unwrap()
                .advisories;
            advisories.into_iter().map(|a| a.advisory.id).collect()
        };

        assert_eq!(
            ids(2024, 1),
            ["A-1", "B-2"],
            "an old advisory modified recently stays"
        );
        assert!(ids(2026, 6).is_empty(), "neither date is in the window");
    }

    #[test]
    fn repeated_page_token_is_an_error_not_a_loop() {
        let server = TestServer::start(|_: &Request| {
            let result = serde_json::json!({"vulns": [], "next_page_token": "same"});
            (200, serde_json::json!({ "results": [result] }).to_string())
        });
        let tmp = tempfile::tempdir().unwrap();
        let err = feeds(&server, tmp.path())
            .osv(&[pkg("npm:a")], History::All, None)
            .unwrap_err();
        assert!(matches!(err, FeedError::Unexpected { .. }), "{err:?}");
        assert_eq!(server.requests().len(), 2);
    }

    #[test]
    fn empty_page_token_ends_paging() {
        let server = TestServer::start(|_: &Request| {
            let result = serde_json::json!({"vulns": [], "next_page_token": ""});
            (200, serde_json::json!({ "results": [result] }).to_string())
        });
        let tmp = tempfile::tempdir().unwrap();
        let advisories = feeds(&server, tmp.path())
            .osv(&[pkg("npm:a")], History::All, None)
            .unwrap()
            .advisories;
        assert!(advisories.is_empty());
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn follows_page_tokens_and_splits_batches() {
        let server = TestServer::start(|request: &Request| {
            if request.path() != "/v1/querybatch" {
                let id = request.path().trim_start_matches("/v1/vulns/");
                return (
                    200,
                    record_json(id, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
                );
            }
            let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
            let results: Vec<_> = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(
                    |q| match (q["package"]["name"].as_str(), q.get("page_token")) {
                        (Some("p0"), None) => serde_json::json!({
                            "vulns": [{"id": "P-1", "modified": "2026-01-01T00:00:00Z"}],
                            "next_page_token": "t1",
                        }),
                        (Some("p0"), Some(token)) => {
                            assert_eq!(token, "t1");
                            serde_json::json!({
                                "vulns": [{"id": "P-2", "modified": "2026-01-01T00:00:00Z"}]
                            })
                        }
                        _ => serde_json::json!({}),
                    },
                )
                .collect();
            (200, serde_json::json!({ "results": results }).to_string())
        });
        let tmp = tempfile::tempdir().unwrap();
        let packages: Vec<_> = (0..=BATCH).map(|i| pkg(&format!("npm:p{i}"))).collect();

        let advisories = feeds(&server, tmp.path())
            .osv(&packages, History::All, None)
            .unwrap()
            .advisories;
        let ids: Vec<_> = advisories.iter().map(|a| a.advisory.id.as_str()).collect();
        assert_eq!(ids, ["P-1", "P-2"]);

        let batch_sizes: Vec<_> = server
            .requests()
            .iter()
            .filter(|r| r.path() == "/v1/querybatch")
            .map(|r| {
                let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
                body["queries"].as_array().unwrap().len()
            })
            .collect();
        // The leftover query and the page-token retry share the second batch.
        assert_eq!(batch_sizes, [BATCH, 2]);
    }

    /// `linux` at 6.1 matches one more than [`CROWDED`] advisories, two of them for CVEs in
    /// KEV; `openssl` matches one advisory also matched by `linux`, and one of its own.
    fn crowded_server() -> TestServer {
        TestServer::start(|request: &Request| {
            if request.path() != "/v1/querybatch" {
                let id = request.path().trim_start_matches("/v1/vulns/");
                let record = serde_json::json!({
                    "id": id,
                    "modified": "2026-01-01T00:00:00Z",
                    "upstream": [id.trim_start_matches("DEBIAN-")],
                });
                return (200, record.to_string());
            }
            let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
            let vuln =
                |id: String| serde_json::json!({"id": id, "modified": "2026-01-01T00:00:00Z"});
            let results: Vec<_> = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| {
                    assert_eq!(q["package"]["ecosystem"], "Debian:12");
                    match (q["package"]["name"].as_str(), q["version"].as_str()) {
                        (Some("linux"), Some("6.1")) => {
                            let ids = (0..=CROWDED).map(|n| format!("DEBIAN-CVE-2024-{n}"));
                            let mut vulns: Vec<_> = ids.map(vuln).collect();
                            vulns.push(vuln("DSA-1".into()));
                            serde_json::json!({ "vulns": vulns })
                        }
                        (Some("openssl"), Some("3.0")) => serde_json::json!({"vulns": [
                            vuln("DEBIAN-CVE-2024-5".into()),
                            vuln("DEBIAN-CVE-2025-1".into()),
                        ]}),
                        other => panic!("unexpected query {other:?}"),
                    }
                })
                .collect();
            (200, serde_json::json!({ "results": results }).to_string())
        })
    }

    #[test]
    fn os_packages_are_queried_by_version_and_crowded_ones_keep_kev_only() {
        let server = crowded_server();
        let tmp = tempfile::tempdir().unwrap();
        let debian = |name: &str, version: &str| {
            let package = Package {
                ecosystem: crate::package::Ecosystem::Debian { release: 12 },
                name: name.to_owned(),
            };
            OsvQuery::new(package, version)
        };
        let queries = [debian("linux", "6.1"), debian("openssl", "3.0")];
        assert_eq!(queries[0].version.as_deref(), Some("6.1"));
        let kev = Kev::from_ids(&["CVE-2024-7", "CVE-2024-200", "CVE-2025-1"]);

        let osv = feeds(&server, tmp.path())
            .osv(&queries, History::All, Some(&kev))
            .unwrap();

        let found: Vec<(&str, usize)> = osv
            .advisories
            .iter()
            .map(|a| (a.advisory.id.as_str(), a.queries.len()))
            .collect();
        assert_eq!(
            found,
            [
                ("DEBIAN-CVE-2024-200", 1),
                ("DEBIAN-CVE-2024-5", 1),
                ("DEBIAN-CVE-2024-7", 1),
                ("DEBIAN-CVE-2025-1", 1),
            ],
            "linux keeps its KEV CVEs; openssl keeps both of its own, and the one it shares \
             with linux is linked to openssl only"
        );
        let shared = &osv.advisories[1];
        assert_eq!(shared.queries, [queries[1].clone()]);
        assert_eq!(
            shared.advisory.aliases,
            ["CVE-2024-5"],
            "upstream ids become aliases"
        );
        assert!(!shared.advisory.is_known_exploited(&kev));
        assert!(osv.advisories[0].advisory.is_known_exploited(&kev));

        let [crowded] = &osv.crowded[..] else {
            panic!("{:?}", osv.crowded)
        };
        assert_eq!(crowded.query, queries[0]);
        assert_eq!(crowded.matched, CROWDED + 2);
        assert_eq!(crowded.kept, 2);
        let records = server
            .requests()
            .iter()
            .filter(|r| r.path() != "/v1/querybatch")
            .count();
        assert_eq!(records, 4, "dropped advisories are never fetched");

        let without_kev = feeds(&server, tmp.path())
            .osv(&queries[..1], History::All, None)
            .unwrap();
        assert_eq!(
            without_kev.advisories.len(),
            CROWDED + 2,
            "nothing is known to be exploited, so nothing is thinned"
        );
        assert!(without_kev.crowded.is_empty());
    }

    #[test]
    fn records_modified_before_the_window_are_not_fetched() {
        let server = osv_server(Arc::new(Mutex::new("2026-01-01T00:00:00Z".to_owned())));
        let tmp = tempfile::tempdir().unwrap();
        let since = History::Since(Since::new(jiff::civil::date(2026, 2, 1)).unwrap());
        let osv = feeds(&server, tmp.path())
            .osv(&[pkg("npm:lodash")], since, None)
            .unwrap();
        assert!(osv.advisories.is_empty());
        assert_eq!(server.requests().len(), 1, "only the batch query");
    }

    #[test]
    fn name_queries_are_never_thinned() {
        let mut ids: BTreeMap<String, Queried> = BTreeMap::new();
        let query = pkg("npm:a");
        for n in 0..=CROWDED {
            let queried = ids.entry(format!("GHSA-{n}")).or_default();
            queried.queries.insert(query.clone());
        }
        assert!(thin_crowded(&mut ids, &Kev::from_ids(&[])).is_empty());
        assert_eq!(ids.len(), CROWDED + 1);
    }

    #[test]
    fn a_query_at_the_crowded_limit_keeps_everything() {
        let mut ids: BTreeMap<String, Queried> = BTreeMap::new();
        let package = Package {
            ecosystem: crate::package::Ecosystem::Debian { release: 12 },
            name: "linux".to_owned(),
        };
        let query = OsvQuery::new(package, "6.1");
        for n in 0..CROWDED {
            let queried = ids.entry(format!("GHSA-{n}")).or_default();
            queried.queries.insert(query.clone());
        }
        assert!(thin_crowded(&mut ids, &Kev::from_ids(&[])).is_empty());
        assert_eq!(ids.len(), CROWDED);
    }

    #[test]
    fn rejects_short_batch_responses_and_unsafe_ids() {
        let server = TestServer::start(|request: &Request| {
            let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
            if body["queries"].as_array().unwrap().len() == 2 {
                (200, r#"{"results":[{}]}"#.to_owned())
            } else {
                let unsafe_ref = r#"{"id":"../x","modified":"2026-01-01T00:00:00Z"}"#;
                (
                    200,
                    format!(r#"{{"results":[{{"vulns":[{unsafe_ref}]}}]}}"#),
                )
            }
        });
        let tmp = tempfile::tempdir().unwrap();
        let feeds = feeds(&server, tmp.path());

        let err = feeds
            .osv(&[pkg("npm:a"), pkg("npm:b")], History::All, None)
            .unwrap_err();
        assert!(matches!(err, FeedError::Unexpected { .. }), "{err:?}");

        let osv = feeds.osv(&[pkg("npm:a")], History::All, None).unwrap();
        assert!(osv.advisories.is_empty());
        assert!(
            matches!(
                &osv.failures[..],
                [RecordFailure {
                    error: FeedError::BadId { .. },
                    ..
                }]
            ),
            "{:?}",
            osv.failures
        );
    }

    /// One querybatch result for `A-1`, with or without a `modified` time.
    fn single_ref_server(modified: Option<&'static str>) -> TestServer {
        TestServer::start(move |request: &Request| {
            if request.path() == "/v1/querybatch" {
                let vuln = match modified {
                    Some(m) => serde_json::json!({"id": "A-1", "modified": m}),
                    None => serde_json::json!({"id": "A-1"}),
                };
                let body = serde_json::json!({"results": [{"vulns": [vuln]}]});
                (200, body.to_string())
            } else {
                let record = record_json("A-1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
                (200, record)
            }
        })
    }

    #[test]
    fn cached_file_with_other_id_is_fetched_again() {
        let server = single_ref_server(Some("2026-01-01T00:00:00Z"));
        let tmp = tempfile::tempdir().unwrap();
        let wrong = record_json("Z-9", "2099-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
        std::fs::create_dir_all(tmp.path().join("osv")).unwrap();
        std::fs::write(tmp.path().join("osv/A-1.json"), wrong).unwrap();

        let advisories = feeds(&server, tmp.path())
            .osv(&[pkg("npm:a")], History::All, None)
            .unwrap()
            .advisories;
        assert_eq!(advisories[0].advisory.id, "A-1");
        assert_eq!(server.requests().len(), 2, "the record was fetched");
    }

    #[test]
    fn missing_modified_always_refetches() {
        let server = single_ref_server(None);
        let tmp = tempfile::tempdir().unwrap();
        let feeds = feeds(&server, tmp.path());
        feeds.osv(&[pkg("npm:a")], History::All, None).unwrap();
        feeds.osv(&[pkg("npm:a")], History::All, None).unwrap();
        assert_eq!(
            server.requests().len(),
            4,
            "two batches and two record fetches"
        );
    }

    #[test]
    fn rejects_record_with_other_id() {
        let server = TestServer::start(|request: &Request| {
            if request.path() == "/v1/querybatch" {
                let r = r#"{"vulns":[{"id":"A-1","modified":"2026-01-01T00:00:00Z"}]}"#;
                (200, format!(r#"{{"results":[{r}]}}"#))
            } else {
                (
                    200,
                    record_json("Z-9", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
                )
            }
        });
        let tmp = tempfile::tempdir().unwrap();
        let osv = feeds(&server, tmp.path())
            .osv(&[pkg("npm:a")], History::All, None)
            .unwrap();
        assert!(osv.advisories.is_empty());
        assert!(
            matches!(
                &osv.failures[..],
                [RecordFailure {
                    error: FeedError::Unexpected { .. },
                    ..
                }]
            ),
            "{:?}",
            osv.failures
        );
        assert!(!tmp.path().join("osv/A-1.json").exists());
    }

    #[test]
    fn one_failing_record_does_not_hide_the_others() {
        let server = TestServer::start(|request: &Request| match request.path() {
            "/v1/querybatch" => {
                let vulns = serde_json::json!([
                    {"id": "A-1", "modified": "2026-01-01T00:00:00Z"},
                    {"id": "B-2", "modified": "2026-01-01T00:00:00Z"},
                ]);
                let body = serde_json::json!({"results": [{"vulns": vulns}]});
                (200, body.to_string())
            }
            "/v1/vulns/A-1" => (404, "not found".to_owned()),
            _ => (
                200,
                record_json("B-2", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            ),
        });
        let tmp = tempfile::tempdir().unwrap();
        let osv = feeds(&server, tmp.path())
            .osv(&[pkg("npm:a")], History::All, None)
            .unwrap();
        let ids: Vec<_> = osv
            .advisories
            .iter()
            .map(|a| a.advisory.id.as_str())
            .collect();
        assert_eq!(ids, ["B-2"]);
        assert!(
            matches!(
                &osv.failures[..],
                [RecordFailure {
                    error: FeedError::Status { status: 404, .. },
                    ..
                }]
            ),
            "{:?}",
            osv.failures
        );
    }

    #[test]
    fn a_record_osv_cannot_send_again_comes_from_the_cache() {
        let modified = Arc::new(Mutex::new("2026-01-01T00:00:00Z".to_owned()));
        let down = Arc::new(Mutex::new(false));
        let server = {
            let (modified, down) = (Arc::clone(&modified), Arc::clone(&down));
            TestServer::start(move |request: &Request| {
                let m = modified.lock().unwrap().clone();
                match request.path() {
                    "/v1/querybatch" => {
                        let vulns = serde_json::json!([{"id": "A-1", "modified": m}]);
                        let body = serde_json::json!({"results": [{"vulns": vulns}]});
                        (200, body.to_string())
                    }
                    _ if *down.lock().unwrap() => (503, "busy".to_owned()),
                    _ => (200, record_json("A-1", &m, "2026-01-01T00:00:00Z")),
                }
            })
        };
        let tmp = tempfile::tempdir().unwrap();
        let feeds_of = |dir: &std::path::Path| feeds(&server, dir);
        let fresh = feeds_of(tmp.path())
            .osv(&[pkg("npm:a")], History::All, None)
            .unwrap();
        assert!(fresh.stale.is_empty() && fresh.failures.is_empty());

        // OSV says the record changed, then fails to send it.
        *modified.lock().unwrap() = "2026-02-01T00:00:00Z".to_owned();
        *down.lock().unwrap() = true;
        let osv = feeds_of(tmp.path())
            .osv(&[pkg("npm:a")], History::All, None)
            .unwrap();
        let [cached] = &osv.advisories[..] else {
            panic!("{:?}", osv.advisories)
        };
        assert_eq!(
            cached.advisory.modified,
            "2026-01-01T00:00:00Z".parse().ok()
        );
        assert!(osv.failures.is_empty(), "{:?}", osv.failures);
        let [stale] = &osv.stale[..] else {
            panic!("{:?}", osv.stale)
        };
        assert_eq!(stale.id, "A-1");
        assert_eq!(
            stale.packages,
            [pkg("npm:a").package],
            "the query that returned it"
        );
        assert!(
            matches!(stale.error, FeedError::Status { status: 503, .. }),
            "{:?}",
            stale.error
        );

        let empty = tempfile::tempdir().unwrap();
        let uncached = feeds_of(empty.path())
            .osv(&[pkg("npm:a")], History::All, None)
            .unwrap();
        assert!(uncached.advisories.is_empty() && uncached.stale.is_empty());
        assert!(
            matches!(&uncached.failures[..], [RecordFailure { id, .. }] if id == "A-1"),
            "nothing cached, so it is missing"
        );
    }

    #[test]
    fn no_packages_makes_no_requests() {
        let server = TestServer::start(|_| (500, String::new()));
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            feeds(&server, tmp.path())
                .osv(&[], History::All, None)
                .unwrap()
                .advisories
                .is_empty()
        );
        assert!(server.requests().is_empty());
    }
}
