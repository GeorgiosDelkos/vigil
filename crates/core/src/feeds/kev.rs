//! The CISA Known Exploited Vulnerabilities catalog: CVEs exploited in the wild.
//!
//! Catalog and schema: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>. It is
//! about 2 MB, so it is downloaded whole each time rather than cached.

use std::collections::HashSet;

use serde::Deserialize;

use crate::feeds::FeedError;
use crate::feeds::Feeds;
use crate::feeds::http::decode;

/// The CVE ids in the KEV catalog.
#[derive(Debug)]
pub struct Kev {
    cves: HashSet<String>,
}

impl Kev {
    /// A catalog of exactly `ids`, for tests elsewhere in the crate.
    #[cfg(test)]
    pub(crate) fn from_ids(ids: &[&str]) -> Self {
        Self {
            cves: ids.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    /// Returns whether `id` is a CVE in the catalog.
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.cves.contains(id)
    }
}

/// The fewest entries a catalog may have. The catalog passed 1000 entries in 2023 and had over
/// 1400 by late 2025, and CISA removes an entry only when it was added in error. A catalog far
/// below that is truncated or not the catalog, and an empty one would mark nothing exploited.
/// Set well under the real size, so the odd removal never trips it; the margin is arbitrary.
const MIN_ENTRIES: usize = 1000;

/// Downloads and checks the catalog: it must name its version, list at least [`MIN_ENTRIES`]
/// vulnerabilities, and give each a CVE id (surrounding whitespace is ignored).
pub(super) fn fetch(feeds: &Feeds) -> Result<Kev, FeedError> {
    let url = &feeds.endpoints.kev;
    let catalog: Catalog = decode(url, &feeds.http.get(url, &[], &[])?)?;
    let unexpected = |what| FeedError::Unexpected {
        url: url.clone(),
        what,
    };
    if catalog.catalog_version.trim().is_empty() {
        return Err(unexpected("the catalog has no catalogVersion"));
    }
    if catalog.vulnerabilities.len() < MIN_ENTRIES {
        return Err(unexpected(
            "the catalog lists far fewer vulnerabilities than CISA's",
        ));
    }
    let mut cves = HashSet::with_capacity(catalog.vulnerabilities.len());
    for entry in catalog.vulnerabilities {
        let id = entry.cve_id.trim();
        if !is_cve_id(id) {
            return Err(unexpected("a cveID is not a CVE id"));
        }
        cves.insert(id.to_owned());
    }
    Ok(Kev { cves })
}

/// Whether `id` is shaped as a CVE id: `CVE-`, a four-digit year, `-`, and four or more digits,
/// the syntax CVE ids have had since 2014.
fn is_cve_id(id: &str) -> bool {
    let Some((year, number)) = id
        .strip_prefix("CVE-")
        .and_then(|rest| rest.split_once('-'))
    else {
        return false;
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    year.len() == 4 && digits(year) && number.len() >= 4 && digits(number)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Catalog {
    catalog_version: String,
    vulnerabilities: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use serde_json::json;

    use super::*;
    use crate::feeds::Advisory;
    use crate::feeds::Endpoints;
    use crate::feeds::NvdAccess;
    use crate::feeds::Source;
    use crate::feeds::test_server::TestServer;

    /// A catalog of `ids`, padded with made-up CVEs to the size a real catalog has.
    fn catalog(ids: &[&str]) -> Value {
        let filler = (0..MIN_ENTRIES).map(|n| format!("CVE-1999-{n:05}"));
        let ids = ids.iter().map(|id| (*id).to_owned()).chain(filler);
        let entries: Vec<Value> = ids
            .map(|id| json!({"cveID": id, "vendorProject": "x"}))
            .collect();
        json!({"catalogVersion": "2026.11.12", "vulnerabilities": entries})
    }

    fn fetch_served(body: &Value) -> Result<Kev, FeedError> {
        let body = body.to_string();
        let server = TestServer::start(move |_| (200, body.clone()));
        let tmp = tempfile::tempdir().unwrap();
        let feeds = Feeds::with_endpoints(
            tmp.path().to_owned(),
            NvdAccess::Anonymous,
            Endpoints {
                osv: String::new(),
                nvd: String::new(),
                kev: server.url.clone(),
            },
        );
        feeds.kev()
    }

    #[test]
    fn marks_known_exploited_ids_and_aliases() {
        let kev = fetch_served(&catalog(&[" CVE-2024-0001\n", "CVE-2024-0002"])).unwrap();
        assert!(kev.contains("CVE-2024-0001"), "ids are trimmed");
        assert!(!kev.contains("CVE-2024-0003"));

        let advisory = |id: &str, aliases: &[&str]| Advisory {
            source: Source::Osv,
            id: id.to_owned(),
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            modified: None,
            record: serde_json::value::RawValue::from_string("{}".to_owned()).unwrap(),
        };
        assert!(advisory("GHSA-x", &["CVE-2024-0002"]).is_known_exploited(&kev));
        assert!(advisory("CVE-2024-0001", &[]).is_known_exploited(&kev));
        assert!(!advisory("GHSA-y", &["CVE-2024-0003"]).is_known_exploited(&kev));

        let exploited = advisory("GHSA-x", &["CVE-2024-0002"]);
        let line: Value = serde_json::from_str(&exploited.to_json_line(Some(&kev))).unwrap();
        assert_eq!(
            line,
            json!({
                "source": "osv",
                "id": "GHSA-x",
                "known_exploited": true,
                "record": {},
            })
        );
        let nvd = Advisory {
            source: Source::Nvd,
            ..advisory("CVE-2024-0003", &[])
        };
        let line: Value = serde_json::from_str(&nvd.to_json_line(Some(&kev))).unwrap();
        assert_eq!(line["source"], "nvd");
        assert_eq!(line["known_exploited"], false);

        let line: Value = serde_json::from_str(&nvd.to_json_line(None)).unwrap();
        assert!(line["known_exploited"].is_null());
    }

    #[test]
    fn a_catalog_that_is_not_cisa_s_is_refused() {
        let unexpected = |body: &Value| match fetch_served(body) {
            Err(FeedError::Unexpected { what, .. }) => what,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            unexpected(&json!({"catalogVersion": "1", "vulnerabilities": []})),
            "the catalog lists far fewer vulnerabilities than CISA's",
            "an empty catalog"
        );
        let mut short = catalog(&[]);
        short["vulnerabilities"].as_array_mut().unwrap().pop();
        assert!(unexpected(&short).contains("far fewer"), "one short");

        let mut versionless = catalog(&[]);
        versionless["catalogVersion"] = json!(" ");
        assert_eq!(
            unexpected(&versionless),
            "the catalog has no catalogVersion"
        );
        assert!(
            matches!(
                fetch_served(&json!({"vulnerabilities": []})),
                Err(FeedError::Decode { .. })
            ),
            "no catalogVersion at all"
        );

        for bad in [
            "CVE-2024-1",
            "cve-2024-0001",
            "GHSA-2024-0001",
            "CVE-24-0001",
            "CVE-2024-",
            "CVE-2024-00a1",
        ] {
            assert_eq!(
                unexpected(&catalog(&[bad])),
                "a cveID is not a CVE id",
                "{bad}"
            );
        }
        assert!(fetch_served(&catalog(&["CVE-2024-123456"])).is_ok());
        assert!(
            fetch_served(&catalog(&[])).is_ok(),
            "exactly the fewest entries a catalog may have"
        );
    }
}
