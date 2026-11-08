//! Advisory feeds: OSV, NVD and the CISA Known Exploited Vulnerabilities catalog.
//!
//! The app narrows advisories to the packages and products in the inventory; the agent decides
//! which ones apply to the installed versions. So every function here takes names, never
//! versions, and returns records as the source served them, unparsed beyond the few fields
//! needed for caching and the history window.
//!
//! Records are cached under `<data dir>/feeds/` as one JSON file per OSV advisory and per NVD
//! product. A missing or unreadable cache file is fetched again, so deleting the folder is
//! always safe. Every cache file name comes from the network or the inventory and is checked
//! by [`cache_key`] first.

mod cache;
pub(crate) mod cpe;
mod http;
mod kev;
mod nvd;
mod osv;
#[cfg(test)]
pub(crate) mod test_server;

use std::cell::Cell;
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use jiff::Timestamp;
use serde_json::value::RawValue;

use crate::config::History;
use crate::feeds::cache::Cache;
use crate::feeds::http::Http;
use crate::package::Package;
use crate::paths::DataDir;

pub use crate::feeds::kev::Kev;
pub use crate::feeds::nvd::KeychainError;
pub use crate::feeds::nvd::NvdAccess;
pub use crate::feeds::nvd::ParseProductError;
pub use crate::feeds::nvd::Product;

/// Where each source is served. Tests point these at a local server.
#[derive(Debug)]
pub(crate) struct Endpoints {
    pub(crate) osv: String,
    pub(crate) nvd: String,
    pub(crate) kev: String,
}

impl Endpoints {
    fn public() -> Self {
        Self {
            osv: "https://api.osv.dev".to_owned(),
            nvd: "https://services.nvd.nist.gov".to_owned(),
            kev: concat!(
                "https://www.cisa.gov/sites/default/files/feeds/",
                "known_exploited_vulnerabilities.json"
            )
            .to_owned(),
        }
    }
}

/// Fetches and caches advisories.
///
/// Every call blocks on the network. NVD calls also sleep between requests to stay within
/// NVD's rate limit (see [`NvdAccess`]).
#[derive(Debug)]
pub struct Feeds {
    http: Http,
    endpoints: Endpoints,
    cache: Cache,
    nvd: NvdAccess,

    // NVD pacing: the minimum gap between requests, and when the last one was sent.
    nvd_interval: Duration,
    nvd_last: Cell<Option<Instant>>,
}

impl Feeds {
    /// Uses the public OSV, NVD and CISA services, caching under `data_dir`.
    pub fn new(data_dir: &DataDir, nvd: NvdAccess) -> Self {
        Self::with_endpoints(data_dir.feeds_dir(), nvd, Endpoints::public())
    }

    /// Turns NVD pacing off, so tests against a local server do not sleep.
    #[cfg(test)]
    pub(crate) fn without_pacing(mut self) -> Self {
        self.nvd_interval = Duration::ZERO;
        self
    }

    pub(crate) fn with_endpoints(dir: PathBuf, nvd: NvdAccess, endpoints: Endpoints) -> Self {
        Self {
            http: Http::new(),
            endpoints,
            cache: Cache::new(dir),
            nvd_interval: nvd_interval(&nvd),
            nvd,
            nvd_last: Cell::new(None),
        }
    }

    /// Returns every OSV advisory for `queries` in the `history` window, malicious-package
    /// reports included, in id order without duplicates.
    ///
    /// Sends a version only for queries that carry one (OS packages). Fetches only records that
    /// are new or changed since they were cached. A query matching more than 200 advisories
    /// keeps only those in `kev` (none without the catalog) and is listed in
    /// [`OsvAdvisories::crowded`]. OS advisories list their CVE as `upstream`, which is
    /// returned among the aliases.
    ///
    /// A record that cannot be fetched (a network error, an unsafe id) is reported in
    /// [`OsvAdvisories::failures`] and the rest are still returned.
    ///
    /// # Errors
    ///
    /// Fails when the id query itself fails, since then no advisory is known.
    pub fn osv(
        &self,
        queries: &[OsvQuery],
        history: History,
        kev: Option<&Kev>,
    ) -> Result<OsvAdvisories, FeedError> {
        osv::fetch(self, queries, history, kev)
    }

    /// Returns every NVD CVE whose configurations name `product` (any vendor) in the
    /// `history` window, in id order.
    ///
    /// The first call for a product fetches its full history. A later call within two hours
    /// returns the cache without a request; after that it fetches only CVEs modified since,
    /// unless the cache is older than NVD's 120-day window. A product NVD's CPE dictionary was
    /// found not to know in the last week, with nothing cached, returns no CVEs without a
    /// request.
    ///
    /// # Errors
    ///
    /// Fails on the first network, decoding, or cache read or write error. NVD answers 403 when its
    /// rate limit is exceeded; an API key raises the limit.
    pub fn nvd(&self, product: &Product, history: History) -> Result<Vec<Advisory>, FeedError> {
        nvd::fetch(self, product, history)
    }

    /// Returns whether NVD's CPE dictionary lists `product`, so a product with no CVEs can be
    /// told apart from a name NVD does not know.
    ///
    /// Asks NVD at most once per product, then every 30 days while the answer is "unknown".
    /// Paced like every NVD request.
    ///
    /// # Errors
    ///
    /// Fails on a network, decoding or cache error.
    pub(crate) fn nvd_product_known(&self, product: &Product) -> Result<bool, FeedError> {
        nvd::product_known(self, product)
    }

    /// Downloads the current CISA Known Exploited Vulnerabilities catalog.
    ///
    /// # Errors
    ///
    /// Fails on a network or decoding error.
    pub fn kev(&self) -> Result<Kev, FeedError> {
        kev::fetch(self)
    }
}

/// The result of [`Feeds::osv`]: the advisories fetched, and the records that could not be.
#[derive(Debug)]
pub struct OsvAdvisories {
    /// Advisories in the history window, in id order.
    pub advisories: Vec<OsvAdvisory>,
    /// One error per record that could not be fetched or cached.
    pub failures: Vec<FeedError>,
    /// Queries that matched so many advisories that only the known-exploited ones were kept.
    pub crowded: Vec<Crowded>,
}

/// One OSV lookup: a package, and the installed version for packages whose ecosystem is
/// [queried by version](crate::Ecosystem::queried_by_version).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OsvQuery {
    /// The package.
    pub package: Package,
    /// The version OSV is asked about, or `None` for every advisory under the name.
    pub version: Option<String>,
}

impl OsvQuery {
    /// The query for `package` installed at `version`: with the version when its ecosystem is
    /// queried by version, by name otherwise.
    pub fn new(package: Package, version: &str) -> Self {
        let version = package
            .ecosystem
            .queried_by_version()
            .then(|| version.to_owned());
        Self { package, version }
    }
}

/// A query that matched too many advisories, and how many of them were kept.
#[derive(Debug)]
pub struct Crowded {
    /// The query.
    pub query: OsvQuery,
    /// How many advisories OSV matched.
    pub matched: usize,
    /// How many were kept: those for a CVE in the KEV catalog.
    pub kept: usize,
}

/// An OSV advisory and the packages whose query returned it.
#[derive(Debug)]
pub struct OsvAdvisory {
    /// The advisory.
    pub advisory: Advisory,
    /// The queries OSV matched it to, in order.
    pub queries: Vec<OsvQuery>,
}

/// Which database an [`Advisory`] came from.
#[derive(Debug)]
pub enum Source {
    /// OSV.dev, which includes the GitHub Advisory Database and malicious-package reports.
    Osv,
    /// The NIST National Vulnerability Database.
    Nvd,
}

/// One advisory record, kept as the source served it so the agent sees every field.
#[derive(Debug)]
pub struct Advisory {
    /// Which database served it.
    pub source: Source,
    /// The source's id (`GHSA-...`, `MAL-...`, `CVE-...`).
    pub id: String,
    /// Other ids for the same issue; for OSV this usually includes the CVE.
    pub aliases: Vec<String>,
    /// When the source last changed the record, when it says.
    pub modified: Option<Timestamp>,
    /// The full record as JSON.
    pub record: Box<RawValue>,
}

impl Source {
    /// The lowercase name used in bundle and output files: `osv` or `nvd`.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Osv => "osv",
            Self::Nvd => "nvd",
        }
    }
}

impl Advisory {
    /// Returns whether the advisory or one of its aliases is in `kev`.
    pub(crate) fn is_known_exploited(&self, kev: &Kev) -> bool {
        kev.contains(&self.id) || self.aliases.iter().any(|a| kev.contains(a))
    }

    /// Returns the advisory as one line of JSON: `source` (`osv` or `nvd`), `id`,
    /// `known_exploited` (whether it is in `kev`, or `null` when the catalog could not be read),
    /// and the source's full `record`.
    pub fn to_json_line(&self, kev: Option<&Kev>) -> String {
        serde_json::json!({
            "source": self.source.name(),
            "id": self.id,
            "known_exploited": kev.map(|kev| self.is_known_exploited(kev)),
            "record": self.record,
        })
        .to_string()
    }
}

/// Keeps an advisory that was published or modified inside the history window. A record
/// modified recently matters even if it is old: NVD keeps a CVE's original `published` date
/// when it later adds the product that makes it relevant. An advisory without dates is kept:
/// dropping it could hide a real issue.
fn in_window(published: Option<Timestamp>, modified: Option<Timestamp>, history: History) -> bool {
    let History::Since(since) = history else {
        return true;
    };
    match (published, modified) {
        (None, None) => true,
        (published, modified) => published.max(modified) >= Some(since.start()),
    }
}

/// Error from a feed request.
#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    /// The request could not be sent or the connection failed.
    #[error("request to {url} failed")]
    Http {
        /// The URL requested. API keys travel in headers, so it holds none.
        url: String,
        /// The underlying error.
        #[source]
        source: Box<ureq::Error>,
    },
    /// The server answered with a status other than 2xx. Redirects count: they are not
    /// followed, so a 3xx means the endpoint moved.
    #[error("{url} answered {status}{}", colon_detail(detail))]
    Status {
        /// The URL requested.
        url: String,
        /// The HTTP status.
        status: u16,
        /// The start of the response body, which for NVD and OSV explains the refusal.
        detail: String,
    },
    /// The connection failed while the body was read.
    #[error("reading the response from {url} failed")]
    Body {
        /// The URL requested.
        url: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The decoded body is larger than the client accepts.
    #[error("response from {url} exceeds {limit} bytes")]
    TooLarge {
        /// The URL requested.
        url: String,
        /// The limit, in bytes.
        limit: u64,
    },
    /// The response was not the JSON the source documents.
    #[error("unexpected response from {url}")]
    Decode {
        /// The URL requested.
        url: String,
        /// What did not match.
        #[source]
        source: serde_json::Error,
    },
    /// The response parsed but broke the source's documented contract.
    #[error("unexpected response from {url}: {what}")]
    Unexpected {
        /// The URL requested.
        url: String,
        /// What was wrong.
        what: &'static str,
    },
    /// A cache file could not be read or written.
    #[error("cannot use feed cache {}; delete it to fetch it again", path.display())]
    Cache {
        /// The cache file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A source returned an id that cannot be a cache file name.
    #[error("refusing advisory or product id {id:?}: not a safe file name")]
    BadId {
        /// The id, as returned.
        id: String,
    },
}

/// Formats a status error's detail as `: <detail>`, or nothing when the body was empty.
fn colon_detail(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}

/// Returns `key` when it is safe as a cache file name: 1 to 128 ASCII letters, digits, `.`,
/// `-` and `_`, not starting with `.`. Advisory ids from every source fit; anything else
/// (a `/`, `..`) could escape the cache folder.
pub(crate) fn cache_key(key: &str) -> Result<&str, FeedError> {
    let ok = (1..=128).contains(&key.len())
        && !key.starts_with('.')
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if ok {
        Ok(key)
    } else {
        Err(FeedError::BadId { id: key.to_owned() })
    }
}

/// Requests NVD allows per rolling 30 seconds without an API key and with one ("Rate Limits"
/// in <https://nvd.nist.gov/developers/start-here>, which has no versioned copy; checked
/// 2026-11-05). Sweeps space their requests by these, and the settings show them.
pub(crate) const NVD_PER_30_SECONDS_ANONYMOUS: u32 = 5;
/// See [`NVD_PER_30_SECONDS_ANONYMOUS`].
pub(crate) const NVD_PER_30_SECONDS_WITH_KEY: u32 = 50;

/// The gap between NVD requests. Spacing at exactly 30 s / 5 puts six requests in one
/// inclusive 30 s window, and our clock and NVD's disagree slightly, so the gap is 10% longer.
/// The margin is arbitrary.
fn nvd_interval(access: &NvdAccess) -> Duration {
    let requests = match access {
        NvdAccess::Anonymous => NVD_PER_30_SECONDS_ANONYMOUS,
        NvdAccess::ApiKey(_) => NVD_PER_30_SECONDS_WITH_KEY,
    };
    Duration::from_secs(30) / requests * 11 / 10
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Since;

    #[test]
    fn cache_keys_reject_path_tricks() {
        for good in [
            "GHSA-35jh-r3h4-6jhm",
            "MAL-2026-1",
            "CVE-2024-1",
            "PYSEC-2021-1",
            "openssl",
        ] {
            assert_eq!(cache_key(good).unwrap(), good);
        }
        let long = "a".repeat(129);
        for bad in [
            "", ".", "..", ".hidden", "a/b", "../x", "a b", "a\nb", &long,
        ] {
            assert!(cache_key(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn history_window_keeps_undated_and_recent() {
        let since = History::Since(Since::new(jiff::civil::date(2025, 1, 31)).unwrap());
        let ts = |s: &str| Some(s.parse::<Timestamp>().unwrap());

        let old = ts("2025-01-30T23:59:59Z");
        assert!(in_window(None, None, since));
        assert!(in_window(ts("2025-01-31T00:00:00Z"), None, since));
        assert!(!in_window(old, None, since));
        assert!(!in_window(old, old, since));
        assert!(!in_window(None, old, since));
        assert!(in_window(old, ts("2025-01-31T00:00:00Z"), since));
        assert!(in_window(None, ts("2026-01-01T00:00:00Z"), since));
        assert!(in_window(ts("1999-01-01T00:00:00Z"), old, History::All));
    }

    #[test]
    fn nvd_pacing_follows_published_limits() {
        assert_eq!(
            nvd_interval(&NvdAccess::Anonymous),
            Duration::from_millis(6600)
        );
        assert_eq!(
            nvd_interval(&NvdAccess::ApiKey("k".into())),
            Duration::from_millis(660)
        );
    }
}
