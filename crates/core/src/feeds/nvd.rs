//! NVD CVE API 2.0, queried per product with `virtualMatchString=cpe:2.3:*:<vendor>:<product>`,
//! where `<vendor>` is `*` for a product given without one.
//!
//! API: <https://nvd.nist.gov/developers/vulnerabilities>. Each product's CVEs are cached in
//! one file with the time the last fetch's coverage ended. A cache under [`FRESH`] old is used
//! without asking; after that a fetch asks only for CVEs modified since then, which NVD allows
//! for windows of at most 120 days; an older cache is fetched in full again. A product NVD's
//! CPE dictionary does not know, with no cached CVEs, is not asked for [`UNKNOWN_SKIP`].
//!
//! Entries are never removed by a delta: a CVE whose configurations no longer name the
//! product, or that NVD rejected, stays cached until the next full fetch. That errs towards
//! showing the agent too much, which it can dismiss, rather than too little.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write as _;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::str::FromStr;
use std::thread;
use std::time::Instant;

use jiff::SignedDuration;
use jiff::Timestamp;
use serde::Deserialize;
use serde::Serialize;
use serde_json::value::RawValue;

use crate::config::History;
use crate::feeds::Advisory;
use crate::feeds::FeedError;
use crate::feeds::Feeds;
use crate::feeds::Source;
use crate::feeds::cache_key;
use crate::feeds::http::decode;
use crate::feeds::in_window;
use crate::paths::BUNDLE_ID;

/// NVD's maximum `lastModStartDate`..`lastModEndDate` range, in days.
const WINDOW_DAYS: i64 = 120;

/// The same limit as a duration.
const MAX_DELTA: SignedDuration = SignedDuration::from_hours(24 * WINDOW_DAYS);

/// How long a product's cached CVEs are used without asking NVD for changes. Without an API
/// key each request is paced to 6.6 s, so a sweep repeated within hours of the last (108
/// products on one Mac, 2026-11-08) spent 11 minutes on requests that found nothing new.
/// Two hours is arbitrary: CVEs change over days, and a sweep a day apart still asks.
const FRESH: SignedDuration = SignedDuration::from_hours(2);

/// How long a product NVD's CPE dictionary does not know is not asked for CVEs. Shorter than
/// [`UNKNOWN_PRODUCT_RECHECK`] on purpose: NVD tends to add a product's CPE name when it
/// analyses the product's first CVE, which is the one CVE that matters most, so the skip ends
/// within a week and the CVE query runs again even while the dictionary answer is trusted.
/// A week is arbitrary.
const UNKNOWN_SKIP: SignedDuration = SignedDuration::from_hours(24 * 7);

/// CVEs per page. NVD allows up to 2000; 500 keeps each response a few MB. Arbitrary.
const PAGE: usize = 500;

/// The Keychain item holding an NVD API key, set with
/// `security add-generic-password -s io.github.georgiosdelkos.vigil -a nvd-api-key -w <key>`.
const KEYCHAIN_SERVICE: &str = BUNDLE_ID;
const KEYCHAIN_ACCOUNT: &str = "nvd-api-key";

/// `security` exits with 44 (`errSecItemNotFound`) when the item does not exist.
const KEYCHAIN_NOT_FOUND: i32 = 44;

/// How requests to NVD authenticate, which sets the rate limit they are paced to.
pub enum NvdAccess {
    /// No key: 5 requests per 30 seconds, paced one every 6.6 s.
    Anonymous,
    /// An NVD API key, sent in the `apiKey` header: 50 requests per 30 seconds, one every 0.66 s.
    ApiKey(String),
}

impl NvdAccess {
    /// Reads the API key from the login Keychain, falling back to [`NvdAccess::Anonymous`]
    /// when none is stored.
    ///
    /// Runs `/usr/bin/security`, which may prompt the user to allow access.
    ///
    /// # Errors
    ///
    /// Fails when `security` cannot run or exits with an error other than "not found".
    pub fn from_keychain() -> Result<Self, KeychainError> {
        let output = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", KEYCHAIN_SERVICE])
            .args(["-a", KEYCHAIN_ACCOUNT, "-w"])
            .output()
            .map_err(KeychainError::Run)?;
        from_security_output(output.status.code(), &output.stdout)
    }

    /// Whether an API key is stored in the Keychain. Asks without `-w`, so the key itself is
    /// never read; any failure counts as no key.
    pub(crate) fn has_keychain_key() -> bool {
        Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", KEYCHAIN_SERVICE])
            .args(["-a", KEYCHAIN_ACCOUNT])
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Stores `key` as the NVD API key in the login Keychain, replacing any earlier one.
    ///
    /// Through `/usr/bin/security`, the same program [`NvdAccess::from_keychain`] reads with, so
    /// the item's access list trusts the reader and a sweep is not prompted. The command goes
    /// to `security -i` on stdin: `security add-generic-password -w <key>` as arguments would
    /// put the key on a command line other processes can read.
    ///
    /// # Errors
    ///
    /// Fails when the key is not an NVD key (letters, digits and dashes), or the Keychain
    /// refuses it.
    pub fn save_to_keychain(key: &str) -> Result<(), KeychainError> {
        let script = keychain_script(key).ok_or(KeychainError::NotAKey)?;
        let mut child = Command::new("/usr/bin/security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(KeychainError::Run)?;
        child
            .stdin
            .take()
            .expect("stdin was piped above")
            .write_all(script.as_bytes())
            .map_err(KeychainError::Run)?;
        let output = child.wait_with_output().map_err(KeychainError::Run)?;
        saved(&output)
    }
}

/// Whether `security -i` stored the key. It exits 0 even when the command fails, and then
/// prints the error or its usage on stderr (observed on macOS 26 with a scratch keychain), so
/// any stderr is a failure. The text is not shown, since it could quote the command and with
/// it the key.
fn saved(output: &Output) -> Result<(), KeychainError> {
    match (output.status.success(), output.stderr.is_empty()) {
        (true, true) => Ok(()),
        (true, false) => Err(KeychainError::Save("security reported an error".to_owned())),
        (false, _) => Err(KeychainError::Save("security failed".to_owned())),
    }
}

/// The `security -i` command that stores `key`, or `None` when `key` is not an NVD key. NVD's
/// keys are UUIDs; accepting only letters, digits and inner dashes means the key needs no
/// quoting and cannot end the command or start an option.
fn keychain_script(key: &str) -> Option<String> {
    let key = key.trim();
    // 128 is arbitrary: NVD keys are 36 characters, and the bound only keeps out what is
    // plainly not a key.
    let plain = (1..=128).contains(&key.len())
        && !key.starts_with('-')
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    plain.then(|| {
        format!("add-generic-password -U -s {KEYCHAIN_SERVICE} -a {KEYCHAIN_ACCOUNT} -w {key}\n")
    })
}

/// The key is a secret: it never appears in `Debug` output or logs.
impl fmt::Debug for NvdAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Anonymous"),
            Self::ApiKey(_) => f.write_str("ApiKey(..)"),
        }
    }
}

fn from_security_output(code: Option<i32>, stdout: &[u8]) -> Result<NvdAccess, KeychainError> {
    match code {
        Some(0) => {
            let key = String::from_utf8_lossy(stdout).trim().to_owned();
            if key.is_empty() {
                Ok(NvdAccess::Anonymous)
            } else {
                Ok(NvdAccess::ApiKey(key))
            }
        }
        Some(KEYCHAIN_NOT_FOUND) => Ok(NvdAccess::Anonymous),
        Some(code) => Err(KeychainError::Status(code)),
        None => Err(KeychainError::Signal),
    }
}

/// Error from reading or saving the NVD key in the Keychain.
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    /// `/usr/bin/security` could not be started.
    #[error("cannot run /usr/bin/security")]
    Run(#[source] std::io::Error),
    /// `security` exited with an error other than "not found", such as access being denied.
    #[error(
        "security find-generic-password exited with {0}; allow access in Keychain Access, \
         or delete the {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT} item to run without a key"
    )]
    Status(i32),
    /// `security` was killed by a signal.
    #[error("security find-generic-password was killed by a signal")]
    Signal,
    /// The text given is not an API key.
    #[error("an NVD API key is one line of letters, digits and dashes; paste it again")]
    NotAKey,
    /// The Keychain refused to store the key.
    #[error(
        "the Keychain did not store the key: {0}; allow access in Keychain Access and try again"
    )]
    Save(String),
}

/// A CPE product, such as `openssl`, matched under any vendor, or `vendor:product`, such as
/// `github:cli`, when the bare name is shared by unrelated products.
#[derive(Debug, Clone, Serialize)]
#[serde(into = "String")]
pub struct Product {
    vendor: Option<String>,
    name: String,
}

impl Product {
    /// Returns the `virtualMatchString` for NVD.
    fn matcher(&self) -> String {
        let vendor = self.vendor.as_deref().unwrap_or("*");
        format!("cpe:2.3:*:{vendor}:{}", self.name)
    }

    /// Returns whether a CPE's `vendor` and `product` fields name this product: the same name,
    /// and the same vendor when this one has one.
    pub(super) fn is_named_by(&self, vendor: &str, product: &str) -> bool {
        self.name == product && self.vendor.as_deref().is_none_or(|v| v == vendor)
    }

    /// Returns the cache file name. Neither part may contain `..`, so `github..cli` cannot be
    /// confused with a vendorless product.
    fn cache_name(&self) -> String {
        match &self.vendor {
            Some(vendor) => format!("{vendor}..{}", self.name),
            None => self.name.clone(),
        }
    }
}

impl FromStr for Product {
    type Err = ParseProductError;

    /// Accepts `product` or `vendor:product`, each 1 to 64 lowercase ASCII letters, digits,
    /// `.`, `-` and `_` (short enough together that the cache name fits), starting with a letter or
    /// digit and without `..`: the characters CPE names use without escaping.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let part_ok = |p: &str| {
            (1..=64).contains(&p.len())
                && p.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && !p.contains("..")
                && p.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
                })
        };
        let (vendor, name) = match s.split_once(':') {
            Some((vendor, name)) => (Some(vendor), name),
            None => (None, s),
        };
        if !part_ok(name) || !vendor.is_none_or(part_ok) {
            return Err(ParseProductError);
        }
        let product = Self {
            vendor: vendor.map(str::to_owned),
            name: name.to_owned(),
        };
        // Only a product whose cache file name is valid is a product: fetching it must not fail
        // later over a name the parser accepted.
        if cache_key(&product.cache_name()).is_err() {
            return Err(ParseProductError);
        }
        Ok(product)
    }
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.vendor {
            Some(vendor) => write!(f, "{vendor}:{}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

impl From<Product> for String {
    fn from(product: Product) -> Self {
        product.to_string()
    }
}

/// A string that is not a CPE product.
#[derive(Debug, thiserror::Error)]
#[error(
    "product must be name or vendor:name, each 1-64 lowercase letters, digits, '.', '-' or '_', \
     starting alphanumeric, without '..'"
)]
pub struct ParseProductError;

pub(super) fn fetch(
    feeds: &Feeds,
    product: &Product,
    history: History,
) -> Result<Vec<Advisory>, FeedError> {
    let name = product.cache_name();
    let key = cache_key(&name)?;
    let mut cached: Option<ProductCache> = feeds.cache.read("nvd", key)?;
    let now = Timestamp::now();
    if let Some(fresh) = cached.take_if(|c| is_fresh(c.fetched_at, now)) {
        return Ok(advisories(fresh.cves, history));
    }
    if cached.as_ref().is_none_or(|c| c.cves.is_empty()) && recently_unknown(feeds, key, now)? {
        return Ok(Vec::new());
    }
    let window = cached
        .as_ref()
        .and_then(|c| delta_window(c.fetched_at, now));
    let mut cves = match (cached, window) {
        (Some(c), Some(_)) => c.cves,
        _ => BTreeMap::new(),
    };
    let first_page_time = request_all(feeds, product, window, &mut cves)?;

    // The next delta starts where this fetch's coverage ends. A delta covers up to `to` on
    // the local clock, but only up to NVD's present when it answered, so the earlier of the
    // two: CVEs modified after it are picked up next time whichever clock is ahead. A full
    // fetch covers up to NVD's time at the first page; later pages were answered after it,
    // so starting there can only repeat CVEs, never skip them.
    let fetched_at = window.map_or(first_page_time, |(_, to)| to.min(first_page_time));
    let entry = ProductCache { fetched_at, cves };
    feeds.cache.write("nvd", key, &entry)?;
    Ok(advisories(entry.cves, history))
}

/// Requests every page of CVEs for `window` (the full history for `None`), adding them to
/// `cves`. Returns NVD's time at the first page.
fn request_all(
    feeds: &Feeds,
    product: &Product,
    window: Option<(Timestamp, Timestamp)>,
    cves: &mut BTreeMap<String, Box<RawValue>>,
) -> Result<Timestamp, FeedError> {
    let mut first_page_time = None;
    let mut start = 0;
    for pages in 1.. {
        let page = request_page(feeds, product, window, start)?;
        first_page_time.get_or_insert(page.timestamp);
        let count = page.cves.len();
        cves.extend(page.cves);
        start += count;
        // `request_page` already rejects an empty page before the end; this also stops a
        // regression there from looping forever.
        if count == 0 || start >= page.total_results {
            break;
        }
        // Every page before the end holds at least one CVE, so there can be no more pages than
        // results. More means the index is not advancing, or the total keeps growing.
        if pages >= page.total_results {
            return Err(FeedError::Unexpected {
                url: cves_url(feeds),
                what: "more pages than results",
            });
        }
    }
    Ok(first_page_time.expect("the loop requests at least one page"))
}

/// Whether NVD's CPE dictionary was found not to know the product less than
/// [`UNKNOWN_SKIP`] ago, so its CVEs need not be asked for. 33 of 108 products on one Mac
/// (2026-11-08) were such names, each a paced request every sweep. The caller asks only when
/// it has no cached CVEs: the CVE query and the dictionary are different answers, and a
/// product can have CVEs that `history.since` filtered out.
fn recently_unknown(feeds: &Feeds, key: &str, now: Timestamp) -> Result<bool, FeedError> {
    let check: Option<ProductCheck> = feeds.cache.read("nvd-cpe", key)?;
    Ok(check.is_some_and(|c| !c.known && within(c.checked_at, now, UNKNOWN_SKIP)))
}

/// Whether a cache fetched at `fetched_at` is recent enough to use without a request (see
/// [`FRESH`]). After a full fetch `fetched_at` is on NVD's clock, so a cache dated after `now`
/// (NVD ahead of us, or our clock moved back) has no known age and is not fresh.
fn is_fresh(fetched_at: Timestamp, now: Timestamp) -> bool {
    within(fetched_at, now, FRESH)
}

/// Whether `at` is less than `span` before `now`. A time after `now` is not: its age is
/// unknown, and trusting it would last as long as the clock error.
fn within(at: Timestamp, now: Timestamp, span: SignedDuration) -> bool {
    let age = now.duration_since(at);
    age >= SignedDuration::ZERO && age < span
}

/// Returns the `lastModStartDate`..`lastModEndDate` range for a cache fetched at
/// `fetched_at`, or `None` when it is too old for NVD's 120-day limit and must be fetched in
/// full. The range ends at `now`, or at `fetched_at` if the local clock is behind it, since
/// NVD rejects an end before the start. The minute of slack keeps the range under the limit
/// after NVD's millisecond rounding; its size is arbitrary.
fn delta_window(fetched_at: Timestamp, now: Timestamp) -> Option<(Timestamp, Timestamp)> {
    let limit = MAX_DELTA - SignedDuration::from_mins(1);
    (now.duration_since(fetched_at) < limit).then(|| (fetched_at, now.max(fetched_at)))
}

/// One page of results, with each CVE's id read from its record.
struct PageData {
    total_results: usize,
    timestamp: Timestamp,
    cves: Vec<(String, Box<RawValue>)>,
}

fn request_page(
    feeds: &Feeds,
    product: &Product,
    window: Option<(Timestamp, Timestamp)>,
    start: usize,
) -> Result<PageData, FeedError> {
    let url = cves_url(feeds);
    let matcher = product.matcher();
    let start_index = start;
    let start = start.to_string();
    let page_size = PAGE.to_string();
    let (from, to) = window.map_or((String::new(), String::new()), |(from, to)| {
        (nvd_time(from), nvd_time(to))
    });

    let mut query = vec![
        ("virtualMatchString", matcher.as_str()),
        ("resultsPerPage", page_size.as_str()),
        ("startIndex", start.as_str()),
    ];
    if window.is_some() {
        query.push(("lastModStartDate", from.as_str()));
        query.push(("lastModEndDate", to.as_str()));
    }
    let headers: Vec<(&str, &str)> = match &feeds.nvd {
        NvdAccess::Anonymous => vec![],
        NvdAccess::ApiKey(key) => vec![("apiKey", key.as_str())],
    };

    pace(feeds);
    let text = feeds.http.get(&url, &query, &headers)?;
    let page: Page = decode(&url, &text)?;
    // A page that does not start where asked (a proxy dropping the query, say), or an empty
    // page before the end, would otherwise pass for a complete sync and hide the rest.
    if page.start_index != start_index {
        return Err(FeedError::Unexpected {
            url,
            what: "the page starts at a different index than requested",
        });
    }
    if page.vulnerabilities.is_empty() && start_index < page.total_results {
        return Err(FeedError::Unexpected {
            url,
            what: "an empty page before the end of the results",
        });
    }
    let cves = page
        .vulnerabilities
        .into_iter()
        .map(|item| {
            let header: CveHeader = decode(&url, item.cve.get())?;
            // The id names cache and bundle files, so it gets the same check as OSV ids.
            cache_key(&header.id)?;
            Ok((header.id, item.cve))
        })
        .collect::<Result<_, FeedError>>()?;
    Ok(PageData {
        total_results: page.total_results,
        timestamp: page.timestamp,
        cves,
    })
}

fn cves_url(feeds: &Feeds) -> String {
    format!("{}/rest/json/cves/2.0", feeds.endpoints.nvd)
}

/// How long "NVD does not know this product" is trusted before asking again, since NVD adds
/// products over time. Arbitrary. A known product is trusted for good: NVD does not remove
/// CPE names, it deprecates them.
const UNKNOWN_PRODUCT_RECHECK: SignedDuration = SignedDuration::from_hours(24 * 30);

/// Returns whether NVD's CPE dictionary has `product`, from the cache when it can.
pub(super) fn product_known(feeds: &Feeds, product: &Product) -> Result<bool, FeedError> {
    let name = product.cache_name();
    let key = cache_key(&name)?;
    let cached: Option<ProductCheck> = feeds.cache.read("nvd-cpe", key)?;
    if let Some(check) = cached
        && check.trusted_at(Timestamp::now())
    {
        return Ok(check.known);
    }

    let url = format!("{}/rest/json/cpes/2.0", feeds.endpoints.nvd);
    let matcher = product.matcher();
    let query = [
        ("cpeMatchString", matcher.as_str()),
        ("resultsPerPage", "1"),
    ];
    let headers: Vec<(&str, &str)> = match &feeds.nvd {
        NvdAccess::Anonymous => vec![],
        NvdAccess::ApiKey(key) => vec![("apiKey", key.as_str())],
    };
    pace(feeds);
    let text = feeds.http.get(&url, &query, &headers)?;
    let page: CpePage = decode(&url, &text)?;
    let check = ProductCheck {
        known: page.total_results > 0,
        checked_at: Timestamp::now(),
    };
    feeds.cache.write("nvd-cpe", key, &check)?;
    Ok(check.known)
}

#[derive(Debug, Serialize, Deserialize)]
struct ProductCheck {
    known: bool,
    checked_at: Timestamp,
}

impl ProductCheck {
    /// Whether the cached answer still holds at `now`: a known product always, an unknown one
    /// for less than [`UNKNOWN_PRODUCT_RECHECK`], and not when it is dated after `now`.
    fn trusted_at(&self, now: Timestamp) -> bool {
        self.known || within(self.checked_at, now, UNKNOWN_PRODUCT_RECHECK)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpePage {
    total_results: usize,
}

/// Sleeps until the pacing interval since the previous NVD request has passed.
fn pace(feeds: &Feeds) {
    if let Some(previous) = feeds.nvd_last.get() {
        thread::sleep(feeds.nvd_interval.saturating_sub(previous.elapsed()));
    }
    feeds.nvd_last.set(Some(Instant::now()));
}

/// NVD's timestamp format, `2026-11-04T20:18:52.330Z`.
fn nvd_time(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn advisories(cves: BTreeMap<String, Box<RawValue>>, history: History) -> Vec<Advisory> {
    cves.into_iter()
        .filter_map(|(id, record)| {
            let header = serde_json::from_str::<CveHeader>(record.get()).ok();
            let published = header.as_ref().and_then(|h| h.published);
            let modified = header.and_then(|h| h.last_modified);
            in_window(published, modified, history).then_some(Advisory {
                source: Source::Nvd,
                id,
                aliases: Vec::new(),
                modified,
                record,
            })
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
struct ProductCache {
    fetched_at: Timestamp,
    cves: BTreeMap<String, Box<RawValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    start_index: usize,
    total_results: usize,
    #[serde(deserialize_with = "de_nvd_time")]
    timestamp: Timestamp,
    vulnerabilities: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    cve: Box<RawValue>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveHeader {
    id: String,
    #[serde(default, deserialize_with = "de_nvd_time_opt")]
    published: Option<Timestamp>,
    #[serde(default, deserialize_with = "de_nvd_time_opt")]
    last_modified: Option<Timestamp>,
}

/// NVD writes UTC times without an offset, as `2026-11-04T20:18:52.330`.
fn parse_nvd_time(text: &str) -> Option<Timestamp> {
    let civil: jiff::civil::DateTime = text.parse().ok()?;
    civil
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()
        .map(|z| z.timestamp())
}

fn de_nvd_time<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Timestamp, D::Error> {
    let text = String::deserialize(d)?;
    parse_nvd_time(&text).ok_or_else(|| serde::de::Error::custom("expected an NVD timestamp"))
}

fn de_nvd_time_opt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Timestamp>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.and_then(|t| parse_nvd_time(&t)))
}

#[cfg(test)]
mod tests {
    use crate::config::Since;
    use crate::feeds::cache::Cache;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;

    use crate::feeds::Endpoints;
    use crate::feeds::test_server::Request;
    use crate::feeds::test_server::TestServer;

    fn feeds(server: &TestServer, dir: &std::path::Path, access: NvdAccess) -> Feeds {
        let mut feeds = Feeds::with_endpoints(
            dir.to_owned(),
            access,
            Endpoints {
                osv: String::new(),
                nvd: server.url.clone(),
                kev: String::new(),
            },
        );
        feeds.nvd_interval = Duration::ZERO;
        feeds
    }

    fn cve(id: &str, published: &str) -> serde_json::Value {
        serde_json::json!({"cve": {"id": id, "published": published, "descriptions": []}})
    }

    fn page(total: usize, timestamp: &str, items: &[serde_json::Value]) -> String {
        page_at(0, total, timestamp, items)
    }

    fn page_at(start: usize, total: usize, timestamp: &str, items: &[serde_json::Value]) -> String {
        serde_json::json!({
            "resultsPerPage": items.len(),
            "startIndex": start,
            "totalResults": total,
            "timestamp": timestamp,
            "vulnerabilities": items,
        })
        .to_string()
    }

    fn product(name: &str) -> Product {
        name.parse().unwrap()
    }

    #[test]
    fn stderr_from_security_is_a_failed_save() {
        use std::os::unix::process::ExitStatusExt as _;
        let output = |code: i32, stderr: &[u8]| Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        };
        assert!(saved(&output(0, b"")).is_ok());
        assert!(saved(&output(0, b"Usage: add-generic-password")).is_err());
        assert!(saved(&output(1, b"")).is_err());
    }

    #[test]
    fn only_an_nvd_key_reaches_the_keychain_command() {
        let key = "1a2b3c4d-0000-4000-8000-0123456789ab";
        assert_eq!(
            keychain_script(&format!(" {key}\n")).unwrap(),
            format!(
                "add-generic-password -U -s {KEYCHAIN_SERVICE} -a {KEYCHAIN_ACCOUNT} -w {key}\n"
            )
        );
        for bad in ["", "-U", "a b", "a\nb", "a\"b", "key;rm", &"a".repeat(129)] {
            assert_eq!(keychain_script(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn paginates_full_history_then_fetches_modified_window() {
        let round = Arc::new(Mutex::new(0));
        let r = Arc::clone(&round);
        let server = TestServer::start(move |request: &Request| {
            let start = request.query("startIndex").unwrap();
            match (*r.lock().unwrap(), start.as_str()) {
                (0, "0") => (
                    200,
                    page(
                        3,
                        "2026-11-01T10:00:00.000",
                        &[
                            cve("CVE-1", "2020-01-01T00:00:00.000"),
                            cve("CVE-2", "2025-06-01T00:00:00.000"),
                        ],
                    ),
                ),
                (0, "2") => (
                    200,
                    page_at(
                        2,
                        3,
                        "2026-11-01T10:00:01.000",
                        &[cve("CVE-3", "2026-01-01T00:00:00.000")],
                    ),
                ),
                (1, "0") => (
                    200,
                    page(
                        1,
                        "2026-11-02T10:00:00.000",
                        &[serde_json::json!({"cve": {
                            "id": "CVE-2",
                            "published": "2025-06-01T00:00:00.000",
                            "v": 2,
                        }})],
                    ),
                ),
                // Answered, not panicked on: a panic would kill the server thread and leave the
                // client waiting for its timeout instead of failing the test at once.
                other => (500, format!("unexpected request {other:?}")),
            }
        });
        let tmp = tempfile::tempdir().unwrap();
        let feeds = feeds(&server, tmp.path(), NvdAccess::ApiKey("k".into()));

        let ids = |advisories: &[Advisory]| -> Vec<String> {
            advisories.iter().map(|a| a.id.clone()).collect()
        };
        let first = feeds.nvd(&product("openssl"), History::All).unwrap();
        assert_eq!(ids(&first), ["CVE-1", "CVE-2", "CVE-3"]);
        assert!(matches!(first[0].source, Source::Nvd));

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].query("virtualMatchString").as_deref(),
            Some("cpe:2.3:*:*:openssl")
        );
        assert_eq!(requests[0].query("lastModStartDate"), None);
        assert_eq!(requests[0].header("apikey"), Some("k"));

        // Stand in for "the cache was written a few hours ago", too old to be used as it is;
        // the window starts at NVD's time.
        let cache_file = tmp.path().join("nvd/openssl.json");
        let text = std::fs::read_to_string(&cache_file).unwrap();
        let mut cache: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(cache["fetched_at"], "2026-11-01T10:00:00Z");
        let hours_ago = Timestamp::now() - SignedDuration::from_hours(3);
        cache["fetched_at"] = hours_ago.to_string().into();
        std::fs::write(&cache_file, cache.to_string()).unwrap();
        let fetched_at: Timestamp = cache["fetched_at"].as_str().unwrap().parse().unwrap();

        *round.lock().unwrap() = 1;
        let since = History::Since(Since::new(jiff::civil::date(2025, 1, 1)).unwrap());
        let second = feeds.nvd(&product("openssl"), since).unwrap();
        assert_eq!(ids(&second), ["CVE-2", "CVE-3"]);
        assert!(second[0].record.get().contains(r#""v":2"#));

        let request = &server.requests()[2];
        assert_eq!(
            request.query("lastModStartDate"),
            Some(nvd_time(fetched_at))
        );
        let end: Timestamp = parse_nvd_time(
            request
                .query("lastModEndDate")
                .unwrap()
                .trim_end_matches('Z'),
        )
        .unwrap();
        // NVD times carry milliseconds, so compare against the start as NVD sees it.
        let start = parse_nvd_time(nvd_time(fetched_at).trim_end_matches('Z')).unwrap();
        assert!(end >= start && end <= Timestamp::now());
    }

    #[test]
    fn stale_cache_is_fetched_in_full() {
        let server = TestServer::start(|_: &Request| {
            (
                200,
                page(
                    1,
                    "2026-11-01T10:00:00.000",
                    &[cve("CVE-9", "2026-01-01T00:00:00.000")],
                ),
            )
        });
        let tmp = tempfile::tempdir().unwrap();
        let old = ProductCache {
            fetched_at: Timestamp::now() - MAX_DELTA,
            cves: BTreeMap::from([(
                "CVE-OLD".to_owned(),
                RawValue::from_string(r#"{"id":"CVE-OLD"}"#.to_owned()).unwrap(),
            )]),
        };
        Cache::new(tmp.path().to_owned())
            .write("nvd", "curl", &old)
            .unwrap();

        let advisories = feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("curl"), History::All)
            .unwrap();
        let ids: Vec<_> = advisories.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["CVE-9"]);
        let request = &server.requests()[0];
        assert_eq!(request.query("lastModStartDate"), None);
        assert_eq!(request.header("apikey"), None);
    }

    #[test]
    fn month_old_cache_fetches_only_the_window() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let fetched_at = Timestamp::now() - SignedDuration::from_hours(24 * 30);
        let cached = ProductCache {
            fetched_at,
            cves: BTreeMap::from([(
                "CVE-KEPT".to_owned(),
                RawValue::from_string(r#"{"id":"CVE-KEPT"}"#.to_owned()).unwrap(),
            )]),
        };
        Cache::new(tmp.path().to_owned())
            .write("nvd", "curl", &cached)
            .unwrap();

        let advisories = feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("curl"), History::All)
            .unwrap();
        let ids: Vec<_> = advisories.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["CVE-KEPT"]);
        assert_eq!(
            server.requests()[0].query("lastModStartDate"),
            Some(nvd_time(fetched_at))
        );
    }

    /// A product's cached CVEs and CPE check, as one sweep leaves them.
    fn cached(cache: &Cache, name: &str, cves: &[&str], ago: SignedDuration, known: bool) {
        let cves = cves
            .iter()
            .map(|id| {
                let raw = format!(r#"{{"id":"{id}"}}"#);
                ((*id).to_owned(), RawValue::from_string(raw).unwrap())
            })
            .collect();
        let at = Timestamp::now() - ago;
        let entry = ProductCache {
            fetched_at: at,
            cves,
        };
        cache.write("nvd", name, &entry).unwrap();
        let check = ProductCheck {
            known,
            checked_at: at,
        };
        cache.write("nvd-cpe", name, &check).unwrap();
    }

    #[test]
    fn a_product_nvd_does_not_know_is_not_asked_for_cves_for_a_week() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().to_owned());
        let feeds = feeds(&server, tmp.path(), NvdAccess::Anonymous);
        let days = |n: i64| SignedDuration::from_hours(24 * n);

        cached(&cache, "abseil", &[], days(3), false);
        assert!(
            feeds
                .nvd(&product("abseil"), History::All)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            server.requests().len(),
            0,
            "known to be unknown, so not asked"
        );

        cached(&cache, "abseil", &[], days(8), false);
        feeds.nvd(&product("abseil"), History::All).unwrap();
        assert_eq!(
            server.requests().len(),
            1,
            "a week on, the CVEs are asked for again"
        );

        cached(&cache, "curl", &[], days(3), true);
        feeds.nvd(&product("curl"), History::All).unwrap();
        assert_eq!(server.requests().len(), 2, "a known product is asked");

        // A product with cached CVEs is asked whatever the dictionary said: the two are
        // different answers, and `history.since` may have hidden its CVEs.
        cached(&cache, "zlib", &["CVE-OLD"], days(3), false);
        let kept = feeds.nvd(&product("zlib"), History::All).unwrap();
        assert_eq!(server.requests().len(), 3);
        assert_eq!(kept.len(), 1, "the cached CVE is still returned");

        // An answer dated after `now` (the clock moved back) has no known age.
        cached(&cache, "abseil", &[], days(0) - days(2), false);
        feeds.nvd(&product("abseil"), History::All).unwrap();
        assert_eq!(server.requests().len(), 4);
    }

    #[test]
    fn a_skipped_or_fresh_fetch_keeps_where_the_next_delta_starts() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().to_owned());
        let feeds = feeds(&server, tmp.path(), NvdAccess::Anonymous);
        let ago = SignedDuration::from_hours(24 * 8);
        cached(&cache, "abseil", &[], ago, false);
        let fetched_at: ProductCache = cache.read("nvd", "abseil").unwrap().unwrap();
        feeds.nvd(&product("abseil"), History::All).unwrap();
        assert_eq!(
            server.requests()[0].query("lastModStartDate"),
            Some(nvd_time(fetched_at.fetched_at)),
            "the delta covers the whole skip"
        );
    }

    #[test]
    fn fresh_means_under_two_hours_and_not_in_the_future() {
        let t: Timestamp = "2026-11-08T00:00:00Z".parse().unwrap();
        assert!(is_fresh(t, t));
        assert!(is_fresh(t, t + FRESH - SignedDuration::from_secs(1)));
        assert!(!is_fresh(t, t + FRESH), "exactly two hours is asked again");
        assert!(!is_fresh(t + SignedDuration::from_nanos(1), t));
    }

    #[test]
    fn a_cache_under_two_hours_old_is_used_without_a_request() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().to_owned());
        let at = |ago: SignedDuration| ProductCache {
            fetched_at: Timestamp::now() - ago,
            cves: BTreeMap::from([(
                "CVE-KEPT".to_owned(),
                RawValue::from_string(r#"{"id":"CVE-KEPT"}"#.to_owned()).unwrap(),
            )]),
        };
        cache
            .write("nvd", "curl", &at(SignedDuration::from_mins(90)))
            .unwrap();
        let feeds = feeds(&server, tmp.path(), NvdAccess::Anonymous);
        let advisories = feeds.nvd(&product("curl"), History::All).unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(server.requests().len(), 0, "fresh, so NVD is not asked");

        cache
            .write("nvd", "curl", &at(SignedDuration::from_mins(130)))
            .unwrap();
        feeds.nvd(&product("curl"), History::All).unwrap();
        assert_eq!(server.requests().len(), 1, "over two hours old, so it is");

        let ahead = Timestamp::now() + SignedDuration::from_mins(5);
        assert!(
            !is_fresh(ahead, Timestamp::now()),
            "a clock that moved back"
        );
    }

    /// With NVD's clock ahead of ours, the delta only covered up to our `now`, so the next one
    /// must start there and not at NVD's later time, or the CVEs in between are never fetched.
    #[test]
    fn delta_coverage_ends_at_the_earlier_clock() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2999-01-01T00:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().to_owned());
        let old = ProductCache {
            fetched_at: Timestamp::now() - SignedDuration::from_hours(3),
            cves: BTreeMap::new(),
        };
        cache.write("nvd", "curl", &old).unwrap();

        let before = Timestamp::now();
        feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("curl"), History::All)
            .unwrap();
        let after: ProductCache = cache.read("nvd", "curl").unwrap().unwrap();
        assert!(after.fetched_at >= before && after.fetched_at <= Timestamp::now());
    }

    /// A CPE dictionary that knows only `github:cli`, counting requests.
    fn cpe_server() -> TestServer {
        TestServer::start(|request: &Request| {
            assert_eq!(request.path(), "/rest/json/cpes/2.0");
            assert_eq!(request.query("resultsPerPage").as_deref(), Some("1"));
            let total = usize::from(
                request.query("cpeMatchString").as_deref() == Some("cpe:2.3:*:github:cli"),
            );
            (
                200,
                serde_json::json!({ "totalResults": total }).to_string(),
            )
        })
    }

    #[test]
    fn known_products_are_asked_once() {
        let server = cpe_server();
        let tmp = tempfile::tempdir().unwrap();
        let feeds = feeds(&server, tmp.path(), NvdAccess::Anonymous);

        assert!(feeds.nvd_product_known(&product("github:cli")).unwrap());
        assert!(feeds.nvd_product_known(&product("github:cli")).unwrap());
        assert_eq!(
            server.requests().len(),
            1,
            "a known product is cached for good"
        );

        let old = ProductCheck {
            known: true,
            checked_at: Timestamp::now() - UNKNOWN_PRODUCT_RECHECK * 2,
        };
        Cache::new(tmp.path().to_owned())
            .write("nvd-cpe", "github..cli", &old)
            .unwrap();
        assert!(feeds.nvd_product_known(&product("github:cli")).unwrap());
        assert_eq!(server.requests().len(), 1, "however old the answer");
    }

    #[test]
    fn unknown_products_are_asked_again_after_a_month() {
        let server = cpe_server();
        let tmp = tempfile::tempdir().unwrap();
        let feeds = feeds(&server, tmp.path(), NvdAccess::Anonymous);
        let cache = Cache::new(tmp.path().to_owned());
        let unknown = product("nope");

        assert!(!feeds.nvd_product_known(&unknown).unwrap());
        assert!(!feeds.nvd_product_known(&unknown).unwrap());
        assert_eq!(server.requests().len(), 1, "a recent unknown is trusted");

        let at = |age: SignedDuration| ProductCheck {
            known: false,
            checked_at: Timestamp::now() - age,
        };
        let almost = UNKNOWN_PRODUCT_RECHECK - SignedDuration::from_hours(1);
        cache.write("nvd-cpe", "nope", &at(almost)).unwrap();
        assert!(!feeds.nvd_product_known(&unknown).unwrap());
        assert_eq!(server.requests().len(), 1, "under a month old");

        let expired = UNKNOWN_PRODUCT_RECHECK + SignedDuration::from_hours(1);
        cache.write("nvd-cpe", "nope", &at(expired)).unwrap();
        assert!(!feeds.nvd_product_known(&unknown).unwrap());
        assert_eq!(
            server.requests().len(),
            2,
            "over a month old is asked again"
        );
    }

    #[test]
    fn recheck_is_thirty_days() {
        assert_eq!(UNKNOWN_PRODUCT_RECHECK, SignedDuration::from_hours(720));
        let checked_at: Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
        let unknown = ProductCheck {
            known: false,
            checked_at,
        };
        let edge = checked_at + UNKNOWN_PRODUCT_RECHECK;
        assert!(unknown.trusted_at(edge - SignedDuration::from_secs(1)));
        assert!(
            !unknown.trusted_at(edge),
            "exactly thirty days is asked again"
        );
        let known = ProductCheck {
            known: true,
            checked_at,
        };
        assert!(
            known.trusted_at(edge + UNKNOWN_PRODUCT_RECHECK),
            "a known product for good"
        );
    }

    #[test]
    fn delta_window_respects_the_limit() {
        let now: Timestamp = "2026-11-05T12:00:00Z".parse().unwrap();
        let limit = MAX_DELTA - SignedDuration::from_mins(1);

        let fresh = now - limit + SignedDuration::from_secs(1);
        assert_eq!(delta_window(fresh, now), Some((fresh, now)));
        assert_eq!(delta_window(now - limit, now), None);
        assert_eq!(delta_window(now - MAX_DELTA, now), None);

        let ahead = now + SignedDuration::from_hours(1);
        assert_eq!(delta_window(ahead, now), Some((ahead, ahead)));
    }

    #[test]
    fn empty_page_before_the_end_fails_without_caching() {
        let server =
            TestServer::start(|_: &Request| (200, page(10, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let err = feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("zlib"), History::All)
            .unwrap_err();
        assert!(matches!(err, FeedError::Unexpected { .. }), "{err:?}");
        assert!(!tmp.path().join("nvd/zlib.json").exists());
    }

    #[test]
    fn no_results_is_a_complete_sync() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let advisories = feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("zlib"), History::All)
            .unwrap();
        assert!(advisories.is_empty());
        assert!(tmp.path().join("nvd/zlib.json").exists());
    }

    /// Every request answered with the first page, as a proxy that drops the query would.
    #[test]
    fn repeated_first_page_fails_without_caching() {
        let server = TestServer::start(|_: &Request| {
            let body = page(
                2,
                "2026-11-01T10:00:00.000",
                &[cve("CVE-1", "2026-01-01T00:00:00.000")],
            );
            (200, body)
        });
        let tmp = tempfile::tempdir().unwrap();
        let err = feeds(&server, tmp.path(), NvdAccess::Anonymous)
            .nvd(&product("zlib"), History::All)
            .unwrap_err();
        assert!(matches!(err, FeedError::Unexpected { .. }), "{err:?}");
        assert!(!tmp.path().join("nvd/zlib.json").exists());
    }

    #[test]
    fn pacing_spaces_requests() {
        let server =
            TestServer::start(|_: &Request| (200, page(0, "2026-11-01T10:00:00.000", &[])));
        let tmp = tempfile::tempdir().unwrap();
        let mut feeds = feeds(&server, tmp.path(), NvdAccess::Anonymous);
        feeds.nvd_interval = Duration::from_millis(200);

        let begin = Instant::now();
        feeds.nvd(&product("a"), History::All).unwrap();
        feeds.nvd(&product("b"), History::All).unwrap();
        assert!(begin.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn products_are_cpe_names() {
        for good in [
            "openssl",
            "node.js",
            "x11",
            "libxml2",
            "go-git",
            "a_b",
            "github:cli",
        ] {
            assert_eq!(product(good).to_string(), good);
        }
        assert_eq!(product("openssl").matcher(), "cpe:2.3:*:*:openssl");
        assert_eq!(product("github:cli").matcher(), "cpe:2.3:*:github:cli");
        assert_eq!(product("openssl").cache_name(), "openssl");
        assert_eq!(product("github:cli").cache_name(), "github..cli");
        assert_eq!(
            serde_json::to_string(&product("github:cli")).unwrap(),
            "\"github:cli\""
        );

        for bad in [
            "",
            "OpenSSL",
            "-x",
            ".x",
            "a/b",
            "a b",
            "a:b:c",
            ":b",
            "a:",
            "a..b",
            "Git:cli",
            &"a".repeat(65),
        ] {
            assert!(
                matches!(bad.parse::<Product>(), Err(ParseProductError)),
                "{bad:?}"
            );
        }
        let longest = format!("{}:{}", "v".repeat(62), "n".repeat(64));
        assert_eq!(product(&longest).cache_name().len(), 128);
        let too_long = format!("{}:{}", "v".repeat(63), "n".repeat(64));
        assert!(too_long.parse::<Product>().is_err());
    }

    #[test]
    fn keychain_output() {
        assert!(matches!(
            from_security_output(Some(0), b"abc-123\n"),
            Ok(NvdAccess::ApiKey(k)) if k == "abc-123"
        ));
        assert!(matches!(
            from_security_output(Some(0), b"\n"),
            Ok(NvdAccess::Anonymous)
        ));
        assert!(matches!(
            from_security_output(Some(44), b""),
            Ok(NvdAccess::Anonymous)
        ));
        assert!(matches!(
            from_security_output(Some(51), b""),
            Err(KeychainError::Status(51))
        ));
        assert!(matches!(
            from_security_output(None, b""),
            Err(KeychainError::Signal)
        ));
        assert_eq!(
            format!("{:?}", NvdAccess::ApiKey("secret".into())),
            "ApiKey(..)"
        );
    }

    #[test]
    fn nvd_times() {
        let ts: Timestamp = "2026-11-04T20:18:52.33Z".parse().unwrap();
        assert_eq!(nvd_time(ts), "2026-11-04T20:18:52.330Z");
        assert_eq!(parse_nvd_time("2026-11-04T20:18:52.330"), Some(ts));
        assert_eq!(parse_nvd_time("garbage"), None);
    }
}

#[cfg(test)]
mod product_properties {
    use proptest::prelude::*;

    use super::*;

    /// Valid product parts: at most 1 + 2 * 30 = 61 bytes, under the 64-byte limit.
    const PART: &str = "[a-z0-9]([a-z0-9_-]|\\.[a-z0-9_-]){0,30}";

    proptest! {
        /// Every accepted product prints back as itself and has a valid cache name.
        #[test]
        fn round_trips_with_a_valid_cache_name(
            vendor in proptest::option::of(PART),
            name in PART,
        ) {
            let text = vendor.as_ref().map_or_else(|| name.clone(), |v| format!("{v}:{name}"));
            let product: Product = text.parse().unwrap();
            prop_assert_eq!(product.to_string(), text);
            prop_assert!(cache_key(&product.cache_name()).is_ok());
        }

        /// Two different products never share a cache file.
        #[test]
        fn cache_names_are_distinct(
            a in proptest::option::of(PART), b in PART,
            c in proptest::option::of(PART), d in PART,
        ) {
            let make = |v: &Option<String>, n: &str| -> Product {
                v.as_ref().map_or_else(|| n.to_owned(), |v| format!("{v}:{n}")).parse().unwrap()
            };
            let (x, y) = (make(&a, &b), make(&c, &d));
            prop_assert_eq!(x.to_string() == y.to_string(), x.cache_name() == y.cache_name());
        }
    }
}
