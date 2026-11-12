//! Which sources failed for a target in one sweep, kept in its `report.json` so a degraded
//! sweep is never read as a clean one.
//!
//! A source that fails leaves its advisories out of the bundle, so the agent cannot find what
//! they would have shown. Before this record the failure was a line of text in the report, and
//! the popover read an empty result as "All clear", the tray turned green, and the lifecycle
//! took every finding the failed source had produced as resolved and every pending fix of one
//! as confirmed. Now:
//!
//! - a target whose newest report has anything [`Unchecked`] is not clear, and says which
//!   sources failed (the popover's target line and banner, the tray's failure look);
//! - a finding of the target's previous report that this sweep did not find, and that a failed
//!   source could have produced ([`Unchecked::covers`]), is carried into the new report as it
//!   was, so it stays open and its fix unconfirmed until a sweep that checks it.
//!
//! What is cached counts as checked: a stale cached copy used when its source could not be
//! asked again is a note in the report, not a failure.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// The sources that failed for one target in one sweep. Empty when everything was checked.
///
/// Reports saved before it existed read as empty: their failures are only in `problems`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unchecked {
    /// The CISA KEV catalog could not be read, so nothing is known to be exploited.
    #[serde(default)]
    pub kev: bool,
    /// What of OSV failed, if anything.
    #[serde(default)]
    pub osv: Option<OsvUnchecked>,
    /// The NVD products whose CVEs could not be fetched and had none cached, as their lookups
    /// name them (`openssl`, `github:cli`).
    #[serde(default)]
    pub nvd: BTreeSet<String>,
}

/// What of OSV failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsvUnchecked {
    /// The id query failed, so no OSV advisory was fetched.
    All,
    /// These records could not be fetched and had no cached copy.
    Records(BTreeSet<String>),
}

impl Unchecked {
    /// Whether every source was checked.
    pub(crate) fn is_empty(&self) -> bool {
        !self.kev && self.osv.is_none() && self.nvd.is_empty()
    }

    /// Which sources failed, in a few words for a person: "CISA KEV, OSV, NVD for 3
    /// products". `None` when every source was checked.
    pub fn describe(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.kev {
            parts.push("CISA KEV".to_owned());
        }
        match &self.osv {
            Some(OsvUnchecked::All) => parts.push("OSV".to_owned()),
            Some(OsvUnchecked::Records(ids)) => parts.push(match ids.len() {
                1 => "1 OSV advisory".to_owned(),
                n => format!("{n} OSV advisories"),
            }),
            None => {}
        }
        match self.nvd.len() {
            0 => {}
            1 => parts.push("NVD for 1 product".to_owned()),
            n => parts.push(format!("NVD for {n} products")),
        }
        (!parts.is_empty()).then(|| parts.join(", "))
    }

    /// Whether a source that failed could have produced a finding of the component looked up
    /// as `lookup` (as a report saves it: `{"package": ...}` or `{"product": "openssl"}`) about
    /// `advisories`. A failed KEV catalog drops no advisory, so it covers nothing.
    pub(crate) fn covers(&self, lookup: &Value, advisories: &[String]) -> bool {
        if lookup.get("package").is_some() {
            return match &self.osv {
                Some(OsvUnchecked::All) => true,
                Some(OsvUnchecked::Records(ids)) => advisories.iter().any(|a| ids.contains(a)),
                None => false,
            };
        }
        lookup
            .get("product")
            .and_then(Value::as_str)
            .is_some_and(|product| self.nvd.contains(product))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn ids(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    #[test]
    fn describes_what_failed() {
        assert_eq!(Unchecked::default().describe(), None);
        assert!(Unchecked::default().is_empty());
        let all = Unchecked {
            kev: true,
            osv: Some(OsvUnchecked::All),
            nvd: ids(&["openssl", "curl", "github:cli"]),
        };
        assert!(!all.is_empty());
        assert_eq!(all.describe().unwrap(), "CISA KEV, OSV, NVD for 3 products");
        let some = Unchecked {
            osv: Some(OsvUnchecked::Records(ids(&["GHSA-1"]))),
            nvd: ids(&["curl"]),
            ..Unchecked::default()
        };
        assert_eq!(
            some.describe().unwrap(),
            "1 OSV advisory, NVD for 1 product"
        );
        let kev = Unchecked {
            kev: true,
            ..Unchecked::default()
        };
        assert!(
            !kev.is_empty(),
            "a missing catalog alone is not a full check"
        );
    }

    #[test]
    fn covers_the_findings_a_failed_source_could_have_produced() {
        let package = json!({"package": {"ecosystem": "npm", "name": "lodash"}});
        let curl = json!({"product": "curl"});
        let ghsa = ["GHSA-1".to_owned()];

        let osv_down = Unchecked {
            osv: Some(OsvUnchecked::All),
            ..Unchecked::default()
        };
        assert!(osv_down.covers(&package, &ghsa));
        assert!(!osv_down.covers(&curl, &[]), "NVD was checked");

        let one_record = Unchecked {
            osv: Some(OsvUnchecked::Records(ids(&["GHSA-1"]))),
            ..Unchecked::default()
        };
        assert!(one_record.covers(&package, &ghsa));
        assert!(!one_record.covers(&package, &["GHSA-2".to_owned()]));

        let nvd = Unchecked {
            nvd: ids(&["curl"]),
            ..Unchecked::default()
        };
        assert!(nvd.covers(&curl, &[]));
        assert!(!nvd.covers(&json!({"product": "openssl"}), &[]));
        assert!(!nvd.covers(&package, &ghsa));

        let kev = Unchecked {
            kev: true,
            ..Unchecked::default()
        };
        assert!(!kev.covers(&package, &ghsa) && !kev.covers(&curl, &[]));
        assert!(
            !osv_down.covers(&Value::Null, &ghsa),
            "an entry without a lookup"
        );
    }

    #[test]
    fn reads_reports_saved_before_it_existed() {
        let old: Unchecked = serde_json::from_value(json!({})).unwrap();
        assert!(old.is_empty());
        let saved = Unchecked {
            kev: false,
            osv: Some(OsvUnchecked::Records(ids(&["GHSA-1"]))),
            nvd: ids(&["curl"]),
        };
        let json = serde_json::to_value(&saved).unwrap();
        assert_eq!(
            json,
            json!({"kev": false, "osv": {"records": ["GHSA-1"]}, "nvd": ["curl"]})
        );
        assert_eq!(serde_json::from_value::<Unchecked>(json).unwrap(), saved);
    }
}
