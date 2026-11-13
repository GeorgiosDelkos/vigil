//! Which sources failed for a target in one sweep, kept in its `report.json` so a degraded
//! sweep is never read as a clean one.
//!
//! A source that fails leaves its part out of the bundle, so the agent cannot find what it would
//! have shown: an advisory feed (KEV, OSV, NVD) its advisories, an inventory source (a listing
//! command, a lockfile, the folder walk) its components. Before this record the failure was a
//! line of text in the report, and the popover read an empty result as "All clear", the tray
//! turned green, and the lifecycle took every finding the failed source had produced as
//! resolved and every pending fix of one as confirmed. Now:
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

use crate::inventory::FoundIn;
use crate::inventory::InventorySource;

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
    /// The NVD products whose CVEs could not be fetched and had none cached in the last week, as
    /// their lookups name them (`openssl`, `github:cli`).
    #[serde(default)]
    pub nvd: BTreeSet<String>,
    /// The inventory sources that failed, so their components were not all looked up.
    #[serde(default)]
    pub inventory: BTreeSet<InventorySource>,
}

/// What of OSV failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsvUnchecked {
    /// The id query failed, so no OSV advisory was fetched.
    All,
    /// Records returned for these packages could not be fetched and had no cached copy, so
    /// some of their advisories are missing. Packages as `ecosystem:name` (`npm:lodash`), not
    /// record ids: a finding may name a record by an alias only.
    Packages(BTreeSet<String>),
}

impl Unchecked {
    /// Whether every source was checked.
    pub(crate) fn is_empty(&self) -> bool {
        !self.kev && self.osv.is_none() && self.nvd.is_empty() && self.inventory.is_empty()
    }

    /// Which sources failed, in a few words for a person: "Homebrew, lockfiles in 4 places,
    /// CISA KEV, OSV, NVD for 3 products". `None` when every source was checked.
    ///
    /// Lockfiles are counted rather than named once there are several: an unreadable folder
    /// tree can fail in many places, and this is one line in the popover.
    pub fn describe(&self) -> Option<String> {
        let (lockfiles, others): (Vec<_>, Vec<_>) = self
            .inventory
            .iter()
            .partition(|source| source.is_lockfiles());
        let mut parts: Vec<String> = others.iter().map(ToString::to_string).collect();
        match lockfiles[..] {
            [] => {}
            [one] => parts.push(one.to_string()),
            ref many => parts.push(format!("lockfiles in {} places", many.len())),
        }
        if self.kev {
            parts.push("CISA KEV".to_owned());
        }
        match &self.osv {
            Some(OsvUnchecked::All) => parts.push("OSV".to_owned()),
            Some(OsvUnchecked::Packages(packages)) => parts.push(match packages.len() {
                1 => "OSV for 1 package".to_owned(),
                n => format!("OSV for {n} packages"),
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
    /// as `lookup` and found in `place`, as a report saves them: a lookup
    /// `{"package": {"ecosystem": "npm", "name": "lodash"}}` or `{"product": "openssl"}`, and
    /// the place read back, `None` when the report has none this build knows.
    ///
    /// A failed inventory source covers the findings of the places it lists
    /// ([`InventorySource::covers`]), and only those: a lockfile that never parses keeps its
    /// own findings open, not every Homebrew one.
    ///
    /// A failed KEV catalog covers the findings of OS packages: a query of one that matches
    /// over 200 advisories (the kernel) keeps only those in the catalog, so without it the
    /// agent judges another, far larger set, and last sweep's findings may not be among what it
    /// lists. Which OS packages were crowded is not known without the catalog, so every OS
    /// package's finding is carried: one fixed since stays open until the catalog is back,
    /// which errs toward showing too much. A saved lookup has only the ecosystem's OSV name,
    /// and the OS ecosystems are those whose name has a colon (`Debian:12`), as the test
    /// `only_os_ecosystems_have_a_colon_in_their_osv_name` in `package` pins.
    pub(crate) fn covers(&self, lookup: &Value, place: Option<&FoundIn>) -> bool {
        if let Some(place) = place
            && self.inventory.iter().any(|source| source.covers(place))
        {
            return true;
        }
        if let Some(package) = lookup.get("package") {
            let field = |name| {
                package
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            };
            let (ecosystem, name) = (field("ecosystem"), field("name"));
            let thinned = self.kev && ecosystem.contains(':');
            return thinned
                || match &self.osv {
                    Some(OsvUnchecked::All) => true,
                    Some(OsvUnchecked::Packages(packages)) => {
                        packages.contains(&package_key(ecosystem, name))
                    }
                    None => false,
                };
        }
        lookup
            .get("product")
            .and_then(Value::as_str)
            .is_some_and(|product| self.nvd.contains(product))
    }
}

/// How [`OsvUnchecked::Packages`] names a package: its ecosystem's OSV name and its name,
/// `npm:lodash`. The sweep writes it and [`Unchecked::covers`] reads it, so both use this.
pub(crate) fn package_key(ecosystem: &str, name: &str) -> String {
    format!("{ecosystem}:{name}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn names(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn describes_what_failed() {
        assert_eq!(Unchecked::default().describe(), None);
        assert!(Unchecked::default().is_empty());
        let all = Unchecked {
            kev: true,
            osv: Some(OsvUnchecked::All),
            nvd: names(&["openssl", "curl", "github:cli"]),
            inventory: BTreeSet::new(),
        };
        assert!(!all.is_empty());
        assert_eq!(all.describe().unwrap(), "CISA KEV, OSV, NVD for 3 products");
        let some = Unchecked {
            osv: Some(OsvUnchecked::Packages(names(&["npm:lodash"]))),
            nvd: names(&["curl"]),
            ..Unchecked::default()
        };
        assert_eq!(
            some.describe().unwrap(),
            "OSV for 1 package, NVD for 1 product"
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
    fn describes_the_inventory_sources_that_failed() {
        let pipx = Unchecked {
            inventory: [InventorySource::Pipx].into(),
            ..Unchecked::default()
        };
        assert!(
            !pipx.is_empty(),
            "a failed inventory source alone is not a full check"
        );
        let walk = InventorySource::LockfileWalk {
            root: "/Users/me/code".into(),
        };
        let brew = Unchecked {
            inventory: [InventorySource::Homebrew, walk.clone()].into(),
            nvd: names(&["curl"]),
            ..Unchecked::default()
        };
        assert_eq!(
            brew.describe().unwrap(),
            "Homebrew, lockfiles under /Users/me/code, NVD for 1 product"
        );
        let lockfile = |path: &str| InventorySource::Lockfile { path: path.into() };
        let lockfiles = Unchecked {
            inventory: [
                lockfile("/a/Cargo.lock"),
                lockfile("/b/uv.lock"),
                walk,
                InventorySource::Pipx,
            ]
            .into(),
            ..Unchecked::default()
        };
        assert_eq!(
            lockfiles.describe().unwrap(),
            "pipx, lockfiles in 3 places",
            "lockfiles are counted once there are several"
        );
        let one = Unchecked {
            inventory: [lockfile("/a/Cargo.lock")].into(),
            ..Unchecked::default()
        };
        assert_eq!(one.describe().unwrap(), "lockfile /a/Cargo.lock");
    }

    #[test]
    fn covers_the_findings_a_failed_source_could_have_produced() {
        let lodash = json!({"package": {"ecosystem": "npm", "name": "lodash"}});
        let kernel = json!({"package": {"ecosystem": "Debian:12", "name": "linux"}});
        let curl = json!({"product": "curl"});
        // The feeds' cover does not depend on the place.
        let mac = Some(&FoundIn::MacOs);

        let osv_down = Unchecked {
            osv: Some(OsvUnchecked::All),
            ..Unchecked::default()
        };
        assert!(osv_down.covers(&lodash, mac) && osv_down.covers(&kernel, None));
        assert!(!osv_down.covers(&curl, mac), "NVD was checked");

        let one_package = Unchecked {
            osv: Some(OsvUnchecked::Packages(names(&["npm:lodash"]))),
            ..Unchecked::default()
        };
        assert!(one_package.covers(&lodash, mac));
        let other = json!({"package": {"ecosystem": "npm", "name": "left-pad"}});
        assert!(!one_package.covers(&other, mac));

        let nvd = Unchecked {
            nvd: names(&["curl"]),
            ..Unchecked::default()
        };
        assert!(nvd.covers(&curl, mac));
        assert!(!nvd.covers(&json!({"product": "openssl"}), mac));
        assert!(!nvd.covers(&lodash, mac));

        // Without the catalog only OS packages, whose crowded queries it thins, are covered.
        let kev = Unchecked {
            kev: true,
            ..Unchecked::default()
        };
        assert!(kev.covers(&kernel, mac));
        let ubuntu = json!({"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "linux"}});
        assert!(kev.covers(&ubuntu, mac));
        assert!(!kev.covers(&lodash, mac) && !kev.covers(&curl, mac));
        assert!(
            !osv_down.covers(&Value::Null, None),
            "an entry without a lookup"
        );
    }

    #[test]
    fn a_failed_inventory_source_covers_the_findings_of_its_places() {
        let curl = json!({"product": "curl"});
        let formula = FoundIn::HomebrewFormula {
            name: "curl".into(),
        };
        let lockfile = FoundIn::Lockfile {
            path: "/p/Cargo.lock".into(),
        };
        let brew_down = Unchecked {
            inventory: [InventorySource::Homebrew].into(),
            ..Unchecked::default()
        };
        assert!(brew_down.covers(&curl, Some(&formula)));
        assert!(!brew_down.covers(&curl, Some(&lockfile)));
        assert!(
            !brew_down.covers(&curl, None),
            "a place this build cannot read"
        );
        let lock_down = Unchecked {
            inventory: [InventorySource::Lockfile {
                path: "/p/Cargo.lock".into(),
            }]
            .into(),
            ..Unchecked::default()
        };
        assert!(lock_down.covers(&curl, Some(&lockfile)));
        assert!(!lock_down.covers(&curl, Some(&formula)));
    }

    #[test]
    fn reads_reports_saved_before_it_existed() {
        let old: Unchecked = serde_json::from_value(json!({})).unwrap();
        assert!(old.is_empty());
        let before_inventory: Unchecked =
            serde_json::from_value(json!({"kev": false, "osv": null, "nvd": ["curl"]})).unwrap();
        assert!(before_inventory.inventory.is_empty());
        let saved = Unchecked {
            kev: false,
            osv: Some(OsvUnchecked::Packages(names(&["npm:lodash"]))),
            nvd: names(&["curl"]),
            inventory: [
                InventorySource::Homebrew,
                InventorySource::Lockfile {
                    path: "/p/uv.lock".into(),
                },
            ]
            .into(),
        };
        let json = serde_json::to_value(&saved).unwrap();
        assert_eq!(
            json,
            json!({"kev": false, "osv": {"packages": ["npm:lodash"]}, "nvd": ["curl"],
                "inventory": [{"kind": "homebrew"}, {"kind": "lockfile", "path": "/p/uv.lock"}]})
        );
        assert_eq!(serde_json::from_value::<Unchecked>(json).unwrap(), saved);
    }
}
