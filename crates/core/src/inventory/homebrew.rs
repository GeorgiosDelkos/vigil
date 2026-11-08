//! Homebrew formulae and casks, from `brew info --json=v2 --installed`.
//!
//! Homebrew records no CPE names, so each formula or cask is matched to an NVD product by its
//! name: the `@version` suffix is dropped (`openssl@3`), and the tables below fix the names we
//! know differ. A name that is well formed but wrong is not caught here: NVD returns no CVEs
//! for it. Checking every guessed name against NVD's CPE dictionary, and reporting the ones it
//! does not know, is planned with the sweep (spec, step 4).

use serde::Deserialize;

use crate::feeds::Product;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;

/// Formula names whose NVD product differs, as (name without `@version`, NVD product). Each
/// product was checked against NVD's CPE dictionary on 2026-11-05 (`/rest/json/cpes/2.0`
/// with `cpeMatchString`). A vendor is named where other vendors use the same product name
/// (`cli`, `kerberos_5`, `http_server`, `network_security_services`). `git` has none: NVD
/// files Git's own CVEs under `git-scm`, `git` and `git_project` (29 of its 70 CVEs are not
/// under `git-scm`, checked 2026-11-08), so the bare name also brings in Jenkins' git plugin,
/// which the agent rules out.
const FORMULA_ALIASES: &[(&str, &str)] = &[
    ("expat", "libexpat"),
    ("gh", "github:cli"),
    ("httpd", "apache:http_server"),
    ("icu4c", "international_components_for_unicode"),
    ("jpeg-turbo", "libjpeg-turbo"),
    ("krb5", "mit:kerberos_5"),
    ("little-cms2", "little_cms"),
    ("node", "node.js"),
    ("nss", "mozilla:network_security_services"),
    ("zstd", "zstandard"),
];

/// Cask tokens whose NVD product differs, checked the same way. Kept apart from formulae
/// because one name can mean different products: the `docker` formula is the CLI, the
/// `docker` cask is Docker Desktop.
const CASK_ALIASES: &[(&str, &str)] = &[
    ("docker", "docker:desktop"),
    ("google-chrome", "google:chrome"),
    ("visual-studio-code", "microsoft:visual_studio_code"),
];

pub(super) fn collect(inventory: &mut Inventory) {
    if let Some(output) = inventory.run("brew", &["info", "--json=v2", "--installed"]) {
        parse(&output, inventory);
    }
}

/// Adds every installed formula version and cask from `brew info --json=v2` output.
fn parse(json: &str, inventory: &mut Inventory) {
    let info: Info = match serde_json::from_str(json) {
        Ok(info) => info,
        Err(e) => {
            inventory
                .problems
                .push(InventoryError::parse("brew info --json=v2", &e));
            return;
        }
    };

    for formula in info.formulae {
        let Some(product) = product(&formula.name, FORMULA_ALIASES) else {
            inventory
                .problems
                .push(InventoryError::NoProduct { name: formula.name });
            continue;
        };
        for installed in formula.installed {
            let found_in = FoundIn::HomebrewFormula {
                name: formula.name.clone(),
            };
            let version = without_revision(&installed.version);
            inventory.add(Lookup::Product(product.clone()), version, found_in);
        }
    }
    // A cask's version can be `latest` or carry a build after a comma (`1.2,345`); it is
    // passed on as Homebrew gives it, and the agent reads it with that in mind.
    for cask in info.casks {
        let Some(version) = cask.installed else {
            continue;
        };
        let Some(product) = product(&cask.token, CASK_ALIASES) else {
            inventory
                .problems
                .push(InventoryError::NoProduct { name: cask.token });
            continue;
        };
        let found_in = FoundIn::HomebrewCask { token: cask.token };
        inventory.add(Lookup::Product(product), version, found_in);
    }
}

/// Returns the NVD product for a Homebrew name, or `None` when even the cleaned name is not a
/// valid product (such as `gtk+3`).
fn product(name: &str, aliases: &[(&str, &str)]) -> Option<Product> {
    let base = name.split_once('@').map_or(name, |(base, _)| base);
    let base = aliases
        .iter()
        .find(|(brew, _)| *brew == base)
        .map_or(base, |(_, nvd)| nvd);
    base.parse().ok()
}

/// Drops Homebrew's `_N` revision (`8.1.2_1` -> `8.1.2`): it counts rebuilds of the same
/// upstream release, which NVD's version ranges know nothing about.
fn without_revision(version: &str) -> &str {
    match version.rsplit_once('_') {
        Some((upstream, revision))
            if !upstream.is_empty()
                && !revision.is_empty()
                && revision.bytes().all(|b| b.is_ascii_digit()) =>
        {
            upstream
        }
        _ => version,
    }
}

#[derive(Debug, Deserialize)]
struct Info {
    #[serde(default)]
    formulae: Vec<Formula>,
    #[serde(default)]
    casks: Vec<Cask>,
}

#[derive(Debug, Deserialize)]
struct Formula {
    name: String,
    #[serde(default)]
    installed: Vec<Installed>,
}

#[derive(Debug, Deserialize)]
struct Installed {
    version: String,
}

/// `installed` is the installed version, or null for a cask that is listed but not installed.
#[derive(Debug, Deserialize)]
struct Cask {
    token: String,
    installed: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(json: &str) -> Inventory {
        let mut inventory = Inventory::default();
        parse(json, &mut inventory);
        inventory
    }

    fn summary(inventory: &Inventory) -> Vec<String> {
        inventory
            .components
            .iter()
            .map(|c| match (&c.lookup, &c.found_in) {
                (Lookup::Product(p), FoundIn::HomebrewFormula { name }) => {
                    format!("{name} -> {p} {}", c.version)
                }
                (Lookup::Product(p), FoundIn::HomebrewCask { token }) => {
                    format!("cask {token} -> {p} {}", c.version)
                }
                other => panic!("unexpected component {other:?}"),
            })
            .collect()
    }

    #[test]
    fn formulae_and_casks_become_products() {
        let inventory = parsed(
            r#"{
              "formulae": [
                {"name": "openssl@3", "installed": [{"version": "3.4.0_1"}], "versions": {}},
                {"name": "node", "installed": [{"version": "24.1.0"}, {"version": "23.0.0"}]},
                {"name": "zstd", "installed": [{"version": "1.5.6"}]},
                {"name": "uninstalled", "installed": []}
              ],
              "casks": [
                {"token": "codex", "version": "0.165.0", "installed": "0.128.0"},
                {"token": "listed-only", "installed": null}
              ]
            }"#,
        );
        assert_eq!(
            summary(&inventory),
            [
                "openssl@3 -> openssl 3.4.0",
                "node -> node.js 24.1.0",
                "node -> node.js 23.0.0",
                "zstd -> zstandard 1.5.6",
                "cask codex -> codex 0.128.0",
            ]
        );
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
    }

    #[test]
    fn unusable_names_are_reported() {
        let inventory = parsed(
            r#"{"formulae": [{"name": "gtk+3", "installed": [{"version": "3.24"}]}],
                "casks": [{"token": "c++-gtk-utils", "installed": "1"}]}"#,
        );
        assert!(inventory.components.is_empty());
        let names: Vec<_> = inventory
            .problems
            .iter()
            .map(|p| match p {
                InventoryError::NoProduct { name } => name.as_str(),
                other => panic!("unexpected problem {other:?}"),
            })
            .collect();
        assert_eq!(names, ["gtk+3", "c++-gtk-utils"]);
    }

    #[test]
    fn bad_json_is_a_parse_problem() {
        let inventory = parsed("not json");
        assert!(matches!(
            inventory.problems[..],
            [InventoryError::Parse { .. }]
        ));
    }

    #[test]
    fn product_names() {
        let name = |s: &str| product(s, FORMULA_ALIASES).map(|p| p.to_string());
        assert_eq!(name("python@3.13").as_deref(), Some("python"));
        assert_eq!(name("gh").as_deref(), Some("github:cli"));
        assert_eq!(name("git").as_deref(), Some("git"));
        assert_eq!(
            name("icu4c@78").as_deref(),
            Some("international_components_for_unicode")
        );
        assert_eq!(name("docker").as_deref(), Some("docker"));
        assert_eq!(name("curl").as_deref(), Some("curl"));
        assert_eq!(name("gtk+3"), None);
        let cask = |s: &str| product(s, CASK_ALIASES).map(|p| p.to_string());
        assert_eq!(cask("docker").as_deref(), Some("docker:desktop"));
    }

    #[test]
    fn revisions_are_dropped() {
        assert_eq!(without_revision("8.1.2_1"), "8.1.2");
        assert_eq!(without_revision("18.6_12"), "18.6");
        assert_eq!(without_revision("3.4.0"), "3.4.0");
        assert_eq!(without_revision("2024_beta"), "2024_beta");
        assert_eq!(without_revision("_1"), "_1");
        assert_eq!(without_revision("1.0_"), "1.0_");
    }
}
