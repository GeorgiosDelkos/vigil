//! Homebrew formulae and casks, from `brew info --json=v2 --installed`.
//!
//! Homebrew records no CPE names, so each formula or cask is matched to an NVD product by its
//! name: the `@version` suffix is dropped (`openssl@3`), and the tables below fix the names we
//! know differ. A name that is well formed but wrong is not caught here: NVD returns no CVEs
//! for it. The sweep checks each product with no CVEs against NVD's CPE dictionary and reports
//! the ones it does not know (spec, step 4).

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::cancel::Cancel;
use crate::feeds::Product;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::InventorySource;
use crate::inventory::Lookup;
use crate::inventory::command;

/// Formula names whose NVD products differ, as (name without `@version`, NVD products), sorted
/// by name for the binary search. A formula has several products when NVD files the software
/// it ships under more than one name; each is looked up at the formula's version.
///
/// Each product was checked against NVD's CPE dictionary (`/rest/json/cpes/2.0` with
/// `cpeMatchString`), and the entries added 2026-11-10 also against their CVEs (`cves/2.0` with
/// `virtualMatchString`) to see that they are the same software. A vendor is named where other
/// vendors use the same product name (`cli`, `kerberos_5`, `http_server`, `libjpeg`, `tar`,
/// `network_security_services`) or the name is generic (`common_libraries`, `file`). `git` has
/// none: NVD files Git's own CVEs under `git-scm`, `git` and `git_project` (29 of its 70 CVEs
/// are not under `git-scm`, checked 2026-11-08), so the bare name also brings in Jenkins' git
/// plugin, which the agent rules out.
///
/// Left out on purpose, as of 2026-11-10: `ggml`, whose vendor's only product is `llama.cpp`,
/// numbered by build (`b5662`); `libomp`, LLVM's OpenMP, where NVD has only Intel's `openmp`;
/// `gpgmepp`, the C++ binding NVD's `gpgme` entries do not cover; `sdl2-compat`, a layer over
/// SDL 3 whose `2.32.x` versions would fall in SDL 2's ranges; `python-tk`, Python's `tkinter`
/// module, whose CVEs NVD files under `python` and the `python` formula already gets. The other
/// names the 2026-11-10 sweep reported have no product in NVD.
const FORMULA_ALIASES: &[(&str, &[&str])] = &[
    // CVE-2025-0838, a heap overflow in Abseil's hash containers.
    ("abseil", &["abseil:common_libraries"]),
    // CVE-2023-6879, in libaom's AV1 encoder.
    ("aom", &["aomedia"]),
    // CVE-2020-2981, Berkeley DB before 18.1.40.
    ("berkeley-db", &["berkeley_db"]),
    // 42 of the 67 libcurl CVEs (CVE-2023-38545 among them) are not filed under `curl`.
    ("curl", &["curl", "libcurl"]),
    ("expat", &["libexpat"]),
    // file(1) and its libmagic, the two formulae built from one release. NVD files its CVEs
    // under `file_project` (CVE-2022-48554) and, before 5.19, under its maintainer
    // `christos_zoulas` (CVE-2014-3538); the one under `gentoo` is from 2007.
    (
        "file-formula",
        &["christos_zoulas:file", "file_project:file"],
    ),
    ("gh", &["github:cli"]),
    // CVE-2025-45582, GNU tar through 1.35.
    ("gnu-tar", &["gnu:tar"]),
    ("httpd", &["apache:http_server"]),
    ("icu4c", &["international_components_for_unicode"]),
    // CVE-2020-14153, IJG libjpeg 8 through 9c.
    ("jpeg", &["ijg:libjpeg"]),
    ("jpeg-turbo", &["libjpeg-turbo"]),
    // libjxl's CVEs are under `libjxl` (13) and one, CVE-2021-28026, under `jpeg-xl`.
    ("jpeg-xl", &["jpeg-xl", "libjxl"]),
    ("krb5", &["mit:kerberos_5"]),
    // The library half of `file-formula`, above.
    ("libmagic", &["christos_zoulas:file", "file_project:file"]),
    // CVE-2024-28182, in the nghttp2 library.
    ("libnghttp2", &["nghttp2"]),
    // libpq ships with PostgreSQL and its CVEs (CVE-2021-23222, CVE-2024-10977) are filed
    // under `postgresql`, so the server's CVEs come along too; the agent rules those out.
    ("libpq", &["postgresql"]),
    ("little-cms2", &["little_cms"]),
    // `mbed:mbedtls` is in the dictionary with no CVEs; Mbed TLS's 73 are under `mbed_tls`,
    // from ARM and from Trusted Firmware, which took the project over.
    ("mbedtls", &["mbed_tls"]),
    ("node", &["node.js"]),
    // CVE-2016-1951, in NSPR's prprf.c.
    ("nspr", &["netscape_portable_runtime"]),
    ("nss", &["mozilla:network_security_services"]),
    // SDL 3 is the same project as SDL 1.2 and 2 (CVE-2021-33657, SDL 2.x).
    ("sdl3", &["simple_directmedia_layer"]),
    // CVE-2021-35331, in Tcl. NVD has no product for Tk, the formula's other half.
    ("tcl-tk", &["tcl"]),
    // CVE-2023-4863, the libwebp heap overflow in CISA's KEV catalog.
    ("webp", &["libwebp"]),
    // libzmq's CVEs are under `zeromq` (CVE-2014-9721) and `libzmq` (CVE-2020-36400).
    ("zeromq", &["libzmq", "zeromq"]),
    ("zstd", &["zstandard"]),
];

/// Cask tokens whose NVD product differs, checked the same way and sorted the same way. Kept
/// apart from formulae because one name can mean different products: the `docker` formula is
/// the CLI, the `docker` cask is Docker Desktop.
const CASK_ALIASES: &[(&str, &[&str])] = &[
    ("docker", &["docker:desktop"]),
    ("google-chrome", &["google:chrome"]),
    ("visual-studio-code", &["microsoft:visual_studio_code"]),
];

/// Adds the installed formulae and casks, and returns the apps the casks put in place: none
/// when Homebrew is not installed, and `None` when `brew` failed, so which apps casks installed
/// is not known.
pub(super) fn collect(inventory: &mut Inventory, cancel: &Cancel) -> Option<CaskApps> {
    let args = ["info", "--json=v2", "--installed"];
    match command::run("brew", &args, cancel) {
        Ok(Some(output)) => parse(&output, inventory),
        Ok(None) => {
            inventory.missing("brew");
            Some(CaskApps::default())
        }
        Err(e) => {
            inventory.fail(InventorySource::Homebrew, e);
            None
        }
    }
}

/// The apps installed casks put in place, each with its cask's token.
#[derive(Debug, Default)]
pub(super) struct CaskApps {
    /// By the app's file name (`Docker.app`), from the casks' `app` artifacts.
    pub(super) by_name: BTreeMap<String, String>,
    /// By the bundle identifiers a cask with no `app` artifact (a `pkg` installer) quits before
    /// it uninstalls (`com.adobe.Reader`). A cask that names its app is known only by that name.
    pub(super) by_identifier: BTreeMap<String, String>,
}

impl CaskApps {
    /// The token of the cask that installed the app with this file name or bundle identifier.
    pub(super) fn token(&self, name: Option<&str>, identifier: Option<&str>) -> Option<&str> {
        let by_name = name.and_then(|name| self.by_name.get(name));
        let by_identifier = || self.by_identifier.get(identifier?);
        by_name.or_else(by_identifier).map(String::as_str)
    }
}

/// Adds every installed formula version and cask from `brew info --json=v2` output, and
/// returns the apps the casks put in place; `None` when the output does not parse.
fn parse(json: &str, inventory: &mut Inventory) -> Option<CaskApps> {
    let info: Info = match serde_json::from_str(json) {
        Ok(info) => info,
        Err(e) => {
            let error = InventoryError::parse("brew info --json=v2", &e);
            inventory.fail(InventorySource::Homebrew, error);
            return None;
        }
    };

    for formula in info.formulae {
        let Some(products) = products(&formula.name, FORMULA_ALIASES) else {
            inventory
                .problems
                .push(InventoryError::NoProduct { name: formula.name });
            continue;
        };
        for installed in &formula.installed {
            let version = without_revision(&installed.version);
            for product in &products {
                let found_in = FoundIn::HomebrewFormula {
                    name: formula.name.clone(),
                };
                inventory.add(Lookup::Product(product.clone()), version, found_in);
            }
        }
    }
    let mut apps = CaskApps::default();
    // A cask's version can be `latest` or carry a build after a comma (`1.2,345`); it is
    // passed on as Homebrew gives it, and the agent reads it with that in mind.
    for cask in info.casks {
        let Some(version) = cask.installed else {
            continue;
        };
        // The first cask listed keeps a name or identifier two of them give, so the result
        // does not depend on which is read last. Homebrew refuses to install a cask's app over
        // another's unless forced, so two names rarely meet.
        let names = app_names(&cask.artifacts);
        // Only a cask with no `app` artifact (a `pkg` installer) is known by what it quits:
        // otherwise an older copy of its app kept a folder down, found first, would claim it.
        let identifiers = if names.is_empty() {
            quit_identifiers(&cask.artifacts)
        } else {
            Vec::new()
        };
        for name in names {
            apps.by_name
                .entry(name)
                .or_insert_with(|| cask.token.clone());
        }
        for identifier in identifiers {
            apps.by_identifier
                .entry(identifier)
                .or_insert_with(|| cask.token.clone());
        }
        let Some(products) = products(&cask.token, CASK_ALIASES) else {
            inventory
                .problems
                .push(InventoryError::NoProduct { name: cask.token });
            continue;
        };
        for product in products {
            let found_in = FoundIn::HomebrewCask {
                token: cask.token.clone(),
            };
            inventory.add(Lookup::Product(product), &version, found_in);
        }
    }
    Some(apps)
}

/// Returns the NVD products for a Homebrew name: its aliases, or else the name itself without
/// `@version`. `None` when that name is not a valid product (such as `gtk+3`).
fn products(name: &str, aliases: &[(&str, &[&str])]) -> Option<Vec<Product>> {
    let base = name.split_once('@').map_or(name, |(base, _)| base);
    let names = match aliases.binary_search_by_key(&base, |(brew, _)| brew) {
        Ok(i) => aliases[i].1,
        Err(_) => std::slice::from_ref(&base),
    };
    names.iter().map(|n| n.parse().ok()).collect()
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
    /// What the cask puts in place, one kind per object (`{"app": ["Docker.app"]}`). Read as
    /// values: the other kinds' shapes vary, and only `app` is read.
    #[serde(default)]
    artifacts: Vec<serde_json::Value>,
}

/// The file names of the apps a cask's `artifacts` put in place. An `app` artifact lists the
/// app in the download, followed by `{"target": ...}` when it is installed under another name
/// (`["Thorium.app", {"target": "Thorium Browser.app"}]`).
fn app_names(artifacts: &[serde_json::Value]) -> Vec<String> {
    let mut names = Vec::new();
    let apps = artifacts.iter().filter_map(|a| a.get("app")?.as_array());
    for app in apps.flatten() {
        match (app.as_str(), app.get("target").and_then(|t| t.as_str())) {
            (Some(source), _) => names.push(source),
            (None, Some(target)) => {
                names.pop();
                names.push(target);
            }
            (None, None) => {}
        }
    }
    names
        .into_iter()
        .filter_map(|name| Some(Path::new(name).file_name()?.to_str()?.to_owned()))
        .collect()
}

/// The bundle identifiers a cask's `uninstall` artifact quits, each given as a string or a
/// list (`{"uninstall": [{"quit": ["com.adobe.Reader", "com.adobe.AdobeRdrCEF"]}]}`). Some
/// name helpers, which no app in `/Applications` has as its identifier.
fn quit_identifiers(artifacts: &[serde_json::Value]) -> Vec<String> {
    let stanzas = artifacts
        .iter()
        .filter_map(|a| a.get("uninstall")?.as_array());
    let quits = stanzas.flatten().filter_map(|stanza| stanza.get("quit"));
    let mut identifiers = Vec::new();
    for quit in quits {
        match quit {
            serde_json::Value::String(id) => identifiers.push(id.clone()),
            serde_json::Value::Array(ids) => {
                let ids = ids.iter().filter_map(serde_json::Value::as_str);
                identifiers.extend(ids.map(str::to_owned));
            }
            _ => {}
        }
    }
    identifiers
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
                {"name": "curl", "installed": [{"version": "8.23.0"}, {"version": "8.22.1_2"}]},
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
                "curl -> curl 8.23.0",
                "curl -> libcurl 8.23.0",
                "curl -> curl 8.22.1",
                "curl -> libcurl 8.22.1",
                "cask codex -> codex 0.128.0",
            ]
        );
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
    }

    #[test]
    fn casks_name_the_apps_they_put_in_place() {
        let mut inventory = Inventory::default();
        let apps = parse(
            r#"{"casks": [
                {"token": "docker", "installed": "4.82.0", "artifacts": [
                    {"uninstall": [{"quit": "com.docker.docker"}]},
                    {"app": ["Docker.app"]}
                ]},
                {"token": "reader", "installed": "25", "artifacts": [
                    {"uninstall": [{"quit": ["com.adobe.Reader", "com.adobe.Helper"]},
                                   {"pkgutil": "com.adobe.acrobat"}]},
                    {"pkg": ["AcroRdr.pkg"]}
                ]},
                {"token": "thorium", "installed": "1", "artifacts": [
                    {"app": ["Thorium.app", {"target": "Thorium Browser.app"}, "Extra.app"]},
                    {"app": ["Tools/Inner.app", {"target": "~/Applications/Moved.app"}]}
                ]},
                {"token": "docker-copy", "installed": "1", "artifacts": [
                    {"uninstall": [{"quit": "com.docker.docker"}]},
                    {"app": ["Docker.app"]}
                ]},
                {"token": "listed-only", "installed": null, "artifacts": [{"app": ["L.app"]}]}
            ]}"#,
            &mut inventory,
        );
        let apps = apps.unwrap();
        let names: Vec<_> = apps
            .by_name
            .iter()
            .map(|(n, t)| format!("{n} {t}"))
            .collect();
        assert_eq!(
            names,
            [
                "Docker.app docker",
                "Extra.app thorium",
                "Moved.app thorium",
                "Thorium Browser.app thorium",
            ]
        );
        assert_eq!(apps.token(Some("Docker.app"), None), Some("docker"));
        // Docker's cask names its app, so what it quits does not name it.
        assert_eq!(apps.token(None, Some("com.docker.docker")), None);
        let reader = apps.token(Some("Other.app"), Some("com.adobe.Reader"));
        assert_eq!(reader, Some("reader"));
        assert_eq!(apps.token(Some("Thorium.app"), Some("com.other")), None);

        let mut inventory = Inventory::default();
        assert!(parse("{", &mut inventory).is_none());
        assert!(inventory.failed.contains(&InventorySource::Homebrew));
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
        assert!(inventory.failed.is_empty(), "Homebrew was still read");
    }

    #[test]
    fn bad_json_is_a_parse_problem_of_homebrew() {
        let inventory = parsed("not json");
        assert!(matches!(
            inventory.problems[..],
            [InventoryError::Parse { .. }]
        ));
        assert_eq!(inventory.failed, [InventorySource::Homebrew].into());
    }

    fn names(name: &str, aliases: &[(&str, &[&str])]) -> Option<Vec<String>> {
        products(name, aliases).map(|ps| ps.iter().map(Product::to_string).collect())
    }

    #[test]
    fn product_names() {
        let formula = |s: &str| names(s, FORMULA_ALIASES);
        assert_eq!(formula("python@3.13").unwrap(), ["python"]);
        assert_eq!(formula("gh").unwrap(), ["github:cli"]);
        assert_eq!(formula("webp").unwrap(), ["libwebp"]);
        assert_eq!(formula("abseil").unwrap(), ["abseil:common_libraries"]);
        assert_eq!(
            formula("icu4c@78").unwrap(),
            ["international_components_for_unicode"]
        );
        assert_eq!(formula("tcl-tk@8").unwrap(), ["tcl"]);
        assert_eq!(formula("curl").unwrap(), ["curl", "libcurl"]);
        assert_eq!(
            formula("libmagic").unwrap(),
            ["christos_zoulas:file", "file_project:file"]
        );
        assert_eq!(formula("git").unwrap(), ["git"]);
        assert_eq!(formula("docker").unwrap(), ["docker"]);
        assert_eq!(formula("gitleaks").unwrap(), ["gitleaks"]);
        assert_eq!(formula("gtk+3"), None);
        assert_eq!(names("docker", CASK_ALIASES).unwrap(), ["docker:desktop"]);
    }

    /// The lookup is a binary search, which misses names out of order and finds only one of
    /// two entries for the same name.
    #[test]
    fn aliases_are_sorted_unique_and_valid() {
        for aliases in [FORMULA_ALIASES, CASK_ALIASES] {
            for pair in aliases.windows(2) {
                assert!(pair[0].0 < pair[1].0, "{} before {}", pair[0].0, pair[1].0);
            }
            for (brew, nvd) in aliases {
                assert!(
                    !brew.contains('@'),
                    "{brew}: products drops @version before the search, so this key never matches"
                );
                assert!(!nvd.is_empty(), "{brew} has no product");
                assert!(
                    nvd.windows(2).all(|p| p[0] < p[1]),
                    "{brew}: products sorted and unique, so none is added twice"
                );
                for product in *nvd {
                    assert!(product.parse::<Product>().is_ok(), "{brew}: {product}");
                }
            }
        }
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
