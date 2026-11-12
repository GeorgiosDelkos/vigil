//! macOS itself and globally installed toolchains: rustup, `cargo install`, Node.js and
//! global npm packages, Python, and uv and pipx tools.
//!
//! Each parser is a plain function over the command's output, so the formats are tested
//! without the tools installed. Only the `node`, `npm` and `python3` first on `PATH` are run.
//! Every Node.js and Python version a version manager keeps is read from its folder in
//! `version_managers`; the global npm packages of versions other than the one on `PATH` are a
//! known gap, recorded in the spec.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::cancel::Cancel;
use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;
use crate::inventory::command;
use crate::package::Ecosystem;
use crate::package::Package;

type Parsed = Result<Vec<Component>, InventoryError>;

pub(super) fn macos(inventory: &mut Inventory, cancel: &Cancel) {
    if let Some(output) = inventory.run("sw_vers", &["-productVersion"], cancel) {
        inventory.absorb(parse_macos_version(&output));
    }
}

pub(super) fn collect(inventory: &mut Inventory, cancel: &Cancel) {
    rustup(inventory, cancel);
    if let Some(output) = inventory.run("cargo", &["install", "--list"], cancel) {
        inventory.absorb(parse_cargo_install(&output));
    }
    if let Some(output) = inventory.run("node", &["--version"], cancel) {
        inventory.absorb(parse_node_version(&output));
    }
    npm_global(inventory, cancel);
    python(inventory, cancel);
    if let Some(output) = inventory.run("uv", &["tool", "list"], cancel) {
        inventory.absorb(parse_uv_tools(&output));
    }
    if let Some(output) = inventory.run("pipx", &["list", "--json"], cancel) {
        inventory.absorb(parse_pipx(&output));
    }
}

fn component(lookup: Lookup, version: &str, found_in: FoundIn) -> Component {
    Component {
        lookup,
        version: version.to_owned(),
        found_in,
    }
}

pub(super) fn product(name: &str) -> Lookup {
    Lookup::Product(name.parse().expect("built-in product names are valid"))
}

fn package(ecosystem: Ecosystem, name: &str) -> Lookup {
    Lookup::Package(Package {
        ecosystem,
        name: name.to_owned(),
    })
}

fn parse_macos_version(output: &str) -> Parsed {
    let version = output.trim();
    if version.is_empty() {
        return Err(InventoryError::parse(
            "sw_vers -productVersion",
            &"empty output",
        ));
    }
    Ok(vec![component(
        product("apple:macos"),
        version,
        FoundIn::MacOs,
    )])
}

/// Each toolchain's version comes from its `rustc`, since `stable` and `nightly` name no
/// version. One toolchain failing does not stop the others.
fn rustup(inventory: &mut Inventory, cancel: &Cancel) {
    let Some(list) = inventory.run("rustup", &["toolchain", "list"], cancel) else {
        return;
    };
    for toolchain in parse_rustup_toolchains(&list) {
        let args = ["run", toolchain.as_str(), "rustc", "--version"];
        if let Some(output) = inventory.run("rustup", &args, cancel) {
            inventory.absorb(parse_rustc_version(&output, toolchain));
        }
    }
}

/// `rustup toolchain list` prints one name per line, with ` (default)` or ` (active)` after,
/// or `no installed toolchains`.
fn parse_rustup_toolchains(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| !line.starts_with("no installed toolchains"))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// `rustc 1.99.1 (58cf8f9c3 2026-10-13)` -> `1.99.1`; nightly prints `1.100.0-nightly`.
fn parse_rustc_version(output: &str, toolchain: String) -> Parsed {
    let mut words = output.split_whitespace();
    match (words.next(), words.next()) {
        (Some("rustc"), Some(version)) => Ok(vec![component(
            product("rust"),
            version,
            FoundIn::Rustup { toolchain },
        )]),
        _ => Err(InventoryError::parse("rustc --version", &output.trim())),
    }
}

/// `cargo install --list` prints `name v1.2.3:` for a crates.io install, `name v1.2.3 (url):`
/// for a git install, and `name v1.2.3 (/path):` for a local path, each followed by indented
/// binary names. Git installs are kept, since a git checkout of a published crate shares its
/// advisories; local paths have no registry advisories.
///
/// A header line in any other shape is an error, so a format change is reported rather than
/// read as "nothing installed".
fn parse_cargo_install(output: &str) -> Parsed {
    let mut components = Vec::new();
    for line in output
        .lines()
        .filter(|l| !l.starts_with(char::is_whitespace))
    {
        let mut words = line
            .strip_suffix(':')
            .unwrap_or_default()
            .split_whitespace();
        let (Some(name), Some(version)) =
            (words.next(), words.next().and_then(|v| v.strip_prefix('v')))
        else {
            return Err(InventoryError::parse("cargo install --list", &line));
        };
        if words.next().is_some_and(|source| source.starts_with("(/")) {
            continue;
        }
        let lookup = package(Ecosystem::CratesIo, name);
        components.push(component(lookup, version, FoundIn::CargoInstall));
    }
    Ok(components)
}

/// `v22.1.0` -> `22.1.0`.
fn parse_node_version(output: &str) -> Parsed {
    let version = output.trim().trim_start_matches('v');
    if version.is_empty() {
        return Err(InventoryError::parse("node --version", &"empty output"));
    }
    Ok(vec![component(product("node.js"), version, FoundIn::Node)])
}

/// `npm ls` exits 1 when the global tree has a problem (a missing peer dependency, an
/// extraneous package) but still prints the whole tree, so its output is used whenever it
/// parses, and the exit status is reported alongside.
fn npm_global(inventory: &mut Inventory, cancel: &Cancel) {
    let args = ["ls", "-g", "--json", "--depth=0"];
    let output = match command::run_any_status("npm", &args, cancel) {
        Ok(Some(output)) => output,
        Ok(None) => {
            inventory.missing("npm");
            return;
        }
        Err(e) => {
            inventory.problems.push(e);
            return;
        }
    };
    match parse_npm_global(&output.stdout) {
        Ok(found) => {
            // A tree problem npm reports while still listing the tree is a lasting fact about
            // this Mac, not a failed source: every package is in `found`.
            if !output.success {
                inventory.problems.push(InventoryError::NpmTree {
                    detail: output.detail,
                });
            }
            inventory.components.extend(found);
        }
        Err(e) if output.success => inventory.problems.push(e),
        Err(_) => inventory.problems.push(InventoryError::Command {
            command: output.command,
            detail: output.detail,
        }),
    }
}

fn parse_npm_global(json: &str) -> Parsed {
    #[derive(Debug, Deserialize)]
    struct Tree {
        #[serde(default)]
        dependencies: BTreeMap<String, Dependency>,
    }
    #[derive(Debug, Deserialize)]
    struct Dependency {
        version: Option<String>,
    }

    // npm can print a second JSON object (its error report) after the tree, so only the first
    // value is read.
    let tree: Tree = serde_json::Deserializer::from_str(json)
        .into_iter()
        .next()
        .ok_or_else(|| InventoryError::parse("npm ls -g --json", &"empty output"))?
        .map_err(|e| InventoryError::parse("npm ls -g --json", &e))?;
    Ok(tree
        .dependencies
        .into_iter()
        .filter_map(|(name, dependency)| {
            let lookup = package(Ecosystem::Npm, &name);
            Some(component(lookup, &dependency.version?, FoundIn::NpmGlobal))
        })
        .collect())
}

/// Reads the `python3` on `PATH`. `/usr/bin/python3` is a stub until the Command Line Tools are
/// installed, and running it then opens an install dialog on every sweep, so it counts as not
/// installed unless `xcode-select -p` finds the tools.
fn python(inventory: &mut Inventory, cancel: &Cancel) {
    let mut problem = None;
    // A non-zero exit from `xcode-select -p` means no tools; any other failure (it cannot be
    // started, hangs, prints something unreadable) is reported, and python3 is then not run.
    let has_tools = || {
        tools_found(
            command::run_any_status("xcode-select", &["-p"], cancel),
            &mut problem,
        )
    };
    let real = python_is_real_at(command::which("python3").as_deref(), has_tools);
    inventory.problems.extend(problem);
    if !real {
        inventory.missing("python3");
    } else if let Some(output) = inventory.run("python3", &["--version"], cancel) {
        inventory.absorb(parse_python_version(&output));
    }
}

/// Reads `xcode-select -p`: the tools are there when it exits 0. A non-zero exit, or no
/// `xcode-select` at all, means they are not; any other failure is put in `problem` and
/// counts as not there.
fn tools_found(
    run: Result<Option<command::Output>, InventoryError>,
    problem: &mut Option<InventoryError>,
) -> bool {
    match run {
        Ok(found) => found.is_some_and(|output| output.success),
        Err(e) => {
            *problem = Some(e);
            false
        }
    }
}

fn python_is_real_at(python3: Option<&Path>, has_tools: impl FnOnce() -> bool) -> bool {
    python3 != Some(Path::new("/usr/bin/python3")) || has_tools()
}

/// `Python 3.13.1` -> `3.13.1`.
fn parse_python_version(output: &str) -> Parsed {
    let version = output
        .trim()
        .strip_prefix("Python ")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| InventoryError::parse("python3 --version", &output.trim()))?;
    Ok(vec![component(product("python"), version, FoundIn::Python)])
}

/// `uv tool list` prints `name v1.2.3` per tool, then its executables as `- exe` lines, or
/// `No tools installed`. Any other line is an error, so a format change is reported rather than
/// read as "nothing installed".
fn parse_uv_tools(output: &str) -> Parsed {
    let mut components = Vec::new();
    for line in output.lines() {
        if line.starts_with('-') || line.trim().is_empty() || line.trim() == "No tools installed" {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(name), Some(version)) =
            (words.next(), words.next().and_then(|v| v.strip_prefix('v')))
        else {
            return Err(InventoryError::parse("uv tool list", &line));
        };
        components.push(component(
            package(Ecosystem::PyPI, name),
            version,
            FoundIn::UvTool,
        ));
    }
    Ok(components)
}

/// Each venv's main package, plus the packages added to it with `pipx inject`.
fn parse_pipx(json: &str) -> Parsed {
    #[derive(Debug, Deserialize)]
    struct List {
        #[serde(default)]
        venvs: BTreeMap<String, Venv>,
    }
    #[derive(Debug, Deserialize)]
    struct Venv {
        metadata: Metadata,
    }
    #[derive(Debug, Deserialize)]
    struct Metadata {
        main_package: PipxPackage,
        #[serde(default)]
        injected_packages: BTreeMap<String, PipxPackage>,
    }
    /// pipx documents `package` as nullable; such an entry is skipped, not the whole list.
    #[derive(Debug, Deserialize)]
    struct PipxPackage {
        package: Option<String>,
        package_version: String,
    }

    let list: List =
        serde_json::from_str(json).map_err(|e| InventoryError::parse("pipx list --json", &e))?;
    Ok(list
        .venvs
        .into_values()
        .flat_map(|venv| {
            let metadata = venv.metadata;
            std::iter::once(metadata.main_package).chain(metadata.injected_packages.into_values())
        })
        .filter_map(|p| {
            let lookup = package(Ecosystem::PyPI, &p.package?);
            Some(component(lookup, &p.package_version, FoundIn::Pipx))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(components: &[Component]) -> Vec<String> {
        components
            .iter()
            .map(|c| match &c.lookup {
                Lookup::Package(p) => {
                    format!("{}:{} {}", p.ecosystem.osv_name(), p.name, c.version)
                }
                Lookup::Product(p) => format!("{p} {}", c.version),
            })
            .collect()
    }

    /// Whichever `python3` this Mac has, a cancelled sweep runs neither it nor `xcode-select`:
    /// either is reported as cancelled, or `python3` is not installed at all.
    #[test]
    fn a_cancelled_sweep_reads_no_python() {
        let cancel = Cancel::new();
        cancel.cancel();
        let mut inventory = Inventory::default();
        python(&mut inventory, &cancel);
        assert!(inventory.components.is_empty());
        let cancelled = matches!(inventory.problems[..], [InventoryError::Cancelled { .. }]);
        assert!(
            cancelled || inventory.not_installed == ["python3"],
            "{:?} {:?}",
            inventory.problems,
            inventory.not_installed
        );
    }

    #[test]
    fn macos_and_node_versions() {
        assert_eq!(
            names(&parse_macos_version("27.2\n").unwrap()),
            ["apple:macos 27.2"]
        );
        assert!(parse_macos_version("\n").is_err());
        assert_eq!(
            names(&parse_node_version("v22.1.0\n").unwrap()),
            ["node.js 22.1.0"]
        );
        assert!(parse_node_version("v\n").is_err());
    }

    #[test]
    fn rustup_toolchains_and_versions() {
        let list = "stable-aarch64-apple-darwin (default)\nnightly-aarch64-apple-darwin\n\
                    1.99.1-aarch64-apple-darwin (active)\n";
        assert_eq!(
            parse_rustup_toolchains(list),
            [
                "stable-aarch64-apple-darwin",
                "nightly-aarch64-apple-darwin",
                "1.99.1-aarch64-apple-darwin"
            ]
        );
        assert_eq!(
            parse_rustup_toolchains("no installed toolchains\n"),
            Vec::<String>::new()
        );
        let parsed = parse_rustc_version("rustc 1.99.1 (58cf8f9c3 2026-10-13)\n", "s".into());
        assert_eq!(names(&parsed.unwrap()), ["rust 1.99.1"]);
        let nightly = parse_rustc_version("rustc 1.100.0-nightly (abc 2026-11-01)", "n".into());
        assert_eq!(names(&nightly.unwrap()), ["rust 1.100.0-nightly"]);
        assert!(parse_rustc_version("error: no such toolchain", "x".into()).is_err());
        assert!(parse_rustc_version("rustc", "x".into()).is_err());
    }

    #[test]
    fn cargo_install_keeps_registry_and_git_installs() {
        let output = "aether-cli v0.1.0 (/Users/me/src/aether):\n    aether\n\
                      cargo-audit v0.22.1:\n    cargo-audit\n\
                      forked v0.3.0 (https://github.com/x/forked#abc123):\n    forked\n";
        assert_eq!(
            names(&parse_cargo_install(output).unwrap()),
            ["crates.io:cargo-audit 0.22.1", "crates.io:forked 0.3.0"]
        );
        assert!(parse_cargo_install("").unwrap().is_empty());
        assert!(parse_cargo_install("warning: something new\n").is_err());
        assert!(parse_cargo_install("tool 1.0:\n").is_err());
    }

    #[test]
    fn npm_global_packages() {
        let json = r#"{"name": "lib", "dependencies": {
            "@google/gemini-cli": {"version": "0.52.0", "overridden": false},
            "npm": {"version": "10.9.7"},
            "broken": {"missing": true}
        }}"#;
        assert_eq!(
            names(&parse_npm_global(json).unwrap()),
            ["npm:@google/gemini-cli 0.52.0", "npm:npm 10.9.7"]
        );
        assert_eq!(
            names(&parse_npm_global("{}").unwrap()),
            Vec::<String>::new()
        );
        assert!(parse_npm_global("[").is_err());
        let with_report = r#"{"dependencies": {"npm": {"version": "10.9.7"}}}
{"error": {"code": "ELSPROBLEMS"}}"#;
        assert_eq!(
            names(&parse_npm_global(with_report).unwrap()),
            ["npm:npm 10.9.7"]
        );
        assert!(
            parse_npm_global("").is_err(),
            "empty output is not \"no packages\""
        );
    }

    #[test]
    fn system_python_stub_needs_the_command_line_tools() {
        let stub = Some(Path::new("/usr/bin/python3"));
        assert!(!python_is_real_at(stub, || false));
        assert!(python_is_real_at(stub, || true));
        let brew = Some(Path::new("/opt/homebrew/bin/python3"));
        assert!(python_is_real_at(brew, || panic!(
            "only the stub needs checking"
        )));
        assert!(python_is_real_at(None, || panic!(
            "a missing python3 is found later"
        )));
    }

    #[test]
    fn xcode_select_verdicts() {
        let output = |success| command::Output {
            success,
            stdout: String::new(),
            detail: String::new(),
            command: "xcode-select -p".to_owned(),
        };
        let mut problem = None;
        assert!(tools_found(Ok(Some(output(true))), &mut problem));
        assert!(!tools_found(Ok(Some(output(false))), &mut problem));
        assert!(!tools_found(Ok(None), &mut problem));
        assert!(problem.is_none(), "a plain answer is not a problem");

        let failed = InventoryError::parse("xcode-select -p", &"hung");
        assert!(!tools_found(Err(failed), &mut problem));
        assert!(matches!(problem, Some(InventoryError::Parse { .. })));
    }

    #[test]
    fn python_version() {
        assert_eq!(
            names(&parse_python_version("Python 3.13.1\n").unwrap()),
            ["python 3.13.1"]
        );
        assert!(parse_python_version("Python \n").is_err());
        assert!(parse_python_version("command not found").is_err());
    }

    #[test]
    fn uv_tools() {
        let output = "ruff v0.6.9\n- ruff\nhttpie v3.2.4\n- http\n- https\n";
        assert_eq!(
            names(&parse_uv_tools(output).unwrap()),
            ["PyPI:ruff 0.6.9", "PyPI:httpie 3.2.4"]
        );
        assert_eq!(
            names(&parse_uv_tools("No tools installed\n").unwrap()),
            Vec::<String>::new()
        );
        assert!(parse_uv_tools("error: failed to read tools\n").is_err());
    }

    #[test]
    fn pipx_venvs_and_injected_packages() {
        let json = r#"{"pipx_spec_version": "0.1", "venvs": {
            "black": {"metadata": {
                "main_package": {"package": "black", "package_version": "24.10.0"},
                "injected_packages": {
                    "black-plugin": {"package": "black-plugin", "package_version": "1.0.0"}
                }
            }},
            "broken": {"metadata": {
                "main_package": {"package": null, "package_version": "0"}
            }}
        }}"#;
        assert_eq!(
            names(&parse_pipx(json).unwrap()),
            ["PyPI:black 24.10.0", "PyPI:black-plugin 1.0.0"]
        );
        assert!(parse_pipx("{").is_err());
    }
}
