//! What is installed: the components a sweep looks up advisories for.
//!
//! Each source (macOS, Homebrew, toolchains, project lockfiles) is collected on its own. A
//! source that fails is reported in [`Inventory::problems`] and the others still count, so one
//! broken tool never hides the rest. A tool that is not installed is listed in
//! [`Inventory::not_installed`], so an inventory taken with a bare `PATH` (an app started by
//! launchd gets `/usr/bin:/bin:/usr/sbin:/sbin`) shows what it did not check.
//!
//! Collecting only reads: it runs listing commands, lists version managers' folders and parses
//! lockfiles, never project code.

pub(crate) mod command;
mod homebrew;
pub(crate) mod lockfiles;
mod toolchains;
mod version_managers;

use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::cancel::Cancel;
use crate::feeds::Product;
use crate::package::Package;

/// Everything found installed, plus what could not be collected.
#[derive(Debug, Default)]
pub struct Inventory {
    /// Installed components, in collection order. The same component appears once per place it
    /// was found, except the `node` or `python3` on `PATH`, which is left out when another place
    /// has the same product and version.
    pub components: Vec<Component>,
    /// Sources or files that could not be read, names that cannot be looked up, and notes on
    /// sources that were still read (see [`InventoryError::is_failure`]).
    pub problems: Vec<InventoryError>,
    /// Listing tools that are not on `PATH`, so their part was not checked.
    pub not_installed: Vec<&'static str>,
}

impl Inventory {
    /// Collects this Mac's inventory: macOS, Homebrew, toolchains, and lockfiles under
    /// `project_dirs`.
    ///
    /// Runs read-only listing commands (`sw_vers`, `brew`, `rustup`, `cargo`, `npm`, `node`,
    /// `python3`, `uv`, `pipx`) found on `PATH`, each from `/` with a one-minute limit, lists
    /// the folders where version managers (nvm, fnm, volta, asdf, pyenv) keep Node.js and
    /// Python versions, and walks `project_dirs`. Blocks until all of them finish; `brew info`
    /// alone can take several seconds, and the walk is limited to ten minutes.
    ///
    /// Once `cancel` is set, the running command or walk stops and nothing more is started:
    /// the result is then incomplete, with [`InventoryError::Cancelled`] in its problems.
    pub fn collect_mac(project_dirs: &[PathBuf], cancel: &Cancel) -> Self {
        let mut inventory = Self::default();
        toolchains::macos(&mut inventory, cancel);
        homebrew::collect(&mut inventory, cancel);
        toolchains::collect(&mut inventory, cancel);
        // Lists a few known folders on this thread, unbounded: a manager's folder on a mount
        // that does not answer (`NVM_DIR` on a dead share) would hang it, which is rare enough
        // to accept, unlike a project folder walk. It starts no listing once cancelled.
        if !cancel.is_cancelled() {
            version_managers::collect(&mut inventory);
        }
        drop_path_duplicates(&mut inventory.components);
        lockfiles::collect(project_dirs, &mut inventory, cancel);
        inventory
    }

    fn add(&mut self, lookup: Lookup, version: impl Into<String>, found_in: FoundIn) {
        self.components.push(Component {
            lookup,
            version: version.into(),
            found_in,
        });
    }

    /// Adds `result`'s components, or records its error.
    fn absorb(&mut self, result: Result<Vec<Component>, InventoryError>) {
        match result {
            Ok(components) => self.components.extend(components),
            Err(e) => self.problems.push(e),
        }
    }

    /// Records that `program` is not installed, once.
    fn missing(&mut self, program: &'static str) {
        if !self.not_installed.contains(&program) {
            self.not_installed.push(program);
        }
    }

    /// Runs a listing command, recording a failure as a problem and a missing tool in
    /// `not_installed`. Returns stdout only when the command succeeded.
    fn run(&mut self, program: &'static str, args: &[&str], cancel: &Cancel) -> Option<String> {
        match command::run(program, args, cancel) {
            Ok(Some(output)) => Some(output),
            Ok(None) => {
                self.missing(program);
                None
            }
            Err(e) => {
                self.problems.push(e);
                None
            }
        }
    }
}

/// Drops the `node` or `python3` on `PATH` when any other component (in practice a version
/// manager's or a Homebrew formula's) has the same product at the same version. The `PATH` one
/// is most likely that install, reached through the manager's shim or Homebrew's `bin` folder
/// on `PATH`. The other entry is the one kept: it names the tool that removes or upgrades the
/// version, and its finding key does not change with the `PATH` Vigil started with.
///
/// The accepted downside: a separate install at the same version (the nodejs.org installer's
/// `/usr/local/bin/node` next to Homebrew's `node` at that version) is reported only once the
/// other copy is gone or upgraded.
fn drop_path_duplicates(components: &mut Vec<Component>) {
    let is_path_runtime = |c: &Component| matches!(c.found_in, FoundIn::Node | FoundIn::Python);
    let product_version = |c: &Component| match &c.lookup {
        Lookup::Product(p) => Some((p.to_string(), c.version.clone())),
        Lookup::Package(_) => None,
    };
    let others: Vec<_> = components
        .iter()
        .filter(|c| !is_path_runtime(c))
        .filter_map(product_version)
        .collect();
    components.retain(|c| {
        !is_path_runtime(c) || product_version(c).is_none_or(|pv| !others.contains(&pv))
    });
}

/// One installed thing at one version, and where it was found.
#[derive(Debug, Clone, Serialize)]
pub struct Component {
    /// How advisories are looked up for it.
    pub lookup: Lookup,
    /// The version as the source reports it: installed, or for a dependency graph a manifest
    /// range (`^1.2.0`) or `unknown` when the graph has none.
    pub version: String,
    /// Where it was found.
    pub found_in: FoundIn,
}

/// How a component's advisories are found.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lookup {
    /// An OSV package (ecosystem and name).
    Package(Package),
    /// An NVD CPE product, `name` or `vendor:name`.
    Product(Product),
}

/// Where a component was found, so the agent knows what to check and what to fix.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FoundIn {
    /// The operating system.
    MacOs,
    /// A Homebrew formula, by its Homebrew name (`openssl@3`).
    HomebrewFormula {
        /// The formula name.
        name: String,
    },
    /// A Homebrew cask, by its token.
    HomebrewCask {
        /// The cask token.
        token: String,
    },
    /// A rustup toolchain, by its name (`stable-aarch64-apple-darwin`).
    Rustup {
        /// The toolchain name.
        toolchain: String,
    },
    /// A binary installed with `cargo install`.
    CargoInstall,
    /// The `node` on `PATH`.
    Node,
    /// A package installed with `npm install -g`.
    NpmGlobal,
    /// The `python3` on `PATH`.
    Python,
    /// A tool installed with `uv tool install`.
    UvTool,
    /// A tool installed with `pipx install`.
    Pipx,
    /// A runtime version a version manager installed, by its folder
    /// (`~/.nvm/versions/node/v22.1.0`).
    VersionManager {
        /// The version manager.
        manager: VersionManager,
        /// The version's folder.
        path: PathBuf,
    },
    /// A lockfile in a project folder.
    Lockfile {
        /// The lockfile's path.
        path: PathBuf,
    },
    /// OS packages built from one source package, by their installed names (`libssl3`,
    /// `openssl`). The component's name is the source package's, as OSV names it.
    OsPackage {
        /// The installed (binary) packages.
        packages: Vec<String>,
    },
    /// A GitHub repository's dependency graph, on its default branch.
    DependencyGraph {
        /// The repository, `owner/name`.
        repo: String,
    },
}

impl FoundIn {
    /// Whether this place is one installed thing, all of whose components one upgrade
    /// replaces: one Homebrew formula can map to several NVD products (curl and libcurl), all
    /// at its version. A lockfile, a dependency graph, npm's global packages or macOS hold
    /// many things, each upgraded on its own.
    pub(crate) fn is_one_install(&self) -> bool {
        match self {
            Self::HomebrewFormula { .. }
            | Self::HomebrewCask { .. }
            | Self::Rustup { .. }
            | Self::Node
            | Self::Python
            | Self::VersionManager { .. }
            | Self::OsPackage { .. } => true,
            Self::MacOs
            | Self::CargoInstall
            | Self::NpmGlobal
            | Self::UvTool
            | Self::Pipx
            | Self::Lockfile { .. }
            | Self::DependencyGraph { .. } => false,
        }
    }

    /// The name this place gives what it installed, when that names it better than any one of
    /// its products: a Homebrew formula's name (`curl`, for curl and libcurl) or a cask's token.
    pub(crate) fn install_name(&self) -> Option<&str> {
        match self {
            Self::HomebrewFormula { name } => Some(name),
            Self::HomebrewCask { token } => Some(token),
            Self::MacOs
            | Self::Rustup { .. }
            | Self::CargoInstall
            | Self::Node
            | Self::NpmGlobal
            | Self::Python
            | Self::UvTool
            | Self::Pipx
            | Self::VersionManager { .. }
            | Self::Lockfile { .. }
            | Self::OsPackage { .. }
            | Self::DependencyGraph { .. } => None,
        }
    }
}

/// How a person reads it: "Homebrew formula openssl@3", "lockfile /path/Cargo.lock".
impl std::fmt::Display for FoundIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MacOs => f.write_str("macOS"),
            Self::HomebrewFormula { name } => write!(f, "Homebrew formula {name}"),
            Self::HomebrewCask { token } => write!(f, "Homebrew cask {token}"),
            Self::Rustup { toolchain } => write!(f, "rustup toolchain {toolchain}"),
            Self::CargoInstall => f.write_str("cargo install"),
            Self::Node => f.write_str("the node on PATH"),
            Self::NpmGlobal => f.write_str("npm global packages"),
            Self::Python => f.write_str("the python3 on PATH"),
            Self::UvTool => f.write_str("uv tools"),
            Self::Pipx => f.write_str("pipx"),
            Self::VersionManager { manager, path } => {
                write!(f, "{} {}", manager.name(), path.display())
            }
            Self::Lockfile { path } => write!(f, "lockfile {}", path.display()),
            Self::OsPackage { packages } => write!(f, "OS packages {}", packages.join(", ")),
            Self::DependencyGraph { repo } => write!(f, "the dependency graph of {repo}"),
        }
    }
}

/// A version manager that keeps several versions of a runtime side by side.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionManager {
    /// nvm, for Node.js.
    Nvm,
    /// fnm, for Node.js.
    Fnm,
    /// Volta, for Node.js.
    Volta,
    /// asdf, for Node.js and Python.
    Asdf,
    /// pyenv, for Python.
    Pyenv,
}

impl VersionManager {
    /// The manager's command name, as in `nvm uninstall`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Nvm => "nvm",
            Self::Fnm => "fnm",
            Self::Volta => "volta",
            Self::Asdf => "asdf",
            Self::Pyenv => "pyenv",
        }
    }
}

/// A source or file that could not be collected, or a name that cannot be looked up.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// A listing command exists but could not be started, waited for, or its output read.
    #[error("cannot run `{command}`")]
    Spawn {
        /// The command line.
        command: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A listing command exited with an error or ran too long.
    #[error("`{command}` failed: {detail}")]
    Command {
        /// The command line.
        command: String,
        /// The exit status and the start of its stderr.
        detail: String,
    },
    /// A command's output or a lockfile was not in the expected format.
    #[error("cannot parse {what}: {detail}")]
    Parse {
        /// The command or file.
        what: String,
        /// What did not match.
        detail: String,
    },
    /// A file or folder could not be read.
    #[error("cannot read {}", path.display())]
    Io {
        /// The path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A `Cargo.lock` uses crates from a registry other than crates.io; they are not checked.
    #[error(
        "{} uses crates from {registry}, which are not checked: OSV covers crates.io only",
        path.display()
    )]
    OtherRegistry {
        /// The lockfile.
        path: PathBuf,
        /// The registry source, as Cargo.lock names it.
        registry: String,
    },
    /// `npm ls -g` reported a problem in the global tree but still listed it, so its packages
    /// are in the inventory.
    #[error(
        "`npm ls -g` reports a problem in the global packages (they are still listed): {detail}"
    )]
    NpmTree {
        /// The exit status and the start of npm's stderr.
        detail: String,
    },
    /// A Homebrew formula or cask name cannot be an NVD product name, so it is not checked.
    #[error("no NVD product name for Homebrew {name:?}; it is not checked")]
    NoProduct {
        /// The formula name or cask token.
        name: String,
    },
    /// The sweep was cancelled, so a command or the project folder walk was stopped or not
    /// started.
    #[error("stopped {what}: the sweep was cancelled")]
    Cancelled {
        /// The command line, or the project folder walk.
        what: String,
    },
    /// A project folder holds more entries than the walk lists, so the walk stopped there and
    /// lockfiles past that point are not checked.
    #[error(
        "{} holds more than {limit} entries, so the lockfile walk stopped there; choose \
         narrower project folders in the settings",
        root.display()
    )]
    TooManyEntries {
        /// The project folder.
        root: PathBuf,
        /// How many entries the walk lists in one project folder.
        limit: usize,
    },
    /// The project folder walk did not finish in time: a folder under `root` is not answering,
    /// such as a network share whose server is gone.
    #[error(
        "the lockfile walk did not finish {} in {} minutes and was stopped, so its lockfiles and \
         those of the project folders after it are not checked; a folder in it is not answering \
         (a network share whose server is gone?)",
        root.display(),
        limit.as_secs() / 60
    )]
    WalkTimedOut {
        /// The project folder it stopped in.
        root: PathBuf,
        /// How long the walk may take.
        limit: std::time::Duration,
    },
    /// A lockfile is in iCloud only, so it is not read: reading it would download it.
    #[error(
        "{} is in iCloud only and was not read, as reading it would download it; download it \
         in Finder to have it checked",
        path.display()
    )]
    CloudOnly {
        /// The lockfile.
        path: PathBuf,
    },
}

impl InventoryError {
    /// Returns whether a source failed, as opposed to a lasting fact about one item (a
    /// Homebrew name with no NVD product) that the next sweep would report again.
    pub fn is_failure(&self) -> bool {
        match self {
            Self::Spawn { .. }
            | Self::Command { .. }
            | Self::Parse { .. }
            | Self::Io { .. }
            | Self::Cancelled { .. }
            | Self::WalkTimedOut { .. } => true,
            // Each is about one item, and the next sweep reports it again: a project folder
            // holds as many entries then, and a lockfile in iCloud stays there.
            Self::NoProduct { .. }
            | Self::OtherRegistry { .. }
            | Self::NpmTree { .. }
            | Self::TooManyEntries { .. }
            | Self::CloudOnly { .. } => false,
        }
    }

    fn parse(what: impl Into<String>, detail: &impl ToString) -> Self {
        Self::Parse {
            what: what.into(),
            detail: detail.to_string(),
        }
    }

    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_place_reads_back_as_written_and_says_how_it_groups() {
        let places = [
            (FoundIn::MacOs, false),
            (
                FoundIn::HomebrewFormula {
                    name: "curl".to_owned(),
                },
                true,
            ),
            (
                FoundIn::HomebrewCask {
                    token: "firefox".to_owned(),
                },
                true,
            ),
            (
                FoundIn::Rustup {
                    toolchain: "stable".to_owned(),
                },
                true,
            ),
            (FoundIn::CargoInstall, false),
            (FoundIn::Node, true),
            (FoundIn::NpmGlobal, false),
            (FoundIn::Python, true),
            (FoundIn::UvTool, false),
            (FoundIn::Pipx, false),
            (
                FoundIn::VersionManager {
                    manager: VersionManager::Nvm,
                    path: PathBuf::from("/v"),
                },
                true,
            ),
            (
                FoundIn::Lockfile {
                    path: PathBuf::from("/l"),
                },
                false,
            ),
            (
                FoundIn::OsPackage {
                    packages: vec!["libssl3".to_owned()],
                },
                true,
            ),
            (
                FoundIn::DependencyGraph {
                    repo: "o/r".to_owned(),
                },
                false,
            ),
        ];
        for (place, one) in places {
            let value = serde_json::to_value(&place).unwrap();
            let back = FoundIn::deserialize(&value).unwrap();
            assert_eq!(back.to_string(), place.to_string());
            assert_eq!(place.is_one_install(), one, "{place}");
        }
        for manager in [
            VersionManager::Fnm,
            VersionManager::Volta,
            VersionManager::Asdf,
            VersionManager::Pyenv,
        ] {
            let value = serde_json::to_value(manager).unwrap();
            assert_eq!(
                VersionManager::deserialize(&value).unwrap().name(),
                manager.name()
            );
        }
        let formula = FoundIn::HomebrewFormula {
            name: "openssl@3".to_owned(),
        };
        assert_eq!(formula.install_name(), Some("openssl@3"));
        assert_eq!(FoundIn::Python.install_name(), None);
    }

    #[test]
    fn missing_tools_are_listed_once() {
        let mut inventory = Inventory::default();
        assert_eq!(
            inventory.run("vigil-no-such-tool", &[], &Cancel::new()),
            None
        );
        assert_eq!(
            inventory.run("vigil-no-such-tool", &["x"], &Cancel::new()),
            None
        );
        assert_eq!(inventory.not_installed, ["vigil-no-such-tool"]);
        assert_eq!(
            inventory.run("echo", &["hi"], &Cancel::new()).as_deref(),
            Some("hi\n")
        );
        assert_eq!(inventory.run("false", &[], &Cancel::new()), None);
        assert!(matches!(
            inventory.problems[..],
            [InventoryError::Command { .. }]
        ));
    }

    #[test]
    fn found_in_reads_like_a_place() {
        let cases = [
            (FoundIn::MacOs, "macOS"),
            (
                FoundIn::HomebrewFormula {
                    name: "openssl@3".into(),
                },
                "Homebrew formula openssl@3",
            ),
            (
                FoundIn::HomebrewCask {
                    token: "codex".into(),
                },
                "Homebrew cask codex",
            ),
            (
                FoundIn::Rustup {
                    toolchain: "stable".into(),
                },
                "rustup toolchain stable",
            ),
            (FoundIn::CargoInstall, "cargo install"),
            (FoundIn::Node, "the node on PATH"),
            (FoundIn::NpmGlobal, "npm global packages"),
            (FoundIn::Python, "the python3 on PATH"),
            (FoundIn::UvTool, "uv tools"),
            (FoundIn::Pipx, "pipx"),
            (
                FoundIn::VersionManager {
                    manager: VersionManager::Nvm,
                    path: "/Users/me/.nvm/versions/node/v22.22.2".into(),
                },
                "nvm /Users/me/.nvm/versions/node/v22.22.2",
            ),
            (
                FoundIn::Lockfile {
                    path: "/p/Cargo.lock".into(),
                },
                "lockfile /p/Cargo.lock",
            ),
            (
                FoundIn::OsPackage {
                    packages: vec!["libssl3".into(), "openssl".into()],
                },
                "OS packages libssl3, openssl",
            ),
            (
                FoundIn::DependencyGraph { repo: "o/r".into() },
                "the dependency graph of o/r",
            ),
        ];
        for (found_in, text) in cases {
            assert_eq!(found_in.to_string(), text);
        }
    }

    #[test]
    fn version_manager_is_serialized_by_name_and_folder() {
        let found_in = FoundIn::VersionManager {
            manager: VersionManager::Pyenv,
            path: "/Users/me/.pyenv/versions/3.13.1".into(),
        };
        let json = r#"{"kind":"version_manager","manager":"pyenv","#.to_owned()
            + r#""path":"/Users/me/.pyenv/versions/3.13.1"}"#;
        assert_eq!(serde_json::to_string(&found_in).unwrap(), json);
    }

    #[test]
    fn only_source_errors_are_failures() {
        assert!(InventoryError::parse("x", &"y").is_failure());
        assert!(!InventoryError::NoProduct { name: "x".into() }.is_failure());
        let other = InventoryError::OtherRegistry {
            path: PathBuf::from("/p/Cargo.lock"),
            registry: "sparse+https://x/".into(),
        };
        assert!(!other.is_failure());
        assert!(other.to_string().contains("OSV covers crates.io only"));
    }

    /// What is left after [`drop_path_duplicates`], as `version [found_in]`.
    fn deduplicated(mut components: Vec<Component>) -> Vec<String> {
        drop_path_duplicates(&mut components);
        components
            .iter()
            .map(|c| format!("{} [{}]", c.version, c.found_in))
            .collect()
    }

    fn at(product: &str, version: &str, found_in: FoundIn) -> Component {
        Component {
            lookup: Lookup::Product(product.parse().unwrap()),
            version: version.to_owned(),
            found_in,
        }
    }

    fn formula(name: &str) -> FoundIn {
        FoundIn::HomebrewFormula { name: name.into() }
    }

    #[test]
    fn the_path_runtime_is_dropped_when_a_manager_has_its_version() {
        let managed = |product: &str, version: &str| {
            let found_in = FoundIn::VersionManager {
                manager: VersionManager::Asdf,
                path: PathBuf::from(format!("/m/{version}")),
            };
            at(product, version, found_in)
        };
        let components = vec![
            at("node.js", "22.1.0", FoundIn::Node),
            at("python", "3.13.1", FoundIn::Python),
            at("node.js", "20.0.0", FoundIn::Node),
            managed("node.js", "22.1.0"),
            managed("python", "3.13.1"),
            managed("python", "20.0.0"),
        ];
        assert_eq!(
            deduplicated(components),
            [
                "20.0.0 [the node on PATH]",
                "22.1.0 [asdf /m/22.1.0]",
                "3.13.1 [asdf /m/3.13.1]",
                "20.0.0 [asdf /m/20.0.0]",
            ],
            "only a PATH runtime with a managed twin of the same product and version goes"
        );
    }

    #[test]
    fn the_path_runtime_is_dropped_when_a_formula_has_its_version() {
        let components = vec![
            at("python", "3.14.6", FoundIn::Python),
            at("node.js", "24.1.0", FoundIn::Node),
            at("python", "3.14.6", formula("python@3.14")),
            at("node.js", "24.1.0", formula("node")),
        ];
        assert_eq!(
            deduplicated(components),
            [
                "3.14.6 [Homebrew formula python@3.14]",
                "24.1.0 [Homebrew formula node]",
            ]
        );
    }

    #[test]
    fn the_path_runtime_is_kept_when_version_or_product_differs() {
        let components = vec![
            at("python", "3.14.6", FoundIn::Python),
            at("python", "3.13.1", formula("python@3.13")),
            at("node.js", "3.14.6", formula("node")),
        ];
        assert_eq!(
            deduplicated(components),
            [
                "3.14.6 [the python3 on PATH]",
                "3.13.1 [Homebrew formula python@3.13]",
                "3.14.6 [Homebrew formula node]",
            ]
        );
    }

    #[test]
    fn absorb_keeps_components_and_problems() {
        let mut inventory = Inventory::default();
        inventory.absorb(Ok(vec![Component {
            lookup: Lookup::Product("curl".parse().unwrap()),
            version: "8".into(),
            found_in: FoundIn::MacOs,
        }]));
        inventory.absorb(Err(InventoryError::parse("x", &"y")));
        assert_eq!(inventory.components.len(), 1);
        assert_eq!(inventory.problems.len(), 1);
    }
}
