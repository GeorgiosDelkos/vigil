//! Node.js and Python versions kept by version managers: nvm, fnm, Volta, asdf and pyenv.
//!
//! Each manager keeps one folder per installed version, so the versions are read by listing
//! those folders. No command runs, so the result does not depend on the `PATH` Vigil started
//! with, nor on which version the shell would pick: every installed version counts, since an
//! unused one is still on disk and one `nvm use` away.
//!
//! The managers' global packages (`npm install -g` under an nvm version) are not read.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;
use crate::inventory::VersionManager;
use crate::inventory::toolchains::product;

/// Adds every version the managers in this user's home folder installed.
///
/// The managers' environment variables (`NVM_DIR`, ...) are read from Vigil's own environment.
/// An app started at login does not have the ones a shell profile sets, and then the default
/// folders are read.
pub(super) fn collect(inventory: &mut Inventory) {
    let Some(home) = std::env::home_dir() else {
        inventory.problems.push(InventoryError::Io {
            path: PathBuf::from("~"),
            source: io::Error::new(io::ErrorKind::NotFound, "no home folder: set HOME"),
        });
        return;
    };
    let env = |name: &str| std::env::var_os(name).map(PathBuf::from);
    for layout in layouts(&home, env) {
        inventory.absorb(read_versions(&layout));
    }
}

/// Where one manager keeps one runtime: `dir` holds a folder per version, named as
/// [`version_prefix`] says.
#[derive(Debug)]
struct Layout {
    manager: VersionManager,
    dir: PathBuf,
    product: &'static str,
}

/// What comes before the version in the name of a manager's version folder.
fn version_prefix(manager: VersionManager) -> &'static str {
    match manager {
        VersionManager::Nvm | VersionManager::Fnm => "v",
        VersionManager::Volta | VersionManager::Asdf | VersionManager::Pyenv => "",
    }
}

/// Each manager's folders, found as the manager finds them. `env` reads an environment
/// variable.
fn layouts(home: &Path, env: impl Fn(&str) -> Option<PathBuf>) -> Vec<Layout> {
    // An empty or relative value names no folder Vigil can find: a relative one is resolved
    // against the working folder of the shell that set it, which Vigil does not know. Both
    // fall back to the defaults.
    let env = |name: &str| env(name).filter(|p| p.is_absolute());
    let layout = |manager, dir: PathBuf, product| Layout {
        manager,
        dir,
        product,
    };
    // nvm: `$NVM_DIR`, which install.sh sets to `$XDG_CONFIG_HOME/nvm` or `~/.nvm` and writes
    // into the shell profile; versions from Node 0.12 on are in `versions/node/v<version>`.
    // Older ones (in `$NVM_DIR` itself) and io.js are not read. Without `NVM_DIR` (an app
    // started at login does not read `.zshrc`) both defaults are read: the variable that picked
    // one at install time may be unset too, and a missing folder gives nothing.
    // https://github.com/nvm-sh/nvm/blob/4e8758a801eea9479b32a904f31093e410ddaba4/install.sh#L35-L45
    // https://github.com/nvm-sh/nvm/blob/4e8758a801eea9479b32a904f31093e410ddaba4/nvm.sh#L1132-L1170
    let nvm = env("NVM_DIR").map_or_else(
        || {
            let xdg = env("XDG_CONFIG_HOME").map(|d| d.join("nvm"));
            xdg.into_iter().chain([home.join(".nvm")]).collect()
        },
        |dir| vec![dir],
    );
    // Volta: `$VOLTA_HOME` or `~/.volta`, versions in `tools/image/node/<version>`.
    // https://github.com/volta-cli/volta/blob/5eedd5fb2f682baceb47a242289111fcd79435a5/crates/volta-layout/src/v4.rs#L7-L42
    // https://github.com/volta-cli/volta/blob/5eedd5fb2f682baceb47a242289111fcd79435a5/crates/volta-core/src/layout/mod.rs#L23-L32
    // https://github.com/volta-cli/volta/blob/5eedd5fb2f682baceb47a242289111fcd79435a5/crates/volta-core/src/layout/unix.rs#L6-L10
    let volta = env("VOLTA_HOME").unwrap_or_else(|| home.join(".volta"));
    // asdf: `$ASDF_DATA_DIR` or `~/.asdf`, versions in `installs/<plugin>/<version>`; the
    // plugins are named `nodejs` and `python`.
    // https://github.com/asdf-vm/asdf/blob/5ddd8f85b2165e3b6f9e67385c8f5beba479abb6/internal/config/config.go#L17
    // https://github.com/asdf-vm/asdf/blob/5ddd8f85b2165e3b6f9e67385c8f5beba479abb6/internal/config/config.go#L105-L108
    // https://github.com/asdf-vm/asdf/blob/5ddd8f85b2165e3b6f9e67385c8f5beba479abb6/internal/data/data.go#L23-L25
    let asdf = env("ASDF_DATA_DIR").unwrap_or_else(|| home.join(".asdf"));
    // pyenv: `$PYENV_ROOT` or `~/.pyenv`, versions in `versions/<version>`.
    // https://github.com/pyenv/pyenv/blob/9e40c078c0f86eae0d96e114269e934681745625/libexec/pyenv#L58-L63
    // https://github.com/pyenv/pyenv/blob/9e40c078c0f86eae0d96e114269e934681745625/libexec/pyenv-versions#L43
    let pyenv = env("PYENV_ROOT").unwrap_or_else(|| home.join(".pyenv"));

    let nvm = nvm
        .into_iter()
        .map(|dir| layout(VersionManager::Nvm, dir.join("versions/node"), "node.js"));
    let fnm = fnm_dirs(home, &env)
        .into_iter()
        .map(|dir| layout(VersionManager::Fnm, dir, "node.js"));
    let mut layouts: Vec<Layout> = nvm.chain(fnm).collect();
    layouts.extend([
        layout(
            VersionManager::Volta,
            volta.join("tools/image/node"),
            "node.js",
        ),
        layout(
            VersionManager::Asdf,
            asdf.join("installs/nodejs"),
            "node.js",
        ),
        layout(VersionManager::Asdf, asdf.join("installs/python"), "python"),
        layout(VersionManager::Pyenv, pyenv.join("versions"), "python"),
    ]);
    layouts
}

/// fnm's `node-versions` folders: under `$FNM_DIR`, else under each of `$XDG_DATA_HOME/fnm`
/// (`~/.local/share/fnm`), `~/.fnm` and `~/Library/Application Support/fnm`. Versions are in
/// `node-versions/v<version>`.
///
/// fnm itself uses the first of those that exists, but it creates the first one on any run,
/// before an install, and `fnm env` writes `FNM_DIR` into `.zshrc`, which an app started at
/// login does not read. So each is read, and a missing one gives nothing.
// https://github.com/Schniz/fnm/blob/07f13237ae208f531f8ea88d4cfde3160c22f99a/src/directories.rs#L47-L69
// https://github.com/Schniz/fnm/blob/07f13237ae208f531f8ea88d4cfde3160c22f99a/src/config.rs#L143-L154
fn fnm_dirs(home: &Path, env: &impl Fn(&str) -> Option<PathBuf>) -> Vec<PathBuf> {
    let bases = env("FNM_DIR").map_or_else(
        || {
            let data = env("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
            vec![
                data.join("fnm"),
                home.join(".fnm"),
                home.join("Library/Application Support/fnm"),
            ]
        },
        |dir| vec![dir],
    );
    bases
        .into_iter()
        .map(|base| base.join("node-versions"))
        .collect()
}

/// One component per version folder in `layout.dir`, sorted by folder name. A missing folder
/// means the manager is not installed: no components and no problem.
fn read_versions(layout: &Layout) -> Result<Vec<Component>, InventoryError> {
    let io_error = |source| InventoryError::Io {
        path: layout.dir.clone(),
        source,
    };
    let entries = match fs::read_dir(&layout.dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_error(e)),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io_error)?;
        // pyenv-virtualenv adds each virtualenv to `versions` as a symlink into the version it
        // was made from, and asdf aliases are symlinks too, so only real folders count.
        if entry.file_type().map_err(io_error)?.is_dir() {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths
        .into_iter()
        .filter_map(|path| {
            let version =
                version(path.file_name()?.to_str()?, version_prefix(layout.manager))?.to_owned();
            Some(Component {
                lookup: product(layout.product),
                version,
                found_in: FoundIn::VersionManager {
                    manager: layout.manager,
                    path,
                },
            })
        })
        .collect())
}

/// The version a folder name gives after `prefix`, when it is one: a release of numbers and
/// dots, then an optional pre-release of lowercase letters and digits (`22.1.0`, `3.13.1`,
/// `3.15.0a1`, `3.14.0rc1`). pyenv's free-threaded builds (`3.13.1t`) are the same Python
/// release, so the `t` is dropped: advisories and `python3 --version` name `3.13.1`.
///
/// Every other name is skipped. fnm's `.downloads` is not an install. pyenv's `3.14-dev` is
/// built from a branch, and asdf's `ref-<git ref>` from a commit, so neither names a release.
/// pyenv's other distributions (`pypy3.10-7.3.15`, `graalpy-24.1`, `anaconda3-2024.06`) name
/// no version of the reference Python: the first two are other implementations, and a conda
/// folder gives the distribution's release, not the version of the Python inside. Reading
/// those would take running them, which this module never does; they are left out, a gap the
/// spec records.
fn version<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let name = name.strip_prefix(prefix)?;
    let version = name.strip_suffix('t').unwrap_or(name);
    let release_end = version
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(version.len());
    let (release, pre) = version.split_at(release_end);
    let release_ok = release
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    let letters = pre.trim_end_matches(|c: char| c.is_ascii_digit());
    // `pre` starts with the first character that is not a digit or a dot, so `letters` is
    // empty only when `pre` is; ending in a digit is what needs checking.
    let pre_ok = pre.is_empty()
        || (letters.len() < pre.len() && letters.bytes().all(|b| b.is_ascii_lowercase()));
    (release_ok && pre_ok).then_some(version)
}

/// Drops the `node` or `python3` on `PATH` when a version manager has the same product at the
/// same version. It is most likely that install, reached through the manager's shim or `PATH`
/// entry. The manager's entry is the one kept: it names the manager that removes the version,
/// and its finding key does not change with the `PATH` Vigil started with.
///
/// The accepted downside: a separate install at the same version (the nodejs.org installer's
/// `/usr/local/bin/node`) is reported only once the manager's copy is gone.
pub(super) fn drop_path_duplicates(components: &mut Vec<Component>) {
    let product_version = |c: &Component| match &c.lookup {
        Lookup::Product(p) => Some((p.to_string(), c.version.clone())),
        Lookup::Package(_) => None,
    };
    let managed: Vec<_> = components
        .iter()
        .filter(|c| matches!(c.found_in, FoundIn::VersionManager { .. }))
        .filter_map(product_version)
        .collect();
    components.retain(|c| {
        !matches!(c.found_in, FoundIn::Node | FoundIn::Python)
            || product_version(c).is_none_or(|pv| !managed.contains(&pv))
    });
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn mkdir(path: &Path) {
        fs::create_dir_all(path).unwrap();
    }

    /// `node.js 22.1.0 [nvm ~/.nvm/versions/node/v22.1.0]` per component found under `home`,
    /// with `vars` as the environment.
    fn found(home: &Path, vars: &[(&str, PathBuf)]) -> Vec<String> {
        let env = |name: &str| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, p)| p.clone())
        };
        let home_text = home.to_str().unwrap();
        layouts(home, env)
            .iter()
            .flat_map(|layout| read_versions(layout).unwrap())
            .map(|c| {
                let Lookup::Product(product) = &c.lookup else {
                    panic!("version managers hold products, not packages");
                };
                let place = c.found_in.to_string().replace(home_text, "~");
                format!("{product} {} [{place}]", c.version)
            })
            .collect()
    }

    #[test]
    fn every_manager_in_its_default_folder() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        for dir in [
            ".nvm/versions/node/v22.22.2",
            ".nvm/versions/node/v22.23.4",
            ".local/share/fnm/node-versions/v20.1.0",
            ".volta/tools/image/node/18.20.4",
            ".asdf/installs/nodejs/21.7.3",
            ".asdf/installs/python/3.12.1",
            ".pyenv/versions/3.13.1",
        ] {
            mkdir(&home.join(dir));
        }
        assert_eq!(
            found(home, &[]),
            [
                "node.js 22.22.2 [nvm ~/.nvm/versions/node/v22.22.2]",
                "node.js 22.23.4 [nvm ~/.nvm/versions/node/v22.23.4]",
                "node.js 20.1.0 [fnm ~/.local/share/fnm/node-versions/v20.1.0]",
                "node.js 18.20.4 [volta ~/.volta/tools/image/node/18.20.4]",
                "node.js 21.7.3 [asdf ~/.asdf/installs/nodejs/21.7.3]",
                "python 3.12.1 [asdf ~/.asdf/installs/python/3.12.1]",
                "python 3.13.1 [pyenv ~/.pyenv/versions/3.13.1]",
            ]
        );
    }

    #[test]
    fn environment_variables_move_the_folders() {
        let tmp = tempfile::tempdir().unwrap();
        let (home, elsewhere) = (tmp.path().join("home"), tmp.path().join("x"));
        // The default folders also exist, and are not read when a variable names another.
        for dir in [
            ".nvm/versions/node/v1.0.0",
            ".local/share/fnm/node-versions/v1.0.0",
            ".volta/tools/image/node/1.0.0",
            ".asdf/installs/nodejs/1.0.0",
            ".pyenv/versions/1.0.0",
        ] {
            mkdir(&home.join(dir));
        }
        for dir in [
            "nvm/versions/node/v22.1.0",
            "fnm/node-versions/v22.2.0",
            "volta/tools/image/node/22.3.0",
            "asdf/installs/nodejs/22.4.0",
            "pyenv/versions/3.13.1",
        ] {
            mkdir(&elsewhere.join(dir));
        }
        let vars = [
            ("NVM_DIR", elsewhere.join("nvm")),
            ("FNM_DIR", elsewhere.join("fnm")),
            ("VOLTA_HOME", elsewhere.join("volta")),
            ("ASDF_DATA_DIR", elsewhere.join("asdf")),
            ("PYENV_ROOT", elsewhere.join("pyenv")),
        ];
        let versions: Vec<String> = found(&home, &vars)
            .iter()
            .map(|line| line.split(' ').nth(1).unwrap().to_owned())
            .collect();
        assert_eq!(versions, ["22.1.0", "22.2.0", "22.3.0", "22.4.0", "3.13.1"]);
    }

    #[test]
    fn relative_or_empty_variables_are_ignored() {
        let home = tempfile::tempdir().unwrap();
        mkdir(&home.path().join(".nvm/versions/node/v22.1.0"));
        mkdir(&home.path().join(".pyenv/versions/3.13.1"));
        let vars = [
            ("NVM_DIR", PathBuf::from("nvm")),
            ("PYENV_ROOT", PathBuf::new()),
        ];
        assert_eq!(
            found(home.path(), &vars),
            [
                "node.js 22.1.0 [nvm ~/.nvm/versions/node/v22.1.0]",
                "python 3.13.1 [pyenv ~/.pyenv/versions/3.13.1]",
            ]
        );
    }

    #[test]
    fn without_nvm_dir_both_nvm_defaults_are_read() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        mkdir(&config.join("nvm/versions/node/v22.1.0"));
        mkdir(&tmp.path().join(".nvm/versions/node/v20.0.0"));
        assert_eq!(
            found(tmp.path(), &[("XDG_CONFIG_HOME", config.clone())]),
            [
                "node.js 22.1.0 [nvm ~/config/nvm/versions/node/v22.1.0]",
                "node.js 20.0.0 [nvm ~/.nvm/versions/node/v20.0.0]",
            ]
        );
        // An empty `$XDG_CONFIG_HOME/nvm` does not hide `~/.nvm`.
        fs::remove_dir_all(config.join("nvm/versions/node/v22.1.0")).unwrap();
        assert_eq!(
            found(tmp.path(), &[("XDG_CONFIG_HOME", config)]),
            ["node.js 20.0.0 [nvm ~/.nvm/versions/node/v20.0.0]"]
        );
    }

    #[test]
    fn every_fnm_base_folder_is_read() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        // fnm creates its first base folder on any run, before an install.
        mkdir(&home.join("data/fnm"));
        for dir in [
            "Library/Application Support/fnm/node-versions/v18.0.0",
            ".fnm/node-versions/v20.0.0",
        ] {
            mkdir(&home.join(dir));
        }
        let data = [("XDG_DATA_HOME", home.join("data"))];
        assert_eq!(
            found(home, &data),
            [
                "node.js 20.0.0 [fnm ~/.fnm/node-versions/v20.0.0]",
                "node.js 18.0.0 [fnm ~/Library/Application Support/fnm/node-versions/v18.0.0]",
            ]
        );
        mkdir(&home.join("data/fnm/node-versions/v22.0.0"));
        assert_eq!(found(home, &data).len(), 3);
    }

    #[test]
    fn entries_that_are_not_versions_are_skipped() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        let pyenv = home.join(".pyenv/versions");
        for name in [
            "3.13.1",
            "3.13.2t",
            "3.15.0a1",
            "3.13.0rc1",
            "3.14-dev",
            "3.13t-dev",
            "3..1",
            "3.1rc",
            "3.1RC1",
            "pypy3.10-7.3.15",
            "anaconda3-2024.06",
            "graalpy-24.1.0",
            "3.1 copy",
        ] {
            mkdir(&pyenv.join(name));
        }
        // A pyenv-virtualenv entry, and a stray file.
        symlink(pyenv.join("3.13.1"), pyenv.join("3.99.0")).unwrap();
        fs::write(pyenv.join("3.12.0"), "").unwrap();
        for dir in [
            ".nvm/versions/node/22.1.0",
            ".nvm/versions/node/vlatest",
            ".local/share/fnm/node-versions/.downloads",
            ".asdf/installs/nodejs/ref-v22.1.0",
        ] {
            mkdir(&home.join(dir));
        }
        assert_eq!(
            found(home, &[]),
            [
                "python 3.13.0rc1 [pyenv ~/.pyenv/versions/3.13.0rc1]",
                "python 3.13.1 [pyenv ~/.pyenv/versions/3.13.1]",
                "python 3.13.2 [pyenv ~/.pyenv/versions/3.13.2t]",
                "python 3.15.0a1 [pyenv ~/.pyenv/versions/3.15.0a1]",
            ]
        );
    }

    #[test]
    fn missing_folders_give_nothing_and_unreadable_ones_a_problem() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(found(home.path(), &[]), Vec::<String>::new());

        let file = home.path().join(".pyenv");
        fs::write(&file, "").unwrap();
        let layout = Layout {
            manager: VersionManager::Pyenv,
            dir: file.join("versions"),
            product: "python",
        };
        let err = read_versions(&layout).unwrap_err();
        assert!(
            matches!(&err, InventoryError::Io { path, .. } if *path == layout.dir),
            "{err:?}"
        );
    }

    #[test]
    fn the_path_runtime_is_dropped_when_a_manager_has_its_version() {
        let at = |product_name: &str, version: &str, found_in: FoundIn| Component {
            lookup: product(product_name),
            version: version.to_owned(),
            found_in,
        };
        let managed = |product_name: &str, version: &str| {
            let found_in = FoundIn::VersionManager {
                manager: VersionManager::Asdf,
                path: PathBuf::from(format!("/m/{version}")),
            };
            at(product_name, version, found_in)
        };
        let brew = FoundIn::HomebrewFormula {
            name: "node".into(),
        };
        let mut components = vec![
            at("node.js", "22.1.0", FoundIn::Node),
            at("python", "3.13.1", FoundIn::Python),
            at("node.js", "20.0.0", FoundIn::Node),
            at("node.js", "22.1.0", brew),
            managed("node.js", "22.1.0"),
            managed("python", "3.13.1"),
            managed("python", "20.0.0"),
        ];
        drop_path_duplicates(&mut components);
        let left: Vec<String> = components
            .iter()
            .map(|c| format!("{} [{}]", c.version, c.found_in))
            .collect();
        assert_eq!(
            left,
            [
                "20.0.0 [the node on PATH]",
                "22.1.0 [Homebrew formula node]",
                "22.1.0 [asdf /m/22.1.0]",
                "3.13.1 [asdf /m/3.13.1]",
                "20.0.0 [asdf /m/20.0.0]",
            ],
            "only a PATH runtime with a managed twin of the same product and version goes"
        );
    }
}
