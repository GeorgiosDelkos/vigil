//! Where Vigil keeps its files.

use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use crate::config::DEFAULT_CONFIG;

/// The app's bundle id, as `identifier` in `app/src-tauri/tauri.conf.json`. It names the data
/// folder and the Keychain service, as `vigil` alone is generic enough for another app to use.
pub(crate) const BUNDLE_ID: &str = "io.github.georgiosdelkos.vigil";

/// The data directory: config, feed cache, state and sweep reports.
///
/// Everything is a plain file so the user and agents can read and edit it.
#[derive(Debug)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// Uses `root` as the data directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the standard macOS location for the user whose home is `home`:
    /// `~/Library/Application Support/io.github.georgiosdelkos.vigil`.
    pub fn for_home(home: &Path) -> Self {
        Self::new(home.join("Library/Application Support").join(BUNDLE_ID))
    }

    /// Returns the path of `config.toml`.
    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    /// Returns the path of `report.html`, the HTML report.
    pub(crate) fn report_html_file(&self) -> PathBuf {
        self.root.join("report.html")
    }

    /// Returns the folder holding one subfolder per sweep.
    pub(crate) fn sweeps_dir(&self) -> PathBuf {
        self.root.join("sweeps")
    }

    /// Returns the folder of state that outlives sweeps: dismissals.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    /// Returns the folder holding one subfolder per fix run.
    pub(crate) fn fixes_dir(&self) -> PathBuf {
        self.root.join("fixes")
    }

    /// Returns the folder of user-editable prompt templates.
    pub(crate) fn prompts_dir(&self) -> PathBuf {
        self.root.join("prompts")
    }

    /// Returns the feed cache folder. Deleting it is always safe; it is refilled on demand.
    pub(crate) fn feeds_dir(&self) -> PathBuf {
        self.root.join("feeds")
    }

    /// Creates the data directory and writes the default `config.toml`.
    ///
    /// Returns the config path. Never overwrites an existing config.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::ConfigExists`] if `config.toml` is already there, and
    /// [`InitError::Io`] if the directory or file cannot be created.
    pub fn init(&self) -> Result<PathBuf, InitError> {
        let path = self.config_file();
        let io_err = |source| InitError::Io {
            path: path.clone(),
            source,
        };

        fs::create_dir_all(&self.root).map_err(|source| InitError::Io {
            path: self.root.clone(),
            source,
        })?;
        let mut file = match fs::File::create_new(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(InitError::ConfigExists { path });
            }
            Err(e) => return Err(io_err(e)),
        };
        if let Err(e) = file
            .write_all(DEFAULT_CONFIG.as_bytes())
            .and_then(|()| file.sync_all())
        {
            // Best effort: a partial file would make every later `init` report ConfigExists, and
            // the write error returned below is the one the user needs to see.
            drop(fs::remove_file(&path));
            return Err(io_err(e));
        }
        Ok(path)
    }
}

/// Error from [`DataDir::init`].
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// A config file already exists and was left untouched.
    #[error("config {} already exists", path.display())]
    ConfigExists {
        /// The existing config file.
        path: PathBuf,
    },
    /// The data directory or config file could not be created.
    #[error("cannot create {}", path.display())]
    Io {
        /// The path being created.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

/// Writes `text` to a temporary name beside `path`, syncs it, and renames it over `path`, so
/// neither a reader nor a crash sees half a file. Two writers of one path at once would share
/// the temporary file, so callers hold a lock.
pub(crate) fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let name = path
        .file_name()
        .expect("the path names a file")
        .to_string_lossy();
    let partial = path.with_file_name(format!(".{name}.partial"));
    fs::File::create(&partial)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_data()
        })
        .and_then(|()| fs::rename(&partial, path))
        // Best effort: the write's error is what matters, and a leftover partial file is
        // harmless, since readers open files by their own names.
        .inspect_err(|_| drop(fs::remove_file(&partial)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_default_config_once() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = DataDir::new(tmp.path().join("nested/data"));

        let path = dir.init().unwrap();
        assert_eq!(path, dir.config_file());
        assert_eq!(fs::read_to_string(&path).unwrap(), DEFAULT_CONFIG);

        fs::write(&path, "edited").unwrap();
        let err = dir.init().unwrap_err();
        assert!(matches!(err, InitError::ConfigExists { .. }), "{err:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "edited");
    }

    #[test]
    fn init_reports_unwritable_root() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("file");
        fs::write(&blocker, "").unwrap();

        let root = blocker.join("data");
        let err = DataDir::new(&root).init().unwrap_err();
        assert!(
            matches!(&err, InitError::Io { path, .. } if *path == root),
            "{err:?}"
        );
    }

    #[test]
    fn init_reports_read_only_root_as_io() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();

        let dir = DataDir::new(&root);
        let err = dir.init().unwrap_err();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(&err, InitError::Io { path, .. } if *path == dir.config_file()),
            "{err:?}"
        );
    }

    #[test]
    fn for_home_uses_application_support() {
        let dir = DataDir::for_home(Path::new("/Users/me"));
        assert_eq!(
            dir.config_file(),
            Path::new(
                "/Users/me/Library/Application Support/io.github.georgiosdelkos.vigil/config.toml"
            )
        );
        assert_eq!(
            dir.feeds_dir(),
            Path::new("/Users/me/Library/Application Support/io.github.georgiosdelkos.vigil/feeds")
        );
    }
}
