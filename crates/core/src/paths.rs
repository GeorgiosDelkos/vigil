//! Where Vigil keeps its files.

use std::fs;
use std::io;
use std::io::Write as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::fs::PermissionsExt as _;
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

    /// Creates the data directory if it is missing, open to this user alone (mode 0700), or
    /// checks the one there: a real folder, not a symlink, that no other user can write to.
    /// Then drops every permission it gives other users, which also proves this user owns it,
    /// since only the owner may change a folder's mode. So the inventory, reports and agent
    /// logs inside stay private, and no other user can plant a symlink where a sweep deletes.
    ///
    /// Only the root is checked: what is inside it was created by Vigil, and its parent
    /// folders are the user's to keep.
    ///
    /// # Errors
    ///
    /// Fails when the folder cannot be created or read, is not a real folder, is writable by
    /// other users, or belongs to another user.
    pub fn ensure_private(&self) -> Result<(), DataDirError> {
        let root = &self.root;
        let io_err = |source| DataDirError::Io {
            path: root.clone(),
            source,
        };
        // A no-op when the folder exists. Parents it creates get the same mode, which keeps
        // a new `--data-dir /tmp/a/b` private too.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(io_err)?;
        let meta = fs::symlink_metadata(root).map_err(io_err)?;
        if !meta.is_dir() {
            return Err(DataDirError::NotAFolder { path: root.clone() });
        }
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(DataDirError::Shared {
                path: root.clone(),
                mode: mode & 0o777,
            });
        }
        match fs::set_permissions(root, fs::Permissions::from_mode(mode & 0o700)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                Err(DataDirError::NotOwned { path: root.clone() })
            }
            Err(e) => Err(io_err(e)),
        }
    }

    /// Creates the data directory (see [`DataDir::ensure_private`]) and writes the default
    /// `config.toml`.
    ///
    /// Returns the config path. Never overwrites an existing config.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::ConfigExists`] if `config.toml` is already there,
    /// [`InitError::DataDir`] if the directory cannot be made private, and [`InitError::Io`]
    /// if the file cannot be created.
    pub fn init(&self) -> Result<PathBuf, InitError> {
        let path = self.config_file();
        let io_err = |source| InitError::Io {
            path: path.clone(),
            source,
        };

        self.ensure_private()?;
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
    /// The data directory could not be created or made private.
    #[error(transparent)]
    DataDir(#[from] DataDirError),
    /// The config file could not be created.
    #[error("cannot create {}", path.display())]
    Io {
        /// The path being created.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

/// Error from [`DataDir::ensure_private`].
#[derive(Debug, thiserror::Error)]
pub enum DataDirError {
    /// The folder could not be created, read or changed.
    #[error("cannot create or read the data folder {}", path.display())]
    Io {
        /// The data folder.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The path is a symlink to a folder. A file in its place fails to be created, as
    /// [`DataDirError::Io`].
    #[error(
        "the data folder {} is a symlink; use the folder it points to",
        path.display()
    )]
    NotAFolder {
        /// The data folder.
        path: PathBuf,
    },
    /// Other users can write to the folder, so they could have changed what is in it.
    #[error(
        "other users can write to the data folder {} (mode {mode:o}); check what is in it, \
         then run `chmod 700` on it, or use another folder",
        path.display()
    )]
    Shared {
        /// The data folder.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The folder belongs to another user.
    #[error("the data folder {} belongs to another user; use a folder of your own", path.display())]
    NotOwned {
        /// The data folder.
        path: PathBuf,
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
        .inspect_err(|_| drop(fs::remove_file(&partial)))?;
    // Syncs the folder too, so a crash after this returns cannot undo the rename.
    let folder = path
        .parent()
        .expect("a path that names a file has a parent");
    fs::File::open(folder)?.sync_all()
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
            matches!(&err, InitError::DataDir(DataDirError::Io { path, .. }) if *path == root),
            "{err:?}"
        );
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_new_data_folder_is_private_and_an_existing_one_is_made_private() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("new/data");
        DataDir::new(&root).ensure_private().unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(
            mode(&tmp.path().join("new")),
            0o700,
            "a parent it created too"
        );

        let old = tmp.path().join("old");
        fs::create_dir(&old).unwrap();
        fs::set_permissions(&old, fs::Permissions::from_mode(0o755)).unwrap();
        DataDir::new(&old).ensure_private().unwrap();
        assert_eq!(mode(&old), 0o700, "readable by others before 2026-11-12");

        // Only other users' bits go: a folder the user made read-only stays read-only.
        fs::set_permissions(&old, fs::Permissions::from_mode(0o555)).unwrap();
        DataDir::new(&old).ensure_private().unwrap();
        assert_eq!(mode(&old), 0o500);
    }

    #[test]
    fn a_data_folder_others_could_change_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("shared");
        fs::create_dir(&shared).unwrap();
        for bits in [0o775, 0o757] {
            fs::set_permissions(&shared, fs::Permissions::from_mode(bits)).unwrap();
            let err = DataDir::new(&shared).ensure_private().unwrap_err();
            assert!(
                matches!(err, DataDirError::Shared { mode, .. } if mode == bits),
                "{err:?}"
            );
            assert_eq!(mode(&shared), bits, "left as it was");
        }
        let err = DataDir::new("/tmp").ensure_private().unwrap_err();
        assert!(
            matches!(err, DataDirError::NotAFolder { .. }),
            "a symlink on macOS: {err:?}"
        );
        let err = DataDir::new("/private/tmp").ensure_private().unwrap_err();
        assert!(
            matches!(err, DataDirError::Shared { mode: 0o777, .. }),
            "{err:?}"
        );

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&shared, &link).unwrap();
        let err = DataDir::new(&link).ensure_private().unwrap_err();
        assert!(matches!(err, DataDirError::NotAFolder { .. }), "{err:?}");
        let file = tmp.path().join("file");
        fs::write(&file, "").unwrap();
        let err = DataDir::new(&file).ensure_private().unwrap_err();
        assert!(matches!(err, DataDirError::Io { .. }), "{err:?}");

        // A root-owned folder on a writable volume: `/usr` is on the read-only system volume,
        // where the chmod fails as read-only before ownership is checked (seen on the GitHub
        // macOS runner, 2026-11-12). As root the chmod would succeed and change /Library: only
        // run it as another user.
        let uid = |path: &Path| std::os::unix::fs::MetadataExt::uid(&fs::metadata(path).unwrap());
        assert_ne!(
            uid(&file),
            uid(Path::new("/Library")),
            "run the tests as a user"
        );
        let err = DataDir::new("/Library").ensure_private().unwrap_err();
        assert!(matches!(err, DataDirError::NotOwned { .. }), "{err:?}");
        assert!(err.to_string().contains("another user"), "{err}");
    }

    #[test]
    fn init_reports_read_only_root_as_io() {
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
