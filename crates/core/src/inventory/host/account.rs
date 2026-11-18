//! Who runs the sweep, and which files that account could replace.
//!
//! A program that runs as root but that this user can replace is a way from this user to root:
//! malware running as the user swaps it, and the next start runs it as root. The check reads
//! mode bits and owners only, as the kernel applies them. It does not read ACLs, which can
//! grant more, so a file shown not replaceable may still be.
//!
//! Write access through the `admin` group does not count: `/Applications` is `root:admin
//! 775`, so it would mark every daemon an app runs from its own bundle for every admin user,
//! and an admin can already become root with their password. The question is a way up with
//! no password. macOS's App Management protection also guards the bundles there.
//!
//! `unsafe` is forbidden in this workspace, so `access(2)` and `getgroups(2)` are out of reach;
//! `/usr/bin/id` names the account and its groups instead, once per sweep.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use crate::cancel::Cancel;
use crate::inventory::InventoryError;
use crate::inventory::command;

/// The tool that names the account, by absolute path as every host tool is.
const ID: &str = "/usr/bin/id";

/// macOS's `admin` group, whose write access does not count (see the module docs).
const ADMIN_GID: u32 = 80;

/// The account the sweep runs as.
#[derive(Debug)]
pub(super) struct Account {
    pub(super) name: String,
    uid: u32,
    /// Its groups, the primary one included.
    groups: Vec<u32>,
}

impl Account {
    /// This process's account, from `id`. `None` when `id` is not there.
    pub(super) fn current(cancel: &Cancel) -> Result<Option<Self>, InventoryError> {
        let Some(stdout) = command::run(ID, &[], cancel)? else {
            return Ok(None);
        };
        parse(&stdout)
            .map(Some)
            .ok_or_else(|| InventoryError::Parse {
                what: ID.to_owned(),
                detail: format!("no uid and groups in {:?}", stdout.trim()),
            })
    }

    /// Whether this account could put another file at `path`: it can write the file, or any
    /// folder it is reached through, on the path as written or with its links followed. Owning
    /// a file or folder counts, since the owner may change its mode. A folder with the sticky
    /// bit (`/tmp`) lets only the owner of an entry replace it. A file that is not there counts
    /// when the account could create it. Always `false` for root, which can replace anything:
    /// the question is whether someone else can become root.
    pub(super) fn can_replace(&self, path: &Path) -> bool {
        if self.uid == 0 {
            return false;
        }
        self.can_replace_along(path)
            || fs::canonicalize(path)
                .is_ok_and(|real| real != path && self.can_replace_along(&real))
    }

    /// [`Self::can_replace`] along the folders of `path` as written: each folder is read with
    /// its link followed, which checks the folder entries land in.
    fn can_replace_along(&self, path: &Path) -> bool {
        let mut child = fs::symlink_metadata(path).ok();
        // A link's own mode and owner let no one change where it points: only its folder does.
        let leaf = child.as_ref().filter(|file| !file.is_symlink());
        if leaf.is_some_and(|file| self.writes(file, Entry::File)) {
            return true;
        }
        for folder in path.ancestors().skip(1) {
            let Ok(meta) = fs::metadata(folder) else {
                // Not there either: whoever can create it decides, so look further up.
                child = None;
                continue;
            };
            // In a sticky folder only an entry's owner, or the folder's, may replace it.
            let sticky = meta.mode() & 0o1000 != 0;
            let guarded = sticky
                && meta.uid() != self.uid
                && child.as_ref().is_some_and(|c| c.uid() != self.uid);
            if self.writes(&meta, Entry::Folder) && !guarded {
                return true;
            }
            child = Some(meta);
        }
        false
    }

    /// Whether this account may write `meta`'s file or folder, or change its mode to. As the
    /// kernel does, only the bits of the account's class count: the owner's (always enough,
    /// since the owner may change them), else the group's, else everyone's. A folder needs its
    /// search bit too.
    fn writes(&self, meta: &fs::Metadata, entry: Entry) -> bool {
        let mode = meta.mode();
        let needed = match entry {
            Entry::File => 0o2,
            Entry::Folder => 0o3,
        };
        if meta.uid() == self.uid {
            true
        } else if self.groups.contains(&meta.gid()) {
            meta.gid() != ADMIN_GID && (mode >> 3) & needed == needed
        } else {
            mode & needed == needed
        }
    }
}

/// What a mode is checked for: writing a file, or writing an entry into a folder.
#[derive(Debug, Clone, Copy)]
enum Entry {
    File,
    Folder,
}

/// The account in `id`'s output: `uid=501(me) gid=20(staff) groups=20(staff),12(everyone)`.
fn parse(text: &str) -> Option<Account> {
    let field = |key: &str| {
        text.split_whitespace()
            .find_map(|part| part.strip_prefix(key)?.strip_prefix('='))
    };
    let number = |part: &str| part.split('(').next()?.parse::<u32>().ok();
    let uid_part = field("uid")?;
    let uid = number(uid_part)?;
    let name = uid_part.split_once('(')?.1.strip_suffix(')')?.to_owned();
    // The list runs to the end of the line: a group's name can hold spaces (an Active
    // Directory group such as `domain users`), so the line is not split on white space there.
    let list = text
        .find("groups=")
        .map(|at| text[at + "groups=".len()..].lines().next().unwrap_or(""));
    let mut groups: Vec<u32> = list.map_or_else(Vec::new, |list| {
        list.split(',')
            .filter_map(|g| number(g.trim_start()))
            .collect()
    });
    groups.extend(field("gid").and_then(number));
    Some(Account { name, uid, groups })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn id_output_gives_the_account_and_its_groups() {
        let account =
            parse("uid=501(me) gid=20(staff) groups=20(staff),12(everyone),80(admin)\n").unwrap();
        assert_eq!(account.name, "me");
        assert_eq!(account.uid, 501);
        assert_eq!(account.groups, [20, 12, 80, 20]);
        let without_groups = parse("uid=0(root) gid=0(wheel)").unwrap();
        assert_eq!(without_groups.groups, [0]);
        assert!(parse("uid=x(me) gid=20(staff)").is_none());
        assert!(parse("gid=20(staff)").is_none());
        assert!(parse("uid=501 gid=20").is_none(), "no name");
        let spaced =
            parse("uid=501(me) gid=20(staff) groups=20(staff),701(domain users),80(admin)")
                .unwrap();
        assert_eq!(
            spaced.groups,
            [20, 701, 80, 20],
            "a group name with a space"
        );
    }

    #[test]
    fn the_current_account_owns_what_it_creates_and_not_the_system() {
        let me = Account::current(&Cancel::new()).unwrap().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("a");
        fs::write(&file, "").unwrap();
        // Read-only, but owned, so its mode can be changed back.
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(me.can_replace(&file));
        assert!(
            me.can_replace(&tmp.path().join("missing/deeper")),
            "it could create them"
        );
        assert!(!me.can_replace(Path::new("/bin/sh")));
        assert!(!me.can_replace(Path::new("/usr/bin/missing")));
    }

    #[test]
    fn another_account_replaces_only_through_a_bit_it_has() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("shared");
        fs::create_dir(&folder).unwrap();
        let file = folder.join("a");
        fs::write(&file, "").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let gid = fs::metadata(&folder).unwrap().gid();
        // A stranger: not the owner, in none of the file's groups.
        let other = Account {
            name: "other".to_owned(),
            uid: u32::MAX - 1,
            groups: Vec::new(),
        };
        let in_group = Account {
            name: "member".to_owned(),
            uid: u32::MAX - 1,
            groups: vec![gid],
        };
        let mode = |path: &Path, mode| fs::set_permissions(path, fs::Permissions::from_mode(mode));

        mode(&folder, 0o755).unwrap();
        assert!(!other.can_replace(&file) && !in_group.can_replace(&file));
        mode(&folder, 0o775).unwrap();
        assert!(!other.can_replace(&file) && in_group.can_replace(&file));
        mode(&folder, 0o777).unwrap();
        assert!(other.can_replace(&file));
        // Sticky: an entry of someone else's stays theirs, but a new one can be made.
        mode(&folder, 0o1777).unwrap();
        assert!(!other.can_replace(&file));
        assert!(other.can_replace(&folder.join("new")));
        mode(&folder, 0o755).unwrap();
        mode(&file, 0o666).unwrap();
        assert!(other.can_replace(&file), "the file itself is writable");

        let root = Account {
            name: "root".to_owned(),
            uid: 0,
            groups: vec![0],
        };
        assert!(!root.can_replace(&file), "root needs no way up");
    }

    #[test]
    fn only_the_account_s_class_of_bits_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("f");
        fs::create_dir(&folder).unwrap();
        let file = folder.join("a");
        fs::write(&file, "").unwrap();
        let gid = fs::metadata(&folder).unwrap().gid();
        let stranger = |groups| Account {
            name: "x".to_owned(),
            uid: u32::MAX - 1,
            groups,
        };
        let mode = |path: &Path, mode| fs::set_permissions(path, fs::Permissions::from_mode(mode));
        mode(&folder, 0o755).unwrap();
        // Everyone may write it, but not its group, and the kernel gives a member the group's.
        mode(&file, 0o646).unwrap();
        assert!(stranger(Vec::new()).can_replace(&file));
        assert!(!stranger(vec![gid]).can_replace(&file));
        // A folder written without its search bit cannot be entered to write into.
        mode(&file, 0o644).unwrap();
        mode(&folder, 0o772).unwrap();
        assert!(!stranger(Vec::new()).can_replace(&file));
        mode(&folder, 0o755).unwrap();
    }

    #[test]
    fn the_admin_group_is_no_way_up() {
        let admin = Account {
            name: "me".to_owned(),
            uid: u32::MAX - 1,
            groups: vec![ADMIN_GID],
        };
        // Built by hand: a test cannot make a folder owned by another user and `admin`.
        let tmp = tempfile::tempdir().unwrap();
        let meta = fs::metadata(tmp.path()).unwrap();
        assert!(meta.gid() != ADMIN_GID || !admin.writes(&meta, Entry::Folder));
        if Path::new("/Applications").exists() {
            let apps = fs::metadata("/Applications").unwrap();
            if apps.gid() == ADMIN_GID && apps.mode() & 0o002 == 0 {
                assert!(!admin.writes(&apps, Entry::Folder), "root:admin 775");
                assert!(!admin.can_replace(Path::new("/Applications/Some.app/Contents/x")));
            }
        }
    }

    #[test]
    fn a_link_is_followed_too() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("a"), "").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let other = Account {
            name: "other".to_owned(),
            uid: u32::MAX - 1,
            groups: Vec::new(),
        };
        let mode = |path: &Path, mode| fs::set_permissions(path, fs::Permissions::from_mode(mode));
        mode(tmp.path(), 0o755).unwrap();
        mode(&real, 0o777).unwrap();
        assert!(
            other.can_replace(&link.join("a")),
            "through the link's target"
        );
        mode(&real, 0o755).unwrap();
        assert!(!other.can_replace(&link.join("a")));
    }
}
