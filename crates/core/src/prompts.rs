//! The prompt templates: built into the app, copied to the data folder's `prompts/` on first
//! use so the user can edit them, and brought up to date when the user has not.
//!
//! At the start of each sweep, [`update`] looks at each copy. A copy that is byte for byte a
//! built-in version some build shipped was never edited, and is replaced by the current
//! built-in version. A copy that matches none was edited, and is kept; the current built-in
//! version is written beside it as `<name>.default.md`, and the sweep notes it once, when that
//! file is written or changes. The note says the built-in prompt may be newer, not that it is:
//! without a record of the version the user started from, an edit of the current version looks
//! the same as an edit of an old one. A missing copy is left for [`render`] to create on first use.
//!
//! How "never edited" is known (owner's decision, 2026-11-10): the app carries the hash of
//! every built-in version in its git history ([`Prompt::shipped`]), and a copy whose hash is in
//! that list is unedited. The alternative weighed was a sidecar file recording the hash of the
//! version copied. A list needs no state the user can lose or edit, and it recognises the
//! copies of installs older than this code, which have no sidecar. Its cost is that every
//! change to a built-in prompt must add the new hash, which a test enforces.

use std::fs;
use std::io;
use std::path::Path;

use crate::paths;
use crate::paths::DataDir;
use crate::sweep::SweepError;

/// Which built-in prompt a target uses.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Prompt {
    Mac,
    GitHub,
    Server,
    Fix,
    FixAll,
}

impl Prompt {
    const ALL: [Self; 5] = [
        Self::Mac,
        Self::GitHub,
        Self::Server,
        Self::Fix,
        Self::FixAll,
    ];

    fn file_name(self) -> &'static str {
        match self {
            Self::Mac => "sweep.md",
            Self::GitHub => "sweep-github.md",
            Self::Server => "sweep-server.md",
            Self::Fix => "fix.md",
            Self::FixAll => "fix-all.md",
        }
    }

    /// Where the current built-in version is written when the user's copy is edited.
    fn default_name(self) -> &'static str {
        match self {
            Self::Mac => "sweep.default.md",
            Self::GitHub => "sweep-github.default.md",
            Self::Server => "sweep-server.default.md",
            Self::Fix => "fix.default.md",
            Self::FixAll => "fix-all.default.md",
        }
    }

    fn default_text(self) -> &'static str {
        match self {
            Self::Mac => include_str!("prompts/sweep.md"),
            Self::GitHub => include_str!("prompts/sweep-github.md"),
            Self::Server => include_str!("prompts/sweep-server.md"),
            Self::Fix => include_str!("prompts/fix.md"),
            Self::FixAll => include_str!("prompts/fix-all.md"),
        }
    }

    /// The [`fnv1a`] hash of every version of the built-in prompt in the git history, the
    /// current one included, in no particular order. Tests check that the list holds every one
    /// of those versions and the current one. It may also hold versions from pull-request
    /// branches that a squash merge left out of main's history.
    fn shipped(self) -> &'static [u64] {
        match self {
            Self::Mac => &[
                0xcd2f_1091_0b13_5be5,
                0x7daf_590d_9d09_a885,
                0x280d_e73a_4e6e_2028,
                0x2f63_49e2_0ee6_b52b,
                0x43e3_14c9_7f99_636c,
                0x6700_b7d7_68f8_b586,
                0x6fb4_8641_0926_923e,
                0xd7b9_24a3_0c7b_42b5,
                0x40f6_3d88_cb2d_afb9,
            ],
            Self::GitHub => &[
                0x61c0_4d78_7cf2_cfd0,
                0xd32b_864c_dff2_7518,
                0x63b2_93e7_5d62_bfc3,
                0xddaa_01c1_7a2a_02d4,
                0x461e_5ecd_ab4c_3f4c,
                0x5587_5ec1_ca59_bdce,
            ],
            Self::Server => &[
                0xf408_6f27_d0ec_3536,
                0xaa44_bd87_ef56_8a55,
                0x495c_677b_2b0e_eafc,
                0xafea_94d5_e019_3384,
                0x7204_4cf2_d0b2_ddbe,
                0x9723_54ab_1f75_134c,
            ],
            Self::Fix => &[0x77ef_cded_9b10_794c, 0x55ae_3d08_e3e0_8813],
            Self::FixAll => &[0xd72c_2266_ddd2_d7f2],
        }
    }
}

/// The user's copy of `kind`'s prompt, created from the built-in one on first use, with the
/// target filled in. Must run under the sweeps lock, as the first write uses a shared temporary
/// name. Written whole or not at all, as a torn copy would match no built-in version and be kept
/// as an edit.
pub(crate) fn render(data_dir: &DataDir, kind: Prompt, target: &str) -> Result<String, SweepError> {
    let dir = data_dir.prompts_dir();
    let path = dir.join(kind.file_name());
    let template = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(&dir)
                .and_then(|()| paths::replace_file(&path, kind.default_text()))
                .map_err(|source| SweepError::Write {
                    path: path.clone(),
                    source,
                })?;
            kind.default_text().to_owned()
        }
        Err(source) => return Err(SweepError::Read { path, source }),
    };
    Ok(template.replace("{{target}}", target))
}

/// Replaces each unedited copy in `prompts/` with the current built-in version, and pushes to
/// `notes` what the user should know: an edited copy whose current built-in version is newly
/// written beside it, or a copy that could not be updated. Must run under the sweeps lock, as
/// the writes share their temporary names.
pub(crate) fn update(data_dir: &DataDir, notes: &mut Vec<String>) {
    let dir = data_dir.prompts_dir();
    for kind in Prompt::ALL {
        if let Err(e) = update_one(&dir, kind, notes) {
            notes.push(format!(
                "prompts/{}: cannot compare it with the built-in prompt or update it: {e}; \
                 check that the prompts folder can be read and written",
                kind.file_name()
            ));
        }
    }
}

fn update_one(dir: &Path, kind: Prompt, notes: &mut Vec<String>) -> io::Result<()> {
    let path = dir.join(kind.file_name());
    let current = kind.default_text().as_bytes();
    let copy = match fs::read(&path) {
        Ok(copy) => copy,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if copy == current {
        return Ok(());
    }
    if kind.shipped().contains(&fnv1a(&copy)) {
        return paths::replace_file(&path, kind.default_text());
    }

    // An unreadable default file is written again, as it is only a copy of the built-in text.
    let default = dir.join(kind.default_name());
    if fs::read(&default).is_ok_and(|text| text == current) {
        return Ok(());
    }
    paths::replace_file(&default, kind.default_text())?;
    notes.push(format!(
        "prompts/{}: your edited copy is used; the current built-in prompt, which may be \
         newer, is in prompts/{} to compare",
        kind.file_name(),
        kind.default_name()
    ));
    Ok(())
}

/// 64-bit FNV-1a (<https://datatracker.ietf.org/doc/html/draft-eastlake-fnv-21>).
///
/// Chosen over SHA-256 because it needs no dependency: `sha2` is in the lockfile only for the
/// app's build macros, and would be new to this crate and the CLI. No adversary picks the
/// copies compared, so a cryptographic hash buys nothing: an edit matches one of `n` listed
/// versions by accident with odds of about `n` in 2^64.
fn fnv1a(bytes: &[u8]) -> u64 {
    // The offset basis and prime the draft gives for 64 bits.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.iter().fold(OFFSET, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    use super::*;

    /// A data folder whose copy of `kind` holds `text`.
    fn with_copy(kind: Prompt, text: &[u8]) -> (tempfile::TempDir, DataDir) {
        let tmp = tempfile::tempdir().unwrap();
        let data = DataDir::new(tmp.path());
        fs::create_dir_all(data.prompts_dir()).unwrap();
        fs::write(data.prompts_dir().join(kind.file_name()), text).unwrap();
        (tmp, data)
    }

    fn read(data: &DataDir, name: &str) -> String {
        fs::read_to_string(data.prompts_dir().join(name)).unwrap()
    }

    /// Every version of `kind`'s built-in prompt in the git history, newest first. Commits on
    /// branches merged with a merge commit count too (`--full-history`): a build from such a
    /// branch may have copied one. A squash merge leaves its branch's commits out of this
    /// history. Renames are not followed; no prompt has been renamed.
    fn versions_in_git(kind: Prompt) -> Vec<Vec<u8>> {
        let git = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}. This test reads the prompts' git history, so it needs a \
                 full clone (`fetch-depth: 0` in CI, `copy_vcs` for cargo mutants).",
                String::from_utf8_lossy(&out.stderr)
            );
            out.stdout
        };
        // A shallow clone's log succeeds with only its newest commits, which would fail the tests
        // with a wrong reason.
        let shallow = git(&["rev-parse", "--is-shallow-repository"]);
        assert_eq!(
            shallow.trim_ascii(),
            b"false",
            "the prompt tests read the prompts' git history: unshallow the clone (`git fetch \
             --unshallow`, `fetch-depth: 0` in CI)"
        );
        let path = format!("src/prompts/{}", kind.file_name());
        let commits =
            String::from_utf8(git(&["log", "--full-history", "--format=%H", "--", &path])).unwrap();
        commits
            .lines()
            .map(|commit| git(&["show", &format!("{commit}:./{path}")]))
            .collect()
    }

    #[test]
    fn render_copies_once_then_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let data = DataDir::new(tmp.path());
        let text = render(&data, Prompt::Mac, "this Mac").unwrap();
        assert!(
            text.starts_with("# Vulnerability sweep: this Mac"),
            "{text}"
        );
        let path = tmp.path().join("prompts/sweep.md");
        fs::write(&path, "Mine: {{target}}").unwrap();
        assert_eq!(render(&data, Prompt::Mac, "x").unwrap(), "Mine: x");

        // A template that exists but cannot be read is an error, not a reason to overwrite it.
        // Write-only, so overwriting would succeed if the code tried.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();
        let result = render(&data, Prompt::Mac, "x");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(result, Err(SweepError::Read { .. })), "{result:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "Mine: {{target}}");
    }

    #[test]
    fn an_unedited_old_copy_is_replaced() {
        let current = Prompt::Mac.default_text().as_bytes();
        let old = versions_in_git(Prompt::Mac)
            .into_iter()
            .find(|v| v != current)
            .expect("sweep.md has changed since it was added");
        let (_tmp, data) = with_copy(Prompt::Mac, &old);

        let mut notes = Vec::new();
        update(&data, &mut notes);
        assert_eq!(read(&data, "sweep.md"), Prompt::Mac.default_text());
        assert!(notes.is_empty(), "{notes:?}");
        assert!(!data.prompts_dir().join("sweep.default.md").exists());
        assert!(!data.prompts_dir().join(".sweep.md.partial").exists());
    }

    #[test]
    fn an_edited_copy_is_kept_and_noted_once() {
        let (_tmp, data) = with_copy(Prompt::Fix, b"Mine: {{target}}");
        let mut notes = Vec::new();
        update(&data, &mut notes);
        assert_eq!(read(&data, "fix.md"), "Mine: {{target}}");
        assert_eq!(read(&data, "fix.default.md"), Prompt::Fix.default_text());
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("prompts/fix.default.md"), "{notes:?}");

        // Known now: the next sweep says nothing until the built-in prompt changes again.
        update(&data, &mut notes);
        assert_eq!(notes.len(), 1, "{notes:?}");

        // A default file from an older build is replaced, and noted again.
        let default = data.prompts_dir().join("fix.default.md");
        fs::write(&default, "older").unwrap();
        update(&data, &mut notes);
        assert_eq!(read(&data, "fix.default.md"), Prompt::Fix.default_text());
        assert_eq!(notes.len(), 2, "{notes:?}");

        // So is one that cannot be read. Write-only: the rename replaces it all the same.
        fs::set_permissions(&default, fs::Permissions::from_mode(0o200)).unwrap();
        update(&data, &mut notes);
        assert_eq!(read(&data, "fix.default.md"), Prompt::Fix.default_text());
        assert_eq!(notes.len(), 3, "{notes:?}");
    }

    #[test]
    fn a_current_copy_is_not_rewritten() {
        let current = Prompt::GitHub.default_text();
        let (_tmp, data) = with_copy(Prompt::GitHub, current.as_bytes());
        // A read-only folder, so a rewrite would fail and be noted.
        fs::set_permissions(data.prompts_dir(), fs::Permissions::from_mode(0o555)).unwrap();
        let mut notes = Vec::new();
        update(&data, &mut notes);
        fs::set_permissions(data.prompts_dir(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(read(&data, "sweep-github.md"), current);
    }

    #[test]
    fn an_unreadable_copy_is_noted_not_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let data = DataDir::new(tmp.path());
        // A folder where the copy should be: reading it fails with something other than
        // NotFound.
        fs::create_dir_all(data.prompts_dir().join("fix.md")).unwrap();

        let mut notes = Vec::new();
        update(&data, &mut notes);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].starts_with("prompts/fix.md: cannot compare it"),
            "{notes:?}"
        );
    }

    #[test]
    fn a_missing_copy_is_left_for_first_use() {
        let tmp = tempfile::tempdir().unwrap();
        let data = DataDir::new(tmp.path());
        let mut notes = Vec::new();
        update(&data, &mut notes);
        assert!(notes.is_empty(), "{notes:?}");
        assert!(!data.prompts_dir().exists());

        let text = render(&data, Prompt::Server, "the server s").unwrap();
        assert!(text.contains("the server s"), "{text}");
        assert_eq!(
            read(&data, "sweep-server.md"),
            Prompt::Server.default_text()
        );
    }

    #[test]
    fn a_copy_that_cannot_be_updated_is_noted() {
        let old = versions_in_git(Prompt::Fix)
            .pop()
            .expect("fix.md has a first version");
        let (_tmp, data) = with_copy(Prompt::Fix, &old);
        // The partial file cannot be created in a read-only folder.
        fs::set_permissions(data.prompts_dir(), fs::Permissions::from_mode(0o555)).unwrap();
        let mut notes = Vec::new();
        update(&data, &mut notes);
        fs::set_permissions(data.prompts_dir(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].starts_with("prompts/fix.md: cannot"), "{notes:?}");
        assert_eq!(read(&data, "fix.md").as_bytes(), old);
    }

    #[test]
    fn the_list_is_every_version_in_git() {
        for kind in Prompt::ALL {
            let in_git: BTreeSet<u64> = versions_in_git(kind).iter().map(|v| fnv1a(v)).collect();
            let listed: BTreeSet<u64> = kind.shipped().iter().copied().collect();
            assert_eq!(
                listed.len(),
                kind.shipped().len(),
                "{kind:?} lists a hash twice"
            );
            // A listed hash with no version in this history is allowed. Pull requests are
            // squash-merged, so a branch that changed a prompt twice must list both versions
            // while its own history holds them, and main then holds only the last one. An extra
            // hash only lets a copy from that branch's build be updated; a missing one would
            // keep a shipped version from being updated, so that direction is the one checked.
            for hash in &in_git {
                assert!(
                    listed.contains(hash),
                    "a version of src/prompts/{} in git is missing from Prompt::shipped: add \
                     {hash:#x}, so installs holding it are updated",
                    kind.file_name()
                );
            }
        }
    }

    #[test]
    fn the_current_built_in_versions_are_listed() {
        for kind in Prompt::ALL {
            let hash = fnv1a(kind.default_text().as_bytes());
            assert!(
                kind.shipped().contains(&hash),
                "src/prompts/{} changed: add {hash:#x} to its list in Prompt::shipped, \
                 so installs holding this version are updated to the next",
                kind.file_name()
            );
        }
    }

    #[test]
    fn fnv1a_matches_known_values() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
