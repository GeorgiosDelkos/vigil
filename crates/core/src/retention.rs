//! Which sweep folders are kept: each target's newest, and its newest with a verdict when the
//! newest has none (the owner's decision, 2026-11-12). Everything else of that target goes:
//! report, bundle and agent logs.
//!
//! What a sweep reads of earlier sweeps is the target's newest report with a verdict: the
//! changes since then, when each finding was first seen, and which reported fixes it confirms.
//! The confirmed fixes listed for 30 days come from `state/fixes.jsonl`, which keeps each fix's
//! title, summary and pull request, so they need no older report. That is why the rule keeps
//! that one report and nothing older, and why it runs only once the new report is written: the
//! comparison with the last sweep has been made by then.
//!
//! A target removed from the config is never swept again, so the folders it has stay until the
//! user deletes them: its newest only, if it was swept since this rule came in, or all of them. A cancelled sweep writes no report for the target it stopped in, so nothing
//! of that target is removed.

use std::fs;
use std::io;
use std::path::Path;

use crate::lifecycle;
use crate::lifecycle::StateError;

/// Removes the folders of the target whose report was just written at
/// `<target_dir>/report.json` in sweeps older than `target_dir`'s, keeping the target's newest
/// report with a verdict when that is an older one. Then removes each of those sweep folders
/// that is left empty.
///
/// Call it holding the sweeps lock, so no sweep or fix reads or writes there meanwhile. Only
/// real folders named after the target are removed, and no symlink is followed: a symlink or
/// file in its place stays, and so does the sweep folder holding it.
///
/// # Errors
///
/// Fails when a sweep folder or the newest report with a verdict cannot be read, which removes
/// nothing, or when a folder cannot be removed, which stops there.
pub(crate) fn remove_older(sweeps: &Path, target_dir: &Path) -> Result<(), StateError> {
    let current = target_dir
        .parent()
        .expect("a target folder is inside its sweep folder");
    let dir_name = target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a target folder is named in UTF-8");
    let kept = lifecycle::newest_verdict(sweeps, dir_name)?
        .and_then(|(report, _)| report.parent().map(Path::to_owned));
    let write_err = |path: &Path| {
        let path = path.to_owned();
        move |source| StateError::Write { path, source }
    };
    // So a crash after a removal cannot keep the removal and lose the new report: the report
    // and its entry were synced as they were written; these sync the entries of its target
    // folder and of its sweep folder.
    for folder in [current, sweeps] {
        fs::File::open(folder)
            .and_then(|folder| folder.sync_all())
            .map_err(write_err(folder))?;
    }
    let all = lifecycle::newest_first(sweeps)?;
    // Only sweeps older than this one: a newer name can only come from a clock set back, and
    // that sweep is left alone.
    let older = all.iter().skip_while(|sweep| *sweep != current).skip(1);
    for sweep in older {
        let target = sweep.join(dir_name);
        if kept.as_deref() == Some(target.as_path()) {
            continue;
        }
        let is_folder = match fs::symlink_metadata(&target) {
            Ok(meta) => meta.is_dir(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(write_err(&target)(e)),
        };
        if is_folder {
            // Does not follow symlinks inside it either: it removes the links themselves.
            fs::remove_dir_all(&target).map_err(write_err(&target))?;
        }
        match fs::remove_dir(sweep) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => {}
            Err(e) => return Err(write_err(sweep)(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    /// Saves a report for `target` in sweep `sweep` under `sweeps`, with a verdict or with a
    /// failure, plus a bundle file and an agent log as a sweep leaves them.
    fn report(sweeps: &Path, sweep: &str, target: &str, verdict: bool) -> PathBuf {
        let dir = sweeps.join(sweep).join(target);
        fs::create_dir_all(dir.join("bundle")).unwrap();
        fs::write(dir.join("bundle/PROMPT.md"), "prompt").unwrap();
        fs::write(dir.join("agent-1.log"), "log").unwrap();
        let failure = if verdict {
            serde_json::Value::Null
        } else {
            "the agent failed".into()
        };
        let json = serde_json::json!({
            "started": "2026-11-05T00:00:00Z",
            "target": target,
            "agent": "claude",
            "components": 1,
            "advisories": 0,
            "findings": [],
            "issues": [],
            "failure": failure,
        });
        fs::write(dir.join("report.json"), json.to_string()).unwrap();
        dir
    }

    /// The `<sweep>/<target>` folders under `sweeps`, sorted.
    fn left(sweeps: &Path) -> Vec<String> {
        let mut left = Vec::new();
        for sweep in fs::read_dir(sweeps).unwrap() {
            let sweep = sweep.unwrap().path();
            if !sweep.is_dir() {
                continue;
            }
            let name = sweep.file_name().unwrap().to_string_lossy().into_owned();
            let targets: Vec<_> = fs::read_dir(&sweep).unwrap().collect();
            if targets.is_empty() {
                left.push(format!("{name}/"));
            }
            for target in targets {
                let target = target.unwrap().file_name();
                left.push(format!("{name}/{}", target.to_string_lossy()));
            }
        }
        left.sort();
        left
    }

    #[test]
    fn a_verdict_keeps_only_itself_and_empty_sweeps_go() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path();
        report(sweeps, "20261101T000000Z", "mac", true);
        report(sweeps, "20261102T000000Z", "mac", false);
        report(sweeps, "20261102T000000Z", "github-o--r", true);
        let new = report(sweeps, "20261103T000000Z", "mac", true);

        remove_older(sweeps, &new).unwrap();
        assert_eq!(
            left(sweeps),
            ["20261102T000000Z/github-o--r", "20261103T000000Z/mac"],
            "another target's folder keeps its sweep folder"
        );
    }

    #[test]
    fn a_failed_sweep_keeps_the_newest_verdict_too() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path();
        report(sweeps, "20261101T000000Z", "mac", true);
        report(sweeps, "20261102T000000Z", "mac", true);
        report(sweeps, "20261103T000000Z", "mac", false);
        let new = report(sweeps, "20261104T000000Z", "mac", false);

        remove_older(sweeps, &new).unwrap();
        assert_eq!(
            left(sweeps),
            ["20261102T000000Z/mac", "20261104T000000Z/mac"]
        );
        let (kept, _) = lifecycle::newest_verdict(sweeps, "mac").unwrap().unwrap();
        assert_eq!(kept, sweeps.join("20261102T000000Z/mac/report.json"));

        // The next verdict replaces it.
        let next = report(sweeps, "20261105T000000Z", "mac", true);
        remove_older(sweeps, &next).unwrap();
        assert_eq!(left(sweeps), ["20261105T000000Z/mac"]);
    }

    #[test]
    fn unfinished_and_unrelated_folders_are_handled_by_the_rule_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path();
        // An older target folder without a report (its save failed) is the target's too.
        fs::create_dir_all(sweeps.join("20261101T000000Z/mac/bundle")).unwrap();
        // A target no longer configured is never swept, so it keeps its newest sweep.
        report(sweeps, "20261101T000000Z", "server-old", true);
        // Not sweep folders: other names, files, and the lock.
        fs::create_dir_all(sweeps.join("notes/mac")).unwrap();
        fs::write(sweeps.join(".lock"), "").unwrap();
        // A sweep named newer than the current one (a clock set back) is left alone.
        report(sweeps, "20261109T000000Z", "mac", true);
        // A sweep interrupted earlier keeps its marker, and so its folder.
        report(sweeps, "20261102T000000Z", "mac", true);
        fs::write(sweeps.join("20261102T000000Z/.running"), "").unwrap();
        let new = report(sweeps, "20261103T000000Z", "mac", true);

        remove_older(sweeps, &new).unwrap();
        let mut sweep_folders = left(sweeps);
        sweep_folders.retain(|f| !f.starts_with("notes"));
        assert_eq!(
            sweep_folders,
            [
                "20261101T000000Z/server-old",
                "20261102T000000Z/.running",
                "20261103T000000Z/mac",
                "20261109T000000Z/mac",
            ]
        );
        assert!(sweeps.join("notes/mac").is_dir());
        assert!(sweeps.join(".lock").is_file());
    }

    #[test]
    fn symlinks_are_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path().join("sweeps");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(outside.join("kept")).unwrap();
        fs::write(outside.join("kept/file"), "").unwrap();

        // A symlink in the target's place stays, and so does its sweep folder.
        fs::create_dir_all(sweeps.join("20261101T000000Z")).unwrap();
        std::os::unix::fs::symlink(&outside, sweeps.join("20261101T000000Z/mac")).unwrap();
        // A symlink inside an older target folder is removed as a link.
        let older = report(&sweeps, "20261102T000000Z", "mac", true);
        std::os::unix::fs::symlink(&outside, older.join("bundle/link")).unwrap();
        // A sweep folder that is a symlink is not a sweep.
        std::os::unix::fs::symlink(&outside, sweeps.join("20261100T000000Z")).unwrap();
        fs::create_dir_all(outside.join("mac")).unwrap();
        let new = report(&sweeps, "20261103T000000Z", "mac", true);

        remove_older(&sweeps, &new).unwrap();
        assert!(outside.join("kept/file").exists());
        assert!(outside.join("mac").is_dir());
        assert!(!older.exists());
        assert!(
            fs::symlink_metadata(sweeps.join("20261101T000000Z/mac"))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn an_unreadable_report_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let sweeps = tmp.path();
        report(sweeps, "20261101T000000Z", "mac", true);
        let broken = report(sweeps, "20261102T000000Z", "mac", true);
        fs::write(broken.join("report.json"), "{").unwrap();
        let new = report(sweeps, "20261103T000000Z", "mac", false);

        let err = remove_older(sweeps, &new).unwrap_err();
        assert!(matches!(err, StateError::Read { .. }), "{err:?}");
        assert_eq!(
            left(sweeps),
            [
                "20261101T000000Z/mac",
                "20261102T000000Z/mac",
                "20261103T000000Z/mac"
            ]
        );
    }
}
