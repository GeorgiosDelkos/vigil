//! Dylib hijacking: programs that would load a library someone else planted, as Objective-See's
//! Dylib Hijack Scanner finds them, written to `mac/dylibs.jsonl`.
//!
//! The loader looks a library up by the install name the program's load command gives
//! ([`macho`]). Two cases leave a place where a planted library loads before, or instead of,
//! the real one (Patrick Wardle, "Dylib Hijacking on OS X", Virus Bulletin, March 2015):
//!
//! - a weak load (`LC_LOAD_WEAK_DYLIB`) of a library that is not there: the program starts
//!   without it, and loads one planted at any place it looks;
//! - an `@rpath/` load the loader finds only in a later `LC_RPATH` folder: one planted in an
//!   earlier folder loads instead.
//!
//! A program is listed only when this user could create a file at such a place
//! ([`Account::can_replace`]) and the program does not enforce library validation, which makes
//! the loader refuse a library not signed by Apple or the program's own team. Each architecture
//! of a universal program counts, since Rosetta runs the Intel one.
//!
//! Read: the program each startup item runs and the main executable of each app in
//! `/Applications` and `~/Applications`. Not read: the libraries those load in turn, other
//! executables inside an app (helpers, plug-ins), and loads relative to the working directory,
//! which depend on how the program is started.
//!
//! Libraries in the system's shared cache are not files on disk: an install name under
//! `/System/` or `/usr/` (but `/usr/local/`) counts as found, as the loader finds it in the cache,
//! and nobody but Apple can write there, on the sealed system volume.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use serde::Serialize;

use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::InventorySource;
use crate::inventory::host::account::Account;
use crate::inventory::host::macho;
use crate::inventory::host::macho::Image;

/// A program to scan, and what runs it.
#[derive(Debug)]
pub(super) struct Program {
    pub(super) path: PathBuf,
    /// The startup item's path, or the app's, as `mac/persistence.jsonl` or the inventory
    /// names it.
    pub(super) used_by: String,
    /// Whether that item runs it as root.
    pub(super) as_root: bool,
}

/// A program a planted library could take over, one line of `mac/dylibs.jsonl`.
#[derive(Debug, Serialize)]
pub(super) struct Hijackable {
    /// The program, as the first item or app that runs it names it. An issue names it by this
    /// path. Text, as an item's path is.
    pub(super) path: String,
    /// What runs it: startup items and apps, by path.
    used_by: Vec<String>,
    /// Whether a startup item runs it as root.
    runs_as_root: bool,
    /// The places a planted library would load from, each one this user could create.
    plants: BTreeSet<Plant>,
}

impl Hijackable {
    /// What keys its issue besides its path: where a library could be planted and whether it
    /// would run as root. A program updated without changing either keeps a dismissal.
    pub(super) fn identity(&self) -> String {
        let key = (self.runs_as_root, &self.plants);
        serde_json::to_string(&key).expect("booleans and strings serialize")
    }
}

/// A place a planted library would load from.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Plant {
    /// The install name, as the load command gives it.
    load: String,
    /// Whether the load is weak.
    weak: bool,
    /// Where a library would be planted, with `.` and `..` resolved.
    path: String,
    why: Why,
}

/// Why a library planted at a place would load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum Why {
    /// A weak load whose library is in none of the places the loader looks.
    WeakMissing,
    /// An `@rpath/` load found only in a later rpath folder; this is an earlier one.
    EarlierRpath,
}

/// The programs in `programs` a planted library could take over. A program several items or
/// apps run is read once, by its real path. A program that is not there or is not Mach-O (a
/// script) is left out: the item already says so. One that cannot be read fails its
/// [`InventorySource::LoadCommands`].
pub(super) fn scan(
    inventory: &mut Inventory,
    programs: Vec<Program>,
    account: &Account,
) -> Vec<Hijackable> {
    // By real path: the path the first item or app gives, what runs it, and whether as root.
    let mut by_file: BTreeMap<PathBuf, (PathBuf, Vec<String>, bool)> = BTreeMap::new();
    for program in programs {
        let real = fs::canonicalize(&program.path).unwrap_or_else(|_| program.path.clone());
        let seen = by_file
            .entry(real)
            .or_insert_with(|| (program.path, Vec::new(), false));
        seen.1.push(program.used_by);
        seen.2 |= program.as_root;
    }

    let mut found = Vec::new();
    for (real, (path, used_by, runs_as_root)) in by_file {
        let images = match macho::read(&real) {
            Ok(images) => images,
            Err(macho::ReadError::NotMachO) => continue,
            Err(macho::ReadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => continue,
            // Root's own helpers (`/Library/PrivilegedHelperTools`) and other users' files stay
            // unreadable on every sweep: a note, as `InventoryError::Io` makes it elsewhere.
            Err(macho::ReadError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                let path = path.clone();
                let detail = format!("cannot read it: {e}");
                inventory
                    .problems
                    .push(InventoryError::MachO { path, detail });
                continue;
            }
            Err(macho::ReadError::Io(e)) => {
                let source = InventorySource::LoadCommands {
                    path: path.to_string_lossy().into_owned(),
                };
                inventory.fail(source, InventoryError::io(&path, e));
                continue;
            }
            Err(macho::ReadError::Malformed(detail)) => {
                let path = path.clone();
                inventory
                    .problems
                    .push(InventoryError::MachO { path, detail });
                continue;
            }
        };
        let folder = real.parent().unwrap_or(Path::new("/"));
        let plants: BTreeSet<Plant> = images
            .iter()
            .filter(|image| !image.library_validation)
            .flat_map(|image| plants(image, folder))
            .filter(|plant| account.can_replace(Path::new(&plant.path)))
            .collect();
        if !plants.is_empty() {
            found.push(Hijackable {
                path: path.to_string_lossy().into_owned(),
                used_by,
                runs_as_root,
                plants,
            });
        }
    }
    found
}

/// The places a library planted would load from, for the image of a program in `folder`.
fn plants(image: &Image, folder: &Path) -> Vec<Plant> {
    let mut plants = Vec::new();
    for load in &image.loads {
        let places = places(&load.name, &image.rpaths, folder);
        let found = places.iter().position(|place| is_present(place));
        let (earlier, why) = match found {
            // Every earlier place is tried first, and is empty.
            Some(i) if i > 0 => (&places[..i], Why::EarlierRpath),
            // Not found: a weak load starts without it, and loads it from any place it looks.
            None if load.weak => (&places[..], Why::WeakMissing),
            // Found at the first place, or a strong load not found, which does not start at all.
            Some(_) | None => continue,
        };
        plants.extend(earlier.iter().map(|place| Plant {
            load: load.name.clone(),
            weak: load.weak,
            path: place.to_string_lossy().into_owned(),
            why,
        }));
    }
    plants
}

/// The places the loader looks for the library named `name`, in order, for a program in
/// `folder` with `rpaths`. The program is the main executable, so `@loader_path` is
/// `@executable_path`: its folder. A name relative to the working directory gives none.
fn places(name: &str, rpaths: &[String], folder: &Path) -> Vec<PathBuf> {
    let expand = |path: &str| -> Option<PathBuf> {
        let relative = path
            .strip_prefix("@executable_path/")
            .or_else(|| path.strip_prefix("@loader_path/"));
        match relative {
            Some(relative) => Some(normal(&folder.join(relative))),
            None if path.starts_with('/') => Some(normal(Path::new(path))),
            None => None,
        }
    };
    match name.strip_prefix("@rpath/") {
        Some(rest) => rpaths
            .iter()
            .filter_map(|rpath| expand(rpath))
            .map(|rpath| normal(&rpath.join(rest)))
            .collect(),
        None => expand(name).into_iter().collect(),
    }
}

/// Whether the loader would find a library at `place`: a file there, or a place on the sealed
/// system volume, whose libraries live in the shared cache rather than on disk.
fn is_present(place: &Path) -> bool {
    let sealed = (place.starts_with("/System") || place.starts_with("/usr"))
        && !place.starts_with("/usr/local");
    sealed || fs::metadata(place).is_ok()
}

/// `path` with `.` and `..` resolved by name, so a place reads as a plain path. A link inside
/// it would resolve `..` differently; an app's own folders rarely hold one.
fn normal(path: &Path) -> PathBuf {
    let mut parts = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    use super::*;
    use crate::cancel::Cancel;

    fn run(program: &str, args: &[&str], dir: &Path) {
        let out = Command::new(program)
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{program} {args:?}: {stderr}");
    }

    /// Builds `app`, universal, in `dir` with Apple's toolchain: it loads `@rpath/liby.dylib`
    /// with rpaths `@executable_path/early` then `@executable_path/late`, where liby is, and
    /// weakly loads `gone/libx.dylib`, which is removed. Linked, so ad hoc signed, with no
    /// hardened runtime.
    fn build(dir: &Path) -> PathBuf {
        let arch = ["-arch", "arm64", "-arch", "x86_64"];
        fs::create_dir_all(dir.join("gone")).unwrap();
        fs::create_dir_all(dir.join("late")).unwrap();
        fs::write(dir.join("x.c"), "int x(void) { return 1; }\n").unwrap();
        fs::write(dir.join("y.c"), "int y(void) { return 2; }\n").unwrap();
        fs::write(
            dir.join("main.c"),
            "int y(void);\nint main(void) { return y(); }\n",
        )
        .unwrap();
        let gone = dir.join("gone/libx.dylib");
        let gone = gone.to_str().unwrap();
        let mut x = vec!["-dynamiclib", "x.c", "-o", gone, "-install_name", gone];
        x.extend(arch);
        run("/usr/bin/cc", &x, dir);
        let mut y = vec!["-dynamiclib", "y.c", "-o", "late/liby.dylib"];
        y.extend(["-install_name", "@rpath/liby.dylib"]);
        y.extend(arch);
        run("/usr/bin/cc", &y, dir);
        let mut app = vec!["main.c", "-o", "app", "late/liby.dylib"];
        app.extend(["-Wl,-weak_library,gone/libx.dylib"]);
        app.extend([
            "-Wl,-rpath,@executable_path/early",
            "-Wl,-rpath,@executable_path/late",
        ]);
        app.extend(arch);
        run("/usr/bin/cc", &app, dir);
        fs::remove_file(gone).unwrap();
        dir.join("app")
    }

    fn account() -> Account {
        Account::current(&Cancel::new())
            .unwrap()
            .expect("macOS ships id")
    }

    fn scanned(programs: Vec<Program>) -> (Vec<Hijackable>, Inventory) {
        let mut inventory = Inventory::default();
        let found = scan(&mut inventory, programs, &account());
        (found, inventory)
    }

    fn program(path: &Path, used_by: &str, as_root: bool) -> Program {
        Program {
            path: path.to_owned(),
            used_by: used_by.to_owned(),
            as_root,
        }
    }

    #[test]
    fn a_missing_weak_library_and_an_earlier_rpath_folder_are_places_to_plant() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = fs::canonicalize(tmp.path()).unwrap();
        let app = build(&dir);

        let images = macho::read(&app).unwrap();
        assert_eq!(images.len(), 2, "one image per architecture");
        let (found, inventory) = scanned(vec![program(&app, "/L/item.plist", false)]);

        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
        let [program] = &found[..] else {
            panic!("{found:#?}");
        };
        assert_eq!(program.path, app.to_str().unwrap());
        let plants: Vec<_> = program
            .plants
            .iter()
            .map(|p| format!("{:?} {} {} {}", p.why, p.weak, p.load, p.path))
            .collect();
        let gone = dir.join("gone/libx.dylib").display().to_string();
        let early = dir.join("early/liby.dylib").display().to_string();
        assert_eq!(
            plants,
            [
                format!("WeakMissing true {gone} {gone}"),
                format!("EarlierRpath false @rpath/liby.dylib {early}"),
            ]
        );
        let line = serde_json::to_value(program).unwrap();
        assert_eq!(line["used_by"], serde_json::json!(["/L/item.plist"]));
        assert_eq!(line["plants"][0]["why"], "weak_missing");
    }

    #[test]
    fn library_validation_leaves_a_program_out_unless_an_entitlement_turns_it_off() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = fs::canonicalize(tmp.path()).unwrap();
        let app = build(&dir);
        let app_arg = app.to_str().unwrap();

        run(
            "/usr/bin/codesign",
            &["-f", "-s", "-", "-o", "runtime", app_arg],
            &dir,
        );
        assert!(
            macho::read(&app)
                .unwrap()
                .iter()
                .all(|i| i.library_validation)
        );
        assert!(scanned(vec![program(&app, "a", false)]).0.is_empty());

        let entitlements = dir.join("e.plist");
        fs::write(
            &entitlements,
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
             <key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>",
        )
        .unwrap();
        let entitlements = entitlements.to_str().unwrap();
        let sign = [
            "-f",
            "-s",
            "-",
            "-o",
            "runtime",
            "--entitlements",
            entitlements,
            app_arg,
        ];
        run("/usr/bin/codesign", &sign, &dir);
        assert!(
            macho::read(&app)
                .unwrap()
                .iter()
                .all(|i| !i.library_validation)
        );
        assert_eq!(scanned(vec![program(&app, "a", false)]).0.len(), 1);

        run(
            "/usr/bin/codesign",
            &["-f", "-s", "-", "-o", "library", app_arg],
            &dir,
        );
        assert!(
            macho::read(&app)
                .unwrap()
                .iter()
                .all(|i| i.library_validation)
        );

        // Apple's own programs are platform binaries, which the loader always validates.
        let ls = macho::read(Path::new("/bin/ls")).unwrap();
        assert!(ls.iter().all(|i| i.library_validation));
    }

    #[test]
    fn a_program_is_read_once_and_what_cannot_be_read_is_left_out_or_noted() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = fs::canonicalize(tmp.path()).unwrap();
        let app = build(&dir);
        std::os::unix::fs::symlink(&app, dir.join("link")).unwrap();
        fs::write(dir.join("script.sh"), "#!/bin/sh\n").unwrap();
        fs::copy(&app, dir.join("locked")).unwrap();
        let locked = dir.join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let (found, inventory) = scanned(vec![
            program(&app, "/L/one.plist", false),
            program(&dir.join("link"), "/L/two.plist", true),
            program(&dir.join("script.sh"), "s", false),
            program(&dir.join("not-there"), "n", false),
            program(&dir, "a folder", false),
            program(&locked, "l", false),
        ]);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();

        let [program] = &found[..] else {
            panic!("{found:#?}");
        };
        assert_eq!(program.path, app.to_str().unwrap());
        assert_eq!(program.used_by, ["/L/one.plist", "/L/two.plist"]);
        assert!(program.runs_as_root, "one of its items runs it as root");
        assert!(inventory.failed.is_empty(), "{:?}", inventory.failed);
        let problems: Vec<_> = inventory.problems.iter().map(ToString::to_string).collect();
        let [problem] = &problems[..] else {
            panic!("{problems:#?}");
        };
        assert!(
            problem.starts_with(&format!("the libraries {} loads", locked.display())),
            "{problem}"
        );
    }

    #[test]
    fn places_follow_the_loaders_names_and_the_shared_cache_counts_as_found() {
        let folder = Path::new("/A/X.app/Contents/MacOS");
        let rpaths = [
            "@executable_path/../Frameworks".to_owned(),
            "@loader_path/./lib".to_owned(),
            "/opt/lib".to_owned(),
            "relative/lib".to_owned(),
        ];
        let places = |name: &str| places(name, &rpaths, folder);
        assert_eq!(
            places("@rpath/Z.framework/Z"),
            [
                PathBuf::from("/A/X.app/Contents/Frameworks/Z.framework/Z"),
                PathBuf::from("/A/X.app/Contents/MacOS/lib/Z.framework/Z"),
                PathBuf::from("/opt/lib/Z.framework/Z"),
            ]
        );
        assert_eq!(
            places("@loader_path/../lib/a.dylib"),
            [PathBuf::from("/A/X.app/Contents/lib/a.dylib")]
        );
        assert_eq!(
            places("/usr/lib/libz.dylib"),
            [PathBuf::from("/usr/lib/libz.dylib")]
        );
        assert!(
            places("libz.dylib").is_empty(),
            "relative to the working directory"
        );

        assert!(is_present(Path::new("/usr/lib/libSystem.B.dylib")));
        assert!(is_present(Path::new(
            "/System/Library/Frameworks/Gone.framework/Gone"
        )));
        assert!(!is_present(Path::new(
            "/usr/local/lib/vigil-test-missing.dylib"
        )));
    }
}
