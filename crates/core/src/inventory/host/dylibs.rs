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
//! Read: the program each startup item runs, the files an interpreter or `env` it runs is given
//! (a Mach-O tool there is what the loader loads), and the main executable of each app in
//! `/Applications` and `~/Applications`. Not read: kernel extensions, which the kernel loads
//! rather than the loader; the libraries those programs load in turn; other executables inside
//! an app (helpers, plug-ins); and loads relative to the working directory, which depend on how
//! the program is started.
//!
//! Libraries in the system's shared cache are not files on disk, and Vigil cannot ask the
//! loader what the cache holds (`unsafe` is forbidden in this workspace). An absolute install
//! name on the sealed system volume counts as found there, as does the Swift runtime
//! (`libswift*.dylib`) through `/usr/lib/swift`; any other place on that volume is empty, and
//! only Apple writes there.

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
    /// Whether it is an app's main executable (`<app>/Contents/MacOS/<name>`), named by that
    /// path rather than its real one: an app in `/Applications` may be a link to one elsewhere,
    /// and only the path in the folder lets a listing failure there carry its issue
    /// ([`InventorySource::ApplicationFolder`]).
    pub(super) in_app: bool,
}

/// A program a planted library could take over, one line of `mac/dylibs.jsonl`.
#[derive(Debug, Serialize)]
pub(super) struct Hijackable {
    /// The program's name ([`Read::name`]), which its issue names it by. Text, as an item's
    /// path is.
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
/// apps run is read once, by its real path, and named as [`Read::name`] says. A program that
/// is not there or is not Mach-O (a script) is left out: the item already says so. One that
/// cannot be read fails its [`InventorySource::LoadCommands`].
pub(super) fn scan(
    inventory: &mut Inventory,
    programs: Vec<Program>,
    account: &Account,
) -> Vec<Hijackable> {
    let mut found = Vec::new();
    for (real, read) in by_real_path(programs) {
        let images = match macho::read(&real) {
            Ok(images) => images,
            Err(macho::ReadError::NotMachO) => continue,
            Err(macho::ReadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => continue,
            // Root's own helpers (`/Library/PrivilegedHelperTools`) and other users' files stay
            // unreadable on every sweep: a note, as `InventoryError::Io` makes it elsewhere.
            Err(macho::ReadError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                let detail = format!("cannot read it: {e}");
                let path = real;
                inventory
                    .problems
                    .push(InventoryError::MachO { path, detail });
                continue;
            }
            Err(macho::ReadError::Io(e)) => {
                let source = InventorySource::LoadCommands {
                    path: text(&read.name),
                };
                inventory.fail(source, InventoryError::io(&real, e));
                continue;
            }
            Err(macho::ReadError::Malformed(detail)) => {
                let path = real;
                inventory
                    .problems
                    .push(InventoryError::MachO { path, detail });
                continue;
            }
        };
        let folder = real.parent().unwrap_or(Path::new("/"));
        let plants: BTreeSet<Plant> = images
            .iter()
            .filter(|image| !validated(image, &real))
            .flat_map(|image| plants(image, folder, account))
            .collect();
        if !plants.is_empty() {
            found.push(Hijackable {
                path: text(&read.name),
                used_by: read.used_by,
                runs_as_root: read.runs_as_root,
                plants,
            });
        }
    }
    found
}

/// Records the programs in `programs` as not read, when where this user could plant a library
/// is not known: their issues carry over instead of reading as resolved.
pub(super) fn not_scanned(inventory: &mut Inventory, programs: Vec<Program>) {
    for read in by_real_path(programs).into_values() {
        let path = text(&read.name);
        inventory
            .failed
            .insert(InventorySource::LoadCommands { path });
    }
}

/// A program file to read, from every [`Program`] that names it.
#[derive(Debug)]
struct Read {
    /// What its issue names it by. The real path, so the key does not depend on which item
    /// names it first; for an app's executable, its path in the app ([`Program::in_app`]).
    /// The inventory lists each app once, by its real bundle, so one app names a file.
    /// Accepted downside: on a sweep that cannot list the app's folder, a startup item that runs
    /// the same file names it by its real path, so that sweep shows a second issue for it. It
    /// takes a linked app, an item running its executable and a listing failure at once.
    name: PathBuf,
    /// What runs it.
    used_by: Vec<String>,
    /// Whether any of those runs it as root.
    runs_as_root: bool,
}

/// `programs` by their real paths.
fn by_real_path(programs: Vec<Program>) -> BTreeMap<PathBuf, Read> {
    let mut by_file: BTreeMap<PathBuf, Read> = BTreeMap::new();
    for program in programs {
        let real = fs::canonicalize(&program.path).unwrap_or_else(|_| program.path.clone());
        let read = by_file.entry(real).or_insert_with_key(|real| Read {
            name: real.clone(),
            used_by: Vec::new(),
            runs_as_root: false,
        });
        if program.in_app {
            read.name = program.path;
        }
        read.used_by.push(program.used_by);
        read.runs_as_root |= program.as_root;
    }
    by_file
}

/// Whether the loader validates the libraries of `image`, the program at `real`: then a
/// planted one is refused. The platform claim counts only where only Apple writes (see
/// `Image::platform`).
fn validated(image: &Image, real: &Path) -> bool {
    image.library_validation || (image.platform && on_sealed_volume(real))
}

/// The places a library planted would load from, for the image of a program in `folder`, that
/// this user could create.
fn plants(image: &Image, folder: &Path, account: &Account) -> Vec<Plant> {
    let mut plants = Vec::new();
    for load in &image.loads {
        let places = places(&load.name, &image.rpaths, folder);
        // On the sealed volume, a library linked by absolute path is Apple's, in the shared
        // cache rather than on disk. Through `@rpath`, only the Swift runtime is there: the
        // `libswift*.dylib` in `/usr/lib/swift`, the rpath Apple's toolchain puts first. Any
        // other place there is empty, and nobody but Apple can plant in it, so the loader goes
        // on to the next one.
        let by_rpath = load.name.starts_with("@rpath/");
        let swift_runtime = |place: &Path| {
            place.parent() == Some(Path::new("/usr/lib/swift"))
                && place
                    .file_name()
                    .is_some_and(|name| name.as_encoded_bytes().starts_with(b"libswift"))
        };
        let in_cache =
            |place: &Path| on_sealed_volume(place) && (!by_rpath || swift_runtime(place));
        // A place that cannot be checked counts as found, so no plant is guessed behind it.
        let present = |place: &Path| in_cache(place) || place.try_exists().unwrap_or(true);
        let found = places.iter().position(|place| present(place));
        let (earlier, why) = match found {
            // Every earlier place is tried first, and is empty. Found at the first, there is
            // none.
            Some(i) => (&places[..i], Why::EarlierRpath),
            // Not found: a weak load starts without it, and loads it from any place it looks.
            None if load.weak => (&places[..], Why::WeakMissing),
            // A strong load not found, which does not start at all.
            None => continue,
        };
        let plantable = earlier
            .iter()
            .filter(|place| !on_sealed_volume(place) && account.can_replace(place));
        plants.extend(plantable.map(|place| Plant {
            load: load.name.clone(),
            weak: load.weak,
            path: text(place),
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
        if path == "@executable_path" || path == "@loader_path" {
            return Some(folder.to_owned());
        }
        let relative = path
            .strip_prefix("@executable_path/")
            .or_else(|| path.strip_prefix("@loader_path/"));
        match relative {
            Some(relative) => Some(normal(&under(folder, relative))),
            None if path.starts_with('/') => Some(normal(Path::new(path))),
            None => None,
        }
    };
    match name.strip_prefix("@rpath/") {
        Some(rest) => rpaths
            .iter()
            .filter_map(|rpath| expand(rpath))
            .map(|rpath| normal(&under(&rpath, rest)))
            .collect(),
        None => expand(name).into_iter().collect(),
    }
}

/// `relative` under `folder`, as the loader joins them, by text: a slash at its start
/// (`@executable_path//lib`) keeps it under the folder, where `Path::join` would start over
/// at the root.
fn under(folder: &Path, relative: &str) -> PathBuf {
    folder.join(relative.trim_start_matches('/'))
}

/// Whether `path` is on the sealed system volume, which only Apple writes: under `/System`
/// (but its writable `/System/Volumes`), `/usr` (but `/usr/local`), `/bin` or `/sbin`.
fn on_sealed_volume(path: &Path) -> bool {
    (path.starts_with("/System") && !path.starts_with("/System/Volumes"))
        || (path.starts_with("/usr") && !path.starts_with("/usr/local"))
        || path.starts_with("/bin")
        || path.starts_with("/sbin")
}

/// `path` as text, any byte that is not UTF-8 replaced, as an item's path is.
fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
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
    use crate::findings::Subject;
    use crate::inventory::host::macho::Load;

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
            in_app: false,
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

        // Apple's own programs claim to be platform binaries, which the loader always
        // validates; the claim counts only on the sealed volume, where only Apple writes.
        let ls = macho::read(Path::new("/bin/ls")).unwrap();
        assert!(ls.iter().all(|i| i.platform));
    }

    #[test]
    fn the_issue_key_follows_the_places_and_root_not_what_runs_it() {
        let plant = |path: &str| Plant {
            load: "@rpath/a.dylib".to_owned(),
            weak: false,
            path: path.to_owned(),
            why: Why::EarlierRpath,
        };
        let program = |used_by: &str, runs_as_root, place: &str| Hijackable {
            path: "/A.app/Contents/MacOS/A".to_owned(),
            used_by: vec![used_by.to_owned()],
            runs_as_root,
            plants: BTreeSet::from([plant(place)]),
        };
        let first = program("/A.app", false, "/x/a.dylib");
        assert_eq!(
            first.identity(),
            program("/L/b.plist", false, "/x/a.dylib").identity()
        );
        assert_ne!(
            first.identity(),
            program("/A.app", true, "/x/a.dylib").identity()
        );
        assert_ne!(
            first.identity(),
            program("/A.app", false, "/y/a.dylib").identity()
        );
    }

    #[test]
    fn a_platform_claim_counts_only_on_the_sealed_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = fs::canonicalize(tmp.path()).unwrap();
        let image = |library_validation, platform| Image {
            loads: vec![Load {
                name: dir.join("gone.dylib").to_str().unwrap().to_owned(),
                weak: true,
            }],
            rpaths: Vec::new(),
            library_validation,
            platform,
        };
        let app = dir.join("app");
        let sealed = Path::new("/bin/ls");

        // A copy of a planted program that sets the byte is still read.
        let claimed = image(false, true);
        assert!(!validated(&claimed, &app));
        assert_eq!(plants(&claimed, &dir, &account()).len(), 1);
        // Apple's own claim, on the sealed volume, is honored; without it, nothing is validated.
        assert!(validated(&claimed, sealed));
        assert!(!validated(&image(false, false), sealed));
        // Library validation holds anywhere.
        assert!(validated(&image(true, false), &app));
    }

    #[test]
    fn a_program_not_read_carries_its_issue_once_by_its_real_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = fs::canonicalize(tmp.path()).unwrap();
        fs::write(dir.join("tool"), "").unwrap();
        std::os::unix::fs::symlink(dir.join("tool"), dir.join("link")).unwrap();
        let mut inventory = Inventory::default();
        let programs = vec![
            program(&dir.join("link"), "/L/one.plist", false),
            program(&dir.join("tool"), "/L/two.plist", true),
        ];

        not_scanned(&mut inventory, programs);

        let path = dir.join("tool").display().to_string();
        let expected = BTreeSet::from([InventorySource::LoadCommands { path }]);
        assert_eq!(inventory.failed, expected);
    }

    #[test]
    fn an_app_linked_into_its_folder_is_named_in_the_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = fs::canonicalize(tmp.path()).unwrap();
        let macos = dir.join("Ext/Foo.app/Contents/MacOS");
        fs::create_dir_all(&macos).unwrap();
        fs::write(macos.join("Foo"), "").unwrap();
        let folder = dir.join("Applications");
        fs::create_dir(&folder).unwrap();
        std::os::unix::fs::symlink(dir.join("Ext/Foo.app"), folder.join("Foo.app")).unwrap();
        let in_folder = folder.join("Foo.app/Contents/MacOS/Foo");
        // A login item names the real file first; the app's path still names it.
        let programs = vec![
            program(&macos.join("Foo"), "/L/item.plist", false),
            Program {
                in_app: true,
                ..program(&in_folder, "/Applications/Foo.app", false)
            },
        ];
        let mut inventory = Inventory::default();

        not_scanned(&mut inventory, programs);

        let path = in_folder.display().to_string();
        let subject = Subject::Item(path.clone());
        let expected = BTreeSet::from([InventorySource::LoadCommands { path }]);
        assert_eq!(inventory.failed, expected);
        // So a listing failure of the folder carries its issue.
        let listing = InventorySource::ApplicationFolder { path: folder };
        assert!(listing.covers_issue(&subject));
    }

    #[test]
    fn a_sealed_place_holds_only_apples_libraries_so_the_search_goes_on() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(dir.join("Frameworks")).unwrap();
        let image = |name: &str, weak: bool, rpaths: &[&str]| Image {
            loads: vec![Load {
                name: name.to_owned(),
                weak,
            }],
            rpaths: rpaths.iter().map(|r| (*r).to_owned()).collect(),
            library_validation: false,
            platform: false,
        };
        let found = |image: &Image| -> Vec<String> {
            let plants = plants(image, &dir.join("MacOS"), &account());
            plants.into_iter().map(|p| p.path).collect()
        };
        let frameworks = dir.join("Frameworks/Foo.framework/Foo");

        // An app's own framework is not in `/usr/lib/swift`: the search goes on to `Frameworks`.
        let swift_first = ["/usr/lib/swift", "@executable_path/../Frameworks"];
        let missing = image("@rpath/Foo.framework/Foo", true, &swift_first);
        assert_eq!(found(&missing), [frameworks.display().to_string()]);
        // The Swift runtime is in the cache through `/usr/lib/swift`.
        let swift = image("@rpath/libswiftCore.dylib", true, &swift_first);
        assert_eq!(found(&swift), Vec::<String>::new());
        // So is a system library linked by absolute path, though not on disk.
        let system = image("/usr/lib/libvigil-test-missing.dylib", true, &[]);
        assert_eq!(found(&system), Vec::<String>::new());
        // A bare `@loader_path` is the program's own folder, tried first.
        fs::create_dir_all(dir.join("MacOS")).unwrap();
        fs::create_dir_all(frameworks.parent().unwrap()).unwrap();
        fs::write(&frameworks, "").unwrap();
        let rpaths = ["@loader_path", "@executable_path/../Frameworks"];
        let bare = image("@rpath/Foo.framework/Foo", false, &rpaths);
        let own = dir.join("MacOS/Foo.framework/Foo");
        assert_eq!(found(&bare), [own.display().to_string()]);
        // Only the Swift runtime is in the cache through `/usr/lib/swift`, not any library.
        let other = image("@rpath/libother.dylib", true, &swift_first);
        let other_here = dir.join("Frameworks/libother.dylib");
        assert_eq!(found(&other), [other_here.display().to_string()]);
        // A place off the sealed volume that this user cannot create is left out.
        let locked = [
            "/Library/vigil-test-absent",
            "@executable_path/../Frameworks",
        ];
        let gone = image("@rpath/Gone.framework/Gone", true, &locked);
        let gone_here = dir.join("Frameworks/Gone.framework/Gone");
        assert_eq!(found(&gone), [gone_here.display().to_string()]);
        // A strong load not found stops the program from starting, so nothing is planted.
        let strong = image("@rpath/Gone.framework/Gone", false, &locked);
        assert_eq!(found(&strong), Vec::<String>::new());
        // A weak load with no rpath looks nowhere.
        let nowhere = image("@rpath/Foo.framework/Foo", true, &[]);
        assert_eq!(found(&nowhere), Vec::<String>::new());
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
    fn places_follow_the_loaders_names_and_the_sealed_volume_is_apples() {
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

        // A slash after the token keeps the place under the folder, as the loader joins text.
        let doubled = ["@executable_path//lib".to_owned()];
        assert_eq!(
            super::places("@rpath//z.dylib", &doubled, folder),
            [folder.join("lib/z.dylib")]
        );
        let bare = ["@executable_path".to_owned()];
        assert_eq!(
            super::places("@rpath/z.dylib", &bare, folder),
            [folder.join("z.dylib")]
        );
        for (path, sealed) in [
            ("/usr/lib/libSystem.B.dylib", true),
            ("/System/Library/Frameworks/A.framework/A", true),
            ("/System/Volumes/Data/Users/me/lib.dylib", false),
            ("/usr/local/lib/a.dylib", false),
            ("/sbin/launchd", true),
            ("/Library/Frameworks/A.framework/A", false),
        ] {
            assert_eq!(on_sealed_volume(Path::new(path)), sealed, "{path}");
        }
    }
}
