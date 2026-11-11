//! The startup disk's size and free space, for the row at the bottom of the popover's main view.
//!
//! On APFS, the startup disk's format since macOS 10.13, the home folder lives on the Data
//! volume, which shares its container's space with the system volume. What the user expects to
//! see is the container: its size is what About This Mac and `df -H /System/Volumes/Data` show,
//! and its free space is what `df` calls available. The name is the system volume's
//! ("Macintosh HD"); the Data volume is named "Data".
//!
//! All three come from one `diskutil info -plist /`. The alternatives weighed: `statfs` and
//! `getattrlist(ATTR_VOL_NAME)` are C calls that std does not wrap, and the workspace forbids
//! `unsafe`; `df` gives the sizes but not the name. diskutil takes about 0.3 seconds, so the
//! app reads it beside the reports rather than after them, and it is given up on after
//! [`DISKUTIL_TIMEOUT`].
//!
//! Sizes are in decimal units (1 GB = 10^9 bytes), as Finder, About This Mac and `df -H` show
//! them, not the GiB of `df -h`.

use std::io::Read as _;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde::Serialize;

/// diskutil's absolute path: the app runs with launchd's minimal environment.
const DISKUTIL: &str = "/usr/sbin/diskutil";

/// The `PATH` diskutil runs with: launchd's default, so nothing from the user's shell runs.
const FIXED_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// How long diskutil may take before the row is left out. Arbitrary: ten times the 0.3 seconds
/// it takes on a 2026 Mac laptop, and short enough that a stuck disk service does not hold up the
/// popover, which waits for the disk with the rest of its overview.
const DISKUTIL_TIMEOUT: Duration = Duration::from_secs(3);

/// The startup disk as the popover shows it. Its fields are private so that only
/// `Disk::new` builds one, keeping the shares summing to 100; the app only serializes it. The
/// byte counts are not sent: the UI shows only these strings and shares.
#[derive(Debug, Serialize)]
pub struct Disk {
    /// The startup volume's name: "Macintosh HD".
    name: String,
    /// The container's size for display: "245 GB".
    size: String,
    /// The whole row in words, for screen readers and the tooltip:
    /// "Macintosh HD: 28 GB free of 245 GB".
    label: String,
    /// How much of the disk is used, from 0 to 100.
    used_percent: f64,
    /// How much of the disk is free, from 0 to 100; `used_percent` plus this is 100.
    free_percent: f64,
}

impl Disk {
    /// The disk from its name, size and free bytes. `None` for a size of 0, which no mounted
    /// disk has; free space above the size is taken as all of it.
    fn new(name: String, total: u64, free: u64) -> Option<Self> {
        if total == 0 {
            return None;
        }
        let free = free.min(total);
        #[expect(
            clippy::cast_precision_loss,
            reason = "a percentage needs about 4 significant digits, f64 keeps 15"
        )]
        let free_percent = free as f64 / total as f64 * 100.0;
        let size = decimal_size(total);
        let label = format!("{name}: {} free of {size}", decimal_size(free));
        Some(Self {
            name,
            size,
            label,
            used_percent: 100.0 - free_percent,
            free_percent,
        })
    }
}

/// Reads the startup disk with diskutil. `None` when diskutil fails or its output lacks the
/// name or the APFS container's sizes; the popover then hides the row.
///
/// Spawns diskutil and waits for it, about 0.3 seconds; one whose output has not ended within
/// [`DISKUTIL_TIMEOUT`] is killed and gives `None`.
pub fn startup_disk() -> Option<Disk> {
    let mut diskutil = Command::new(DISKUTIL);
    diskutil
        .args(["info", "-plist", "/"])
        .env_clear()
        .env("PATH", FIXED_PATH);
    let out = stdout_within(&mut diskutil, DISKUTIL_TIMEOUT)?;
    parse_info(&String::from_utf8(out).ok()?)
}

/// What `command` prints, if its output ends within `timeout` and it then exits successfully.
/// Past the timeout the command is killed and the answer is `None`; a process it started that
/// still holds its output open is left to end on its own, with the thread reading from it.
fn stdout_within(command: &mut Command, timeout: Duration) -> Option<Vec<u8>> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Read on its own thread, so output larger than the pipe's buffer cannot stall the command
    // while this side waits, and so the wait can have a deadline. Capacity 1: the one result
    // is sent without blocking, even after this side stopped listening.
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut out = Vec::new();
        // The receiver is gone after a timeout; the result is then unwanted.
        drop(send.send(stdout.read_to_end(&mut out).ok().map(|_| out)));
    });
    let Ok(Some(out)) = receive.recv_timeout(timeout) else {
        // Best effort: the child may have exited already, and either way the answer is None.
        drop(child.kill());
        drop(child.wait());
        return None;
    };
    // Its output has ended, so it has exited or is about to.
    let status = child.wait().ok()?;
    status.success().then_some(out)
}

/// The disk from the plist `diskutil info -plist /` prints.
fn parse_info(plist: &str) -> Option<Disk> {
    let name = unescape(plist_value(plist, "VolumeName", "string")?);
    let total = plist_value(plist, "APFSContainerSize", "integer")?
        .parse()
        .ok()?;
    let free = plist_value(plist, "APFSContainerFree", "integer")?
        .parse()
        .ok()?;
    Disk::new(name, total, free)
}

/// The text of the `<tag>` element right after the first `<key>key</key>`. The plist's nested
/// dictionaries (`APFSPhysicalStores`, the SMART keys) use none of the keys read here, so the
/// first match is the top-level one; the test fixture keeps both in place to check it.
fn plist_value<'a>(plist: &'a str, key: &str, tag: &str) -> Option<&'a str> {
    let key = format!("<key>{key}</key>");
    let after_key = &plist[plist.find(&key)? + key.len()..];
    let value = after_key.trim_start().strip_prefix(&format!("<{tag}>"))?;
    Some(&value[..value.find(&format!("</{tag}>"))?])
}

/// Undoes XML's escapes, which a volume name such as "Tom & Jerry" carries in the plist.
/// `&amp;` goes last, so an escaped escape ("&amp;lt;") stays as written ("&lt;").
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// A byte count in decimal gigabytes or terabytes as Finder rounds them: whole units from 10
/// up ("245 GB"), one decimal below ("4.2 GB"), and no ".0" ("1 TB", "0 GB").
fn decimal_size(bytes: u64) -> String {
    // From 999.5 GB up, rounding would print "1000 GB".
    let (unit, scale) = if bytes >= 999_500_000_000 {
        ("TB", 1e12)
    } else {
        ("GB", 1e9)
    };
    #[expect(
        clippy::cast_precision_loss,
        reason = "a display size needs 4 significant digits, f64 keeps 15"
    )]
    let value = bytes as f64 / scale;
    // From 9.95 up, one decimal would round to "10.0".
    let rounded = if value >= 9.95 {
        value.round()
    } else {
        (value * 10.0).round() / 10.0
    };
    format!("{rounded} {unit}")
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The parts of `diskutil info -plist /` that matter, from macOS 27 on an APFS startup disk,
    /// with the neighbouring keys that hold other sizes and the two nested dictionaries, in the
    /// real output's order, so the lookup must pick the right one.
    const INFO: &str = r"<?xml version='1.0' encoding='UTF-8'?>
<plist version='1.0'>
<dict>
	<key>APFSContainerFree</key>
	<integer>27953098752</integer>
	<key>APFSContainerReference</key>
	<string>disk3</string>
	<key>APFSContainerSize</key>
	<integer>245107195904</integer>
	<key>APFSPhysicalStores</key>
	<array>
		<dict>
			<key>APFSPhysicalStore</key>
			<string>disk0s2</string>
		</dict>
	</array>
	<key>FreeSpace</key>
	<integer>0</integer>
	<key>SMARTDeviceSpecificKeysMayVaryNotGuaranteed</key>
	<dict>
		<key>AVAILABLE_SPARE</key>
		<integer>100</integer>
	</dict>
	<key>VolumeName</key>
	<string>Macintosh HD</string>
	<key>VolumeSize</key>
	<integer>0</integer>
</dict>
</plist>
";

    #[test]
    fn reads_the_container_s_size_and_free_space_and_the_volume_s_name() {
        let disk = parse_info(INFO).unwrap();
        assert_eq!(disk.name, "Macintosh HD");
        assert_eq!(disk.size, "245 GB");
        assert_eq!(disk.label, "Macintosh HD: 28 GB free of 245 GB");
    }

    /// Every Mac this runs on, CI's included, starts from an APFS disk.
    #[test]
    fn reads_this_mac_s_startup_disk_with_a_minimal_environment() {
        let disk = startup_disk().expect("diskutil describes the startup disk");
        assert_ne!(disk.name, "");
        assert!(disk.label.starts_with(&disk.name), "{}", disk.label);
        assert!((disk.used_percent + disk.free_percent - 100.0).abs() < 1e-9);
    }

    #[test]
    fn gives_up_on_a_command_that_outlives_its_deadline() {
        let mut slow = Command::new("/bin/sh");
        slow.args(["-c", "echo early; sleep 5"]);
        assert_eq!(stdout_within(&mut slow, Duration::from_millis(100)), None);
    }

    #[test]
    fn reads_output_larger_than_the_pipe_s_buffer() {
        let mut large = Command::new("/bin/sh");
        large.args(["-c", "head -c 200000 /dev/zero"]);
        let out = stdout_within(&mut large, DISKUTIL_TIMEOUT).expect("head succeeds");
        assert_eq!(out.len(), 200_000);
    }

    #[test]
    fn returns_what_a_command_prints_only_when_it_succeeds() {
        let mut ok = Command::new("/bin/sh");
        ok.args(["-c", "echo done"]);
        assert_eq!(
            stdout_within(&mut ok, DISKUTIL_TIMEOUT),
            Some(b"done\n".to_vec())
        );
        let mut failed = Command::new("/bin/sh");
        failed.args(["-c", "echo partial; exit 1"]);
        assert_eq!(stdout_within(&mut failed, DISKUTIL_TIMEOUT), None);
    }

    #[test]
    fn decodes_escapes_in_the_name() {
        let info = INFO.replace("Macintosh HD", "Tom &amp; Jerry &lt;3 &amp;lt;");
        assert_eq!(parse_info(&info).unwrap().name, "Tom & Jerry <3 &lt;");
    }

    #[test]
    fn is_none_without_a_name_or_container_sizes() {
        for key in ["VolumeName", "APFSContainerSize", "APFSContainerFree"] {
            let info = INFO.replace(&format!("<key>{key}</key>"), "<key>Other</key>");
            assert!(parse_info(&info).is_none(), "without {key}");
        }
        assert!(parse_info("").is_none());
    }

    #[test]
    fn is_none_when_a_size_is_not_a_number() {
        let info = INFO.replace("245107195904", "-1");
        assert!(parse_info(&info).is_none());
        let info = INFO.replace("<integer>27953098752", "<string>27953098752");
        assert!(parse_info(&info).is_none());
    }

    #[test]
    fn is_none_for_a_disk_of_size_zero() {
        assert!(Disk::new("Empty".into(), 0, 0).is_none());
        assert!(Disk::new("Empty".into(), 0, 5).is_none());
    }

    #[test]
    fn takes_free_space_above_the_size_as_all_of_it() {
        let disk = Disk::new("Odd".into(), 1_000_000_000, 2_000_000_000).unwrap();
        assert!((disk.free_percent - 100.0).abs() < f64::EPSILON);
        assert!(disk.used_percent.abs() < f64::EPSILON);
        assert_eq!(disk.label, "Odd: 1 GB free of 1 GB");
    }

    #[test]
    fn splits_the_disk_into_used_and_free() {
        let disk = Disk::new("Half".into(), 200_000_000_000, 50_000_000_000).unwrap();
        assert!((disk.used_percent - 75.0).abs() < 1e-9);
        assert!((disk.free_percent - 25.0).abs() < 1e-9);
    }

    #[test]
    fn rounds_sizes_as_finder_does() {
        for (bytes, shown) in [
            (0, "0 GB"),
            (40_000_000, "0 GB"),
            (50_000_000, "0.1 GB"),
            (500_000_000, "0.5 GB"),
            (1_000_000_000, "1 GB"),
            (4_249_999_999, "4.2 GB"),
            (4_250_000_001, "4.3 GB"),
            (9_949_999_999, "9.9 GB"),
            (9_950_000_000, "10 GB"),
            (27_953_098_752, "28 GB"),
            (245_107_195_904, "245 GB"),
            (999_499_999_999, "999 GB"),
            (999_500_000_000, "1 TB"),
            (1_250_000_000_000, "1.3 TB"),
            (2_000_398_934_016, "2 TB"),
        ] {
            assert_eq!(decimal_size(bytes), shown, "{bytes} bytes");
        }
    }

    proptest! {
        #[test]
        fn used_and_free_are_shares_of_one_hundred(total in 1..u64::MAX, free: u64) {
            let disk = Disk::new("Any".into(), total, free).unwrap();
            prop_assert!((0.0..=100.0).contains(&disk.used_percent));
            prop_assert!((0.0..=100.0).contains(&disk.free_percent));
            prop_assert!((disk.used_percent + disk.free_percent - 100.0).abs() < 1e-9);
        }
    }
}
