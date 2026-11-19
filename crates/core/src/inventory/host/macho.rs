//! The parts of a Mach-O program that decide which libraries it loads, and from where: its
//! load commands and whether its code signature makes the loader enforce library validation.
//!
//! Vigil reads these itself, as it reads signatures, because a sweep's agent runs no commands
//! and `otool` ships only with Apple's developer tools. Only the header, the load commands, and
//! two blobs of the signature are read, each within a limit, never the whole file: an app's
//! executable can be hundreds of megabytes.
//!
//! The formats follow Apple's headers in the macOS SDK: `mach-o/loader.h` and `mach-o/fat.h`
//! for the file, and `Security/CSCommon.h` with the `cs_blobs.h` of XNU for the signature
//! (<https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/cs_blobs.h>).
//! A thin file is little-endian, as every Mac it runs on; a universal (fat) file's header and
//! a signature are big-endian.

use std::io;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use crate::paths;

/// One architecture's image in a program that this Mac can run: a thin file has one, a
/// universal file one per `arm64` or `x86_64` slice.
#[derive(Debug)]
pub(super) struct Image {
    /// The libraries it loads, in load-command order.
    pub(super) loads: Vec<Load>,
    /// Its `LC_RPATH` entries, in the order the loader tries them.
    pub(super) rpaths: Vec<String>,
    /// Whether its signature makes the loader refuse a library not signed by Apple or the
    /// program's own team: flagged `library-validation`, or the hardened runtime without the
    /// entitlement that turns validation off.
    pub(super) library_validation: bool,
    /// Whether its code directory claims a platform binary, which the loader always validates.
    /// Anyone who signs a file can set the byte; the kernel honors it only for Apple's own
    /// code, so the caller trusts it only where only Apple writes.
    pub(super) platform: bool,
}

/// A library a program loads, by the install name its load command gives.
#[derive(Debug)]
pub(super) struct Load {
    /// As written: an absolute path, or one starting `@rpath/`, `@executable_path/` or
    /// `@loader_path/`.
    pub(super) name: String,
    /// `LC_LOAD_WEAK_DYLIB`: the program starts without it when it is not found.
    pub(super) weak: bool,
}

/// Why a file's images could not be read.
#[derive(Debug)]
pub(super) enum ReadError {
    /// The file could not be opened or read.
    Io(io::Error),
    /// The file is not a Mach-O program: a script, or another format.
    NotMachO,
    /// The file is a Mach-O program whose structure does not hold together.
    Malformed(String),
}

impl From<io::Error> for ReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

// Magic numbers, from `mach-o/loader.h` and `mach-o/fat.h`.
const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;

// Load commands, from `mach-o/loader.h`. `LC_REQ_DYLD` (0x8000_0000) is part of the values.
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_RPATH: u32 = 0x8000_001c;
const LC_CODE_SIGNATURE: u32 = 0x1d;

// The architectures a Mac runs, from `mach/machine.h`: arm64 (arm64e included, a subtype), and
// x86_64 under Rosetta. Slices of others (i386, ppc) never load, so they are not read.
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;

// Code signature blobs and flags, from `cs_blobs.h`.
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ENTITLEMENTS: u32 = 5;
const CS_REQUIRE_LV: u32 = 0x2000;
const CS_RUNTIME: u32 = 0x1_0000;

/// The entitlement with which a hardened program loads libraries anyone signed.
const DISABLE_LIBRARY_VALIDATION: &str = "com.apple.security.cs.disable-library-validation";

/// The most slices read from a universal file. Arbitrary: Apple ships at most a few. A Java
/// class file starts with `FAT_MAGIC` too, followed by its version (45 or more), which this
/// keeps from being read as one.
const FAT_ARCH_LIMIT: u32 = 16;

/// The most bytes of load commands read. Arbitrary: an app's are tens of kilobytes.
const COMMANDS_LIMIT: u32 = 1024 * 1024;

/// The most blobs read from a signature's index. Arbitrary: a signature holds about ten.
const BLOB_LIMIT: u32 = 64;

/// The largest entitlements blob read. Arbitrary: entitlements are a few kilobytes.
const ENTITLEMENTS_LIMIT: u32 = 1024 * 1024;

/// Reads the images of the program at `path`. A link is followed by the caller, not here: the
/// file is opened as [`paths::open_regular`] opens it, so a FIFO cannot block the sweep.
pub(super) fn read(path: &Path) -> Result<Vec<Image>, ReadError> {
    let file = match paths::open_regular(path) {
        // A folder (an app whose executable is not there) or a FIFO runs no Mach-O.
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => return Err(ReadError::NotMachO),
        other => other?,
    };
    let len = file.metadata()?.len();
    if len < 4 {
        return Err(ReadError::NotMachO);
    }
    let mut magic = [0; 4];
    file.read_exact_at(&mut magic, 0)?;
    match u32::from_be_bytes(magic) {
        FAT_MAGIC => fat(&file, len, false),
        FAT_MAGIC_64 => fat(&file, len, true),
        _ => Ok(image(&file, 0, len)?.into_iter().collect()),
    }
}

fn runs_here(cputype: u32) -> bool {
    matches!(cputype, CPU_TYPE_ARM64 | CPU_TYPE_X86_64)
}

/// The slices of a universal file of `len` bytes: `fat_arch` entries of 20 bytes, or
/// `fat_arch_64` ones of 32, after an 8-byte header.
fn fat(file: &std::fs::File, len: u64, wide: bool) -> Result<Vec<Image>, ReadError> {
    let count = u32::from_be_bytes(read_array(file, 4)?);
    if count == 0 || count > FAT_ARCH_LIMIT {
        return Err(ReadError::NotMachO);
    }
    let entry = if wide { 32 } else { 20 };
    let mut table = vec![0; count as usize * entry];
    file.read_exact_at(&mut table, 8)
        .map_err(|_| malformed("its universal header is cut short"))?;
    let mut images = Vec::new();
    for arch in table.chunks_exact(entry) {
        let (offset, size) = if wide {
            (be64(arch, 8), be64(arch, 16))
        } else {
            (u64::from(be32(arch, 8)), u64::from(be32(arch, 12)))
        };
        if offset.checked_add(size).is_none_or(|end| end > len) {
            return Err(malformed("a slice lies past the end of the file"));
        }
        if !runs_here(be32(arch, 0)) {
            continue;
        }
        // A slice that is not Mach-O is skipped, and the others still count.
        match image(file, offset, size) {
            Ok(slice) => images.extend(slice),
            Err(ReadError::NotMachO) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(images)
}

/// The image of `size` bytes at `base`, or `None` for an architecture this Mac does not run.
fn image(file: &std::fs::File, base: u64, size: u64) -> Result<Option<Image>, ReadError> {
    let mut header = [0; 32];
    if size < 28 {
        return Err(ReadError::NotMachO);
    }
    file.read_exact_at(&mut header[..28], base)?;
    let header_len: u32 = match le32(&header, 0) {
        MH_MAGIC => 28,
        MH_MAGIC_64 => 32,
        _ => return Err(ReadError::NotMachO),
    };
    if !runs_here(le32(&header, 4)) {
        return Ok(None);
    }
    let ncmds = le32(&header, 16);
    let sizeofcmds = le32(&header, 20);
    if sizeofcmds > COMMANDS_LIMIT || u64::from(header_len + sizeofcmds) > size {
        return Err(malformed("its load commands do not fit in it"));
    }
    let mut commands = vec![0; sizeofcmds as usize];
    file.read_exact_at(&mut commands, base + u64::from(header_len))?;

    let mut loads = Vec::new();
    let mut rpaths = Vec::new();
    let mut signature = None;
    let mut at = 0;
    for _ in 0..ncmds {
        let command = commands
            .get(at..at + 8)
            .ok_or_else(|| malformed("a load command lies past the others' end"))?;
        let (cmd, cmdsize) = (le32(command, 0), le32(command, 4) as usize);
        let command = commands
            .get(at..at.saturating_add(cmdsize))
            .filter(|_| cmdsize >= 8)
            .ok_or_else(|| malformed("a load command's size is wrong"))?;
        match cmd {
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => loads.push(Load {
                name: string_at(command)?,
                weak: cmd == LC_LOAD_WEAK_DYLIB,
            }),
            LC_RPATH => rpaths.push(string_at(command)?),
            LC_CODE_SIGNATURE => {
                let fields = command
                    .get(8..16)
                    .ok_or_else(|| malformed("its LC_CODE_SIGNATURE command is cut short"))?;
                signature = Some((le32(fields, 0), le32(fields, 4)));
            }
            _ => {}
        }
        at += cmdsize;
    }

    let validation = match signature {
        Some((offset, len)) => {
            let (offset, len) = (u64::from(offset), u64::from(len));
            if offset + len > size {
                return Err(malformed("its code signature lies past its end"));
            }
            read_validation(file, base + offset, len)?
        }
        None => Validation::default(),
    };
    Ok(Some(Image {
        loads,
        rpaths,
        library_validation: validation.flagged,
        platform: validation.platform,
    }))
}

/// What a signature says of library validation: see [`Image`].
#[derive(Debug, Default)]
struct Validation {
    flagged: bool,
    platform: bool,
}

/// What the embedded signature of `len` bytes at `at` says of library validation.
fn read_validation(file: &std::fs::File, at: u64, len: u64) -> Result<Validation, ReadError> {
    let blob = |offset: u64, want: u64| -> Result<Vec<u8>, ReadError> {
        if offset.checked_add(want).is_none_or(|end| end > len) {
            return Err(malformed(
                "a code signature blob lies past the signature's end",
            ));
        }
        // At most `ENTITLEMENTS_LIMIT` or a few blob headers, within the signature's `u32`.
        let mut bytes = vec![0; usize::try_from(want).expect("a blob is within a u32 size")];
        file.read_exact_at(&mut bytes, at + offset)?;
        Ok(bytes)
    };
    let header = blob(0, 12)?;
    if be32(&header, 0) != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(malformed("its code signature is not an embedded signature"));
    }
    let count = be32(&header, 8);
    if count > BLOB_LIMIT {
        return Err(malformed("its code signature lists too many blobs"));
    }
    let index = blob(12, u64::from(count) * 8)?;
    let slot = |wanted: u32| {
        let (entries, _) = index.as_chunks::<8>();
        entries
            .iter()
            .find(|entry| be32(&entry[..], 0) == wanted)
            .map(|entry| u64::from(be32(entry, 4)))
    };

    let directory_at = slot(CSSLOT_CODEDIRECTORY)
        .ok_or_else(|| malformed("its code signature has no code directory"))?;
    // Nine 32-bit fields (magic, length, version, flags, ...), then hashSize, hashType and
    // platform, the byte at 38: all within `end_earliest`, the layout of every version.
    let directory = blob(directory_at, 40)?;
    if be32(&directory, 0) != CSMAGIC_CODEDIRECTORY {
        return Err(malformed("its code directory has the wrong magic"));
    }
    let flags = be32(&directory, 12);
    let platform = directory[38] != 0;
    let found = |flagged| Validation { flagged, platform };
    if flags & CS_REQUIRE_LV != 0 {
        return Ok(found(true));
    }
    if flags & CS_RUNTIME == 0 {
        return Ok(found(false));
    }

    let Some(entitlements_at) = slot(CSSLOT_ENTITLEMENTS) else {
        return Ok(found(true));
    };
    let header = blob(entitlements_at, 8)?;
    let length = be32(&header, 4);
    if be32(&header, 0) != CSMAGIC_EMBEDDED_ENTITLEMENTS
        || !(8..=ENTITLEMENTS_LIMIT).contains(&length)
    {
        return Err(malformed("its entitlements blob is not one"));
    }
    let xml = blob(entitlements_at + 8, u64::from(length) - 8)?;
    let entitlements: plist::Dictionary = plist::from_bytes(&xml)
        .map_err(|e| malformed(&format!("its entitlements do not parse: {e}")))?;
    let disabled = entitlements
        .get(DISABLE_LIBRARY_VALIDATION)
        .and_then(plist::Value::as_boolean)
        .unwrap_or(false);
    Ok(found(!disabled))
}

/// The string a load command holds at the offset its third field gives, up to its NUL.
fn string_at(command: &[u8]) -> Result<String, ReadError> {
    let offset = command
        .get(8..12)
        .map(|field| le32(field, 0) as usize)
        .filter(|&offset| offset >= 12)
        .ok_or_else(|| malformed("a load command's string offset is wrong"))?;
    let bytes = command
        .get(offset..)
        .ok_or_else(|| malformed("a load command's string lies past its end"))?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_array<const N: usize>(file: &std::fs::File, at: u64) -> Result<[u8; N], ReadError> {
    let mut bytes = [0; N];
    file.read_exact_at(&mut bytes, at)
        .map_err(|_| malformed("it is cut short"))?;
    Ok(bytes)
}

fn malformed(what: &str) -> ReadError {
    ReadError::Malformed(what.to_owned())
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn be64(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// A thin 64-bit image holding `commands`, each a whole load command.
    fn thin(commands: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = commands.concat();
        let mut file = Vec::new();
        for field in [MH_MAGIC_64, 0x0100_000c, 0, 2] {
            file.extend(field.to_le_bytes());
        }
        file.extend(u32::try_from(commands.len()).unwrap().to_le_bytes());
        file.extend(u32::try_from(body.len()).unwrap().to_le_bytes());
        file.extend([0; 8]);
        file.extend(body);
        file
    }

    /// A load command `cmd` holding `text` at offset 12 (a dylib's name or an rpath).
    fn with_string(cmd: u32, text: &str) -> Vec<u8> {
        let mut command = Vec::new();
        let size = (12 + text.len() + 1).next_multiple_of(8);
        command.extend(cmd.to_le_bytes());
        command.extend(u32::try_from(size).unwrap().to_le_bytes());
        command.extend(12_u32.to_le_bytes());
        command.extend(text.as_bytes());
        command.resize(size, 0);
        command
    }

    fn read_bytes(bytes: &[u8]) -> Result<Vec<Image>, ReadError> {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("program");
        std::fs::write(&path, bytes).unwrap();
        read(&path)
    }

    fn malformed_detail(bytes: &[u8]) -> String {
        match read_bytes(bytes) {
            Err(ReadError::Malformed(detail)) => detail,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn load_commands_give_loads_and_rpaths_in_order() {
        let bytes = thin(&[
            with_string(LC_RPATH, "@executable_path/../Frameworks"),
            with_string(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),
            with_string(LC_LOAD_WEAK_DYLIB, "@rpath/W.framework/W"),
            with_string(LC_REEXPORT_DYLIB, "/r.dylib"),
            with_string(LC_LAZY_LOAD_DYLIB, "/l.dylib"),
            with_string(LC_LOAD_UPWARD_DYLIB, "/u.dylib"),
            with_string(0x2, "a command that is not read"),
        ]);
        let [image] = &read_bytes(&bytes).unwrap()[..] else {
            panic!("one image");
        };
        let loads: Vec<_> = image
            .loads
            .iter()
            .map(|l| (l.name.as_str(), l.weak))
            .collect();
        assert_eq!(
            loads,
            [
                ("/usr/lib/libSystem.B.dylib", false),
                ("@rpath/W.framework/W", true),
                ("/r.dylib", false),
                ("/l.dylib", false),
                ("/u.dylib", false),
            ]
        );
        assert_eq!(image.rpaths, ["@executable_path/../Frameworks"]);
        assert!(!image.library_validation, "no signature");
    }

    #[test]
    fn what_is_not_mach_o_is_told_apart_from_what_is_broken() {
        assert!(matches!(
            read_bytes(b"#!/bin/sh\n"),
            Err(ReadError::NotMachO)
        ));
        assert!(matches!(read_bytes(b""), Err(ReadError::NotMachO)));
        // A Java class file: `cafebabe`, then its version where a slice count would be.
        let class = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34];
        assert!(matches!(read_bytes(&class), Err(ReadError::NotMachO)));

        let mut cut = thin(&[with_string(LC_RPATH, "/a")]);
        cut.truncate(40);
        assert_eq!(malformed_detail(&cut), "its load commands do not fit in it");

        let mut zero = thin(&[with_string(LC_RPATH, "/a")]);
        zero[36..40].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(malformed_detail(&zero), "a load command's size is wrong");

        let mut many = thin(&[with_string(LC_RPATH, "/a")]);
        many[16..20].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            malformed_detail(&many),
            "a load command lies past the others' end"
        );

        let mut far = thin(&[with_string(LC_RPATH, "/a")]);
        far[40..44].copy_from_slice(&200_u32.to_le_bytes());
        assert_eq!(
            malformed_detail(&far),
            "a load command's string lies past its end"
        );

        let mut fat = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1];
        for field in [0x0100_000c_u32, 0, 4096, 4096, 12] {
            fat.extend(field.to_be_bytes());
        }
        assert_eq!(
            malformed_detail(&fat),
            "a slice lies past the end of the file"
        );
    }

    /// An `LC_CODE_SIGNATURE` command pointing at `signature`, appended to `file` after its
    /// load commands, as the linker places it.
    fn signed(mut commands: Vec<Vec<u8>>, signature: &[u8]) -> Vec<u8> {
        let mut command = Vec::new();
        for field in [
            LC_CODE_SIGNATURE,
            16,
            0,
            u32::try_from(signature.len()).unwrap(),
        ] {
            command.extend(field.to_le_bytes());
        }
        commands.push(command);
        let mut file = thin(&commands);
        let at = u32::try_from(file.len()).unwrap();
        let fields = file.len() - 8;
        file[fields..fields + 4].copy_from_slice(&at.to_le_bytes());
        file.extend(signature);
        file
    }

    /// An embedded signature holding `blobs`, each with its slot type.
    fn superblob(blobs: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let header = 12 + 8 * blobs.len();
        let mut index = Vec::new();
        let mut body: Vec<u8> = Vec::new();
        for (slot, blob) in blobs {
            index.extend(slot.to_be_bytes());
            index.extend(u32::try_from(header + body.len()).unwrap().to_be_bytes());
            body.extend(blob);
        }
        let mut out = Vec::new();
        out.extend(CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        out.extend(u32::try_from(header + body.len()).unwrap().to_be_bytes());
        out.extend(u32::try_from(blobs.len()).unwrap().to_be_bytes());
        out.extend(index);
        out.extend(body);
        out
    }

    /// A code directory with `flags` and the platform byte.
    fn directory(flags: u32, platform: u8) -> Vec<u8> {
        let mut out = vec![0; 44];
        out[..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        out[12..16].copy_from_slice(&flags.to_be_bytes());
        out[38] = platform;
        out
    }

    fn entitlements(xml: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
        out.extend(u32::try_from(8 + xml.len()).unwrap().to_be_bytes());
        out.extend(xml.as_bytes());
        out
    }

    fn validation_of(signature: &[u8]) -> (bool, bool) {
        let images = read_bytes(&signed(Vec::new(), signature)).unwrap();
        (images[0].library_validation, images[0].platform)
    }

    #[test]
    fn the_signature_decides_library_validation() {
        let plain = superblob(&[(CSSLOT_CODEDIRECTORY, directory(0, 0))]);
        assert_eq!(validation_of(&plain), (false, false));
        let flagged = superblob(&[(CSSLOT_CODEDIRECTORY, directory(CS_REQUIRE_LV, 0))]);
        assert_eq!(validation_of(&flagged), (true, false));
        let hardened = superblob(&[(CSSLOT_CODEDIRECTORY, directory(CS_RUNTIME, 0))]);
        assert_eq!(validation_of(&hardened), (true, false));
        let claim = superblob(&[(CSSLOT_CODEDIRECTORY, directory(0, 2))]);
        assert_eq!(
            validation_of(&claim),
            (false, true),
            "a claim, not validation"
        );

        let xml = |value: &str| {
            format!(
                "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>{DISABLE_LIBRARY_VALIDATION}\
                 </key>{value}</dict></plist>"
            )
        };
        let disabled = superblob(&[
            (CSSLOT_CODEDIRECTORY, directory(CS_RUNTIME, 0)),
            (CSSLOT_ENTITLEMENTS, entitlements(&xml("<true/>"))),
        ]);
        assert_eq!(validation_of(&disabled), (false, false));
        let kept = superblob(&[
            (CSSLOT_CODEDIRECTORY, directory(CS_RUNTIME, 0)),
            (CSSLOT_ENTITLEMENTS, entitlements(&xml("<false/>"))),
        ]);
        assert_eq!(validation_of(&kept), (true, false));
    }

    #[test]
    fn a_broken_signature_says_what_is_wrong() {
        let detail = |signature: Vec<u8>| malformed_detail(&signed(Vec::new(), &signature));
        let mut wrong_magic = superblob(&[(CSSLOT_CODEDIRECTORY, directory(0, 0))]);
        wrong_magic[0] = 0;
        assert_eq!(
            detail(wrong_magic),
            "its code signature is not an embedded signature"
        );
        let mut many = superblob(&[]);
        many[8..12].copy_from_slice(&65_u32.to_be_bytes());
        assert_eq!(detail(many), "its code signature lists too many blobs");
        assert_eq!(
            detail(superblob(&[])),
            "its code signature has no code directory"
        );
        let mut directory_magic = directory(0, 0);
        directory_magic[0] = 0;
        assert_eq!(
            detail(superblob(&[(CSSLOT_CODEDIRECTORY, directory_magic)])),
            "its code directory has the wrong magic"
        );
        let short = superblob(&[(CSSLOT_CODEDIRECTORY, vec![0; 8])]);
        assert_eq!(
            detail(short),
            "a code signature blob lies past the signature's end"
        );
        let mut bad_length = entitlements("x");
        bad_length[4..8].copy_from_slice(&4_u32.to_be_bytes());
        let blobs = [
            (CSSLOT_CODEDIRECTORY, directory(CS_RUNTIME, 0)),
            (CSSLOT_ENTITLEMENTS, bad_length),
        ];
        assert_eq!(
            detail(superblob(&blobs)),
            "its entitlements blob is not one"
        );
        let blobs = [
            (CSSLOT_CODEDIRECTORY, directory(CS_RUNTIME, 0)),
            (CSSLOT_ENTITLEMENTS, entitlements("not a plist")),
        ];
        assert!(detail(superblob(&blobs)).starts_with("its entitlements do not parse"));

        let mut past = signed(Vec::new(), &superblob(&[]));
        let fields = 32 + 8;
        past[fields..fields + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            malformed_detail(&past),
            "its code signature lies past its end"
        );
    }

    #[test]
    fn a_universal_file_gives_the_slices_this_mac_runs() {
        let slice = thin(&[with_string(LC_RPATH, "/a")]);
        let mut intel = slice.clone();
        intel[4..8].copy_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        let mut i386 = slice.clone();
        i386[4..8].copy_from_slice(&7_u32.to_le_bytes());
        let slices = [(CPU_TYPE_ARM64, slice), (CPU_TYPE_X86_64, intel), (7, i386)];
        let header = 8 + 32 * slices.len();
        let mut file = Vec::new();
        file.extend(FAT_MAGIC_64.to_be_bytes());
        file.extend(u32::try_from(slices.len()).unwrap().to_be_bytes());
        let mut at = header;
        for (cputype, bytes) in &slices {
            file.extend(cputype.to_be_bytes());
            file.extend(0_u32.to_be_bytes());
            file.extend(u64::try_from(at).unwrap().to_be_bytes());
            file.extend(u64::try_from(bytes.len()).unwrap().to_be_bytes());
            file.extend([0; 8]);
            at += bytes.len();
        }
        for (_, bytes) in &slices {
            file.extend(bytes);
        }
        let images = read_bytes(&file).unwrap();
        assert_eq!(images.len(), 2, "i386 does not run on a Mac today");

        // A thin file for an architecture no Mac runs has no image to read.
        let mut ppc = thin(&[]);
        ppc[4..8].copy_from_slice(&18_u32.to_le_bytes());
        assert!(read_bytes(&ppc).unwrap().is_empty());
    }

    proptest! {
        /// Any bytes, and a valid image with bytes changed, read without a panic: the file
        /// may be planted.
        #[test]
        fn any_bytes_read_without_panicking(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
            flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..8),
        ) {
            drop(read_bytes(&bytes));
            let signature = superblob(&[
                (CSSLOT_CODEDIRECTORY, directory(CS_RUNTIME, 0)),
                (CSSLOT_ENTITLEMENTS, entitlements("<plist><dict/></plist>")),
            ]);
            let mut image = signed(vec![with_string(LC_RPATH, "/a")], &signature);
            for (at, byte) in flips {
                let at = at.index(image.len());
                image[at] = byte;
            }
            drop(read_bytes(&image));
        }
    }
}
