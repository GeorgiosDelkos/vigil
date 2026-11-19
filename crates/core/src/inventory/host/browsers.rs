//! Browser extensions in this user's Chromium-based browsers and Firefox.
//!
//! Each browser keeps its extensions per profile, as a record the browser writes and the
//! extension's own manifest:
//!
//! - Chromium's browsers (Chrome, Brave, Edge, Vivaldi, Arc, Opera, ...): a profile is a
//!   folder with a `Preferences` file, under the browser's folder or the folder itself
//!   (Opera's). Its `extensions.settings` in `Secure Preferences`, or else `Preferences`, says
//!   where each extension came from (`location`), whether it is turned off
//!   (`disable_reasons`, `state`) and where its files are (`path`); the `manifest.json` there
//!   says what it may do. Extensions that ship inside the browser (`location` 5 and 10) are
//!   left out. The locations are Chromium's
//!   ([manifest.mojom](https://github.com/chromium/chromium/blob/5e3241d8741d630b6f01bbda750b932a2dab4021/extensions/common/mojom/manifest.mojom#L18)).
//! - Firefox: each folder in `Profiles` with an `extensions.json`, whose `addons` give each
//!   extension's location, state, signature check and granted permissions. Add-ons that ship
//!   with Firefox (`app-builtin`, `app-system-defaults`, `app-system-addons`) and those that
//!   are not extensions (themes, dictionaries, language packs) are left out. `signedState` is
//!   named as `AddonManager` names it
//!   ([AddonManager.sys.mjs](https://github.com/mozilla-firefox/firefox/blob/615217b20e60e956769e7876514f920c339e9a76/toolkit/mozapps/extensions/AddonManager.sys.mjs#L4307)).
//!   A profile that `profiles.ini` places outside `Profiles` is not read.
//!
//! Safari's extensions are app extensions, listed by `pluginkit` in [`super`].
//!
//! An extension is named inside its profile: `<profile>/Extensions/<id>` for Chromium,
//! whatever version is inside, and `<profile>/extensions/<id>.xpi` for Firefox. So the same
//! folder loaded in two profiles is two items, and a profile whose record cannot be read
//! carries the issues of all its extensions. Where an unpacked extension, or a Firefox add-on
//! kept elsewhere, was loaded from is its `loaded_from`. Its key is what it may do and where it
//! came from, not its version: an update that asks for nothing new keeps a dismissal (owner's
//! decision, 2026-11-19).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;

use crate::inventory::Inventory;
use crate::inventory::InventoryError;
use crate::inventory::InventorySource;
use crate::paths;

/// Chromium's browsers: the name shown, and the folder under `~/Library/Application Support`.
const CHROMIUM_BROWSERS: [(&str, &str); 9] = [
    ("Google Chrome", "Google/Chrome"),
    ("Google Chrome Beta", "Google/Chrome Beta"),
    ("Google Chrome Canary", "Google/Chrome Canary"),
    ("Chromium", "Chromium"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Microsoft Edge", "Microsoft Edge"),
    ("Vivaldi", "Vivaldi"),
    ("Arc", "Arc/User Data"),
    ("Opera", "com.operasoftware.Opera"),
];

/// Firefox's folder of profiles, under `~/Library/Application Support`.
const FIREFOX_PROFILES: &str = "Firefox/Profiles";

/// Chromium's `location` values for extensions that ship inside the browser: `kComponent` and
/// `kExternalComponent`.
const BUILT_IN: [u64; 2] = [5, 10];

/// Firefox's locations of add-ons that ship with it.
const FIREFOX_BUILT_IN: [&str; 3] = ["app-builtin", "app-system-defaults", "app-system-addons"];

/// The largest preferences file read. Arbitrary: a profile's `Preferences` is a few hundred
/// kB to a few MB; a larger one is not read rather than held in memory.
const PREFERENCES_LIMIT: u64 = 64 * 1024 * 1024;

/// The largest manifest or messages file read. Arbitrary: a manifest is a few kB.
const MANIFEST_LIMIT: u64 = 1024 * 1024;

/// One browser extension, as the agent reads it.
#[derive(Debug, Serialize)]
pub(super) struct BrowserExtension {
    /// Its name inside its profile, which an issue names (see the module docs).
    pub(super) path: String,
    /// Always `browser_extension`, so the agent tells it from the other lines.
    kind: &'static str,
    browser: &'static str,
    /// The profile's folder name (`Default`, `Profile 1`, `abcd1234.default-release`).
    profile: String,
    id: String,
    /// Its name, with Chromium's `__MSG_x__` looked up in its default locale when it can be.
    name: Option<String>,
    version: Option<String>,
    /// The folder or file it was loaded from, when that is not its name: an unpacked
    /// extension's, or a Firefox add-on's kept outside the profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    loaded_from: Option<String>,
    /// Why its manifest could not be read; the fields from it are then empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    enabled: bool,
    /// Where it came from: Chromium's location (`internal` for the store, `unpacked`,
    /// `external_policy`, `command_line`, ...), or Firefox's (`app-profile`, ...).
    source: String,
    /// Chromium: whether it came from the browser's store.
    #[serde(skip_serializing_if = "Option::is_none")]
    from_store: Option<bool>,
    /// Firefox: where it was downloaded from.
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_from: Option<String>,
    /// Firefox: whether Mozilla signed it, from `signedState`.
    #[serde(skip_serializing_if = "Option::is_none")]
    signed: Option<&'static str>,
    /// Where it updates from, when it names a place.
    update_url: Option<String>,
    /// The API permissions it asks for (Chromium's manifest) or was granted (Firefox), sorted.
    permissions: Vec<String>,
    /// The sites it may read and change, sorted: host permissions (for Manifest V2, the entries of
    /// `permissions` that are host patterns), and for Chromium the pages its content scripts
    /// run on.
    hosts: Vec<String>,
}

impl BrowserExtension {
    /// What keys an issue about it: everything but its name and version, so an update that
    /// asks for nothing new keeps a dismissal. JSON, so no two extensions join into one text.
    pub(super) fn identity(&self) -> String {
        json!({
            "id": self.id,
            "loaded_from": self.loaded_from,
            "error": self.error,
            "enabled": self.enabled,
            "source": self.source,
            "from_store": self.from_store,
            "installed_from": self.installed_from,
            "signed": self.signed,
            "update_url": self.update_url,
            "permissions": self.permissions,
            "hosts": self.hosts,
        })
        .to_string()
    }
}

/// Reads every extension the module docs list in the browsers under `support`
/// (`~/Library/Application Support`). A profile whose record cannot be read, or a browser's
/// folder that cannot be listed, is a failure of its [`InventorySource::BrowserProfile`], a
/// note when permission was denied.
pub(super) fn collect(inventory: &mut Inventory, support: &Path) -> Vec<BrowserExtension> {
    let mut extensions = Vec::new();
    for (browser, folder) in CHROMIUM_BROWSERS {
        let folder = support.join(folder);
        let profiles = match chromium_profiles(&folder) {
            Ok(profiles) => profiles,
            Err(source) => {
                let path = folder.clone();
                fail(inventory, &folder, InventoryError::Io { path, source });
                continue;
            }
        };
        for profile in profiles {
            match chromium_profile(browser, &profile) {
                Ok(found) => extensions.extend(found),
                Err(e) => fail(inventory, &profile, e),
            }
        }
    }
    let folder = support.join(FIREFOX_PROFILES);
    let profiles = subfolders(&folder).unwrap_or_else(|source| {
        let path = folder.clone();
        fail(inventory, &folder, InventoryError::Io { path, source });
        Vec::new()
    });
    for profile in profiles {
        match firefox_profile(&profile) {
            Ok(found) => extensions.extend(found),
            Err(e) => fail(inventory, &profile, e),
        }
    }
    extensions
}

fn fail(inventory: &mut Inventory, folder: &Path, error: InventoryError) {
    let path = folder.to_string_lossy().into_owned();
    inventory.fail(InventorySource::BrowserProfile { path }, error);
}

/// The folders in `folder`, sorted; none when it is not there, as for a browser that was never
/// installed.
fn subfolders(folder: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut folders = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            folders.push(entry.path());
        }
    }
    folders.sort();
    Ok(folders)
}

/// The profiles of a Chromium browser: its folder, when it holds a `Preferences` file
/// (Opera's), then each folder in it that does.
fn chromium_profiles(browser: &Path) -> io::Result<Vec<PathBuf>> {
    let profiles = std::iter::once(browser.to_owned())
        .chain(subfolders(browser)?)
        .filter(|folder| folder.join("Preferences").is_file())
        .collect();
    Ok(profiles)
}

/// Chromium's record of one extension, the parts read.
#[derive(Debug, Deserialize)]
struct Setting {
    location: Option<u64>,
    path: Option<String>,
    /// A list of reasons in recent versions, a bit mask in older ones.
    disable_reasons: Option<Value>,
    /// `0` for turned off, in older versions.
    state: Option<u64>,
    from_webstore: Option<bool>,
    /// The manifest as the browser stored it, used when the file cannot be read.
    manifest: Option<Value>,
}

/// The extensions of one Chromium profile, from `Secure Preferences`, or `Preferences` for an
/// extension only it records. A record with no `location` is not an installed extension.
fn chromium_profile(
    browser: &'static str,
    profile: &Path,
) -> Result<Vec<BrowserExtension>, InventoryError> {
    let mut settings: BTreeMap<String, Setting> = BTreeMap::new();
    for name in ["Secure Preferences", "Preferences"] {
        let Some(text) = read_record(&profile.join(name))? else {
            continue;
        };
        let parse = |detail: String| InventoryError::Parse {
            what: profile.join(name).display().to_string(),
            detail,
        };
        let all: Value = serde_json::from_str(&text).map_err(|e| parse(e.to_string()))?;
        let Some(found) = all
            .pointer("/extensions/settings")
            .and_then(Value::as_object)
        else {
            continue;
        };
        for (id, setting) in found {
            let setting = Setting::deserialize(setting)
                .map_err(|e| parse(format!("the extension {id}: {e}")))?;
            // A record without a location holds only settings for an extension that is not
            // installed (`{"incognito": true}`), and must not hide the other file's record.
            if setting.location.is_some() {
                settings.entry(id.clone()).or_insert(setting);
            }
        }
    }

    let profile_name = profile
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let extensions = settings
        .into_iter()
        .filter(|(_, setting)| !setting.location.is_some_and(|l| BUILT_IN.contains(&l)))
        .map(|(id, setting)| chromium_extension(browser, profile, &profile_name, id, setting))
        .collect();
    Ok(extensions)
}

fn chromium_extension(
    browser: &'static str,
    profile: &Path,
    profile_name: &str,
    id: String,
    setting: Setting,
) -> BrowserExtension {
    // A packed extension's `path` is `<id>/<version>` under the profile's `Extensions`; an
    // unpacked one's is absolute, which `join` keeps as it is.
    let extensions = profile.join("Extensions");
    let files = setting.path.as_deref().map(|path| extensions.join(path));
    let loaded_from = setting.path.filter(|path| Path::new(path).is_absolute());
    let manifest = match &files {
        Some(files) => read_json(&files.join("manifest.json")),
        None => Err("its record names no folder".to_owned()),
    };
    let (manifest, error) = match (manifest, setting.manifest) {
        (Ok(manifest), _) => (manifest, None),
        // The stored copy is what the browser checked at install time.
        (Err(_), Some(stored)) => (stored, None),
        (Err(e), None) => (Value::Null, Some(e)),
    };
    let disabled = match &setting.disable_reasons {
        Some(Value::Array(reasons)) => !reasons.is_empty(),
        Some(Value::Number(mask)) => mask.as_u64() != Some(0),
        Some(_) | None => false,
    };
    // Manifest V2 lists host patterns among its permissions.
    let (mut hosts, permissions): (Vec<String>, Vec<String>) = strings(&manifest["permissions"])
        .into_iter()
        .partition(|permission| permission == "<all_urls>" || permission.contains("://"));
    hosts.extend(strings(&manifest["host_permissions"]));
    if let Some(scripts) = manifest["content_scripts"].as_array() {
        hosts.extend(
            scripts
                .iter()
                .flat_map(|script| strings(&script["matches"])),
        );
    }
    BrowserExtension {
        path: extensions.join(&id).to_string_lossy().into_owned(),
        kind: "browser_extension",
        browser,
        profile: profile_name.to_owned(),
        name: manifest["name"]
            .as_str()
            .map(|name| localized(name, &manifest, files.as_deref())),
        version: manifest["version"].as_str().map(str::to_owned),
        id,
        loaded_from,
        error,
        enabled: !disabled && setting.state != Some(0),
        source: location_name(setting.location).to_owned(),
        from_store: setting.from_webstore,
        installed_from: None,
        signed: None,
        update_url: manifest["update_url"].as_str().map(str::to_owned),
        permissions: sorted(permissions),
        hosts: sorted(hosts),
    }
}

/// Chromium's `ManifestLocation` by number, as `manifest.mojom` names it.
fn location_name(location: Option<u64>) -> &'static str {
    match location {
        Some(1) => "internal",
        Some(2) => "external_pref",
        Some(3) => "external_registry",
        Some(4) => "unpacked",
        Some(6) => "external_pref_download",
        Some(7) => "external_policy_download",
        Some(8) => "command_line",
        Some(9) => "external_policy",
        Some(_) | None => "unknown",
    }
}

/// `name`, or for Chromium's `__MSG_<key>__` the message its default locale gives for the key
/// (matched without case, as Chromium does), when that can be read.
fn localized(name: &str, manifest: &Value, files: Option<&Path>) -> String {
    let key = name
        .strip_prefix("__MSG_")
        .and_then(|rest| rest.strip_suffix("__"));
    let (Some(key), Some(files), Some(locale)) = (key, files, manifest["default_locale"].as_str())
    else {
        return name.to_owned();
    };
    let messages = files.join("_locales").join(locale).join("messages.json");
    let Ok(Value::Object(messages)) = read_json(&messages) else {
        return name.to_owned();
    };
    messages
        .iter()
        .find(|(found, _)| found.eq_ignore_ascii_case(key))
        .and_then(|(_, message)| message["message"].as_str())
        .map_or_else(|| name.to_owned(), str::to_owned)
}

/// Firefox's record of one add-on, the parts read.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Addon {
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    location: Option<String>,
    active: Option<bool>,
    version: Option<String>,
    path: Option<String>,
    #[serde(rename = "sourceURI")]
    source_uri: Option<String>,
    #[serde(rename = "updateURL")]
    update_url: Option<String>,
    signed_state: Option<i64>,
    default_locale: Option<Locale>,
    user_permissions: Option<Permissions>,
}

#[derive(Debug, Deserialize)]
struct Locale {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Permissions {
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    origins: Vec<String>,
}

/// The extensions of one Firefox profile, from its `extensions.json`.
fn firefox_profile(profile: &Path) -> Result<Vec<BrowserExtension>, InventoryError> {
    /// The parts of `extensions.json` read.
    #[derive(Debug, Deserialize)]
    struct Database {
        #[serde(default)]
        addons: Vec<Addon>,
    }
    let file = profile.join("extensions.json");
    let Some(text) = read_record(&file)? else {
        return Ok(Vec::new());
    };
    let database: Database = serde_json::from_str(&text).map_err(|e| InventoryError::Parse {
        what: file.display().to_string(),
        detail: e.to_string(),
    })?;
    let profile_name = profile
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let extensions = database
        .addons
        .into_iter()
        .filter(|addon| addon.kind.as_deref() == Some("extension"))
        .filter(|addon| {
            !addon
                .location
                .as_deref()
                .is_some_and(|l| FIREFOX_BUILT_IN.contains(&l))
        })
        .filter_map(|addon| {
            let id = addon.id?;
            let path = profile.join("extensions").join(format!("{id}.xpi"));
            let loaded_from = addon.path.filter(|kept| Path::new(kept) != path);
            let (permissions, hosts) = addon
                .user_permissions
                .map(|p| (p.permissions, p.origins))
                .unwrap_or_default();
            Some(BrowserExtension {
                path: path.to_string_lossy().into_owned(),
                kind: "browser_extension",
                browser: "Firefox",
                profile: profile_name.clone(),
                id,
                loaded_from,
                name: addon.default_locale.and_then(|locale| locale.name),
                version: addon.version,
                error: None,
                enabled: addon.active.unwrap_or(false),
                source: addon.location.unwrap_or_else(|| "unknown".to_owned()),
                from_store: None,
                installed_from: addon.source_uri,
                signed: Some(signed_name(addon.signed_state)),
                update_url: addon.update_url,
                permissions: sorted(permissions),
                hosts: sorted(hosts),
            })
        })
        .collect();
    Ok(extensions)
}

/// Firefox's `signedState`, as `AddonManager.SIGNEDSTATE_*` names it.
fn signed_name(state: Option<i64>) -> &'static str {
    match state {
        Some(-2) => "broken",
        Some(0) => "missing",
        Some(1) => "preliminary",
        Some(2) => "signed",
        Some(3) => "system",
        Some(4) => "privileged",
        Some(_) | None => "unknown",
    }
}

/// The text of a browser's record at `path`, or `None` when it is not there.
fn read_record(path: &Path) -> Result<Option<String>, InventoryError> {
    let bytes = match paths::read_capped(path, PREFERENCES_LIMIT + 1) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            let path = path.to_owned();
            return Err(InventoryError::Io { path, source });
        }
    };
    let parse = |detail: String| InventoryError::Parse {
        what: path.display().to_string(),
        detail,
    };
    if bytes.len() as u64 > PREFERENCES_LIMIT {
        return Err(parse(format!(
            "it is more than the {PREFERENCES_LIMIT} bytes read"
        )));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| parse(e.to_string()))
}

/// The JSON in a manifest or messages file at `path`, or why it could not be read. The reason
/// names the file but not its folder, which holds the version: it is part of an extension's
/// key, which an update must not change.
fn read_json(path: &Path) -> Result<Value, String> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let bytes = paths::read_capped(path, MANIFEST_LIMIT + 1)
        .map_err(|e| format!("cannot read {name}: {e}"))?;
    if bytes.len() as u64 > MANIFEST_LIMIT {
        return Err(format!(
            "{name} is more than the {MANIFEST_LIMIT} bytes read"
        ));
    }
    // Chromium accepts a byte order mark at the start of a manifest.
    let bytes = bytes.strip_prefix("\u{feff}".as_bytes()).unwrap_or(&bytes);
    serde_json::from_slice(bytes).map_err(|e| format!("{name} does not parse: {e}"))
}

/// `list` sorted, each once: the order a manifest lists them in means nothing, and is part of
/// the key, which an update that only reorders them must not change.
fn sorted(list: Vec<String>) -> Vec<String> {
    list.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The strings in a JSON list; anything else in it (Chromium's permission objects) is left
/// out.
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
pub(super) mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// Writes `value` as JSON at `path`, making its folders.
    pub(in crate::inventory::host) fn write_json(path: &Path, value: &Value) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value.to_string()).unwrap();
    }

    /// A Chromium profile at `profile` whose `Secure Preferences` holds `settings`.
    pub(in crate::inventory::host) fn chromium(profile: &Path, settings: &Value) {
        write_json(&profile.join("Preferences"), &json!({}));
        let preferences = json!({ "extensions": { "settings": settings } });
        write_json(&profile.join("Secure Preferences"), &preferences);
    }

    /// The extensions found under `support`, with the problems recorded.
    fn found(support: &Path) -> (Vec<Value>, Inventory) {
        let mut inventory = Inventory::default();
        let extensions = collect(&mut inventory, support)
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect();
        (extensions, inventory)
    }

    #[test]
    fn a_chromium_profile_gives_what_each_extension_may_do() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = tmp.path().join("Google/Chrome/Profile 1");
        let files = profile.join("Extensions/abc/1.2_0");
        write_json(
            &files.join("manifest.json"),
            &json!({
                "name": "__MSG_appName__",
                "default_locale": "en",
                "version": "1.2",
                "permissions": ["cookies", {"fileSystem": ["write"]}, "http://old.e.x/*"],
                "host_permissions": ["https://*/*"],
                "content_scripts": [{"matches": ["<all_urls>", "https://*/*"]}],
                "update_url": "https://e.x/update",
            }),
        );
        write_json(
            &files.join("_locales/en/messages.json"),
            &json!({"APPNAME": {"message": "Helper"}}),
        );
        let unpacked = tmp.path().join("dev/ext");
        write_json(
            &unpacked.join("manifest.json"),
            &json!({"name": "Dev", "version": "0"}),
        );
        chromium(
            &profile,
            &json!({
                "abc": {"location": 1, "path": "abc/1.2_0", "from_webstore": true,
                        "disable_reasons": []},
                "dev": {"location": 4, "path": unpacked, "disable_reasons": [8192]},
                "pdf": {"location": 5, "path": "/Applications/Chrome.app/pdf"},
                "ext": {"location": 10, "path": "ext/1_0"},
                "stub": {"incognito": true},
            }),
        );

        let (found, inventory) = found(tmp.path());
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
        assert_eq!(
            found.len(),
            2,
            "built-in extensions and stubs are left out: {found:?}"
        );
        assert_eq!(
            found[0],
            json!({
                "path": profile.join("Extensions/abc"),
                "kind": "browser_extension",
                "browser": "Google Chrome",
                "profile": "Profile 1",
                "id": "abc",
                "name": "Helper",
                "version": "1.2",
                "enabled": true,
                "source": "internal",
                "from_store": true,
                "update_url": "https://e.x/update",
                "permissions": ["cookies"],
                "hosts": ["<all_urls>", "http://old.e.x/*", "https://*/*"],
            })
        );
        // An unpacked extension is named inside its profile too.
        assert_eq!(found[1]["path"], json!(profile.join("Extensions/dev")));
        assert_eq!(found[1]["loaded_from"], json!(unpacked));
        assert_eq!(found[1]["source"], "unpacked");
        assert_eq!(found[1]["enabled"], false);
        assert_eq!(found[1]["from_store"], Value::Null);
    }

    #[test]
    fn a_chromium_record_is_read_from_either_file_and_its_state_from_either_field() {
        let tmp = tempfile::tempdir().unwrap();
        // Opera keeps its one profile in the browser's own folder.
        let profile = tmp.path().join("com.operasoftware.Opera");
        let secure = json!({ "extensions": { "settings": {
            "a": {"location": 1, "path": "a/1", "state": 0},
            "b": {"incognito": true},
            "c": {"location": 1, "path": "c/1", "disable_reasons": 0,
                  "manifest": {"name": "Stored", "permissions": ["tabs"]}},
        }}});
        write_json(&profile.join("Secure Preferences"), &secure);
        let plain = json!({ "extensions": { "settings": {
            "a": {"location": 9, "path": "a/2"},
            "b": {"location": 2, "path": "b/1", "disable_reasons": 4},
            "d": {"location": 1},
        }}});
        write_json(&profile.join("Preferences"), &plain);
        // A folder that is not a profile is not read.
        write_json(&profile.join("Crashpad/settings.json"), &json!({}));

        let (found, inventory) = found(tmp.path());
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
        let ids: Vec<&str> = found.iter().map(|e| e["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["a", "b", "c", "d"]);
        // `Secure Preferences` wins for `a`; `state` 0 is off.
        assert_eq!(found[0]["source"], "internal");
        assert_eq!(found[0]["enabled"], false);
        assert!(
            found[0]["error"]
                .as_str()
                .unwrap()
                .contains("manifest.json")
        );
        // The stub in `Secure Preferences` does not hide `b`'s record; a non-zero mask is off.
        assert_eq!(found[1]["source"], "external_pref");
        assert_eq!(found[1]["enabled"], false);
        // With no manifest on disk, the stored copy is read.
        assert_eq!(found[2]["name"], "Stored");
        assert_eq!(found[2]["permissions"], json!(["tabs"]));
        assert_eq!(found[2]["enabled"], true);
        assert_eq!(found[2]["error"], Value::Null);
        assert_eq!(found[3]["error"], "its record names no folder");
    }

    #[test]
    fn a_firefox_profile_gives_its_extensions_but_not_firefoxs_own() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = tmp.path().join("Firefox/Profiles/x1.default-release");
        let addon = |id: &str, kind: &str, location: &str| {
            let mut addon = json!({"id": id, "type": kind});
            addon["location"] = json!(location);
            addon["active"] = json!(true);
            addon
        };
        let mut full = addon("full@e.x", "extension", "app-profile");
        full["version"] = json!("2.0");
        full["path"] = json!("/p/full.xpi");
        full["sourceURI"] = json!("https://addons.mozilla.org/x.xpi");
        full["signedState"] = json!(2);
        full["defaultLocale"] = json!({"name": "Full"});
        full["userPermissions"] = json!({"permissions": ["tabs"], "origins": ["<all_urls>"]});
        let mut off = addon("off@e.x", "extension", "app-profile");
        off["active"] = json!(false);
        off["signedState"] = json!(-2);
        write_json(
            &profile.join("extensions.json"),
            &json!({"addons": [
                full, off,
                addon("builtin@e.x", "extension", "app-builtin"),
                addon("system@e.x", "extension", "app-system-defaults"),
                addon("theme@e.x", "theme", "app-profile"),
            ]}),
        );

        let (found, inventory) = found(tmp.path());
        assert!(inventory.problems.is_empty(), "{:?}", inventory.problems);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(
            found[0],
            json!({
                "path": profile.join("extensions/full@e.x.xpi"),
                "loaded_from": "/p/full.xpi",
                "kind": "browser_extension",
                "browser": "Firefox",
                "profile": "x1.default-release",
                "id": "full@e.x",
                "name": "Full",
                "version": "2.0",
                "enabled": true,
                "source": "app-profile",
                "installed_from": "https://addons.mozilla.org/x.xpi",
                "signed": "signed",
                "update_url": null,
                "permissions": ["tabs"],
                "hosts": ["<all_urls>"],
            })
        );
        assert_eq!(
            found[1]["path"],
            json!(profile.join("extensions/off@e.x.xpi"))
        );
        assert_eq!(found[1]["loaded_from"], Value::Null);
        assert_eq!(found[1]["enabled"], false);
        assert_eq!(found[1]["signed"], "broken");
    }

    #[test]
    fn a_record_that_cannot_be_read_fails_its_profile_only() {
        let tmp = tempfile::tempdir().unwrap();
        let broken = tmp.path().join("Google/Chrome/Default");
        fs::create_dir_all(&broken).unwrap();
        fs::write(broken.join("Preferences"), "{").unwrap();
        let fine = tmp.path().join("Google/Chrome/Profile 1");
        chromium(&fine, &json!({"a": {"location": 1, "path": "a/1"}}));
        let firefox = tmp.path().join("Firefox/Profiles/p");
        fs::create_dir_all(&firefox).unwrap();
        fs::write(firefox.join("extensions.json"), r#"{"addons": 1}"#).unwrap();
        let locked = tmp.path().join("Google/Chrome/Profile 2");
        chromium(&locked, &json!({}));
        let secure = locked.join("Secure Preferences");
        fs::set_permissions(&secure, fs::Permissions::from_mode(0o000)).unwrap();

        // A browser whose folder cannot be listed fails as a whole.
        let edge = tmp.path().join("Microsoft Edge");
        fs::create_dir(&edge).unwrap();
        fs::set_permissions(&edge, fs::Permissions::from_mode(0o000)).unwrap();

        let (found, inventory) = found(tmp.path());
        fs::set_permissions(&secure, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&edge, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(found.len(), 1);
        let failed: Vec<&InventorySource> = inventory.failed.iter().collect();
        let source = |path: &Path| InventorySource::BrowserProfile {
            path: path.to_string_lossy().into_owned(),
        };
        assert_eq!(failed, [&source(&firefox), &source(&broken)]);
        // A record or a folder this user may not read is a note, as everywhere in the
        // inventory.
        assert_eq!(inventory.problems.len(), 4, "{:?}", inventory.problems);
        let noted = InventoryError::Io {
            path: edge.clone(),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        assert!(
            inventory
                .problems
                .iter()
                .any(|e| e.to_string() == noted.to_string()),
            "{:?}",
            inventory.problems
        );
    }

    #[test]
    fn the_key_follows_what_it_may_do_not_its_version() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = tmp.path().join("Chromium/Default");
        let manifest = profile.join("Extensions/a/1/manifest.json");
        let key = |manifest_body: Value| {
            write_json(&manifest, &manifest_body);
            chromium(&profile, &json!({"a": {"location": 1, "path": "a/1"}}));
            let mut inventory = Inventory::default();
            collect(&mut inventory, tmp.path())[0].identity()
        };
        let first = key(json!({"name": "A", "version": "1", "permissions": ["tabs"]}));
        let update = key(json!({"name": "A 2", "version": "2", "permissions": ["tabs"]}));
        assert_eq!(
            first, update,
            "an update that asks for nothing new keeps the key"
        );
        let two = key(json!({"version": "1", "permissions": ["tabs", "cookies"]}));
        let reordered = key(json!({"version": "2", "permissions": ["cookies", "tabs"]}));
        assert_eq!(two, reordered, "reordering what it asks for keeps the key");
        let more = key(json!({"name": "A", "version": "2", "permissions": ["tabs", "cookies"]}));
        assert_ne!(first, more);
        let hosts = key(json!({"name": "A", "version": "1", "permissions": ["tabs"],
                               "host_permissions": ["<all_urls>"]}));
        assert_ne!(first, hosts);
        let moved = key(json!({"name": "A", "version": "1", "permissions": ["tabs"],
                               "update_url": "https://e.x/u"}));
        assert_ne!(first, moved);

        // A manifest that cannot be read keys the same error across versions.
        let unreadable = |version: &str| {
            let path = format!("a/{version}");
            chromium(&profile, &json!({"a": {"location": 1, "path": path}}));
            let mut inventory = Inventory::default();
            collect(&mut inventory, tmp.path())[0].identity()
        };
        assert_eq!(unreadable("7"), unreadable("8"));
    }

    #[test]
    fn one_folder_loaded_in_two_profiles_is_two_extensions() {
        let tmp = tempfile::tempdir().unwrap();
        let unpacked = tmp.path().join("dev/ext");
        write_json(&unpacked.join("manifest.json"), &json!({"name": "Dev"}));
        let chrome = tmp.path().join("Google/Chrome/Default");
        let brave = tmp.path().join("BraveSoftware/Brave-Browser/Default");
        for profile in [&chrome, &brave] {
            chromium(profile, &json!({"dev": {"location": 4, "path": unpacked}}));
        }
        let (found, _) = found(tmp.path());
        let paths: Vec<&Value> = found.iter().map(|e| &e["path"]).collect();
        assert_eq!(
            paths,
            [
                &json!(chrome.join("Extensions/dev")),
                &json!(brave.join("Extensions/dev")),
            ]
        );
    }

    #[test]
    fn records_and_manifests_past_their_limits_are_not_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("big.json");
        let limit = usize::try_from(MANIFEST_LIMIT).unwrap();
        let text = format!("[{}]", " ".repeat(limit - 2));
        fs::write(&path, &text).unwrap();
        assert_eq!(read_json(&path), Ok(json!([])));
        fs::write(&path, format!("{text} ")).unwrap();
        assert!(read_json(&path).unwrap_err().contains("more than the"));
        fs::write(&path, "\u{feff}{}").unwrap();
        assert_eq!(
            read_json(&path),
            Ok(json!({})),
            "a byte order mark is accepted"
        );

        let limit = usize::try_from(PREFERENCES_LIMIT).unwrap();
        fs::write(&path, " ".repeat(limit)).unwrap();
        assert!(read_record(&path).unwrap().is_some());
        fs::write(&path, " ".repeat(limit + 1)).unwrap();
        let error = read_record(&path).unwrap_err();
        assert!(error.to_string().contains("more than the"), "{error}");
        assert_eq!(read_record(&tmp.path().join("none")).unwrap(), None);
    }
}
