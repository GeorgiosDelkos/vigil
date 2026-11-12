//! One GitHub repository as a sweep target, collected through `gh api` with the user's login.
//!
//! Layout and decisions: spec, "GitHub repositories". Every part is fetched on its own and a
//! part that fails is a problem, so one refused endpoint never hides the rest. GitHub answers a
//! feature that is off (Dependabot alerts disabled, no code scanning, an unprotected branch)
//! with a 403 or 404 and a message; that answer is recorded as the setting's value in
//! `settings.json`, for the agent to judge, not as a failure; so is a 403 for a login without
//! the rights. A rate limit, bad credentials, or a token whose scopes do not cover the
//! endpoint also answers 403, and is a failure (see [`is_failure`]).
//!
//! Values in `settings.json` take one of five shapes, which the GitHub prompt explains: the
//! answer itself; `{"status": 204}` for an empty success (vulnerability alerts on); `{"status",
//! "message"}` for GitHub's refusal; [`NOT_VISIBLE`] for a field GitHub leaves out for this
//! login; and [`NOT_COLLECTED`] for a part that failed, whose reason is a problem in the
//! report.
//!
//! Everything here is untrusted: package names come from the repository's manifests and
//! workflow files are the repository's own text. Nothing is run; names that cannot be file
//! names are skipped.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde_json::Value;
use serde_json::json;

use crate::cancel::Cancel;
use crate::config::RepoSlug;
use crate::feeds::cache_key;
use crate::inventory::Component;
use crate::inventory::FoundIn;
use crate::inventory::InventoryError;
use crate::inventory::Lookup;
use crate::inventory::command;
use crate::package::Ecosystem;
use crate::package::Package;

/// The most workflow files read from one repository. Arbitrary: real repositories have a
/// handful; a cap keeps a repository with thousands from stalling the sweep.
#[cfg(not(test))]
const WORKFLOW_LIMIT: usize = 100;
// Tests read every workflow at the limit through a fake `gh`, one process per file. On CI's
// macOS runners a process takes about 0.35 s, so 100 made `limits_hold_at_their_edge` 70 of
// the core suite's 75 s, paid again for every mutant. A small limit tests the same edges. It
// stays above the 6 workflow files of the main fixture, `o/r`.
#[cfg(test)]
const WORKFLOW_LIMIT: usize = 8;

/// The largest workflow file put in the bundle, in bytes. Arbitrary: real workflows are a few
/// kilobytes; the cap keeps one file from filling the agent's context.
const WORKFLOW_SIZE_LIMIT: usize = 256 * 1024;

/// The most alerts of one kind put in the bundle. Arbitrary, for the same reason; the count
/// in `settings.json` stays exact.
const ALERT_LIMIT: usize = 500;

/// The value of a setting that could not be collected; the reason is a problem in the report.
const NOT_COLLECTED: &str = "not collected; see the problems in the report";

/// The `settings.json` key of the organization's 2FA requirement.
const TWO_FACTOR: &str = "organization_two_factor_requirement";

/// The value of a setting GitHub shows only to the repository's admins or the organization's
/// owners.
const NOT_VISIBLE: &str = "not visible to this login (admins or owners only)";

/// A collected repository: its components and the files that go into its bundle.
#[derive(Debug, Default)]
pub(crate) struct Repo {
    /// Packages from the dependency graph.
    pub(crate) components: Vec<Component>,
    /// Bundle files, as a path relative to the bundle (`github/settings.json`) and the text.
    pub(crate) files: Vec<(String, String)>,
    /// The keys of `github/settings.json`, which an issue may name.
    pub(crate) settings: Vec<String>,
    /// Parts that could not be collected.
    pub(crate) problems: Vec<String>,
}

impl Repo {
    /// Adds the dependency graph's packages as components, or a problem saying why not.
    fn sbom(&mut self, gh: &str, repo: &RepoSlug, base: &str) {
        let path = format!("{base}/dependency-graph/sbom");
        match api(gh, &path, Paging::Single) {
            Ok(Answer::Ok(sbom)) => {
                let (components, skipped) = components_from_sbom(&sbom, &repo.to_string());
                self.components = components;
                if !skipped.is_empty() {
                    let list: Vec<String> = skipped
                        .iter()
                        .map(|(kind, n)| format!("{kind} ({n})"))
                        .collect();
                    self.problems.push(format!(
                        "dependency graph packages that were not checked: {}",
                        list.join(", ")
                    ));
                }
            }
            Ok(Answer::Refused { status, message }) => {
                let advice = if status == 404 {
                    "; turn on the dependency graph under Settings, Code security"
                } else {
                    ""
                };
                self.problems.push(format!(
                    "dependency graph ({status}: {message}), so the repository's dependencies \
                     were not checked{advice}"
                ));
            }
            Err(e) => self.problems.push(format!("dependency graph: {e}")),
        }
    }

    /// Writes `github/<name>-alerts.json` and returns the setting value: the open count, or
    /// GitHub's refusal.
    fn alerts(&mut self, gh: &str, name: &str, path: &str) -> Value {
        match api(gh, path, Paging::All) {
            Ok(Answer::Ok(Value::Array(mut alerts))) => {
                for alert in &mut alerts {
                    // The request asks GitHub to leave the secret out; this is the second guard,
                    // so a secret never reaches the bundle or the agent's context.
                    remove_secrets(alert);
                }
                let open = alerts.len();
                if open > ALERT_LIMIT {
                    self.problems.push(format!(
                        "{name} alerts: {open} open, only the first {ALERT_LIMIT} are in the bundle"
                    ));
                    alerts.truncate(ALERT_LIMIT);
                }
                self.files.push((
                    format!("github/{name}-alerts.json"),
                    pretty(&Value::Array(alerts)),
                ));
                json!({ "open": open })
            }
            Ok(Answer::Ok(other)) => {
                let what = kind_of(&other);
                self.problems
                    .push(format!("{name} alerts: expected a list, got {what}"));
                json!(NOT_COLLECTED)
            }
            Ok(Answer::Refused { status, message }) => refused(status, &message),
            Err(e) => {
                self.problems.push(format!("{name} alerts: {e}"));
                json!(NOT_COLLECTED)
            }
        }
    }

    /// Adds the default branch's workflow files under `github/workflows/`.
    fn workflows(&mut self, gh: &str, base: &str) {
        // The contents API reads the default branch when no `ref` is given.
        let list = format!("{base}/contents/.github/workflows");
        let entries = match api(gh, &list, Paging::Single) {
            Ok(Answer::Ok(Value::Array(entries))) => entries,
            // No workflows folder.
            Ok(Answer::Refused { status: 404, .. }) => return,
            Ok(Answer::Ok(other)) => {
                let what = kind_of(&other);
                self.problems
                    .push(format!("workflows: expected a folder listing, got {what}"));
                return;
            }
            Ok(Answer::Refused { status, message }) => {
                self.problems
                    .push(format!("workflows: {status}: {message}"));
                return;
            }
            Err(e) => {
                self.problems.push(format!("workflows: {e}"));
                return;
            }
        };
        let names: Vec<(&str, Option<u64>)> = entries
            .iter()
            .filter(|e| e["type"] == "file")
            .filter_map(|e| Some((e["name"].as_str()?, e["size"].as_u64())))
            .collect();
        if names.len() > WORKFLOW_LIMIT {
            self.problems.push(format!(
                "workflows: {} files, only the first {WORKFLOW_LIMIT} were read",
                names.len()
            ));
        }
        // macOS file names ignore case, so `CI.yml` would overwrite `ci.yml` in the bundle and
        // one of them would go unread.
        let mut seen = BTreeSet::new();
        for (name, size) in names.into_iter().take(WORKFLOW_LIMIT) {
            if cache_key(name).is_err() {
                self.problems.push(format!(
                    "workflows: {name:?} is not a safe file name; not read"
                ));
                continue;
            }
            if !seen.insert(name.to_ascii_lowercase()) {
                self.problems.push(format!(
                    "workflows: {name:?} differs from another file only in case; not read"
                ));
                continue;
            }
            // The listing gives each size, so a file over the limit is not even downloaded.
            if let Some(size) = size.filter(|s| *s > WORKFLOW_SIZE_LIMIT as u64) {
                self.problems.push(format!(
                    "workflow {name}: {size} bytes, over the {WORKFLOW_SIZE_LIMIT}-byte limit; \
                     not read"
                ));
                continue;
            }
            self.workflow(gh, base, name);
        }
    }

    fn workflow(&mut self, gh: &str, base: &str, name: &str) {
        let path = format!("{base}/contents/.github/workflows/{name}");
        match raw(gh, &path) {
            Ok(text) if text.len() > WORKFLOW_SIZE_LIMIT => self.problems.push(format!(
                "workflow {name}: {} bytes, over the {WORKFLOW_SIZE_LIMIT}-byte limit; not read",
                text.len()
            )),
            Ok(text) => self.files.push((format!("github/workflows/{name}"), text)),
            Err(e) => self.problems.push(format!("workflow {name}: {e}")),
        }
    }

    /// One setting's value: the answer, GitHub's refusal, or [`NOT_COLLECTED`] with a problem.
    fn setting(&mut self, gh: &str, key: &str, path: &str) -> Value {
        match api(gh, path, Paging::Single) {
            Ok(Answer::Ok(value)) => value,
            Ok(Answer::Refused { status, message }) => refused(status, &message),
            Err(e) => {
                self.problems.push(format!("setting {key}: {e}"));
                json!(NOT_COLLECTED)
            }
        }
    }

    /// The organization's 2FA requirement. Only its owners see the field; a refusal or a
    /// failure stays as it is.
    fn two_factor(&mut self, gh: &str, login: &str) -> Value {
        let path = format!("orgs/{}", path_segment(login));
        match api(gh, &path, Paging::Single) {
            Ok(Answer::Ok(org)) => org
                .get("two_factor_requirement_enabled")
                .cloned()
                .unwrap_or_else(|| json!(NOT_VISIBLE)),
            Ok(Answer::Refused { status, message }) => refused(status, &message),
            Err(e) => {
                self.problems.push(format!("setting {TWO_FACTOR}: {e}"));
                json!(NOT_COLLECTED)
            }
        }
    }
}

/// What `gh api` answered.
#[derive(Debug)]
enum Answer {
    /// The JSON body; `{"status": 204}` for an empty success.
    Ok(Value),
    /// A 403 or 404 with GitHub's message: the feature is off, or the login may not see it.
    Refused { status: u16, message: String },
}

/// How many pages to ask for.
#[derive(Debug, Clone, Copy)]
enum Paging {
    Single,
    /// Every page, joined into one array.
    All,
}

/// A failure that stops a repository's sweep, or one part of it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GitHubError {
    /// `gh` is not on `PATH`.
    #[error("gh is not installed; install it (brew install gh) and run `gh auth login`")]
    NoGh,
    /// The repository cannot be read.
    #[error(
        "cannot read {repo} on GitHub: {message} (is the name right, and can your gh login see it?)"
    )]
    Repo {
        /// The repository.
        repo: String,
        /// GitHub's message.
        message: String,
    },
    /// GitHub refused for a reason that says nothing about the setting: a rate limit, a token
    /// without the permission, a server error.
    #[error("GitHub answered {status} for {path}: {message}")]
    Api {
        /// The API path.
        path: String,
        /// The HTTP status.
        status: u16,
        /// GitHub's message.
        message: String,
    },
    /// `gh` failed without GitHub's answer (not logged in, offline).
    #[error(transparent)]
    Gh(#[from] InventoryError),
    /// `gh` printed something that is not JSON.
    #[error("unexpected answer from GitHub for {path}")]
    Answer {
        /// The API path.
        path: String,
        /// What did not parse.
        #[source]
        source: serde_json::Error,
    },
}

/// Collects `repo` with `gh`, the program to run.
///
/// Not cancellable: the sweep checks its cancel before each repository, and each `gh` call is
/// bounded by the command time limit.
///
/// # Errors
///
/// Fails when `gh` is not installed or the repository itself cannot be read; every later part
/// that fails is a problem in the result instead.
pub(crate) fn collect(gh: &str, repo: &RepoSlug) -> Result<Repo, GitHubError> {
    let base = format!("repos/{repo}");
    let meta = match api(gh, &base, Paging::Single)? {
        Answer::Ok(meta) => meta,
        Answer::Refused { message, .. } => {
            return Err(GitHubError::Repo {
                repo: repo.to_string(),
                message,
            });
        }
    };
    let mut out = Repo::default();
    let mut settings = BTreeMap::new();
    // GitHub leaves the field out for a login without admin rights on the repository.
    let security = match meta.get("security_and_analysis") {
        Some(value) if !value.is_null() => value.clone(),
        _ => json!(NOT_VISIBLE),
    };
    settings.insert("security_and_analysis".to_owned(), security);
    out.files.push((
        "github/repository.json".to_owned(),
        pretty(&repository_summary(&meta)),
    ));

    out.sbom(gh, repo, &base);
    for (name, path) in [
        ("dependabot", "dependabot/alerts?state=open&per_page=100"),
        (
            "code-scanning",
            "code-scanning/alerts?state=open&per_page=100",
        ),
        (
            "secret-scanning",
            "secret-scanning/alerts?state=open&per_page=100&hide_secret=true",
        ),
    ] {
        let value = out.alerts(gh, name, &format!("{base}/{path}"));
        settings.insert(format!("{}_alerts", name.replace('-', "_")), value);
    }
    out.workflows(gh, &base);

    let mut parts = vec![
        (
            "vulnerability_alerts",
            format!("{base}/vulnerability-alerts"),
        ),
        ("rulesets", format!("{base}/rulesets")),
        ("actions_permissions", format!("{base}/actions/permissions")),
        (
            "actions_workflow_permissions",
            format!("{base}/actions/permissions/workflow"),
        ),
    ];
    match meta["default_branch"].as_str() {
        Some(branch) => parts.push((
            "default_branch_protection",
            format!("{base}/branches/{}/protection", path_segment(branch)),
        )),
        None => out.problems.push(
            "the repository names no default branch, so its protection was not checked".to_owned(),
        ),
    }
    for (key, path) in parts {
        let value = out.setting(gh, key, &path);
        settings.insert(key.to_owned(), value);
    }
    if meta["owner"]["type"] == "Organization"
        && let Some(login) = meta["owner"]["login"].as_str()
    {
        let value = out.two_factor(gh, login);
        settings.insert(TWO_FACTOR.to_owned(), value);
    }

    out.settings = settings.keys().cloned().collect();
    out.files.push((
        "github/settings.json".to_owned(),
        pretty(&Value::Object(settings.into_iter().collect())),
    ));
    Ok(out)
}

/// The parts of `repos/{repo}` that matter to a security review, without the dozens of URLs.
fn repository_summary(meta: &Value) -> Value {
    let mut kept = serde_json::Map::new();
    for key in [
        "full_name",
        "private",
        "visibility",
        "archived",
        "fork",
        "default_branch",
        "pushed_at",
        "allow_forking",
        "has_issues",
        "has_wiki",
        "has_pages",
    ] {
        if let Some(value) = meta.get(key) {
            kept.insert(key.to_owned(), value.clone());
        }
    }
    kept.insert("owner_type".to_owned(), meta["owner"]["type"].clone());
    Value::Object(kept)
}

/// Removes every `secret` key, at any depth.
fn remove_secrets(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("secret");
            object.values_mut().for_each(remove_secrets);
        }
        Value::Array(items) => items.iter_mut().for_each(remove_secrets),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn refused(status: u16, message: &str) -> Value {
    json!({ "status": status, "message": message })
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "nothing",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("a JSON value always serializes")
}

/// `text` percent-encoded for one URL path segment: everything but ASCII letters, digits and
/// `-._~` (RFC 3986 unreserved), so a branch named `a#b` or `a/b` stays one segment.
fn path_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Whether a refusal says nothing about the setting itself: a rate limit, a token without the
/// permission, bad credentials. Matched on GitHub's messages ("API rate limit exceeded",
/// "You have exceeded a secondary rate limit", "Resource not accessible by personal access
/// token", "Bad credentials"), since the status is the same 403 as for a feature that is off.
fn is_failure(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    ["rate limit", "resource not accessible", "bad credentials"]
        .iter()
        .any(|m| message.contains(m))
}

/// Runs `gh api` on `path`. A 403 or 404 that GitHub explains is a [`Answer::Refused`]; any
/// other failure is an error.
fn api(gh: &str, path: &str, paging: Paging) -> Result<Answer, GitHubError> {
    let all = matches!(paging, Paging::All);
    let mut args = vec!["api"];
    if all {
        args.extend(["--paginate", "--slurp"]);
    }
    args.push(path);
    let output = command::run_any_status(gh, &args, &Cancel::new())?.ok_or(GitHubError::NoGh)?;
    if output.success {
        if output.stdout.trim().is_empty() {
            return Ok(Answer::Ok(json!({ "status": 204 })));
        }
        let body: Value =
            serde_json::from_str(&output.stdout).map_err(|source| GitHubError::Answer {
                path: path.to_owned(),
                source,
            })?;
        return Ok(Answer::Ok(match body {
            // `--slurp` wraps each page: `[[...], [...]]`.
            Value::Array(pages) if all => {
                Value::Array(pages.into_iter().flat_map(page_items).collect())
            }
            body => body,
        }));
    }
    match error_body(&output.stdout) {
        Some((status @ (403 | 404), message)) if !is_failure(&message) => {
            Ok(Answer::Refused { status, message })
        }
        Some((status, message)) => Err(GitHubError::Api {
            path: path.to_owned(),
            status,
            message,
        }),
        None => Err(GitHubError::Gh(InventoryError::Command {
            command: output.command,
            detail: output.detail,
        })),
    }
}

/// The status and message of GitHub's error body, as a failed `gh api` prints it: an object,
/// or that object in a list under `--slurp`, with the status as a string or a number. `None`
/// for anything else (an HTML error page), whose explanation is gh's own message.
fn error_body(stdout: &str) -> Option<(u16, String)> {
    let body: Value = serde_json::from_str(stdout).ok()?;
    let error = match &body {
        Value::Array(list) if list.len() == 1 => &list[0],
        other => other,
    };
    let status = error["status"]
        .as_str()
        .and_then(|s| s.parse::<u16>().ok())
        .or_else(|| error["status"].as_u64().and_then(|s| u16::try_from(s).ok()))?;
    Some((status, error["message"].as_str()?.to_owned()))
}

fn page_items(page: Value) -> Vec<Value> {
    match page {
        Value::Array(items) => items,
        other => vec![other],
    }
}

/// Fetches a file's raw text through the contents API.
fn raw(gh: &str, path: &str) -> Result<String, GitHubError> {
    let args = ["api", "-H", "Accept: application/vnd.github.raw", path];
    match command::run(gh, &args, &Cancel::new())? {
        Some(text) => Ok(text),
        None => Err(GitHubError::NoGh),
    }
}

/// The packages of an SPDX SBOM as components, and the count of packages that cannot be
/// looked up, by package-URL type (an ecosystem OSV is not asked about) or by what is wrong.
/// The repository itself (the package the document describes) has no package URL and is left
/// out; any other package without one is counted as such.
fn components_from_sbom(sbom: &Value, repo: &str) -> (Vec<Component>, BTreeMap<String, usize>) {
    let mut components = Vec::new();
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
    let packages = sbom["sbom"]["packages"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let described = &sbom["sbom"]["documentDescribes"];
    for package in packages {
        let itself = described
            .as_array()
            .is_some_and(|ids| ids.contains(&package["SPDXID"]));
        let purl = package["externalRefs"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["referenceType"] == "purl")
            .and_then(|r| r["referenceLocator"].as_str());
        let Some(purl) = purl else {
            if !itself {
                *skipped.entry("no package URL".to_owned()).or_default() += 1;
            }
            continue;
        };
        let listed = package["versionInfo"].as_str().filter(|v| !v.is_empty());
        match parse_purl(purl) {
            Ok((package, version)) => {
                let version = version
                    .or_else(|| listed.map(str::to_owned))
                    .unwrap_or_else(|| "unknown".to_owned());
                components.push(Component {
                    lookup: Lookup::Package(package),
                    version,
                    found_in: FoundIn::DependencyGraph {
                        repo: repo.to_owned(),
                    },
                });
            }
            Err(kind) => *skipped.entry(kind).or_default() += 1,
        }
    }
    (components, skipped)
}

/// Parses a package URL (<https://github.com/package-url/purl-spec>) into a package and its
/// version, or says why it cannot be looked up: its type, when that is not an ecosystem the app
/// looks up, or what is wrong with it.
fn parse_purl(purl: &str) -> Result<(Package, Option<String>), String> {
    let malformed = || "not a package URL".to_owned();
    let rest = purl.strip_prefix("pkg:").ok_or_else(malformed)?;
    // Qualifiers (`?`) and a subpath (`#`) do not name the package.
    let rest = rest.split_once(['?', '#']).map_or(rest, |(r, _)| r);
    let (kind, path) = rest.split_once('/').ok_or_else(malformed)?;
    let ecosystem = match kind.to_ascii_lowercase().as_str() {
        "cargo" => Ecosystem::CratesIo,
        "npm" => Ecosystem::Npm,
        "pypi" => Ecosystem::PyPI,
        "golang" => Ecosystem::Go,
        "gem" => Ecosystem::RubyGems,
        "githubactions" => Ecosystem::GitHubActions,
        other => return Err(other.to_owned()),
    };
    // The version follows an `@` in the last segment; an `@` before it (an npm scope that was
    // not percent-encoded) belongs to the name.
    let (namespace, last) = match path.rsplit_once('/') {
        Some((namespace, last)) => (Some(namespace), last),
        None => (None, path),
    };
    let (last, version) = match last.rsplit_once('@') {
        Some((name, version)) if !name.is_empty() => (name, Some(percent_decode(version))),
        _ => (last, None),
    };
    let mut parts: Vec<String> = namespace
        .into_iter()
        .flat_map(|n| n.split('/'))
        .chain([last])
        .map(percent_decode)
        .collect();
    // An action in a subfolder (`github/codeql-action/analyze`) is published by its
    // repository, which is the name OSV knows: `owner/repo`.
    if ecosystem == Ecosystem::GitHubActions {
        parts.truncate(2);
    }
    let name = parts.join("/");
    let package = format!("{}:{name}", ecosystem.osv_name())
        .parse()
        .map_err(|_| format!("{kind} with an invalid name"))?;
    Ok((package, version.filter(|v| !v.is_empty())))
}

/// Decodes `%XX` escapes; a malformed escape is kept as written.
fn percent_decode(text: &str) -> String {
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        let hex = tail
            .get(..2)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (first, hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                rest = &tail[2..];
            }
            (byte, _) => {
                out.push(byte);
                rest = tail;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;

    /// A fake `gh` that answers by the API path (its last argument), as `gh api` does: JSON on
    /// stdout, exit 1 for an HTTP error, with GitHub's error body. Fixtures (`<name>.json`) sit
    /// beside it. A raw file is served only with the raw `Accept` header, and secret alerts only
    /// with `hide_secret=true`, so dropping either fails a test.
    const FAKE_GH: &str = r#"#!/bin/sh
for last; do :; done
d=$(dirname "$0")
ok() { cat "$d/$1.json"; }
no() { cat "$d/$1.json"; exit 1; }
refuse() { echo "{\"message\":\"$2\",\"status\":\"$1\"}"; exit 1; }
file() {
  case "$*" in *application/vnd.github.raw*) ;; *) echo "not raw" >&2; exit 3 ;; esac
}
slurp() {
  case "$*" in *--paginate*--slurp*) ;; *) echo "not slurped" >&2; exit 3 ;; esac
}
case "$last" in
  repos/o/r) ok repo ;;
  repos/o/r/dependency-graph/sbom) ok sbom ;;
  repos/o/r/dependabot/alerts*) no dependabot ;;
  repos/o/r/code-scanning/alerts*) no code-scanning ;;
  repos/o/r/secret-scanning/alerts*hide_secret=true*) slurp "$@"; ok secret-scanning ;;
  repos/o/r/contents/.github/workflows) ok workflows ;;
  repos/o/r/contents/.github/workflows/ci.yml) file "$@"; echo 'on: push' ;;
  repos/o/r/contents/.github/workflows/big.yml) file "$@"; head -c 300000 /dev/zero | tr '\0' a ;;
  repos/o/r/contents/.github/workflows/gone.yml) refuse 404 "Not Found" ;;
  repos/o/r/vulnerability-alerts) ;;
  repos/o/r/branches/release%2F1/protection) refuse 404 "Branch not protected" ;;
  repos/o/r/rulesets) echo '[["kept as listed"]]' ;;
  repos/o/r/actions/permissions) echo '{"enabled":true,"allowed_actions":"all"}' ;;
  repos/o/r/actions/permissions/workflow) echo 'not json' ;;
  orgs/o) echo '{"login":"o","message":"hi","two_factor_requirement_enabled":true}' ;;
  repos/o/limited) ok limited ;;
  repos/o/limited/dependency-graph/sbom) refuse 403 "API rate limit exceeded for user ID 1." ;;
  repos/o/limited/dependabot/alerts*) echo '[]'; exit 1 ;;
  repos/o/limited/code-scanning/alerts*) echo '<html>502</html>'; echo 'HTTP 502' >&2; exit 1 ;;
  repos/o/limited/secret-scanning/alerts*) ok many-alerts ;;
  repos/o/limited/contents/.github/workflows) refuse 403 "Must have admin rights" ;;
  repos/o/limited/*) echo '{}' ;;
  orgs/lim) refuse 403 "Resource not accessible by personal access token" ;;
  repos/o/many) echo '{"default_branch":"main","owner":{"type":"Organization","login":"viewer"}}' ;;
  orgs/viewer) echo '{"login":"viewer"}' ;;
  orgs/hidden) refuse 404 "Not Found" ;;
  repos/o/many/dependency-graph/sbom) refuse 404 "Not Found" ;;
  repos/o/many/secret-scanning/alerts*) ok limit-alerts ;;
  repos/o/many/contents/.github/workflows) ok limit-workflows ;;
  repos/o/many/contents/.github/workflows/w0.yml) file "$@"; ok limit-file ;;
  repos/o/many/contents/.github/workflows/*) file "$@"; echo 'on: push' ;;
  repos/o/many/*) echo '[]' ;;
  repos/o/over) echo '{"default_branch":"main","owner":{"type":"Organization","login":"hidden"}}' ;;
  repos/o/over/contents/.github/workflows) ok many-workflows ;;
  repos/o/over/contents/.github/workflows/*) file "$@"; echo 'on: push' ;;
  repos/o/over/*) echo '[]' ;;
  repos/o/missing) refuse 404 "Not Found" ;;
  repos/o/offline) echo 'error connecting to api.github.com' >&2; exit 1 ;;
  *) echo "unexpected $last" >&2; exit 2 ;;
esac
"#;

    fn fake_gh(dir: &Path) -> String {
        let path = dir.join("gh");
        fs::write(&path, FAKE_GH).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let purl = |p: &str| json!([{"referenceType": "purl", "referenceLocator": p}]);
        let many_alerts: Vec<Value> = (0..=ALERT_LIMIT).map(|n| json!({"number": n})).collect();
        let workflows = |n: usize| -> Value {
            (0..n)
                .map(|n| json!({"type": "file", "name": format!("w{n}.yml"), "size": 1}))
                .collect()
        };
        let mut at_limit = workflows(WORKFLOW_LIMIT);
        // Exactly at the size limit, as the listing reports it.
        at_limit[0]["size"] = json!(WORKFLOW_SIZE_LIMIT);
        let limit_alerts: Vec<Value> = (0..ALERT_LIMIT).map(|n| json!({"number": n})).collect();
        fs::write(dir.join("limit-file.json"), "a".repeat(WORKFLOW_SIZE_LIMIT)).unwrap();
        let fixtures = [
            (
                "sbom",
                json!({"sbom": {"documentDescribes": ["SPDXRef-repo"], "packages": [
                    {"SPDXID": "SPDXRef-repo", "name": "com.github.o/r", "versionInfo": "main"},
                    {"SPDXID": "SPDXRef-orphan", "name": "orphan"},
                    {"SPDXID": "SPDXRef-orphan-2", "name": "orphan 2"},
                    {"versionInfo": "4.17.20", "externalRefs": purl("pkg:npm/lodash@4.17.20")},
                    {"versionInfo": "^1.0.0", "externalRefs": purl("pkg:npm/%40s/p")},
                    {"versionInfo": "4.12", "externalRefs": purl("pkg:maven/junit/junit@4.12")}
                ]}}),
            ),
            (
                "repo",
                json!({
                    "default_branch": "release/1",
                    "private": false,
                    "owner": {"type": "Organization", "login": "o"},
                    "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
                    "url": "x"
                }),
            ),
            (
                "limited",
                json!({
                    "owner": {"type": "Organization", "login": "lim"},
                    "security_and_analysis": null
                }),
            ),
            (
                "dependabot",
                json!([{
                    "message": "Dependabot alerts are disabled for this repository.",
                    "status": "403"
                }]),
            ),
            (
                "code-scanning",
                json!([{"message": "no analysis found", "status": "404"}]),
            ),
            (
                "secret-scanning",
                json!([
                    [{"number": 1, "secret": "hunter2", "secret_type": "t"}],
                    [{"number": 2, "secret": "x", "nested": [{"secret": "deep"}]}]
                ]),
            ),
            (
                "workflows",
                json!([
                    {"type": "file", "name": "ci.yml"},
                    {"type": "file", "name": "CI.yml"},
                    {"type": "dir", "name": "sub"},
                    {"type": "file", "name": ".evil"},
                    {"type": "file", "name": "big.yml"},
                    {"type": "file", "name": "gone.yml"},
                    {"type": "file", "name": "huge.yml", "size": 10_000_000}
                ]),
            ),
            ("many-alerts", json!([many_alerts])),
            ("many-workflows", workflows(WORKFLOW_LIMIT + 1)),
            ("limit-workflows", at_limit),
            ("limit-alerts", json!([limit_alerts])),
        ];
        for (name, value) in fixtures {
            fs::write(dir.join(format!("{name}.json")), value.to_string()).unwrap();
        }
        path.to_str().unwrap().to_owned()
    }

    fn slug(s: &str) -> RepoSlug {
        s.parse().unwrap()
    }

    fn file<'a>(repo: &'a Repo, name: &str) -> &'a str {
        let found = repo.files.iter().find(|(n, _)| n == name);
        &found.unwrap_or_else(|| panic!("no {name}")).1
    }

    fn settings(repo: &Repo) -> Value {
        serde_json::from_str(file(repo, "github/settings.json")).unwrap()
    }

    #[test]
    fn collects_every_part_and_records_what_is_off() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = fake_gh(tmp.path());
        let repo = collect(&gh, &slug("o/r")).unwrap();

        let names: Vec<String> = repo
            .components
            .iter()
            .map(|c| match &c.lookup {
                Lookup::Package(p) => {
                    format!("{}:{} {}", p.ecosystem.osv_name(), p.name, c.version)
                }
                Lookup::Product(p) => p.to_string(),
            })
            .collect();
        assert_eq!(names, ["npm:lodash 4.17.20", "npm:@s/p ^1.0.0"]);
        let found_in = &repo.components[0].found_in;
        assert!(matches!(found_in, FoundIn::DependencyGraph { repo } if repo == "o/r"));

        let settings = settings(&repo);
        assert_eq!(settings["dependabot_alerts"]["status"], 403);
        assert_eq!(
            settings["code_scanning_alerts"]["message"],
            "no analysis found"
        );
        assert_eq!(settings["secret_scanning_alerts"], json!({"open": 2}));
        assert_eq!(
            settings["vulnerability_alerts"],
            json!({"status": 204}),
            "on: no content"
        );
        assert_eq!(
            settings["default_branch_protection"]["message"], "Branch not protected",
            "the branch is one encoded path segment"
        );
        assert_eq!(
            settings["rulesets"],
            json!([["kept as listed"]]),
            "one page is not flattened"
        );
        assert_eq!(settings["actions_permissions"]["allowed_actions"], "all");
        assert_eq!(settings["actions_workflow_permissions"], NOT_COLLECTED);
        assert_eq!(settings["organization_two_factor_requirement"], true);
        assert_eq!(
            settings["security_and_analysis"]["secret_scanning"]["status"],
            "enabled"
        );
        let keys: Vec<&str> = settings
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(repo.settings, keys);

        let secrets = file(&repo, "github/secret-scanning-alerts.json");
        assert!(
            !secrets.contains("hunter2"),
            "the secret is removed: {secrets}"
        );
        assert!(!secrets.contains("deep"), "at any depth: {secrets}");
        assert!(secrets.contains("\"secret_type\""), "{secrets}");
        assert!(
            !repo.files.iter().any(|(n, _)| n.contains("dependabot")),
            "refused: no file"
        );
        assert_eq!(file(&repo, "github/workflows/ci.yml").trim(), "on: push");
        let workflows = repo
            .files
            .iter()
            .filter(|(n, _)| n.contains("workflows/"))
            .count();
        assert_eq!(workflows, 1, "{:?}", repo.files);
        let summary: Value = serde_json::from_str(file(&repo, "github/repository.json")).unwrap();
        assert_eq!(summary["owner_type"], "Organization");
        assert!(summary.get("url").is_none(), "{summary}");

        let problems = repo.problems.join("\n");
        for expected in [
            "not checked: maven (1), no package URL (2)",
            "\".evil\" is not a safe file name",
            "\"CI.yml\" differs from another file only in case",
            "workflow big.yml: 300000 bytes, over the 262144-byte limit",
            "workflow gone.yml:",
            "workflow huge.yml: 10000000 bytes, over the 262144-byte limit",
            "setting actions_workflow_permissions: unexpected answer",
        ] {
            assert!(problems.contains(expected), "{expected}: {problems}");
        }
        assert_eq!(repo.problems.len(), 7, "{problems}");
    }

    #[test]
    fn rate_limits_and_broken_answers_are_failures_not_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = fake_gh(tmp.path());
        let repo = collect(&gh, &slug("o/limited")).unwrap();
        let settings = settings(&repo);
        assert_eq!(
            settings["dependabot_alerts"], NOT_COLLECTED,
            "an empty failed slurp"
        );
        assert_eq!(
            settings["code_scanning_alerts"], NOT_COLLECTED,
            "an HTML error page"
        );
        assert_eq!(
            settings["organization_two_factor_requirement"],
            NOT_COLLECTED
        );
        assert_eq!(
            settings["secret_scanning_alerts"],
            json!({"open": ALERT_LIMIT + 1})
        );
        assert!(
            settings.get("default_branch_protection").is_none(),
            "no default branch"
        );
        assert_eq!(
            settings["security_and_analysis"], NOT_VISIBLE,
            "null for a non-admin"
        );
        let alerts: Value =
            serde_json::from_str(file(&repo, "github/secret-scanning-alerts.json")).unwrap();
        assert_eq!(alerts.as_array().unwrap().len(), ALERT_LIMIT);

        let problems = repo.problems.join("\n");
        for expected in [
            "dependency graph: GitHub answered 403 for repos/o/limited/dependency-graph/sbom: \
             API rate limit exceeded",
            "dependabot alerts: `",
            "code-scanning alerts: `",
            "HTTP 502",
            "secret-scanning alerts: 501 open, only the first 500 are in the bundle",
            "workflows: 403: Must have admin rights",
            "names no default branch",
            "setting organization_two_factor_requirement: GitHub answered 403",
        ] {
            assert!(problems.contains(expected), "{expected}: {problems}");
        }
        assert!(
            !problems.contains("turn on the dependency graph"),
            "{problems}"
        );
    }

    #[test]
    fn limits_hold_at_their_edge() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = fake_gh(tmp.path());

        // Exactly at every limit: everything is kept and nothing is reported but the SBOM.
        let repo = collect(&gh, &slug("o/many")).unwrap();
        let workflows = repo
            .files
            .iter()
            .filter(|(n, _)| n.contains("workflows/"))
            .count();
        assert_eq!(workflows, WORKFLOW_LIMIT);
        assert_eq!(
            file(&repo, "github/workflows/w0.yml").len(),
            WORKFLOW_SIZE_LIMIT
        );
        let alerts: Value =
            serde_json::from_str(file(&repo, "github/secret-scanning-alerts.json")).unwrap();
        assert_eq!(alerts.as_array().unwrap().len(), ALERT_LIMIT);
        assert_eq!(repo.problems.len(), 1, "{:?}", repo.problems);
        assert_eq!(
            settings(&repo)[TWO_FACTOR],
            NOT_VISIBLE,
            "an org that hides the field"
        );
        assert!(
            repo.problems[0].contains("(404: Not Found)")
                && repo.problems[0]
                    .ends_with("turn on the dependency graph under Settings, Code security"),
            "{:?}",
            repo.problems
        );

        let repo = collect(&gh, &slug("o/over")).unwrap();
        let refusal = json!({"status": 404, "message": "Not Found"});
        assert_eq!(
            settings(&repo)[TWO_FACTOR],
            refusal,
            "an org this login cannot see"
        );
        let workflows = repo
            .files
            .iter()
            .filter(|(n, _)| n.contains("workflows/"))
            .count();
        assert_eq!(workflows, WORKFLOW_LIMIT);
        let problems = repo.problems.join("\n");
        assert!(
            problems.contains(&format!(
                "workflows: {} files, only the first {WORKFLOW_LIMIT} were read",
                WORKFLOW_LIMIT + 1
            )),
            "{problems}"
        );
    }

    #[test]
    fn a_repository_that_cannot_be_read_stops_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = fake_gh(tmp.path());
        let err = collect(&gh, &slug("o/missing")).unwrap_err();
        assert!(
            matches!(&err, GitHubError::Repo { message, .. } if message == "Not Found"),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("can your gh login see it"),
            "{err}"
        );

        let err = collect(&gh, &slug("o/offline")).unwrap_err();
        assert!(matches!(err, GitHubError::Gh(_)), "{err:?}");
        assert!(err.to_string().contains("error connecting"), "{err}");

        let missing = tmp.path().join("no-gh");
        let err = collect(missing.to_str().unwrap(), &slug("o/r")).unwrap_err();
        assert!(matches!(err, GitHubError::NoGh), "{err:?}");
    }

    #[test]
    fn parses_package_urls() {
        let ok = |purl: &str| {
            let (package, version) = parse_purl(purl).unwrap();
            (
                format!("{}:{}", package.ecosystem.osv_name(), package.name),
                version,
            )
        };
        let v = |s: &str| Some(s.to_owned());
        assert_eq!(
            ok("pkg:npm/%40scope/name@1.2.3"),
            ("npm:@scope/name".into(), v("1.2.3"))
        );
        assert_eq!(
            ok("pkg:npm/@scope/name@1.2.3"),
            ("npm:@scope/name".into(), v("1.2.3"))
        );
        assert_eq!(ok("pkg:npm/@scope/name"), ("npm:@scope/name".into(), None));
        assert_eq!(
            ok("pkg:npm/@types"),
            ("npm:@types".into(), None),
            "a leading @ is the name"
        );
        assert_eq!(
            ok("pkg:cargo/serde@1.0.0"),
            ("crates.io:serde".into(), v("1.0.0"))
        );
        assert_eq!(
            ok("pkg:pypi/django@4.2?extra=x"),
            ("PyPI:django".into(), v("4.2"))
        );
        assert_eq!(
            ok("pkg:golang/github.com/cli/go-gh/v2@v2.13.0"),
            ("Go:github.com/cli/go-gh/v2".into(), v("v2.13.0"))
        );
        assert_eq!(
            ok("pkg:githubactions/actions/checkout@v4#sub"),
            ("GitHub Actions:actions/checkout".into(), v("v4"))
        );
        assert_eq!(ok("pkg:gem/rails"), ("RubyGems:rails".into(), None));
        assert_eq!(
            ok("pkg:githubactions/github/codeql-action/analyze@v3"),
            ("GitHub Actions:github/codeql-action".into(), v("v3")),
            "an action in a subfolder is its repository"
        );
        assert_eq!(ok("pkg:npm/left-pad@"), ("npm:left-pad".into(), None));

        assert_eq!(
            parse_purl("pkg:maven/junit/junit@4.12").unwrap_err(),
            "maven"
        );
        assert_eq!(parse_purl("npm/lodash").unwrap_err(), "not a package URL");
        assert_eq!(parse_purl("pkg:npm").unwrap_err(), "not a package URL");
        assert_eq!(
            parse_purl("pkg:npm/a%0Ab@1").unwrap_err(),
            "npm with an invalid name"
        );
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
    }

    #[test]
    fn prompt_names_every_value_it_must_explain() {
        let prompt = include_str!("prompts/sweep-github.md");
        for value in [NOT_VISIBLE, NOT_COLLECTED] {
            assert!(prompt.contains(&format!("`\"{value}\"`")), "{value}");
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(path_segment("release/1.0_a~b#c"), "release%2F1.0_a~b%23c");
        assert!(is_failure("API rate limit exceeded for user ID 1."));
        assert!(is_failure("You have exceeded a secondary rate limit."));
        assert!(is_failure("Resource not accessible by integration"));
        assert!(is_failure("Bad credentials"));
        assert!(!is_failure(
            "Dependabot alerts are disabled for this repository."
        ));
        assert_eq!(kind_of(&json!(null)), "nothing");
        assert_eq!(kind_of(&json!(true)), "a boolean");
        assert_eq!(kind_of(&json!(1)), "a number");
        assert_eq!(kind_of(&json!("s")), "a string");
        assert_eq!(kind_of(&json!([])), "a list");
        assert_eq!(kind_of(&json!({})), "an object");
    }
}

#[cfg(test)]
mod percent_properties {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Decoding what `path_segment` encoded gives the text back.
        #[test]
        fn decodes_what_was_encoded(text in any::<String>()) {
            prop_assert_eq!(percent_decode(&path_segment(&text)), text);
        }
    }
}
