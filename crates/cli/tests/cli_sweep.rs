//! End-to-end tests of `sweep` with a fake agent, a fake login shell and no network.
//!
//! Every feed request goes to a dead proxy, so the bundle holds the inventory and no
//! advisories, and the only valid verdict is `{"findings": []}`. The fake agent's behaviour is
//! chosen by `FAKE_AGENT_MODE`; it counts its runs in `FAKE_AGENT_COUNTER`.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

const FAKE_AGENT: &str = r#"#!/bin/sh
echo "path: $PATH"
# The login shell's PATH is made up; this script needs cat.
PATH=/usr/bin:/bin
n=$(cat "$FAKE_AGENT_COUNTER" 2>/dev/null || echo 0)
n=$((n + 1))
echo $n > "$FAKE_AGENT_COUNTER"
test -f PROMPT.md || { echo "no PROMPT.md in $(pwd)" >&2; exit 9; }
echo "args: $*"
case "$FAKE_AGENT_MODE:$n" in
  ok:*) echo '{"findings": [], "issues": []}' > findings.json ;;
  issue:*)
    if [ -f github/workflows/ci.yml ]; then
      echo '{"findings": [], "issues": [{"subject": {"file": "github/workflows/ci.yml"},
        "severity": "medium", "evidence": "e", "explanation": "x",
        "fix": {"summary": "s", "steps": [], "commands": []}}]}' > findings.json
    else
      echo '{"findings": [], "issues": []}' > findings.json
    fi ;;
  retry:1) echo '{"findings": [], "issues": [], "bogus": 1}' > findings.json ;;
  retry:*) echo '{"findings": [], "issues": []}' > findings.json ;;
  bad:*) echo 'not json' > findings.json ;;
  silent:*) ;;
  partial:*) echo '{"outcome": "partial", "summary": "half"}' > result.json ;;
  fix:*)
    echo '{"outcome": "fixed", "summary": "pinned the action",
      "pull_request": "https://github.com/o/r/pull/7"}' > result.json ;;
  crash:*) exit 3 ;;
  hang:*|second-hangs:2) sleep 60 & echo $! > "$FAKE_AGENT_COUNTER.child"; wait ;;
  second-hangs:*) echo '{"findings": [], "issues": []}' > findings.json ;;
  late-crash:*) echo '{"findings": [], "issues": []}' > findings.json; exit 3 ;;
esac
"#;

/// A fake `gh`: `o/r` is a public repository with one npm dependency and one workflow;
/// `o/missing` does not exist. Answers by the API path, its last argument.
const FAKE_GH: &str = r#"#!/bin/sh
for last; do :; done
refuse() { echo "{\"message\":\"$2\",\"status\":\"$1\"}"; exit 1; }
case "$last" in
  repos/o/r) echo '{"default_branch":"main","private":false,"owner":{"type":"User"}}' ;;
  repos/o/r/dependency-graph/sbom) echo '{"sbom":{"packages":[{"versionInfo":"4.17.20",
    "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.20"}]}]}}' ;;
  repos/o/r/*alerts*) echo '[[]]' ;;
  repos/o/r/contents/.github/workflows) echo '[{"type":"file","name":"ci.yml"}]' ;;
  repos/o/r/contents/.github/workflows/ci.yml) echo 'on: pull_request_target' ;;
  repos/o/r/branches/main/protection) refuse 404 "Branch not protected" ;;
  repos/o/r/*) echo '{}' ;;
  *) refuse 404 "Not Found" ;;
esac
"#;

/// A fake `ssh`: `web` answers as a Debian 12 server with one OS package and one listening
/// socket; `down` cannot be reached. The marker is on stdin's first line, `marker=<hex>`.
const FAKE_SSH: &str = r#"#!/bin/sh
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
dest=$2
IFS= read -r first
m=${first#marker=}
case "$dest" in
  web)
    printf '%s begin os-release\nID=debian\nVERSION_ID=12\n\n%s end 0\n' "$m" "$m"
    printf '%s begin kernel\nLinux 6.1.0-28-amd64 x86_64\n%s end 0\n' "$m" "$m"
    printf '%s begin dpkg\nPackage: openssl\nStatus: install ok installed\n' "$m"
    printf 'Version: 3.0.15-1\n\n%s end 0\n' "$m"
    for part in apk rpm docker-containers docker-images; do
      printf '%s begin %s\n\n%s end 127\n' "$m" "$part" "$m"
    done
    printf '%s begin listening\ntcp LISTEN 0.0.0.0:6379\n%s end 0\n' "$m" "$m"
    ;;
  *) echo "ssh: Could not resolve hostname $dest" >&2; exit 255 ;;
esac
"#;

struct Sandbox {
    root: tempfile::TempDir,
}

impl Sandbox {
    /// A home with `bin/sw_vers`, a fake `claude`, and a fake login shell that finds it.
    fn new(config: &str) -> Self {
        let root = tempfile::tempdir().expect("a temp dir can be created");
        let sandbox = Self { root };
        fs::create_dir_all(sandbox.bin()).expect("the temp dir is writable");
        sandbox.script("bin/sw_vers", "#!/bin/sh\necho 27.2\n");
        sandbox.script("bin/gh", FAKE_GH);
        sandbox.script("bin/ssh", FAKE_SSH);
        sandbox.script("agents/claude", FAKE_AGENT);
        let claude = sandbox.path().join("agents/claude");
        sandbox.script(
            "login-shell",
            &format!(
                "#!/bin/sh\n# Called as: login-shell -lc '<script that runs command -v <agent>>'\n\
                 printf '%s\\n' __vigil_path__ /login/bin:/usr/bin \
                 __vigil_binary__\n\
                 case \"$2\" in *'command -v claude;'*) echo {} ;; esac\n\
                 echo __vigil_end__\n",
                claude.display()
            ),
        );
        let data = sandbox.path().join("data");
        fs::create_dir_all(&data).expect("the temp dir is writable");
        fs::write(data.join("config.toml"), config).expect("the temp dir is writable");
        sandbox
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }

    fn script(&self, rel: &str, body: &str) {
        let path = self.path().join(rel);
        fs::create_dir_all(path.parent().expect("a relative path has a parent"))
            .expect("the temp dir is writable");
        fs::write(&path, body).expect("the temp dir is writable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("the script exists");
    }

    fn sweep(&self, mode: &str) -> Output {
        self.command(mode)
            .arg("sweep")
            .output()
            .expect("the test binary was built by cargo")
    }

    /// Runs `fix` with `args`, answering `answer` to its question.
    fn fix(&self, args: &[&str], answer: &str) -> Output {
        let mut child = self
            .command("fix")
            .arg("fix")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the test binary was built by cargo");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(answer.as_bytes())
            .expect("the CLI reads its answer");
        child.wait_with_output().expect("the CLI finishes")
    }

    /// The CLI with the sandbox's home, tools and data directory, the fake agent in `mode`.
    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vigil"));
        command
            .arg("--data-dir")
            .arg(self.path().join("data"))
            .env("HOME", self.path())
            .env("PATH", self.bin())
            .env("SHELL", self.path().join("login-shell"))
            .env("FAKE_AGENT_MODE", mode)
            .env("FAKE_AGENT_COUNTER", self.path().join("counter"))
            // Version managers are read from the sandbox's home only.
            .env_remove("NVM_DIR")
            .env_remove("FNM_DIR")
            .env_remove("VOLTA_HOME")
            .env_remove("ASDF_DATA_DIR")
            .env_remove("PYENV_ROOT")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            // Port 1 on loopback refuses connections, so every feed request fails at once.
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env_remove("HTTPS_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy");
        command
    }

    /// Runs the CLI with `args` against the sandbox's data directory.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vigil"))
            .arg("--data-dir")
            .arg(self.path().join("data"))
            .args(args)
            .output()
            .expect("the test binary was built by cargo")
    }

    /// The path of `report.json` of `target` in the newest sweep folder.
    fn newest_report_path(&self, target: &str) -> PathBuf {
        let mut dirs: Vec<_> = fs::read_dir(self.path().join("data/sweeps"))
            .expect("a sweep wrote its folder")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort_by_key(|dir| {
            let name = dir
                .file_name()
                .and_then(|n| n.to_str())
                .expect("sweep folders have UTF-8 names")
                .to_owned();
            match name.split_once('-') {
                Some((stamp, n)) => (
                    stamp.to_owned(),
                    n.parse::<u32>()
                        .expect("a sweep folder suffix is the same-second count"),
                ),
                None => (name, 1),
            }
        });
        dirs.last()
            .expect("a sweep ran")
            .join(target)
            .join("report.json")
    }

    /// `report.json` of `target` in the newest sweep folder. Folder names are start times,
    /// then `-2` and so on within one second; by name alone `-10` would sort before `-9`.
    fn newest_report(&self, target: &str) -> serde_json::Value {
        let report = self.newest_report_path(target);
        serde_json::from_str(&fs::read_to_string(report).expect("the report was saved"))
            .expect("the report is JSON")
    }

    fn runs(&self) -> String {
        fs::read_to_string(self.path().join("counter")).unwrap_or_default()
    }

    /// The single sweep folder's `mac` target.
    fn sweep_dir(&self) -> PathBuf {
        self.target_dir("mac")
    }

    /// A target's folder in the single sweep folder.
    fn target_dir(&self, target: &str) -> PathBuf {
        let sweeps = self.path().join("data/sweeps");
        let mut dirs: Vec<_> = fs::read_dir(&sweeps)
            .expect("a sweep wrote its folder")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        assert_eq!(dirs.len(), 1, "{dirs:?}");
        dirs.remove(0).join(target)
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn clean_sweep_writes_bundle_and_report() {
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let out = sandbox.sweep("ok");
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("listing what is installed"), "{stderr}");
    assert!(
        stderr.contains("claude is reviewing the target"),
        "{stderr}"
    );
    assert!(stderr.contains("NVD 1/1: apple:macos"), "{stderr}");
    // The feeds are unreachable, so the verdict says it covers only what was checked.
    assert!(
        stdout.contains("Nothing affected or risky was found in what was checked"),
        "{stdout}"
    );
    assert!(stdout.contains("## Not checked"), "{stdout}");
    assert!(stdout.contains("NVD product apple:macos"), "{stdout}");
    assert!(stdout.contains("CISA KEV catalog"), "{stdout}");
    assert!(
        stdout.contains("not installed, so not checked: brew"),
        "{stdout}"
    );
    assert_eq!(sandbox.runs().trim(), "1");

    let dir = sandbox.sweep_dir();
    for file in [
        "bundle/PROMPT.md",
        "bundle/inventory.jsonl",
        "bundle/advisories.jsonl",
        "bundle/findings.schema.json",
        "bundle/findings.json",
        "agent-1.log",
        "report.json",
        "report.md",
    ] {
        assert!(dir.join(file).exists(), "{file}");
    }
    let prompt = fs::read_to_string(dir.join("bundle/PROMPT.md")).unwrap();
    assert!(
        prompt.starts_with("# Vulnerability sweep: this Mac (macOS 27.2)"),
        "{prompt}"
    );
    let log = fs::read_to_string(dir.join("agent-1.log")).unwrap();
    assert!(
        log.contains("--permission-mode dontAsk"),
        "restricted: {log}"
    );
    assert!(!log.contains("dangerously"), "{log}");
    assert!(
        log.contains("path: /login/bin:/usr/bin"),
        "the login shell's PATH: {log}"
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["agent"], "claude");
    assert_eq!(report["components"], 1);
    assert!(report["failure"].is_null());

    // The prompt template is now the user's to edit.
    let template = sandbox.path().join("data/prompts/sweep.md");
    assert!(fs::read_to_string(template).unwrap().contains("{{target}}"));
}

#[test]
fn an_edited_prompt_is_used_and_the_newer_built_in_one_noted() {
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let prompts = sandbox.path().join("data/prompts");
    fs::create_dir_all(&prompts).unwrap();
    fs::write(prompts.join("sweep.md"), "Mine: {{target}}").unwrap();
    let out = sandbox.sweep("ok");
    assert!(out.status.success(), "{}", text(&out.stderr));

    let dir = sandbox.sweep_dir();
    let prompt = fs::read_to_string(dir.join("bundle/PROMPT.md")).unwrap();
    assert_eq!(prompt, "Mine: this Mac (macOS 27.2)");
    let built_in = fs::read_to_string(prompts.join("sweep.default.md")).unwrap();
    assert!(built_in.starts_with("# Vulnerability sweep:"), "{built_in}");
    let report = fs::read_to_string(dir.join("report.md")).unwrap();
    assert!(
        report.contains("prompts/sweep.md: your edited copy is used"),
        "{report}"
    );
}

#[test]
fn agent_exit_codes_decide_only_without_a_valid_file() {
    // Valid findings count even when the agent exits non-zero after writing them.
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let out = sandbox.sweep("late-crash");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(sandbox.runs().trim(), "1");

    // Without a file, a failing agent would fail again, so it is not retried.
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let out = sandbox.sweep("crash");
    let stderr = text(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("claude exited with"), "{stderr}");
    assert!(stderr.contains("agent-1.log"), "{stderr}");
    assert_eq!(sandbox.runs().trim(), "1");
}

#[test]
fn rejected_findings_are_retried_once_with_the_problems() {
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let out = sandbox.sweep("retry");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("fixing its rejected findings"));
    assert_eq!(sandbox.runs().trim(), "2");
    let dir = sandbox.sweep_dir();
    let log = fs::read_to_string(dir.join("agent-2.log")).unwrap();
    assert!(log.contains("was rejected"), "{log}");
    assert!(log.contains("unknown field"), "{log}");
    let rejected = fs::read_to_string(dir.join("bundle/findings.rejected.json")).unwrap();
    assert!(
        rejected.contains("bogus"),
        "the first answer is kept: {rejected}"
    );
}

#[test]
fn twice_rejected_findings_fail_the_sweep_but_keep_the_report() {
    for mode in ["bad", "silent"] {
        let sandbox = Sandbox::new("agent = \"claude\"\n");
        let out = sandbox.sweep(mode);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert!(!out.status.success(), "{mode}: {stderr}");
        assert!(stderr.contains("sweep incomplete"), "{mode}: {stderr}");
        assert!(stdout.contains("**No verdict:**"), "{mode}: {stdout}");
        assert!(
            !stdout.contains("Nothing affected or risky was found."),
            "{mode}: {stdout}"
        );
        assert_eq!(sandbox.runs().trim(), "2", "{mode}");
        assert!(sandbox.sweep_dir().join("report.json").exists(), "{mode}");
    }
}

#[test]
fn missing_or_unset_agent_stops_before_sweeping() {
    let sandbox = Sandbox::new("");
    let out = sandbox.sweep("ok");
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("no agent chosen"),
        "{}",
        text(&out.stderr)
    );

    let sandbox = Sandbox::new("agent = \"gemini\"\n");
    let out = sandbox.sweep("ok");
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("gemini is not installed"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        !sandbox.path().join("data/sweeps").exists(),
        "nothing was swept"
    );
}

#[test]
fn github_repositories_are_swept_after_the_mac() {
    let sandbox =
        Sandbox::new("agent = \"claude\"\n\n[github]\nrepos = [\"o/r\", \"o/missing\"]\n");
    let out = sandbox.sweep("ok");
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(!out.status.success(), "o/missing has no verdict: {stderr}");
    assert!(stderr.contains("sweeping github:o/r"), "{stderr}");
    assert!(
        stderr.contains("github:o/missing: cannot read o/missing on GitHub: Not Found"),
        "{stderr}"
    );
    assert!(stdout.contains("# Sweep of mac"), "{stdout}");
    assert!(stdout.contains("# Sweep of github:o/r"), "{stdout}");
    assert_eq!(
        sandbox.runs().trim(),
        "2",
        "the agent ran for the Mac and o/r only"
    );

    let dir = sandbox.target_dir("github-o--r");
    for file in [
        "bundle/github/settings.json",
        "bundle/github/repository.json",
        "bundle/github/workflows/ci.yml",
        "report.json",
    ] {
        assert!(dir.join(file).exists(), "{file}");
    }
    let inventory = fs::read_to_string(dir.join("bundle/inventory.jsonl")).unwrap();
    assert!(inventory.contains("\"lodash\""), "{inventory}");
    let prompt = fs::read_to_string(dir.join("bundle/PROMPT.md")).unwrap();
    assert!(
        prompt.starts_with("# Security sweep: the GitHub repository o/r"),
        "{prompt}"
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["target"], "github:o/r");
    assert_eq!(report["components"], 1);

    let missing = sandbox.target_dir("github-o--missing");
    let report = fs::read_to_string(missing.join("report.md")).unwrap();
    assert!(
        report.contains("**No verdict:** cannot read o/missing"),
        "{report}"
    );
    assert!(sandbox.path().join("data/prompts/sweep-github.md").exists());
}

#[test]
fn servers_are_swept_after_the_repositories() {
    let sandbox = Sandbox::new(
        "agent = \"claude\"\n\n[[servers]]\nname = \"web\"\nssh = \"web\"\n\n\
         [[servers]]\nname = \"down\"\nssh = \"down\"\n",
    );
    let out = sandbox.sweep("ok");
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(!out.status.success(), "down has no verdict: {stderr}");
    assert!(stderr.contains("sweeping server:web"), "{stderr}");
    assert!(
        stderr.contains("server:down: cannot read the server over ssh"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Could not resolve hostname down"),
        "{stderr}"
    );
    assert!(stdout.contains("# Sweep of server:web"), "{stdout}");
    assert_eq!(
        sandbox.runs().trim(),
        "2",
        "the agent ran for the Mac and web only"
    );

    let dir = sandbox.target_dir("server-web");
    let listening = fs::read_to_string(dir.join("bundle/server/listening.txt")).unwrap();
    assert_eq!(listening, "tcp LISTEN 0.0.0.0:6379");
    let system = fs::read_to_string(dir.join("bundle/server/system.json")).unwrap();
    assert!(system.contains("\"Debian:12\""), "{system}");
    let inventory = fs::read_to_string(dir.join("bundle/inventory.jsonl")).unwrap();
    assert!(inventory.contains("\"Debian:12\""), "{inventory}");
    assert!(inventory.contains("\"os_package\""), "{inventory}");
    let prompt = fs::read_to_string(dir.join("bundle/PROMPT.md")).unwrap();
    assert!(
        prompt.starts_with("# Security sweep: the server web"),
        "{prompt}"
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["target"], "server:web");
    assert_eq!(report["components"], 1);

    let down = sandbox.target_dir("server-down");
    let report = fs::read_to_string(down.join("report.md")).unwrap();
    assert!(
        report.contains("**No verdict:** cannot read the server"),
        "{report}"
    );
    assert!(sandbox.path().join("data/prompts/sweep-server.md").exists());
}

#[test]
fn dismissals_hold_across_sweeps_and_changes_are_counted() {
    let sandbox = Sandbox::new("agent = \"claude\"\n\n[github]\nrepos = [\"o/r\"]\n");
    assert!(sandbox.sweep("issue").status.success());
    let first = sandbox.newest_report("github-o--r");
    assert!(first["changes"].is_null(), "no earlier sweep: {first}");
    assert_eq!(first["first_verdict"], true, "{first}");
    let key = first["issues"][0]["key"].as_str().unwrap().to_owned();
    assert_eq!(key.len(), 16, "{first}");

    let unknown = sandbox.run(&["dismiss", "0123456789abcdef", "--reason", "x"]);
    assert!(!unknown.status.success());
    assert!(text(&unknown.stderr).contains("no report has finding 0123456789abcdef"));
    let out = sandbox.run(&["dismiss", &key, "--reason", "pinned on purpose"]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let out = sandbox.sweep("issue");
    assert!(out.status.success());
    let second = sandbox.newest_report("github-o--r");
    assert_eq!(second["first_verdict"], false, "{second}");
    assert_eq!(
        second["issues"][0]["key"],
        key.as_str(),
        "the key is stable"
    );
    assert_eq!(
        second["issues"][0]["dismissed"]["reason"],
        "pinned on purpose"
    );
    assert_eq!(second["changes"]["new"], serde_json::json!([]));
    assert_eq!(second["changes"]["resolved"], serde_json::json!([]));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("Since the sweep of"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "## Dismissed\n\n- medium file github/workflows/ci.yml (key {key}): pinned on purpose"
        )),
        "{stdout}"
    );

    assert!(sandbox.run(&["undismiss", &key]).status.success());
    let again = sandbox.run(&["undismiss", &key]);
    assert!(text(&again.stderr).contains(&format!("finding {key} is not dismissed")));
    assert!(sandbox.sweep("issue").status.success());
    let third = sandbox.newest_report("github-o--r");
    assert_eq!(
        third["changes"]["new"],
        serde_json::json!([key]),
        "shown again"
    );

    assert!(sandbox.sweep("ok").status.success());
    let fourth = sandbox.newest_report("github-o--r");
    assert_eq!(fourth["changes"]["resolved"], serde_json::json!([key]));

    fs::write(sandbox.path().join("data/state/dismissals.json"), "{").unwrap();
    assert!(sandbox.sweep("ok").status.success());
    let problems = sandbox.newest_report("mac")["problems"].to_string();
    assert!(
        problems.contains("dismissals, so dismissed findings show again: cannot read"),
        "{problems}"
    );
}

#[test]
fn a_fix_runs_only_after_it_is_confirmed_and_is_recorded() {
    let sandbox = Sandbox::new("agent = \"claude\"\n\n[github]\nrepos = [\"o/r\"]\n");
    assert!(sandbox.sweep("issue").status.success());
    let report = sandbox.newest_report("github-o--r");
    let key = report["issues"][0]["key"].as_str().unwrap().to_owned();
    let runs = sandbox.runs();

    for answer in ["n\n", ""] {
        let declined = sandbox.fix(&[&key], answer);
        assert!(!declined.status.success(), "{answer:?} is not a yes");
        let stdout = text(&declined.stdout);
        assert!(
            stdout.starts_with(&format!(
                "Fix {key} on the GitHub repository o/r, as a pull request (found by the sweep of \
                 {}): s\n",
                report["started"].as_str().unwrap()
            )),
            "{stdout}"
        );
        let stderr = text(&declined.stderr);
        assert!(stderr.contains("Run this fix now with claude, with full access? [y/N]"));
        assert!(
            stderr.contains("not confirmed; nothing was run"),
            "{stderr}"
        );
    }
    assert_eq!(sandbox.runs(), runs, "the agent did not run");
    assert!(!sandbox.path().join("data/state/fixes.jsonl").exists());

    let out = sandbox.fix(&[&key], "y\n");
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stdout.contains("fixed: pinned the action"), "{stdout}");
    let steps = [
        "preparing the fix",
        "claude is applying the fix",
        "recording the result",
    ];
    let at: Vec<Option<usize>> = steps.iter().map(|s| stderr.find(s)).collect();
    assert!(at.iter().all(Option::is_some) && at.is_sorted(), "{stderr}");
    assert!(
        stdout.contains("pull request: https://github.com/o/r/pull/7"),
        "{stdout}"
    );

    let history = fs::read_to_string(sandbox.path().join("data/state/fixes.jsonl")).unwrap();
    let record: serde_json::Value = serde_json::from_str(history.trim()).unwrap();
    assert_eq!(record["key"], key.as_str());
    assert_eq!(record["target"], "github:o/r");
    assert_eq!(record["outcome"], "fixed");
    assert_eq!(record["confirmed"], "asked");
    let dir = PathBuf::from(record["dir"].as_str().unwrap());
    assert!(
        dir.starts_with(sandbox.path().join("data/fixes")),
        "{}",
        dir.display()
    );
    let log = fs::read_to_string(dir.join("agent.log")).unwrap();
    assert!(log.contains("--permission-mode bypassPermissions"), "{log}");
    let prompt = fs::read_to_string(dir.join("PROMPT.md")).unwrap();
    assert!(prompt.contains(&format!("vigil/fix-{key}")), "{prompt}");
    assert!(
        !prompt.contains("{{"),
        "every placeholder is filled: {prompt}"
    );
    let brief: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("fix.json")).unwrap()).unwrap();
    assert_eq!(brief["subject"]["file"], "github/workflows/ci.yml");
    assert!(
        brief.get("evidence").is_none(),
        "the sweep's prose stays out: {brief}"
    );

    // `--yes` asks nothing; a second run in the same second gets its own folder.
    let again = sandbox.fix(&[&key, "--yes"], "");
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert!(!text(&again.stderr).contains("[y/N]"));
    let history = fs::read_to_string(sandbox.path().join("data/state/fixes.jsonl")).unwrap();
    let dirs: Vec<String> = history
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["dir"].to_string())
        .collect();
    assert_eq!(dirs.len(), 2);
    let last: serde_json::Value = serde_json::from_str(history.lines().last().unwrap()).unwrap();
    assert_eq!(last["confirmed"], "yes_flag");
    assert_ne!(dirs[0], dirs[1]);

    let unknown = sandbox.fix(&["0123456789abcdef", "--yes"], "");
    assert!(!unknown.status.success());
    assert!(text(&unknown.stderr).contains("no report has finding 0123456789abcdef"));
}

#[test]
fn only_a_current_undismissed_finding_is_fixed_and_a_silent_agent_fails() {
    let sandbox = Sandbox::new("agent = \"claude\"\n\n[github]\nrepos = [\"o/r\"]\n");
    assert!(sandbox.sweep("issue").status.success());
    let key = sandbox.newest_report("github-o--r")["issues"][0]["key"]
        .as_str()
        .unwrap()
        .to_owned();

    let silent = sandbox
        .command("silent")
        .args(["fix", &key, "--yes"])
        .output()
        .unwrap();
    assert!(!silent.status.success());
    assert!(
        text(&silent.stdout).contains("unknown: no result.json"),
        "{}",
        text(&silent.stdout)
    );
    let history = fs::read_to_string(sandbox.path().join("data/state/fixes.jsonl")).unwrap();
    assert!(history.contains(r#""outcome":"unknown""#), "{history}");
    let partial = sandbox
        .command("partial")
        .args(["fix", &key, "--yes"])
        .output()
        .unwrap();
    assert!(!partial.status.success(), "only fixed counts as done");
    assert!(text(&partial.stderr).contains("the fix did not finish: partial, agent exit code 0"));

    assert!(
        sandbox
            .run(&["dismiss", &key, "--reason", "accepted"])
            .status
            .success()
    );
    let dismissed = sandbox.fix(&[&key, "--yes"], "");
    assert!(
        text(&dismissed.stderr).contains(&format!("{key} is dismissed")),
        "dismissed now, with no sweep since: {}",
        text(&dismissed.stderr)
    );
    assert!(sandbox.run(&["undismiss", &key]).status.success());

    // A report edited to carry the heredoc's end word is refused before anything runs.
    let report = sandbox.newest_report_path("github-o--r");
    let edited = fs::read_to_string(&report)
        .unwrap()
        .replace(r#""commands": []"#, r#""commands": ["VIGIL_END"]"#);
    fs::write(&report, &edited).unwrap();
    let malformed = sandbox.fix(&[&key, "--yes"], "");
    assert!(
        text(&malformed.stderr).contains("VIGIL_END is reserved"),
        "{}",
        text(&malformed.stderr)
    );

    // An agent that cannot start is still recorded.
    assert!(sandbox.sweep("issue").status.success());
    sandbox.script("agents/claude", "#!/no/such/interpreter\n");
    let broken = sandbox.fix(&[&key, "--yes"], "");
    assert!(!broken.status.success());
    assert!(text(&broken.stdout).contains("unknown: the agent did not run: cannot start claude"));
    sandbox.script("agents/claude", FAKE_AGENT);

    // With no agent configured, nothing is asked.
    fs::write(
        sandbox.path().join("data/config.toml"),
        "[github]\nrepos = [\"o/r\"]\n",
    )
    .unwrap();
    let no_agent = sandbox.fix(&[&key], "y\n");
    assert!(
        text(&no_agent.stderr).contains("no agent chosen"),
        "{}",
        text(&no_agent.stderr)
    );
    assert!(!text(&no_agent.stderr).contains("[y/N]"));
    fs::write(
        sandbox.path().join("data/config.toml"),
        "agent = \"claude\"\n\n[github]\nrepos = [\"o/r\"]\n",
    )
    .unwrap();

    assert!(sandbox.sweep("ok").status.success());
    let stale = sandbox.fix(&[&key, "--yes"], "");
    assert!(!stale.status.success());
    assert!(
        text(&stale.stderr).contains(&format!("no longer found {key}; nothing to fix")),
        "{}",
        text(&stale.stderr)
    );
}

#[test]
fn findings_list_what_is_open_and_one_target_can_be_swept() {
    let sandbox = Sandbox::new("agent = \"claude\"\n\n[github]\nrepos = [\"o/r\"]\n");
    let before = sandbox.run(&["findings"]);
    assert!(before.status.success(), "{}", text(&before.stderr));
    assert_eq!(
        text(&before.stdout),
        "mac: no sweep with a verdict yet\ngithub:o/r: no sweep with a verdict yet\n"
    );

    let only = sandbox
        .command("issue")
        .args(["sweep", "--target", "github:o/r"])
        .output()
        .unwrap();
    assert!(only.status.success(), "{}", text(&only.stderr));
    assert_eq!(sandbox.runs().trim(), "1", "the Mac was not swept");
    assert!(
        !sandbox
            .target_dir("github-o--r")
            .parent()
            .unwrap()
            .join("mac")
            .exists()
    );
    let key = sandbox.newest_report("github-o--r")["issues"][0]["key"]
        .as_str()
        .unwrap()
        .to_owned();

    let listed = text(&sandbox.run(&["findings"]).stdout);
    assert!(
        listed.starts_with("mac: no sweep with a verdict yet\ngithub:o/r (swept "),
        "{listed}"
    );
    assert!(
        listed.contains(&format!(
            "): 1 open\n  medium   {key}  file github/workflows/ci.yml\n           fix: s\n"
        )),
        "{listed}"
    );

    // A dismissal shows at once, with no sweep between.
    assert!(
        sandbox
            .run(&["dismiss", &key, "--reason", "fine"])
            .status
            .success()
    );
    let json = text(&sandbox.run(&["findings", "--json"]).stdout);
    let lines: Vec<serde_json::Value> = json
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{json}");
    assert_eq!(lines[0]["target"], "mac");
    assert!(lines[0]["swept"].is_null());
    assert_eq!(lines[1]["open"], serde_json::json!([]));
    assert_eq!(lines[1]["dismissed"], 1);

    assert!(sandbox.run(&["undismiss", &key]).status.success());
    let json = text(&sandbox.run(&["findings", "--json"]).stdout);
    let repo: serde_json::Value = serde_json::from_str(json.lines().nth(1).unwrap()).unwrap();
    let open = &repo["open"][0];
    assert_eq!(repo["open"].as_array().map(Vec::len), Some(1), "{repo}");
    for (field, value) in [
        ("key", serde_json::json!(key)),
        ("severity", serde_json::json!("medium")),
        ("title", serde_json::json!("file github/workflows/ci.yml")),
        ("name", serde_json::json!("github/workflows/ci.yml")),
        ("version", serde_json::Value::Null),
        ("advisories", serde_json::json!([])),
        ("known_exploited", serde_json::json!(false)),
        ("explanation", serde_json::json!("x")),
        ("fix", serde_json::json!("s")),
        ("commands", serde_json::json!([])),
        ("new", serde_json::json!(false)),
    ] {
        assert_eq!(open[field], value, "{field}: {open}");
    }
    assert!(open["first_seen"].is_string(), "{open}");
    assert!(repo["components"].as_u64().is_some(), "{repo}");

    let mac = sandbox
        .command("ok")
        .args(["sweep", "--target", "mac"])
        .output()
        .unwrap();
    assert!(mac.status.success(), "{}", text(&mac.stderr));
    assert!(!text(&mac.stdout).contains("# Sweep of github:o/r"));
    let listed = text(&sandbox.run(&["findings"]).stdout);
    assert!(listed.starts_with("mac (swept "), "{listed}");
}

#[test]
fn a_target_name_that_matches_nothing_runs_nothing() {
    let sandbox = Sandbox::new("agent = \"claude\"\n\n[github]\nrepos = [\"o/r\"]\n");
    assert!(sandbox.sweep("ok").status.success());
    let unknown = sandbox
        .command("ok")
        .args(["sweep", "--target", "github:o/x"])
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert!(text(&unknown.stderr).contains("github:o/x is not a configured target"));
    let sweeps = || {
        fs::read_dir(sandbox.path().join("data/sweeps"))
            .unwrap()
            .count()
    };
    let (folders, runs) = (sweeps(), sandbox.runs());
    for name in ["github:o", "github:O/R", "server:web"] {
        let out = sandbox
            .command("ok")
            .args(["sweep", "--target", name])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{name} matches nothing");
    }
    assert_eq!(
        (sweeps(), sandbox.runs()),
        (folders, runs),
        "nothing ran for unknown names"
    );
}

/// Whether process `pid` still runs. Killed processes take a moment to go and nothing signals
/// it, so this waits up to a deadline.
fn gone(pid: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let alive = Command::new("/bin/kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .expect("kill runs")
            .success();
        if !alive {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// Starts a sweep with the fake agent in `mode`, presses Ctrl-C once the agent has started a
/// child, and returns the CLI's output and that child's pid.
fn sweep_and_interrupt(sandbox: &Sandbox, mode: &str) -> (Output, String) {
    let cli = sandbox
        .command(mode)
        .arg("sweep")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the CLI starts");
    // The agent writes its child's pid once both run: the signal to press Ctrl-C.
    let child_pid = sandbox.path().join("counter.child");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !fs::read_to_string(&child_pid).is_ok_and(|t| t.ends_with('\n')) {
        assert!(
            std::time::Instant::now() < deadline,
            "the fake agent never started"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let interrupted = Command::new("/bin/kill")
        .args(["-INT", &cli.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(interrupted.success());
    let out = cli.wait_with_output().expect("the CLI finishes");
    let child = fs::read_to_string(&child_pid)
        .expect("the agent wrote its child")
        .trim()
        .to_owned();
    (out, child)
}

/// The folders under `data/sweeps`, each with its target folders.
fn sweep_folders(sandbox: &Sandbox) -> Vec<(String, Vec<String>)> {
    let names = |dir: &Path| -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("the sweeps folder exists")
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let sweeps = sandbox.path().join("data/sweeps");
    names(&sweeps)
        .into_iter()
        .map(|sweep| {
            let targets = names(&sweeps.join(&sweep));
            (sweep, targets)
        })
        .collect()
}

#[test]
fn ctrl_c_stops_the_agent_and_what_it_started_and_cleans_up() {
    let sandbox = Sandbox::new("agent = \"claude\"\n");
    let (out, child) = sweep_and_interrupt(&sandbox, "hang");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(130), "{stderr}");
    assert!(stderr.contains("stopping"), "{stderr}");
    assert!(stderr.contains("the sweep was cancelled"), "{stderr}");
    assert!(gone(&child), "the agent's own child is stopped too");
    assert_eq!(
        sweep_folders(&sandbox),
        [],
        "the cancelled sweep's folder is removed"
    );
}

#[test]
fn a_sweep_cancelled_in_its_second_target_keeps_the_first() {
    let sandbox = Sandbox::new("agent = \"claude\"\n[github]\nrepos = [\"o/r\"]\n");
    let (out, child) = sweep_and_interrupt(&sandbox, "second-hangs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(130), "{stderr}");
    assert!(gone(&child));
    let folders = sweep_folders(&sandbox);
    assert_eq!(folders.len(), 1, "{folders:?}");
    assert_eq!(folders[0].1, ["mac"], "the repository's folder is removed");
    assert!(sandbox.newest_report_path("mac").exists());
}
