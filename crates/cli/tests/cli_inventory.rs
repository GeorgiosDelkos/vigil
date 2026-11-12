//! End-to-end test of `inventory` with fake listing tools on `PATH`.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

/// A temporary home with a `bin` folder of fake tools, the only thing on `PATH`.
struct Sandbox {
    root: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("a temp dir can be created");
        fs::create_dir_all(root.path().join("bin")).expect("the temp dir is writable");
        Self { root }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }

    /// Writes an executable shell script `name` into `bin`.
    fn tool(&self, name: &str, script: &str) {
        let path = self.bin().join(name);
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).expect("the temp dir is writable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("the script exists");
    }

    /// Runs `inventory` with `config` as config.toml.
    fn inventory(&self, config: &str) -> Output {
        let data = self.path().join("data");
        fs::create_dir_all(&data).expect("the temp dir is writable");
        fs::write(data.join("config.toml"), config).expect("the temp dir is writable");
        Command::new(env!("CARGO_BIN_EXE_vigil"))
            .arg("--data-dir")
            .arg(&data)
            .arg("inventory")
            .env("HOME", self.path())
            .env("PATH", self.bin())
            .env_remove("NVM_DIR")
            .env_remove("FNM_DIR")
            .env_remove("VOLTA_HOME")
            .env_remove("ASDF_DATA_DIR")
            .env_remove("PYENV_ROOT")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .output()
            .expect("the test binary was built by cargo")
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn collects_every_source() {
    let sandbox = Sandbox::new();
    sandbox.tool("sw_vers", "echo 27.2");
    sandbox.tool(
        "brew",
        r#"echo '{"formulae": [{"name": "openssl@3", "installed": [{"version": "3.4.0"}]},
                              {"name": "python@3.13", "installed": [{"version": "3.13.1_1"}]}],
                 "casks": [{"token": "codex", "installed": "0.128.0"}]}'"#,
    );
    sandbox.tool(
        "rustup",
        r#"if [ "$1" = toolchain ]; then echo "stable-aarch64-apple-darwin (default)";
           else echo "rustc 1.99.1 (abc 2026-10-13)"; fi"#,
    );
    sandbox.tool("cargo", r"printf 'ripgrep v14.1.0:\n    rg\n'");
    sandbox.tool("node", "echo v22.1.0");
    sandbox.tool(
        "npm",
        r#"echo '{"dependencies": {"npm": {"version": "10.9.7"}}}'"#,
    );
    sandbox.tool("python3", "echo 'Python 3.13.1'");
    sandbox.tool("uv", r"printf 'ruff v0.6.9\n- ruff\n'");
    // `pipx` is deliberately missing: a tool that is not installed is listed, not an error.
    // Homebrew has the `python3` on PATH's version (after its `_1` revision is dropped), which
    // is then listed once, as the formula's. nvm has the `node` on PATH's version, which is
    // then listed once, as nvm's, and another.
    for version in ["v22.1.0", "v20.0.0"] {
        fs::create_dir_all(sandbox.path().join(".nvm/versions/node").join(version)).unwrap();
    }

    let project = sandbox.path().join("src/app");
    fs::create_dir_all(&project).unwrap();
    fs::write(
        project.join("Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .unwrap();
    let src = sandbox.path().join("src");
    let out = sandbox.inventory(&format!(
        "mac.project_dirs = [{:?}]\n",
        src.to_str().unwrap()
    ));

    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(stderr, "warning: not installed, so not checked: pipx\n");
    let lines: Vec<serde_json::Value> = text(&out.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let summary: Vec<String> = lines
        .iter()
        .map(|c| {
            let lookup = c["lookup"]["product"].as_str().map_or_else(
                || {
                    let p = &c["lookup"]["package"];
                    format!(
                        "{}:{}",
                        p["ecosystem"].as_str().unwrap(),
                        p["name"].as_str().unwrap()
                    )
                },
                str::to_owned,
            );
            format!(
                "{} {lookup} {}",
                c["found_in"]["kind"].as_str().unwrap(),
                c["version"]
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            r#"mac_os apple:macos "27.2""#,
            r#"homebrew_formula openssl "3.4.0""#,
            r#"homebrew_formula python "3.13.1""#,
            r#"homebrew_cask codex "0.128.0""#,
            r#"rustup rust "1.99.1""#,
            r#"cargo_install crates.io:ripgrep "14.1.0""#,
            r#"npm_global npm:npm "10.9.7""#,
            r#"uv_tool PyPI:ruff "0.6.9""#,
            r#"version_manager node.js "20.0.0""#,
            r#"version_manager node.js "22.1.0""#,
            r#"lockfile crates.io:serde "1.0.229""#,
        ]
    );
    assert_eq!(lines[8]["found_in"]["manager"], "nvm");
    assert_eq!(
        lines[10]["found_in"]["path"],
        project.join("Cargo.lock").to_str().unwrap()
    );
}

#[test]
fn failing_tool_is_reported_and_the_rest_still_count() {
    let sandbox = Sandbox::new();
    sandbox.tool("sw_vers", "echo 27.2");
    sandbox.tool("brew", "echo 'brew is broken' >&2; exit 1");
    let out = sandbox.inventory("");

    let stderr = text(&out.stderr);
    assert!(
        !out.status.success(),
        "a failed source makes the list incomplete: {stderr}"
    );
    assert!(stderr.contains("1 inventory problem(s)"), "{stderr}");
    assert!(
        stderr.contains("not installed, so not checked: rustup, cargo"),
        "{stderr}"
    );
    assert!(
        stderr.contains("warning: `brew info --json=v2 --installed` failed"),
        "{stderr}"
    );
    assert!(stderr.contains("brew is broken"), "{stderr}");
    let stdout = text(&out.stdout);
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("apple:macos"), "{stdout}");
}

/// A tool's stderr is quoted in the warning, so escape sequences in it must not reach the
/// terminal: here an OSC 52 clipboard write and a right-to-left override.
#[test]
fn warnings_print_no_escape_sequences() {
    let sandbox = Sandbox::new();
    sandbox.tool("sw_vers", "echo 27.2");
    sandbox.tool(
        "brew",
        r"printf 'broken \033]52;c;aGk=\007 \342\200\256txt.exe\n' >&2; exit 1",
    );
    let out = sandbox.inventory("");

    let stderr = text(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("broken \u{fffd}]52;c;aGk=\u{fffd}"),
        "{stderr:?}"
    );
    assert!(
        !stderr.contains(['\u{1b}', '\u{7}', '\u{202e}']),
        "{stderr:?}"
    );
}

/// npm lists the whole global tree even when it exits 1 over a problem in it; the packages
/// count, the problem is noted, and it does not fail the command.
#[test]
fn npm_tree_problem_keeps_its_packages() {
    let sandbox = Sandbox::new();
    sandbox.tool(
        "npm",
        r#"echo '{"dependencies": {"npm": {"version": "10.9.7"}}}'
           echo 'npm error code ELSPROBLEMS' >&2; exit 1"#,
    );
    let out = sandbox.inventory("");

    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("reports a problem in the global packages"),
        "{stderr}"
    );
    assert!(stderr.contains("ELSPROBLEMS"), "{stderr}");
    let stdout = text(&out.stdout);
    assert!(stdout.contains(r#""name":"npm""#), "{stdout}");
}

/// Output npm cannot have meant as a tree is a parse error when npm succeeded, and npm's own
/// failure (with its stderr) when it did not.
#[test]
fn unreadable_npm_output_names_the_right_cause() {
    for (exit, expected) in [
        ("exit 0", "cannot parse npm ls -g --json"),
        ("exit 1", "`npm ls -g --json --depth=0` failed"),
    ] {
        let sandbox = Sandbox::new();
        sandbox.tool(
            "npm",
            &format!("echo 'not json'; echo 'npm broke' >&2; {exit}"),
        );
        let out = sandbox.inventory("");

        let stderr = text(&out.stderr);
        assert!(!out.status.success(), "{exit}: {stderr}");
        assert!(stderr.contains(expected), "{exit}: {stderr}");
    }
}
