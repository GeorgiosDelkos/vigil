//! End-to-end tests of `init` and `config`.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::process::Output;

fn run(data_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vigil"))
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .env("HOME", "/Users/me")
        .output()
        .expect("the test binary was built by cargo")
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("CLI output is UTF-8")
}

#[test]
fn config_before_init_says_to_run_init() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run(tmp.path(), &["config"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("run `vigil init` first"));
}

/// A TOML parse error quotes the offending line, so the error that ends the command must not
/// pass an escape sequence in that line on to the terminal.
#[test]
fn config_error_prints_no_escape_sequences() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "agent = \"\u{1b}]52;c;aGk=\u{7}\n",
    )
    .unwrap();
    let out = run(tmp.path(), &["config"]);
    assert!(!out.status.success());
    let stderr = text(&out.stderr);
    assert!(stderr.starts_with("error: "), "{stderr:?}");
    assert!(stderr.contains("]52;c;aGk="), "{stderr:?}");
    assert!(!stderr.contains(['\u{1b}', '\u{7}']), "{stderr:?}");
}

#[test]
fn init_then_config_prints_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run(tmp.path(), &["init"]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let out = run(tmp.path(), &["init"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("already exists"));

    fs::write(
        tmp.path().join("config.toml"),
        r#"
        agent = "codex"
        schedule.every_hours = 12
        history.since = "2025-06-01"
        mac.project_dirs = ["~/src"]
        github.repos = ["octo/app"]
        [[servers]]
        name = "prod"
        ssh = "prod"
        dirs = ["/srv/app"]

        [[servers]]
        name = "db"
        host = "10.0.0.5"
        user = "deploy"
        port = 2222
        identity_file = "~/.ssh/id"
        "#,
    )
    .unwrap();
    let out = run(tmp.path(), &["config"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "agent: codex\n\
         schedule: every 12 hours\n\
         history: since 2025-06-01\n\
         mac project dir: /Users/me/src\n\
         github repo: octo/app\n\
         server: prod (ssh alias prod)\n\
         server prod dir: /srv/app\n\
         server: db (host 10.0.0.5, user deploy, port 2222, key /Users/me/.ssh/id)\n"
    );
}

#[test]
fn default_config_summary() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(run(tmp.path(), &["init"]).status.success());
    let out = run(tmp.path(), &["config"]);
    assert_eq!(
        text(&out.stdout),
        "agent: none (set `agent` in config.toml)\nschedule: manual\nhistory: all\n"
    );
}

#[test]
fn invalid_config_lists_every_problem() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("config.toml"),
        "github.repos = [\"bad\"]\nmac.project_dirs = [\"rel\"]\n",
    )
    .unwrap();
    let out = run(tmp.path(), &["config"]);
    assert!(!out.status.success());
    let stderr = text(&out.stderr);
    assert!(stderr.contains("github.repos[0]"), "{stderr}");
    assert!(stderr.contains("mac.project_dirs[0]"), "{stderr}");
}

#[test]
fn init_with_data_dir_does_not_need_home() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .arg("--data-dir")
        .arg(tmp.path())
        .arg("init")
        .env_remove("HOME")
        .output()
        .expect("the test binary was built by cargo");
    assert!(out.status.success(), "{}", text(&out.stderr));
}
