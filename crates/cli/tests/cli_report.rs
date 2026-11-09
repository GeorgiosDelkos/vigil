//! End-to-end test of `report`.

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
fn report_writes_the_page_with_the_newest_findings_and_prints_its_path() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run(tmp.path(), &["init"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let sweep = tmp.path().join("sweeps/20261109T134800Z/mac");
    fs::create_dir_all(&sweep).unwrap();
    let report = serde_json::json!({
        "started": "2026-11-09T13:48:00Z", "target": "mac", "failure": null, "components": 3,
        "findings": [{
            "key": "00000000000000aa", "severity": "high", "title": "t", "name": "webp",
            "place": "Homebrew", "first_seen": "2026-11-01T00:00:00Z",
            "advisories": ["CVE-2023-4863"], "known_exploited": true, "confidence": "confirmed",
            "evidence": "1.3.1 < 1.3.2", "explanation": "<script>x</script>",
            "installed": {"version": "1.3.1"},
            "fix": {"summary": "upgrade", "steps": ["s"], "commands": ["brew upgrade webp"]}
        }],
        "issues": []
    });
    fs::write(sweep.join("report.json"), report.to_string()).unwrap();

    let out = run(tmp.path(), &["report"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let path = tmp.path().join("report.html");
    assert_eq!(text(&out.stdout).trim_end(), path.display().to_string());
    let html = fs::read_to_string(&path).unwrap();
    assert!(html.contains("<h1>1 finding needs you</h1>"), "{html}");
    assert!(html.contains("<code>brew upgrade webp</code>"));
    assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
}

#[test]
fn report_before_init_says_to_run_init() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run(tmp.path(), &["report"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("run `vigil init` first"));
    assert!(!tmp.path().join("report.html").exists());
}
