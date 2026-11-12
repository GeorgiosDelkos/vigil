//! End-to-end tests of `advisories` that need no network: every request goes to a dead proxy.

use std::fs;
use std::process::Command;

/// With every source unreachable, nothing is printed, each failure is reported, and the exit
/// status says the output is incomplete.
#[test]
fn reports_every_failed_source() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("config.toml"), "").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .arg("--data-dir")
        .arg(tmp.path())
        .args(["advisories", "--package", "npm:lodash", "--product", "zlib"])
        .env("HOME", tmp.path())
        // Port 1 on loopback refuses connections, so every request fails at once.
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("the test binary was built by cargo");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(stderr.contains("warning: CISA KEV catalog"), "{stderr}");
    assert!(stderr.contains("warning: OSV:"), "{stderr}");
    assert!(stderr.contains("warning: NVD product zlib"), "{stderr}");
    assert!(stderr.contains("3 feed request(s) failed"), "{stderr}");
}

/// `advisories` on the data directory `data_dir` with `args`, every request to a dead proxy;
/// returns its stderr.
fn advisories(data_dir: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .arg("--data-dir")
        .arg(data_dir)
        .arg("advisories")
        .args(args)
        .env("HOME", data_dir)
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("the test binary was built by cargo");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// NVD paces its requests per process, so asking it waits for no sweep: it fails while one
/// holds the sweeps lock. OSV alone shares no rate and runs beside a sweep.
#[test]
fn nvd_is_not_asked_while_a_sweep_runs() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("config.toml"), "").unwrap();
    let sweeps = tmp.path().join("sweeps");
    fs::create_dir_all(&sweeps).unwrap();
    let lock = fs::File::create(sweeps.join(".lock")).unwrap();
    lock.try_lock()
        .expect("no sweep runs in a fresh data directory");

    let nvd = advisories(tmp.path(), &["--product", "zlib"]);
    assert!(nvd.contains("a sweep or fix is running"), "{nvd}");
    assert!(!nvd.contains("NVD product zlib"), "{nvd}");

    let osv = advisories(tmp.path(), &["--package", "npm:lodash"]);
    assert!(!osv.contains("a sweep or fix is running"), "{osv}");
    assert!(osv.contains("warning: OSV:"), "{osv}");
    drop(lock);
}
