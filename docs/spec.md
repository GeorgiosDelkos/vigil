# Vigil: spec and implementation plan

## Context

New CVEs land daily across every stack. We want a small macOS menu-bar app that, on demand
or on a schedule, pulls the newest advisories and has a coding agent (Claude Code, Grok,
Codex, Gemini, opencode) decide whether this Mac, the user's declared GitHub repos, and the
user's declared servers are affected, then fixes approved findings. The repo is an empty
`cargo new` skeleton (`Cargo.toml`, `src/main.rs`, `.gitignore`), so everything is new.

Done means: one click (or the schedule) runs a sweep over all declared targets, findings
appear in the tray with severity and explanation, critical/high ones raise a notification,
and the user can approve a fix the agent then performs.

## Decisions taken with the user

| Area | Decision |
|---|---|
| Name | Vigil (2026-11-07; was Ancient Protector, which the owner found not technical enough). Mark (changed 2026-11-09, the owner's choice): the main view's vortex. The app icon is the Findings view's vortex itself on the dark tile (`vortex.html`); the tray keeps three streaks on each of its three arms (`marks.py`, which also says how the PNGs are rendered), both in `app/src-tauri/icons/src/`. The data folder and the Keychain service use the bundle id `io.github.georgiosdelkos.vigil`, as `vigil` alone is generic enough for another app to share |
| Outcome | Report, and fix on per-finding approval |
| Who decides "affected" | The agent. The app only narrows input |
| Sources | OSV.dev (includes GitHub reviewed advisories and malicious-package reports), NVD + CISA KEV |
| Feed flow | App fetches into a local cache; agent reads files |
| History window | User-chosen (`since` date or `all`); then deltas |
| Pre-filter | App keeps advisories whose package name is in the inventory, plus OS/kernel and all KEV entries. An NVD CVE not in KEV is also dropped when its CPE matches show it cannot affect the installed version, or name the product only as the platform another product runs on; a CVE for software outside the inventory then no longer reaches the agent through macOS (decided 2026-11-08: one Mac's bundle went from 10304 advisories to 267, 104 of them in KEV). Since 2026-11-10 the same rule covers OSV: Vigil compares versions itself (see "Version pre-match") and drops every advisory whose components are all out of range; the agent judges applicability. KEV entries no longer skip it (owner's decision, 2026-11-10): a known-exploited advisory that is provably out of range for every component is dropped too, which took one Mac's bundle from 271 advisories to 168 |
| Agents | Auto-detect claude, grok, codex, gemini, opencode; user picks one default |
| Agent permissions | Sweeps restricted: read anything but credential paths, write only `findings.json`, no shell (Codex: inside its sandbox), and no network path out (decided 2026-11-05, network and credentials 2026-11-12). Fixes get full access, only after the user confirms (decided 2026-11-05) |
| Mac inventory | App collects: macOS + Homebrew, global toolchains, lockfiles in declared folders |
| GitHub | Explicit repo list added on demand; deps, Dependabot/code/secret alerts, Actions workflows, account/org settings; auth via `gh` login |
| Servers | App runs a fixed read-only script over SSH, agent reads the result (changed 2026-11-06, see "Servers"); declared as `~/.ssh/config` alias or host/user/port/key fields |
| Fix | Agent performs it per target; plan shown first, user confirms each fix |
| Schedule | Manual plus optional interval |
| Surfacing | Tray icon state, macOS notification on new critical/high, JSON + Markdown report per sweep |
| Lifecycle | Dismiss with reason, diff vs last sweep, fix history (see "Lifecycle") |
| Concurrency | One agent run per target, sequential |
| UI | Tauri 2 + SolidJS/TS; one popover holding findings, details and settings; every value it shows is worked out in Rust, the UI only lays it out |
| Storage | Files in `~/Library/Application Support/io.github.georgiosdelkos.vigil/` |
| CLI | Yes, thin CLI over the same core |
| Distribution | Personal build first; signed + notarized DMG later; launch at login |
| v1 | All three targets |

## Architecture

Cargo workspace (root `Cargo.toml` becomes the workspace manifest; `src/main.rs` is deleted):

```
crates/core/        vigil-core   all logic, no UI
crates/cli/         vigil        bin: sweep, findings, dismiss, fix
app/src-tauri/      tray app (Tauri 2), calls core
app/ui/             SolidJS + TS frontend (ts-style)
prompts/            default prompt templates, copied to the data dir on first run
```

Core modules (one concept each):

- `config`: `config.toml` load/validate (`serde`, `deny_unknown_fields`).
- `paths`: data dir layout.
- `feeds::{osv, nvd, kev, ghsa}`: sync with cursor per source; `feeds::index` name index.
- `inventory::{homebrew, toolchains, version_managers, lockfiles}`: Mac collectors producing `Vec<Component>`;
  `github` collects a repository (step 5).
- `agent`: `AgentKind` enum, detection, command construction, run with output capture.
- `sweep`: orchestrates targets sequentially, emits progress events.
- `findings`: schema, validation. `lifecycle`: finding keys, dismissals, changes.
- `fix`: plan, confirm, execute, history; Fix all of one target in one run.
- `report`: JSON + Markdown writers.

### Data layout

```
~/Library/Application Support/io.github.georgiosdelkos.vigil/
  config.toml
  report.html (the HTML report, replaced each time it is asked for)
  prompts/{sweep,sweep-github,sweep-server,fix,fix-all}.md
  prompts/<name>.default.md (the built-in prompt when it last differed from a copy the user edited)
  feeds/osv/<id>.json, feeds/nvd/<product>.json
  state/.lock, state/dismissals.json, state/fixes.jsonl
  sweeps/.lock
  fixes/<utc-timestamp>-<key>/{PROMPT.md, fix.json, result.schema.json, agent.log, result.json}
  fixes/<utc-timestamp>-all/{PROMPT.md, fixes.json, result.schema.json, agent.log, results.jsonl}
    (only while the fix runs: deleted once its run is in state/fixes.jsonl)
  sweeps/<utc-timestamp>[-n]/<target>/{bundle/, agent-1.log, agent-2.log, report.json, report.md}
    (<target> is `mac`, `github-<owner>--<name>` or `server-<name>`)
```

Permissions (decided 2026-11-12): the data folder is created with mode 0700, and
`DataDir::ensure_private`, which the app runs at start, the CLI before every command and `sweep`
before it writes or deletes anything, refuses a root that is a symlink, is writable by group or others, or
belongs to another user (only the owner may change a folder's mode, so dropping the group and
other bits doubles as the ownership check). An existing 0755 root is tightened to 0700. What is
inside is created by Vigil and stays unreadable to other users through the root; its parent
folders are the user's to keep. So `vigil --data-dir /tmp/x` cannot expose the inventory and
agent logs, and no other user can plant a symlink where a sweep deletes.

Retention (the owner's decision, 2026-11-12): each target keeps only its newest sweep folder,
and its newest with a verdict when the newest has none. Once a target's `report.json` is
written, the sweep removes that target's folders (report, bundle, logs) in every older sweep,
except that newest verdict, and then each of those sweep folders left empty. It runs under
`sweeps/.lock`, removes only real folders named after the target (a symlink in that place, and
its sweep folder, stay; nothing inside is followed), and leaves sweeps named newer than the
current one (a clock set back) alone. A cancelled sweep writes no report for the target it
stopped in, so nothing of that target goes; a target removed from the config is never swept
again, so it keeps the folders it has (its newest only if it was swept since retention came in,
every earlier one otherwise) until the user deletes them; a report that cannot be read stops
the removal before anything goes. Nothing older is needed: changes, first-seen times and fix
confirmation read the newest report with a verdict, and the confirmed fixes listed for 30
days come from `state/fixes.jsonl`, which keeps each fix's title, summary and pull request.
Readers that hold no lock (the app's views, a fix's plan) take their scan again when a target
folder they read without a report has one by the end, or the sweep folders changed, since the
removal can fall between their two reads. A key only an older report had now
gets "no report has finding X: a newer sweep no longer finds it" instead of "a sweep at T no
longer found X".

### Key types (sketch, final shapes decided at the call site)

```rust
enum Target { Mac, GitHub { repo: RepoSlug }, Server { name: String, conn: SshConn } }
enum SshConn { Alias(String), Fields { host: String, user: String, port: u16, identity: Option<PathBuf> } }
enum AgentKind { Claude, Grok, Codex, Gemini, Opencode }
struct Component { ecosystem: Ecosystem, name: String, version: String, origin: PathBuf }
enum Severity { Critical, High, Medium, Low, Unknown }
struct Finding { key: FindingKey, target: TargetId, advisory_ids: Vec<String>, component: Component,
                 severity: Severity, kev: bool, evidence: String, explanation: String,
                 fix: Option<FixPlan> }
```

### Lifecycle (decided 2026-11-06)

- `FindingKey`: 16 hex digits, FNV-1a (64 bit, fixed across builds) of the target, the primary
  advisory, the component's lookup and where it was found (an OS package by its source
  package alone, since its binary packages change with installs and renames); an issue's of
  the target and its subject, which names one issue per report. The version is left out, so
  a finding keeps its key until it is fixed, except where two findings would share a key (two
  versions of one package in one lockfile): those get the version too. The primary advisory
  is the smallest id among the bundle advisories the agent's listed ids resolve to, so it does
  not depend on their order or on whether the agent listed the GHSA or its CVE.
- Dismissals: `state/dismissals.json`, key -> reason, time, and the advisory's `modified` time
  as the newest report had it. A dismissed finding shows again when that time changes; an
  issue stays dismissed until `undismiss`. Writes take `state/.lock` and replace the file
  whole. Reports keep dismissed entries, marked, and `report.md` lists them under "Dismissed".
  A dismissals file that cannot be read is a note in each report with a verdict, and nothing
  is dismissed. A target that could not be collected has nothing to dismiss and no note.
- Changes: each target's report has `changes`, against that target's newest earlier report
  with a verdict: new is what is shown now and was not shown then (absent, or dismissed and
  shown again), resolved is what was shown then and is gone now; a key dismissed since is
  neither. Only `<sweep>/<target>/report.json` is read, newest sweep first, stopping at the
  first with a verdict, which retention keeps (see "Data layout"). A report without a verdict
  has none, and a report that cannot be read is a note.
- Degraded sweeps (decided 2026-11-12; until then a source that failed, OSV offline say, made
  its findings show as resolved, confirmed pending fixes, and left a green icon and "All
  clear"): each report has `unchecked`, a typed record of the sources that failed for its
  target: the KEV catalog, OSV (the id query, or records that could not be fetched and had no
  cached copy), and the NVD products with nothing fetched and nothing cached in the last week. A finding of the
  target's last report with a verdict that this sweep did not find, and that a failed source
  could have produced (an OSV finding when OSV failed or a record its package's query returned
  did, an NVD finding when its product failed, an OS package's finding when the KEV catalog
  failed, since without it a crowded query is not thinned and the agent judges another set),
  goes into the new report's `carried` as that report saved it, with `carried_from`, the start
  of the last sweep that checked it. It stays open, is neither
  resolved nor new, and its fix is not confirmed until a sweep that checks it; a fix planned
  from any report since `carried_from` is still "fix reported". A target whose newest report
  has anything `unchecked` is never clear (see "UI"). A report saved before these fields reads
  as fully checked with nothing carried. A source served from its cache, because it could not
  be asked again, is a note in the report, not a failure. Accepted downside: a build from
  before these fields ignores `carried`, so after a downgrade a carried finding reads as
  resolved and its fix as confirmed.
- Reading: one report or state file that cannot be read is a problem of the targets it
  touches, never of all of them (decided 2026-11-12, after one broken `report.json` blanked
  the popover and greyed a red icon). A target whose newest report cannot be read shows the
  newest one that can, with the problem; dismissals that cannot be read dismiss nothing, and a
  fix history that cannot be read reports no fix, each a problem on every target. Fix all and
  `vigil fix` still refuse to act on what they cannot read.
- Fixes: the fix in the sweep's finding is the plan the user confirms; there is no
  separate planning run. A confirmed fix is one agent run with full access and the `fix`
  prompt. A GitHub fix works in a fresh clone, on a new branch, and opens a pull request; a
  server fix may run ssh to that one server, with the sweep's ssh options. Each fix is appended
  to `state/fixes.jsonl`.
- Fixed (decided 2026-11-08 with the user, changed 2026-11-11): a finding whose last fix run
  ended `fixed` with exit code 0, planned from the report the finding is in, is "fix
  reported". A fix is for the installed component, so every finding in an item decides, not
  the lead alone (`vigil fix` takes any finding's key, and a dismissal can change the lead):
  an item is a reported fix when at least one of its findings has a fix reported without a
  pull request, and none is "Still found after a fix" or has a fix that opened one.
  Otherwise it stays open and counted, whole; a component's findings are never split between
  open and fixed. A reported fix keeps every finding in it, its row says how many advisories,
  and the newest fix's summary and time speak for it. It is counted nowhere (needs you,
  exploited, the severity counts, the headline, the tray icon) and is listed green as "Fixed ·
  the next sweep confirms it", in the popover's Fixed tab above the confirmed fixes and in its
  own table in the HTML report. A target with nothing open but such fixes reads "1 fix to
  confirm" in green, not clear. The owner verified such fixes by hand and asked on 2026-11-11
  that a fixed issue not show as open; this replaces the 2026-11-08 rule that kept it
  counted. With only such items left the headline reads "1 fix to confirm" ("2 fixes to
  confirm"), not "All clear", until a sweep confirms them; the main view's centre shows their
  number over "to confirm", as it shows what needs you, and opens the Fixed tab. When a run
  opened a pull request, the item stays open and counted, marked "Pull request open", until
  a sweep no longer finds it; whether the pull request was merged is not checked. A later
  sweep that still finds it marks it "Still found after a fix", and it is open again.
  Once a later sweep no longer finds it, the fix is confirmed and listed under Fixed, with the
  finding's title, the agent's summary and the pull request, for 30 days.
  Which report a run fixes is decided by the sweep it was planned from (`found` in the
  record), never by comparing clocks; the last run of a key in `state/fixes.jsonl` decides,
  in file order. `vigil findings` shows the same.

### Grouping by component (decided 2026-11-10)

The 2026-11-10 Mac sweep found 113 findings in 12 components: ffmpeg 8.1.2 alone had 33, one
per advisory, each with the same `brew upgrade ffmpeg`. The owner chose to show components:

- A finding belongs to the installed component it was found in: same target, version and
  place found, and same lookup unless the place is one installed thing (a Homebrew formula or
  cask, a rustup toolchain, the `node` or `python3` on `PATH`, a version manager's folder, an
  OS source package). One formula can map to several NVD products (curl and libcurl), all at
  its version, and one upgrade replaces them, so they are one component, named after the
  formula. A place that holds many packages (a lockfile, a dependency graph, npm's global
  packages, macOS) keeps them apart by lookup; so does a place this build cannot read.
- `popover_view` turns open findings into items: one per component, holding its findings,
  and one per issue (an issue has no component). An item's lead is its most urgent finding
  (exploited, then severity, then newest); the lead's fix is the item's fix, shown once, and
  Fix runs it with the existing per-finding flow, its confirmation saying the fix is for the
  component and the next sweep checks every advisory again. An item has the worst severity
  of its findings, is exploited if any is, and was first seen when the earliest was.
- Everything the popover and the report count is items: the headline, "N exploited", the
  severity counts and bar, the target rows' columns (each component once, at its worst
  severity), the tabs, the tray's worst severity, the urgent line, and the notification
  (one line per component, with how many new advisories). Dismissed counts stay findings.
- Findings stay the unit of keys, dismissals, fixes and storage; nothing on disk changed. A
  component's detail lists each advisory, collapsed, with its own severity, explanation,
  evidence, key and Dismiss; dismissing them all removes the item.

### Mac inventory

Decided 2026-11-05. Each source is collected on its own; a failing one is reported and the
rest still count. A tool that is not installed is skipped, not an error.

| Source | Command or file | Looked up as |
|---|---|---|
| macOS | `sw_vers -productVersion` | NVD product `apple:macos` |
| Homebrew formulae and casks, dependencies included | `brew info --json=v2 --installed` | NVD products: name without `@version`, through a small alias table checked against NVD (`node` -> `node.js`, `gh` -> `github:cli`, `webp` -> `libwebp`, `curl` -> `curl` and `libcurl`); a name that is not a valid product is reported |
| Rust toolchains | `rustup toolchain list`, `rustup run <toolchain> rustc --version` | NVD product `rust` |
| Cargo-installed binaries | `cargo install --list` | OSV `crates.io` |
| Node.js | `node --version` | NVD product `node.js`; left out when another component has the same product and version (below) |
| Global npm packages | `npm ls -g --json --depth=0` | OSV `npm` |
| Python | `python3 --version` | NVD product `python`; left out when another component has the same product and version (below) |
| Node.js and Python versions kept by version managers | the version folders: nvm `versions/node/v*` under `$NVM_DIR`, else under both `$XDG_CONFIG_HOME/nvm` and `~/.nvm`, fnm `node-versions/v*` under `$FNM_DIR`, else under each of `$XDG_DATA_HOME/fnm` (`~/.local/share/fnm`), `~/.fnm`, `~/Library/Application Support/fnm`, Volta `$VOLTA_HOME/tools/image/node/*` (`~/.volta`), asdf `$ASDF_DATA_DIR/installs/{nodejs,python}/*` (`~/.asdf`), pyenv `$PYENV_ROOT/versions/*` (`~/.pyenv`) | NVD product `node.js` or `python` |
| uv and pipx tools | `uv tool list`, `pipx list --json` | OSV `PyPI` |
| Project lockfiles under `mac.project_dirs` | `Cargo.lock`, `package-lock.json` and `npm-shrinkwrap.json` (v2/v3), `uv.lock`, `poetry.lock` | OSV by ecosystem |

The folder walk skips `node_modules`, `target`, `.git`, `vendor`, `.venv`, `dist`, `build` and
every hidden folder, follows no symlinks, and only reads lockfiles: it never runs project code.

Bounds of the walk (decided 2026-11-12), so a home folder chosen as a project folder (config
accepts `~`) does not lead into Mail, Messages or Photos, downloads no cloud-only file, and
cannot hold the sweeps lock for good. macOS still asks once for `~/Desktop`, `~/Documents` and
`~/Downloads`, which choosing the home folder chose:

- It skips folders Finder hides (`UF_HIDDEN`, which `~/Library` has until "Show Library
  Folder"), macOS packages (`*.app`, `*.bundle`, `*.framework`, `*.photoslibrary`), and
  `~/Library` by path; `~/.Trash` goes with every dot-named folder. Folders and lockfiles in
  iCloud only (`SF_DATALESS`) are not listed or read, since that downloads them; such a
  lockfile is a note.
- It stays on the project folder's device: a disk or network share mounted under it is not
  entered.
- It lists at most a million entries per project folder, then stops there with a note (not a
  failed source: the same folders stop there again).
- It runs on its own thread, checked every 200 ms: the sweep's cancel or ten minutes in all
  stops it. The project folders walked before then count; the one it stopped in is named in
  the problem, and those after it are not walked. A system call that never returns (a stale
  SMB or NFS mount) leaves that thread blocked, and the sweep goes on without it.
- The cancel also stops the running inventory command and starts no more; a cancelled
  inventory makes no report. `gh` and `ssh` collection is not cancellable yet: the sweep
  checks the cancel before each repository and server, and each command has its time limit.
Workspace members and local path packages (no registry source) are left out of lockfile results.

Commands run from `/` with stdin closed and a one-minute limit, so a project file in the
caller's folder (`rust-toolchain.toml`, `.nvmrc`) cannot change which tool answers. Tools that
are not installed are listed, so an inventory taken with a bare `PATH` shows what it skipped.

Version managers (decided 2026-11-10): every installed version counts, not only the one the
shell would pick, since an unused version is still on disk and one `nvm use` away. The folders
are listed with no command run, so the result does not depend on `PATH`. The managers'
variables (`NVM_DIR`, `FNM_DIR`, ...) usually live in `.zshrc`, which an app started at login
does not read, so without them every default folder is read rather than the one the manager
would pick; a missing folder gives nothing. Only real folders whose name (after nvm's and
fnm's `v`) is a release of numbers and dots with an optional pre-release (`3.14.0rc1`) are
versions; pyenv's free-threaded `3.13.1t` is read as `3.13.1`. Symlinks (pyenv-virtualenv's
virtualenvs), fnm's `.downloads`, asdf's `ref-` builds, pyenv's `-dev` builds and its other
distributions (`pypy3.10-7.3.15`, `anaconda3-2024.06`) are skipped. Each version is found in `version_manager` with the manager and the folder, shown
as "nvm /Users/me/.nvm/versions/node/v22.22.2"; the folder is in the finding key, so two
versions are two findings and removing one keeps the other's key. The sweep's fix for such a
version removes it with the manager (`nvm uninstall 22.22.2`, after sourcing `nvm.sh`; Volta
has no command for it, so its folder goes to the Trash), installing a fixed version first if
none is installed and moving the default off it; switching the default alone is not a fix.

The `node` and `python3` on `PATH` (decided 2026-11-10, extended to Homebrew the same day):
when any other component, in practice a version manager's version or a Homebrew formula
(`python@3.14` 3.14.6 next to a `python3` 3.14.6), has the same product and version, the
`PATH` one is most likely that install and is reported once, as the other entry. That entry
names the tool that removes or upgrades it, and its key does not change with `PATH`. The
accepted downside: a separate install at the same version (the nodejs.org installer's
`/usr/local/bin/node` next to Homebrew's `node`) is reported only after the other copy is gone
or upgraded. The `PATH` finding's key (`node`, `python`) goes away once; its advisories stay
reported under the other entry's key. A dismissal made only of the `PATH` finding does not
carry over. For a Homebrew formula nothing reappears, since the formula's finding was already
reported next to the `PATH` one; a version manager's finding, new with that reader, is shown
even if the `PATH` one was dismissed. The reverse is accepted too: when only the formula's copy
was dismissed, the advisory leaves the report and the `PATH` key is listed as resolved on the
first sweep after this change, since both were the same install and the dismissal stands for
it. Keeping the `PATH` key open would mean merging keys between inventory and dismissals.

Known gaps, accepted for now:

- Global npm packages are read only from the `npm` first on `PATH`; those installed under
  other Node.js versions a version manager keeps are not.
- pyenv's and asdf's Pythons that are not a CPython release folder (PyPy, GraalPy, conda
  distributions, `-dev` builds) and asdf's `ref-` builds are not read. nvm versions older than Node.js 0.12
  and io.js are not read. A manager's folder set only in a shell profile (`NVM_DIR` in
  `.zshrc`) is not seen by an app started at login, which reads the default folders.
- `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` and `Pipfile.lock` are not read.
- A Homebrew name that is a valid CPE name but the wrong product gets no CVEs and no warning.
  Step 4 checks each product with no CVEs against NVD's CPE dictionary (an unknown answer is
  asked again after 30 days) and reports the ones NVD does not know.
- Homebrew names are matched to NVD products by name and an alias table
  (`inventory/homebrew.rs`, decided 2026-11-10). An entry is added only when the product is in
  NVD's CPE dictionary and its CVEs show it is the same software; one formula can map to
  several products where NVD files its CVEs under more than one name (`curl` and `libcurl`,
  `jpeg-xl` and `libjxl`). Names with no such product are looked up as they are, and step 4
  reports the ones NVD does not know, as the 2026-11-10 sweep found for `actionlint`, `fftw`,
  `gitleaks`, `libassuan`, `npth`, `pinentry`, `libsm`, `libxau`, `libxaw`, `libxmu`,
  `xorgproto` and others; those are not checked. The names left out on purpose although a near
  NVD name exists (`ggml`, `libomp`, `sdl2-compat`, ...) are listed, with why, on the table.
- An app started by launchd gets `/usr/bin:/bin:/usr/sbin:/sbin`; step 9 runs the inventory
  with the login shell's `PATH` (`$SHELL -lc`), as the agent adapters do.

### GitHub repositories (decided 2026-11-06)

Each repository in `repos` is its own target, swept after the Mac in the same sweep folder
(`sweeps/<time>/github-<owner>--<name>/`). The app collects everything through `gh api` with
the user's `gh` login; the agent never calls GitHub and reads only the bundle.

| Part | API | In the bundle as |
|---|---|---|
| Repository | `repos/{repo}` | `github/repository.json`; a repo that cannot be read fails its target |
| Dependencies | `repos/{repo}/dependency-graph/sbom` (default branch) | components in `inventory.jsonl`, from each package URL; ecosystems the app cannot look up are counted in the report |
| Dependabot alerts | `repos/{repo}/dependabot/alerts?state=open` | `github/dependabot-alerts.json` |
| Code scanning alerts | `repos/{repo}/code-scanning/alerts?state=open` | `github/code-scanning-alerts.json` |
| Secret scanning alerts | `repos/{repo}/secret-scanning/alerts?state=open` | `github/secret-scanning-alerts.json`, the secret value removed |
| Workflows | `repos/{repo}/contents/.github/workflows` and each file | `github/workflows/<name>` |
| Settings | the repository's `security_and_analysis`, `vulnerability-alerts`, the default branch's protection, `rulesets`, `actions/permissions`, `actions/permissions/workflow`, and for an organization owner its 2FA requirement | `github/settings.json`, one key per setting |

Each kind of alert is read 100 a page, following the cursor in GitHub's `Link` header, for at
most 5 pages: the bundle keeps the first 500, and when a sixth page is linked `settings.json`
says "n or more" open (n the alerts kept, so usually "500 or more") instead of a count, so a
repository with thousands of alerts costs five requests.

A feature that is off answers with a 403 or 404 and a message ("Dependabot alerts are
disabled", "no analysis found", "Branch not protected"); that answer is the setting's value in
`settings.json`, not a failure, so the agent can report it. Any other failure of a part is a
problem in the report and the rest still count. The dependency graph off (the SBOM returns 404)
is reported, since the repo's dependencies were then not checked.

Findings about settings and workflows have no advisory or component, so `findings.json` has a
second list, `issues` (decided 2026-11-06): each names a `subject`, either `{"setting": <key
in settings.json>}` or `{"file": <path of a bundle file under github/>}`, with severity,
evidence, explanation and fix, checked like findings. A Mac sweep writes `"issues": []`.

### Servers (decided 2026-11-06)

Each server in `servers` is its own target, swept after the repositories
(`sweeps/<time>/server-<name>/`). The spec first had the agent SSH in and write the inventory;
that would let untrusted advisory text steer commands on the server, so the app collects
instead and the agent only reads the bundle, as for GitHub.

The app sends one fixed script, `server.sh`, on ssh's stdin and runs it with `sh -s -- <random
marker> <dirs...>`. It only reads and never uses sudo. ssh runs with `BatchMode=yes` (a prompt
fails the target), `StrictHostKeyChecking=yes` (the host key must already be in
`known_hosts`, which a sweep never updates), agent, X11, port, tunnel and Kerberos credential
forwarding off, a server that stops answering dropped after 30 s, and no connection sharing.
These are command-line options, so `ProxyJump` hops do not get them; the README asks for
`BatchMode` and `StrictHostKeyChecking` on each hop in `~/.ssh/config`. The marker and the
folders travel on stdin, not on the server's process list. The Mac reads at most 256 MiB of
the answer and decodes each part on its own. It keeps at most 32 MiB of a package database and
1 MiB of any other part but a lockfile, cut on a package or line boundary and noted in the
report, so a server cannot fill the agent's bundle.

| Part | Read with | In the bundle as |
|---|---|---|
| OS release | `/etc/os-release` | `server/system.json` (`os_release`, `osv_ecosystem`); never in the prompt |
| Kernel | `uname -srm` | `server/system.json` (`kernel`) |
| OS packages | `/var/lib/dpkg/status` (Debian, Ubuntu), `/lib/apk/db/installed` (Alpine) | one component per source package and version in `inventory.jsonl`, `found_in` naming the installed packages |
| Unlooked-up packages | `rpm -qa`; dpkg or apk on a release OSV is not asked about (Debian testing, derivatives) | `server/{rpm,dpkg,apk}-packages.txt`, not looked up (noted in the report) |
| Listening sockets | `ss -tulpn` or `netstat -tulpn` | `server/listening.txt` |
| Docker | `docker ps`, `docker images` | `server/docker-containers.jsonl`, `server/docker-images.jsonl` |
| Lockfiles | `find` under each of the server's `dirs` (same names and skipped folders as the Mac walk; at most 200 per folder, each under 16 MiB, 128 MiB in all; every one left out is noted) | components in `inventory.jsonl` |

OS packages are looked up in OSV by release ecosystem (`Debian:12`, `Ubuntu:24.04:LTS`,
`Alpine:v3.20`) and source package name, with the installed version: by name alone Debian 12's
`openssl` matches 266 advisories and `linux` over 1000 (checked 2026-11-06), and OSV compares
dpkg and apk versions as the distribution does. So OSV sees the versions of OS packages, unlike
language packages (accepted by the user 2026-11-06). A query that still matches more than 200 advisories (the kernel) keeps only
those for a CVE in CISA KEV, read from the advisory id (`DEBIAN-CVE-...`; grouped `DSA-` and
`USN-` advisories of such a query are dropped), and the report says how many were left out.
Without the KEV catalog nothing is known to be exploited, so such a query keeps them all.
Kernel images built from `linux-signed*` source packages are looked up as the kernel's source
package, which is where OSV files kernel advisories. RPM distributions are not looked up:
OSV's Rocky Linux and AlmaLinux records disagree on binary versus source names and on epochs.
Not handled yet: Ubuntu Pro (ESM) packages are looked up in the plain release, not
`Ubuntu:Pro:...`.

Issues on a server name a file (`server/listening.txt`); there are no settings.

### Sweep flow (per target, sequential)

1. Feeds: delta-sync all sources (skip a source that fails, record the error in the report).
2. Inventory:
   - Mac, GitHub and servers: app collects (servers over SSH, see "Servers").
3. Pre-match (see "Version pre-match"): each advisory and component pair gets in range,
   unknown or out of range. Out-of-range pairs are dropped, KEV or not, then advisories left
   with none; the report counts those as `out_of_range`.
4. Bundle: app writes `bundle/` = `inventory.json`, filtered `advisories.jsonl` with each
   candidate's verdict and reason, `findings.schema.json`, rendered prompt.
5. Agent run: headless CLI in `bundle/` as cwd; agent writes `findings.json`.
6. Validate with serde (strict). On failure, one retry with the error appended; then mark the
   target failed.
7. Key each finding and issue, apply dismissals, compare with the target's last sweep (see
   "Lifecycle"), write the report; the tray app updates and notifies on new critical/high.

### Fix flow

Fix click (or `vigil fix <key>`) -> the finding's fix (steps + exact commands)
from the newest report that has the key, shown in the details window -> user confirms (`--yes`
for scripts that already showed it) -> agent run with the `fix` prompt, full access -> result
appended to `state/fixes.jsonl` -> the next sweep checks the finding again. Decided 2026-11-06
(see "Lifecycle"): no separate planning run; GitHub fixes open a pull request; server fixes may
use ssh.

- Before asking, everything that can be checked is: the key is in the newest report of its
  target with a verdict (a newer sweep without it means it is gone, and an old fix could
  downgrade a package), it is not dismissed, its fix passes the sweep's text checks again, the
  target is still in `config.toml`, and the agent is installed. The question shows where the
  fix runs (for a server, the exact ssh command), the agent and its model, when the sweep
  found it, the summary, the steps and the exact commands, as the agent is told the user
  confirmed all three; and notes:
  for a server, that the agent on this Mac reads the server's output, and when the user's
  edited `prompts/fix.md` is used. A summary is shown on one line, so it cannot pass for a
  command. Not confirming exits non-zero.
- What runs is the plan the question showed (decided 2026-11-12): the plan holds where it runs,
  the agent and model, and the prompt template, read once. The app keeps the plan of the last
  confirmation it showed under a number the UI sends back with Run; a newer preview replaces
  it, and an old number is refused. Planning again at the click was the old design: it read
  `config.toml` again, so a host, agent or model edited while the user read the question ran
  unseen. A fix prompt without `{{access}}`, where the "Where to work" rules go, is refused.
- A repository fix whose commands may address another repository is refused before asking
  (decided 2026-11-12). The rule is an allow-list and conservative; commands are split into
  words and parts as a shell splits them, nothing is expanded. No word names a `GH_*`,
  `GITHUB_*` or `GIT_*` variable, holds a character the shell expands (`$`, a backquote, a
  glob or brace character), or runs other words (`sh`, `bash`, `eval`, `source`, `xargs`,
  `alias`, ...), and a word with spaces passes the rule itself. Every word naming `gh`, `git`,
  `curl`, `wget`, `cd` or `pushd` is checked as a call with the words after it, so no wrapper,
  keyword or argument before it hides one. In those calls every GitHub address
  (`github.com/<owner>/<name>`, `github.com:<owner>/<name>`, `github.com.`, any case) names
  this repository with no `..` or `%` after it, and every `api.github.com` address is under
  `/repos/<this repository>` with no `..` or `%`, and not `forks`, `generate` or `transfer`.
  `gh` runs only `api`, `secret`, `variable`, `workflow`, `pr`, `issue`, `label`, `release`
  or `repo edit`, never with `--hostname`, `--org`, `-o` or `--owner`; `gh api` calls one
  path under `repos/<this repository>`; every other subcommand names the repository with
  `--repo` (or `gh repo edit <repo>`), as `gh` otherwise takes it from the folder it runs in.
  `cd` and `pushd`, and `git -C`, `--git-dir` and `--work-tree`, go only to a relative folder
  with no `..`, and git takes no `-c`, `--config-env` or `--exec-path=<dir>`, which can make it
  run a shell. Other
  programs and interpreters are not checked: `go get github.com/<module>`
  names a module, not a repository to change, and a script or `python -c` reaching GitHub is
  the accepted risk of a full-access agent; the rule is defence in depth around what the user
  reads, not a sandbox. A fix it refuses wrongly (a package named `gh`, say) is for the user
  to run by hand. A settings fix, which needs no pull request, is one whose every command is
  a single `gh` call, the word `gh` first, other than `gh pr`.
- A finding key is a 64-bit hash over every target, so two targets could share one (a crafted
  lockfile path in a repository). Looking a key up for a fix or a dismissal fails, naming both
  reports, when the newest report of another target also has it.
- The agent gets `fix.json` with the key, target, severity, advisories or subject, the
  installed component and the fix, not the sweep's evidence and explanation: those were
  written from untrusted advisory text and files, and the user confirmed the fix, not them.
  When a confirmed command fails, the agent may adapt it to reach the same goal (decided
  2026-11-06 for servers: "so it can adapt when a command fails"), and the prompt forbids
  anything the fix does not name.
- Each run has a new folder `fixes/<utc-timestamp>-<key>[-n]/`: `PROMPT.md` (the user's
  `prompts/fix.md` with the target and where to work filled in), `fix.json` (the report entry), the schema of
  `result.json`, the agent's `agent.log`, and `result.json`, which the agent writes: `outcome`
  (`fixed`, `partial`, `failed`), a one-line `summary`, and for a repository the
  `pull_request` URL (`https://github.com/<owner>/<name>/pull/<number>` of that repository
  only, owner and name compared case-insensitively as GitHub does). Files the agent wrote are
  read only when regular (no link, no FIFO, which would block the read) and only up to a cap.
  Once the run is recorded the folder is deleted (the owner's decision, 2026-11-12), under the
  sweeps lock, without following links; the app keeps the end of `agent.log` in memory for the
  results view, and the CLI prints it for a fix that did not finish. A run whose record cannot
  be appended keeps its folder.
- Where to work: this Mac; for a repository, a clone in the fix folder, a branch
  `vigil/fix-<key>-<start time to the millisecond>`, new for each run, and a pull request
  into the default branch (never a push to the default branch); for a server, every command
  through `ssh` with the sweep's options to that one host, carried to the server's `sh -s` in
  a quoted heredoc, so a quote in a command cannot end the ssh line and run the rest on the
  Mac.
- A repository fix's agent runs with git hooks off (`GIT_CONFIG_COUNT` setting
  `core.hooksPath=/dev/null`, which every git command it runs reads as command-line
  configuration) and package lifecycle scripts off (`npm_config_ignore_scripts=true` for npm
  and pnpm, `YARN_ENABLE_SCRIPTS=false`), the owner's decision of 2026-11-12. The prompt says
  that files in the clone such as `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` and `.cursorrules` are
  data. Before the run the app reads the default branch and its head with `gh`; after it, the
  default branch must be the same branch with the same head, a reported pull request must be
  open from the run's branch of this repository into it, and a fix reported `fixed` must name
  one unless every confirmed command is a `gh` call other than `gh pr` (a settings fix).
  Otherwise the run is recorded `unknown`, with why and what the agent reported. Accepted
  risk: the full-access
  agent still reads the clone, could unset those variables, and could push to other branches
  or tags, which are not checked; the check sees the end state, not each push, so a push to
  the default branch undone before the agent exits is not seen; the repositories are the user's own, and the agent's
  project settings and hooks come from its working folder, the fix folder.
- Server fixes keep the full-access agent on this Mac (the owner's decision, 2026-11-12). It
  reads the server's output, which a compromised server controls; the confirmation says so.
- `state/fixes.jsonl` gets one line per run: key, target, agent, start and end, exit code,
  outcome (`unknown` when `result.json` is missing or invalid, the agent did not start, or a
  repository's check after the run failed, with why), summary, pull request, how it was
  confirmed (`asked` or `yes_flag`). Records written before 2026-11-12 also name the folder,
  which those versions kept; this version does not remove such folders, nor one whose
  deletion a quit cut short. Appends
  take `state/.lock`; a last line cut short by a crash is ended first. The CLI exits non-zero
  unless the outcome is `fixed` and the agent exited 0.
- A fix holds `sweeps/.lock`, so no sweep or other fix runs while it changes the target.

### Fix all (decided 2026-11-11)

The owner asked for a Fix all button on a target's screen and chose "one run, one confirm":

- Fix all takes every open item of one target whose lead's fix has commands to run, in the
  order the popover ranks them. A fix without commands is manual and keeps its own Fix. The
  button reads "Fix all N" (Rust's label) and shows only when it takes two or more items: one
  item already has Fix.
- Not for repositories (our choice; the owner left it open). There each fix is a pull request
  on its own branch, reviewed and merged on its own, and a setting is fixed with `gh api`.
  One pull request for all of them was weighed: it needs a branch named after no one finding,
  and one merge would stand for many fixes. Fix all is for this Mac and servers, where fixes
  apply in place; `vigil fix all github:...` refuses with that reason.
- Before asking, each item is checked as one Fix checks its finding (current, not dismissed,
  well formed, target configured, agent installed), and all come from the same report. The
  one question lists every item: its name and version, the fix's summary and exact commands,
  where it runs and with which agent, then "Fix all N" and Cancel.
- Staleness: the app runs only the list it showed: the plan the question showed, kept as for
  one fix, so the same keys in the same order, from the same sweep, with the same destination,
  agent and prompt. Under the sweeps lock the list is made again as planning makes it, and must be
  the same keys in the same order from the same report: a sweep, a fix reported in between, a
  dismissal or undismissal, or a new lead refuses the whole run, naming the first item that
  differs ("nothing was run: curl 8.1.2: a sweep, fix or dismissal changed the list while it
  was being confirmed; run `fix all mac` again ..."). Dropping that item and running the rest
  was weighed: it would run a list nobody confirmed, so refusing is the honest one, and Fix
  all asked again shows the current list.
- One agent run with full access, the `fix-all` prompt (`prompts/fix-all.md`, listed with its
  hashes like the others), and `fixes.json` holding each item's brief as `fix.json` holds one.
  The agent applies them in order and appends one line per item to `results.jsonl` (`key`,
  `outcome`, `summary`) as it finishes it; when one fails it says why in that line and goes
  on with the rest. A line that does not parse or fails the checks of `result.json` is left
  out; the last valid line of a key wins.
- Each item is appended to `state/fixes.jsonl` on its own, exactly as a single fix records
  it (its key, title, `found`, the run's agent, times, exit code and folder), so the reported
  fix, "Still found after a fix" and the next sweep's check work per item. An item with no
  valid line is `unknown`, with why when the agent was stopped or did not start; what the
  agent reported before it was stopped is kept, and counts as a reported fix only with exit
  code 0, as always.
- One agent at a time (the owner's rule, 2026-11-11): Fix all is one agent process for the
  whole batch, never one per item, and holds `sweeps/.lock` for the whole run, so a sweep, a
  fix or another Fix all from the CLI or the app is refused ("a sweep or fix is running").
  The app also claims its runner as for one fix, so Sweep now, the schedule, Fix and Fix all
  are refused while it runs.
- While it runs, the popover's fixing view lists preparing, one step per item, and recording;
  the running item is the first the agent has not reported in `results.jsonl` yet, with one
  spinner on it. When it ends, the view stays with each item's result (see "Fix results" under
  UI). The CLI's last line says "2 of 3 fixed" and names each item not fixed; it reads
  "failed" only when every item reported `failed`, and "partial" otherwise.
- CLI: `vigil fix all <target> [--yes]` shows every item, asks once, runs, prints a line per
  item and exits non-zero unless every item was fixed with exit code 0.

### Agent adapters

One `match` on `AgentKind` builds the `Command` (headless flag, permission flags, prompt as an
argument). Exact flags for each CLI are verified against current docs at implementation
time, not from memory. Detection: GUI apps launched at login get a minimal `PATH`, so the
user's login shell (`$SHELL -lc`) prints its `PATH` and `command -v <bin>` between marker lines
at the start of each sweep; the agent then runs with that `PATH`, so an npm-installed agent and
the tools it calls start as in a terminal. The shell is a non-interactive login shell, so zsh
reads `.zprofile` but not `.zshrc`: an agent whose `PATH` entry is set only in `.zshrc` (nvm
often is) is not found, and the error says to install it. An agent missing or logged out is a target error
with a fix hint, never a silent skip.

Sweeps run restricted (decided 2026-11-05): the agent may read anything, write only
`findings.json`, and run no shell command. Network and credentials (decided 2026-11-12, at the
owner's request after a security review): sweeps keep reading the Mac, but every network path
out of a sweep run is closed, so text a prompt-injected agent read cannot be sent anywhere from
the run but to its own model provider, and credential paths are denied for every agent whose
CLI can deny reads. What the agent writes in `findings.json` still leaves the run: the app shows
it, and a fix the user confirms is given it (see "Fix flow"); that is the reason for the caps
and command rules under "Bundle and findings". Concretely:

- No shell command, except Codex's, which runs inside its sandbox with the network off. The
  listing commands sweeps used to allow are gone: `npm view` took `--registry <url>` (any URL,
  so any data in it), `npm ls` takes `--logs-dir` and `--cache` (writes anywhere) and every
  npm command may run npm's update check against the configured registry, and `brew info
  --analytics` fetches from formulae.brew.sh, with no setting to forbid it. None could be made
  network-free, and the bundle already holds what they listed.
  `cargo tree` was never one: it can write `Cargo.lock` and runs the `rustc` a project's
  `.cargo/config.toml` names.
- No web, MCP, subagent or memory tools, and not the user's own agent settings where they could
  grant more: allow rules, hooks, plugins, MCP servers and connectors. Not closed: Gemini CLI
  still loads `~/.gemini/settings.json` (its hooks run and its MCP servers start, with their
  tools denied), and Grok its own `~/.grok` hooks; both are code the user installed.
- Credential paths denied (one list, `CREDENTIAL_PATHS` in `agent.rs`): `.ssh`, `.aws`,
  `.config/gh`, `.gnupg`, `.netrc`, `.npmrc`, `.pypirc`, `.docker/config.json`, `.kube`,
  `Library/Keychains`, `.config/gcloud`, `.azure`, `.env*`, and the token files of git, cargo
  and the agents (`.git-credentials`, `.codex/auth.json`, ...), in any folder: the home folder
  has other spellings (`/System/Volumes/Data/Users/<name>`) that a rule anchored at `~/` would
  miss. Not covered: another letter case (`~/.SSH`), which APFS accepts and no CLI's rules fold.
  Gemini CLI gets them as a policy rule over its tools' path arguments; Codex cannot deny reads
  inside its sandbox, which is accepted because it has no way to send them out of the run.
- The environment is an allowlist: `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `TMPDIR`,
  `TERM`, proxies and their certificate files, `LC_*`, `XDG_*`, and the agent's own prefixes
  (`ANTHROPIC_` and `CLAUDE_` for Claude Code, `XAI_` and `GROK_` for Grok, `OPENAI_` and
  `CODEX_` for Codex, `GEMINI_` and `GOOGLE_` for Gemini CLI, which includes Google Cloud
  credentials for a Vertex AI login, and all of them for opencode, which serves any provider).
  Logins still work: Claude Code reads the Keychain, the others files under `HOME`. Fixes keep
  the inherited environment.
- Sweeps and fixes alike get `HOMEBREW_FORBID_PACKAGES_FROM_PATHS=1` without
  `HOMEBREW_INTERNAL_ALLOW_PACKAGES_FROM_PATHS`, so Homebrew never loads a formula from a file
  in a cloned repository, and a `PATH` without empty, `.` or relative entries.

Fixes (step 7) get full access, and only after the user confirms the plan. Flags, checked
2026-11-12 against `claude --help` (2.1.322), `grok --help` and its user guide (1.0.77),
`opencode run --help` and `opencode debug agent` (1.17.11), codex's CLI and config reference,
and gemini-cli's source at v0.68.0; every agent runs with the bundle folder as its working
directory:

| Agent | Sweep call | Verified on this Mac |
|---|---|---|
| `claude` | `claude -p <prompt> --permission-mode dontAsk --setting-sources "" --strict-mcp-config --tools Read,Glob,Grep,Edit,Write --allowedTools Read(//**) Edit(./findings.json) --disallowedTools mcp__* WebFetch WebSearch Read(//**/.ssh) Read(//**/.ssh/**) ...` | 2026-11-05: writes `findings.json`, cannot write elsewhere. 2026-11-12: the new flags parse (an empty `--setting-sources` is accepted, an unknown one refused); not run with a prompt |
| `grok` | `grok -p <prompt> --permission-mode default --sandbox workspace --disable-web-search --no-subagents --tools read_file,grep,list_dir,search_replace,write --disallowed-tools search_tool,use_tool --allow Read(/**) --allow Edit(./findings.json) --deny Bash --deny mcp__* --deny Read(**/.ssh) ... --cwd <bundle>`, `GROK_MEMORY=0` and `GROK_{CLAUDE,CURSOR}_{AGENTS,HOOKS,MCPS,RULES,SKILLS}_ENABLED=false` | 2026-11-05, same check as claude. The 2026-11-12 flags are from `grok --help` and its docs; not run with a prompt |
| `codex` | `codex exec --sandbox workspace-write --skip-git-repo-check --ignore-user-config --ignore-rules --disable apps -c sandbox_workspace_write.network_access=false -c web_search="disabled" -C <bundle> <prompt>` | no: not installed (flags from its CLI and config reference) |
| `gemini` | `gemini -p <prompt> --approval-mode auto_edit --skip-trust --extensions none --admin-policy <bundle>/gemini-policy.toml` | no: not installed; the free tier was refused (`IneligibleTierError`) |
| `opencode` | `opencode run --pure --agent vigil-sweep --dir <bundle> <prompt>`, the agent defined in `OPENCODE_CONFIG_CONTENT` | `opencode debug agent vigil-sweep` against a permissive user config: the sweep's rules come last and win, and the shell, web, task and skill tools are off; not run with a prompt (the local model timed out) |

Why each CLI needs what it gets:

- Claude Code merges `permissions.allow` from every settings file with `--allowedTools`, so a
  user rule such as `Bash(curl *)` would hold in a sweep. `--setting-sources ""` loads no user,
  project or local settings (the Agent SDK's `settingSources: []`); its cost is that a provider
  configured only in `~/.claude/settings.json` (Bedrock through its `env` block, an
  `apiKeyHelper`) is not used during sweeps. `--tools` limits the built-in tools, but not MCP
  ones: `--strict-mcp-config` without `--mcp-config` starts no MCP server, and the `mcp__*` deny
  removes the claude.ai connectors too. A `Read` deny also covers Grep and Glob.
- Grok's `web_search` (with an `open_page` action that fetches any URL) runs without approval
  in every mode, so `--disable-web-search`; MCP stays reachable through its `search_tool` and
  `use_tool` meta-tools unless they are removed. It also loads Claude Code's and Cursor's
  hooks, MCP servers and skills unless its `GROK_*_ENABLED` switches are off. A leading `//`
  is literal text in its rules, so "every path" is `/**`. The `workspace` sandbox makes the
  kernel hold writes to the bundle, `~/.grok` and temporary folders; its network limits are a
  no-op on macOS, so they are not relied on.
- opencode deep-merges `OPENCODE_CONFIG_CONTENT` into the user's config, and agent rules come
  after global ones, so a rule the user set for its `build` agent would outrank global sweep
  rules. The sweep defines its own agent, whose rules are evaluated last (last match wins), and
  runs without the user's plugins (`--pure`). Its grep tool stays denied: opencode checks the
  search pattern, not the files searched, so `read` denies would not hold for it.
- Codex's `--ignore-user-config` skips `~/.codex/config.toml`, so its MCP servers and any
  `network_access = true` do not apply (the login under `CODEX_HOME` does); `--ignore-rules`
  skips the user's command rules. A `model_provider` set only there is not used during sweeps.
- Gemini CLI's `--admin-policy` loads a policy at the admin tier, above the user's own; it is
  ignored when policy files exist in `/Library/Application Support/GeminiCli/policies`, an
  administrator's choice. Its file tools reach only the workspace unless the user's settings
  add folders, so the policy also denies any tool call (writes included) whose path argument
  names a credential path, matching only path arguments so `findings.json` text may still name
  `~/.ssh/config`, and denies content search and `read_many_files` outright, since a search or
  a glob such as `.ss[h]` gets past a rule on names.
  The app writes it into the bundle before each run, replacing whatever is there (a link
  included), since Gemini CLI can edit bundle files but reads the policy only at start.
  `--extensions none` turns every extension off.

`auto_edit` (gemini) and `workspace-write` (codex) allow edits anywhere in the bundle, not only
`findings.json`; the bundle is the app's own copy, so that is accepted. `findings.json` is
opened without following a link and without waiting on a FIFO, and only a regular file of at
most 4 MiB is read, since those two agents could put anything there.

A confirmed fix runs with full access, in its fix folder (flags checked 2026-11-06 in each CLI's
`--help`; codex in its CLI reference): `claude -p <prompt> --permission-mode bypassPermissions`,
`grok -p <prompt> --permission-mode bypassPermissions --cwd <dir>`, `codex exec
--dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -C <dir> <prompt>`, `gemini -p
<prompt> --approval-mode yolo --skip-trust`, `opencode run --dangerously-skip-permissions --dir
<dir> <prompt>` (rules the user's own opencode config denies stay denied).

Model (decided 2026-11-07, at the owner's request to choose provider and model): `[models]` in
`config.toml` maps an agent to the model it runs with (`claude = "opus"`, `opencode =
"ollama/gemma4:e4b"`); an agent left out runs its own default. Every CLI takes `--model <name>`
(each `--help` on 2026-11-07, codex in its CLI reference), passed right after `exec` or `run`
for codex and opencode and first for the others, in sweeps and fixes alike. A model name is up
to 128 ASCII letters, digits and `. _ - : / @`, never starting with `-`. The settings offer the
chosen agent's models: Claude Code's aliases (`opus`, `sonnet`, `haiku`), what `grok models`
and `opencode models` list at detection, and a typed name for any agent (codex's `debug
models` is experimental and Gemini CLI lists none). The provider is fixed by the agent
(Anthropic, xAI, OpenAI, Google) except for opencode, whose `provider/model` names group its
models by provider.

The prompt argument is one line pointing at `PROMPT.md` in the bundle, so the real prompt is a
file the user can read and edit (`prompts/sweep.md` in the data dir, copied from the built-in
default on first use). The agent's stdout and stderr go to `agent-<attempt>.log` beside the
bundle.

Prompt updates (decided 2026-11-10): an improved built-in prompt must reach existing installs
without overwriting what the user wrote. At the start of each sweep, under the sweeps lock,
each copy in `prompts/` is checked:

- byte for byte the current built-in prompt: left alone, not rewritten;
- byte for byte an older built-in version: never edited, so replaced by the current built-in
  prompt, written to a temporary name, synced and renamed;
- anything else: edited by the user, so kept. The current built-in prompt is written beside it
  as `<name>.default.md` to compare, and the sweep's reports note it under "Not checked"
  (`problems`), once: when that file is first written or its text changes;
- missing: left for the first use to create, as before.

"An older built-in version" is a match against the hash (64-bit FNV-1a) of every version of
the prompt in the git history, listed in `crates/core/src/prompts.rs`. The alternative was a
sidecar recording the hash of the version copied; the list was chosen because it needs no
state the user can lose, and it recognises the copies of installs made before this change,
which have no sidecar. Its cost: each change to a built-in prompt adds its hash to the list,
which a test enforces with a message saying what to add. SHA-256 was weighed and not used:
no adversary picks the files compared, and `sha2` would be a new dependency of the core.
The report problems were chosen as the channel because the sweep is where the prompt is used
and they already carry the sweep's other notes (dismissals unreadable, an interrupted
sweep's cleanup); the settings view has no place for notices. They reach `vigil sweep`'s
output, `report.md` and `report.json`, but the menu-bar app shows no report problems yet, so
an app-only user finds the note only there and in the `.default.md` file. The note says the
built-in prompt may be newer, not that it is: without a record of the version the user
started from, an edit of the current version looks the same as an edit of an old one. Not
handled: a fix run does not update `fix.md` itself, the next sweep does; and an edit saved in
the instant between the check and the rename is replaced.

### Bundle and findings (decided 2026-11-05)

Each target's bundle folder holds:

- `PROMPT.md`: the rendered sweep prompt.
- `inventory.jsonl`: one component per line with a short id (`c1`, `c2`, ...).
- `advisories.jsonl`: one compact line per advisory: id, source, aliases, summary, source
  severity (CVSS score and vector, NVD's primary score first, or GHSA severity), what is
  affected, `known_exploited`, the components it is a candidate for, each as
  `{"component": "c23", "match": "in_range", "why": "2.88.1 < versionEndExcluding 2.89.0"}`
  (see "Version pre-match"), and `record`, the path of its full record.
- `records/<source>-<id>.json`: each advisory's full record as the source served it, opened
  on demand. OSV `versions` lists of up to 50 stay on the index line; a longer one is only
  counted there. NVD configurations keep their AND/OR structure.
- `findings.schema.json`: the JSON Schema of `findings.json`.

The agent writes `findings.json`: only advisories it judges to affect an installed version.
Each finding names its advisory ids or aliases (which must be in `advisories.jsonl`), its
component id (which must be in `inventory.jsonl` and among the components of one of those
advisories), a severity (`critical`, `high`, `medium`, `low`), whether
it is known exploited, a confidence (`confirmed` or `likely`), the evidence, a plain-language
explanation, and a suggested fix (summary, steps and commands, never run during a sweep). The
agent sets severity from the source score and this machine's context and says why when it
differs. When the KEV catalog was read, it decides `known_exploited` in both directions and
the app raises such a finding to at least `high`; without it the agent's value stands.

The app validates strictly (unknown fields, unknown ids, an advisory not fetched for the finding's
component, a repeated advisory and component pair, empty text, control and invisible formatting
characters, and bad enums are errors) and caps what it shows (decided 2026-11-12): at most 500
findings and 500 issues, 4000 bytes of evidence or explanation, 500 bytes per summary or step,
20 steps and 20 commands per fix, and 300 bytes per command; a web address must be ASCII, so a
look-alike letter cannot fake a host. A command is one visible command: printable ASCII, no
run of spaces (which would push a second command out of sight in the confirmation), and no
`;`, `|`, `&`, `<`, `>`, backtick, `$` or `\` (the last two build the others when the line
runs: `eval $'a\x3b b'`), except the documented `. <dir>/nvm.sh && nvm ...`. A command naming
a script (`bash ./x.sh`, or the nvm form's sourced file) still runs what that script holds;
the rule keeps the line's shape visible, not what the programs it names do. It retries once
with the first 50 errors appended to the prompt (the prompt is one argument, under macOS's
1 MiB `ARG_MAX`), the rejected file kept as `findings.rejected.json`; a second
failure marks the target failed. A valid file counts even if the agent then exits non-zero; an
agent that exits non-zero without one is not retried. One sweep runs at a time: it holds a
`flock` on `sweeps/.lock`, which the system releases when the process ends.

Homebrew products for which NVD returns no CVEs are checked against NVD's CPE dictionary (an
unknown answer is asked again after 30 days); a product NVD does not know is reported in the
sweep report, so a wrong guessed name is visible.

### Version pre-match (decided 2026-11-10)

Sweeps run the agent without a shell, so an agent that compared hundreds of ranges by hand
spent 38 minutes on one Mac and 24 on one repository, with context compaction and a real risk
of a wrong match. Version comparison is deterministic, so the app does it (`matching`,
`feeds::cpe`) and the agent only judges applicability: the app narrows input, the agent
decides "affected".

Each advisory and component pair gets one verdict with a short reason:

- `in_range`: the version is in an affected range or listed as affected.
- `unknown`: the version could not be placed with certainty.
- `out_of_range`: every part of the record that names the component puts the version
  outside.

The rule is conservative: anything not read with certainty is `unknown`, never
`out_of_range`, since a false `out_of_range` hides a vulnerability.

- OSV: the schema's evaluation algorithm
  (<https://github.com/ossf/osv-schema/blob/7e336cc6dabe2f414d8e65f1955d1f1aa4b17d39/docs/schema.md#evaluation>)
  over the `affected` entries for the component's ecosystem and name (PyPI names normalized,
  crates.io `-` and `_` alike): `SEMVER` and `ECOSYSTEM` ranges with `introduced` (`0` before
  every version), `fixed`, `last_affected` and `limit`, plus the explicit `versions` list.
  Versions compare as SemVer 2.0 for crates.io, npm, Go (a Go version loses its `v`),
  GitHub Actions and every `SEMVER` range, as PEP 440 for PyPI, and for RubyGems only when
  both sides are plain dotted numbers. `GIT` ranges, unreadable versions or bounds (a manifest range such
  as `^1.2.0`), two events at one version, a range without `introduced`, and a record whose
  entries never name the component are `unknown`. OS packages are queried by version, so
  OSV's answer is `in_range`. In PyPI a local build (`2.0.1+cu118`) is the listed version
  `2.0.1`, as PEP 440's version matching ignores the local label when the listed version has
  none.
- NVD: each CPE match marked vulnerable for the component's product, with the rules in
  `feeds::cpe` (start and end bounds, including or excluding; a version named in the
  criteria; `*` without bounds is every version). A match whose version is `-` (not
  applicable), a negated node, an unparsable record, and a record that never names the
  product are `unknown`; a record that names the product only as not vulnerable (the
  platform) is `out_of_range`. A match in a configuration that ANDs several CPEs keeps its
  verdict, and its reason asks the agent to judge the platform; the app never decides
  platforms. Letters in a version order only as release stages (`dev` < `alpha` < `beta` <
  `pre` < `rc` < `ga`, with their spellings); any other two different words (`1.0.2k` and
  `1.0.2l`) are `unknown`, since alphabetical order put `1.0.RC1` after `1.0.GA` (2026-11-12).

Out-of-range pairs are dropped from each advisory, then advisories left with none, and the
report's `out_of_range` counts those advisories, so none disappears silently. KEV
advisories follow the same rule (owner's decision, 2026-11-10): one is kept only when some
pair is in range or unknown, and whether the catalog could be read changes nothing. Until
then every KEV entry reached the agent; on the Mac 104 of 281 advisories were KEV CVEs for
macOS releases fixed long ago. An advisory linked to no component would be kept, as nothing
shows it out of range, but every fetched advisory comes from a component's lookup. On the
2026-11-10 sweep's bundles this kept 16 of a repository's 341 advisories and 168 of the
Mac's 281, and every one of the 118 findings of that sweep stayed a candidate, in range.

### Feeds

Decided 2026-11-05 after checking the live APIs: OSV already mirrors the GitHub Advisory
Database (GHSA IDs), so there is no separate GHSA client; OSV bulk files are large (npm alone
is 220 MB, mostly `MAL-` reports), so the app queries by name instead of mirroring; Homebrew is
not an OSV ecosystem, so formulae go through NVD.

- OSV: `POST /v1/querybatch` with the inventory's package names (no versions), which returns
  every advisory id and `modified` time for those packages, `MAL-` malicious-package reports
  included. Full records come from `GET /v1/vulns/{id}` and are cached by id; a record is
  fetched again only when its `modified` time changes. OSV sees the package names, and the
  versions only of a server's OS packages (see "Servers").
- NVD: CVE API 2.0 queried per product with `virtualMatchString=cpe:2.3:*:<vendor>:<product>`
  (`*` for a product given without a vendor; `vendor:name` where the bare name is shared), all
  history on the first fetch, then `lastModStartDate`/`lastModEndDate` windows (120-day
  maximum; an older cache is fetched in full again). Requests are paced to the published
  limit: 5 per 30 s without a key, 50 per 30 s with an API key read from the macOS Keychain
  (service `io.github.georgiosdelkos.vigil`, account `nvd-api-key`). A CVE reaches the bundle
  only for the installed versions its CPE matches may cover (`feeds::cpe`, which lists the
  rules, and "Version pre-match"); whatever it cannot tell is kept, a CVE that names the
  product only as not vulnerable (the platform another product runs on) is dropped, KEV or
  not (since 2026-11-10; before, a CVE in KEV was always kept).
- KEV: the full CISA JSON catalog each sweep (about 2 MB); marks advisories whose CVE is
  actively exploited. The catalog must name its `catalogVersion`, list at least 1000
  vulnerabilities (it passed 1000 in 2023) and give each a CVE id, or it is refused like an
  unreachable one: an empty catalog would mark nothing exploited (decided 2026-11-12).
- A failed request uses what is cached (decided 2026-11-12): an OSV record or a product's NVD
  CVEs that cannot be fetched again come from the cache, and the report notes it; only with
  nothing cached does the source count as failed for the target (see "Lifecycle"). A product's
  NVD cache older than a week does not stand in, so an NVD blocked for weeks shows as not
  checked rather than as clear. After NVD
  answers 403 or 429, its rate limit, it is not asked again in that sweep; asking again would
  only extend the refusal. Pacing is per process, so `vigil advisories` takes the sweeps lock
  before it asks NVD, and fails while a sweep runs rather than doubling the rate.
- A product's cached CVEs are used without a request for 2 hours after the last fetch's
  coverage ended, and a product NVD's CPE dictionary does not know, with no cached CVEs, is
  not asked for CVEs for a week. On one Mac a repeated sweep had spent 11 minutes on NVD
  requests that found nothing (decided 2026-11-08).
- `history.since` drops advisories both published and last modified before that date (NVD keeps
  a CVE's original published date when it later adds a product); records without either date
  are kept. NVD rarely leaves an old CVE untouched: all 10294 NVD records in one Mac's bundle
  (2026-11-08) were last modified in 2024 or later, so a `since` date before 2024 drops nothing
  from NVD there.
- Advisory ids and product names come from the network and become cache file names, so they
  are checked against a safe character set first.

### UI (Tauri 2)

- `LSUIElement` (no Dock icon), tray icon states: critical open, high open, clear (no
  critical or high open), sweeping, error.
- Popover panel under the icon, hidden on blur: per-target counts, Sweep now, newest findings.
- Window: finding details (agent explanation, evidence, fix plan + confirm), targets
  (Mac folders, repos, servers), agent picker, schedule, history window, report history.
- Rust <-> UI: Tauri commands call core; sweep progress streams as Tauri events.
- While sweeping, the popover shows a progress bar with one equal share per target. Rust
  measures it (`Progress::thousandths`): listing up to 5% of a target, fetching advisories up
  to 50%, the agent the rest. The agent's run has no known length, so that part of the bar
  moves instead of filling, and the step shows how long it has run (decided 2026-11-08).
- One typeface for all text, IBM Plex Sans (chosen 2026-11-10 over Sora, Geist and Chakra
  Petch), code and counts included: IBM's unmodified web fonts, bundled in `app/ui/src/fonts`
  so the app and the report look the same offline. The licence ships beside them in the build
  (`app/ui/public/fonts/OFL.txt`), and the report's font CSS opens with the copyright notice.
- Plugins: notification, autostart, positioner (versions looked up at implementation time),
  and the updater ("Updates" below).
- Scheduler: in-app interval timer; skip if a sweep is running; run once on wake if overdue.

Built in step 9a (2026-11-06):

- Settings were first only shown, with "Edit settings" opening `config.toml`; step 9b edits
  them in the popover. The config is read again on every refresh.
- The tray icon is the mark: grey inner streaks with red outer ones (a critical finding open),
  orange (a high one open, no critical), or green (only medium or low open, or nothing); all
  cyan (sweeping or fixing, with the tooltip "Vigil: sweeping" or "Vigil: fixing"); and with
  one arm missing, in the bar's own colour (the last sweep stopped, a target got no verdict,
  a target's newest sweep had a source fail or its files cannot be read, or the schedule could
  not be checked, and nothing critical or high is open). A target with a failed source or an
  unreadable file is never "All clear" (decided 2026-11-12): the headline reads "Not fully
  checked" when nothing is open, an amber banner names each such target and what failed, its
  row says "not fully checked", and the main view's vortex is not green. A failure never hides an open critical or high (the
  owner's rule, clarified 2026-11-11): the icon stays red or orange, and the tooltip ("Vigil:
  critical findings open; something failed, open Vigil to see it") and the popover's banner show the failure.
  Medium and low no longer colour the icon and stay
  visible in the popover (the owner's decision, 2026-11-11, replacing blue, yellow and pink for
  low, medium, and critical and high, and the uncoloured icon for nothing open). Red, orange
  and green are the app's `--critical`, `--high` and `--ok`. The coloured icons come in two
  palettes switched with the menu bar's appearance (decided 2026-11-09): bright on a dark
  bar, the same hues deepened to 3:1 contrast on a light one.
- A left click on the icon shows or hides the popover; a right click opens a menu with only
  Quit Vigil (asked for 2026-11-09), which quits as the popover's Quit does.
- The popover (the app's one window, hidden on blur) shows the status, each target's open
  counts by severity, the six most severe open findings with their keys and fixes on hover, a
  Fixed tab with the fixes reported and waiting for the next sweep, then the confirmed fixes
  that finished in the last 30 days,
  Sweep now, Edit settings, Launch at login (the autostart plugin's LaunchAgent) and Quit. It
  asks the app for an overview whenever it is shown and on every `changed` event.
- One sweep at a time: the app checks and claims "sweeping" under one lock, and the core's
  sweeps lock still covers a CLI sweep, which then shows as a failed sweep.
- Cancel and quit (decided 2026-11-08): the popover's Cancel stops a sweep between targets,
  between NVD requests, or while its agent runs; the targets already swept keep their reports
  and the folder of the one it stopped in is removed. A fix cannot be cancelled from the
  popover, since one stopped halfway could leave a change half made. Quitting the app cancels
  whatever runs (a fix included, recorded as `unknown`: it may have made part of the change)
  and exits once it has ended, or after 10 s; a second quit changes nothing. In the CLI,
  Ctrl-C cancels the same way (exit code 130); a second Ctrl-C exits at once.
- While a fix runs, the popover lists its steps (preparing the fix, the agent applying it,
  recording the result) as done, now or next, as Rust reports them (`FixProgress`), with how
  long the current one has run, where the fix runs, and no Cancel button. Almost all of a fix
  is the agent's step, which has no known length, so there is no bar (decided 2026-11-08).
- Fix results (the owner's decision, 2026-11-11, after a Fix all of 9 items ended in one red
  banner at the top that ran every item's summary together): when a fix or Fix all ends, its
  view stays until the user closes it, never as a banner at the top.
  - One row per item, in the order they ran, with its final state: a green check for fixed,
    amber for partial, red for failed, grey for no result, and Rust's word for it ("fixed",
    "partial", "failed", "no result"). A `fixed` report counts only with exit code 0, as
    everywhere else, so one without it reads "no result". A single fix's row is named by its
    finding's title, a Fix all item's as its step was ("curl 8.1.2").
  - Details on a row opens the agent's summary for it (why it is partial or failed, or what it
    did), and a repository fix's pull request: plain wrapped text, shown and never acted on.
  - Show log shows the end of the run's `agent.log`, its last 64 KiB from a whole line, in a
    scrollable monospace block (the one place not in IBM Plex Sans: the owner asked for
    monospace), each line plain. The run read it before it deleted its folder, and the app
    keeps it in memory in the core's `FixRun` (`FixRun::log_tail`), never a path from the UI.
    A missing or unreadable log says so.
  - At the bottom, one line from Rust: "5 of 9 fixed · 4 partial" (then failed, then "with no
    result", each only when there are any).
  - Close, or Escape, returns to where the fix was started: the target's screen or the
    finding's detail (the list, when the finding is no longer open).
  - The results are a status of the app's runner (`Fixed`, after `Fixing`), made from the
    records the run appended to `state/fixes.jsonl` and kept in memory: they survive the
    popover hiding and showing, not a restart. A new sweep or fix replaces them; the minute's
    schedule check does not write a failure over them. A fix that ends without records leaves
    the app's failed status, "Last fix: ..." in the failure banner, kept in Rust so a popover
    opened later still shows it: one refused before anything ran (the lock held by the CLI, a
    sweep that landed under the lock), or, rarely, one whose records could not be appended
    after the agent ran, which may have changed the target. Rust words the whole banner line
    ("Last sweep: ..." or "Last fix: ...").
- Every program a sweep or fix starts (the agent, `brew`, `gh`, `ssh`) runs under a small `sh`
  watchdog that leads its own process group and checks once a second that the app or CLI
  still runs. However that ends (quit, logout, `kill`, a crash, a closed terminal), the
  watchdog stops the group: `SIGTERM`, then `SIGKILL` after 3 s. A cancel also stops every
  descendant of the agent, including one that left its group (`setsid`); after a crash such a
  descendant is the one thing that can outlive the app. A sweep folder holds a `.running`
  marker while its sweep runs; at the next start, and before every sweep, the unfinished
  target folders of a sweep that never ended are removed.
- The schedule is checked every minute (`Schedule::due` against the newest sweep folder's
  start, failed ones included, so a failing sweep is not retried at once); a Mac that wakes
  after a missed sweep runs it within a minute.
- A sweep that finds new, open, critical or high findings or issues raises one notification
  listing up to three of them (`alerts`; on a target's first sweep with a verdict every such
  one is new, and when its last report cannot be read none is, so nothing is notified twice).
  It counts as the popover does: one line per component, with how many such advisories it
  has, and one per issue.
- A tray click within 300 ms of the popover hiding on blur leaves it hidden: clicking the icon
  first takes focus from the open popover, then delivers the click.
- Accepted: the "last sweep failed" icon is kept in memory, so after the app restarts the
  icon shows the open findings until the next sweep.
- Licenses: Tauri brings in MPL-2.0 crates (cssparser, selectors and others); MPL-2.0 was
  allowed for all crates by the owner on 2026-11-06. `cargo deny` checks only the macOS
  targets, so GTK and D-Bus crates (Linux only, with open advisories) are left out.
- CI: `app.yml` builds the UI and then lints and tests the app crate in the release
  configuration (`--features custom-protocol`, which embeds the built UI); it is not a
  default workspace member, and cargo-mutants skips it. Its decisions live in the core
  (`Schedule::due`, `alerts`, `last_sweep_started`), where they are mutation-tested.
- The schedule also counts when the app last started a sweep, so one that fails before it
  writes its folder (no agent chosen, a CLI sweep running) is not retried every minute; a
  sweep that panics leaves a failed status, not a stuck "sweeping".
- Run it: `cargo tauri dev` from `app/src-tauri` (starts the UI dev server), or `cargo tauri
  build` for `Vigil.app`.

Built in step 9b (2026-11-06):

- Settings live inside the popover (a section list with Back, sized to the popover) and are
  saved into `config.toml` through `toml_edit`, so its comments stay. A missing config is the
  default one; the first change writes it. Each change is one `Setting` (add or remove a
  folder, repository or server; set the agent, schedule or history) checked like a loaded
  config before it is written.
- Every value the UI shows is worked out in Rust (owner's rule, 2026-11-06): the core's
  `popover_view` groups findings by component, ranks the items (exploited, then severity, then newest), counts them, lists the confirmed fixes
  newest first, writes the headline and the target lines; `settings_view` writes each section's summary, the
  choices and which are chosen, folders as `~/...`, and whether a host can be added. The UI
  lays these out and sends `Setting`s; the only formatting left in TypeScript is "5 min ago",
  which follows the popover's clock.
- Detection (agents and tools on the login shell's `PATH`, the gh login and repositories,
  `~/.ssh/config` hosts, project folders, the Keychain key) takes about two seconds, so it
  runs once as the app starts and again only on "Look again". A change returns the new view
  at once instead of detecting again.
- Each detection also sets the `PATH` every tool and agent then runs with, so a tool found
  by "Look again" is the one the next sweep runs. Until the first detection at start ends,
  tools run with macOS's minimal `PATH` (accepted: a sweep that early is rare).
- Saves take an exclusive lock on `.config.toml.lock`, so two at once (quick clicks; any
  other process that saves later) both land. A key written another way than a change expects (an inline
  table, `repos = "o/r"`) is refused with what to change, never replaced.
- A confirmed fix or Fix all carries the preview's number, and the app runs the plan it kept
  for that preview (see "Fix flow"); the core refuses it when a sweep, fix or dismissal changed
  the finding since. The confirm shows the summary, the steps, the commands that will run and
  Rust's notes.
- The NVD key is saved with `/usr/bin/security -i`, the command on stdin, so the program
  that reads it before each sweep is the one that created it and is trusted without a
  prompt. Accepted: a key saved by an earlier build through Security.framework may prompt
  once; "Always Allow" or saving it again fixes that.
- The popover stays open while detection or the folder picker runs: macOS asks for Documents
  or Keychain access then, and the prompt would take the focus and hide it.
- Tests: the views and changes have Rust unit tests in the core (mutation-tested in CI); the
  popover and settings have component tests (Vitest, jsdom, `@solidjs/testing-library`) with
  the Tauri commands mocked, checking that each control sends the right command and shows
  what Rust returns.

HTML report (asked for 2026-11-09: "click on a button and get that opened on the browser
with all the details", dark, not white):

- `write_html_report` writes `report.html` in the data directory, replacing the last one, and
  the app's `open_report` command writes it and opens it with `/usr/bin/open`; the popover's
  button that calls it comes with the popover's new main view, built separately. It renders `latest` through `popover_view`, so it shows what `vigil
  findings` and the popover show: the headline, the key numbers (need you, exploited, open,
  fixed in 30 days, dismissed), a callout for each item with a finding exploited in the wild,
  naming those advisories, with the command to run first, the open items under "Needs you"
  (exploited, critical or high) and "Lower". A finding or issue alone expands to its
  explanation, advisories (or, for an issue, its subject), installed version, place,
  confidence, first seen, fix status, key, the agent's evidence, the fix's summary, steps and
  commands with Copy buttons. A component with several findings is one card (2026-11-10):
  how many advisories, what is installed where, its one fix shown once with what it covers,
  then each advisory collapsed, with its own severity, explanation, evidence and key (and its
  own fix summary when it differs from the lead's); then a table of targets and one of the fixes
  confirmed in the last 30 days, and the sources. Times are in UTC. Agent text is shown as
  one plain line, as everywhere else (line breaks become spaces). Writers take `state/.lock`,
  so the CLI and the app never write it at once.
- Dark only, after the approved mockup: the night ground with faint violet and cyan light,
  glass panels, neon severity colours, and IBM Plex Sans, the app's one typeface.
- One file that loads nothing: inline CSS, the font inlined as data (about 155 kB), an inline
  SVG mark, and one inline script for the Copy buttons. Its Content Security Policy allows no
  request, only inline fonts, and only that script, by hash.
- Every text is HTML-escaped: it holds agent text and names from the target. Advisory ids
  link only to NVD (CVE ids) or OSV.dev (other ids), and only when the id has a strict
  shape; anything else, the agent's pull request URLs included, is plain text.

### Updates (decided 2026-11-12)

The owner's decisions, and why:

- **Mechanism: Tauri's official updater plugin** (`tauri-plugin-updater` 2), with its mandatory
  minisign signature check. The public key is `plugins.updater.pubkey` in `tauri.conf.json`;
  the private key and its password live only in the GitHub Environment `release`. The endpoint
  is `https://github.com/GeorgiosDelkos/vigil/releases/latest/download/latest.json`, HTTPS only.
  `requireSignedVersion` is on: the signature must also name the version `latest.json`
  announces, so an older signed release cannot be passed off as a newer one (nothing was
  released before, so no old signature lacks the version).
- **When:** at launch and every 12 hours while the app runs, measured on the wall clock (the
  check thread wakes every 10 minutes), so time asleep counts. A failed check is retried after
  an hour (a Mac launching Vigil at login is often not online yet). The check and the download
  each time out after 5 minutes: the plugin sets no timeout by default, and one stalled request
  would stop every later check.
- **Download in the background, install on the user's click.** A newer version is downloaded
  and verified at once, then waits in memory. The popover shows "Update ready: Vigil x.y.z" with
  Restart to update, and one notification says so. The click installs it (the plugin replaces
  the bundle on disk) and restarts. It never installs or restarts while a sweep or fix runs: the
  button waits, and Rust refuses it under the runner's lock in the same step that checks its
  status, then marks it installing: nothing new starts, no check runs, and an exit request
  that reaches the app (Cmd-Q) is held and the tray's Quit does nothing, so neither can land between the plugin
  moving the old app out and the new one in. A logout or `kill` does not ask first, as for
  sweeps; the plugin swaps the two bundles in one step where the file system allows (APFS). Only then does the restart's exit pass. An install that fails keeps the update
  waiting. A Quit clicked during the install is dropped (accepted: it lasts a moment).
- **Failures are quiet.** Offline, GitHub down or a bad signature leave one line under Settings
  ("the last update check failed: ...") and one on stderr. They never set the runner's failed
  status, so no banner, no tray change, and never a held-up sweep.
- **State:** `update::Updates` lives in the runner's shared state (`Runner`), like the status,
  not in a global: last check time, last problem, the waiting package.
- **Only installed releases check.** A debug build, `cargo tauri dev`, and a release binary
  run from `target/` never check: the plugin installs over the executable's folder unless it
  is a bundle's `Contents/MacOS`, so the app checks only when it runs from `<name>.app`. An app
  bundle built from source with `cargo tauri build` does check, and is offered official
  releases. No on/off switch (simplicity); Settings shows the version and the last check.
- **The webview has no updater permission.** Checking, downloading and installing run in Rust;
  the UI calls only the app's `restart_to_update` command. `updater:default` is not in the
  capabilities.
- **Versioning:** one version, `[workspace.package] version` in the root `Cargo.toml`, which
  every crate inherits. `tauri.conf.json` has no `version`, so Tauri takes the app crate's.
- **Releases** (`.github/workflows/release.yml`): pushing a tag `v*` runs one macOS job in the
  `release` environment (the owner approves each run). It fails unless the tag is `v` plus the
  Cargo version, builds a universal app (Apple Silicon and Intel in one binary, so one download
  and one `latest.json` entry serve every Mac) with `tauri-apps/tauri-action` and the CLI from
  `app/ui`'s lockfile, signs it with the owner's Developer ID and notarizes it (Tauri's Apple
  variables), notarizes and staples the `.dmg`, and signs the updater package with the updater
  key. It then checks the signature, team, hardened runtime, notarization and staple of the app
  and of the app inside the updater package, both architectures, and the updater signature with
  the committed public key and the signed version (`examples/verify_update.rs`, using
  `minisign-verify` as the plugin does), and only then publishes the draft release. A
  workflow_dispatch run is a dry run with no release. The pattern follows
  ourovoros-io/oikonomia's release workflow.
- **Local builds need no key:** the updater artifacts and the `.dmg` are added by
  `tauri.release.conf.json`, which only the workflow passes, so `cargo tauri build` keeps
  working without `TAURI_SIGNING_PRIVATE_KEY`.

### CLI

`vigil sweep [--target <id>]`, `findings [--json]`, `report [--open]`,
`dismiss <key> --reason <text>`, `undismiss <key>`, `fix <key> [--yes]` (shows the fix and
asks to confirm), `fix all <target> [--yes]` (every fixable item of a target in one run;
see "Fix all"). Same core, same files.

- `sweep --target` takes a report name (`mac`, `github:<owner>/<name>`, `server:<name>`) of a
  configured target and sweeps only it; an unknown name fails before anything runs.
- `findings` lists, per configured target in sweep order, the open findings and issues of its
  newest report with a verdict: severity, key, title (the advisories, component, version and
  where it was found; or the issue's subject) and the fix summary, plus how many are
  dismissed. Dismissed means dismissed in `state/dismissals.json` now, as `fix` checks it, so a
  `dismiss` shows at once. Since 2026-11-10 it groups as the popover does and counts items:
  a component with several findings is one line (worst severity, name, version, place, how
  many advisories) with its one fix, then a line per finding with its severity, key and
  advisories; a lone finding or an issue keeps its one line. Titles and summaries are printed
  as plain lines (control and
  invisible characters replaced), since they hold agent text and names from the target.
  `--json` prints one object per target (`target`, `swept`, `components`, `open`, `fixed`,
  `dismissed`), still one `open` entry per finding; an open entry also has its `confidence`
  (null for an issue), `evidence`, fix `steps` and `component` (its key and name, null for
  an issue), and its `fix_state` is null or `reported` (with `summary` and
  `pull_request`) or `not_held`. Each report
  entry carries that `title`, so the tray app shows the same line. `--target` matches the
  report name exactly.
- `report` writes the HTML report (see UI) to `report.html` in the data directory and prints
  its path; `--open` also opens it in the default browser.

## Risks to keep visible

- Prompt injection: advisory text and repo/server content are untrusted. Sweeps run
  restricted and prompts mark the bundle data as untrusted; fixes have full access, gated by
  per-fix confirmation. The report escapes agent text, so it cannot forge Markdown or send
  terminal escapes.
- Sweep runs have no timeout and no transcript (user's choice). `agent-<attempt>.log` captures
  stdout and stderr only.
- Agent cost: sequential per-target runs; feed pre-filtering keeps context small.

## Implementation order

Each step is a feature branch + draft PR with a fresh-context review per the global rules.
Load `rust-style` (plus the async/concurrency topic files), `ts-style`, and `gh-actions-style`
before the first edit in each area; look up current crate versions (tauri, tokio, serde,
toml, reqwest, clap, zip) before adding them.

1. Workspace skeleton, lints, deny.toml, CI, `config` + `paths`.
2. Feeds: OSV query + record cache, NVD per-product cache, KEV, and an `advisories` CLI command.
3. Mac inventory collectors and an `inventory` CLI command.
4. Agent adapters + detection + sweep for the Mac target + findings schema/validation + report,
   and the `sweep` CLI command.
5. GitHub target (deps, alerts, workflows, settings via `gh`).
6. Server target (two-phase agent run).
7. Lifecycle: dismissals and changes (PR 8); fix confirm/exec and fix history (PR 9).
   Done when both merge.
8. CLI: `findings` and `sweep --target` (PR 10); `dismiss`, `undismiss` and `fix` came with
   step 7.
9. Tauri app: tray, popover, notifications, autostart, scheduler (PR 11, 9a); finding details
   and fix confirmation in a window (9b).
10. Later: signing + notarization in CI once an Apple Developer account is available.

## Verification

- Unit tests per module with fixture files (feed records, `brew info --json`, lockfiles, `gh`
  API responses).
- Property tests for config round-trip, feed parsing, and the name-index pre-filter.
- Fake agent: a test script on `PATH` that writes canned `findings.json` (valid, invalid,
  missing) to exercise the sweep, retry, and failure paths without a real agent.
- `cargo-mutants` over core logic; kill or explain survivors.
- End to end: `vigil sweep` against this Mac with a real agent and a test repo;
  then `cargo tauri dev`, run a sweep from the tray, confirm icon state, notification,
  report files, and a fix plan + apply on a deliberately outdated Homebrew formula.
- Zero warnings: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, oxlint/tsc.
