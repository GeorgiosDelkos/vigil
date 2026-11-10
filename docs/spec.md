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
| Pre-filter | App keeps advisories whose package name is in the inventory, plus OS/kernel and all KEV entries. An NVD CVE not in KEV is also dropped when its CPE matches show it cannot affect the installed version, or name the product only as the platform another product runs on; a CVE for software outside the inventory then no longer reaches the agent through macOS (decided 2026-11-08: one Mac's bundle went from 10304 advisories to 267, 104 of them in KEV). Since 2026-11-10 the same rule covers OSV: Vigil compares versions itself (see "Version pre-match") and drops every advisory not in KEV whose components are all out of range; the agent judges applicability |
| Agents | Auto-detect claude, grok, codex, gemini, opencode; user picks one default |
| Agent permissions | Sweeps restricted: read anything, write only `findings.json`, read-only listing commands. Fixes get full access, only after the user confirms (decided 2026-11-05) |
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
- `fix`: plan, confirm, execute, history.
- `report`: JSON + Markdown writers.

### Data layout

```
~/Library/Application Support/io.github.georgiosdelkos.vigil/
  config.toml
  report.html (the HTML report, replaced each time it is asked for)
  prompts/{sweep,sweep-github,sweep-server,fix}.md
  feeds/osv/<id>.json, feeds/nvd/<product>.json
  state/.lock, state/dismissals.json, state/fixes.jsonl
  sweeps/.lock
  fixes/<utc-timestamp>-<key>/{PROMPT.md, fix.json, result.schema.json, agent.log, result.json}
  sweeps/<utc-timestamp>[-n]/<target>/{bundle/, agent-1.log, agent-2.log, report.json, report.md}
    (<target> is `mac`, `github-<owner>--<name>` or `server-<name>`)
```

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
  first with a verdict. A report without a verdict has none, and a report that cannot be read
  is a note. Accepted
  downside: a source that fails (OSV offline) makes its findings show as resolved; the report
  lists the failed source under "Not checked".
- Fixes: the fix in the sweep's finding is the plan the user confirms; there is no
  separate planning run. A confirmed fix is one agent run with full access and the `fix`
  prompt. A GitHub fix works in a fresh clone, on a new branch, and opens a pull request; a
  server fix may run ssh to that one server, with the sweep's ssh options. Each fix is appended
  to `state/fixes.jsonl`.
- Fixed (decided 2026-11-08 with the user): a fix the agent reports does not hide the
  finding on its word. A finding whose last fix run ended `fixed` with exit code 0, planned
  from the report the finding is in, stays open and counted, marked "Fix reported", or "Pull
  request open" when the run opened one (it lands once merged). A later sweep that still
  finds it marks it "Still found after a fix". Once a later sweep no longer finds it, the fix
  is confirmed and listed under Fixed, with the finding's title, the agent's summary and the
  pull request, for 30 days. Which report a run fixes is decided by the sweep it was planned
  from (`found` in the record), never by comparing clocks; the last run of a key in
  `state/fixes.jsonl` decides, in file order. `vigil findings` shows the same.

### Mac inventory

Decided 2026-11-05. Each source is collected on its own; a failing one is reported and the
rest still count. A tool that is not installed is skipped, not an error.

| Source | Command or file | Looked up as |
|---|---|---|
| macOS | `sw_vers -productVersion` | NVD product `apple:macos` |
| Homebrew formulae and casks, dependencies included | `brew info --json=v2 --installed` | NVD product: name without `@version`, through a small alias table checked against NVD (`node` -> `node.js`, `gh` -> `github:cli`); a name that is not a valid product is reported |
| Rust toolchains | `rustup toolchain list`, `rustup run <toolchain> rustc --version` | NVD product `rust` |
| Cargo-installed binaries | `cargo install --list` | OSV `crates.io` |
| Node.js | `node --version` | NVD product `node.js` |
| Global npm packages | `npm ls -g --json --depth=0` | OSV `npm` |
| Python | `python3 --version` | NVD product `python` |
| Node.js and Python versions kept by version managers | the version folders: nvm `versions/node/v*` under `$NVM_DIR`, else under both `$XDG_CONFIG_HOME/nvm` and `~/.nvm`, fnm `node-versions/v*` under `$FNM_DIR`, else under each of `$XDG_DATA_HOME/fnm` (`~/.local/share/fnm`), `~/.fnm`, `~/Library/Application Support/fnm`, Volta `$VOLTA_HOME/tools/image/node/*` (`~/.volta`), asdf `$ASDF_DATA_DIR/installs/{nodejs,python}/*` (`~/.asdf`), pyenv `$PYENV_ROOT/versions/*` (`~/.pyenv`) | NVD product `node.js` or `python` |
| uv and pipx tools | `uv tool list`, `pipx list --json` | OSV `PyPI` |
| Project lockfiles under `mac.project_dirs` | `Cargo.lock`, `package-lock.json` and `npm-shrinkwrap.json` (v2/v3), `uv.lock`, `poetry.lock` | OSV by ecosystem |

The folder walk skips `node_modules`, `target`, `.git`, `vendor`, `.venv`, `dist`, `build` and
every hidden folder, follows no symlinks, and only reads lockfiles: it never runs project code.
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
versions are two findings and removing one keeps the other's key. When the `node` or `python3`
on `PATH` has the same product and version as a manager's entry it is reported once, as the
manager's: that names the tool that removes it, and its key does not change with `PATH`. A
separate install at the same version is then reported only after the manager's copy is gone.
Such a `PATH` finding's key changes once, from `node` to the manager's folder, so a dismissal
of it made before this change no longer matches and the finding is shown again.
The sweep's fix for such a version removes it with the manager (`nvm uninstall 22.22.2`,
after sourcing `nvm.sh`; Volta has no command for it, so its folder goes to the Trash), installing a fixed version
first if none is installed and moving the default off it; switching the default alone is not
a fix.

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
`known_hosts`, which a sweep never updates), agent, X11 and port forwarding off, and no
connection sharing. The marker and the folders travel on stdin, not on the server's process
list. The Mac reads at most 256 MiB of the answer and decodes each part on its own.

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
   unknown or out of range. Out-of-range pairs are dropped unless the advisory is in KEV, then
   advisories left with none; the report counts those as `out_of_range`.
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
  fix runs (for a server, the exact ssh command) and when the sweep found it. A summary is
  shown on one line, so it cannot pass for a command. Not confirming exits non-zero.
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
  only).
- Where to work: this Mac; for a repository, a clone in the fix folder, a branch
  `vigil/fix-<key>`, and a pull request (never a push to the default branch); for a
  server, every command through `ssh` with the sweep's options to that one host, carried to the
  server's `sh -s` in a quoted heredoc, so a quote in a command cannot end the ssh line and run
  the rest on the Mac. Accepted risk: a repository fix lets the full-access agent read the
  clone, which may hold agent instruction files; the repositories are the user's own, and the
  agent's project settings and hooks come from its working folder, the fix folder.
- `state/fixes.jsonl` gets one line per run: key, target, agent, start and end, exit code,
  outcome (`unknown` when `result.json` is missing or invalid or the agent did not start, with
  why), summary, pull request, how it was confirmed (`asked` or `yes_flag`), folder. Appends
  take `state/.lock`; a last line cut short by a crash is ended first. The CLI exits non-zero
  unless the outcome is `fixed` and the agent exited 0.
- A fix holds `sweeps/.lock`, so no sweep or other fix runs while it changes the target.

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
`findings.json`, and run only listing commands (`brew info`, `brew list`, `npm ls`, `npm view`)
where the CLI can allow commands one by one. `cargo tree` is not one: it can write `Cargo.lock`
and runs the `rustc` a project's `.cargo/config.toml` names. Fixes (step 7) get full access, and
only after the user confirms the plan. Flags, checked 2026-11-05 against each CLI's `--help` and
docs; every agent runs with the bundle folder as its working directory:

| Agent | Sweep call | Verified on this Mac |
|---|---|---|
| `claude` | `claude -p <prompt> --permission-mode dontAsk --allowedTools Read(//**) Edit(./findings.json) Bash(brew info *) ...` | yes: writes `findings.json`, cannot write elsewhere |
| `grok` | `grok -p <prompt> --permission-mode default --allow Read(//**) --allow Edit(./findings.json) --deny Bash --cwd <bundle>` | yes, same check |
| `codex` | `codex exec --sandbox workspace-write --skip-git-repo-check -C <bundle> <prompt>` | no: not installed (from its source at `openai/codex@49f0c60`) |
| `gemini` | `gemini -p <prompt> --approval-mode auto_edit --skip-trust` | no: the free tier is refused (`IneligibleTierError`) |
| `opencode` | `opencode run --dir <bundle> <prompt>`, permissions in `OPENCODE_CONFIG_CONTENT` | no: the local model timed out |

`auto_edit` (gemini) and `workspace-write` (codex) allow edits anywhere in the bundle, not only
`findings.json`; the bundle is the app's own copy, so that is accepted.

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
characters, and bad enums are errors) and retries once with
the errors appended to the prompt, the rejected file kept as `findings.rejected.json`; a second
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
  Versions compare as SemVer 2.0 for crates.io, npm and every `SEMVER` range (a Go version
  loses its `v`), as PEP 440 for PyPI, and in other ecosystems only when both sides are
  plain dotted numbers. `GIT` ranges, unreadable versions or bounds (a manifest range such
  as `^1.2.0`), two events at one version, a range without `introduced`, and a record whose
  entries never name the component are `unknown`. OS packages are queried by version, so
  OSV's answer is `in_range`.
- NVD: each CPE match marked vulnerable for the component's product, with the rules in
  `feeds::cpe` (start and end bounds, including or excluding; a version named in the
  criteria; `*` without bounds is every version). A match whose version is `-` (not
  applicable), a negated node, an unparsable record, and a record that never names the
  product are `unknown`; a record that names the product only as not vulnerable (the
  platform) is `out_of_range`. A match in a configuration that ANDs several CPEs keeps its
  verdict, and its reason asks the agent to judge the platform; the app never decides
  platforms.

Out-of-range pairs are dropped from each advisory, then advisories left with none, and the
report's `out_of_range` counts those advisories, so none disappears silently. An advisory in
KEV keeps every pair, out-of-range ones included, as does every advisory when the catalog
could not be read (the pre-filter decision: every KEV entry reaches the agent). On the
2026-11-10 sweep's bundles this kept 17 of a repository's 341 advisories and 271 of the
Mac's 281 (104 of them in KEV and wholly out of range), and every one of the 118 findings
of that sweep stayed a candidate, in range.

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
  product only as not vulnerable (the platform another product runs on) is dropped, and a
  CVE in KEV is always kept; when the KEV catalog cannot be read, no CVE is filtered.
- KEV: the full CISA JSON catalog each sweep (about 2 MB); marks advisories whose CVE is
  actively exploited.
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

- `LSUIElement` (no Dock icon), tray icon states: idle-clean, findings (by worst severity),
  sweeping, error.
- Popover panel under the icon, hidden on blur: per-target counts, Sweep now, newest findings.
- Window: finding details (agent explanation, evidence, fix plan + confirm), targets
  (Mac folders, repos, servers), agent picker, schedule, history window, report history.
- Rust <-> UI: Tauri commands call core; sweep progress streams as Tauri events.
- While sweeping, the popover shows a progress bar with one equal share per target. Rust
  measures it (`Progress::thousandths`): listing up to 5% of a target, fetching advisories up
  to 50%, the agent the rest. The agent's run has no known length, so that part of the bar
  moves instead of filling, and the step shows how long it has run (decided 2026-11-08).
- Plugins: notification, autostart, positioner (versions looked up at implementation time).
- Scheduler: in-app interval timer; skip if a sweep is running; run once on wake if overdue.

Built in step 9a (2026-11-06):

- Settings were first only shown, with "Edit settings" opening `config.toml`; step 9b edits
  them in the popover. The config is read again on every refresh.
- The tray icon is the mark: in the menu bar's own colour (nothing open); grey inner streaks
  with blue, yellow or pink outer ones (worst open severity: low, medium, or critical and
  high); all cyan (sweeping); and with one arm missing, in the bar's colour (the last sweep
  failed or a target got no verdict). The coloured icons come in two palettes switched with the
  menu bar's appearance (decided 2026-11-09): neon on a dark bar, the same hues deepened to 3:1
  contrast on a light one.
- A left click on the icon shows or hides the popover; a right click opens a menu with only
  Quit Vigil (asked for 2026-11-09), which quits as the popover's Quit does.
- The popover (the app's one window, hidden on blur) shows the status, each target's open
  counts by severity, the six most severe open findings with their keys and fixes on hover, a
  Fixed tab with the confirmed fixes that finished in the last 30 days,
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
  `popover_view` ranks findings (exploited, then severity, then newest), counts them, lists the confirmed fixes
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
- A confirmed fix carries the preview's `found`; the app refuses it when a newer sweep
  changed the finding, and the confirm shows the commands that will run.
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
  fixed in 30 days, dismissed), a callout for each finding exploited in the wild with the
  command to run first, the open findings and issues under "Needs you" (exploited, critical
  or high) and "Lower", each expanding to its explanation, advisories (or, for an issue, its
  subject), installed version, place, confidence, first seen, fix status, key, the agent's evidence, the fix's summary,
  steps and commands with Copy buttons; then a table of targets and one of the fixes
  confirmed in the last 30 days, and the sources. Times are in UTC. Agent text is shown as
  one plain line, as everywhere else (line breaks become spaces). Writers take `state/.lock`,
  so the CLI and the app never write it at once.
- Dark only, after the approved mockup: the night ground with faint violet and cyan light,
  glass panels, neon severity colours, system fonts.
- One file that loads nothing: inline CSS, an inline SVG mark, and one inline script for the
  Copy buttons. Its Content Security Policy allows no request and only that script, by hash.
- Every text is HTML-escaped: it holds agent text and names from the target. Advisory ids
  link only to NVD (CVE ids) or OSV.dev (other ids), and only when the id has a strict
  shape; anything else, the agent's pull request URLs included, is plain text.

### CLI

`vigil sweep [--target <id>]`, `findings [--json]`, `report [--open]`,
`dismiss <key> --reason <text>`, `undismiss <key>`, `fix <key> [--yes]` (shows the fix and
asks to confirm). Same core, same files.

- `sweep --target` takes a report name (`mac`, `github:<owner>/<name>`, `server:<name>`) of a
  configured target and sweeps only it; an unknown name fails before anything runs.
- `findings` lists, per configured target in sweep order, the open findings and issues of its
  newest report with a verdict: severity, key, title (the advisories, component, version and
  where it was found; or the issue's subject) and the fix summary, plus how many are
  dismissed. Dismissed means dismissed in `state/dismissals.json` now, as `fix` checks it, so a
  `dismiss` shows at once. Titles and summaries are printed as plain lines (control and
  invisible characters replaced), since they hold agent text and names from the target.
  `--json` prints one object per target (`target`, `swept`, `components`, `open`, `fixed`,
  `dismissed`); an open entry also has its `confidence` (null for an issue), `evidence` and
  fix `steps`, and its `fix_state` is null or `reported` (with `summary` and
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
