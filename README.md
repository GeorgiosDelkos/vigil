<div align="center">

<img src="docs/images/logo.png" width="112" alt="Vigil's mark: a spiral arm of dots">

# Vigil

**Know which new vulnerabilities affect your Mac, your repositories and your servers,
and fix them with one confirmed click.**

[![test](https://github.com/GeorgiosDelkos/vigil/actions/workflows/test.yml/badge.svg)](https://github.com/GeorgiosDelkos/vigil/actions/workflows/test.yml) [![check](https://github.com/GeorgiosDelkos/vigil/actions/workflows/check.yml/badge.svg)](https://github.com/GeorgiosDelkos/vigil/actions/workflows/check.yml) [![app](https://github.com/GeorgiosDelkos/vigil/actions/workflows/app.yml/badge.svg)](https://github.com/GeorgiosDelkos/vigil/actions/workflows/app.yml) ![macOS](https://img.shields.io/badge/platform-macOS-1f2430) ![Rust](https://img.shields.io/badge/Rust-1.99-1f2430?logo=rust) ![Tauri](https://img.shields.io/badge/Tauri-2-1f2430?logo=tauri)

</div>

<p align="center">
  <img src="docs/images/hero.png" alt="Vigil's popover: four findings that need attention, the confirmation of a Homebrew fix, and that fix running" width="100%">
</p>

New CVEs land every day, in every stack you run. Vigil is a macOS menu-bar app that pulls the
newest advisories, works out which of them could touch the software you actually have
installed, and asks a coding agent of your choice (Claude Code, Grok, Codex, Gemini or
opencode) to judge whether each one really affects you. What does shows up in the menu bar
with its severity, the evidence and an exact fix. You approve a fix, and the agent applies it.

It sweeps three kinds of target in one pass:

| Target | What Vigil reads |
|---|---|
| **This Mac** | macOS, Homebrew formulae and casks, Rust, Node.js and Python toolchains, global npm, cargo, uv and pipx packages, and the lockfiles in the project folders you choose |
| **GitHub repositories** | The dependency graph, Dependabot, code scanning and secret scanning alerts, Actions workflows, and security settings such as branch protection |
| **Servers** | OS packages (Debian, Ubuntu, Alpine), the kernel, listening sockets, Docker containers and images, and lockfiles, read over SSH by a fixed read-only script |

## Contents

- [Highlights](#highlights)
- [Screenshots](#screenshots)
- [How a sweep works](#how-a-sweep-works)
- [Safety model](#safety-model)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Command line](#command-line)
- [Advisory sources](#advisory-sources)
- [Supported agents](#supported-agents)
- [Project layout](#project-layout)
- [Development](#development)
- [Status](#status)

## Highlights

- **Only what applies to you.** The app narrows the advisory feeds to the packages and
  products in your inventory, then drops CVEs whose CPE ranges cannot cover the versions you
  have. On one Mac that took the agent's input from 10,304 advisories to 267.
- **An agent's judgement, with the evidence.** Each finding says what is affected, where it
  was found, why it matters and how to fix it, with the exact commands.
- **Exploited first.** Advisories in CISA's Known Exploited Vulnerabilities catalog are
  flagged and always kept, and the popover ranks them above everything else.
- **Fixes you approve.** Nothing changes until you confirm a fix. A repository fix is
  delivered as a pull request, never a push to the default branch.
- **A fix is not done until a sweep says so.** A fix the agent reports stays open and counted,
  marked "Fix reported" or "Pull request open". It moves to the Fixed list only once a later
  sweep no longer finds the problem.
- **Quiet until it matters.** The menu-bar icon shows the worst open severity at a glance,
  and a notification arrives only for new critical or high findings.
- **Files you own.** Configuration, reports, dismissals and fix history are plain TOML, JSON
  and Markdown in your Library folder. The menu-bar app and the CLI share them.

## Screenshots

All screenshots use example data: well-known CVEs with their real affected versions, on
example targets.

<table>
  <tr>
    <td width="33%" align="center"><img src="docs/images/findings.png" alt="The findings that need attention, worst first"><br><sub><b>Needs you.</b> Critical, high and exploited findings, worst first.</sub></td>
    <td width="33%" align="center"><img src="docs/images/detail.png" alt="The details of a finding with its explanation and fix commands"><br><sub><b>Details.</b> The agent's explanation and the exact fix.</sub></td>
    <td width="33%" align="center"><img src="docs/images/confirm.png" alt="The confirmation before a fix runs"><br><sub><b>Confirm.</b> Where the fix runs, with which agent, and what it runs.</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="docs/images/sweeping.png" alt="A sweep in progress with a progress bar per target"><br><sub><b>Sweeping.</b> Progress per target, cancellable at any time.</sub></td>
    <td align="center"><img src="docs/images/fixing.png" alt="A fix in progress with the agent's live output"><br><sub><b>Fixing.</b> Each step, with the agent's latest output.</sub></td>
    <td align="center"><img src="docs/images/targets.png" alt="Each target with its open findings by severity"><br><sub><b>Targets.</b> What each sweep checked and what it found.</sub></td>
  </tr>
  <tr>
    <td align="center"><img src="docs/images/fixed.png" alt="Fixes that a later sweep confirmed"><br><sub><b>Fixed.</b> Fixes a later sweep confirmed, for 30 days.</sub></td>
    <td align="center"><img src="docs/images/clear.png" alt="The all clear view"><br><sub><b>All clear.</b> Every target swept, nothing open.</sub></td>
    <td align="center"><img src="docs/images/settings.png" alt="The settings view"><br><sub><b>Settings.</b> Agent, schedule, targets and NVD key.</sub></td>
  </tr>
</table>

The menu-bar icon is Vigil's mark, a spiral of dots, and its colour carries the state:

<p align="center">
  <img src="docs/images/tray-states.png" alt="The six menu-bar icon states: clear, low, medium, high, sweeping and failed" width="100%">
</p>

A left click opens the popover; a right click offers Quit Vigil.

## How a sweep works

```mermaid
flowchart LR
    A[Advisory feeds<br>OSV, NVD, CISA KEV] --> C
    B[Inventory<br>Mac, GitHub, servers] --> C
    C[Pre-filter<br>names, products,<br>version ranges] --> D[Bundle<br>inventory and<br>advisories as files]
    D --> E[Coding agent<br>restricted, read-only]
    E --> F[findings.json<br>validated]
    F --> G[Report<br>dismissals, changes,<br>notifications]
```

Targets are swept one after another, each in its own folder under `sweeps/<time>/`:

1. **Feeds.** OSV, NVD and the CISA KEV catalog are synced into a local cache. Later sweeps
   fetch only what changed.
2. **Inventory.** The app collects what is installed. For a repository it reads the GitHub
   API with your `gh` login; for a server it runs a fixed script over SSH.
3. **Bundle.** The inventory, the advisories that could apply, the findings schema and the
   prompt are written as files for the agent to read.
4. **Verdict.** The agent reads the bundle and writes `findings.json`. The app validates it
   strictly and gives the agent one retry with the error if it is malformed.
5. **Report.** Findings get stable keys, dismissals are applied, the result is compared with
   the target's last sweep, and a JSON and Markdown report is written. New critical and high
   findings raise a notification.

## Safety model

Advisory text, repository files and server output are all untrusted input, and a coding agent
acts on what it reads. Vigil is built around that.

| | Sweeps | Fixes |
|---|---|---|
| **Agent permissions** | Restricted: read anything, write only `findings.json`, run only listing commands such as `brew info` | Full access, and only after you confirm that specific fix |
| **What the agent sees** | The bundle the app wrote; it never calls GitHub or SSH itself | The confirmed fix, not the sweep's evidence, which came from untrusted text |
| **Where it acts** | Its bundle folder | This Mac; a clone and a pull request for a repository; one SSH host for a server |

More of the design:

- **Checked before you are asked.** Before the confirmation, the app checks that the finding
  is still in the target's newest report, is not dismissed, and still passes the sweep's text
  checks, and that the target is still configured.
- **Read-only server collection.** The server script never uses `sudo`. SSH runs in batch
  mode with strict host key checking, and with agent and port forwarding off.
- **Stopping cleanly.** Cancelling a sweep or quitting the app stops the agent and every
  process it started, and removes the unfinished target's folder.
- **Secrets stay put.** The NVD API key is stored only in the macOS Keychain.
- **Escaped output.** Agent text is escaped in reports, so it cannot forge Markdown or send
  terminal escape sequences.

## Getting started

Vigil is built from source for now. A signed and notarized DMG is planned.

### Requirements

- macOS
- [Rust](https://rustup.rs). The pinned toolchain (`rust-toolchain.toml`) is installed
  automatically on first build.
- [Node.js](https://nodejs.org) 22 and [pnpm](https://pnpm.io) 10, to build the interface
- At least one supported coding agent, installed and logged in
- [GitHub CLI](https://cli.github.com), logged in with `gh auth login`, to sweep repositories
- SSH access without a password prompt, to sweep servers. Host keys must already be in
  `~/.ssh/known_hosts`.

### Build and run the menu-bar app

```sh
git clone https://github.com/GeorgiosDelkos/vigil.git
cd vigil
pnpm --dir app/ui install --frozen-lockfile
pnpm --dir app/ui build
cargo build --release -p vigil-app --features custom-protocol
./target/release/vigil-app
```

Vigil appears in the menu bar, with no Dock icon. Open the popover, pick your agent in
Settings, choose your targets, and press **Sweep**. The gear menu turns on launch at login.

### Install the command-line tool

```sh
cargo install --path crates/cli
vigil init      # creates the data folder and a default config.toml
vigil config    # validates it and shows what a sweep would cover
vigil sweep
```

### Raise the NVD rate limit (optional)

Without a key NVD allows 5 requests per 30 seconds; with one it allows 50. Request a key from
[NVD](https://nvd.nist.gov/developers/request-an-api-key), then add it in Settings, or store
it in the Keychain yourself:

```sh
security add-generic-password -s io.github.georgiosdelkos.vigil -a nvd-api-key -w <key>
```

## Configuration

Everything lives in `~/Library/Application Support/io.github.georgiosdelkos.vigil/`. The app's
settings and `config.toml` edit the same file:

```toml
agent = "claude"                 # claude, grok, codex, gemini or opencode

[models]
claude = "opus"                  # optional, per agent; the agent's default otherwise

[schedule]
every_hours = 6                  # leave unset to sweep only on demand

[history]
since = "all"                    # or a date such as "2025-01-31"

[mac]
project_dirs = ["~/code"]        # searched for lockfiles; project code is never run

[github]
repos = ["acme/storefront"]

[[servers]]
name = "web-1"
ssh = "web-1"                    # an alias from ~/.ssh/config, or host, user, port, identity_file
dirs = ["/srv/app"]
```

The data folder also holds:

| Path | Contents |
|---|---|
| `prompts/` | The sweep and fix prompts, editable |
| `sweeps/<time>/<target>/` | Each target's bundle, agent log, `findings.json` and report |
| `sweeps/<time>/report.{json,md}` | The sweep's combined report |
| `fixes/<time>-<key>/` | Each fix's prompt, the agent's log and its result |
| `state/dismissals.json` | Dismissed findings, with reasons |
| `state/fixes.jsonl` | Every fix run, one line each |

## Command line

The `vigil` CLI uses the same core and the same files as the app.

| Command | What it does |
|---|---|
| `vigil init` | Create the data folder and a default `config.toml` |
| `vigil config` | Validate `config.toml` and print what a sweep would cover |
| `vigil inventory` | List what is installed on this Mac, one JSON object per line |
| `vigil advisories --package npm:lodash --product openssl` | Fetch advisories for packages and NVD products |
| `vigil sweep [--target mac \| github:<owner>/<name> \| server:<name>]` | Sweep every target, or one |
| `vigil findings [--json]` | Each target's open findings, with their keys |
| `vigil dismiss <key> --reason <text>` | Hide a finding, for a reason; it returns if its advisory changes |
| `vigil undismiss <key>` | Show a dismissed finding again |
| `vigil fix <key> [--yes]` | Show a finding's fix, ask to confirm, and have the agent apply it |

Ctrl-C cancels a sweep cleanly (exit code 130); a second Ctrl-C exits at once.

## Advisory sources

| Source | Used for |
|---|---|
| [OSV.dev](https://osv.dev) | Language and OS package advisories, including the GitHub Advisory Database and malicious-package reports |
| [NVD](https://nvd.nist.gov) | CVEs for macOS, Homebrew software and toolchains, matched by CPE product and version range |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Marking CVEs that are exploited in the wild |

OSV is queried by package name, and the full records are cached locally. It sees version
numbers only for a server's OS packages, where the distribution's own version rules decide.

## Supported agents

| Agent | CLI | Sweeps | Fixes |
|---|---|---|---|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `claude` | Restricted: may write only `findings.json` | Full access after confirmation |
| [Grok](https://x.ai) | `grok` | Restricted: may write only `findings.json`, no shell | Full access after confirmation |
| [Codex](https://github.com/openai/codex) | `codex` | Workspace-write sandbox in the bundle | Full access after confirmation |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `gemini` | Auto-edit in the bundle | Full access after confirmation |
| [opencode](https://opencode.ai) | `opencode` | Permissions set per run | Full access after confirmation |

Agents are found through your login shell's `PATH`, so an agent installed with npm or
Homebrew starts as it does in a terminal. The model each agent uses is set in Settings or in
`[models]`.

## Project layout

```
crates/core/      vigil-core   feeds, inventory, agents, sweep, findings, lifecycle, fixes
crates/cli/       vigil        the command-line tool
app/src-tauri/    vigil-app    the menu-bar app (Tauri 2)
app/ui/                        the popover interface (SolidJS and TypeScript)
docs/spec.md                   the design, with the reasoning behind each decision
```

The logic lives in Rust. The interface only lays out what the core works out, so the app and
the CLI always agree.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

pnpm --dir app/ui check          # oxlint, oxfmt and tsc
pnpm --dir app/ui test           # vitest

pnpm --dir app/ui build          # the app's tests embed the built interface
cargo test -p vigil-app --features custom-protocol
```

For a live-reloading app, run `cargo tauri dev` in `app/src-tauri` (needs `cargo install
tauri-cli`).

CI runs the same checks, `cargo deny`, and `cargo mutants` over each pull request's changes.
Tests use a fake agent on `PATH` to exercise sweeps, retries and failures without a real one.
See [`docs/spec.md`](docs/spec.md) for the full design.

## Status

Vigil is under active development. It is complete enough for daily use on one Mac:
sweeps, findings, dismissals, confirmed fixes and fix history all work across the three
target types. Next on the list:

- A signed and notarized DMG, which needs an Apple Developer account
- Lockfiles not read yet: `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `Pipfile.lock` and
  `go.sum`
- Node and Python versions managed by nvm, fnm, volta, asdf or pyenv, beyond the one on `PATH`
