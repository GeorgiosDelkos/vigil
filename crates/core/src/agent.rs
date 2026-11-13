//! The coding agents a sweep can run, and how each is started headless.
//!
//! Every agent gets the same one-line prompt, pointing it at `PROMPT.md` in the bundle folder,
//! and runs with that folder as its working directory and the login shell's `PATH`.
//!
//! Sweeps run restricted (decided 2026-11-05), because untrusted text (advisory descriptions,
//! package names from cloned repositories) reaches the agent: they read the Mac, and write only
//! `findings.json` where the CLI can limit writes to one file (claude, grok, opencode). Codex and
//! gemini can write anywhere in the bundle, which is the app's own copy, and codex may run any
//! command its sandbox allows; the app trusts nothing in the bundle but its own files and
//! `findings.json`, which it validates.
//!
//! A prompt-injected sweep run must have no network path out (owner's decision, 2026-11-12:
//! sweeps keep reading the Mac, but every network path out is closed and credential paths are
//! denied wherever the CLI can deny reads). So a sweep runs no shell command except codex's,
//! inside a sandbox without network; has no web, MCP, subagent or memory tools; ignores the
//! user's own agent settings where they could grant more; is denied [`CREDENTIAL_PATHS`]
//! (claude, grok, opencode, gemini; codex cannot deny reads); and inherits only the environment
//! variables in [`SWEEP_ENV`]. What it writes in `findings.json` still leaves the run: the app
//! shows it, and a fix the user confirms is given it. Fixes, which change the Mac after the user
//! confirms them, are a separate run with full access ([`AgentKind::fix_command`]). The flags per
//! CLI are in the spec's "Agent adapters" table, with what was verified on this Mac.

use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;

use serde::Deserialize;
use serde::Serialize;

use crate::cancel;
use crate::cancel::Cancel;
use crate::cancel::Ended;
use crate::config::ModelName;
use crate::inventory::InventoryError;
use crate::login_shell;
use crate::login_shell::END_MARK;
use crate::login_shell::PATH_MARK;
use crate::paths;

/// The one line every agent is given; the real instructions are in the bundle's `PROMPT.md`.
pub(crate) const PROMPT_LINE: &str =
    "Read PROMPT.md in the current directory and follow its instructions exactly.";

/// Credential files and folders a sweep agent is denied, where its CLI can deny reads (Claude
/// Code, Grok, opencode, and Gemini CLI through its policy), so a prompt-injected sweep cannot
/// read keys and tokens. Each is the tail of a path, matched in any folder: the home folder has
/// other spellings (`/System/Volumes/Data/Users/<name>`, a firmlink) that a rule anchored at
/// `~/` would miss, and any folder holding one of these names is worth keeping out. Each entry
/// also covers everything under it. Not covered: another letter case of the same name, which
/// the macOS file system accepts and these CLIs' rules do not fold. Each CLI's spelling is
/// built from this one list: [`claude_denied`], [`grok_denied`], [`opencode_denied`],
/// [`gemini_policy`].
const CREDENTIAL_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".config/gh",
    ".gnupg",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".kube",
    "Library/Keychains",
    ".config/gcloud",
    ".azure",
    ".env*",
    // Tokens kept by git, cargo and the agents themselves (each CLI reads its own login, not
    // through these tools).
    ".git-credentials",
    ".config/git/credentials",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".codex/auth.json",
    ".grok/auth.json",
    ".gemini/oauth_creds.json",
    ".local/share/opencode/auth.json",
];

/// Each [`CREDENTIAL_PATHS`] entry in any folder, after `anywhere`, and everything under it,
/// after `under`.
fn credential_patterns<'a>(anywhere: &'a str, under: &'a str) -> impl Iterator<Item = String> + 'a {
    CREDENTIAL_PATHS
        .iter()
        .flat_map(move |p| [format!("{anywhere}{p}"), format!("{anywhere}{p}{under}")])
}

/// Claude Code's deny rules for [`CREDENTIAL_PATHS`]. Its path rules are gitignore patterns:
/// `//` is the filesystem root, and a bare `**/` would only match under the working folder
/// (<https://code.claude.com/docs/en/permissions>, "How path patterns match", checked
/// 2026-11-12). It applies `Read` denies to Grep and Glob too.
fn claude_denied() -> impl Iterator<Item = String> {
    credential_patterns("//**/", "/**").map(|p| format!("Read({p})"))
}

/// Grok's deny rules for [`CREDENTIAL_PATHS`]: a leading `**/` matches at any depth, anywhere;
/// `Read` rules also govern its grep tool and the files shell commands touch
/// (`~/.grok/docs/user-guide/22-permissions-and-safety.md`, "Read, Edit, and Grep Rules", Grok
/// 1.0.77, checked 2026-11-12).
fn grok_denied() -> impl Iterator<Item = String> {
    credential_patterns("**/", "/**").map(|p| format!("Read({p})"))
}

/// opencode's `read` patterns for [`CREDENTIAL_PATHS`]. Its `*` matches any characters, `/`
/// included, and external paths are canonicalized before matching
/// (<https://opencode.ai/docs/permissions/>, checked 2026-11-12).
fn opencode_denied() -> impl Iterator<Item = String> {
    credential_patterns("*/", "/*")
}

/// The name of the agent a sweep defines for opencode in `OPENCODE_CONFIG_CONTENT` and selects
/// with `--agent`. Its own agent, not opencode's `build`, because opencode appends an agent's
/// rules after the global ones and the last matching rule wins: rules the user's config sets for
/// `build` would otherwise outrank the sweep's global rules.
const OPENCODE_SWEEP_AGENT: &str = "vigil-sweep";

/// opencode's sweep agent: everything denied (the first rule, `"*": "deny"`, covers the shell,
/// web, task, skill and MCP tools) except reading anywhere but [`CREDENTIAL_PATHS`], finding and
/// listing files, and editing `findings.json`. Its grep tool is left denied: opencode asks
/// permission for the search pattern, not for the files searched, so `read` denies do not hold
/// for it (checked in the opencode 1.17.11 binary, 2026-11-12). Format:
/// <https://opencode.ai/docs/permissions/> (checked 2026-11-12) and `opencode debug agent
/// vigil-sweep` on opencode 1.17.11, which showed these rules last, after the user's. The last
/// matching rule wins, so each `"*"` comes first; the text is built in order rather than with a
/// JSON map, which would sort the keys.
fn opencode_sweep_config() -> String {
    let denied: Vec<String> = opencode_denied()
        .map(|p| format!(r#", {}: "deny""#, serde_json::Value::String(p)))
        .collect();
    let denied = denied.concat();
    format!(
        concat!(
            r#"{{"agent": {{"{agent}": {{"mode": "primary", "permission": {{"*": "deny", "#,
            r#""read": {{"*": "allow"{denied}}}, "glob": "allow", "#,
            r#""list": "allow", "external_directory": "allow", "#,
            r#""edit": {{"*": "deny", "findings.json": "allow"}}}}}}}}}}"#,
        ),
        agent = OPENCODE_SWEEP_AGENT,
        denied = denied,
    )
}

/// The file in the bundle holding Gemini CLI's sweep policy, passed with `--admin-policy`.
/// Inside the bundle, so it needs no other folder; Gemini CLI can edit bundle files, but it reads
/// the policy once at start, and the app writes it again before each run.
const GEMINI_POLICY: &str = "gemini-policy.toml";

/// Gemini CLI's sweep policy: no shell, web, memory or MCP tools, no content search or
/// multi-file read, and no tool call whose path argument names one of [`CREDENTIAL_PATHS`]. Its
/// file tools reach only its workspace, the bundle, unless the user's settings add folders
/// (`context.includeDirectories`), hence the credential rule; it covers every tool, writes too
/// (`replace` on `~/.ssh/config` could add a `ProxyCommand`). It matches only path arguments
/// (`file_path`, `dir_path`, `path`, glob `pattern`), not text such as a `content` that may name
/// `~/.ssh/config`, so writing `findings.json` is never refused. Content search (`grep_search`,
/// formerly `search_file_content`) and `read_many_files` (which takes globs such as `.ss[h]`)
/// would get past a rule on names, so they are denied outright; `read_file` is enough for a
/// sweep. Admin tier, so the user's own policies cannot allow them again. Format, tool names and
/// argument keys: `docs/reference/policy-engine.md` and `docs/reference/tools.md` of
/// google-gemini/gemini-cli at v0.68.0 (5a5c718), checked 2026-11-12: `argsPattern` is a
/// regular expression over the arguments as a stable JSON string, written `"key":"value"` as in
/// its own `"file_path":".*\.env"` example. `save_memory` is from older releases; a name no tool
/// has matches nothing. The pattern is built by escaping only `.`, and sits in a TOML literal
/// string: a test holds every entry to letters, digits and `._/-` with an optional trailing `*`.
fn gemini_policy() -> String {
    let names: Vec<String> = CREDENTIAL_PATHS
        .iter()
        .map(|p| p.trim_end_matches('*').replace('.', r"\."))
        .collect();
    // The name is the whole value or follows a folder separator in it.
    let pattern = format!(
        r#""(?:file_path|dir_path|path|pattern)":"(?:[^"]*/)?(?:{})"#,
        names.join("|")
    );
    format!(
        r#"# Written by Vigil before each sweep; edits are overwritten.
[[rule]]
toolName = [
  "run_shell_command", "web_fetch", "google_web_search", "save_memory",
  "grep_search", "search_file_content", "read_many_files",
]
decision = "deny"
priority = 999

[[rule]]
toolName = "*"
mcpName = "*"
decision = "deny"
priority = 999

[[rule]]
toolName = "*"
argsPattern = '{pattern}'
decision = "deny"
priority = 999
"#
    )
}

/// The environment variables a sweep agent inherits, besides the `PATH` it is given: what a
/// login needs (home, user, shell, locale, temporary folder, terminal, proxies and their
/// certificates), and the agent's own configuration and API keys ([`AgentKind::env_prefixes`]).
/// Everything else, an SSH agent socket or another provider's token among them, is removed.
/// Claude Code reads its login from the Keychain, and the others from files under `HOME`, so
/// none needs more.
const SWEEP_ENV: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "TMPDIR",
    "TERM",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The prefixes of further variables every sweep agent inherits: locale and XDG folders
/// (opencode keeps its config under `XDG_CONFIG_HOME`).
const SWEEP_ENV_PREFIXES: &[&str] = &["LC_", "XDG_"];

/// Every agent's own prefixes, for opencode, which serves models from any of their providers.
const PROVIDER_ENV_PREFIXES: &[&str] = &[
    "ANTHROPIC_",
    "CLAUDE_",
    "XAI_",
    "GROK_",
    "OPENAI_",
    "CODEX_",
    "GEMINI_",
    "GOOGLE_",
    "OPENCODE_",
];

/// Marks the agent's path in the login shell's answer, between [`login_shell::PATH_MARK`] and
/// [`login_shell::END_MARK`], so nothing its startup files print is mistaken for the answer.
const BINARY_MARK: &str = "__vigil_binary__";

/// A coding-agent CLI that Vigil can drive headless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentKind {
    /// Claude Code (`claude`).
    Claude,
    /// Grok CLI (`grok`).
    Grok,
    /// OpenAI Codex CLI (`codex`).
    Codex,
    /// Gemini CLI (`gemini`).
    Gemini,
    /// opencode (`opencode`).
    Opencode,
}

impl AgentKind {
    /// Returns the executable name looked up on `PATH`.
    pub fn binary(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Grok => "grok",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Opencode => "opencode",
        }
    }

    /// The agent's name as people know it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Grok => "Grok",
            Self::Codex => "Codex",
            Self::Gemini => "Gemini CLI",
            Self::Opencode => "opencode",
        }
    }

    /// Who serves the agent's models, or `None` for opencode, whose model names start with
    /// their provider.
    pub(crate) fn provider(self) -> Option<&'static str> {
        match self {
            Self::Claude => Some("Anthropic"),
            Self::Grok => Some("xAI"),
            Self::Codex => Some("OpenAI"),
            Self::Gemini => Some("Google"),
            Self::Opencode => None,
        }
    }

    /// Finds the agent's executable the way the user's terminal would, since an app started at
    /// login gets a `PATH` without `~/.local/bin`, nvm or Homebrew. Returns `None` when the
    /// shell cannot find it as a file (an alias or a shell function does not count).
    ///
    /// Runs `$SHELL` as an interactive login shell (`-ilc` for zsh and bash, so zsh reads
    /// `.zshrc` as well as `.zprofile`), falling back to `-lc`; see [`login_shell`]. This runs
    /// the user's shell startup files, as their terminal does, and takes up to 10 seconds
    /// before the fallback when a `.zshrc` hangs. The agent found runs `model`, or its own
    /// default for `None`.
    ///
    /// # Errors
    ///
    /// Fails when the shell itself cannot be run.
    pub(crate) fn locate(self, model: Option<&ModelName>) -> Result<Option<Located>, AgentError> {
        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_owned());
        let script = format!(
            "printf '%s\\n' {PATH_MARK} \"$PATH\" {BINARY_MARK}; command -v {}; \
             printf '%s\\n' {END_MARK}",
            self.binary()
        );
        match login_shell::run(&shell, &script) {
            Ok(Some(output)) => Ok(parse_located(&output.stdout, model)),
            Ok(None) => Err(AgentError::NoShell { shell }),
            Err(source) => Err(AgentError::Locate {
                agent: self,
                source,
            }),
        }
    }

    /// The prefixes of the agent's own environment variables, which its sweeps inherit (see
    /// [`SWEEP_ENV`]). Gemini CLI's `GOOGLE_` includes Google Cloud credentials
    /// (`GOOGLE_APPLICATION_CREDENTIALS`), which a Vertex AI login needs.
    fn env_prefixes(self) -> &'static [&'static str] {
        match self {
            Self::Claude => &["ANTHROPIC_", "CLAUDE_"],
            Self::Grok => &["XAI_", "GROK_"],
            Self::Codex => &["OPENAI_", "CODEX_"],
            Self::Gemini => &["GEMINI_", "GOOGLE_"],
            Self::Opencode => PROVIDER_ENV_PREFIXES,
        }
    }

    /// Whether this agent's sweep inherits the variable `name`: see [`SWEEP_ENV`].
    fn sweep_inherits(self, name: &OsStr) -> bool {
        name.to_str().is_some_and(|name| {
            SWEEP_ENV.contains(&name)
                || SWEEP_ENV_PREFIXES
                    .iter()
                    .chain(self.env_prefixes())
                    .any(|p| name.starts_with(p))
        })
    }

    /// Builds the restricted sweep command for `prompt`, run in `bundle` (see the module docs).
    /// For Gemini CLI it first writes [`GEMINI_POLICY`] into `bundle`.
    ///
    /// Flags checked on 2026-11-12: `claude --help` (2.1.322), `grok --help` and its user guide
    /// (1.0.77), `opencode run --help` and `opencode debug agent` (1.17.11), codex's CLI and
    /// config reference (<https://learn.chatgpt.com/docs/cli/reference>; not installed here),
    /// and gemini-cli's `packages/cli/src/config/config.ts` at v0.68.0 (not installed here).
    ///
    /// # Errors
    ///
    /// Fails when Gemini CLI's policy cannot be written.
    pub(crate) fn sweep_command(
        self,
        located: &Located,
        bundle: &Path,
        prompt: &str,
    ) -> Result<Command, AgentError> {
        let mut command = Command::new(&located.binary);
        // Each variable is removed by name, not with `env_clear`: `cancel::supervised` copies
        // the command through `get_envs`, which does not carry `env_clear`, so the watchdog
        // shell would pass the whole environment on.
        for (name, _) in env::vars_os().filter(|(name, _)| !self.sweep_inherits(name)) {
            command.env_remove(name);
        }
        set_up(&mut command, located, bundle);
        self.start_args(&mut command, located);
        match self {
            Self::Claude => claude_sweep_args(&mut command, prompt),
            Self::Grok => grok_sweep_args(&mut command, bundle, prompt),
            Self::Codex => codex_sweep_args(&mut command, bundle, prompt),
            Self::Gemini => {
                let policy = bundle.join(GEMINI_POLICY);
                write_new(&policy, &gemini_policy()).map_err(|source| AgentError::Policy {
                    path: policy.clone(),
                    source,
                })?;
                command.args(["-p", prompt, "--approval-mode", "auto_edit", "--skip-trust"]);
                // `none` alone turns every extension off (extensionEnablement.ts at v0.68.0):
                // extensions bring MCP servers and policies of their own.
                command.args(["--extensions", "none", "--admin-policy"]);
                command.arg(policy);
            }
            Self::Opencode => {
                command.env("OPENCODE_CONFIG_CONTENT", opencode_sweep_config());
                // `--pure`: without the user's plugins, which run code on every tool call.
                command.args(["--pure", "--agent", OPENCODE_SWEEP_AGENT, "--dir"]);
                command.arg(bundle).arg(prompt);
            }
        }
        Ok(command)
    }

    /// Builds the full-access fix command for `prompt`, run in `dir`: no permission prompts,
    /// no sandbox. Only for a fix the user confirmed (spec, "Fix flow"). The flags were checked
    /// on 2026-11-06 in each CLI's `--help` (codex, not installed here, in its CLI reference).
    /// It inherits this process's environment, which a fix may need (a cloud CLI's token).
    pub(crate) fn fix_command(self, located: &Located, dir: &Path, prompt: &str) -> Command {
        let mut command = Command::new(&located.binary);
        set_up(&mut command, located, dir);
        self.start_args(&mut command, located);
        match self {
            Self::Claude => {
                command.args(["-p", prompt, "--permission-mode", "bypassPermissions"]);
            }
            Self::Grok => {
                command.args([
                    "-p",
                    prompt,
                    "--permission-mode",
                    "bypassPermissions",
                    "--cwd",
                ]);
                command.arg(dir);
            }
            Self::Codex => {
                command.args([
                    "--dangerously-bypass-approvals-and-sandbox",
                    "--skip-git-repo-check",
                ]);
                command.arg("-C").arg(dir).arg(prompt);
            }
            Self::Gemini => {
                command.args(["-p", prompt, "--approval-mode", "yolo", "--skip-trust"]);
            }
            Self::Opencode => {
                command.args(["--dangerously-skip-permissions", "--dir"]);
                command.arg(dir).arg(prompt);
            }
        }
        command
    }

    /// Starts the arguments of a headless run: the subcommand codex and opencode need, then
    /// the chosen model. Every CLI takes `--model` (checked on 2026-11-07 in each `--help`, and
    /// for codex in its CLI reference); it comes before the prompt, which codex and opencode
    /// take as their last argument.
    fn start_args(self, command: &mut Command, located: &Located) {
        match self {
            Self::Codex => drop(command.arg("exec")),
            Self::Opencode => drop(command.arg("run")),
            Self::Claude | Self::Grok | Self::Gemini => {}
        }
        if let Some(model) = &located.model {
            command.arg("--model").arg(model.as_str());
        }
    }

    /// Runs `command`, from [`Self::sweep_command`] or [`Self::fix_command`], with its stdout
    /// and stderr in `log`, and waits for it. It runs under the `cancel` module's watchdog, so
    /// it stops when this process ends, and `cancel` stops it and everything it started.
    /// Returns its exit status: what a failure means depends on whether it wrote its result
    /// file, which is the caller's to check. There is no time limit: an agent can take many
    /// minutes, and the user chose to let it run.
    ///
    /// # Errors
    ///
    /// Fails when the log cannot be created, the agent cannot start or be followed, or it was
    /// cancelled.
    pub(crate) fn run(
        self,
        command: &Command,
        log: &Path,
        cancel: &Cancel,
    ) -> Result<ExitStatus, AgentError> {
        // The watchdog shell always starts, so a binary that has gone is caught here; the
        // binary is the login shell's absolute path.
        if !Path::new(command.get_program()).is_file() {
            return Err(AgentError::Start {
                agent: self,
                source: io::Error::from(io::ErrorKind::NotFound),
            });
        }
        let log_err = |source| AgentError::Log {
            path: log.to_owned(),
            source,
        };
        let out = fs::File::create(log).map_err(log_err)?;
        let err = out.try_clone().map_err(log_err)?;
        let child = cancel::supervised(command)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()
            .map_err(|source| AgentError::Start {
                agent: self,
                source,
            })?;
        match cancel::watch(child, cancel) {
            Ok(Ended::Exited(status)) => match cancel::not_run(status, &log_head(log)) {
                Some(reason) => Err(AgentError::Start {
                    agent: self,
                    source: io::Error::other(reason),
                }),
                None => Ok(status),
            },
            Ok(Ended::Cancelled) => Err(AgentError::Cancelled { agent: self }),
            Err(source) => Err(AgentError::Watch {
                agent: self,
                source,
            }),
        }
    }
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.binary())
    }
}

/// Writes `text` to `path` as a new file, after removing whatever is there. On a second attempt
/// the bundle is the one the agent just ran in, and a link it left at `path` would otherwise
/// make the write land on the link's target.
fn write_new(path: &Path, text: &str) -> io::Result<()> {
    // The removal's result is not needed: when it fails on anything but a missing file, the
    // path is still taken, and `create_new` reports that.
    drop(fs::remove_file(path));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(text.as_bytes())
}

/// What sweeps and fixes share: the working folder `dir`, the login shell's `PATH`, and Homebrew
/// refusing formulae and casks from file paths. Without that, `brew install ./x.rb` in a cloned
/// repository would run that repository's Ruby. Homebrew forbids them unless
/// `HOMEBREW_DEVELOPER` or `HOMEBREW_TESTS` is set, and always allows them when
/// `HOMEBREW_INTERNAL_ALLOW_PACKAGES_FROM_PATHS` is set; an explicit
/// `HOMEBREW_FORBID_PACKAGES_FROM_PATHS` beats the first two (`Library/Homebrew/env_config.rb`,
/// `forbid_packages_from_paths?`, Homebrew 7.0.13 at bc63375ac3, checked 2026-11-12).
fn set_up(command: &mut Command, located: &Located, dir: &Path) {
    command.current_dir(dir).env("PATH", &located.path);
    command.env_remove("HOMEBREW_INTERNAL_ALLOW_PACKAGES_FROM_PATHS");
    command.env("HOMEBREW_FORBID_PACKAGES_FROM_PATHS", "1");
}

/// Claude Code: reads anywhere but [`CREDENTIAL_PATHS`], writes only `findings.json`, and has no
/// other tool. `--setting-sources ""` loads none of the user's, project or local settings, so
/// their allow rules, hooks and plugins do not apply; `--tools` leaves only the file tools (no
/// shell, web or subagent tool); `--strict-mcp-config` with no `--mcp-config` starts no MCP
/// server, and the `mcp__*` deny also removes the claude.ai connectors. An empty
/// `--setting-sources` is accepted (an unknown source is refused) by Claude Code 2.1.322; the
/// Agent SDK's `settingSources: []` means the same. The cost: provider settings kept in
/// `~/.claude/settings.json` (an `env` block for Bedrock, an `apiKeyHelper`) do not reach sweeps.
fn claude_sweep_args(command: &mut Command, prompt: &str) {
    command.args(["-p", prompt, "--permission-mode", "dontAsk"]);
    command.args(["--setting-sources", "", "--strict-mcp-config"]);
    // `Write` creates `findings.json`; `Edit` rules govern it too.
    command.args(["--tools", "Read,Glob,Grep,Edit,Write"]);
    command.args(["--allowedTools", "Read(//**)", "Edit(./findings.json)"]);
    command.args(["--disallowedTools", "mcp__*", "WebFetch", "WebSearch"]);
    command.args(claude_denied());
}

/// Grok: the file tools only, without web search (whose `open_page` fetches any URL and runs
/// without approval in every mode), subagents, MCP or memory. Its `dontAsk` mode allowed a shell
/// command in a test on 2026-11-05, so the shell is also denied outright. The `workspace`
/// sandbox lets the kernel hold writes to the bundle, `~/.grok` and temporary folders whatever
/// a rule allows (macOS Seatbelt; `18-sandbox.md`). Its network limits are a no-op on macOS, so
/// they are not relied on. Tool ids from `14-headless-mode.md` and `07-mcp-servers.md`.
fn grok_sweep_args(command: &mut Command, bundle: &Path, prompt: &str) {
    command.args(["-p", prompt, "--permission-mode", "default"]);
    command.args([
        "--sandbox",
        "workspace",
        "--disable-web-search",
        "--no-subagents",
    ]);
    command.args(["--tools", "read_file,grep,list_dir,search_replace,write"]);
    command.args(["--disallowed-tools", "search_tool,use_tool"]);
    // A leading `//` is literal text in Grok's rules, unlike Claude Code's; `/**` is every path.
    command.args(["--allow", "Read(/**)", "--allow", "Edit(./findings.json)"]);
    command.args(["--deny", "Bash", "--deny", "mcp__*"]);
    for rule in grok_denied() {
        command.arg("--deny").arg(rule);
    }
    command.arg("--cwd").arg(bundle);
    // `GROK_MEMORY=0` turns cross-session memory off for the process (`13-memory.md`). The
    // others stop Grok loading Claude Code's and Cursor's hooks, MCP servers, skills, agents and
    // rules, which the Claude Code sweep does not load either (`26-config-reference.md`,
    // `compat`).
    command.env("GROK_MEMORY", "0");
    for name in [
        "GROK_CLAUDE_AGENTS_ENABLED",
        "GROK_CLAUDE_HOOKS_ENABLED",
        "GROK_CLAUDE_MCPS_ENABLED",
        "GROK_CLAUDE_RULES_ENABLED",
        "GROK_CLAUDE_SKILLS_ENABLED",
        "GROK_CURSOR_AGENTS_ENABLED",
        "GROK_CURSOR_HOOKS_ENABLED",
        "GROK_CURSOR_MCPS_ENABLED",
        "GROK_CURSOR_RULES_ENABLED",
        "GROK_CURSOR_SKILLS_ENABLED",
    ] {
        command.env(name, "false");
    }
}

/// Codex: its workspace-write sandbox, with the network off and without web search, connectors
/// (`apps`), the user's `config.toml` (its MCP servers, and settings that could open the network
/// again; the login under `CODEX_HOME` still applies) or the user's command rules. Codex cannot
/// deny reads inside its sandbox, so it can read [`CREDENTIAL_PATHS`], but it has no way to send
/// them out.
fn codex_sweep_args(command: &mut Command, bundle: &Path, prompt: &str) {
    command.args(["--sandbox", "workspace-write", "--skip-git-repo-check"]);
    command.args([
        "--ignore-user-config",
        "--ignore-rules",
        "--disable",
        "apps",
    ]);
    command.args(["-c", "sandbox_workspace_write.network_access=false"]);
    command.args(["-c", r#"web_search="disabled""#]);
    command.arg("-C").arg(bundle).arg(prompt);
}

/// An agent found by the login shell, with the `PATH` it runs under.
#[derive(Debug)]
pub(crate) struct Located {
    /// The executable.
    binary: PathBuf,
    /// The login shell's `PATH`, so the agent (an npm script, say) and the tools it calls
    /// start as they do in the user's terminal.
    path: OsString,
    /// The model it runs with, or `None` for its own default.
    model: Option<ModelName>,
}

#[cfg(test)]
impl Located {
    /// An agent at `binary`, for tests of code that only passes it on.
    pub(crate) fn at(binary: &Path) -> Self {
        Self {
            binary: binary.to_owned(),
            path: OsString::from("/usr/bin:/bin"),
            model: None,
        }
    }
}

/// Reads the marked lines of the login shell's answer: the `PATH`, then exactly one absolute
/// path to an executable regular file. The agent found runs `model`.
fn parse_located(stdout: &str, model: Option<&ModelName>) -> Option<Located> {
    let lines: Vec<&str> = stdout.lines().collect();
    let at = |mark: &str| lines.iter().position(|l| l.trim() == mark);
    let path_at = lines.iter().position(|l| login_shell::is_path_mark(l))?;
    let (binary_at, end_at) = (at(BINARY_MARK)?, at(END_MARK)?);
    if binary_at != path_at + 2 || end_at != binary_at + 2 {
        return None;
    }
    let binary = PathBuf::from(lines[binary_at + 1].trim());
    let executable =
        fs::metadata(&binary).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
    (binary.is_absolute() && executable).then(|| Located {
        binary,
        path: OsString::from(absolute_entries(lines[path_at + 1])),
        model: model.cloned(),
    })
}

/// `path` without its empty, `.` and other relative entries, each of which looks commands up
/// in the agent's working folder: a bundle, or a cloned repository during a fix.
fn absolute_entries(path: &str) -> String {
    let entries: Vec<&str> = path.split(':').filter(|e| e.starts_with('/')).collect();
    entries.join(":")
}

/// How much of an agent log [`AgentKind::run`] reads to tell why the program did not start: the
/// watchdog's one-line message comes first. Arbitrary: a few lines.
const LOG_HEAD: u64 = 4096;

/// The first [`LOG_HEAD`] bytes of `log`, or none when it cannot be read: the log was just
/// written, and an unreadable one only means the start failure is reported as the exit status.
/// A fix runs in the folder that holds its log, so the agent can leave a FIFO or a link there:
/// the log is read through [`paths::read_capped`], which follows no link and waits for no
/// writer, and reads only a regular file.
fn log_head(log: &Path) -> Vec<u8> {
    paths::read_capped(log, LOG_HEAD).unwrap_or_default()
}

/// Error from finding or running an agent.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The user's login shell could not be found.
    #[error("cannot find the login shell {shell}; set SHELL")]
    NoShell {
        /// The shell tried.
        shell: String,
    },
    /// The login shell failed while looking the agent up.
    #[error("cannot look up {agent}")]
    Locate {
        /// The agent.
        agent: AgentKind,
        /// What went wrong.
        #[source]
        source: InventoryError,
    },
    /// The agent's log file could not be created.
    #[error("cannot write the agent log {}", path.display())]
    Log {
        /// The log path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// Gemini CLI's sweep policy could not be written into the bundle.
    #[error("cannot write the Gemini CLI policy {}", path.display())]
    Policy {
        /// The policy path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The agent could not be started.
    #[error("cannot start {agent}")]
    Start {
        /// The agent.
        agent: AgentKind,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// Waiting for the running agent failed; it was stopped.
    #[error("cannot follow {agent} while it runs")]
    Watch {
        /// The agent.
        agent: AgentKind,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The agent was stopped by a cancel request, the user's or the app's as it quit.
    #[error("{agent} was stopped before it finished")]
    Cancelled {
        /// The agent.
        agent: AgentKind,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [AgentKind; 5] = [
        AgentKind::Claude,
        AgentKind::Grok,
        AgentKind::Codex,
        AgentKind::Gemini,
        AgentKind::Opencode,
    ];

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn located(binary: &Path) -> Located {
        Located {
            binary: binary.to_owned(),
            path: OsString::from("/usr/bin:/bin"),
            model: None,
        }
    }

    fn words(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// What a command does with one environment variable.
    #[derive(Debug, PartialEq)]
    enum Var<'a> {
        Inherited,
        Removed,
        Set(&'a OsStr),
    }

    fn var<'a>(command: &'a Command, name: &str) -> Var<'a> {
        match command.get_envs().find(|(k, _)| *k == name) {
            None => Var::Inherited,
            Some((_, None)) => Var::Removed,
            Some((_, Some(value))) => Var::Set(value),
        }
    }

    #[test]
    fn a_chosen_model_comes_before_the_prompt_in_sweeps_and_fixes() {
        let model: ModelName = "ollama/gemma4:e4b".parse().unwrap();
        let at = Located {
            model: Some(model),
            ..located(Path::new("/bin/x"))
        };
        let bundle = tempfile::tempdir().unwrap();
        for kind in ALL {
            let sweep = words(&kind.sweep_command(&at, bundle.path(), "P").unwrap());
            let fix = words(&kind.fix_command(&at, Path::new("/f"), "P"));
            let start: &[&str] = match kind {
                AgentKind::Codex => &["exec", "--model", "ollama/gemma4:e4b"],
                AgentKind::Opencode => &["run", "--model", "ollama/gemma4:e4b"],
                AgentKind::Claude | AgentKind::Grok | AgentKind::Gemini => {
                    &["--model", "ollama/gemma4:e4b"]
                }
            };
            assert!(
                sweep.iter().take(start.len()).eq(start.iter()),
                "{kind}: {sweep:?}"
            );
            assert!(
                fix.iter().take(start.len()).eq(start.iter()),
                "{kind}: {fix:?}"
            );
        }
        let default = located(Path::new("/bin/x"));
        let sweep = AgentKind::Claude.sweep_command(&default, bundle.path(), "P");
        let args = words(&sweep.unwrap());
        assert!(!args.iter().any(|a| a == "--model"), "{args:?}");
    }

    /// The config name, the binary and the display name are the same word, so a user who
    /// writes `agent = "x"` knows the app runs `x`.
    #[test]
    fn config_name_is_binary_name() {
        for kind in ALL {
            let name = kind.binary();
            let parsed: AgentKind = toml::Value::String(name.into()).try_into().unwrap();
            assert_eq!(parsed, kind);
            assert_eq!(kind.to_string(), name);
        }
    }

    #[test]
    fn fixes_use_the_full_access_flags() {
        let at = located(Path::new("/bin/x"));
        let args = |kind: AgentKind| -> Vec<String> {
            kind.fix_command(&at, Path::new("/f"), "P")
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let expected: [(AgentKind, &[&str]); 5] = [
            (
                AgentKind::Claude,
                &["-p", "P", "--permission-mode", "bypassPermissions"],
            ),
            (
                AgentKind::Grok,
                &[
                    "-p",
                    "P",
                    "--permission-mode",
                    "bypassPermissions",
                    "--cwd",
                    "/f",
                ],
            ),
            (
                AgentKind::Codex,
                &[
                    "exec",
                    "--dangerously-bypass-approvals-and-sandbox",
                    "--skip-git-repo-check",
                    "-C",
                    "/f",
                    "P",
                ],
            ),
            (
                AgentKind::Gemini,
                &["-p", "P", "--approval-mode", "yolo", "--skip-trust"],
            ),
            (
                AgentKind::Opencode,
                &["run", "--dangerously-skip-permissions", "--dir", "/f", "P"],
            ),
        ];
        for (kind, flags) in expected {
            assert_eq!(args(kind), flags, "{kind}");
            let command = kind.fix_command(&at, Path::new("/f"), "P");
            assert_eq!(command.get_current_dir(), Some(Path::new("/f")));
            let config = command
                .get_envs()
                .any(|(k, _)| k == "OPENCODE_CONFIG_CONTENT");
            assert!(!config, "{kind}: no sweep permissions on a fix");
            // A fix keeps the inherited environment, apart from Homebrew's and `PATH`.
            assert_eq!(command.get_envs().count(), 3, "{kind}");
            assert_eq!(var(&command, "PATH"), Var::Set(OsStr::new("/usr/bin:/bin")));
            assert_eq!(
                var(&command, "HOMEBREW_FORBID_PACKAGES_FROM_PATHS"),
                Var::Set(OsStr::new("1"))
            );
            assert_eq!(
                var(&command, "HOMEBREW_INTERNAL_ALLOW_PACKAGES_FROM_PATHS"),
                Var::Removed
            );
        }
    }

    #[test]
    fn sweeps_use_the_restricted_flags() {
        let at = located(Path::new("/bin/x"));
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path();
        let b = bundle.to_str().unwrap();
        let args = |kind: AgentKind| words(&kind.sweep_command(&at, bundle, "P").unwrap());
        let owned =
            |words: &[&str]| -> Vec<String> { words.iter().map(|w| (*w).to_owned()).collect() };

        let mut claude = owned(&[
            "-p",
            "P",
            "--permission-mode",
            "dontAsk",
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--tools",
            "Read,Glob,Grep,Edit,Write",
            "--allowedTools",
            "Read(//**)",
            "Edit(./findings.json)",
            "--disallowedTools",
            "mcp__*",
            "WebFetch",
            "WebSearch",
        ]);
        claude.extend(claude_denied());
        assert_eq!(args(AgentKind::Claude), claude);

        let mut grok = owned(&[
            "-p",
            "P",
            "--permission-mode",
            "default",
            "--sandbox",
            "workspace",
            "--disable-web-search",
            "--no-subagents",
            "--tools",
            "read_file,grep,list_dir,search_replace,write",
            "--disallowed-tools",
            "search_tool,use_tool",
            "--allow",
            "Read(/**)",
            "--allow",
            "Edit(./findings.json)",
            "--deny",
            "Bash",
            "--deny",
            "mcp__*",
        ]);
        grok.extend(grok_denied().flat_map(|rule| ["--deny".to_owned(), rule]));
        grok.extend(owned(&["--cwd", b]));
        assert_eq!(args(AgentKind::Grok), grok);

        assert_eq!(
            args(AgentKind::Codex),
            [
                "exec",
                "--sandbox",
                "workspace-write",
                "--skip-git-repo-check",
                "--ignore-user-config",
                "--ignore-rules",
                "--disable",
                "apps",
                "-c",
                "sandbox_workspace_write.network_access=false",
                "-c",
                r#"web_search="disabled""#,
                "-C",
                b,
                "P"
            ]
        );
        let policy = bundle.join(GEMINI_POLICY);
        assert_eq!(
            args(AgentKind::Gemini),
            [
                "-p",
                "P",
                "--approval-mode",
                "auto_edit",
                "--skip-trust",
                "--extensions",
                "none",
                "--admin-policy",
                policy.to_str().unwrap()
            ]
        );
        assert_eq!(
            args(AgentKind::Opencode),
            ["run", "--pure", "--agent", "vigil-sweep", "--dir", b, "P"]
        );
    }

    #[test]
    fn every_sweep_runs_in_the_bundle_without_full_access() {
        let at = located(Path::new("/bin/x"));
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path();
        for kind in ALL {
            let command = kind.sweep_command(&at, bundle, "P").unwrap();
            assert_eq!(command.get_current_dir(), Some(bundle), "{kind}");
            assert_eq!(
                var(&command, "PATH"),
                Var::Set(OsStr::new("/usr/bin:/bin")),
                "{kind}"
            );
            assert_eq!(
                var(&command, "HOMEBREW_FORBID_PACKAGES_FROM_PATHS"),
                Var::Set(OsStr::new("1")),
                "{kind}"
            );
            for arg in command.get_args() {
                let arg = arg.to_string_lossy();
                assert!(
                    !arg.contains("dangerously") && arg != "--yolo",
                    "{kind}: {arg}"
                );
                assert!(!arg.starts_with("Bash("), "{kind}: no shell command: {arg}");
            }
        }
        let grok = AgentKind::Grok.sweep_command(&at, bundle, "P").unwrap();
        assert_eq!(var(&grok, "GROK_MEMORY"), Var::Set(OsStr::new("0")));
        for name in ["GROK_CLAUDE_HOOKS_ENABLED", "GROK_CURSOR_MCPS_ENABLED"] {
            assert_eq!(var(&grok, name), Var::Set(OsStr::new("false")), "{name}");
        }
    }

    #[test]
    fn credential_paths_are_spelled_for_each_agent() {
        let claude: Vec<String> = claude_denied().collect();
        let grok: Vec<String> = grok_denied().collect();
        let opencode: Vec<String> = opencode_denied().collect();
        // Unanchored, so the home folder's other spellings are covered too.
        for (rules, expected) in [
            (
                &claude,
                ["Read(//**/.ssh)", "Read(//**/.ssh/**)", "Read(//**/.env*)"],
            ),
            (
                &grok,
                ["Read(**/.ssh)", "Read(**/.ssh/**)", "Read(**/.env*)"],
            ),
            (&opencode, ["*/.ssh", "*/.ssh/*", "*/.env*"]),
        ] {
            assert_eq!(rules.len(), 2 * CREDENTIAL_PATHS.len());
            for rule in expected {
                assert!(rules.iter().any(|r| r == rule), "{rule} in {rules:?}");
            }
        }
        for path in [".aws", ".config/gh", "Library/Keychains", ".netrc"] {
            assert!(CREDENTIAL_PATHS.contains(&path), "{path}");
        }
    }

    #[test]
    fn sweeps_inherit_only_the_listed_environment() {
        let inherits = |kind: AgentKind, name: &str| kind.sweep_inherits(OsStr::new(name));
        for kind in ALL {
            for kept in ["HOME", "USER", "LC_ALL", "XDG_CONFIG_HOME"] {
                assert!(inherits(kind, kept), "{kind}: {kept}");
            }
            for dropped in [
                "SSH_AUTH_SOCK",
                "GITHUB_TOKEN",
                "AWS_SECRET_ACCESS_KEY",
                "HOMEBREW_DEVELOPER",
                "NODE_OPTIONS",
                "PATH",
            ] {
                assert!(!inherits(kind, dropped), "{kind}: {dropped}");
            }
        }
        // Each agent gets its own provider's variables, not the others'.
        assert!(inherits(AgentKind::Claude, "ANTHROPIC_API_KEY"));
        assert!(!inherits(AgentKind::Claude, "OPENAI_API_KEY"));
        assert!(!inherits(AgentKind::Codex, "ANTHROPIC_API_KEY"));
        assert!(!inherits(
            AgentKind::Codex,
            "GOOGLE_APPLICATION_CREDENTIALS"
        ));
        assert!(inherits(
            AgentKind::Gemini,
            "GOOGLE_APPLICATION_CREDENTIALS"
        ));
        assert!(inherits(AgentKind::Grok, "XAI_API_KEY"));
        assert!(inherits(AgentKind::Opencode, "ANTHROPIC_API_KEY"));
        // opencode serves every provider, so its list holds every agent's prefixes.
        for kind in ALL {
            for prefix in kind.env_prefixes() {
                assert!(PROVIDER_ENV_PREFIXES.contains(prefix), "{kind}: {prefix}");
            }
        }
        // Cargo sets `CARGO_MANIFEST_DIR` for every test run, and a sweep must not pass it on.
        let at = located(Path::new("/bin/x"));
        let tmp = tempfile::tempdir().unwrap();
        let command = AgentKind::Claude
            .sweep_command(&at, tmp.path(), "P")
            .unwrap();
        assert_eq!(var(&command, "CARGO_MANIFEST_DIR"), Var::Removed);
        assert_eq!(var(&command, "HOME"), Var::Inherited, "inherited as it is");
    }

    #[test]
    fn opencode_runs_its_own_agent_denied_by_default() {
        let at = located(Path::new("/bin/x"));
        let tmp = tempfile::tempdir().unwrap();
        let opencode = AgentKind::Opencode
            .sweep_command(&at, tmp.path(), "P")
            .unwrap();
        let Var::Set(config) = var(&opencode, "OPENCODE_CONFIG_CONTENT") else {
            panic!("a sweep defines its opencode agent");
        };
        let config: serde_json::Value = serde_json::from_str(&config.to_string_lossy()).unwrap();
        let permission = &config["agent"][OPENCODE_SWEEP_AGENT]["permission"];
        assert_eq!(config["agent"][OPENCODE_SWEEP_AGENT]["mode"], "primary");
        assert_eq!(permission["*"], "deny");
        assert_eq!(permission["read"]["*"], "allow");
        assert_eq!(permission["read"]["*/.ssh/*"], "deny");
        assert_eq!(permission["read"]["*/.env*"], "deny");
        assert_eq!(permission["edit"]["findings.json"], "allow");
        assert_eq!(permission["external_directory"], "allow");
        // grep is checked against its pattern, not the files it reads, so it stays denied.
        for tool in ["bash", "grep", "webfetch", "websearch", "task", "skill"] {
            assert!(
                permission.get(tool).is_none(),
                "{tool} falls to \"*\": deny"
            );
        }
        // The last matching rule wins, so each catch-all comes before what it lets through.
        let raw = opencode_sweep_config();
        let first = |object: &str, rule: &str| {
            let inner = &raw[raw.find(object).unwrap()..];
            inner.find(rule).unwrap()
        };
        assert!(first(r#""permission""#, r#""*": "deny""#) < first(r#""permission""#, "read"));
        assert!(first(r#""read""#, r#""*": "allow""#) < first(r#""read""#, ".ssh"));
        assert!(first(r#""edit""#, r#""*": "deny""#) < first(r#""edit""#, "findings.json"));
    }

    #[test]
    fn gemini_gets_its_policy_written_into_the_bundle() {
        let at = located(Path::new("/bin/x"));
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        let policy = bundle.join(GEMINI_POLICY);
        // A link the agent left in place of the policy is replaced, not written through.
        let target = tmp.path().join("zshrc");
        fs::write(&target, "mine").unwrap();
        std::os::unix::fs::symlink(&target, &policy).unwrap();
        AgentKind::Gemini.sweep_command(&at, &bundle, "P").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "mine");
        assert!(!fs::symlink_metadata(&policy).unwrap().is_symlink());

        let rules: toml::Table = fs::read_to_string(&policy).unwrap().parse().unwrap();
        let rules = rules["rule"].as_array().unwrap();
        let denied = rules[0]["toolName"].as_array().unwrap();
        for tool in [
            "run_shell_command",
            "web_fetch",
            "google_web_search",
            "grep_search",
            "read_many_files",
        ] {
            assert!(denied.iter().any(|t| t.as_str() == Some(tool)), "{tool}");
        }
        assert_eq!(rules[1]["mcpName"].as_str(), Some("*"));
        // The credential rule covers every tool, writes included, but only path arguments, so
        // findings.json may still name `~/.ssh/config` in its text.
        assert_eq!(rules[2]["toolName"].as_str(), Some("*"));
        // The pattern escapes only `.` and is written into a TOML literal string.
        let plain = |p: &str| {
            p.trim_end_matches('*')
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        };
        assert!(
            CREDENTIAL_PATHS.iter().all(|p| plain(p)),
            "{CREDENTIAL_PATHS:?}"
        );
        let pattern = rules[2]["argsPattern"].as_str().unwrap();
        assert!(
            pattern.starts_with(
                r#""(?:file_path|dir_path|path|pattern)":"(?:[^"]*/)?(?:\.ssh|\.aws|"#
            ),
            "{pattern}"
        );
        assert!(pattern.contains(r"|Library/Keychains|"), "{pattern}");
        assert!(pattern.contains(r"|\.env|\.git-credentials|"), "{pattern}");
        assert!(
            pattern.ends_with(r"|\.local/share/opencode/auth\.json)"),
            "{pattern}"
        );
        for rule in rules {
            assert_eq!(rule["decision"].as_str(), Some("deny"));
        }

        let missing = tmp.path().join("missing");
        let err = AgentKind::Gemini
            .sweep_command(&at, &missing, "P")
            .unwrap_err();
        assert!(matches!(err, AgentError::Policy { .. }), "{err:?}");
    }

    #[test]
    fn reads_only_the_marked_answer() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = script(tmp.path(), "claude", "true");
        let answer = |binary: &str| {
            format!(
                "Welcome! /usr/bin/evil\n{PATH_MARK}\n/a:/b\n{BINARY_MARK}\n{binary}\n{END_MARK}\n\
                 /usr/bin/also-evil\n"
            )
        };
        let found = parse_located(&answer(agent.to_str().unwrap()), None).unwrap();
        assert_eq!(found.binary, agent);
        assert_eq!(found.path, OsString::from("/a:/b"));
        assert_eq!(found.model, None);
        let opus: ModelName = "opus".parse().unwrap();
        let found = parse_located(&answer(agent.to_str().unwrap()), Some(&opus)).unwrap();
        assert_eq!(
            found.model,
            Some(opus),
            "the configured model reaches the agent"
        );

        // An alias, a function, a missing file and a file that cannot run are not agents.
        assert!(parse_located(&answer("alias claude='rm -rf ~'"), None).is_none());
        assert!(parse_located(&answer("/nonexistent/claude"), None).is_none());
        let plain = tmp.path().join("plain");
        fs::write(&plain, "").unwrap();
        assert!(parse_located(&answer(plain.to_str().unwrap()), None).is_none());
        assert!(parse_located(&answer(tmp.path().to_str().unwrap()), None).is_none());
        // `command -v` printed nothing: the next mark follows at once.
        let none = format!("{PATH_MARK}\n/a\n{BINARY_MARK}\n{END_MARK}\n");
        assert!(parse_located(&none, None).is_none());
        assert!(parse_located("no marks at all", None).is_none());
        // Each mark must be exactly where it belongs, even around a real executable.
        let agent = agent.to_str().unwrap();
        let no_path = format!("{PATH_MARK}\n{BINARY_MARK}\n{agent}\n{END_MARK}\n");
        assert!(parse_located(&no_path, None).is_none());
        let extra = format!("{PATH_MARK}\n/a\n{BINARY_MARK}\n{agent}\nmore\n{END_MARK}\n");
        assert!(parse_located(&extra, None).is_none());

        // Entries that would look commands up in the working folder are dropped.
        let relative =
            format!("{PATH_MARK}\n:/a::.:bin:./x:/b:\n{BINARY_MARK}\n{agent}\n{END_MARK}\n");
        let found = parse_located(&relative, None).unwrap();
        assert_eq!(found.path, OsString::from("/a:/b"));
    }

    #[test]
    fn an_interactive_shell_noise_around_the_answer_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = script(tmp.path(), "claude", "true");
        let agent = agent.to_str().unwrap();
        // A prompt theme's escape codes without a newline end up on the mark's line; a
        // `.zlogout` prints after the answer.
        let noisy = format!(
            "Unable to locate a Java Runtime.\n\x1b[?1h\x1b={PATH_MARK}\r\n/a:/b\n\
             {BINARY_MARK}\n{agent}\n{END_MARK}\n\x1b]0;~\x07bye\n"
        );
        let found = parse_located(&noisy, None).unwrap();
        assert_eq!(found.binary, Path::new(agent));
        assert_eq!(found.path, OsString::from("/a:/b"));

        let after_mark = format!("{PATH_MARK}x\n/a\n{BINARY_MARK}\n{agent}\n{END_MARK}\n");
        assert!(
            parse_located(&after_mark, None).is_none(),
            "text after the mark is not the mark"
        );
    }

    #[test]
    fn run_logs_output_and_reports_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let ok = script(
            tmp.path(),
            "ok",
            "pwd; echo \"PATH=$PATH\"; echo \"$@\"; echo oops >&2; \
             echo \"MANIFEST=${CARGO_MANIFEST_DIR-unset}\"",
        );
        let log = tmp.path().join("agent.log");
        let sweep = |binary: &Path| {
            AgentKind::Gemini
                .sweep_command(&located(binary), tmp.path(), "P")
                .unwrap()
        };
        AgentKind::Gemini
            .run(&sweep(&ok), &log, &Cancel::new())
            .unwrap();
        let text = fs::read_to_string(&log).unwrap();
        let bundle = tmp.path().canonicalize().unwrap();
        assert!(text.contains(bundle.to_str().unwrap()), "{text}");
        assert!(text.contains("PATH=/usr/bin:/bin"), "{text}");
        assert!(text.contains("-p P --approval-mode auto_edit"), "{text}");
        assert!(text.contains("oops"), "{text}");
        assert!(
            text.contains("MANIFEST=unset"),
            "the variables a sweep drops are gone through the watchdog too: {text}"
        );

        let fail = script(tmp.path(), "fail", "exit 3");
        let status = AgentKind::Gemini
            .run(&sweep(&fail), &log, &Cancel::new())
            .unwrap();
        assert_eq!(status.code(), Some(3));

        let missing = tmp.path().join("missing");
        let err = AgentKind::Gemini
            .run(&sweep(&missing), &log, &Cancel::new())
            .unwrap_err();
        assert!(matches!(err, AgentError::Start { .. }), "{err:?}");
    }

    #[test]
    fn an_agent_that_leaves_a_fifo_for_its_log_does_not_hang_the_run() {
        let tmp = tempfile::tempdir().unwrap();
        let swap = script(
            tmp.path(),
            "swap",
            "rm -f agent.log && /usr/bin/mkfifo agent.log",
        );
        // So a regression to a blocking open cannot hang this test; the link tests of the
        // regular-file open catch it instead.
        paths::release_fifo(&tmp.path().join("agent.log"));
        let status = AgentKind::Claude
            .run(
                &AgentKind::Claude.fix_command(&located(&swap), tmp.path(), "P"),
                &tmp.path().join("agent.log"),
                &Cancel::new(),
            )
            .unwrap();
        assert_eq!(status.code(), Some(0), "it ran, and the run returned");
    }

    #[test]
    fn only_the_head_of_a_log_is_read() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("agent.log");
        fs::write(&log, vec![b'a'; 3 * 4096]).unwrap();
        assert_eq!(log_head(&log).len(), 4096);
        fs::write(&log, "short").unwrap();
        assert_eq!(log_head(&log), b"short");
        assert_eq!(log_head(&tmp.path().join("missing")), b"");

        // A link left in place of the log is not read at all, and a FIFO without waiting. The
        // link comes first: an open without the flags follows it and fails here at once,
        // instead of hanging on the FIFO.
        let link = tmp.path().join("link.log");
        std::os::unix::fs::symlink(&log, &link).unwrap();
        assert_eq!(log_head(&link), b"");
        let fifo = tmp.path().join("fifo.log");
        paths::releasing_fifo(&fifo);
        assert_eq!(log_head(&fifo), b"");
    }
}
