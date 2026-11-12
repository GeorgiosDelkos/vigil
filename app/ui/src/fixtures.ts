// Command results for the component tests, shaped as the Rust commands return them.

import type { Finding, Listed, Overview } from "./overview.ts";
import type { SettingsView } from "./settings.ts";

export function settingsView(changes: Partial<SettingsView> = {}): SettingsView {
  return {
    headline: "1 setting needs you",
    ready: false,
    groups: [
      {
        title: "Sweeps",
        sections: [
          { id: "agent", title: "Agent", summary: "Choose one", attention: true },
          { id: "schedule", title: "Schedule", summary: "Manual", attention: false },
        ],
      },
      {
        title: "Targets",
        sections: [
          { id: "mac", title: "This Mac", summary: "1 folder", attention: false },
          { id: "github", title: "GitHub", summary: "0 repositories", attention: false },
          { id: "servers", title: "Servers", summary: "0 servers", attention: false },
        ],
      },
      {
        title: "Advisories",
        sections: [{ id: "nvd", title: "NVD key", summary: "Not set", attention: false }],
      },
    ],
    agents: [
      { agent: "claude", name: "Claude Code", path: "/bin/claude", available: true, chosen: false },
      { agent: "codex", name: "Codex", path: null, available: false, chosen: false },
    ],
    model: null,
    schedule: { automatic: false, hours: 6, all_history: true, since: "2025-01-01" },
    folders: [
      { value: "~/code", chosen: true },
      { value: "~/src", chosen: false },
    ],
    tools: [{ name: "Homebrew", path: "/opt/homebrew/bin/brew" }],
    gh_login: "me",
    repos: [
      { repo: "me/app", private: true, chosen: true },
      { repo: "me/site", private: false, chosen: false },
    ],
    servers: [],
    hosts: [
      { alias: "web", host_name: "10.0.0.5", addable: true },
      { alias: "bad host", host_name: null, addable: false },
    ],
    nvd_key: false,
    nvd_rates: [
      { label: "Without a key", per_30_seconds: 5, applies: true },
      { label: "With a key", per_30_seconds: 50, applies: false },
    ],
    ...changes,
  };
}

/** One open finding, as Rust's `Open` serializes it. */
export function advisory(key: string, changes: Partial<Finding> = {}): Finding {
  return {
    key,
    severity: "high",
    title: `title ${key}`,
    name: `pkg-${key}`,
    version: "1.0.0",
    advisories: [`GHSA-${key}`],
    place: "/Users/me/code/app/package-lock.json",
    known_exploited: false,
    evidence: "1.0.0 is in the affected range.",
    explanation: "Reachable from the app.",
    fix: "Update to 1.0.1",
    commands: ["npm install pkg@1.0.1"],
    first_seen: "2026-11-06T10:00:00Z",
    new: false,
    fix_state: null,
    ...changes,
  };
}

/** An item: a component holding `findings`, the first its lead. Its own values default to the
 * lead's; a test that ranks or counts sets them, as Rust would work them out. */
export function component(
  id: string,
  findings: readonly [Finding, ...Finding[]],
  changes: Partial<Listed> = {},
): Listed {
  const [lead, ...others] = findings;
  const grouped = others.length > 0;
  return {
    id,
    target: "This Mac",
    target_key: "mac",
    name: lead.name,
    lead,
    others,
    severity: lead.severity,
    known_exploited: lead.known_exploited,
    needs_you: true,
    first_seen: lead.first_seen,
    new: lead.new,
    advisory_count: grouped ? `${findings.length} advisories` : null,
    fix_scope: grouped
      ? `This fix is for the component, ${changes.name ?? lead.name} ${lead.version ?? ""}, which all ${findings.length} advisories are in; the next sweep checks each of them again.`
      : null,
    pending_fix: null,
    ...changes,
  };
}

/** An item of one finding, `key`, with the finding's and the item's own changes. */
export function finding(
  key: string,
  changes: Partial<Finding> & Partial<Pick<Listed, "target" | "target_key" | "needs_you">> = {},
): Listed {
  const { target = "This Mac", target_key = "mac", needs_you = true, ...rest } = changes;
  return component(key, [advisory(key, rest)], { target, target_key, needs_you });
}

export function overview(changes: Partial<Overview> = {}): Overview {
  return {
    status: { state: "idle" },
    busy: false,
    items: [],
    list_tab: "needs",
    to_confirm: null,
    reported: [],
    needs_you: 0,
    exploited: 0,
    counts: { critical: 0, high: 0, medium: 0, low: 0 },
    headline: "All clear",
    last_swept: null,
    first_sweep_hint: "Sweep checks your targets against the newest advisories.",
    all_clear: false,
    fixed: [],
    target_count: "1 target",
    targets: [
      {
        key: "mac",
        label: "This Mac",
        kind: "mac",
        swept: null,
        checked: null,
        counts: { critical: 0, high: 0, medium: 0, low: 0 },
        open: 0,
        to_confirm: null,
        fix_all: null,
        dismissed: 0,
      },
    ],
    dismissed: 0,
    agent: "Claude Code",
    schedule: "manual",
    config: "/Users/me/Library/Application Support/io.github.georgiosdelkos.vigil/config.toml",
    problem: null,
    disk: null,
    update: { version: "0.1.0", checks: true, checked: null, problem: null, ready: null },
    ...changes,
  };
}
