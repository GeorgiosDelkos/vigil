// Command results for the component tests, shaped as the Rust commands return them.

import type { Listed, Overview } from "./overview.ts";
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

export function finding(key: string, changes: Partial<Listed> = {}): Listed {
  return {
    key,
    severity: "high",
    title: `title ${key}`,
    name: `pkg-${key}`,
    version: "1.0.0",
    advisories: [`GHSA-${key}`],
    place: "/Users/me/code/app/package-lock.json",
    known_exploited: false,
    explanation: "Reachable from the app.",
    fix: "Update to 1.0.1",
    commands: ["npm install pkg@1.0.1"],
    first_seen: "2026-11-06T10:00:00Z",
    new: false,
    fix_state: null,
    target: "This Mac",
    needs_you: true,
    ...changes,
  };
}

export function overview(changes: Partial<Overview> = {}): Overview {
  return {
    status: { state: "idle" },
    busy: false,
    findings: [],
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
        label: "This Mac",
        kind: "mac",
        swept: null,
        checked: null,
        counts: { critical: 0, high: 0, medium: 0, low: 0 },
        open: 0,
        dismissed: 0,
      },
    ],
    dismissed: 0,
    agent: "Claude Code",
    schedule: "manual",
    config: "/Users/me/Library/Application Support/io.github.georgiosdelkos.vigil/config.toml",
    problem: null,
    ...changes,
  };
}
