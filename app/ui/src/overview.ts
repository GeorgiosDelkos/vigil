// The shapes the app's commands return (app/src-tauri/src/main.rs, runner.rs and the core's
// popover.rs). Everything here is worked out in Rust; the UI only lays it out.

export type Severity = "critical" | "high" | "medium" | "low";

/** The severities in the order the popover lists them. */
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

export type Counts = Readonly<Record<Severity, number>>;

export type FixStep = {
  readonly label: string;
  readonly state: "done" | "now" | "next";
};

export type Status =
  | { readonly state: "idle" }
  | {
      readonly state: "sweeping";
      readonly step: string;
      readonly current: string | null;
      readonly done: readonly string[];
      readonly pending: readonly string[];
      readonly position: number;
      readonly total: number;
      /** How far the whole sweep is, 0 to 100. */
      readonly percent: number;
      /** Where the current target's share of the bar ends, 0 to 100. */
      readonly target_end: number;
      /** Where the bar marks the boundaries between targets, 0 to 100. */
      readonly ticks: readonly number[];
      /** The current step has no known length (the agent is running). */
      readonly open_ended: boolean;
      /** The user cancelled it, and it is stopping its agent and cleaning up. */
      readonly stopping: boolean;
      readonly started: string;
      readonly step_started: string;
    }
  | {
      readonly state: "fixing";
      readonly title: string;
      /** Its target's name: "This Mac", `owner/name`, the server. */
      readonly place: string;
      /** Every step of the fix in order, as Rust places them. */
      readonly steps: readonly FixStep[];
      /** The agent's last line of output while it runs. */
      readonly activity: string | null;
      readonly started: string;
      readonly step_started: string;
    }
  | { readonly state: "failed"; readonly error: string };

export type Listed = {
  readonly key: string;
  readonly severity: Severity;
  readonly title: string;
  readonly name: string;
  readonly version: string | null;
  readonly advisories: readonly string[];
  readonly place: string;
  readonly known_exploited: boolean;
  readonly explanation: string;
  readonly fix: string;
  readonly commands: readonly string[];
  readonly first_seen: string | null;
  readonly new: boolean;
  readonly fix_state: FixState | null;
  readonly target: string;
  readonly needs_you: boolean;
};

export type TargetLine = {
  readonly label: string;
  readonly kind: "mac" | "repo" | "server";
  readonly swept: string | null;
  /** What its last sweep checked ("139 components checked"); null before a sweep. */
  readonly checked: string | null;
  readonly counts: Counts;
  readonly open: number;
  readonly dismissed: number;
};

/** What the fix history says about an open finding. */
export type FixState =
  | {
      readonly state: "reported";
      readonly at: string;
      readonly summary: string;
      readonly pull_request: string | null;
    }
  | { readonly state: "not_held"; readonly at: string };

/** A fix a later sweep confirmed, from the last 30 days. */
export type FixedItem = {
  readonly key: string;
  readonly title: string;
  readonly target: string;
  readonly fixed_at: string;
  readonly summary: string;
  readonly pull_request: string | null;
};

export type Overview = {
  readonly status: Status;
  readonly busy: boolean;
  readonly findings: readonly Listed[];
  /** Fixes a later sweep confirmed that finished in the last 30 days, newest first. */
  readonly fixed: readonly FixedItem[];
  readonly needs_you: number;
  readonly exploited: number;
  readonly counts: Counts;
  readonly headline: string;
  readonly last_swept: string | null;
  readonly first_sweep_hint: string | null;
  readonly all_clear: boolean;
  readonly target_count: string;
  readonly targets: readonly TargetLine[];
  readonly dismissed: number;
  readonly agent: string | null;
  readonly schedule: string;
  readonly config: string;
  readonly problem: string | null;
};

export type FixPreview = {
  readonly destination: string;
  readonly found: string;
  readonly summary: string;
  readonly steps: readonly string[];
  readonly commands: readonly string[];
  readonly agent: string;
};

export type FixDone = {
  readonly key: string;
  readonly outcome: string;
  readonly summary: string;
  readonly pull_request: string | null;
};
