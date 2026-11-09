// The shapes the app's commands return (app/src-tauri/src/main.rs, runner.rs and the core's
// popover.rs). Everything here is worked out in Rust; the UI only lays it out.

export type Severity = "critical" | "high" | "medium" | "low";

/** The severities in the order the popover lists them. */
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

export type Counts = Readonly<Record<Severity, number>>;

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
  | { readonly state: "fixing"; readonly title: string }
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
  readonly target: string;
  readonly needs_you: boolean;
};

export type TargetLine = {
  readonly label: string;
  readonly kind: "mac" | "repo" | "server";
  readonly swept: string | null;
  readonly components: number;
  readonly counts: Counts;
  readonly open: number;
  readonly dismissed: number;
};

export type Overview = {
  readonly status: Status;
  readonly busy: boolean;
  readonly findings: readonly Listed[];
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
