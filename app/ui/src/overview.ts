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
  | FixedStatus
  /** What failed and why, one line as Rust words it: "Last sweep: ..." or "Last fix: ...". */
  | { readonly state: "failed"; readonly error: string };

/** A fix's results, which stay until the user closes them (the owner's decision,
 * 2026-11-11). */
export type FixedStatus = {
  readonly state: "fixed";
  readonly title: string;
  readonly place: string;
  /** One row per item, in the order they ran. */
  readonly items: readonly FixRunItem[];
  /** The line at the bottom: "5 of 9 fixed · 4 partial". */
  readonly summary: string;
  readonly finished: string;
};

/** One open finding or issue (the core's `Open`). */
export type Finding = {
  readonly key: string;
  readonly severity: Severity;
  readonly title: string;
  readonly name: string;
  readonly version: string | null;
  readonly advisories: readonly string[];
  readonly place: string;
  readonly known_exploited: boolean;
  readonly evidence: string;
  readonly explanation: string;
  readonly fix: string;
  readonly commands: readonly string[];
  readonly first_seen: string | null;
  readonly new: boolean;
  readonly fix_state: FixState | null;
};

/** One item of the list: an installed component with its open findings, or an issue. The
 * lead's version, place and fix are the item's, and Fix runs the lead's key. */
export type Listed = {
  /** Its id in the list; it stays while findings in it are dismissed. */
  readonly id: string;
  readonly target: string;
  /** Its target line's `key`. */
  readonly target_key: string;
  /** The component's name (a Homebrew formula's own, which can hold several products), or the
   * issue's subject. */
  readonly name: string;
  readonly lead: Finding;
  /** The other findings in the same component, ranked; empty for an issue. */
  readonly others: readonly Finding[];
  /** The worst severity of its findings. */
  readonly severity: Severity;
  /** Whether any of its findings is exploited in the wild. */
  readonly known_exploited: boolean;
  readonly needs_you: boolean;
  /** When any of its findings was first found. */
  readonly first_seen: string | null;
  readonly new: boolean;
  /** "33 advisories" when it holds more than one finding. */
  readonly advisory_count: string | null;
  /** What the Fix confirmation adds when it holds more than one finding. */
  readonly fix_scope: string | null;
  /** What keeps a fix of it from counting as done, decided over all its findings. */
  readonly pending_fix: PendingFix | null;
};

/** A fix that did not hold, or one whose pull request is not merged yet. */
export type PendingFix = "not_held" | "pull_request";

export type TargetLine = {
  /** The target as configured (`mac`, `github:owner/name`); its items carry it as
   * `target_key`. Labels can repeat across targets, keys cannot. */
  readonly key: string;
  readonly label: string;
  readonly kind: "mac" | "repo" | "server";
  readonly swept: string | null;
  /** What its last sweep checked ("139 components checked"); null before a sweep. */
  readonly checked: string | null;
  readonly counts: Counts;
  readonly open: number;
  /** "1 fix to confirm" when fixes of its items wait for the next sweep. */
  readonly to_confirm: string | null;
  readonly dismissed: number;
  /** "Fix all 3" when Fix all takes two or more of its open items; null hides the button. */
  readonly fix_all: string | null;
  /** Why what it shows may be incomplete: sources that failed in its newest sweep, or files
   * Rust could not read. Null when neither. */
  readonly warning: string | null;
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

/** An item whose fix the agent reported done, which the next sweep confirms (the core's
 * `ReportedFix`). It is not open, so nothing counts it. */
export type ReportedFix = {
  readonly item: Listed;
  /** What its row says: "Fixed · the next sweep confirms it". */
  readonly status: string;
  readonly summary: string;
  readonly fixed_at: string;
};

/** The startup disk (the core's `Disk`): its name, size and how much is used and free. */
export type Disk = {
  readonly name: string;
  /** The size for display: "245 GB". */
  readonly size: string;
  /** The row in words: "Macintosh HD: 28 GB free of 245 GB". */
  readonly label: string;
  /** From 0 to 100; with `free_percent` it makes 100. */
  readonly used_percent: number;
  readonly free_percent: number;
};

export type Overview = {
  readonly status: Status;
  readonly busy: boolean;
  /** The open items, ranked by risk. */
  readonly items: readonly Listed[];
  /** The list tab the main view's centre opens. */
  readonly list_tab: "needs" | "fixed";
  /** The centre's number and words when nothing is open but fixes wait for the next sweep. */
  readonly to_confirm: { readonly count: number; readonly label: string } | null;
  /** Items whose fix was reported, newest fix first. */
  readonly reported: readonly ReportedFix[];
  /** Fixes a later sweep confirmed that finished in the last 30 days, newest first. */
  readonly fixed: readonly FixedItem[];
  readonly needs_you: number;
  readonly exploited: number;
  readonly counts: Counts;
  readonly headline: string;
  readonly last_swept: string | null;
  readonly first_sweep_hint: string | null;
  readonly all_clear: boolean;
  /** One line naming each target with a warning, and the warning; null when none has. */
  readonly warning: string | null;
  readonly target_count: string;
  readonly targets: readonly TargetLine[];
  readonly dismissed: number;
  readonly agent: string | null;
  readonly schedule: string;
  readonly config: string;
  readonly problem: string | null;
  /** Null when Rust could not read the disk; the main view then has no disk row. */
  readonly disk: Disk | null;
  readonly update: UpdateView;
};

/** The running version and the app's updates (app/src-tauri/src/update.rs). */
export type UpdateView = {
  /** The running version: "0.1.0". */
  readonly version: string;
  /** Whether this build checks for updates: only an installed release does. */
  readonly checks: boolean;
  /** When the last check ended. */
  readonly checked: string | null;
  /** Why the last check or install failed, one line as Rust words it. */
  readonly problem: string | null;
  /** The version downloaded and verified, waiting for Restart to update. */
  readonly ready: string | null;
};

/** What the single fix's confirmation shows: everything the agent is told the user confirmed. */
export type FixPreview = {
  /** The number `fix` takes to run exactly the plan shown. */
  readonly preview: number;
  readonly destination: string;
  readonly found: string;
  readonly summary: string;
  readonly steps: readonly string[];
  readonly commands: readonly string[];
  readonly agent: string;
  /** What to read before confirming, one sentence each, in Rust's words. */
  readonly notes: readonly string[];
};

/** One item of a Fix all, with its fix as the single-item preview shows one. */
export type FixAllPreviewItem = {
  readonly key: string;
  /** "curl 8.1.2", or an issue's subject. */
  readonly name: string;
  readonly summary: string;
  readonly steps: readonly string[];
  readonly commands: readonly string[];
};

/** What a target's screen asks before a Fix all: every item's fix, for one confirmation. */
export type FixAllPreview = {
  /** The number `fix` takes to run exactly the plan shown. */
  readonly preview: number;
  readonly destination: string;
  readonly found: string;
  readonly agent: string;
  /** The confirming button's label: "Fix all 3". */
  readonly confirm: string;
  readonly items: readonly FixAllPreviewItem[];
  /** What to read before confirming, one sentence each, in Rust's words. */
  readonly notes: readonly string[];
};

/** How one item of a finished fix ended (the core's `FixRunItem`). */
export type FixRunItem = {
  /** A Fix all item's name ("curl 8.1.2"), or a single fix's finding title. */
  readonly name: string;
  /** `unknown` also when the agent reported fixed but did not exit 0. */
  readonly state: "fixed" | "partial" | "failed" | "unknown";
  /** The state in a word: "fixed", "partial", "failed", "no result". */
  readonly state_label: string;
  /** The agent's summary, or why there is none: untrusted text, only shown. */
  readonly summary: string;
  readonly pull_request: string | null;
};

/** The end of a finished fix's agent log (the core's `LogTail`). */
export type LogTail = {
  /** Plain lines of the agent's output: untrusted text, only shown. */
  readonly text: string;
  /** That only the end is shown, or that the log is empty. */
  readonly note: string | null;
};
