import type { Severity } from "./overview.ts";

/** A severity's glyph: each level has its own shape and colour, so it reads without hue. */
export function Glyph(props: { severity: Severity }) {
  return (
    <svg class={`sev ${props.severity}`} viewBox="0 0 14 14" role="img" aria-label={props.severity}>
      {props.severity === "critical" ? (
        <>
          <path d="M7 1.2 13 12.3H1z" fill="currentColor" />
          <path
            d="M7 5.2v3.2M7 10.1v.1"
            stroke="#1a0d0d"
            stroke-width="1.5"
            stroke-linecap="round"
          />
        </>
      ) : props.severity === "high" ? (
        <path d="M7 1 13 7 7 13 1 7z" fill="currentColor" />
      ) : props.severity === "medium" ? (
        <>
          <circle cx="7" cy="7" r="5.2" fill="none" stroke="currentColor" stroke-width="2" />
          <path d="M7 1.8a5.2 5.2 0 0 1 0 10.4z" fill="currentColor" />
        </>
      ) : (
        <circle cx="7" cy="7" r="4.6" fill="none" stroke="currentColor" stroke-width="1.6" />
      )}
    </svg>
  );
}

export type IconName =
  | "sweep"
  | "wrench"
  | "mac"
  | "repo"
  | "server"
  | "settings"
  | "check"
  | "done"
  | "partial"
  | "failed"
  | "wait"
  | "chev"
  | "agent"
  | "clock"
  | "key"
  | "folder"
  | "plus"
  | "lock"
  | "doc"
  | "shield";

const PATHS: Record<IconName, string> = {
  sweep: "M13.5 8A5.5 5.5 0 1 1 11.9 4.1M13.5 2.5v3h-3",
  wrench:
    "M10.1 1.6a4 4 0 0 0-4.3 5.3L1.7 11a1.6 1.6 0 0 0 2.3 2.3l4.1-4.1a4 4 0 0 0 5.3-4.3L11.2 7.2 9.2 6.8 8.8 4.8z",
  mac: "M3 3.5h10a1.5 1.5 0 0 1 1.5 1.5v5.5A1.5 1.5 0 0 1 13 12H3a1.5 1.5 0 0 1-1.5-1.5V5A1.5 1.5 0 0 1 3 3.5zM5.5 14h5",
  repo: "M3.5 2.5h8a1 1 0 0 1 1 1v9.5h-8.5a1.5 1.5 0 0 1 0-3h8.5M3.5 2.5v9",
  server:
    "M3 2.5h10a1 1 0 0 1 1 1V6a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1zM3 9h10a1 1 0 0 1 1 1v2.5a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V10a1 1 0 0 1 1-1z",
  // Two sliders, the settings mark of most current apps; a small cog read as a sun.
  settings:
    "M2 4.5h6.5M12.5 4.5H14M2 11.5h1.5M7.5 11.5H14M10.5 3a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zM5.5 10a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z",
  check: "M3.5 8.4 6.6 11.4 12.5 4.8",
  done: "M5 8.2 7.1 10.2 11 5.9",
  // A fix's end states beside done, on the same tinted disc: half done, and not done.
  partial: "M5.2 8h5.6",
  failed: "M5.8 5.8l4.4 4.4M10.2 5.8l-4.4 4.4",
  wait: "M8 2.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11z",
  chev: "M10 3.5 5.5 8l4.5 4.5",
  agent: "M2.5 4.5 6 8l-3.5 3.5M8 12h5.5",
  clock: "M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2zM8 4.8V8l2.3 1.6",
  key: "M5.5 4.3a2.9 2.9 0 1 0 0 5.8 2.9 2.9 0 0 0 0-5.8zM8.4 7.2h6M12.4 7.2v2.4M14.4 7.2v1.8",
  folder: "M2 4.2a1 1 0 0 1 1-1h3.2l1.5 1.6H13a1 1 0 0 1 1 1v6.4a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z",
  plus: "M8 3v10M3 8h10",
  lock: "M4.5 7.5h7a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1zM5.5 7.5V5.3a2.5 2.5 0 0 1 5 0v2.2",
  doc: "M4 1.8h5.2L12.5 5v8.2a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2.8a1 1 0 0 1 1-1zM9 1.8V5h3.5M5.5 8.5h5M5.5 11h3.5",
  shield:
    "M8 1.6 13.2 3.5v4.1c0 3.2-2.2 5.6-5.2 6.8-3-1.2-5.2-3.6-5.2-6.8V3.5zM5.6 8l1.7 1.7 3.2-3.4",
};

/** The marks drawn on a disc tinted with their own colour. */
const DISCS: ReadonlySet<IconName> = new Set(["done", "partial", "failed"]);

/** A line icon, drawn in the current text colour. */
export function Icon(props: { name: IconName }) {
  return (
    <svg class={`icon ${props.name}`} viewBox="0 0 16 16" aria-hidden="true">
      {DISCS.has(props.name) ? <circle cx="8" cy="8" r="6.5" class="disc" /> : null}
      <path d={PATHS[props.name]} />
    </svg>
  );
}
