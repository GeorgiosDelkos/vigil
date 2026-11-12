import { Show } from "solid-js";

import type { UpdateView } from "./overview.ts";
import { ago } from "./time.ts";

/** The popover's line once an update is downloaded and verified. The button waits while a sweep
 * or fix runs, and Rust refuses it then too: an update never installs during a run, and only
 * this click restarts the app (the owner's decision, 2026-11-12). */
export function UpdateReady(props: { version: string; busy: boolean; onRestart: () => void }) {
  return (
    <div class="banner good update">
      <span>
        Update ready: Vigil {props.version}
        <Show when={props.busy}> · after this run ends</Show>
      </span>
      <button
        type="button"
        class="btn small primary x"
        disabled={props.busy}
        onClick={() => props.onRestart()}
      >
        Restart to update
      </button>
    </div>
  );
}

/** The version and the last update check, quietly, at the bottom of the settings. */
export function UpdateAbout(props: { update: UpdateView; now: Date }) {
  const checked = () => props.update.checked;
  return (
    <p class="note about">
      Vigil {props.update.version}
      {" · "}
      <Show
        when={props.update.checks}
        fallback="this build does not check for updates; installed releases do"
      >
        <Show when={checked()} fallback="checks for updates at start and every 12 hours">
          {(at) => `checked for updates ${ago(at(), props.now)}`}
        </Show>
      </Show>
      <Show when={props.update.problem}>
        {(problem) => <span class="about-problem">{problem()}</span>}
      </Show>
    </p>
  );
}
