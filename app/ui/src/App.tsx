import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  For,
  Match,
  Show,
  Switch,
  createEffect,
  createMemo,
  createResource,
  createSignal,
  on,
  onCleanup,
  onMount,
} from "solid-js";

import {
  SEVERITIES,
  type Finding,
  type FixedItem,
  type FixedStatus,
  type FixRunItem,
  type FixState,
  type FixAllPreview,
  type FixPreview,
  type Listed,
  type LogTail,
  type Overview,
  type PendingFix,
  type ReportedFix,
  type Severity,
  type Status,
  type TargetLine,
} from "./overview.ts";
import { Menu } from "./Menu.tsx";
import { Orbit, TargetFigures } from "./Orbit.tsx";
import { Settings } from "./Settings.tsx";
import type { Section } from "./settings.ts";
import { Glyph, Icon, type IconName } from "./icons.tsx";
import { ago, since } from "./time.ts";
import { UpdateReady } from "./Update.tsx";

type Tab = "needs" | "targets" | "all" | "fixed";

/** The main view, or the list behind it. */
type Screen = "orbit" | "list";

/** What the popover shows, in the order it decides. */
type View =
  | "settings"
  | "fixing"
  | "results"
  | "detail"
  | "target"
  | "orbit"
  | "busy"
  | "problem"
  | "agent"
  | "clear"
  | "list";

function viewOf(
  o: Overview,
  open: { settings: boolean; detail: boolean; target: boolean; screen: Screen },
): View {
  if (open.settings) {
    return "settings";
  }
  // Once a fix starts, its steps replace the confirmation, whatever is selected.
  if (o.status.state === "fixing") {
    return "fixing";
  }
  // Its results then stay until closed, over the screen it was started from.
  if (o.status.state === "fixed") {
    return "results";
  }
  if (open.detail) {
    return "detail";
  }
  // A target's findings cover the screen it was opened from, which Back returns to.
  return open.target ? "target" : screenOf(o, open.screen);
}

/** The main view or the list, unless a problem stops sweeps; a running sweep shows either. */
function screenOf(o: Overview, screen: Screen): View {
  const blocked = blocker(o);
  if (screen === "orbit" && (o.busy || blocked === null)) {
    return "orbit";
  }
  if (o.busy) {
    return "busy";
  }
  return blocked ?? (o.all_clear ? "clear" : "list");
}

/** The last fix's results, while they show. */
function fixedOf(o: Overview): FixedStatus | null {
  return o.status.state === "fixed" ? o.status : null;
}

/** What stops a sweep before it starts: settings Rust cannot read, or no agent. */
function blocker(o: Overview): "problem" | "agent" | null {
  if (o.problem !== null && o.targets.length === 0) {
    return "problem";
  }
  return o.agent === null ? "agent" : null;
}

export function App() {
  const [overview, { refetch }] = createResource(() => invoke<Overview>("overview"));
  const [now, setNow] = createSignal(new Date());
  const [screen, setScreen] = createSignal<Screen>("orbit");
  const [tab, setTab] = createSignal<Tab>("needs");
  const [selected, setSelected] = createSignal<string | null>(null);
  // The key of the target whose findings show, over the main view or the list.
  const [targetKey, setTargetKey] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  // Settings open in the popover, at a section or at the list; `undefined` when closed.
  const [settings, setSettings] = createSignal<Section | null | undefined>(undefined);

  // Registered synchronously, so Solid runs the cleanups; the listeners resolve later.
  const unlisten: Promise<() => void>[] = [
    listen("changed", () => {
      setNow(new Date());
      void refetch();
    }),
  ];
  onCleanup(() => {
    for (const u of unlisten) {
      void u.then((stop) => stop());
    }
  });
  const tick = setInterval(() => setNow(new Date()), 30_000);
  onCleanup(() => clearInterval(tick));
  // A fix's agent reports nothing until it ends, so while one runs the popover asks Rust again
  // every few seconds, for the agent's latest line and the elapsed time.
  const poll = setInterval(() => {
    if (overview()?.status.state === "fixing") {
      setNow(new Date());
      void refetch();
    }
  }, 4_000);
  onCleanup(() => clearInterval(poll));

  const listed = () => overview()?.items ?? [];
  const chosen = createMemo(() => listed().find((o) => o.id === selected()) ?? null);
  const target = createMemo(() => overview()?.targets.find((t) => t.key === targetKey()) ?? null);

  const run = (action: () => Promise<unknown>) => {
    setError(null);
    action().catch((e: unknown) => setError(String(e)));
  };
  const view = () => {
    const o = overview();
    return o === undefined
      ? null
      : viewOf(o, {
          settings: settings() !== undefined,
          detail: chosen() !== null,
          target: target() !== null,
          screen: screen(),
        });
  };
  // A fix that starts clears an older error, so none sits over its steps or results.
  createEffect(on(view, (shows, was) => shows === "fixing" && was !== shows && setError(null)));
  const list = (at: Tab) => {
    setTab(at);
    setScreen("list");
  };
  const back = () => setScreen("orbit");

  return (
    <main class="pop" classList={{ "on-orbit": view() === "orbit" }}>
      <Show when={error()}>{(e) => <p class="banner bad">{e()}</p>}</Show>
      <Show when={overview()?.update.ready}>
        {(version) => (
          <UpdateReady
            version={version()}
            busy={overview()?.busy ?? false}
            onRestart={() => run(() => invoke("restart_to_update"))}
          />
        )}
      </Show>
      <Show when={overview()} fallback={<p class="quiet">Reading the last sweep…</p>}>
        {(o) => (
          <Switch>
            <Match when={view() === "settings"}>
              <Settings
                start={settings() ?? null}
                update={o().update}
                now={now()}
                onClose={() => {
                  setSettings(undefined);
                  void refetch();
                }}
              />
            </Match>
            <Match when={view() === "fixing"}>
              <Busy
                status={o().status}
                now={now()}
                onCancel={() => run(() => invoke("cancel_sweep"))}
              />
            </Match>
            <Match when={view() === "results" && fixedOf(o())}>
              {(status) => (
                <FixResults
                  status={status()}
                  now={now()}
                  onClose={() => run(() => invoke("close_fix"))}
                />
              )}
            </Match>
            <Match when={view() === "detail" && chosen()}>
              {(item) => (
                <Detail
                  item={item()}
                  now={now()}
                  busy={o().busy}
                  onBack={() => setSelected(null)}
                  onError={setError}
                />
              )}
            </Match>
            <Match when={view() === "target" && target()}>
              {(line) => (
                <>
                  <Nav onBack={() => setTargetKey(null)} />
                  <TargetFindings
                    line={line()}
                    overview={o()}
                    now={now()}
                    onOpen={setSelected}
                    onError={setError}
                  />
                </>
              )}
            </Match>
            <Match when={view() === "orbit"}>
              <Orbit
                overview={o()}
                now={now()}
                actions={{
                  onList: () => list(o().list_tab),
                  onTarget: setTargetKey,
                  onSweep: () => run(() => invoke("sweep_now")),
                  onCancel: () => run(() => invoke("cancel_sweep")),
                  onReport: () => run(() => invoke("open_report")),
                  onSettings: () => setSettings(null),
                  onError: setError,
                }}
              />
            </Match>
            <Match when={view() === "busy"}>
              <Nav onBack={back} />
              <Busy
                status={o().status}
                now={now()}
                onCancel={() => run(() => invoke("cancel_sweep"))}
              />
            </Match>
            <Match when={view() === "problem"}>
              <Problem
                title="Settings need a look"
                text={o().problem ?? ""}
                action="Open settings"
                onAction={() => setSettings(null)}
              />
            </Match>
            <Match when={view() === "agent"}>
              <Problem
                title="Choose an agent to start"
                text="Vigil has a coding agent judge which advisories affect you. Pick one of those installed on this Mac."
                action="Choose an agent"
                onAction={() => setSettings("agent")}
              />
            </Match>
            <Match when={view() === "clear"}>
              <Nav onBack={back} />
              <AllClear overview={o()} now={now()} onTarget={setTargetKey} />
            </Match>
            <Match when={view() === "list"}>
              <Nav onBack={back} />
              <Summary overview={o()} now={now()} onSweep={() => run(() => invoke("sweep_now"))} />
              <Tabs tab={tab()} onTab={setTab} overview={o()} />
              <Switch>
                <Match when={tab() === "needs"}>
                  <Rows
                    items={listed().filter((f) => f.needs_you)}
                    now={now()}
                    empty="Nothing critical, high or exploited is open."
                    onOpen={setSelected}
                  />
                </Match>
                <Match when={tab() === "targets"}>
                  <Targets targets={o().targets} now={now()} onOpen={setTargetKey} />
                </Match>
                <Match when={tab() === "all"}>
                  <Rows
                    items={listed()}
                    now={now()}
                    empty="Nothing is open."
                    onOpen={setSelected}
                  />
                </Match>
                <Match when={tab() === "fixed"}>
                  <FixedRows reported={o().reported} fixed={o().fixed} now={now()} />
                </Match>
              </Switch>
            </Match>
          </Switch>
        )}
      </Show>
      <Show when={view() !== "settings" && view() !== "orbit"}>
        <Footer overview={overview()} onSettings={() => setSettings(null)} onError={setError} />
      </Show>
    </main>
  );
}

function Summary(props: { overview: Overview; now: Date; onSweep: () => void }) {
  const counts = () => props.overview.counts;
  const exploited = () => props.overview.exploited;
  const swept = () => props.overview.last_swept;
  const failed = () => (props.overview.status.state === "failed" ? props.overview.status : null);
  return (
    <section class="summary">
      <div class="headline">
        <div>
          <h1>{props.overview.headline}</h1>
          <p class="sub">
            <Show when={exploited() > 0}>
              <span class="kev-text">{exploited()} exploited in the wild</span> ·{" "}
            </Show>
            {props.overview.first_sweep_hint ?? `swept ${since(swept() ?? "", props.now)} ago`}
          </p>
        </div>
        <button type="button" class="pill" onClick={() => props.onSweep()}>
          <Icon name="sweep" />
          Sweep
        </button>
      </div>
      <Show when={failed()}>{(f) => <p class="banner bad">{f().error}</p>}</Show>
      <Show when={props.overview.items.length > 0}>
        <div
          class="bar"
          role="img"
          aria-label={SEVERITIES.map((s) => `${counts()[s]} ${s}`).join(", ")}
        >
          <For each={SEVERITIES.filter((s) => counts()[s] > 0)}>
            {(s) => <i class={s} style={{ "flex-grow": counts()[s] }} />}
          </For>
        </div>
        <div class="legend">
          <For each={SEVERITIES}>
            {(s) => (
              <span class={counts()[s] === 0 ? "none" : ""}>
                <Glyph severity={s} />
                <b>{counts()[s]}</b> {s}
              </span>
            )}
          </For>
        </div>
      </Show>
    </section>
  );
}

function Tabs(props: { tab: Tab; onTab: (tab: Tab) => void; overview: Overview }) {
  const tabs = (): [Tab, string, number][] => [
    ["needs", "Needs you", props.overview.needs_you],
    ["targets", "Targets", props.overview.targets.length],
    ["all", "All open", props.overview.items.length],
    ["fixed", "Fixed", props.overview.reported.length + props.overview.fixed.length],
  ];
  return (
    <div class="seg" role="tablist" aria-label="View">
      <For each={tabs()}>
        {([id, label, n]) => (
          <button
            type="button"
            role="tab"
            aria-selected={props.tab === id}
            onClick={() => props.onTab(id)}
          >
            {label} <span class="n">{n}</span>
          </button>
        )}
      </For>
    </div>
  );
}

/** Fixes the agent reported, which the next sweep confirms, then fixes a later sweep
 * confirmed: what was fixed, where, when, and how. */
function FixedRows(props: {
  reported: readonly ReportedFix[];
  fixed: readonly FixedItem[];
  now: Date;
}) {
  return (
    <Show
      when={props.reported.length + props.fixed.length > 0}
      fallback={<p class="quiet">No confirmed fixes from the last 30 days.</p>}
    >
      <ul class="group list pane" aria-label="Fixed" tabindex="0">
        <For each={props.reported}>
          {(fix) => (
            <li class="row fixed-row">
              <Icon name="done" />
              <span class="what">
                <span class="t">
                  {fix.item.name}
                  <Show when={fix.item.lead.version}>{(v) => <span class="ver">{v()}</span>}</Show>
                </span>
                <Show when={fix.item.advisory_count}>
                  {(count) => <span class="id">{count()}</span>}
                </Show>
                <span class="confirming">{fix.status}</span>
                <span class="where">{fix.item.target}</span>
                <span class="fix">{fix.summary}</span>
              </span>
              <span class="age">{ago(fix.fixed_at, props.now)}</span>
            </li>
          )}
        </For>
        <For each={props.fixed}>
          {(item) => (
            <li class="row fixed-row">
              <Icon name="done" />
              <span class="what">
                <span class="t">{item.title}</span>
                <span class="where">{item.target}</span>
                <span class="fix">{item.summary}</span>
                <Show when={item.pull_request}>
                  {(url) => <span class="pr">Pull request: {url()}</span>}
                </Show>
              </span>
              <span class="age">{ago(item.fixed_at, props.now)}</span>
            </li>
          )}
        </For>
      </ul>
    </Show>
  );
}

/** The badge of an open finding a fix was reported for, as its fix state says. In an open
 * item, "Fix reported" shows only on one advisory of several, in the detail: an item whose
 * fixes are all reported is not open. */
function fixLabel(state: FixState): string {
  if (state.state === "not_held") {
    return "Still found after a fix";
  }
  return state.pull_request === null ? "Fix reported" : "Pull request open";
}

/** The badge of an open item a fix is pending for, as Rust decides over all its findings. */
const PENDING_LABELS: Readonly<Record<PendingFix, string>> = {
  not_held: "Still found after a fix",
  pull_request: "Pull request open",
};

/** Whether a row shows any tag: exploited, new, or what keeps its fix from counting. */
function tagged(item: Listed): boolean {
  return item.known_exploited || item.new || item.pending_fix !== null;
}

/** What a row says it is about: how many advisories a component has, or its advisory ids. */
function about(item: Listed): string {
  return item.advisory_count ?? item.lead.advisories.join(" · ");
}

function Rows(props: {
  items: readonly Listed[];
  now: Date;
  empty: string;
  onOpen: (id: string) => void;
}) {
  return (
    <Show when={props.items.length > 0} fallback={<p class="quiet">{props.empty}</p>}>
      <div class="group list pane">
        <For each={props.items}>
          {(item) => (
            <button type="button" class="row" onClick={() => props.onOpen(item.id)}>
              <Glyph severity={item.severity} />
              <span class="what">
                <span class="t">
                  {item.name}
                  <Show when={item.lead.version}>{(v) => <span class="ver">{v()}</span>}</Show>
                </span>
                <Show when={about(item) !== "" || tagged(item)}>
                  <span class="tagline">
                    <Show when={about(item)}>{(text) => <span class="id">{text()}</span>}</Show>
                    <Show when={item.known_exploited}>
                      <span class="tag kev">Exploited</span>
                    </Show>
                    <Show when={item.new && !item.known_exploited}>
                      <span class="tag new">New</span>
                    </Show>
                    <Show when={item.pending_fix}>
                      {(pending) => (
                        <span class={`tag fix-${pending()}`}>{PENDING_LABELS[pending()]}</span>
                      )}
                    </Show>
                  </span>
                </Show>
                <span class="where">
                  {item.target}
                  <Show when={item.lead.place}> · {item.lead.place}</Show>
                </span>
                <span class="fix">
                  <Icon name="wrench" />
                  {item.lead.fix}
                </span>
              </span>
              <span class="age">
                <Show when={item.first_seen}>{(seen) => since(seen(), props.now)}</Show>
              </span>
            </button>
          )}
        </For>
      </div>
    </Show>
  );
}

/** The list's severity colours, for the target rows' counts and bars. */
const SEVERITY_COLOURS: Readonly<Record<Severity, string>> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

/** What a target's last sweep checked, when, and how many findings are dismissed there:
 * "139 components checked · swept 1 h ago · 2 dismissed". */
function sweptLine(t: TargetLine, now: Date): string {
  const parts =
    t.swept === null ? ["not swept yet"] : [t.checked, `swept ${since(t.swept, now)} ago`];
  if (t.dismissed > 0) {
    parts.push(`${t.dismissed} dismissed`);
  }
  return parts.filter((part) => part !== null).join(" · ");
}

/** One row per target, laid out as the main view's target rows (Orbit.tsx): the name and its
 * open count, what was checked and when across the full width, then the counts and the bar.
 * A row opens that target's findings. */
function Targets(props: {
  targets: readonly TargetLine[];
  now: Date;
  onOpen: (key: string) => void;
}) {
  return (
    <div class="group list pane" role="group" aria-label="Targets" tabindex="0">
      <For each={props.targets}>
        {(t) => (
          <button type="button" class="trow target" onClick={() => props.onOpen(t.key)}>
            <Icon name={t.kind} />
            <span class="tname">{t.label}</span>
            <span class="tsub">{sweptLine(t, props.now)}</span>
            <TargetFigures target={t} colours={SEVERITY_COLOURS} />
            {/* TargetFigures says the open count in its sentence, so it is not read twice. */}
            <span class="open" aria-hidden="true">
              <Show when={t.swept !== null}>
                <Show
                  when={t.open > 0}
                  fallback={
                    <Show
                      when={t.to_confirm}
                      fallback={
                        <>
                          <Icon name="done" /> clear
                        </>
                      }
                    >
                      {(text) => <span class="confirming">{text()}</span>}
                    </Show>
                  }
                >
                  <b>{t.open}</b> open
                </Show>
              </Show>
            </span>
          </button>
        )}
      </For>
    </div>
  );
}

/** One target's findings: its name and what its last sweep checked, its open items in the order
 * Rust ranked them, then the fixes of its items the next sweep confirms, as the Fixed tab shows
 * them. Both lists are Rust's, picked by the target's key. */
function TargetFindings(props: {
  line: TargetLine;
  overview: Overview;
  now: Date;
  onOpen: (id: string) => void;
  onError: (error: string) => void;
}) {
  const items = () => props.overview.items.filter((i) => i.target_key === props.line.key);
  const reported = () =>
    props.overview.reported.filter((r) => r.item.target_key === props.line.key);
  // Fix all's question, once Rust has checked every item; it replaces the lists until answered.
  const [asked, setAsked] = createSignal<FixAllPreview | null>(null);
  const askFixAll = () => {
    invoke<FixAllPreview>("fix_all_preview", { target: props.line.key })
      .then(setAsked)
      .catch((e: unknown) => props.onError(String(e)));
  };
  // The keys and `found` pin the run to the list shown: Rust refuses it if anything changed.
  const runFixAll = (shown: FixAllPreview) => {
    const keys = shown.items.map((item) => item.key);
    invoke("fix_all", { target: props.line.key, keys, found: shown.found }).catch((e: unknown) =>
      props.onError(String(e)),
    );
  };
  return (
    <>
      <section class="summary">
        <div class="headline">
          <div class="headline-text">
            <h1>{props.line.label}</h1>
            <p class="sub">{sweptLine(props.line, props.now)}</p>
          </div>
          <Show when={asked() === null && props.line.fix_all}>
            {(label) => (
              <button type="button" class="pill" disabled={props.overview.busy} onClick={askFixAll}>
                <Icon name="wrench" />
                {label()}
              </button>
            )}
          </Show>
        </div>
      </section>
      <Show
        when={asked()}
        fallback={
          <>
            <Rows
              items={items()}
              now={props.now}
              empty={props.line.swept === null ? "Not swept yet." : "Nothing is open."}
              onOpen={props.onOpen}
            />
            <Show when={reported().length > 0}>
              <FixedRows reported={reported()} fixed={[]} now={props.now} />
            </Show>
          </>
        }
      >
        {(shown) => (
          <FixAllConfirm
            shown={shown()}
            busy={props.overview.busy}
            onRun={() => runFixAll(shown())}
            onCancel={() => setAsked(null)}
          />
        )}
      </Show>
    </>
  );
}

/** One question for a whole Fix all: where and with what it runs, then each item's fix as the
 * single Fix shows one, then the button Rust labelled and Cancel. */
function FixAllConfirm(props: {
  shown: FixAllPreview;
  busy: boolean;
  onRun: () => void;
  onCancel: () => void;
}) {
  return (
    <section class="group detail confirm fix-all pane" aria-label="Fix all" tabindex="0">
      <p>
        Run these {props.shown.items.length} fixes on <b>{props.shown.destination}</b> with{" "}
        {props.shown.agent}, with full access, in one run?
      </p>
      <p>
        The agent applies them in this order. If one fails, it says which and goes on with the rest;
        each is recorded on its own.
      </p>
      <ol class="fix-all-items" aria-label="Fixes to run">
        <For each={props.shown.items}>
          {(item) => (
            <li>
              <h2>{item.name}</h2>
              <p class="fixline">
                <Icon name="wrench" />
                {item.summary}
              </p>
              {/* The agent is told the steps were confirmed too, so they are shown. */}
              <Show when={item.steps.length > 0}>
                <ol class="fix-steps" aria-label={`Steps for ${item.name}`}>
                  <For each={item.steps}>{(step) => <li>{step}</li>}</For>
                </ol>
              </Show>
              <Commands commands={item.commands} label={`Commands for ${item.name}`} />
            </li>
          )}
        </For>
      </ol>
      <div class="dacts">
        <button type="button" class="btn primary" disabled={props.busy} onClick={props.onRun}>
          {props.shown.confirm}
        </button>
        <button type="button" class="btn" onClick={() => props.onCancel()}>
          Cancel
        </button>
      </div>
    </section>
  );
}

/** Back to the screen before, with its button or Escape. */
function Nav(props: { onBack: () => void }) {
  const back = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      props.onBack();
    }
  };
  onMount(() => window.addEventListener("keydown", back));
  onCleanup(() => window.removeEventListener("keydown", back));
  return (
    <div class="nav">
      <button type="button" class="back" onClick={() => props.onBack()}>
        <Icon name="chev" />
        Back
      </button>
      <kbd>esc</kbd>
    </div>
  );
}

/** An item's detail: what it is and where, its one fix, and for a component each advisory. */
function Detail(props: {
  item: Listed;
  now: Date;
  busy: boolean;
  onBack: () => void;
  onError: (error: string) => void;
}) {
  const lead = () => props.item.lead;
  const single = () => props.item.others.length === 0;
  // The preview keeps the key it was asked for: dismissing the lead while it shows makes
  // another finding the lead, and Run fix must still run the fix shown.
  const [preview, setPreview] = createSignal<{ key: string; shown: FixPreview } | null>(null);
  const [dismissing, setDismissing] = createSignal(false);
  const askFix = () => {
    const key = lead().key;
    invoke<FixPreview>("fix_preview", { key })
      .then((shown) => setPreview({ key, shown }))
      .catch((e: unknown) => props.onError(String(e)));
  };
  // The preview's `found` pins the fix to the one shown: Rust refuses it if a sweep changed
  // the finding since.
  const runFix = (asked: { key: string; shown: FixPreview }) => {
    invoke("fix", { key: asked.key, found: asked.shown.found }).catch((e: unknown) =>
      props.onError(String(e)),
    );
  };
  // Dismissing one of a component's advisories keeps the detail open on the rest; Rust's next
  // overview leaves the dismissed one out. The last one gone, the item is gone, so back.
  const dismiss = (key: string, reason: string) => {
    const last = single();
    invoke("dismiss", { key, reason })
      .then(() => last && props.onBack())
      .catch((e: unknown) => props.onError(String(e)));
  };

  return (
    <section class="detail-view">
      <Nav onBack={props.onBack} />
      <div class="group detail">
        <div class="dhead">
          <Glyph severity={props.item.severity} />
          <div class="dtitle">
            <h2>
              {props.item.name}
              <Show when={lead().version}>{(v) => <span class="ver"> {v()}</span>}</Show>
            </h2>
            <Show when={about(props.item)}>{(text) => <span class="id">{text()}</span>}</Show>
          </div>
          <Show when={props.item.known_exploited}>
            <span class="tag kev">Exploited</span>
          </Show>
        </div>
        <dl class="meta">
          <dt>Severity</dt>
          <dd>
            {props.item.severity}
            <Show when={props.item.known_exploited}>, exploited in the wild (CISA KEV)</Show>
          </dd>
          <dt>Where</dt>
          <dd>
            {props.item.target}
            <Show when={lead().place}> · {lead().place}</Show>
          </dd>
          <Show when={props.item.first_seen}>
            {(seen) => (
              <>
                <dt>Found</dt>
                <dd>{since(seen(), props.now)} ago</dd>
              </>
            )}
          </Show>
          <Show when={single()}>
            <dt>Key</dt>
            <dd class="mono">{lead().key}</dd>
          </Show>
        </dl>
        <Show when={single() && lead().explanation}>
          <p class="why">{lead().explanation}</p>
        </Show>
        <p class="fixline">
          <Icon name="wrench" />
          {lead().fix}
        </p>
        <Commands commands={lead().commands} />
        <Switch>
          <Match when={preview()}>
            {(p) => (
              <div class="confirm">
                <p>
                  Run this fix on <b>{p().shown.destination}</b> with {p().shown.agent}, with full
                  access?
                </p>
                <Show when={props.item.fix_scope}>{(scope) => <p>{scope()}</p>}</Show>
                <p class="fixline">{p().shown.summary}</p>
                <Commands commands={p().shown.commands} label="Commands the fix runs" />
                <div class="dacts">
                  <button
                    type="button"
                    class="btn primary"
                    disabled={props.busy}
                    onClick={() => runFix(p())}
                  >
                    Run fix
                  </button>
                  <button type="button" class="btn" onClick={() => setPreview(null)}>
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </Match>
          <Match when={dismissing()}>
            <DismissForm
              id="reason"
              onDismiss={(reason) => dismiss(lead().key, reason)}
              onCancel={() => setDismissing(false)}
            />
          </Match>
          <Match when={true}>
            <div class="dacts">
              <button type="button" class="btn primary" disabled={props.busy} onClick={askFix}>
                Fix…
              </button>
              {/* A component's advisories are dismissed one by one, below. */}
              <Show when={single()}>
                <button type="button" class="btn" onClick={() => setDismissing(true)}>
                  Dismiss…
                </button>
              </Show>
            </div>
          </Match>
        </Switch>
      </div>
      <Show when={!single()}>
        <ul class="group advs" aria-label="Advisories">
          <For each={[lead(), ...props.item.others]}>
            {(finding) => (
              <Advisory finding={finding} onDismiss={(reason) => dismiss(finding.key, reason)} />
            )}
          </For>
        </ul>
      </Show>
      <p class="hint">A fix runs only after you confirm it, with full access, and is recorded.</p>
    </section>
  );
}

/** One advisory of a component, collapsed to its severity and ids; opened, what it means,
 * what the agent checked, its key, and Dismiss. */
function Advisory(props: { finding: Finding; onDismiss: (reason: string) => void }) {
  const [dismissing, setDismissing] = createSignal(false);
  const f = () => props.finding;
  return (
    <li>
      <details class="adv">
        <summary>
          <Glyph severity={f().severity} />
          {/* As in a list row: the badges follow the ids, and move under them when both do not
              fit on one line. */}
          <span class="tagline">
            <span class="id">{f().advisories.join(" · ")}</span>
            <Show when={f().known_exploited}>
              <span class="tag kev">Exploited</span>
            </Show>
            <Show when={f().fix_state}>
              {(state) => <span class={`tag fix-${state().state}`}>{fixLabel(state())}</span>}
            </Show>
          </span>
          <span class="adv-sev">{f().severity}</span>
        </summary>
        <div class="adv-body">
          <Show when={f().explanation}>
            <p class="why">{f().explanation}</p>
          </Show>
          <Show when={f().evidence}>
            <p class="evidence">{f().evidence}</p>
          </Show>
          <dl class="meta">
            <dt>Key</dt>
            <dd class="mono">{f().key}</dd>
          </dl>
          <Show
            when={dismissing()}
            fallback={
              <div class="dacts">
                <button type="button" class="btn" onClick={() => setDismissing(true)}>
                  Dismiss…
                </button>
              </div>
            }
          >
            <DismissForm
              id={`reason-${f().key}`}
              onDismiss={(reason) => props.onDismiss(reason)}
              onCancel={() => setDismissing(false)}
            />
          </Show>
        </div>
      </details>
    </li>
  );
}

/** Asks why a finding does not apply, and dismisses it with that reason. */
function DismissForm(props: {
  id: string;
  onDismiss: (reason: string) => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = createSignal("");
  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    props.onDismiss(reason());
  };
  return (
    <form class="confirm" onSubmit={submit}>
      <label for={props.id}>Why does this not apply?</label>
      <input
        id={props.id}
        value={reason()}
        onInput={(e) => setReason(e.currentTarget.value)}
        placeholder="Not reachable: we never parse untrusted images"
        required
      />
      <div class="dacts">
        <button type="submit" class="btn primary">
          Dismiss
        </button>
        <button type="button" class="btn" onClick={() => props.onCancel()}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** A fix's exact commands, one per line after a prompt; nothing when there are none. */
function Commands(props: { commands: readonly string[]; label?: string }) {
  return (
    <Show when={props.commands.length > 0}>
      <pre class="cmd" aria-label={props.label}>
        <For each={props.commands}>
          {(c) => (
            <span>
              <span class="p">$ </span>
              {c}
              {"\n"}
            </span>
          )}
        </For>
      </pre>
    </Show>
  );
}

/** The sweep's progress bar, as Rust measures it, with a mark between targets. While the
 * agent runs, the rest of its target's share moves instead of filling: that step has no
 * known length. */
function Bar(props: {
  percent: number;
  targetEnd: number;
  openEnded: boolean;
  ticks: readonly number[];
  label: string;
}) {
  return (
    <div
      class="sweep-bar"
      role="progressbar"
      aria-label="Sweep progress"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={props.percent}
      aria-valuetext={`${props.percent}%, ${props.label}`}
    >
      <span class="sweep-bar-fill" style={{ width: `${props.percent}%` }} />
      <Show when={props.openEnded}>
        <span
          class="sweep-bar-work"
          style={{ left: `${props.percent}%`, width: `${props.targetEnd - props.percent}%` }}
        />
      </Show>
      <For each={props.ticks}>
        {(at) => <span class="sweep-bar-tick" style={{ left: `${at}%` }} />}
      </For>
    </div>
  );
}

function Busy(props: { status: Status; now: Date; onCancel: () => void }) {
  return (
    <Switch>
      <Match when={props.status.state === "sweeping" ? props.status : null}>
        {(s) => (
          <section class="summary">
            <div class="headline">
              <div class="headline-text">
                <h1>Sweeping {s().current ?? ""}</h1>
                <p class="sub">
                  target {s().position} of {s().total} · started {since(s().started, props.now)} ago
                </p>
              </div>
              <span class="pct" aria-hidden="true">
                {s().percent}%
              </span>
            </div>
            <Bar
              percent={s().percent}
              targetEnd={s().target_end}
              openEnded={s().open_ended}
              ticks={s().ticks}
              label={s().step}
            />
            <div class="group steps">
              <For each={s().done}>
                {(t) => (
                  <div class="step done">
                    <Icon name="done" />
                    <span>{t}</span>
                    <span class="st">done</span>
                  </div>
                )}
              </For>
              <Show when={s().current}>
                {(current) => (
                  <div class="step now">
                    <span class="spin" />
                    <span class="step-text">
                      <span class="step-name">{current()}</span>
                      <span class="step-detail">{s().step}</span>
                    </span>
                    <span class="st">{since(s().step_started, props.now)}</span>
                  </div>
                )}
              </Show>
              <For each={s().pending}>
                {(t) => (
                  <div class="step next">
                    <Icon name="wait" />
                    <span>{t}</span>
                    <span class="st">next</span>
                  </div>
                )}
              </For>
            </div>
            <div class="busy-foot">
              <p class="hint">
                {s().stopping
                  ? "Stopping the agent and cleaning up…"
                  : "You can close this; a notification tells you what it finds."}
              </p>
              <button type="button" class="btn" disabled={s().stopping} onClick={props.onCancel}>
                {s().stopping ? "Stopping…" : "Cancel"}
              </button>
            </div>
          </section>
        )}
      </Match>
      <Match when={props.status.state === "fixing" ? props.status : null}>
        {(f) => {
          const current = () => f().steps.find((s) => s.state === "now");
          return (
            <section class="summary">
              <div class="headline">
                <div class="headline-text">
                  <h1>Fixing</h1>
                  <p class="sub">
                    {f().place} · started {ago(f().started, props.now)}
                  </p>
                </div>
                {/* No spinner here: the running step has one, and two at once distract. */}
              </div>
              <p class="fix-title">{f().title}</p>
              <ol class="group steps" role="list" aria-label="Fix progress">
                <For each={f().steps}>
                  {(step) => (
                    <li
                      class={`step ${step.state}`}
                      aria-current={step.state === "now" ? "step" : undefined}
                    >
                      <Switch>
                        <Match when={step.state === "done"}>
                          <Icon name="done" />
                        </Match>
                        <Match when={step.state === "now"}>
                          <span class="spin" aria-hidden="true" />
                        </Match>
                        <Match when={step.state === "next"}>
                          <Icon name="wait" />
                        </Match>
                      </Switch>
                      <span class="step-text">
                        <span class="step-label">{step.label}</span>
                        <Show when={step.state === "now" && f().activity}>
                          {(line) => <span class="step-detail activity">{line()}</span>}
                        </Show>
                      </span>
                      <span class="st">
                        {step.state === "now"
                          ? since(f().step_started, props.now)
                          : step.state === "done"
                            ? "done"
                            : "next"}
                      </span>
                    </li>
                  )}
                </For>
              </ol>
              {/* Announces each new step once; the list itself would repeat its ticking time. */}
              <p class="sr-only" aria-live="polite">
                {current()?.label}
              </p>
              <p class="hint">
                The agent is working with full access. There is no Cancel: stopping a fix halfway
                could leave a change half made. You can close this.
              </p>
            </section>
          );
        }}
      </Match>
    </Switch>
  );
}

/** The icon of an item's final state: green check, amber dash, red cross, grey circle. */
const RESULT_ICONS = {
  fixed: "done",
  partial: "partial",
  failed: "failed",
  unknown: "wait",
} as const satisfies Record<FixRunItem["state"], IconName>;

/** What Show log shows: the log's end, or why it could not be read. */
type LogView = { readonly tail: LogTail } | { readonly error: string };

/** A finished fix's results, where its steps were: each item in its final state, with the
 * agent's summary a click away, the run's log on request, and Rust's summary line at the
 * bottom. The owner's decision (2026-11-11): results stay here until closed, never in a banner
 * at the top. Close, or Escape, returns to the screen the fix was started from. */
function FixResults(props: { status: FixedStatus; now: Date; onClose: () => void }) {
  const [log, setLog] = createSignal<LogView | null>(null);
  const toggleLog = () => {
    if (log() !== null) {
      setLog(null);
      return;
    }
    // Read each time it is shown, so it is never a stale copy.
    invoke<LogTail>("fix_log")
      .then((tail) => setLog({ tail }))
      .catch((e: unknown) => setLog({ error: String(e) }));
  };
  const close = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      props.onClose();
    }
  };
  onMount(() => window.addEventListener("keydown", close));
  onCleanup(() => window.removeEventListener("keydown", close));
  return (
    <>
      <section class="summary">
        <div class="headline">
          <div class="headline-text">
            <h1>Fix finished</h1>
            <p class="sub">
              {props.status.place} · finished {ago(props.status.finished, props.now)}
            </p>
          </div>
        </div>
        <p class="fix-title">{props.status.title}</p>
      </section>
      <ol class="group steps results pane" aria-label="Fix results" tabindex="0">
        <For each={props.status.items}>{(item) => <ResultRow item={item} />}</For>
      </ol>
      <Show when={log()}>
        {(shown) => {
          const view = shown();
          return "error" in view ? (
            <p class="log-error" role="alert">
              {view.error}
            </p>
          ) : (
            <LogBlock tail={view.tail} />
          );
        }}
      </Show>
      <div class="results-foot">
        <p class="results-summary" role="status">
          {props.status.summary}
        </p>
        <div class="dacts">
          <button type="button" class="btn" aria-expanded={log() !== null} onClick={toggleLog}>
            {log() === null ? "Show log" : "Hide log"}
          </button>
          <button type="button" class="btn primary" onClick={() => props.onClose()}>
            Close
          </button>
        </div>
      </div>
    </>
  );
}

/** One item's final state, and Details, which opens the agent's summary under it. */
function ResultRow(props: { item: FixRunItem }) {
  const [open, setOpen] = createSignal(false);
  return (
    <li class={`step result ${props.item.state}`}>
      <Icon name={RESULT_ICONS[props.item.state]} />
      <span class="result-name">{props.item.name}</span>
      <span class="st">{props.item.state_label}</span>
      <button
        type="button"
        class="details"
        aria-expanded={open()}
        aria-label={`Details: ${props.item.name}`}
        onClick={() => setOpen(!open())}
      >
        Details
        <Icon name="chev" />
      </button>
      <Show when={open()}>
        {/* The agent's own words: shown as text, never acted on. */}
        <p class="result-detail">
          {props.item.summary}
          <Show when={props.item.pull_request}>
            {(url) => <span class="pr">Pull request: {url()}</span>}
          </Show>
        </p>
      </Show>
    </li>
  );
}

/** The end of the run's log, scrolled to its last line, where the agent finished. */
function LogBlock(props: { tail: LogTail }) {
  let block: HTMLPreElement | undefined;
  onMount(() => {
    if (block !== undefined) {
      block.scrollTop = block.scrollHeight;
    }
  });
  return (
    <>
      <Show when={props.tail.note}>{(note) => <p class="hint">{note()}</p>}</Show>
      <Show when={props.tail.text !== ""}>
        <pre class="log pane" aria-label="Agent log" tabindex="0" ref={(el) => (block = el)}>
          {props.tail.text}
        </pre>
      </Show>
    </>
  );
}

function AllClear(props: { overview: Overview; now: Date; onTarget: (key: string) => void }) {
  const swept = () => props.overview.last_swept;
  const dismissed = () => props.overview.dismissed;
  return (
    <section class="clear">
      <div class="seal">
        <Icon name="check" />
      </div>
      <h1>All clear</h1>
      <p>
        {props.overview.target_count} swept {since(swept() ?? "", props.now)} ago. Nothing open
        <Show when={dismissed() > 0}>; {dismissed()} dismissed</Show>.
      </p>
      <Targets targets={props.overview.targets} now={props.now} onOpen={props.onTarget} />
      <Show when={props.overview.fixed.length > 0}>
        <h2 class="label">Fixed in the last 30 days</h2>
        <FixedRows
          reported={props.overview.reported}
          fixed={props.overview.fixed}
          now={props.now}
        />
      </Show>
    </section>
  );
}

function Problem(props: { title: string; text: string; action: string; onAction: () => void }) {
  return (
    <section class="clear">
      <h1>{props.title}</h1>
      <p>{props.text}</p>
      <button type="button" class="btn primary" onClick={() => props.onAction()}>
        {props.action}
      </button>
    </section>
  );
}

function Footer(props: {
  overview: Overview | undefined;
  onSettings: () => void;
  onError: (error: string) => void;
}) {
  return (
    <footer class="foot">
      <span class="agent">
        <span class={`live ${props.overview?.agent ? "" : "off"}`} />
        {props.overview?.agent ?? "no agent"} · {props.overview?.schedule ?? ""}
      </span>
      <span class="spacer" />
      <Menu onSettings={props.onSettings} onError={props.onError} />
    </footer>
  );
}
