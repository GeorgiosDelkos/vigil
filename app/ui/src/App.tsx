import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { disable, enable, isEnabled } from "@tauri-apps/plugin-autostart";
import {
  For,
  Match,
  Show,
  Switch,
  createMemo,
  createResource,
  createSignal,
  onCleanup,
  onMount,
} from "solid-js";

import {
  SEVERITIES,
  type FixDone,
  type FixedItem,
  type FixState,
  type FixPreview,
  type Listed,
  type Overview,
  type Status,
  type TargetLine,
} from "./overview.ts";
import { Settings } from "./Settings.tsx";
import type { Section } from "./settings.ts";
import { Glyph, Icon } from "./icons.tsx";
import { ago, since } from "./time.ts";

type Tab = "needs" | "targets" | "all" | "fixed";

export function App() {
  const [overview, { refetch }] = createResource(() => invoke<Overview>("overview"));
  const [now, setNow] = createSignal(new Date());
  const [tab, setTab] = createSignal<Tab>("needs");
  const [selected, setSelected] = createSignal<string | null>(null);
  const [done, setDone] = createSignal<FixDone | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  // Settings open in the popover, at a section or at the list; `undefined` when closed.
  const [settings, setSettings] = createSignal<Section | null | undefined>(undefined);

  // Registered synchronously, so Solid runs the cleanups; the listeners resolve later.
  const unlisten: Promise<() => void>[] = [
    listen("changed", () => {
      setNow(new Date());
      void refetch();
    }),
    listen<FixDone>("fix-done", (event) => {
      setDone(event.payload);
      setSelected(null);
    }),
  ];
  onCleanup(() => {
    for (const u of unlisten) {
      void u.then((stop) => stop());
    }
  });
  const tick = setInterval(() => setNow(new Date()), 30_000);
  onCleanup(() => clearInterval(tick));

  const listed = () => overview()?.findings ?? [];
  const chosen = createMemo(() => listed().find((o) => o.key === selected()) ?? null);

  const run = (action: () => Promise<unknown>) => {
    setError(null);
    action().catch((e: unknown) => setError(String(e)));
  };

  return (
    <main class="pop">
      <Show when={error()}>{(e) => <p class="banner bad">{e()}</p>}</Show>
      <Show when={done()}>
        {(d) => (
          <p class={`banner ${d().outcome === "fixed" ? "good" : "bad"}`}>
            <b>{d().outcome === "fixed" ? "Fixed" : `Fix ${d().outcome}`}:</b> {d().summary}
            <Show when={d().pull_request}>
              {(url) => <span class="pr">Pull request: {url()}</span>}
            </Show>
            <button type="button" class="ghost x" aria-label="Close" onClick={() => setDone(null)}>
              ×
            </button>
          </p>
        )}
      </Show>
      <Show when={overview()} fallback={<p class="quiet">Reading the last sweep…</p>}>
        {(o) => (
          <Switch>
            <Match when={settings() !== undefined}>
              <Settings
                start={settings() ?? null}
                onClose={() => {
                  setSettings(undefined);
                  void refetch();
                }}
              />
            </Match>
            <Match when={chosen()}>
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
            <Match when={o().busy}>
              <Busy status={o().status} now={now()} />
            </Match>
            <Match when={o().problem !== null && o().targets.length === 0}>
              <Problem
                title="Settings need a look"
                text={o().problem ?? ""}
                action="Open settings"
                onAction={() => setSettings(null)}
              />
            </Match>
            <Match when={o().agent === null}>
              <Problem
                title="Choose an agent to start"
                text="Vigil has a coding agent judge which advisories affect you. Pick one of those installed on this Mac."
                action="Choose an agent"
                onAction={() => setSettings("agent")}
              />
            </Match>
            <Match when={o().all_clear}>
              <AllClear overview={o()} now={now()} />
            </Match>
            <Match when={true}>
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
                  <Targets targets={o().targets} now={now()} />
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
                  <FixedRows items={o().fixed} now={now()} />
                </Match>
              </Switch>
            </Match>
          </Switch>
        )}
      </Show>
      <Show when={settings() === undefined}>
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
      <Show when={failed()}>{(f) => <p class="banner bad">Last sweep: {f().error}</p>}</Show>
      <Show when={props.overview.findings.length > 0}>
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
    ["all", "All open", props.overview.findings.length],
    ["fixed", "Fixed", props.overview.fixed.length],
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

/** Fixes a later sweep confirmed: what was fixed, where, when, and how. */
function FixedRows(props: { items: readonly FixedItem[]; now: Date }) {
  return (
    <Show
      when={props.items.length > 0}
      fallback={<p class="quiet">No confirmed fixes from the last 30 days.</p>}
    >
      <ul class="group list pane" aria-label="Fixed">
        <For each={props.items}>
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

/** The badge of an open finding a fix was reported for, as its fix state says. */
function fixLabel(state: FixState): string {
  if (state.state === "not_held") {
    return "Still found after a fix";
  }
  return state.pull_request === null ? "Fix reported" : "Pull request open";
}

/** Whether a row shows any tag: exploited, new, or what a fix came to. */
function tagged(item: Listed): boolean {
  return item.known_exploited || item.new || item.fix_state !== null;
}

function Rows(props: {
  items: readonly Listed[];
  now: Date;
  empty: string;
  onOpen: (key: string) => void;
}) {
  return (
    <Show when={props.items.length > 0} fallback={<p class="quiet">{props.empty}</p>}>
      <div class="group list pane">
        <For each={props.items}>
          {(item) => (
            <button type="button" class="row" onClick={() => props.onOpen(item.key)}>
              <Glyph severity={item.severity} />
              <span class="what">
                <span class="t">
                  {item.name}
                  <Show when={item.version}>{(v) => <span class="ver">{v()}</span>}</Show>
                </span>
                <Show when={item.advisories.length > 0 || tagged(item)}>
                  <span class="tagline">
                    <Show when={item.advisories.length > 0}>
                      <span class="id">{item.advisories.join(" · ")}</span>
                    </Show>
                    <Show when={item.known_exploited}>
                      <span class="tag kev">Exploited</span>
                    </Show>
                    <Show when={item.new && !item.known_exploited}>
                      <span class="tag new">New</span>
                    </Show>
                    <Show when={item.fix_state}>
                      {(state) => (
                        <span class={`tag fix-${state().state}`}>{fixLabel(state())}</span>
                      )}
                    </Show>
                  </span>
                </Show>
                <span class="where">
                  {item.target}
                  <Show when={item.place}> · {item.place}</Show>
                </span>
                <span class="fix">
                  <Icon name="wrench" />
                  {item.fix}
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

function Targets(props: { targets: readonly TargetLine[]; now: Date }) {
  return (
    <div class="group list pane">
      <For each={props.targets}>
        {(t) => (
          <div class="row static target">
            <span class="ticon">
              <Icon name={t.kind} />
            </span>
            <span class="what">
              <span class="t">{t.label}</span>
              <Show when={t.open > 0}>
                <span class="legend sevs">
                  <For each={SEVERITIES.filter((s) => t.counts[s] > 0)}>
                    {(s) => (
                      <span>
                        <Glyph severity={s} />
                        <b>{t.counts[s]}</b> {s}
                      </span>
                    )}
                  </For>
                </span>
              </Show>
              <span class="where">
                <Show when={t.swept} fallback="not swept yet">
                  {(swept) => `${t.checked ?? ""} · swept ${since(swept(), props.now)} ago`}
                </Show>
                <Show when={t.dismissed > 0}> · {t.dismissed} dismissed</Show>
              </span>
            </span>
            <span class="open">
              <Show when={t.swept !== null}>
                <Show when={t.open > 0} fallback={<Icon name="done" />}>
                  <b>{t.open}</b> open
                </Show>
              </Show>
            </span>
          </div>
        )}
      </For>
    </div>
  );
}

function Detail(props: {
  item: Listed;
  now: Date;
  busy: boolean;
  onBack: () => void;
  onError: (error: string) => void;
}) {
  const [preview, setPreview] = createSignal<FixPreview | null>(null);
  const [dismissing, setDismissing] = createSignal(false);
  const [reason, setReason] = createSignal("");
  const back = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      props.onBack();
    }
  };
  onMount(() => window.addEventListener("keydown", back));
  onCleanup(() => window.removeEventListener("keydown", back));

  const askFix = () => {
    invoke<FixPreview>("fix_preview", { key: props.item.key })
      .then(setPreview)
      .catch((e: unknown) => props.onError(String(e)));
  };
  // The preview's `found` pins the fix to the one shown: Rust refuses it if a sweep changed
  // the finding since.
  const runFix = (shown: FixPreview) => {
    invoke("fix", { key: props.item.key, found: shown.found }).catch((e: unknown) =>
      props.onError(String(e)),
    );
  };
  const dismiss = (event: SubmitEvent) => {
    event.preventDefault();
    invoke("dismiss", { key: props.item.key, reason: reason() })
      .then(() => props.onBack())
      .catch((e: unknown) => props.onError(String(e)));
  };

  return (
    <section class="detail-view">
      <div class="nav">
        <button type="button" class="back" onClick={() => props.onBack()}>
          <Icon name="chev" />
          Back
        </button>
        <kbd>esc</kbd>
      </div>
      <div class="group detail">
        <div class="dhead">
          <Glyph severity={props.item.severity} />
          <div class="dtitle">
            <h2>
              {props.item.name}
              <Show when={props.item.version}>{(v) => <span class="ver"> {v()}</span>}</Show>
            </h2>
            <Show when={props.item.advisories.length > 0}>
              <span class="id">{props.item.advisories.join(" · ")}</span>
            </Show>
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
            <Show when={props.item.place}> · {props.item.place}</Show>
          </dd>
          <Show when={props.item.first_seen}>
            {(seen) => (
              <>
                <dt>Found</dt>
                <dd>{since(seen(), props.now)} ago</dd>
              </>
            )}
          </Show>
          <dt>Key</dt>
          <dd class="mono">{props.item.key}</dd>
        </dl>
        <Show when={props.item.explanation}>
          <p class="why">{props.item.explanation}</p>
        </Show>
        <p class="fixline">
          <Icon name="wrench" />
          {props.item.fix}
        </p>
        <Show when={props.item.commands.length > 0}>
          <pre class="cmd">
            <For each={props.item.commands}>
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
        <Switch>
          <Match when={preview()}>
            {(p) => (
              <div class="confirm">
                <p>
                  Run this fix on <b>{p().destination}</b> with {p().agent}, with full access?
                </p>
                <p class="fixline">{p().summary}</p>
                <Show when={p().commands.length > 0}>
                  <pre class="cmd" aria-label="Commands the fix runs">
                    <For each={p().commands}>
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
            <form class="confirm" onSubmit={dismiss}>
              <label for="reason">Why does this not apply?</label>
              <input
                id="reason"
                value={reason()}
                onInput={(e) => setReason(e.currentTarget.value)}
                placeholder="Not reachable: we never parse untrusted images"
                required
              />
              <div class="dacts">
                <button type="submit" class="btn primary">
                  Dismiss
                </button>
                <button type="button" class="btn" onClick={() => setDismissing(false)}>
                  Cancel
                </button>
              </div>
            </form>
          </Match>
          <Match when={true}>
            <div class="dacts">
              <button type="button" class="btn primary" disabled={props.busy} onClick={askFix}>
                Fix…
              </button>
              <button type="button" class="btn" onClick={() => setDismissing(true)}>
                Dismiss…
              </button>
            </div>
          </Match>
        </Switch>
      </div>
      <p class="hint">A fix runs only after you confirm it, with full access, and is recorded.</p>
    </section>
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

function Busy(props: { status: Status; now: Date }) {
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
            <p class="hint">You can close this; a notification tells you what it finds.</p>
          </section>
        )}
      </Match>
      <Match when={props.status.state === "fixing" ? props.status : null}>
        {(f) => (
          <section class="summary">
            <div class="headline">
              <div>
                <h1>Fixing</h1>
                <p class="sub">{f().title}</p>
              </div>
              <span class="spin" aria-label="Fixing" />
            </div>
            <p class="hint">The agent is working with full access; this shows how it ends.</p>
          </section>
        )}
      </Match>
    </Switch>
  );
}

function AllClear(props: { overview: Overview; now: Date }) {
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
      <Targets targets={props.overview.targets} now={props.now} />
      <Show when={props.overview.fixed.length > 0}>
        <h2 class="label">Fixed in the last 30 days</h2>
        <FixedRows items={props.overview.fixed} now={props.now} />
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
  const [login, setLogin] = createSignal(false);
  const [menu, setMenu] = createSignal(false);
  onMount(() => {
    isEnabled()
      .then(setLogin)
      .catch(() => setLogin(false));
  });
  const toggleLogin = (event: Event & { currentTarget: HTMLInputElement }) => {
    const box = event.currentTarget;
    (login() ? disable() : enable())
      .catch((e: unknown) => props.onError(String(e)))
      .finally(() => {
        // The box shows what is set, even when changing it failed.
        isEnabled()
          .then((on) => {
            setLogin(on);
            box.checked = on;
          })
          .catch(() => undefined);
      });
  };
  return (
    <footer class="foot">
      <span class="agent">
        <span class={`live ${props.overview?.agent ? "" : "off"}`} />
        {props.overview?.agent ?? "no agent"} · {props.overview?.schedule ?? ""}
      </span>
      <span class="spacer" />
      <div class="menu-wrap">
        <button
          type="button"
          class="ghost"
          aria-label="Settings"
          title="Settings"
          aria-expanded={menu()}
          onClick={() => setMenu(!menu())}
        >
          <Icon name="settings" />
        </button>
        <Show when={menu()}>
          <div class="menu" role="menu">
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setMenu(false);
                props.onSettings();
              }}
            >
              Settings…
            </button>
            <label class="menuitem">
              <input id="login" type="checkbox" checked={login()} onChange={toggleLogin} />
              Launch at login
            </label>
            <hr />
            <button type="button" role="menuitem" onClick={() => void invoke("quit")}>
              Quit Vigil
            </button>
          </div>
        </Show>
      </div>
    </footer>
  );
}
