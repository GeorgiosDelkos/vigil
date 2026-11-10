import { invoke } from "@tauri-apps/api/core";
import type { JSX } from "solid-js";
import {
  For,
  Match,
  Show,
  Switch,
  children,
  createEffect,
  createResource,
  createSignal,
} from "solid-js";

import { Icon } from "./icons.tsx";
import type { IconName } from "./icons.tsx";
import type { Section, SectionLine, Setting, SettingsView } from "./settings.ts";

/** Each section's icon and the line under its title. Copy only: what a section holds and
 * whether it needs the user come from Rust. */
const PAGES: Record<Section, { readonly icon: IconName; readonly blurb: string }> = {
  agent: { icon: "agent", blurb: "Runs each sweep and, after you confirm, each fix." },
  schedule: { icon: "clock", blurb: "When sweeps run, and how far back the first one looks." },
  mac: { icon: "mac", blurb: "Lockfiles in these folders, and the tools on this Mac." },
  github: {
    icon: "repo",
    blurb: "Dependencies, alerts and workflows of the repositories you pick.",
  },
  servers: { icon: "server", blurb: "Read over SSH with a fixed, read-only script." },
  nvd: { icon: "key", blurb: "Optional. Makes the first sweep about ten times faster." },
};

/** Settings inside the popover: grouped sections, each opening on its own page with Back.
 * Every value and choice comes from Rust; a change returns the settings as they now are. */
export function Settings(props: { start: Section | null; onClose: () => void }) {
  const [view, { mutate }] = createResource(() => invoke<SettingsView>("settings_data"));
  const [section, setSection] = createSignal<Section | null>(props.start);
  const [error, setError] = createSignal<string | null>(null);
  const [saved, setSaved] = createSignal(false);
  const [looking, setLooking] = createSignal(false);

  // Rust applies changes one at a time, but replies can arrive out of order; only the reply
  // to the newest command (a change or Look again) is shown, so an older view or error never
  // replaces a newer one.
  let newest = 0;
  /** Runs a command that returns the new settings, and shows them. Resolves to whether Rust
   * applied the change, so a form keeps what was typed until it is saved. */
  const update = (command: Promise<SettingsView | null>): Promise<boolean> => {
    newest += 1;
    const asked = newest;
    setError(null);
    setSaved(false);
    return command.then(
      (next) => {
        if (next !== null && asked === newest) {
          mutate(next);
          setSaved(true);
        }
        return next !== null;
      },
      (e: unknown) => {
        if (asked === newest) {
          setError(String(e));
        }
        return false;
      },
    );
  };
  const save = (setting: Setting) => update(invoke<SettingsView>("save", { setting }));
  const lookAgain = () => {
    setLooking(true);
    newest += 1;
    const asked = newest;
    setError(null);
    invoke<SettingsView>("detect_again")
      .then(
        (next) => asked === newest && mutate(next),
        (e: unknown) => asked === newest && setError(String(e)),
      )
      .finally(() => setLooking(false));
  };
  // Reading an errored resource throws, so check for an error first.
  const loaded = () => (view.error === undefined ? view() : undefined);
  const line = () =>
    loaded()
      ?.groups.flatMap((g) => g.sections)
      .find((s) => s.id === section());

  return (
    <section class="settings-view">
      <div class="nav">
        <button
          type="button"
          class="back"
          onClick={() => (section() === null ? props.onClose() : setSection(null))}
        >
          <Icon name="chev" />
          {section() === null ? "Done" : "Settings"}
        </button>
        <span class="navtitle">{line()?.title ?? "Settings"}</span>
        <span class="navside">
          <Show when={saved()}>
            <span class="savedtag">
              <Icon name="check" />
              Saved
            </span>
          </Show>
        </span>
      </div>
      <Show when={error() ?? (view.error === undefined ? null : String(view.error))}>
        {(e) => (
          <p class="banner bad">
            {e()}{" "}
            <button type="button" class="link" onClick={() => void invoke("open_config")}>
              Open config.toml
            </button>
          </p>
        )}
      </Show>
      <Show
        when={loaded()}
        fallback={
          <Show when={view.loading}>
            <p class="quiet">Looking at what this Mac has…</p>
          </Show>
        }
      >
        {(v) => (
          <Show
            when={line()}
            fallback={
              <Overview view={v()} looking={looking()} onOpen={setSection} onLook={lookAgain} />
            }
          >
            {(l) => (
              <Page line={l()}>
                <Switch>
                  <Match when={l().id === "agent"}>
                    <Agent view={v()} save={save} />
                  </Match>
                  <Match when={l().id === "schedule"}>
                    <ScheduleSection view={v()} save={save} />
                  </Match>
                  <Match when={l().id === "mac"}>
                    <Mac
                      view={v()}
                      save={save}
                      onAdd={() => update(invoke<SettingsView | null>("add_folder"))}
                    />
                  </Match>
                  <Match when={l().id === "github"}>
                    <GitHub view={v()} save={save} />
                  </Match>
                  <Match when={l().id === "servers"}>
                    <Servers view={v()} save={save} />
                  </Match>
                  <Match when={l().id === "nvd"}>
                    <Nvd
                      view={v()}
                      onSave={(key) => update(invoke<SettingsView>("set_nvd_key", { key }))}
                    />
                  </Match>
                </Switch>
              </Page>
            )}
          </Show>
        )}
      </Show>
    </section>
  );
}

/** The list of sections under Rust's headline. */
function Overview(props: {
  view: SettingsView;
  looking: boolean;
  onOpen: (section: Section) => void;
  onLook: () => void;
}) {
  return (
    <div class="page">
      <div class={`hero ${props.view.ready ? "ready" : "needs"}`}>
        <span class="tile shield" aria-hidden="true">
          <Icon name="shield" />
        </span>
        <span class="what">
          <span class="hero-title">{props.view.headline}</span>
          <span class="hero-sub">Changes save to config.toml as you make them.</span>
        </span>
      </div>
      <For each={props.view.groups}>
        {(group) => (
          <div class="block">
            <h2 class="label">{group.title}</h2>
            <div class="group list">
              <For each={group.sections}>
                {(s) => <SectionRow line={s} onOpen={() => props.onOpen(s.id)} />}
              </For>
            </div>
          </div>
        )}
      </For>
      <div class="footer">
        <button type="button" class="foot-btn" onClick={() => void invoke("open_config")}>
          <Icon name="doc" />
          Open config.toml
        </button>
        <button type="button" class="foot-btn" disabled={props.looking} onClick={props.onLook}>
          <span class={props.looking ? "spin" : "still"}>
            <Icon name="sweep" />
          </span>
          {props.looking ? "Looking…" : "Look again"}
        </button>
      </div>
    </div>
  );
}

function SectionRow(props: { line: SectionLine; onOpen: () => void }) {
  return (
    <button type="button" class="srow nav-row" onClick={() => props.onOpen()}>
      <span class={`tile ${props.line.id}`} aria-hidden="true">
        <Icon name={PAGES[props.line.id].icon} />
      </span>
      <span class="t">{props.line.title}</span>
      <span class="sum">
        <Show when={props.line.attention}>
          <i class="dot" aria-hidden="true" />
        </Show>
        <span class={`val ${props.line.attention ? "warn" : ""}`} title={props.line.summary}>
          {props.line.summary}
        </span>
        <Icon name="chev" />
      </span>
    </button>
  );
}

/** A section's page: its icon, title and what it is for, then its content. */
function Page(props: { line: SectionLine; children: JSX.Element }) {
  const page = () => PAGES[props.line.id];
  return (
    <div class="page enter">
      <div class="head">
        <span class={`tile ${props.line.id}`} aria-hidden="true">
          <Icon name={page().icon} />
        </span>
        <span class="what">
          <h1>{props.line.title}</h1>
          <span class="blurb">{page().blurb}</span>
        </span>
      </div>
      {props.children}
    </div>
  );
}

/** A row that turns something on or off, such as sweeping a repository. */
function Toggle(props: {
  on: boolean;
  title: string;
  icon: IconName;
  sub?: JSX.Element;
  disabled?: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      class="srow toggle"
      role="switch"
      aria-checked={props.on}
      disabled={props.disabled === true}
      onClick={() => props.onToggle()}
    >
      <span class="lead-icon">
        <Icon name={props.icon} />
      </span>
      <span class="what">
        <span class="t">{props.title}</span>
        <Show when={props.sub}>
          <span class="s">{props.sub}</span>
        </Show>
      </span>
      <span class={`switch ${props.on ? "on" : ""}`} aria-hidden="true" />
    </button>
  );
}

/** Two choices side by side, one of them on. */
function Segmented(props: {
  choices: readonly { label: string; on: boolean; pick: () => void }[];
}) {
  return (
    <span class="seg wide">
      <For each={props.choices}>
        {(c) => (
          <button type="button" aria-pressed={c.on} class={c.on ? "on" : ""} onClick={c.pick}>
            {c.label}
          </button>
        )}
      </For>
    </span>
  );
}

type Props = { view: SettingsView; save: (setting: Setting) => Promise<boolean> };

/** What the model menu shows besides the models themselves. Not model names: a name never
 * starts with `-`, and Rust refuses one that does. */
const DEFAULT = "-default";
const CUSTOM = "-custom";
const NONE = "-none";

function Agent(props: Props) {
  const chosen = () => props.view.agents.find((a) => a.chosen);
  return (
    <div class="group fields">
      <Field
        for="agent"
        label="Agent"
        aside={
          <Show when={chosen()}>
            {(agent) => (
              <span id="agent-state" class={`state ${agent().path === null ? "no" : "ok"}`}>
                {agent().path === null ? "Not found" : "Found"}
              </span>
            )}
          </Show>
        }
      >
        <Menu
          id="agent"
          describedBy="agent-state agent-path"
          value={chosen()?.agent ?? NONE}
          onPick={(agent) => void props.save({ kind: "agent", agent })}
        >
          <Show when={chosen() === undefined}>
            <option value={NONE} disabled>
              Choose one
            </option>
          </Show>
          <For each={props.view.agents}>
            {(agent) => (
              <option value={agent.agent} disabled={!agent.available}>
                {agent.available ? agent.name : `${agent.name} (not found)`}
              </option>
            )}
          </For>
        </Menu>
        <Show when={chosen()}>
          {(agent) => (
            <span id="agent-path" class="fld-path">
              {agent().path ?? "not on your login shell's PATH"}
            </span>
          )}
        </Show>
      </Field>
      <Show when={props.view.model}>{(model) => <Model model={model()} save={props.save} />}</Show>
      <p class="fld-foot">
        Agents are found through your login shell, the same way a sweep starts them.
      </p>
    </div>
  );
}

/** One setting in a form card: its label (with an optional badge at the end of the line), an
 * optional line saying what it does, then its control across the full width. The hint's id is
 * the control's id with `-hint`, for the control's `aria-describedby`. */
function Field(props: {
  for: string;
  label: string;
  hint?: string;
  aside?: JSX.Element;
  children: JSX.Element;
}) {
  return (
    <div class="fld">
      <div class="fld-head">
        <label for={props.for}>{props.label}</label>
        {props.aside}
      </div>
      <Show when={props.hint}>
        <p class="fld-hint" id={`${props.for}-hint`}>
          {props.hint}
        </p>
      </Show>
      {props.children}
    </div>
  );
}

/** A native drop-down menu, drawn as a full-width field with a chevron. */
function Menu(props: {
  id: string;
  /** The ids of what describes the menu: its field's hint, a badge. */
  describedBy: string;
  value: string;
  onPick: (value: string) => void;
  children: JSX.Element;
}) {
  let select: HTMLSelectElement | undefined;
  const options = children(() => props.children);
  // The value is set once the options are in place: set together with options that change in
  // the same update (another provider's models), a select finds no option for it and WebKit
  // falls back to the first one. An effect runs after the options are inserted.
  createEffect(() => {
    options();
    if (select !== undefined) {
      select.value = props.value;
    }
  });
  return (
    <span class="menu-pick">
      <select
        ref={(el) => (select = el)}
        id={props.id}
        aria-describedby={props.describedBy}
        onChange={(e) => {
          props.onPick(e.currentTarget.value);
          // The menu shows what Rust has, not what was clicked: a pick that is saved moves it
          // when Rust's next view arrives, and one that is refused leaves it where it was.
          e.currentTarget.value = props.value;
        }}
      >
        {options()}
      </select>
      <Icon name="chev" />
    </span>
  );
}

type ModelView = NonNullable<SettingsView["model"]>;

/** The chosen agent's provider and model: its default, one it lists, or a custom name. */
function Model(props: { model: ModelView; save: Props["save"] }) {
  // Which provider's models the menu offers, and whether the custom field is open. Both hold
  // only for the view they were set on: each view Rust returns (a save, another agent) shows
  // the provider Rust marked and closes the field.
  const [picked, setPicked] = createSignal<{ name: string; on: ModelView } | null>(null);
  const [custom, setCustom] = createSignal<ModelView | null>(null);
  const [typed, setTyped] = createSignal("");
  const shown = () => {
    const pick = picked();
    const name = pick !== null && pick.on === props.model ? pick.name : null;
    return (
      props.model.providers.find((p) => p.name === name) ??
      props.model.providers.find((p) => p.chosen)
    );
  };
  const typing = () => custom() === props.model;
  const value = () => {
    if (typing()) {
      return CUSTOM;
    }
    if (props.model.default) {
      return DEFAULT;
    }
    return shown()?.models.find((m) => m.chosen)?.value ?? NONE;
  };
  const choose = (model: string | null) =>
    props.save({ kind: "model", agent: props.model.agent, model });
  const pick = (option: string) => {
    if (option === CUSTOM) {
      setTyped("");
      setCustom(props.model);
    } else {
      // Another pick closes the field, so the menu shows Rust's model, not Custom.
      setCustom(null);
      void choose(option === DEFAULT ? null : option);
    }
  };
  return (
    <>
      <Show when={props.model.providers.length > 1}>
        <Field for="provider" label="Provider" hint="Whose models the list below offers.">
          <Menu
            id="provider"
            describedBy="provider-hint"
            value={shown()?.name ?? ""}
            onPick={(name) => setPicked({ name, on: props.model })}
          >
            <For each={props.model.providers}>
              {(p) => <option value={p.name}>{p.label}</option>}
            </For>
          </Menu>
        </Field>
      </Show>
      <Field
        for="model"
        label="Model"
        hint="Default leaves the choice to the agent. Custom takes any name its --model accepts."
      >
        <Menu id="model" describedBy="model-hint" value={value()} onPick={pick}>
          <Show when={value() === NONE}>
            <option value={NONE} disabled>
              Choose one
            </option>
          </Show>
          <option value={DEFAULT}>Default</option>
          <For each={shown()?.models ?? []}>
            {(m) => <option value={m.value}>{m.label}</option>}
          </For>
          <option value={CUSTOM}>Custom…</option>
        </Menu>
        <Show when={typing()}>
          <form
            class="fld-custom"
            onSubmit={(e) => {
              e.preventDefault();
              // A saved name closes the field, as Rust's next view does; a refused one stays.
              void choose(typed());
            }}
          >
            <input
              ref={(el) => queueMicrotask(() => el.focus())}
              id="model-name"
              class="field grow mono"
              placeholder={props.model.hint}
              aria-label="Model name"
              aria-describedby="model-hint"
              autocomplete="off"
              value={typed()}
              onInput={(e) => setTyped(e.currentTarget.value)}
            />
            <button type="submit" class="btn primary" disabled={typed().trim() === ""}>
              Use
            </button>
          </form>
        </Show>
      </Field>
    </>
  );
}

function ScheduleSection(props: Props) {
  const s = () => props.view.schedule;
  return (
    <>
      <div class="block">
        <h2 class="label">Sweeps</h2>
        <div class="group pad">
          <Segmented
            choices={[
              {
                label: "Manual",
                on: !s().automatic,
                pick: () => props.save({ kind: "schedule", every_hours: null }),
              },
              {
                label: "Every",
                on: s().automatic,
                pick: () => props.save({ kind: "schedule", every_hours: s().hours }),
              },
            ]}
          />
          <label class={`field-row ${s().automatic ? "" : "off"}`} for="hours">
            <span>Sweep every</span>
            <input
              id="hours"
              class="field num"
              type="number"
              min="1"
              max="168"
              value={s().hours}
              disabled={!s().automatic}
              onChange={(e) =>
                props.save({ kind: "schedule", every_hours: Number(e.currentTarget.value) })
              }
            />
            <span class="dim">hours</span>
          </label>
        </div>
      </div>
      <div class="block">
        <h2 class="label">History</h2>
        <div class="group pad">
          <Segmented
            choices={[
              {
                label: "All",
                on: s().all_history,
                pick: () => props.save({ kind: "history", since: "all" }),
              },
              {
                label: "Since",
                on: !s().all_history,
                pick: () => props.save({ kind: "history", since: s().since }),
              },
            ]}
          />
          <label class={`field-row ${s().all_history ? "off" : ""}`} for="since">
            <span>Advisories since</span>
            <input
              id="since"
              class="field"
              type="date"
              value={s().since}
              disabled={s().all_history}
              onChange={(e) => props.save({ kind: "history", since: e.currentTarget.value })}
            />
          </label>
        </div>
        <p class="note">
          How far back the first advisory download goes; later sweeps fetch changes.
        </p>
      </div>
    </>
  );
}

function Mac(props: Props & { onAdd: () => void }) {
  return (
    <>
      <div class="block">
        <h2 class="label">Folders searched for lockfiles</h2>
        <div class="group list">
          <For each={props.view.folders}>
            {(dir) => (
              <Toggle
                on={dir.chosen}
                icon="folder"
                title={dir.value}
                {...(dir.chosen ? {} : { sub: "suggested" })}
                onToggle={() =>
                  props.save({
                    kind: dir.chosen ? "remove_folder" : "add_folder",
                    dir: dir.value,
                  })
                }
              />
            )}
          </For>
          <button type="button" class="srow add" onClick={() => props.onAdd()}>
            <span class="lead-icon">
              <Icon name="plus" />
            </span>
            <span class="t">Add folder…</span>
          </button>
        </div>
      </div>
      <div class="block">
        <h2 class="label">Tools a Mac sweep reads</h2>
        <div class="tools">
          <For each={props.view.tools}>
            {(tool) => (
              <span
                class={`tool ${tool.path === null ? "no" : ""}`}
                title={tool.path ?? "not found"}
              >
                <i />
                {tool.name}
              </span>
            )}
          </For>
        </div>
        <p class="note">The ones not installed are skipped.</p>
      </div>
    </>
  );
}

function GitHub(props: Props) {
  const [typed, setTyped] = createSignal("");
  return (
    <>
      <div class="group">
        <div class="srow account">
          <Show
            when={props.view.gh_login}
            fallback={
              <>
                <span class="avatar off">?</span>
                <span class="what">
                  <span class="t">Not signed in</span>
                  <span class="s">Run gh auth login in a terminal to list your repositories.</span>
                </span>
                <span class="state warn">gh not logged in</span>
              </>
            }
          >
            {(login) => (
              <>
                <span class="avatar">{login().slice(0, 1).toUpperCase()}</span>
                <span class="what">
                  <span class="t">{login()}</span>
                  <span class="s">signed in with gh</span>
                </span>
                <span class="state ok">gh ready</span>
              </>
            )}
          </Show>
        </div>
      </div>
      <div class="block">
        <h2 class="label">Repositories</h2>
        <div class="group list scroll">
          <For each={props.view.repos}>
            {(repo) => (
              <Toggle
                on={repo.chosen}
                icon={repo.private === true ? "lock" : "repo"}
                title={repo.repo}
                {...(repo.private === null ? {} : { sub: repo.private ? "private" : "public" })}
                onToggle={() =>
                  props.save({ kind: repo.chosen ? "remove_repo" : "add_repo", repo: repo.repo })
                }
              />
            )}
          </For>
        </div>
        <form
          class="inline-add"
          onSubmit={(e) => {
            e.preventDefault();
            const sent = typed();
            void props
              .save({ kind: "add_repo", repo: sent })
              .then((ok) => ok && typed() === sent && setTyped(""));
          }}
        >
          <input
            id="repo"
            class="field grow"
            placeholder="owner/name"
            aria-label="Another repository"
            value={typed()}
            onInput={(e) => setTyped(e.currentTarget.value)}
          />
          <button type="submit" class="btn" disabled={typed().trim() === ""}>
            Add
          </button>
        </form>
      </div>
    </>
  );
}

function Servers(props: Props) {
  return (
    <div class="block">
      <Show
        when={props.view.servers.length > 0 || props.view.hosts.length > 0}
        fallback={
          <p class="empty">No hosts in ~/.ssh/config. Add one there, or edit config.toml.</p>
        }
      >
        <div class="group list scroll">
          <For each={props.view.servers}>
            {(server) => (
              <Toggle
                on
                icon="server"
                title={server.name}
                sub={
                  <>
                    ssh {server.reach}
                    <Show when={server.dirs.length > 0}> · {server.dirs.join(", ")}</Show>
                  </>
                }
                onToggle={() => props.save({ kind: "remove_server", name: server.name })}
              />
            )}
          </For>
          <For each={props.view.hosts}>
            {(host) => (
              <Toggle
                on={false}
                icon="server"
                title={host.alias}
                sub={`from ~/.ssh/config${host.host_name === null ? "" : ` · ${host.host_name}`}`}
                disabled={!host.addable}
                onToggle={() => props.save({ kind: "add_server", ssh: host.alias })}
              />
            )}
          </For>
        </div>
      </Show>
      <p class="note">
        A host needs its key in ~/.ssh/known_hosts and a login that does not prompt. Folders to
        search for lockfiles are set in config.toml.
      </p>
    </div>
  );
}

function Nvd(props: { view: SettingsView; onSave: (key: string) => Promise<boolean> }) {
  const [key, setKey] = createSignal("");
  return (
    <>
      <div class="group">
        <div class="srow account">
          <span class="lead-icon">
            <Icon name="key" />
          </span>
          <span class="what">
            <span class="t">NVD API key</span>
            <span class="s">free from nvd.nist.gov</span>
          </span>
          <span class={`state ${props.view.nvd_key ? "ok" : "warn"}`}>
            {props.view.nvd_key ? "In Keychain" : "Not set"}
          </span>
        </div>
      </div>
      <div class="block">
        <h2 class="label">Requests NVD allows per 30 seconds</h2>
        <div class="group pad rates">
          <For each={props.view.nvd_rates}>
            {(rate) => (
              <Rate
                rate={rate}
                most={Math.max(...props.view.nvd_rates.map((r) => r.per_30_seconds))}
              />
            )}
          </For>
        </div>
        <p class="note">
          Without a key, a first sweep of a Mac with many Homebrew formulae takes several minutes.
        </p>
      </div>
      <form
        class="inline-add"
        onSubmit={(e) => {
          e.preventDefault();
          // The key leaves the field only once it is in the Keychain.
          const sent = key();
          void props.onSave(sent).then((ok) => ok && key() === sent && setKey(""));
        }}
      >
        <input
          id="nvd-key"
          class="field grow mono"
          type="password"
          autocomplete="off"
          aria-label="NVD API key"
          placeholder={props.view.nvd_key ? "Replace the stored key" : "Paste your key"}
          value={key()}
          onInput={(e) => setKey(e.currentTarget.value)}
        />
        <button type="submit" class="btn primary" disabled={key().trim() === ""}>
          Save to Keychain
        </button>
      </form>
      <p class="note">
        Stored in your Keychain (service io.github.georgiosdelkos.vigil), never in config.toml or a
        report.
      </p>
    </>
  );
}

/** One of NVD's rate limits, drawn against the highest, `most`. */
function Rate(props: { rate: SettingsView["nvd_rates"][number]; most: number }) {
  return (
    <div class={`rate ${props.rate.applies ? "on" : ""}`}>
      <span class="rate-label">{props.rate.label}</span>
      <span class="meter">
        <i style={{ width: `${(props.rate.per_30_seconds / props.most) * 100}%` }} />
      </span>
      <span class="rate-n">{props.rate.per_30_seconds}</span>
    </div>
  );
}
