import { cleanup, fireEvent, render, screen, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Settings } from "./Settings.tsx";
import { settingsView } from "./fixtures.ts";
import type { UpdateView } from "./overview.ts";
import type { Section, SettingsView } from "./settings.ts";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

/** Answers each command with what `answers` gives for it. */
function answer(answers: Record<string, (args?: unknown) => unknown>) {
  invoke.mockImplementation((command: string, args?: unknown) => {
    const reply = answers[command];
    return reply === undefined
      ? Promise.reject(new Error(`unexpected ${command}`))
      : Promise.resolve().then(() => reply(args));
  });
}

/** The settings row holding `name`. */
async function row(name: string): Promise<HTMLElement> {
  return (await screen.findByText(name)).closest("button") as HTMLElement;
}

/** Whether the switch in the row holding `name` is on. */
async function on(name: string): Promise<string | null> {
  return (await row(name)).getAttribute("aria-checked");
}

/** The width of the meter on NVD's rate line labelled `label`. */
function meter(label: string): string | undefined {
  return screen.getByText(label).closest(".rate")?.querySelector("i")?.style.width;
}

/** The class of NVD's rate line labelled `label`. */
async function rate(label: string): Promise<string | undefined> {
  return (await screen.findByText(label)).closest(".rate")?.className;
}

/** The drop-down menu with this id, once the settings have loaded. */
async function menu(id: string): Promise<HTMLSelectElement> {
  return vi.waitFor(() => {
    const found = document.getElementById(id);
    if (!(found instanceof HTMLSelectElement)) {
      throw new Error(`no menu #${id}`);
    }
    return found;
  });
}

/** The text of what `aria-describedby` points at, as a screen reader reads it after the name. */
function described(element: HTMLElement): string {
  return (element.getAttribute("aria-describedby") ?? "")
    .split(" ")
    .map((id) => document.getElementById(id)?.textContent ?? "")
    .filter((text) => text !== "")
    .join(" ");
}

/** Picks `value` in the menu with this id. */
async function pick(id: string, value: string): Promise<void> {
  fireEvent.change(await menu(id), { target: { value } });
}

/** Each option of a menu: its value, its text, and whether it is disabled. */
async function options(id: string): Promise<[string, string, boolean][]> {
  return [...(await menu(id)).options].map((o) => [o.value, o.text, o.disabled]);
}

const NO_UPDATE: UpdateView = {
  version: "0.1.0",
  checks: true,
  checked: null,
  problem: null,
  ready: null,
};

function open(start: Section | null = null, update: UpdateView = NO_UPDATE) {
  const onClose = vi.fn();
  render(() => <Settings start={start} update={update} now={new Date()} onClose={onClose} />);
  return onClose;
}

beforeEach(() => {
  invoke.mockReset();
});
afterEach(cleanup);

describe("the section list", () => {
  it("shows each section with the summary Rust gave it, and closes with Done", async () => {
    answer({ settings_data: () => settingsView() });
    const onClose = open();
    expect(screen.getByText("Looking at what this Mac has…")).toBeTruthy();
    expect(await screen.findByText("Choose one")).toBeTruthy();
    expect(document.querySelector(".banner")).toBeNull();
    expect(screen.getByText("Choose one").className).toBe("val warn");
    expect(screen.getByText("1 folder").className).toBe("val ");
    expect(screen.getByText("1 folder").title).toBe("1 folder");
    fireEvent.click(screen.getByText("Done"));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("opens with Rust's headline and the sections in Rust's groups", async () => {
    answer({ settings_data: () => settingsView() });
    open();
    const headline = await screen.findByText("1 setting needs you");
    expect(headline.closest(".hero")?.className).toBe("hero needs");
    const labels = screen.getAllByRole("heading").map((h) => h.textContent);
    expect(labels).toEqual(["Sweeps", "Targets", "Advisories"]);
    cleanup();
    answer({ settings_data: () => settingsView({ headline: "Ready to sweep", ready: true }) });
    open();
    const ready = await screen.findByText("Ready to sweep");
    expect(ready.closest(".hero")?.className).toBe("hero ready");
  });

  it("marks a suggested folder, off until added", async () => {
    answer({ settings_data: () => settingsView() });
    open("mac");
    expect(await on("~/code")).toBe("true");
    expect(await on("~/src")).toBe("false");
    expect(within(await row("~/src")).getByText("suggested")).toBeTruthy();
    expect((await row("~/code")).querySelector(".s")).toBeNull();
  });

  it("draws each choice's state: switches, radios, segments and meters", async () => {
    answer({ settings_data: () => settingsView() });
    open("github");
    const knob = async (name: string) => (await row(name)).querySelector(".switch")?.className;
    expect(await knob("me/app")).toBe("switch on");
    expect(await knob("me/site")).toBe("switch ");
    expect((await row("me/app")).querySelector(".icon.lock")).toBeTruthy();
    expect((await row("me/site")).querySelector(".icon.repo")).toBeTruthy();
    expect(screen.getByText("M").className).toBe("avatar");
    cleanup();
    answer({ settings_data: () => settingsView() });
    open("schedule");
    expect((await screen.findByText("Since")).ariaPressed).toBe("false");
    expect(screen.getByText("All").ariaPressed).toBe("true");
    expect(screen.getByText("Sweep every").closest("label")?.className).toBe("field-row off");
    expect(screen.getByText("Advisories since").closest("label")?.className).toBe("field-row off");
    cleanup();
    answer({ settings_data: () => settingsView() });
    open("nvd");
    await screen.findByText("With a key");
    expect(meter("With a key")).toBe("100%");
    expect(screen.getByText("Not set").className).toBe("state warn");
  });

  it("highlights the NVD rate Rust says applies", async () => {
    answer({ settings_data: () => settingsView() });
    open("nvd");
    expect(await rate("Without a key")).toBe("rate on");
    expect(await rate("With a key")).toBe("rate ");
    cleanup();
    const rates = [
      { label: "Slow", per_30_seconds: 10, applies: false },
      { label: "Fast", per_30_seconds: 40, applies: true },
    ];
    answer({ settings_data: () => settingsView({ nvd_rates: rates }) });
    open("nvd");
    expect(await rate("Fast")).toBe("rate on");
    expect(meter("Slow")).toBe("25%");
    expect(meter("Fast")).toBe("100%");
    expect(screen.getByText("40")).toBeTruthy();
  });

  it("opens a section and goes back to the list", async () => {
    answer({ settings_data: () => settingsView() });
    open();
    fireEvent.click(await screen.findByText("This Mac"));
    expect(screen.getByText("Folders searched for lockfiles")).toBeTruthy();
    fireEvent.click(screen.getByText("Settings"));
    expect(screen.getByText("Choose one")).toBeTruthy();
  });

  it("looks again only when asked, and shows what it finds", async () => {
    let looked = 0;
    answer({
      settings_data: () => settingsView(),
      detect_again: () => {
        looked += 1;
        return settingsView({ nvd_key: true });
      },
    });
    open();
    fireEvent.click(await screen.findByText("Look again"));
    expect(screen.getByText("Looking…")).toBeTruthy();
    expect(await screen.findByText("Look again")).toBeTruthy();
    expect(looked).toBe(1);
  });

  it("shows why the config cannot be read, with a way to open it", async () => {
    invoke.mockImplementation((command: string) =>
      command === "settings_data"
        ? Promise.reject("config.toml line 2: expected a value")
        : Promise.resolve(),
    );
    open();
    expect(await screen.findByText(/line 2: expected a value/)).toBeTruthy();
    fireEvent.click(screen.getByText("Open config.toml"));
    expect(invoke).toHaveBeenCalledWith("open_config");
  });
});

describe("a change", () => {
  it("sends one setting and shows the view Rust returns, without detecting again", async () => {
    const chosen: SettingsView = settingsView({
      agents: [
        {
          agent: "claude",
          name: "Claude Code",
          path: "/bin/claude",
          available: true,
          chosen: true,
        },
        { agent: "codex", name: "Codex", path: null, available: false, chosen: false },
      ],
    });
    answer({ settings_data: () => settingsView(), save: () => chosen });
    open("agent");
    expect((await menu("agent")).value).toBe("-none");
    await pick("agent", "claude");
    expect(await screen.findByText("Saved")).toBeTruthy();
    expect((await menu("agent")).value).toBe("claude");
    expect(invoke).toHaveBeenCalledWith("save", { setting: { kind: "agent", agent: "claude" } });
    expect(invoke.mock.calls.filter(([c]) => c === "settings_data")).toHaveLength(1);
  });

  it("shows a refused change and keeps the settings as they were", async () => {
    answer({ settings_data: () => settingsView() });
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    invoke.mockImplementationOnce(() =>
      Promise.reject("mac.project_dirs[1]: use an absolute path"),
    );
    open("mac");
    fireEvent.click(await screen.findByText("~/code"));
    expect(await screen.findByText(/use an absolute path/)).toBeTruthy();
    expect(screen.queryByText("Saved")).toBeNull();
    expect(screen.getByText("~/code")).toBeTruthy();
  });

  it.each([
    ["mac", "~/code", { kind: "remove_folder", dir: "~/code" }],
    ["mac", "~/src", { kind: "add_folder", dir: "~/src" }],
    ["github", "me/app", { kind: "remove_repo", repo: "me/app" }],
    ["github", "me/site", { kind: "add_repo", repo: "me/site" }],
    ["servers", "web", { kind: "add_server", ssh: "web" }],
    ["schedule", "Every", { kind: "schedule", every_hours: 6 }],
    ["schedule", "Since", { kind: "history", since: "2025-01-01" }],
  ] as const)("in %s, clicking %s saves %o", async (section, text, setting) => {
    answer({ settings_data: () => settingsView(), save: () => settingsView() });
    open(section);
    fireEvent.click(await screen.findByText(text));
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenCalledWith("save", { setting });
  });

  it("does not offer a host whose alias cannot be a server name", async () => {
    answer({ settings_data: () => settingsView() });
    open("servers");
    const bad = await screen.findByText("bad host");
    expect(bad.closest("button")?.disabled).toBe(true);
  });

  it("adds a typed repository as typed; Rust trims and checks it", async () => {
    answer({ settings_data: () => settingsView(), save: () => settingsView() });
    open("github");
    const input = (await screen.findByPlaceholderText("owner/name")) as HTMLInputElement;
    const add = screen.getByText("Add") as HTMLButtonElement;
    expect(add.disabled).toBe(true);
    fireEvent.input(input, { target: { value: " other/lib " } });
    expect(add.disabled).toBe(false);
    fireEvent.submit(input.form as HTMLFormElement);
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenCalledWith("save", {
      setting: { kind: "add_repo", repo: " other/lib " },
    });
    expect(input.value).toBe("");
  });

  it("adds a picked folder, and does nothing when the picker is cancelled", async () => {
    let picked: SettingsView | null = null;
    answer({ settings_data: () => settingsView(), add_folder: () => picked });
    open("mac");
    fireEvent.click(await screen.findByText("Add folder…"));
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledWith("add_folder"));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(screen.queryByText("Saved")).toBeNull();
    picked = settingsView({ folders: [{ value: "/opt/work", chosen: true }] });
    fireEvent.click(screen.getByText("Add folder…"));
    expect(await screen.findByText("/opt/work")).toBeTruthy();
  });

  it("stores an NVD key and clears the field", async () => {
    answer({
      settings_data: () => settingsView(),
      set_nvd_key: () => settingsView({ nvd_key: true }),
    });
    open("nvd");
    const input = (await screen.findByPlaceholderText("Paste your key")) as HTMLInputElement;
    const save = screen.getByText("Save to Keychain") as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.input(input, { target: { value: "abc-123" } });
    expect(save.disabled).toBe(false);
    fireEvent.submit(input.form as HTMLFormElement);
    expect(await screen.findByText("In Keychain")).toBeTruthy();
    expect(invoke).toHaveBeenCalledWith("set_nvd_key", { key: "abc-123" });
    expect(input.value).toBe("");
  });
});

describe("each section shows what Rust found", () => {
  it("names the open section in the title, and starts without Saved", async () => {
    answer({ settings_data: () => settingsView() });
    open("github");
    expect(await screen.findByText("GitHub", { selector: ".navtitle" })).toBeTruthy();
    expect(screen.queryByText("Saved")).toBeNull();
    fireEvent.click(screen.getByText("Settings"));
    expect(screen.getByText("Settings", { selector: ".navtitle" })).toBeTruthy();
  });

  it("offers the agents found, and shows where the chosen one is", async () => {
    answer({ settings_data: () => settingsView() });
    open("agent");
    expect(await options("agent")).toEqual([
      ["-none", "Choose one", true],
      ["claude", "Claude Code", false],
      ["codex", "Codex (not found)", true],
    ]);
    expect(screen.queryByText("Found")).toBeNull();
    cleanup();
    const agents = settingsView().agents.map((a) => ({ ...a, chosen: a.agent === "claude" }));
    answer({ settings_data: () => settingsView({ agents }) });
    open("agent");
    expect((await options("agent")).map(([value]) => value)).toEqual(["claude", "codex"]);
    expect(screen.getByText("/bin/claude")).toBeTruthy();
    expect(screen.getByText("Found").className).toBe("state ok");
  });

  it("marks tools found or not", async () => {
    answer({
      settings_data: () =>
        settingsView({
          tools: [
            { name: "Homebrew", path: "/opt/homebrew/bin/brew" },
            { name: "uv", path: null },
          ],
        }),
    });
    open("mac");
    const brew = await screen.findByText("Homebrew");
    expect(brew.className).toBe("tool ");
    expect(brew.title).toBe("/opt/homebrew/bin/brew");
    expect(screen.getByText("uv").className).toBe("tool no");
    expect(screen.getByText("uv").title).toBe("not found");
  });

  it("shows a repository as private, public, or neither when typed", async () => {
    answer({
      settings_data: () =>
        settingsView({
          repos: [
            { repo: "me/app", private: true, chosen: true },
            { repo: "me/site", private: false, chosen: false },
            { repo: "other/lib", private: null, chosen: true },
          ],
        }),
    });
    open("github");
    expect(within(await row("me/app")).getByText("private")).toBeTruthy();
    expect(await on("me/app")).toBe("true");
    expect(within(await row("me/site")).getByText("public")).toBeTruthy();
    expect(await on("me/site")).toBe("false");
    expect((await row("other/lib")).querySelector(".s")).toBeNull();
  });

  it("asks for a gh login when there is none", async () => {
    answer({ settings_data: () => settingsView({ gh_login: null, repos: [] }) });
    open("github");
    expect(await screen.findByText("gh not logged in")).toBeTruthy();
  });

  it("lists swept servers with their folders, and removes one", async () => {
    answer({
      settings_data: () =>
        settingsView({
          servers: [
            { name: "web", reach: "web", dirs: ["/srv/app", "/srv/api"] },
            { name: "box", reach: "ops@10.0.0.9:2222", dirs: [] },
          ],
          hosts: [],
        }),
      save: () => settingsView(),
    });
    open("servers");
    expect(await screen.findByText("ssh web · /srv/app, /srv/api")).toBeTruthy();
    expect(screen.getByText("ssh ops@10.0.0.9:2222")).toBeTruthy();
    expect(screen.queryByText(/No hosts/)).toBeNull();
    expect(await on("web")).toBe("true");
    fireEvent.click(screen.getByText("box"));
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenCalledWith("save", {
      setting: { kind: "remove_server", name: "box" },
    });
  });

  it("shows a host's name beside its alias, and says when there are none", async () => {
    answer({ settings_data: () => settingsView() });
    open("servers");
    expect(await screen.findByText("from ~/.ssh/config · 10.0.0.5")).toBeTruthy();
    expect(screen.getByText("from ~/.ssh/config")).toBeTruthy();
    expect(screen.queryByText(/No hosts/)).toBeNull();
    cleanup();
    answer({ settings_data: () => settingsView({ servers: [], hosts: [] }) });
    open("servers");
    expect(await screen.findByText(/No hosts in ~\/.ssh\/config/)).toBeTruthy();
  });

  it("shows no folder list when there are none", async () => {
    answer({ settings_data: () => settingsView({ folders: [] }) });
    open("mac");
    await screen.findByText("Add folder…");
    expect(document.querySelector(".section .group")).toBeNull();
  });
});

describe("the schedule", () => {
  it("switches to manual and changes the hours and the date as typed", async () => {
    const automatic = settingsView({
      schedule: { automatic: true, hours: 4, all_history: false, since: "2026-01-01" },
    });
    answer({ settings_data: () => automatic, save: () => automatic });
    open("schedule");
    const hours = (await screen.findByDisplayValue("4")) as HTMLInputElement;
    expect(hours.disabled).toBe(false);
    fireEvent.change(hours, { target: { value: "12" } });
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenLastCalledWith("save", {
      setting: { kind: "schedule", every_hours: 12 },
    });
    const since = screen.getByDisplayValue("2026-01-01") as HTMLInputElement;
    expect(since.disabled).toBe(false);
    fireEvent.change(since, { target: { value: "2026-02-01" } });
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenLastCalledWith("save", {
        setting: { kind: "history", since: "2026-02-01" },
      }),
    );
    fireEvent.click(screen.getByText("Manual"));
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenLastCalledWith("save", {
        setting: { kind: "schedule", every_hours: null },
      }),
    );
    fireEvent.click(screen.getByText("All"));
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenLastCalledWith("save", {
        setting: { kind: "history", since: "all" },
      }),
    );
  });

  it("disables the fields that do not apply", async () => {
    answer({ settings_data: () => settingsView() });
    open("schedule");
    expect(((await screen.findByDisplayValue("6")) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByDisplayValue("2025-01-01") as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText("Manual").className).toBe("on");
    expect(screen.getByText("Every").className).toBe("");
  });
});

describe("the model", () => {
  const opencode = settingsView({
    model: {
      agent: "opencode",
      default: false,
      listed: true,
      hint: "Another model",
      providers: [
        {
          name: "opencode",
          label: "opencode",
          chosen: false,
          models: [
            {
              value: "opencode/big-pickle",
              label: "big-pickle",
              sub: "opencode/big-pickle",
              chosen: false,
            },
          ],
        },
        {
          name: "ollama",
          label: "ollama",
          chosen: true,
          models: [
            {
              value: "ollama/gemma4:e4b",
              label: "gemma4:e4b",
              sub: "ollama/gemma4:e4b",
              chosen: true,
            },
          ],
        },
      ],
    },
  });

  it("keeps a menu on what Rust has when a pick is refused", async () => {
    answer({ settings_data: () => opencode, save: () => Promise.reject("refused") });
    open("agent");
    await pick("agent", "claude");
    await screen.findByText(/refused/);
    expect((await menu("agent")).value).toBe("-none");
    await pick("model", "-default");
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledTimes(3));
    expect((await menu("model")).value).toBe("ollama/gemma4:e4b");
  });

  it("says when the chosen agent is not found", async () => {
    const agents = settingsView().agents.map((a) => ({ ...a, chosen: a.agent === "codex" }));
    answer({ settings_data: () => settingsView({ agents }) });
    open("agent");
    expect(await screen.findByText("not on your login shell's PATH")).toBeTruthy();
    expect(screen.getByText("Not found").className).toBe("state no");
    expect((await menu("agent")).value).toBe("codex");
  });

  it("closes Custom on another pick, and shows Rust's model if that pick is refused", async () => {
    answer({ settings_data: () => opencode, save: () => Promise.reject("refused") });
    open("agent");
    await pick("model", "-custom");
    fireEvent.input(await screen.findByPlaceholderText("Another model"), {
      target: { value: "draft" },
    });
    await pick("model", "-default");
    await screen.findByText(/refused/);
    expect(screen.queryByPlaceholderText("Another model")).toBeNull();
    expect((await menu("model")).value).toBe("ollama/gemma4:e4b");
    expect(invoke).not.toHaveBeenCalledWith("save", {
      setting: { kind: "model", agent: "opencode", model: "draft" },
    });
  });

  it("follows the model Rust's reply marks chosen", async () => {
    const one = opencode.model as NonNullable<SettingsView["model"]>;
    const picked = settingsView({
      model: {
        ...one,
        providers: one.providers.map((p) => ({
          ...p,
          chosen: p.name === "opencode",
          models: p.models.map((m) => ({ ...m, chosen: m.value === "opencode/big-pickle" })),
        })),
      },
    });
    answer({ settings_data: () => opencode, save: () => picked });
    open("agent");
    await pick("provider", "opencode");
    await pick("model", "-default");
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("save", {
        setting: { kind: "model", agent: "opencode", model: null },
      }),
    );
    await pick("model", "opencode/big-pickle");
    await screen.findByText("Saved");
    expect((await menu("provider")).value).toBe("opencode");
    expect((await menu("model")).value).toBe("opencode/big-pickle");
  });

  it("is offered only once an agent is chosen", async () => {
    answer({ settings_data: () => settingsView() });
    open("agent");
    await menu("agent");
    expect(document.getElementById("model")).toBeNull();
  });

  it("offers the chosen provider's models, and another provider's when picked", async () => {
    answer({ settings_data: () => opencode, save: () => opencode });
    open("agent");
    expect(await options("provider")).toEqual([
      ["opencode", "opencode", false],
      ["ollama", "ollama", false],
    ]);
    expect((await menu("provider")).value).toBe("ollama");
    expect(await options("model")).toEqual([
      ["-default", "Default", false],
      ["ollama/gemma4:e4b", "gemma4:e4b", false],
      ["-custom", "Custom…", false],
    ]);
    expect((await menu("model")).value).toBe("ollama/gemma4:e4b");
    await pick("provider", "opencode");
    expect((await menu("model")).value).toBe("-none");
    expect((await options("model"))[0]).toEqual(["-none", "Choose one", true]);
    expect(invoke).not.toHaveBeenCalledWith("save", expect.anything());
    await pick("model", "opencode/big-pickle");
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenCalledWith("save", {
      setting: { kind: "model", agent: "opencode", model: "opencode/big-pickle" },
    });
    await pick("model", "-default");
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("save", {
        setting: { kind: "model", agent: "opencode", model: null },
      }),
    );
  });

  it("names each menu by its label, and describes it by its hint and badge", async () => {
    const agents = opencode.agents.map((a) => ({ ...a, chosen: a.agent === "claude" }));
    answer({ settings_data: () => ({ ...opencode, agents }) });
    open("agent");
    await menu("model");
    const agent = screen.getByRole("combobox", { name: "Agent" });
    expect(agent.id).toBe("agent");
    expect(described(agent)).toBe("Found /bin/claude");
    expect(described(screen.getByRole("combobox", { name: "Provider" }))).toBe(
      "Whose models the list below offers.",
    );
    expect(described(screen.getByRole("combobox", { name: "Model" }))).toMatch(
      /^Default leaves the choice to the agent\./,
    );
    expect(screen.getByText(/Agents are found through your login shell/)).toBeTruthy();
  });

  it("shows the provider Rust marks once a save returns, whatever was picked", async () => {
    // Rust sends a new view with every reply.
    answer({ settings_data: () => opencode, save: () => structuredClone(opencode) });
    open("agent");
    await pick("provider", "opencode");
    await pick("model", "opencode/big-pickle");
    await screen.findByText("Saved");
    expect((await menu("provider")).value).toBe("ollama");
    expect((await menu("model")).value).toBe("ollama/gemma4:e4b");
  });

  it("opens a field for a custom model, empty each time, closed by the next view", async () => {
    answer({ settings_data: () => opencode, save: () => structuredClone(opencode) });
    open("agent");
    expect(screen.queryByPlaceholderText("Another model")).toBeNull();
    await pick("model", "-custom");
    const input = (await screen.findByPlaceholderText("Another model")) as HTMLInputElement;
    expect((await menu("model")).value).toBe("-custom");
    await vi.waitFor(() => expect(document.activeElement).toBe(input));
    expect(invoke).not.toHaveBeenCalledWith("save", expect.anything());
    expect((screen.getByText("Use") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(input, { target: { value: "  " } });
    expect((screen.getByText("Use") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(input, { target: { value: "ollama/qwen3" } });
    fireEvent.submit(input.form as HTMLFormElement);
    await screen.findByText("Saved");
    expect(invoke).toHaveBeenCalledWith("save", {
      setting: { kind: "model", agent: "opencode", model: "ollama/qwen3" },
    });
    expect(screen.queryByPlaceholderText("Another model")).toBeNull();
    await pick("model", "-custom");
    expect(((await screen.findByPlaceholderText("Another model")) as HTMLInputElement).value).toBe(
      "",
    );
  });

  it("keeps a custom model that Rust refuses, to be corrected", async () => {
    answer({ settings_data: () => opencode, save: () => Promise.reject("models.opencode: bad") });
    open("agent");
    await pick("model", "-custom");
    const input = (await screen.findByPlaceholderText("Another model")) as HTMLInputElement;
    fireEvent.input(input, { target: { value: "a b" } });
    fireEvent.submit(input.form as HTMLFormElement);
    expect(await screen.findByText(/models.opencode: bad/)).toBeTruthy();
    expect(input.value).toBe("a b");
  });

  it("does not bring a refused name back once another change went through", async () => {
    let saves = 0;
    answer({
      settings_data: () => opencode,
      save: () => {
        saves += 1;
        return saves === 1 ? Promise.reject("refused") : structuredClone(opencode);
      },
    });
    open("agent");
    await pick("model", "-custom");
    const input = (await screen.findByPlaceholderText("Another model")) as HTMLInputElement;
    fireEvent.input(input, { target: { value: "a b" } });
    fireEvent.submit(input.form as HTMLFormElement);
    await screen.findByText(/refused/);
    await pick("model", "-default");
    await screen.findByText("Saved");
    await pick("model", "-custom");
    expect(((await screen.findByPlaceholderText("Another model")) as HTMLInputElement).value).toBe(
      "",
    );
  });

  it("offers Default and Custom, and a provider menu only for several providers", async () => {
    const gemini = settingsView({
      model: {
        agent: "gemini",
        default: true,
        listed: false,
        hint: "Model name, as --model takes it",
        providers: [],
      },
    });
    answer({ settings_data: () => gemini });
    open("agent");
    expect(await options("model")).toEqual([
      ["-default", "Default", false],
      ["-custom", "Custom…", false],
    ]);
    expect((await menu("model")).value).toBe("-default");
    expect(document.getElementById("provider")).toBeNull();
    await pick("model", "-custom");
    const name = await screen.findByPlaceholderText("Model name, as --model takes it");
    // The field that takes the name hears the same constraint as the menu.
    expect(described(name)).toMatch(/any name its --model accepts/);
    cleanup();
    const one = opencode.model as NonNullable<SettingsView["model"]>;
    const single = { ...one, providers: one.providers.slice(1) };
    answer({ settings_data: () => settingsView({ model: single }) });
    open("agent");
    expect((await menu("model")).value).toBe("ollama/gemma4:e4b");
    expect(document.getElementById("provider")).toBeNull();
  });
});

describe("replies out of order", () => {
  it("drop a Look again reply that a newer change overtook", async () => {
    const replies: ((view: SettingsView) => void)[] = [];
    invoke.mockImplementation((command: string) =>
      command === "settings_data"
        ? Promise.resolve(settingsView())
        : new Promise<SettingsView>((resolve) => replies.push(resolve)),
    );
    open();
    fireEvent.click(await screen.findByText("Look again"));
    fireEvent.click(screen.getByText("Agent"));
    await pick("agent", "claude");
    replies[1]?.(settingsView({ headline: "after the change" }));
    await screen.findByText("Saved");
    replies[0]?.(settingsView({ headline: "before the change" }));
    await new Promise((resolve) => setTimeout(resolve, 10));
    fireEvent.click(screen.getByText("Settings"));
    expect(screen.getByText("after the change")).toBeTruthy();
    expect(screen.queryByText("before the change")).toBeNull();
  });

  it("show no error from a change a newer one overtook", async () => {
    const replies: { ok: (v: SettingsView) => void; no: (e: string) => void }[] = [];
    invoke.mockImplementation((command: string) =>
      command === "settings_data"
        ? Promise.resolve(settingsView())
        : new Promise<SettingsView>((ok, no) => replies.push({ ok, no })),
    );
    open("github");
    fireEvent.click(await screen.findByText("me/site"));
    fireEvent.click(screen.getByText("me/app"));
    replies[1]?.ok(settingsView());
    await screen.findByText("Saved");
    replies[0]?.no("stale refusal");
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(screen.queryByText(/stale refusal/)).toBeNull();
  });

  it("keep what was typed after a save was sent", async () => {
    let reply: ((view: SettingsView) => void) | undefined;
    invoke.mockImplementation((command: string) =>
      command === "settings_data"
        ? Promise.resolve(settingsView())
        : new Promise<SettingsView>((resolve) => (reply = resolve)),
    );
    open("github");
    const input = (await screen.findByPlaceholderText("owner/name")) as HTMLInputElement;
    fireEvent.input(input, { target: { value: "me/one" } });
    fireEvent.submit(input.form as HTMLFormElement);
    fireEvent.input(input, { target: { value: "me/two" } });
    reply?.(settingsView());
    await screen.findByText("Saved");
    expect(input.value).toBe("me/two");
  });
});

describe("errors", () => {
  it("clear on the next change, and Saved shows only after one succeeds", async () => {
    answer({ settings_data: () => settingsView() });
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    invoke.mockImplementationOnce(() => Promise.reject("refused"));
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    open("mac");
    fireEvent.click(await screen.findByText("~/code"));
    expect(await screen.findByText(/refused/)).toBeTruthy();
    fireEvent.click(screen.getByText("~/code"));
    expect(await screen.findByText("Saved")).toBeTruthy();
    expect(screen.queryByText(/refused/)).toBeNull();
  });

  it("show when looking again fails, and clear on the next try", async () => {
    answer({ settings_data: () => settingsView() });
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    invoke.mockImplementationOnce(() => Promise.reject("gh failed"));
    invoke.mockImplementationOnce(() => Promise.resolve(settingsView()));
    open();
    fireEvent.click(await screen.findByText("Look again"));
    expect(await screen.findByText(/gh failed/)).toBeTruthy();
    fireEvent.click(await screen.findByText("Look again"));
    await vi.waitFor(() => expect(screen.queryByText(/gh failed/)).toBeNull());
  });

  it("open config.toml from the section list", async () => {
    answer({ settings_data: () => settingsView(), open_config: () => null });
    open();
    fireEvent.click(await screen.findByText("Open config.toml"));
    expect(invoke).toHaveBeenCalledWith("open_config");
  });
});

describe("inputs", () => {
  it("do not send spaces alone", async () => {
    answer({ settings_data: () => settingsView() });
    open("github");
    fireEvent.input(await screen.findByPlaceholderText("owner/name"), {
      target: { value: "   " },
    });
    expect((screen.getByText("Add") as HTMLButtonElement).disabled).toBe(true);
    cleanup();
    open("nvd");
    fireEvent.input(await screen.findByPlaceholderText("Paste your key"), {
      target: { value: "  " },
    });
    expect((screen.getByText("Save to Keychain") as HTMLButtonElement).disabled).toBe(true);
  });

  it("offer to replace an NVD key already stored", async () => {
    answer({ settings_data: () => settingsView({ nvd_key: true }) });
    open("nvd");
    expect(await screen.findByPlaceholderText("Replace the stored key")).toBeTruthy();
    expect(screen.getByText("In Keychain").className).toBe("state ok");
  });
});

describe("quick changes", () => {
  it("show the reply to the newest one, even when an older reply comes later", async () => {
    const replies: ((view: SettingsView) => void)[] = [];
    invoke.mockImplementation((command: string) =>
      command === "settings_data"
        ? Promise.resolve(settingsView())
        : new Promise<SettingsView>((resolve) => replies.push(resolve)),
    );
    open("github");
    fireEvent.click(await screen.findByText("me/site"));
    fireEvent.click(screen.getByText("me/app"));
    const newer = settingsView({
      repos: [
        { repo: "me/app", private: true, chosen: false },
        { repo: "me/site", private: false, chosen: true },
      ],
    });
    replies[1]?.(newer);
    await screen.findByText("Saved");
    replies[0]?.(settingsView());
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(await on("me/app")).toBe("false");
    expect(await on("me/site")).toBe("true");
  });
});

describe("the version line", () => {
  it("shows the version and when updates were last checked", async () => {
    answer({ settings_data: () => settingsView() });
    const checked = new Date(Date.now() - 5 * 60_000).toISOString();
    open(null, { ...NO_UPDATE, checked });
    expect(await screen.findByText("Vigil 0.1.0 · checked for updates 5 min ago")).toBeTruthy();
  });

  it("says when updates are not checked yet, and when this build never checks", async () => {
    answer({ settings_data: () => settingsView() });
    open();
    expect(
      await screen.findByText("Vigil 0.1.0 · checks for updates at start and every 12 hours"),
    ).toBeTruthy();
    cleanup();
    open(null, { ...NO_UPDATE, checks: false });
    expect(
      await screen.findByText(/this build does not check for updates; installed releases do/),
    ).toBeTruthy();
  });

  it("shows a failed check quietly, as Rust words it", async () => {
    answer({ settings_data: () => settingsView() });
    open(null, { ...NO_UPDATE, problem: "the last check failed: offline" });
    expect(await screen.findByText("the last check failed: offline")).toBeTruthy();
    expect(document.querySelector(".banner")).toBeNull();
  });
});
