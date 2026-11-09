import { cleanup, fireEvent, render, screen, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App.tsx";
import { finding, overview, settingsView } from "./fixtures.ts";
import type { Overview, Status } from "./overview.ts";

const invoke = vi.hoisted(() => vi.fn());
const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return Promise.resolve(() => handlers.delete(name));
  },
}));
const login = vi.hoisted(() => ({ on: false, fail: false }));
vi.mock("@tauri-apps/plugin-autostart", () => ({
  isEnabled: () => Promise.resolve(login.on),
  enable: () => {
    if (login.fail) {
      return Promise.reject("launchctl refused");
    }
    login.on = true;
    return Promise.resolve();
  },
  disable: () => {
    login.on = false;
    return Promise.resolve();
  },
}));

let shown: Overview;

/** The target line labelled `label`. */
function row(label: string): HTMLElement {
  return screen.getByText(label, { selector: ".t" }).closest(".row") as HTMLElement;
}

/** The names on the finding rows, top to bottom. */
function names(): string[] {
  return [...document.querySelectorAll("button.row .t")].map(
    (t) => t.firstChild?.textContent ?? "",
  );
}

function answer(extra: Record<string, (args?: unknown) => unknown> = {}) {
  invoke.mockImplementation((command: string, args?: unknown) => {
    if (command === "overview") {
      return Promise.resolve(shown);
    }
    const reply = extra[command];
    return reply === undefined
      ? Promise.reject(new Error(`unexpected ${command}`))
      : Promise.resolve().then(() => reply(args));
  });
}

const two = () =>
  overview({
    findings: [
      finding("a", { name: "openssl", known_exploited: true, severity: "medium" }),
      finding("b", { name: "lodash", target: "me/app" }),
      finding("c", { name: "zlib", severity: "low", needs_you: false }),
    ],
    needs_you: 2,
    exploited: 1,
    counts: { critical: 0, high: 1, medium: 1, low: 1 },
    headline: "2 findings need you",
    last_swept: "2026-11-06T11:00:00Z",
    first_sweep_hint: null,
  });

/** What the spiral's canvas drew, and whether the test asks for reduced motion. */
const canvas = vi.hoisted(() => ({ dots: 0, reduce: false }));

/** A 2D context that counts the dots drawn: jsdom has none. */
const context = {
  setTransform: () => undefined,
  clearRect: () => undefined,
  createRadialGradient: () => ({ addColorStop: () => undefined }),
  beginPath: () => undefined,
  arc: () => {
    canvas.dots += 1;
  },
  fill: () => undefined,
};

/** Renders the popover and opens the list behind the main view. */
async function openList() {
  render(() => <App />);
  fireEvent.click(await screen.findByTitle("Open the list"));
}

beforeEach(() => {
  canvas.dots = 0;
  canvas.reduce = false;
  Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
    configurable: true,
    value: () => context,
  });
  vi.stubGlobal("matchMedia", (query: string) => ({
    media: query,
    matches: canvas.reduce && query === "(prefers-reduced-motion: reduce)",
  }));
  invoke.mockReset();
  handlers.clear();
  login.on = false;
  login.fail = false;
  shown = overview();
});
afterEach(cleanup);

/** A sweep on its only target with the agent running, stopping or not. */
function sweeping(stopping: boolean): Overview {
  return overview({
    busy: true,
    status: {
      state: "sweeping",
      step: "grok is judging 3 advisories",
      current: "This Mac",
      done: [],
      pending: [],
      position: 1,
      total: 1,
      percent: 50,
      target_end: 100,
      ticks: [],
      open_ended: true,
      stopping,
      started: new Date().toISOString(),
      step_started: new Date().toISOString(),
    },
  });
}

/** A fix whose agent is running, as Rust reports it. */
function fixing(): Status {
  return {
    state: "fixing",
    title: "other",
    place: "This Mac",
    activity: "upgrading openssl to 3.6.5",
    steps: [
      { label: "preparing the fix", state: "done" },
      { label: "grok is applying the fix", state: "now" },
      { label: "recording the result", state: "next" },
    ],
    started: new Date().toISOString(),
    step_started: new Date(Date.now() - 2 * 60_000).toISOString(),
  };
}

describe("the popover", () => {
  it("asks for an agent first, and opens the agent settings", async () => {
    shown = overview({ agent: null });
    answer({ settings_data: () => settingsView() });
    render(() => <App />);
    expect(await screen.findByText("Choose an agent to start")).toBeTruthy();
    fireEvent.click(screen.getByText("Choose an agent"));
    expect(
      await screen.findByText("Runs each sweep and, after you confirm, each fix."),
    ).toBeTruthy();
  });

  it("lists the findings in the order Rust ranked them, with its headline", async () => {
    shown = two();
    answer();
    await openList();
    expect(await screen.findByText("2 findings need you")).toBeTruthy();
    expect(screen.getByText("1 exploited in the wild")).toBeTruthy();
    expect(names()).toEqual(["openssl", "lodash"]);
    fireEvent.click(screen.getByRole("tab", { name: /All open/ }));
    expect(names()).toEqual(["openssl", "lodash", "zlib"]);
    expect(screen.getByText(/me\/app/)).toBeTruthy();
  });

  it("asks Rust again when it says something changed", async () => {
    answer();
    await openList();
    expect(await screen.findByText("Sweep")).toBeTruthy();
    shown = two();
    handlers.get("changed")?.({ payload: null });
    expect(await screen.findByText("2 findings need you")).toBeTruthy();
  });

  it("shows a running sweep's place as Rust counts it", async () => {
    shown = overview({
      busy: true,
      status: {
        state: "sweeping",
        step: "reading Homebrew",
        current: "me/app",
        done: ["This Mac"],
        pending: ["web"],
        position: 2,
        total: 3,
        percent: 50,
        target_end: 66,
        ticks: [33.3, 66.6],
        open_ended: true,
        stopping: false,
        started: new Date().toISOString(),
        step_started: new Date(Date.now() - 3 * 60_000).toISOString(),
      },
    });
    answer();
    await openList();
    expect(await screen.findByText("Sweeping me/app")).toBeTruthy();
    expect(screen.getByText(/target 2 of 3/)).toBeTruthy();
    expect(screen.getByText("reading Homebrew")).toBeTruthy();
    expect(screen.getByText("50%")).toBeTruthy();
    expect(screen.getByText("3 min")).toBeTruthy();

    const bar = screen.getByRole("progressbar", { name: "Sweep progress" });
    expect(bar.getAttribute("aria-valuenow")).toBe("50");
    expect(bar.getAttribute("aria-valuetext")).toBe("50%, reading Homebrew");
    const fill = bar.querySelector<HTMLElement>(".sweep-bar-fill");
    const work = bar.querySelector<HTMLElement>(".sweep-bar-work");
    expect(fill?.style.width).toBe("50%");
    expect([work?.style.left, work?.style.width]).toEqual(["50%", "16%"]);
    const ticks = [...bar.querySelectorAll<HTMLElement>(".sweep-bar-tick")];
    expect(ticks.map((t) => t.style.left)).toEqual(["33.3%", "66.6%"]);
  });

  it("fills the bar without the moving part while a step has a known length", async () => {
    shown = overview({
      busy: true,
      status: {
        state: "sweeping",
        step: "NVD 1/1: apple:macos",
        current: "This Mac",
        done: [],
        pending: [],
        position: 1,
        total: 1,
        percent: 27,
        target_end: 100,
        ticks: [],
        open_ended: false,
        stopping: false,
        started: new Date().toISOString(),
        step_started: new Date().toISOString(),
      },
    });
    answer();
    await openList();
    const bar = await screen.findByRole("progressbar", { name: "Sweep progress" });
    expect(bar.querySelector<HTMLElement>(".sweep-bar-fill")?.style.width).toBe("27%");
    expect(bar.querySelector(".sweep-bar-work")).toBeNull();
    expect(bar.querySelectorAll(".sweep-bar-tick")).toHaveLength(0);
  });

  it("marks a reported fix, an open pull request and a fix that did not hold", async () => {
    const at = new Date().toISOString();
    shown = overview({
      findings: [
        finding("a", {
          name: "curl",
          fix_state: { state: "reported", at, summary: "upgraded", pull_request: null },
        }),
        finding("b", {
          name: "lodash",
          fix_state: { state: "reported", at, summary: "bumped", pull_request: "https://x/pull/9" },
        }),
        finding("c", { name: "zlib", fix_state: { state: "not_held", at } }),
      ],
      needs_you: 3,
      headline: "3 findings need you",
      last_swept: at,
      first_sweep_hint: null,
    });
    answer();
    await openList();
    await screen.findByText("curl");
    expect(within(row("curl")).getByText("Fix reported")).toBeTruthy();
    expect(within(row("lodash")).getByText("Pull request open")).toBeTruthy();
    expect(within(row("zlib")).getByText("Still found after a fix")).toBeTruthy();
  });

  it("lists confirmed fixes in a tab of their own and when all is clear", async () => {
    const confirmed = {
      key: "f",
      title: "curl 8.0.0 is old",
      target: "This Mac",
      fixed_at: new Date(Date.now() - 5 * 60_000).toISOString(),
      summary: "upgraded curl to 8.11",
      pull_request: "https://github.com/o/r/pull/9",
    };
    shown = { ...two(), fixed: [confirmed] };
    answer();
    await openList();
    const tab = await screen.findByRole("tab", { name: /Fixed/ });
    expect(within(tab).getByText("1")).toBeTruthy();
    fireEvent.click(tab);
    const list = await screen.findByRole("list", { name: "Fixed" });
    expect(within(list).getByText("curl 8.0.0 is old")).toBeTruthy();
    expect(within(list).getByText("upgraded curl to 8.11")).toBeTruthy();
    expect(within(list).getByText("5 min ago")).toBeTruthy();
    expect(within(list).getByText(/pull\/9/)).toBeTruthy();

    cleanup();
    shown = overview({
      last_swept: "2026-11-06T11:00:00Z",
      first_sweep_hint: null,
      all_clear: true,
      fixed: [confirmed],
    });
    answer();
    await openList();
    expect(await screen.findByText("All clear")).toBeTruthy();
    expect(screen.getByText("Fixed in the last 30 days")).toBeTruthy();
    expect(screen.getByRole("list", { name: "Fixed" })).toBeTruthy();
  });

  it("cancels a running sweep, and shows it stopping", async () => {
    shown = sweeping(false);
    answer({ cancel_sweep: () => null });
    await openList();
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(invoke).toHaveBeenCalledWith("cancel_sweep");

    shown = sweeping(true);
    handlers.get("changed")?.({ payload: null });
    const stopping = await screen.findByRole("button", { name: "Stopping…" });
    expect((stopping as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("Stopping the agent and cleaning up…")).toBeTruthy();
  });

  it("shows all clear once a sweep found nothing", async () => {
    shown = overview({
      last_swept: "2026-11-06T11:00:00Z",
      first_sweep_hint: null,
      dismissed: 2,
      all_clear: true,
    });
    answer();
    await openList();
    expect(await screen.findByText("All clear")).toBeTruthy();
    expect(screen.getByText(/2 dismissed/)).toBeTruthy();
  });
});

describe("a finding", () => {
  it("runs its fix only after the preview is confirmed", async () => {
    shown = two();
    answer({
      fix_preview: () => ({
        destination: "this Mac",
        found: "2026-11-06T11:00:00Z",
        summary: "Update openssl",
        steps: [],
        commands: ["brew upgrade openssl"],
        agent: "claude",
      }),
      fix: () => null,
    });
    await openList();
    fireEvent.click(await screen.findByText("openssl"));
    fireEvent.click(screen.getByText("Fix…"));
    const confirm = await screen.findByText(/with full access\?/);
    expect(within(confirm).getByText("this Mac")).toBeTruthy();
    expect(screen.getByText("Update openssl")).toBeTruthy();
    expect(screen.getByLabelText("Commands the fix runs").textContent).toContain(
      "brew upgrade openssl",
    );
    expect(invoke).not.toHaveBeenCalledWith("fix", expect.anything());
    fireEvent.click(screen.getByText("Run fix"));
    expect(invoke).toHaveBeenCalledWith("fix", { key: "a", found: "2026-11-06T11:00:00Z" });

    // The finding stays selected, but once the fix runs its steps replace the confirmation.
    shown = { ...two(), busy: true, status: fixing() };
    handlers.get("changed")?.({ payload: null });
    expect(await screen.findByRole("list", { name: "Fix progress" })).toBeTruthy();
    expect(screen.queryByText("Run fix")).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
  });

  it("is dismissed with the reason given", async () => {
    shown = two();
    answer({ dismiss: () => null });
    await openList();
    fireEvent.click(await screen.findByText("lodash"));
    fireEvent.click(screen.getByText("Dismiss…"));
    const reason = screen.getByLabelText("Why does this not apply?");
    fireEvent.input(reason, { target: { value: "never loaded" } });
    fireEvent.submit((reason as HTMLInputElement).form as HTMLFormElement);
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("dismiss", { key: "b", reason: "never loaded" }),
    );
    expect(await screen.findByText("2 findings need you")).toBeTruthy();
  });

  it("shows a running fix's steps as Rust places them", async () => {
    shown = {
      ...two(),
      busy: true,
      status: fixing(),
    };
    answer();
    render(() => <App />);
    const steps = await screen.findByRole("list", { name: "Fix progress" });
    const rows = within(steps).getAllByRole("listitem");
    expect(rows.map((r) => r.className)).toEqual(["step done", "step now", "step next"]);
    expect(rows[1]?.getAttribute("aria-current")).toBe("step");
    expect(within(rows[1] as HTMLElement).getByText("grok is applying the fix")).toBeTruthy();
    expect(within(rows[1] as HTMLElement).getByText("2 min")).toBeTruthy();
    expect(screen.getByText("other")).toBeTruthy();
    expect(screen.getByText("This Mac · started just now")).toBeTruthy();
    expect(within(rows[1] as HTMLElement).getByText("upgrading openssl to 3.6.5")).toBeTruthy();
    expect(within(rows[0] as HTMLElement).queryByText("upgrading openssl to 3.6.5")).toBeNull();
    expect(rows[0]?.getAttribute("aria-current")).toBeNull();
    const live = document.querySelector("[aria-live=polite]");
    expect(live?.textContent?.trim()).toBe("grok is applying the fix");
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
  });

  it("cannot be fixed while a sweep runs", async () => {
    shown = {
      ...two(),
      busy: true,
      status: fixing(),
    };
    answer();
    render(() => <App />);
    expect(await screen.findByText("Fixing")).toBeTruthy();
  });
});

describe("the summary", () => {
  it("says when nothing was swept yet, and sweeps on demand", async () => {
    shown = overview({ headline: "Not swept yet", first_sweep_hint: "Rust's first-sweep line" });
    answer({ sweep_now: () => null });
    await openList();
    expect(await screen.findByText("Rust's first-sweep line")).toBeTruthy();
    // The headline says it once; the line under it shows Rust's hint, not a repeat.
    expect(screen.getAllByText(/not swept yet/i)).toHaveLength(1);
    expect(screen.queryByText(/exploited in the wild/)).toBeNull();
    fireEvent.click(screen.getByText("Sweep"));
    expect(invoke).toHaveBeenCalledWith("sweep_now");
  });

  it("shows a failed sweep, and why Sweep was refused", async () => {
    shown = {
      ...two(),
      status: { state: "failed", error: "no agent chosen" },
    };
    answer();
    invoke.mockImplementation((command: string) =>
      command === "overview" ? Promise.resolve(shown) : Promise.reject("a sweep is running"),
    );
    await openList();
    expect(await screen.findByText(/Last sweep: no agent chosen/)).toBeTruthy();
    expect(screen.getByText(/swept .* ago/)).toBeTruthy();
    fireEvent.click(screen.getByText("Sweep"));
    expect(await screen.findByText("a sweep is running")).toBeTruthy();
  });

  it("draws one bar part per severity found, and labels every severity", async () => {
    shown = two();
    answer();
    await openList();
    await screen.findByText("2 findings need you");
    const bar = document.querySelector(".bar") as HTMLElement;
    expect(bar.getAttribute("aria-label")).toBe("0 critical, 1 high, 1 medium, 1 low");
    expect([...bar.querySelectorAll("i")].map((i) => i.className)).toEqual([
      "high",
      "medium",
      "low",
    ]);
    expect((bar.querySelector("i") as HTMLElement).style.flexGrow).toBe("1");
    const legend = document.querySelectorAll(".legend > span");
    expect([...legend].map((s) => s.className)).toEqual(["none", "", "", ""]);
  });

  it("has no bar without findings", async () => {
    shown = overview({ headline: "All clear" });
    answer();
    await openList();
    await screen.findByText("Sweep");
    expect(document.querySelector(".bar")).toBeNull();
  });
});

describe("the tabs", () => {
  it("show Rust's counts, mark the open one, and say when one is empty", async () => {
    shown = overview({
      findings: [finding("c", { severity: "low", needs_you: false })],
      counts: { critical: 0, high: 0, medium: 0, low: 1 },
      headline: "1 open, none urgent",
    });
    answer();
    await openList();
    const needs = await screen.findByRole("tab", { name: /Needs you/ });
    expect(needs.textContent).toBe("Needs you 0");
    expect(needs.getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText("Nothing critical, high or exploited is open.")).toBeTruthy();
    const all = screen.getByRole("tab", { name: /All open/ });
    fireEvent.click(all);
    expect(all.getAttribute("aria-selected")).toBe("true");
    expect(needs.getAttribute("aria-selected")).toBe("false");
    expect(screen.getByRole("tab", { name: /Targets/ }).textContent).toBe("Targets 1");
  });

  it("list each target with what its last sweep found", async () => {
    shown = {
      ...two(),
      targets: [
        {
          label: "This Mac",
          kind: "mac",
          swept: "2026-11-06T11:00:00Z",
          checked: "42 components checked",
          counts: { critical: 0, high: 6, medium: 0, low: 0 },
          open: 6,
          dismissed: 1,
        },
        {
          label: "web",
          kind: "server",
          swept: "2026-11-06T11:00:00Z",
          checked: "3 components checked",
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          open: 0,
          dismissed: 0,
        },
        {
          label: "me/app",
          kind: "repo",
          swept: null,
          checked: null,
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          open: 0,
          dismissed: 0,
        },
      ],
    };
    answer();
    await openList();
    fireEvent.click(await screen.findByRole("tab", { name: /Targets/ }));
    expect(
      within(row("This Mac")).getByText(/42 components checked · swept .* ago · 1 dismissed/),
    ).toBeTruthy();
    // Only the severities it has, each named, and the open count in words.
    expect(row("This Mac").querySelector(".sevs")?.textContent).toBe("6 high");
    expect(row("This Mac").querySelector(".open")?.textContent).toBe("6 open");
    expect(row("web").textContent).not.toContain("dismissed");
    expect(row("web").querySelector(".sevs")).toBeNull();
    expect(row("web").querySelector(".open svg")).not.toBeNull();
    expect(row("web").querySelector(".open")?.textContent).toBe(" clear");
    // Glyphs beside the words are hidden from screen readers, so each severity is read once.
    expect(within(row("This Mac")).queryByRole("img", { name: "high" })).toBeNull();
    // Long lists scroll in their own focusable pane, under the summary and tabs.
    expect(screen.getByRole("list", { name: "Targets" }).classList.contains("pane")).toBe(true);
    expect(screen.getByRole("list", { name: "Targets" }).tabIndex).toBe(0);
    expect(within(row("me/app")).getByText("not swept yet")).toBeTruthy();
    expect(row("me/app").querySelector(".open")?.textContent).toBe("");
  });
});

describe("the rows", () => {
  it("show the version, advisories, place, fix and tags Rust gave", async () => {
    shown = overview({
      findings: [
        finding("a", { known_exploited: true, new: true }),
        finding("b", { new: true, version: null, advisories: [], place: "", first_seen: null }),
      ],
      needs_you: 2,
      headline: "2 findings need you",
    });
    answer();
    await openList();
    const a = (await screen.findByText("pkg-a")).closest("button") as HTMLElement;
    expect(within(a).getByText("1.0.0")).toBeTruthy();
    expect(within(a).getByText("GHSA-a")).toBeTruthy();
    expect(within(a).getByText(/This Mac · \/Users\/me\/code/)).toBeTruthy();
    expect(within(a).getByText("Update to 1.0.1")).toBeTruthy();
    // Tags sit on the advisories' line, so the age alone fills the right column.
    expect(a.querySelector(".tagline")?.textContent).toBe("GHSA-aExploited");
    expect(within(a).queryByText("New")).toBeNull();
    expect(a.querySelector(".age")?.textContent).not.toBe("");
    const b = screen.getByText("pkg-b").closest("button") as HTMLElement;
    expect(within(b).getByText("New")).toBeTruthy();
    expect(b.querySelector(".ver, .id")).toBeNull();
    expect(b.querySelector(".age")?.textContent).toBe("");
    expect(within(b).getByText("This Mac").textContent).toBe("This Mac");
  });
});

describe("the detail", () => {
  it("shows everything about the finding, and goes back with Back or Escape", async () => {
    shown = two();
    answer();
    await openList();
    fireEvent.click(await screen.findByText("openssl"));
    expect(screen.getByText("Reachable from the app.")).toBeTruthy();
    expect(screen.getByText("npm install pkg@1.0.1")).toBeTruthy();
    expect(screen.getByText("a", { selector: "dd" })).toBeTruthy();
    expect(screen.getByText(/exploited in the wild \(CISA KEV\)/)).toBeTruthy();
    expect(screen.getByText(/ ago$/, { selector: "dd" })).toBeTruthy();
    fireEvent.keyDown(window, { key: "Enter" });
    expect(screen.getByText("Reachable from the app.")).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByText("Reachable from the app.")).toBeNull();
    fireEvent.click(screen.getByText("lodash"));
    fireEvent.click(screen.getByText("Back"));
    expect(screen.getByText("2 findings need you")).toBeTruthy();
  });

  it("leaves out the parts a finding does not have", async () => {
    shown = overview({
      findings: [
        finding("x", {
          version: null,
          advisories: [],
          commands: [],
          explanation: "",
          place: "",
          first_seen: null,
        }),
      ],
      needs_you: 1,
    });
    answer();
    await openList();
    fireEvent.click(await screen.findByText("pkg-x"));
    expect(document.querySelector(".detail .ver, .detail .id, .cmd, .why")).toBeNull();
    expect(screen.queryByText("Found")).toBeNull();
  });

  it("shows why a fix or a dismissal failed, and cancels both", async () => {
    shown = two();
    invoke.mockImplementation((command: string) => {
      if (command === "overview") {
        return Promise.resolve(shown);
      }
      if (command === "fix_preview") {
        return Promise.resolve({
          destination: "this Mac",
          found: "2026-11-06T11:00:00Z",
          summary: "s",
          steps: [],
          commands: [],
          agent: "claude",
        });
      }
      return Promise.reject(`${command} refused`);
    });
    await openList();
    fireEvent.click(await screen.findByText("openssl"));
    fireEvent.click(screen.getByText("Fix…"));
    fireEvent.click(await screen.findByText("Run fix"));
    expect(await screen.findByText("fix refused")).toBeTruthy();
    fireEvent.click(screen.getByText("Cancel"));
    expect(screen.queryByText("Run fix")).toBeNull();
    fireEvent.click(screen.getByText("Dismiss…"));
    const reason = screen.getByLabelText("Why does this not apply?") as HTMLInputElement;
    fireEvent.input(reason, { target: { value: "x" } });
    fireEvent.submit(reason.form as HTMLFormElement);
    expect(await screen.findByText("dismiss refused")).toBeTruthy();
    expect(screen.getByText("Reachable from the app.")).toBeTruthy();
    fireEvent.click(screen.getByText("Cancel"));
    expect(screen.queryByLabelText("Why does this not apply?")).toBeNull();
  });

  it("shows why a fix preview was refused", async () => {
    shown = two();
    answer();
    invoke.mockImplementation((command: string, args?: { key: string }) =>
      command === "overview"
        ? Promise.resolve(shown)
        : Promise.reject(`no fix for ${args?.key ?? "?"}`),
    );
    await openList();
    fireEvent.click(await screen.findByText("openssl"));
    fireEvent.click(screen.getByText("Fix…"));
    expect(await screen.findByText("no fix for a")).toBeTruthy();
  });

  it("disables fixing while the app is busy", async () => {
    shown = two();
    answer();
    await openList();
    fireEvent.click(await screen.findByText("openssl"));
    const fix = screen.getByText("Fix…") as HTMLButtonElement;
    expect(fix.disabled).toBe(false);
    // A sweep, not a fix: a running fix shows its steps instead of the finding.
    shown = { ...two(), busy: true, status: sweeping(false).status };
    handlers.get("changed")?.({ payload: null });
    await vi.waitFor(() => expect(fix.disabled).toBe(true));
  });
});

describe("a finished fix", () => {
  it.each([
    ["fixed", "Fixed:", "banner good", "https://github.com/me/app/pull/7"],
    ["failed", "Fix failed:", "banner bad", null],
  ])("reads %s, and closes", async (outcome, label, className, pr) => {
    shown = two();
    answer();
    await openList();
    await screen.findByText("2 findings need you");
    handlers.get("fix-done")?.({
      payload: { key: "a", outcome, summary: "Updated openssl", pull_request: pr },
    });
    const banner = (await screen.findByText(label)).closest("p") as HTMLElement;
    expect(banner.className).toBe(className);
    expect(banner.querySelector(".pr")?.textContent ?? null).toBe(
      pr === null ? null : `Pull request: ${pr}`,
    );
    expect(banner.textContent).toContain("Updated openssl");
    fireEvent.click(within(banner).getByLabelText("Close"));
    expect(screen.queryByText(label)).toBeNull();
  });
});

describe("a problem", () => {
  it("with the config opens the settings", async () => {
    shown = overview({ problem: "config.toml line 3: bad", targets: [] });
    answer({ settings_data: () => settingsView() });
    render(() => <App />);
    expect(await screen.findByText("config.toml line 3: bad")).toBeTruthy();
    fireEvent.click(screen.getByText("Open settings"));
    expect(await screen.findByText("Done")).toBeTruthy();
    expect(document.querySelector(".foot")).toBeNull();
    fireEvent.click(screen.getByText("Done"));
    expect(document.querySelector(".foot")).not.toBeNull();
    expect(invoke.mock.calls.filter(([c]) => c === "overview").length).toBeGreaterThan(1);
  });

  it("does not hide the targets Rust could still read", async () => {
    shown = { ...two(), problem: "a report cannot be read" };
    answer();
    await openList();
    expect(await screen.findByText("2 findings need you")).toBeTruthy();
  });
});

describe("the footer", () => {
  it("names the agent and schedule, or says there is no agent", async () => {
    answer();
    await openList();
    expect(await screen.findByText("Claude Code · manual")).toBeTruthy();
    cleanup();
    shown = overview({ agent: null });
    render(() => <App />);
    expect(await screen.findByText("no agent · manual")).toBeTruthy();
  });

  it("opens a menu with settings, launch at login and quit", async () => {
    answer({ settings_data: () => settingsView(), quit: () => null });
    await openList();
    const gear = await screen.findByLabelText("Settings");
    expect(screen.queryByRole("menu")).toBeNull();
    fireEvent.click(gear);
    expect(gear.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(gear);
    expect(screen.queryByRole("menu")).toBeNull();
    fireEvent.click(gear);
    fireEvent.click(screen.getByText("Quit Vigil"));
    expect(invoke).toHaveBeenCalledWith("quit");
    fireEvent.click(screen.getByText("Settings…"));
    expect(await screen.findByText("Done")).toBeTruthy();
    expect(screen.queryByRole("menu")).toBeNull();
  });
});

describe("launch at login", () => {
  it("shows the real setting, and turns it on and off", async () => {
    login.on = true;
    answer();
    await openList();
    fireEvent.click(await screen.findByLabelText("Settings"));
    const box = screen.getByLabelText("Launch at login") as HTMLInputElement;
    await vi.waitFor(() => expect(box.checked).toBe(true));
    fireEvent.change(box, { target: { checked: false } });
    await vi.waitFor(() => expect(login.on).toBe(false));
    // Let the toggle read the setting back before the next click.
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(box.checked).toBe(false);
    fireEvent.change(box, { target: { checked: true } });
    await vi.waitFor(() => expect(login.on).toBe(true));
    expect(box.checked).toBe(true);
  });

  it("shows why it could not be turned on, and stays off", async () => {
    login.fail = true;
    answer();
    await openList();
    fireEvent.click(await screen.findByLabelText("Settings"));
    const box = screen.getByLabelText("Launch at login") as HTMLInputElement;
    fireEvent.change(box, { target: { checked: true } });
    expect(await screen.findByText("launchctl refused")).toBeTruthy();
    await vi.waitFor(() => expect(box.checked).toBe(false));
  });
});

describe("state across commands", () => {
  it("clears an old error when Sweep is pressed again", async () => {
    shown = two();
    let calls = 0;
    invoke.mockImplementation((command: string) => {
      if (command === "overview") {
        return Promise.resolve(shown);
      }
      calls += 1;
      return calls === 1 ? Promise.reject("busy") : new Promise(() => undefined);
    });
    await openList();
    fireEvent.click(await screen.findByText("Sweep"));
    expect(await screen.findByText("busy")).toBeTruthy();
    fireEvent.click(screen.getByText("Sweep"));
    expect(screen.queryByText("busy")).toBeNull();
  });

  it("closes the detail when its fix finishes", async () => {
    shown = two();
    answer();
    await openList();
    fireEvent.click(await screen.findByText("openssl"));
    expect(screen.getByText("Fix…")).toBeTruthy();
    handlers.get("fix-done")?.({
      payload: { key: "a", outcome: "fixed", summary: "done", pull_request: null },
    });
    await screen.findByText("Fixed:");
    expect(screen.queryByText("Fix…")).toBeNull();
  });

  it("says nothing about dismissals when there are none", async () => {
    shown = overview({
      last_swept: "2026-11-06T11:00:00Z",
      first_sweep_hint: null,
      all_clear: true,
    });
    answer();
    await openList();
    const text = (await screen.findByText(/target swept/)).textContent ?? "";
    expect(text).not.toContain("dismissed");
    expect(text).toMatch(/1 target swept .* ago\. Nothing open\./);
  });
});

describe("the main view", () => {
  it("shows what needs you, the most urgent finding and the targets", async () => {
    shown = two();
    answer();
    render(() => <App />);
    const count = await screen.findByTitle("Open the list");
    expect(within(count).getByText("2")).toBeTruthy();
    expect(within(count).getByText("need you")).toBeTruthy();
    expect(within(count).getByText("1 exploited")).toBeTruthy();
    const urgent = screen.getByText("openssl 1.0.0").closest("button") as HTMLElement;
    expect(within(urgent).getByText("exploited in the wild · This Mac")).toBeTruthy();
    expect(urgent.querySelector(".glow.beat")).not.toBeNull();
    expect(screen.getByRole("button", { name: /^This Mac/ })).toBeTruthy();
    expect(screen.getByText(/^swept .* ago$/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sweep now" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open report ↗" })).toBeTruthy();
    // The settings menu moves to the top; the footer would not fit under the spiral.
    expect(document.querySelector(".foot")).toBeNull();
    expect(screen.getByRole("button", { name: "Settings" })).toBeTruthy();
  });

  it("counts what is open when nothing needs you", async () => {
    shown = overview({
      findings: [finding("c", { name: "zlib", severity: "low", needs_you: false })],
      counts: { critical: 0, high: 0, medium: 0, low: 1 },
      headline: "1 open, none urgent",
      last_swept: "2026-11-06T11:00:00Z",
      first_sweep_hint: null,
    });
    answer();
    render(() => <App />);
    const count = await screen.findByTitle("Open the list");
    expect(count.textContent).toBe("1open");
    expect(screen.getByText("low · This Mac")).toBeTruthy();
  });

  it("says when nothing was swept yet", async () => {
    shown = overview({ headline: "Not swept yet" });
    answer();
    render(() => <App />);
    expect(await screen.findByText("Not swept yet")).toBeTruthy();
    expect(
      screen.getByText("Sweep checks your targets against the newest advisories."),
    ).toBeTruthy();
  });

  it("shows a running sweep's progress, and cancels it", async () => {
    shown = sweeping(false);
    answer({ cancel_sweep: () => null });
    render(() => <App />);
    const count = await screen.findByTitle("Open the list");
    expect(count.textContent).toBe("50%grok is judging 3 advisories");
    expect(screen.getByText("sweeping This Mac")).toBeTruthy();
    const bar = screen.getByRole("progressbar", { name: "Sweep progress" });
    expect(bar.querySelector("i")?.style.width).toBe("50%");
    expect(screen.getByText(/^target 1 of 1 · started/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Sweep now" })).toBeNull();
    expect(screen.getByRole("button", { name: "Open last report" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(invoke).toHaveBeenCalledWith("cancel_sweep");

    shown = sweeping(true);
    handlers.get("changed")?.({ payload: null });
    const stopping = await screen.findByRole("button", { name: "Stopping…" });
    expect((stopping as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows all clear in green, with the fixes confirmed", async () => {
    shown = overview({
      last_swept: "2026-11-06T11:00:00Z",
      first_sweep_hint: null,
      all_clear: true,
      target_count: "3 targets",
      schedule: "every 6 hours",
      targets: overview().targets.map((t) => ({ ...t, swept: "2026-11-06T11:00:00Z" })),
      fixed: [
        {
          key: "f",
          title: "curl",
          target: "This Mac",
          fixed_at: "2026-11-06T11:00:00Z",
          summary: "upgraded",
          pull_request: null,
        },
      ],
    });
    answer();
    render(() => <App />);
    const count = await screen.findByTitle("Open the list");
    expect(count.textContent).toBe("Clearnothing open");
    expect(document.querySelector(".orbit.green")).not.toBeNull();
    expect(screen.getByText("1 fixed in the last 30 days")).toBeTruthy();
    expect(screen.getByText("3 targets · every 6 hours")).toBeTruthy();
    const chip = screen.getByRole("button", { name: /^This Mac/ });
    expect(chip.querySelector("span")?.style.getPropertyValue("--c")).toBe("var(--n-green)");
  });

  it("opens the list from the count, and goes back with Back or Escape", async () => {
    shown = two();
    answer();
    render(() => <App />);
    fireEvent.click(await screen.findByTitle("Open the list"));
    expect(screen.getByText("2 findings need you")).toBeTruthy();
    expect(screen.getByRole("tab", { name: /Needs you/ }).getAttribute("aria-selected")).toBe(
      "true",
    );
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByTitle("Open the list")).toBeTruthy();
    fireEvent.click(screen.getByTitle("Open the list"));
    fireEvent.keyDown(window, { key: "Escape" });
    expect(await screen.findByTitle("Open the list")).toBeTruthy();
  });

  it("opens the most urgent finding, and goes back to the main view", async () => {
    shown = two();
    answer();
    render(() => <App />);
    fireEvent.click((await screen.findByText("openssl 1.0.0")).closest("button") as HTMLElement);
    expect(await screen.findByText("Reachable from the app.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByTitle("Open the list")).toBeTruthy();
  });

  it("opens the list at the targets from a target", async () => {
    shown = two();
    answer();
    render(() => <App />);
    fireEvent.click(await screen.findByRole("button", { name: /^This Mac/ }));
    expect(screen.getByRole("tab", { name: /Targets/ }).getAttribute("aria-selected")).toBe("true");
  });

  it("sweeps and opens the report, and shows why the report did not open", async () => {
    shown = two();
    answer({
      sweep_now: () => null,
      open_report: () => Promise.reject(new Error("no sweep has a report yet")),
    });
    render(() => <App />);
    fireEvent.click(await screen.findByRole("button", { name: "Sweep now" }));
    expect(invoke).toHaveBeenCalledWith("sweep_now");
    fireEvent.click(screen.getByRole("button", { name: "Open report ↗" }));
    expect(invoke).toHaveBeenCalledWith("open_report");
    expect(await screen.findByText("Error: no sweep has a report yet")).toBeTruthy();
  });

  it("draws one still frame under reduced motion", async () => {
    canvas.reduce = true;
    const frames = vi.spyOn(window, "requestAnimationFrame");
    shown = sweeping(false);
    answer();
    render(() => <App />);
    await screen.findByTitle("Open the list");
    const drawn = canvas.dots;
    expect(drawn).toBeGreaterThan(0);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(canvas.dots).toBe(drawn);
    expect(frames).not.toHaveBeenCalled();
    frames.mockRestore();
  });

  it("turns while a sweep runs, and stops while the popover is hidden", async () => {
    const frames = vi.spyOn(window, "requestAnimationFrame");
    const stop = vi.spyOn(window, "cancelAnimationFrame");
    shown = sweeping(false);
    answer();
    render(() => <App />);
    await screen.findByTitle("Open the list");
    expect(frames).toHaveBeenCalled();

    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
    expect(stop).toHaveBeenCalled();
    frames.mockClear();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(frames).not.toHaveBeenCalled();
    expect(document.querySelector(".orbit.paused")).not.toBeNull();

    // Restores jsdom's own getter.
    Reflect.deleteProperty(document, "visibilityState");
    frames.mockRestore();
    stop.mockRestore();
  });
});
