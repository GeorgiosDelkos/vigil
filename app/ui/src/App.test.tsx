import { cleanup, fireEvent, render, screen, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App.tsx";
import { advisory, component, finding, overview, settingsView } from "./fixtures.ts";
import { sceneOf } from "./Orbit.tsx";
import type { Listed, Overview, ReportedFix, Status } from "./overview.ts";

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

/** The target row named `label` in the list's Targets tab. */
function listTarget(label: string): HTMLElement {
  return screen.getByText(label, { selector: ".tname" }).closest(".trow") as HTMLElement;
}

/** A target row's count columns as number and word, dimmed ones in brackets. */
function counts(target: HTMLElement): string[] {
  return [...target.querySelectorAll(".tcount")].map((c) => {
    const text = `${c.querySelector("b")?.textContent ?? ""} ${c.querySelector("small")?.textContent ?? ""}`;
    return c.classList.contains("zero") ? `(${text})` : text;
  });
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

/** `item` as a fix the agent reported 5 minutes ago, as Rust sets it apart. */
function reportedFix(item: Listed): ReportedFix {
  return {
    item,
    status: "Fixed · the next sweep confirms it",
    summary: `upgraded ${item.name}`,
    fixed_at: new Date(Date.now() - 5 * 60_000).toISOString(),
  };
}

const two = () =>
  overview({
    items: [
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

/** How often the spiral's canvas was painted, and the browser events that repaint it. */
const canvas = vi.hoisted(() => ({
  paints: 0,
  /** Reports a new size for the spiral's canvas, as the browser's ResizeObserver would. */
  resize: undefined as ((width: number, height: number) => void) | undefined,
  /** Reports that the display's pixel ratio changed, as a resolution media query would. */
  moved: undefined as (() => void) | undefined,
}));

/** A 2D context that counts whole paints (one `clearRect` each): jsdom has none. */
const gradient = () => ({ addColorStop: () => undefined });
const context = {
  setTransform: () => undefined,
  clearRect: () => {
    canvas.paints += 1;
  },
  createRadialGradient: gradient,
  createLinearGradient: gradient,
  fillRect: () => undefined,
  beginPath: () => undefined,
  lineTo: () => undefined,
  stroke: () => undefined,
};

/** The target row named `name`: its checked line, count columns (dimmed ones in brackets), bar segments as count and colour, and
 * whether its bar is the all-clear green. */
function targetRow(name: RegExp): {
  sub: string;
  counts: string[];
  bar: string[];
  clear: boolean;
} {
  const button = screen.getByRole("button", { name });
  return {
    sub: button.querySelector(".tsub")?.textContent ?? "",
    counts: counts(button),
    bar: [...button.querySelectorAll<HTMLElement>(".tbar i")].map(
      (i) => `${i.style.flexGrow} ${i.style.getPropertyValue("--c")}`,
    ),
    clear: button.querySelector(".tbar.ok") !== null,
  };
}

/** Renders the popover and opens the list behind the main view. */
async function openList() {
  render(() => <App />);
  fireEvent.click(await screen.findByTitle("Show details"));
}

beforeEach(() => {
  canvas.paints = 0;
  canvas.moved = undefined;
  Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
    configurable: true,
    value: () => context,
  });
  canvas.resize = undefined;
  vi.stubGlobal(
    "ResizeObserver",
    class {
      constructor(callback: ResizeObserverCallback) {
        canvas.resize = (width, height) =>
          callback([{ contentRect: { width, height } } as ResizeObserverEntry], this);
      }
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  vi.stubGlobal("matchMedia", (query: string) => ({
    media: query,
    matches: false,
    addEventListener: (_: string, listener: () => void) => {
      canvas.moved = listener;
    },
    removeEventListener: () => undefined,
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

  it("marks an open item's pending fix as Rust decides it over all its findings", async () => {
    const at = new Date().toISOString();
    const reported = { state: "reported", at, summary: "upgraded", pull_request: null } as const;
    shown = overview({
      items: [
        // A fix reported for one advisory, but a later sweep still found another.
        component(
          "a",
          [
            advisory("a1", { name: "curl", fix_state: reported }),
            advisory("a2", { name: "curl", fix_state: { state: "not_held", at } }),
          ],
          { pending_fix: "not_held" },
        ),
        {
          ...finding("b", {
            name: "lodash",
            fix_state: { ...reported, pull_request: "https://x/pull/9" },
          }),
          pending_fix: "pull_request",
        },
        { ...finding("c", { name: "zlib" }), pending_fix: "not_held" },
      ],
      needs_you: 3,
      headline: "3 findings need you",
      last_swept: at,
      first_sweep_hint: null,
    });
    answer();
    await openList();
    await screen.findByText("curl");
    expect(within(row("curl")).getByText("Still found after a fix")).toBeTruthy();
    expect(within(row("curl")).queryByText("Fix reported")).toBeNull();
    expect(within(row("lodash")).getByText("Pull request open")).toBeTruthy();
    expect(within(row("zlib")).getByText("Still found after a fix")).toBeTruthy();

    // Each advisory in the detail still says what its own fix came to.
    fireEvent.click(row("curl"));
    const advisories = await screen.findByRole("list", { name: "Advisories" });
    expect(within(advisories).getByText("Fix reported")).toBeTruthy();
    expect(within(advisories).getByText("Still found after a fix")).toBeTruthy();
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

  it("lists a reported fix green under Fixed, above the confirmed ones, and not as open", async () => {
    const node = finding("n", { name: "node.js", version: "22.22.2", known_exploited: true });
    shown = {
      ...two(),
      reported: [reportedFix(node)],
      fixed: [
        {
          key: "f",
          title: "curl 8.0.0 is old",
          target: "This Mac",
          fixed_at: "2026-11-06T11:00:00Z",
          summary: "upgraded curl",
          pull_request: null,
        },
      ],
    };
    answer();
    await openList();
    fireEvent.click(await screen.findByRole("tab", { name: /All open/ }));
    expect(names()).toEqual(["openssl", "lodash", "zlib"]);

    const tab = screen.getByRole("tab", { name: /Fixed/ });
    expect(within(tab).getByText("2")).toBeTruthy();
    fireEvent.click(tab);
    const list = await screen.findByRole("list", { name: "Fixed" });
    const rows = [...list.querySelectorAll(".fixed-row .t")].map((t) => t.textContent);
    expect(rows).toEqual(["node.js22.22.2", "curl 8.0.0 is old"]);
    const first = list.querySelector(".fixed-row") as HTMLElement;
    const status = within(first).getByText("Fixed · the next sweep confirms it");
    expect(status.classList.contains("confirming")).toBe(true);
    expect(within(first).getByText("upgraded node.js")).toBeTruthy();
    expect(within(first).getByText("5 min ago")).toBeTruthy();
    expect(first.querySelector(".icon.done")).not.toBeNull();
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
    const empty = overview();
    shown = overview({
      last_swept: "2026-11-06T11:00:00Z",
      first_sweep_hint: null,
      dismissed: 2,
      all_clear: true,
      targets: empty.targets.map((t) => ({ ...t, swept: "2026-11-06T11:00:00Z" })),
    });
    answer();
    await openList();
    expect(await screen.findByText("All clear")).toBeTruthy();
    expect(screen.getByText(/2 dismissed/)).toBeTruthy();
    // Its targets are the shared target rows: four dimmed zeros and the green bar.
    expect(counts(listTarget("This Mac"))).toEqual([
      "(0 critical)",
      "(0 high)",
      "(0 medium)",
      "(0 low)",
    ]);
    expect(listTarget("This Mac").querySelector(".tbar.ok")).not.toBeNull();
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
    // One spinner, on the running step: a second in the header only distracts.
    const spinners = document.querySelectorAll(".spin");
    expect(spinners.length).toBe(1);
    expect(rows[1]?.contains(spinners[0] as Node)).toBe(true);
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

/** ffmpeg 8.1.2 with three advisories, `f2` exploited and so the lead, as Rust ranks them. */
function ffmpeg(keys: readonly string[] = ["f2", "f1", "f3"]): Overview["items"][number] {
  const all = {
    f1: {
      severity: "critical",
      explanation: "Overflow in the demuxer.",
      evidence: "8.1.2 < 8.1.3",
    },
    f2: { severity: "medium", explanation: "Crash on a crafted file.", known_exploited: true },
    f3: { severity: "low", explanation: "Leaks a little memory.", evidence: "only with -i" },
  } as const;
  const found = keys.map((key) =>
    advisory(key, {
      ...all[key as keyof typeof all],
      name: "ffmpeg",
      version: "8.1.2",
      place: "Homebrew formula ffmpeg",
      advisories: [`CVE-2026-${key}`],
      fix: "Upgrade ffmpeg.",
      commands: ["brew upgrade ffmpeg"],
    }),
  );
  const [lead, ...others] = found;
  if (lead === undefined) {
    throw new Error("a component has at least one finding");
  }
  return component("c-ffmpeg", [lead, ...others], {
    severity: "critical",
    known_exploited: keys.includes("f2"),
  });
}

const grouped = (item = ffmpeg()) =>
  overview({
    items: [
      item,
      finding("i", {
        name: "default_branch_protection",
        version: null,
        advisories: [],
        place: "",
        severity: "low",
        needs_you: false,
        target: "me/app",
      }),
    ],
    needs_you: 1,
    exploited: 1,
    counts: { critical: 1, high: 0, medium: 0, low: 1 },
    headline: "1 finding needs you",
    last_swept: "2026-11-06T11:00:00Z",
    first_sweep_hint: null,
  });

describe("a component", () => {
  it("is one row with its worst severity, how many advisories and one fix", async () => {
    shown = grouped();
    answer();
    await openList();
    await screen.findByText("ffmpeg");
    expect(names()).toEqual(["ffmpeg"]);
    const ffmpegRow = screen.getByText("ffmpeg").closest("button") as HTMLElement;
    expect(within(ffmpegRow).getByRole("img", { name: "critical" })).toBeTruthy();
    expect(within(ffmpegRow).getByText("3 advisories")).toBeTruthy();
    expect(within(ffmpegRow).getByText("Exploited")).toBeTruthy();
    expect(within(ffmpegRow).getByText("Upgrade ffmpeg.")).toBeTruthy();
    expect(within(ffmpegRow).queryByText(/CVE-2026/)).toBeNull();
    expect(within(screen.getByRole("tab", { name: /All open/ })).getByText("2")).toBeTruthy();
    expect(within(screen.getByRole("tab", { name: /Needs you/ })).getByText("1")).toBeTruthy();
    expect(screen.getByRole("img", { name: "1 critical, 0 high, 0 medium, 1 low" })).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: /All open/ }));
    expect(names()).toEqual(["ffmpeg", "default_branch_protection"]);
  });

  it("goes by the name Rust gives it, a formula's over its product's", async () => {
    const curl = component("c-curl", [
      advisory("l", { name: "libcurl", version: "8.11.0" }),
      advisory("c", { name: "curl", version: "8.11.0" }),
    ]);
    shown = { ...grouped({ ...curl, name: "curl" }) };
    answer();
    await openList();
    expect(await screen.findByText("curl")).toBeTruthy();
    expect(screen.queryByText("libcurl")).toBeNull();
    fireEvent.click(screen.getByText("curl"));
    expect((await screen.findByRole("heading")).textContent).toBe("curl 8.11.0");
  });

  it("is what the main view counts and names first", async () => {
    shown = grouped();
    answer();
    render(() => <App />);
    const count = await screen.findByTitle("Show details");
    expect(count.textContent).toBe("1need you1 exploitedShow details");
    const urgent = screen.getByText("ffmpeg 8.1.2").closest("button") as HTMLElement;
    expect(
      within(urgent).getByText("exploited in the wild · 3 advisories · This Mac"),
    ).toBeTruthy();
    fireEvent.click(urgent);
    expect(await screen.findByRole("list", { name: "Advisories" })).toBeTruthy();
  });

  it("lists each advisory with its own severity, explanation and evidence", async () => {
    shown = grouped();
    answer();
    await openList();
    fireEvent.click(await screen.findByText("ffmpeg"));
    const list = await screen.findByRole("list", { name: "Advisories" });
    const advisories = within(list).getAllByRole("listitem");
    expect(advisories.map((a) => a.querySelector("summary")?.textContent)).toEqual([
      "CVE-2026-f2Exploitedmedium",
      "CVE-2026-f1critical",
      "CVE-2026-f3low",
    ]);
    const [, f1] = advisories;
    expect(within(f1 as HTMLElement).getByText("Overflow in the demuxer.")).toBeTruthy();
    expect(within(f1 as HTMLElement).getByText("8.1.2 < 8.1.3")).toBeTruthy();
    expect(within(f1 as HTMLElement).getByText("f1")).toBeTruthy();
    // One fix for the component, its commands once; dismissing is per advisory.
    expect(screen.getAllByText("brew upgrade ffmpeg")).toHaveLength(1);
    expect(screen.getByText("3 advisories")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Dismiss…" })).toHaveLength(3);
  });

  it("runs the lead's fix, saying it is for the component", async () => {
    shown = grouped();
    answer({
      fix_preview: () => ({
        destination: "this Mac",
        found: "2026-11-06T11:00:00Z",
        summary: "Upgrade ffmpeg.",
        steps: [],
        commands: ["brew upgrade ffmpeg"],
        agent: "claude",
      }),
      fix: () => null,
    });
    await openList();
    fireEvent.click(await screen.findByText("ffmpeg"));
    fireEvent.click(screen.getByText("Fix…"));
    expect(await screen.findByText(/which all 3 advisories are in; the next sweep/)).toBeTruthy();
    expect(invoke).toHaveBeenCalledWith("fix_preview", { key: "f2" });
    // The lead dismissed elsewhere while the preview shows: Run fix still runs the fix shown.
    shown = grouped(ffmpeg(["f1", "f3"]));
    handlers.get("changed")?.({ payload: null });
    await vi.waitFor(() => expect(screen.getByText("2 advisories")).toBeTruthy());
    fireEvent.click(screen.getByText("Run fix"));
    expect(invoke).toHaveBeenCalledWith("fix", { key: "f2", found: "2026-11-06T11:00:00Z" });
  });

  it("marks an advisory whose fix did not hold, not only the lead", async () => {
    const item = ffmpeg();
    const [f1, f3] = item.others;
    if (f1 === undefined || f3 === undefined) {
      throw new Error("ffmpeg has three findings");
    }
    const at = "2026-11-06T10:00:00Z";
    shown = grouped({ ...item, others: [{ ...f1, fix_state: { state: "not_held", at } }, f3] });
    answer();
    await openList();
    fireEvent.click(await screen.findByText("ffmpeg"));
    const list = await screen.findByRole("list", { name: "Advisories" });
    const [, held] = within(list).getAllByRole("listitem");
    expect(within(held as HTMLElement).getByText("Still found after a fix")).toBeTruthy();
  });

  it("dismisses one advisory and keeps showing the rest", async () => {
    shown = grouped();
    answer({ dismiss: () => null });
    await openList();
    fireEvent.click(await screen.findByText("ffmpeg"));
    const list = await screen.findByRole("list", { name: "Advisories" });
    const f1 = within(list).getAllByRole("listitem")[1] as HTMLElement;
    fireEvent.click(within(f1).getByRole("button", { name: "Dismiss…" }));
    const reason = within(f1).getByLabelText("Why does this not apply?");
    fireEvent.input(reason, { target: { value: "no demuxer" } });
    fireEvent.submit((reason as HTMLInputElement).form as HTMLFormElement);
    await vi.waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("dismiss", { key: "f1", reason: "no demuxer" }),
    );

    shown = grouped(ffmpeg(["f2", "f3"]));
    handlers.get("changed")?.({ payload: null });
    await vi.waitFor(() => expect(screen.getByText("2 advisories")).toBeTruthy());
    expect(screen.getByRole("list", { name: "Advisories" })).toBeTruthy();

    // With every advisory dismissed the item is gone, and so is its detail.
    shown = { ...grouped(), items: [] };
    handlers.get("changed")?.({ payload: null });
    await vi.waitFor(() => expect(screen.queryByText("ffmpeg")).toBeNull());
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
      items: [finding("c", { severity: "low", needs_you: false })],
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
          to_confirm: null,
          dismissed: 1,
        },
        {
          label: "web",
          kind: "server",
          swept: "2026-11-06T11:00:00Z",
          checked: "3 components checked",
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          open: 0,
          to_confirm: null,
          dismissed: 0,
        },
        {
          label: "me/app",
          kind: "repo",
          swept: null,
          checked: null,
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          open: 0,
          to_confirm: null,
          dismissed: 0,
        },
        {
          label: "db",
          kind: "server",
          swept: "2026-11-06T11:00:00Z",
          checked: "9 components checked",
          counts: { critical: 1, high: 0, medium: 2, low: 0 },
          open: 3,
          to_confirm: null,
          dismissed: 0,
        },
      ],
    };
    answer();
    await openList();
    fireEvent.click(await screen.findByRole("tab", { name: /Targets/ }));
    // Several severities are named worst first, in the main view's words.
    expect(listTarget("db").querySelector(".sr-only")?.textContent).toBe(
      "3 open: 1 critical, 2 medium",
    );
    expect(
      within(listTarget("This Mac")).getByText(
        /42 components checked · swept .* ago · 1 dismissed/,
      ),
    ).toBeTruthy();
    // Every severity in its column, as on the main view, and the ones it has named in words.
    expect(counts(listTarget("This Mac"))).toEqual([
      "(0 critical)",
      "6 high",
      "(0 medium)",
      "(0 low)",
    ]);
    expect(listTarget("This Mac").querySelector(".sr-only")?.textContent).toBe("6 open: 6 high");
    expect(listTarget("This Mac").querySelector(".tbar i")?.getAttribute("style")).toContain(
      "--high",
    );
    expect(listTarget("This Mac").querySelector(".open")?.textContent).toBe("6 open");
    expect(listTarget("web").textContent).not.toContain("dismissed");
    expect(listTarget("web").querySelector(".sr-only")?.textContent).toBe("clear");
    expect(listTarget("web").querySelector(".tbar.ok")).not.toBeNull();
    expect(listTarget("web").querySelector(".open svg")).not.toBeNull();
    expect(listTarget("web").querySelector(".open")?.textContent).toBe(" clear");
    // The drawn counts are hidden from screen readers, so each severity is read once.
    expect(listTarget("This Mac").querySelector(".tcounts")?.getAttribute("aria-hidden")).toBe(
      "true",
    );
    // Long lists scroll in their own focusable pane, under the summary and tabs.
    expect(screen.getByRole("list", { name: "Targets" }).classList.contains("pane")).toBe(true);
    expect(screen.getByRole("list", { name: "Targets" }).tabIndex).toBe(0);
    expect(
      within(listTarget("me/app")).getByText("not swept yet", { selector: ".tsub" }),
    ).toBeTruthy();
    expect(counts(listTarget("me/app"))).toEqual([
      "(– critical)",
      "(– high)",
      "(– medium)",
      "(– low)",
    ]);
    expect(listTarget("me/app").querySelector(".sr-only")?.textContent).toBe("not swept yet");
    expect(listTarget("me/app").querySelector(".open")?.textContent).toBe("");
    // The status is in the sentence, so the drawn one is not read a second time.
    expect(listTarget("This Mac").querySelector(".open")?.getAttribute("aria-hidden")).toBe("true");
  });
});

describe("the rows", () => {
  it("show the version, advisories, place, fix and tags Rust gave", async () => {
    shown = overview({
      items: [
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
      items: [
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
    const count = await screen.findByTitle("Show details");
    expect(within(count).getByText("2")).toBeTruthy();
    expect(within(count).getByText("need you")).toBeTruthy();
    expect(within(count).getByText("1 exploited")).toBeTruthy();
    const urgent = screen.getByText("openssl 1.0.0").closest("button") as HTMLElement;
    expect(within(urgent).getByText("exploited in the wild · This Mac")).toBeTruthy();
    expect(screen.getByRole("button", { name: /^This Mac/ })).toBeTruthy();
    expect(screen.getByText(/^swept .* ago$/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sweep now" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open report" })).toBeTruthy();
    // The settings menu moves to the top; the footer would not fit under the spiral.
    expect(document.querySelector(".foot")).toBeNull();
    expect(screen.getByRole("button", { name: "Settings" })).toBeTruthy();
  });

  it("shows the next open item, not a reported fix, as the urgent card", async () => {
    const node = finding("n", { name: "node.js", version: "22.22.2", known_exploited: true });
    shown = { ...two(), reported: [reportedFix(node)] };
    answer();
    render(() => <App />);
    await screen.findByTitle("Show details");
    expect(screen.getByText("openssl 1.0.0").closest("button")).not.toBeNull();
    expect(screen.queryByText(/node\.js/)).toBeNull();
  });

  it("with only reported fixes left, shows them to confirm, green, and opens Fixed", async () => {
    const node = component("n", [
      advisory("n1", { name: "node.js", version: "22.22.2", known_exploited: true }),
      advisory("n2", { name: "node.js", version: "22.22.2" }),
    ]);
    shown = overview({
      reported: [reportedFix(node)],
      list_tab: "fixed",
      to_confirm: { count: 1, label: "to confirm" },
      headline: "1 fix to confirm",
      last_swept: "2026-11-06T11:00:00Z",
      first_sweep_hint: null,
      targets: overview().targets.map((t) => ({
        ...t,
        swept: "2026-11-06T11:00:00Z",
        checked: "12 components checked",
        to_confirm: "1 fix to confirm",
      })),
    });
    answer();
    render(() => <App />);
    const count = await screen.findByTitle("Show details");
    expect(count.textContent).toBe("1to confirmShow details");
    expect(within(count).getByText("1").classList.contains("n")).toBe(true);
    expect(within(count).getByText("to confirm").classList.contains("l")).toBe(true);
    expect(document.querySelector(".urgent")).toBeNull();
    expect(screen.queryByText(/node\.js/)).toBeNull();
    expect(sceneOf(shown)).toEqual({ mood: "clear" });
    expect(sceneOf(overview())).toEqual({ mood: "unswept" });
    expect(sceneOf(two()).mood).toBe("findings");

    const mac = targetRow(/^This Mac/);
    expect(mac.sub).toBe("12 components checked · 1 fix to confirm");
    expect(mac.clear).toBe(false);
    expect(mac.counts).toEqual(["(0 critical)", "(0 high)", "(0 medium)", "(0 low)"]);
    expect(screen.getByRole("button", { name: /^This Mac, 1 fix to confirm,/ })).toBeTruthy();
    expect(screen.getByText("1 fix to confirm", { selector: ".confirming" })).toBeTruthy();

    fireEvent.click(count);
    const tab = await screen.findByRole("tab", { name: /Fixed/ });
    expect(tab.getAttribute("aria-selected")).toBe("true");
    const list = screen.getByRole("list", { name: "Fixed" });
    expect(within(list).getByText("2 advisories")).toBeTruthy();

    fireEvent.click(screen.getByRole("tab", { name: /Targets/ }));
    const target = listTarget("This Mac");
    const status = within(target).getByText("1 fix to confirm", { selector: ".confirming" });
    expect(status.classList.contains("confirming")).toBe(true);
    expect(within(target).queryByText(/clear/)).toBeNull();
    expect(target.querySelector(".tbar.ok")).toBeNull();
  });

  it("counts what is open when nothing needs you", async () => {
    shown = overview({
      items: [finding("c", { name: "zlib", severity: "low", needs_you: false })],
      counts: { critical: 0, high: 0, medium: 0, low: 1 },
      headline: "1 open, none urgent",
      last_swept: "2026-11-06T11:00:00Z",
      first_sweep_hint: null,
    });
    answer();
    render(() => <App />);
    const count = await screen.findByTitle("Show details");
    expect(count.textContent).toBe("1openShow details");
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
    const count = await screen.findByTitle("Show details");
    expect(count.textContent).toBe("50%grok is judging 3 advisoriesShow details");
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
      targets: overview().targets.map((t) => ({
        ...t,
        swept: "2026-11-06T11:00:00Z",
        checked: "12 components checked",
      })),
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
    const count = await screen.findByTitle("Show details");
    expect(count.textContent).toBe("Clearnothing openShow details");
    expect(document.querySelector(".orbit.green")).not.toBeNull();
    expect(screen.getByText("1 fixed in the last 30 days")).toBeTruthy();
    expect(screen.getByText("3 targets · every 6 hours")).toBeTruthy();
    expect(targetRow(/^This Mac/)).toEqual({
      sub: "12 components checked",
      counts: ["(0 critical)", "(0 high)", "(0 medium)", "(0 low)"],
      bar: [],
      clear: true,
    });
  });

  it("opens the list from the count, and goes back with Back or Escape", async () => {
    shown = two();
    answer();
    render(() => <App />);
    fireEvent.click(await screen.findByTitle("Show details"));
    expect(screen.getByText("2 findings need you")).toBeTruthy();
    expect(screen.getByRole("tab", { name: /Needs you/ }).getAttribute("aria-selected")).toBe(
      "true",
    );
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByTitle("Show details")).toBeTruthy();
    fireEvent.click(screen.getByTitle("Show details"));
    fireEvent.keyDown(window, { key: "Escape" });
    expect(await screen.findByTitle("Show details")).toBeTruthy();
  });

  it("opens the most urgent finding, and goes back to the main view", async () => {
    shown = two();
    answer();
    render(() => <App />);
    fireEvent.click((await screen.findByText("openssl 1.0.0")).closest("button") as HTMLElement);
    expect(await screen.findByText("Reachable from the app.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByTitle("Show details")).toBeTruthy();
  });

  it("shows each target's counts in fixed severity columns and a bar, worst first", async () => {
    const swept = "2026-11-06T11:00:00Z";
    const line = overview().targets[0];
    if (line === undefined) {
      throw new Error("the fixture has a target");
    }
    shown = {
      ...two(),
      targets: [
        {
          ...line,
          label: "web",
          kind: "server",
          swept,
          checked: "139 components checked",
          counts: { critical: 1, high: 5, medium: 2, low: 1 },
          open: 9,
        },
        { ...line, label: "me/app", kind: "repo", swept, checked: "3 components checked" },
        {
          ...line,
          label: "big",
          kind: "server",
          swept,
          checked: "900 components checked",
          counts: { critical: 100, high: 0, medium: 12, low: 0 },
          open: 112,
        },
        { ...line, label: "This Mac", swept: null, checked: null },
      ],
    };
    answer();
    render(() => <App />);
    await screen.findByTitle("Show details");
    expect(targetRow(/^web/)).toEqual({
      sub: "139 components checked",
      counts: ["1 critical", "5 high", "2 medium", "1 low"],
      bar: ["1 #ff3b3b", "5 #ff8a1f", "2 #ffe14a", "1 #8fa2ff"],
      clear: false,
    });
    expect(
      screen.getByRole("button", {
        name: "web, 9 open: 1 critical, 5 high, 2 medium, 1 low, 139 components checked",
      }),
    ).toBeTruthy();
    // Every severity keeps its column: a zero beside a count is dimmed, not dropped.
    expect(targetRow(/^big/).counts).toEqual(["100 critical", "(0 high)", "12 medium", "(0 low)"]);
    expect(targetRow(/^me\/app/)).toEqual({
      sub: "3 components checked",
      counts: ["(0 critical)", "(0 high)", "(0 medium)", "(0 low)"],
      bar: [],
      clear: true,
    });
    expect(
      screen.getByRole("button", { name: "me/app, clear, 3 components checked" }),
    ).toBeTruthy();
    expect(targetRow(/^This Mac/)).toEqual({
      sub: "not swept yet",
      counts: ["(– critical)", "(– high)", "(– medium)", "(– low)"],
      bar: [],
      clear: false,
    });
    expect(screen.getByRole("button", { name: "This Mac, not swept yet" })).toBeTruthy();
    expect(document.querySelector(".trows.stale")).toBeNull();

    // A sweep keeps the last counts in place, faded.
    shown = { ...sweeping(false), targets: shown.targets };
    handlers.get("changed")?.({ payload: null });
    await screen.findByText("sweeping This Mac");
    expect(document.querySelector(".trows.stale")).not.toBeNull();
    expect(targetRow(/^web/).counts).toEqual(["1 critical", "5 high", "2 medium", "1 low"]);
  });

  it("shows why the last sweep failed", async () => {
    shown = { ...two(), status: { state: "failed", error: "grok exited with 1" } };
    answer();
    render(() => <App />);
    expect(await screen.findByText("Last sweep: grok exited with 1")).toBeTruthy();
  });

  it("shows a running sweep's steps behind the main view, and goes back", async () => {
    shown = sweeping(false);
    answer();
    render(() => <App />);
    fireEvent.click(await screen.findByTitle("Show details"));
    expect(await screen.findByText("Sweeping This Mac")).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(await screen.findByText("sweeping This Mac")).toBeTruthy();
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
    fireEvent.click(screen.getByRole("button", { name: "Open report" }));
    expect(invoke).toHaveBeenCalledWith("open_report");
    expect(await screen.findByText("Error: no sweep has a report yet")).toBeTruthy();
  });

  it("paints a still picture, again only when the state, size or display changes", async () => {
    const frames = vi.spyOn(window, "requestAnimationFrame");
    shown = sweeping(false);
    answer();
    render(() => <App />);
    await screen.findByTitle("Show details");
    // Nothing is painted before layout gives the canvas a size.
    expect(canvas.paints).toBe(0);
    canvas.resize?.(360, 372);
    const first = canvas.paints;
    expect(first).toBe(1);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(canvas.paints).toBe(first);
    expect(frames).not.toHaveBeenCalled();
    frames.mockRestore();

    shown = two();
    handlers.get("changed")?.({ payload: null });
    await screen.findByText("need you");
    expect(canvas.paints).toBe(first + 1);

    // A banner taking room resizes the canvas.
    canvas.resize?.(360, 300);
    expect(canvas.paints).toBe(first + 2);

    // The popover moved to a display with another density.
    vi.stubGlobal("devicePixelRatio", 3);
    canvas.moved?.();
    expect(canvas.paints).toBe(first + 3);
  });
});
