import { cleanup, fireEvent, render, screen, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App.tsx";
import { finding, overview, settingsView } from "./fixtures.ts";
import type { Overview } from "./overview.ts";

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

beforeEach(() => {
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
    render(() => <App />);
    expect(await screen.findByText("2 findings need you")).toBeTruthy();
    expect(screen.getByText("1 exploited in the wild")).toBeTruthy();
    expect(names()).toEqual(["openssl", "lodash"]);
    fireEvent.click(screen.getByRole("tab", { name: /All open/ }));
    expect(names()).toEqual(["openssl", "lodash", "zlib"]);
    expect(screen.getByText(/me\/app/)).toBeTruthy();
  });

  it("asks Rust again when it says something changed", async () => {
    answer();
    render(() => <App />);
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
    render(() => <App />);
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
    render(() => <App />);
    const bar = await screen.findByRole("progressbar", { name: "Sweep progress" });
    expect(bar.querySelector<HTMLElement>(".sweep-bar-fill")?.style.width).toBe("27%");
    expect(bar.querySelector(".sweep-bar-work")).toBeNull();
    expect(bar.querySelectorAll(".sweep-bar-tick")).toHaveLength(0);
  });

  it("cancels a running sweep, and shows it stopping", async () => {
    shown = sweeping(false);
    answer({ cancel_sweep: () => null });
    render(() => <App />);
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
    render(() => <App />);
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
    render(() => <App />);
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
  });

  it("is dismissed with the reason given", async () => {
    shown = two();
    answer({ dismiss: () => null });
    render(() => <App />);
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

  it("cannot be fixed while a sweep runs", async () => {
    shown = { ...two(), busy: true, status: { state: "fixing", title: "other" } };
    answer();
    render(() => <App />);
    expect(await screen.findByText("Fixing")).toBeTruthy();
  });
});

describe("the summary", () => {
  it("says when nothing was swept yet, and sweeps on demand", async () => {
    shown = overview({ headline: "Not swept yet", first_sweep_hint: "Rust's first-sweep line" });
    answer({ sweep_now: () => null });
    render(() => <App />);
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
    render(() => <App />);
    expect(await screen.findByText(/Last sweep: no agent chosen/)).toBeTruthy();
    expect(screen.getByText(/swept .* ago/)).toBeTruthy();
    fireEvent.click(screen.getByText("Sweep"));
    expect(await screen.findByText("a sweep is running")).toBeTruthy();
  });

  it("draws one bar part per severity found, and labels every severity", async () => {
    shown = two();
    answer();
    render(() => <App />);
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
    render(() => <App />);
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
    render(() => <App />);
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
          components: 42,
          counts: { critical: 0, high: 6, medium: 0, low: 0 },
          open: 6,
          dismissed: 1,
        },
        {
          label: "web",
          kind: "server",
          swept: "2026-11-06T11:00:00Z",
          components: 3,
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          open: 0,
          dismissed: 0,
        },
        {
          label: "me/app",
          kind: "repo",
          swept: null,
          components: 0,
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          open: 0,
          dismissed: 0,
        },
      ],
    };
    answer();
    render(() => <App />);
    fireEvent.click(await screen.findByRole("tab", { name: /Targets/ }));
    expect(
      within(row("This Mac")).getByText(/42 checked · swept .* ago · 1 dismissed/),
    ).toBeTruthy();
    expect(row("This Mac").querySelectorAll(".mini i")).toHaveLength(4);
    expect(within(row("This Mac")).getByLabelText("6 open")).toBeTruthy();
    expect(row("web").textContent).not.toContain("dismissed");
    expect(row("web").querySelector(".mini svg")).not.toBeNull();
    expect(within(row("me/app")).getByText("not swept yet")).toBeTruthy();
    expect(row("me/app").querySelector(".mini svg")).toBeNull();
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
    render(() => <App />);
    const a = (await screen.findByText("pkg-a")).closest("button") as HTMLElement;
    expect(within(a).getByText("1.0.0")).toBeTruthy();
    expect(within(a).getByText("GHSA-a")).toBeTruthy();
    expect(within(a).getByText(/This Mac · \/Users\/me\/code/)).toBeTruthy();
    expect(within(a).getByText("Update to 1.0.1")).toBeTruthy();
    expect(within(a).getByText("Exploited")).toBeTruthy();
    expect(within(a).queryByText("New")).toBeNull();
    expect(a.querySelector(".age")).not.toBeNull();
    const b = screen.getByText("pkg-b").closest("button") as HTMLElement;
    expect(within(b).getByText("New")).toBeTruthy();
    expect(b.querySelector(".ver, .id, .age")).toBeNull();
    expect(within(b).getByText("This Mac").textContent).toBe("This Mac");
  });
});

describe("the detail", () => {
  it("shows everything about the finding, and goes back with Back or Escape", async () => {
    shown = two();
    answer();
    render(() => <App />);
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
    render(() => <App />);
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
    render(() => <App />);
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
    render(() => <App />);
    fireEvent.click(await screen.findByText("openssl"));
    fireEvent.click(screen.getByText("Fix…"));
    expect(await screen.findByText("no fix for a")).toBeTruthy();
  });

  it("disables fixing while the app is busy", async () => {
    shown = two();
    answer();
    render(() => <App />);
    fireEvent.click(await screen.findByText("openssl"));
    const fix = screen.getByText("Fix…") as HTMLButtonElement;
    expect(fix.disabled).toBe(false);
    shown = { ...two(), busy: true, status: { state: "fixing", title: "other" } };
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
    render(() => <App />);
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
    render(() => <App />);
    expect(await screen.findByText("2 findings need you")).toBeTruthy();
  });
});

describe("the footer", () => {
  it("names the agent and schedule, or says there is no agent", async () => {
    answer();
    render(() => <App />);
    expect(await screen.findByText("Claude Code · manual")).toBeTruthy();
    cleanup();
    shown = overview({ agent: null });
    render(() => <App />);
    expect(await screen.findByText("no agent · manual")).toBeTruthy();
  });

  it("opens a menu with settings, launch at login and quit", async () => {
    answer({ settings_data: () => settingsView(), quit: () => null });
    render(() => <App />);
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
    render(() => <App />);
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
    render(() => <App />);
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
    render(() => <App />);
    fireEvent.click(await screen.findByText("Sweep"));
    expect(await screen.findByText("busy")).toBeTruthy();
    fireEvent.click(screen.getByText("Sweep"));
    expect(screen.queryByText("busy")).toBeNull();
  });

  it("closes the detail when its fix finishes", async () => {
    shown = two();
    answer();
    render(() => <App />);
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
    render(() => <App />);
    const text = (await screen.findByText(/target swept/)).textContent ?? "";
    expect(text).not.toContain("dismissed");
    expect(text).toMatch(/1 target swept .* ago\. Nothing open\./);
  });
});
