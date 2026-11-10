// The main view: Vigil's spiral as a still vortex of light, the count of what needs you in its
// centre, the most urgent finding, the targets and two actions. The details are a screen behind it:
// the list, or a running sweep's steps.

import { Index, Match, Show, Switch, createEffect, createSignal, onCleanup } from "solid-js";

import { Icon } from "./icons.tsx";
import { Menu } from "./Menu.tsx";
import { NEON, neon, vortex, type Box, type Scene, type Streak, type Vortex } from "./orbit.ts";
import {
  SEVERITIES,
  type Listed,
  type Overview,
  type Severity,
  type Status,
  type TargetLine,
} from "./overview.ts";
import { since } from "./time.ts";

type Sweeping = Extract<Status, { state: "sweeping" }>;

export type OrbitActions = {
  /** Opens the screen behind the main view: the list, or a running sweep's steps. */
  readonly onList: () => void;
  /** Opens the list at its targets. */
  readonly onTargets: () => void;
  readonly onFinding: (key: string) => void;
  readonly onSweep: () => void;
  readonly onCancel: () => void;
  readonly onReport: () => void;
  readonly onSettings: () => void;
  readonly onError: (error: string) => void;
};

/** What the spiral shows for this overview. */
function sceneOf(overview: Overview): Scene {
  if (overview.status.state === "sweeping") {
    return { mood: "progress", progress: overview.status.percent / 100 };
  }
  if (overview.all_clear) {
    return { mood: "clear" };
  }
  // Rust says all clear once a sweep found nothing, so no findings here means no sweep yet.
  return overview.findings.length > 0
    ? { mood: "findings", lit: overview.findings.map(neon) }
    : { mood: "unswept" };
}

export function Orbit(props: { overview: Overview; now: Date; actions: OrbitActions }) {
  const sweeping = () =>
    props.overview.status.state === "sweeping" ? props.overview.status : null;
  const clear = () => sweeping() === null && props.overview.all_clear;
  const first = () => (sweeping() === null ? props.overview.findings[0] : undefined);
  const failed = () => (props.overview.status.state === "failed" ? props.overview.status : null);

  return (
    <section class="orbit" classList={{ green: clear() }}>
      <div class="sky" aria-hidden="true">
        <div class="aurora">
          <i class="a1" />
          <i class="a2" />
          <i class="a3" />
        </div>
      </div>
      <div class="orbit-top">
        <b>Vigil</b>
        <span class="orbit-when">
          <Show when={sweeping()} fallback={swept(props.overview, props.now)}>
            {(s) => `sweeping ${s().current ?? ""}`}
          </Show>
        </span>
        <Menu onSettings={props.actions.onSettings} onError={props.actions.onError} />
      </div>
      <Show when={failed()}>{(f) => <p class="banner bad">Last sweep: {f().error}</p>}</Show>
      <div class="stage">
        <Spiral scene={sceneOf(props.overview)} />
        <button
          type="button"
          class="centre"
          title="Show details"
          onClick={() => props.actions.onList()}
        >
          <Centre overview={props.overview} sweeping={sweeping()} />
          <span class="sr-only">Show details</span>
        </button>
      </div>
      <Switch>
        <Match when={sweeping()}>{(s) => <Progress status={s()} now={props.now} />}</Match>
        <Match when={first()}>
          {(f) => <Urgent finding={f()} onOpen={() => props.actions.onFinding(f().key)} />}
        </Match>
        <Match when={clear()}>
          <button type="button" class="urgent glass" onClick={() => props.actions.onList()}>
            <span class="glow" style={{ "--c": "var(--n-green)" }} />
            <span>
              <b>{props.overview.fixed.length} fixed in the last 30 days</b>
              <small>
                {props.overview.target_count} · {props.overview.schedule}
              </small>
            </span>
            <span class="go" aria-hidden="true">
              ›
            </span>
          </button>
        </Match>
        <Match when={props.overview.first_sweep_hint}>
          {(hint) => <p class="orbit-hint">{hint()}</p>}
        </Match>
      </Switch>
      <TargetRows
        targets={props.overview.targets}
        sweeping={sweeping() !== null}
        onOpen={props.actions.onTargets}
      />
      <Actions sweeping={sweeping()} actions={props.actions} />
    </section>
  );
}

/** When the last sweep ran, or nothing before the first. */
function swept(overview: Overview, now: Date): string {
  return overview.last_swept === null ? "" : `swept ${since(overview.last_swept, now)} ago`;
}

function Centre(props: { overview: Overview; sweeping: Sweeping | null }) {
  const o = () => props.overview;
  return (
    <Switch>
      <Match when={props.sweeping}>
        {(s) => (
          <>
            <span class="n percent">
              {s().percent}
              <small>%</small>
            </span>
            <span class="l">{s().step}</span>
          </>
        )}
      </Match>
      <Match when={o().all_clear}>
        <span class="n word">Clear</span>
        <span class="l">nothing open</span>
      </Match>
      <Match when={o().findings.length === 0}>
        <span class="n word small">{o().headline}</span>
      </Match>
      {/* With nothing urgent, the count is of what is open, as Rust's headline says. */}
      <Match when={o().needs_you === 0}>
        <span class="n">{o().findings.length}</span>
        <span class="l">open</span>
      </Match>
      <Match when={true}>
        <span class="n">{o().needs_you}</span>
        <span class="l">need you</span>
        <Show when={o().exploited > 0}>
          <span class="kev-pill">{o().exploited} exploited</span>
        </Show>
      </Match>
    </Switch>
  );
}

/** The finding Rust ranked first, with where it is; tapping it opens its detail. */
function Urgent(props: { finding: Listed; onOpen: () => void }) {
  const f = () => props.finding;
  return (
    <button type="button" class="urgent glass" onClick={() => props.onOpen()}>
      <span class="glow" style={{ "--c": neon(f()) }} />
      <span>
        <b>
          {f().name}
          <Show when={f().version}>{(v) => ` ${v()}`}</Show>
        </b>
        <small>
          {f().known_exploited ? "exploited in the wild" : f().severity} · {f().target}
        </small>
      </span>
      <span class="go" aria-hidden="true">
        ›
      </span>
    </button>
  );
}

function Progress(props: { status: Sweeping; now: Date }) {
  return (
    <div class="progress">
      <div
        class="neon-bar"
        role="progressbar"
        aria-label="Sweep progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={props.status.percent}
        aria-valuetext={`${props.status.percent}%, ${props.status.step}`}
      >
        <i style={{ width: `${props.status.percent}%` }} />
      </div>
      <p>
        target {props.status.position} of {props.status.total} · started{" "}
        {since(props.status.started, props.now)} ago
      </p>
    </div>
  );
}

/** The tags' severity names. "med" is short so three tags fit on one line beside a name; a
 * fourth wraps. */
const TAG: Readonly<Record<Severity, string>> = {
  critical: "critical",
  high: "high",
  medium: "med",
  low: "low",
};

/** A target's open findings per severity it has, worst first: one tag and one bar segment
 * each. Empty before its first sweep and when it is clear. */
function mix(target: TargetLine): { severity: Severity; count: number }[] {
  if (target.swept === null) {
    return [];
  }
  return SEVERITIES.filter((s) => target.counts[s] > 0).map((s) => ({
    severity: s,
    count: target.counts[s],
  }));
}

/** What a row's tags and bar say, for those who cannot see them. */
function rowStatus(target: TargetLine): string {
  if (target.swept === null) {
    return "not swept yet";
  }
  const parts = mix(target).map((m) => `${m.count} ${m.severity}`);
  const open = target.open > 0 ? `${target.open} open: ${parts.join(", ")}` : "clear";
  return target.checked === null ? open : `${open}, ${target.checked}`;
}

/** One row per target, with its open findings as labelled tags and a bar split by severity.
 * Every bar is the full width, so it shows the mix within its target, not its size beside the
 * others (the owner's choice, 2026-11-10). During a sweep the rows dim: their counts are from
 * the last sweep. Past three rows the card scrolls, so the vortex keeps its room. */
function TargetRows(props: {
  targets: readonly TargetLine[];
  sweeping: boolean;
  onOpen: () => void;
}) {
  return (
    <div class="trows glass" classList={{ stale: props.sweeping }}>
      {/* Keyed by position, so a refetch during a sweep keeps the rows and their focus. */}
      <Index each={props.targets}>
        {(t) => (
          <button type="button" class="trow" onClick={() => props.onOpen()}>
            <Icon name={t().kind} />
            <b class="tname" aria-hidden="true">
              {t().label}
            </b>
            <span class="sr-only">
              {t().label}, {rowStatus(t())}
            </span>
            <span class="tags" aria-hidden="true">
              <Show
                when={mix(t()).length > 0}
                fallback={
                  <Show when={t().swept !== null}>
                    <span class="stag ok">clear</span>
                  </Show>
                }
              >
                <Index each={mix(t())}>
                  {(m) => (
                    <span class="stag" style={{ "--c": NEON[m().severity] }}>
                      {m().count} {TAG[m().severity]}
                    </span>
                  )}
                </Index>
              </Show>
            </span>
            <span class="go" aria-hidden="true">
              ›
            </span>
            <small class="tsub" aria-hidden="true">
              {t().checked ?? "not swept yet"}
            </small>
            <span class="tbar" classList={{ ok: t().swept !== null && t().open === 0 }}>
              <Index each={mix(t())}>
                {(m) => <i style={{ "flex-grow": m().count, "--c": NEON[m().severity] }} />}
              </Index>
            </span>
          </button>
        )}
      </Index>
    </div>
  );
}

function Actions(props: { sweeping: Sweeping | null; actions: OrbitActions }) {
  return (
    <div class="orbit-foot">
      <Show
        when={props.sweeping}
        fallback={
          <button type="button" class="orbit-btn" onClick={() => props.actions.onSweep()}>
            Sweep now
          </button>
        }
      >
        {(s) => (
          <button
            type="button"
            class="orbit-btn"
            disabled={s().stopping}
            onClick={() => props.actions.onCancel()}
          >
            {s().stopping ? "Stopping…" : "Cancel"}
          </button>
        )}
      </Show>
      <button type="button" class="orbit-btn lit" onClick={() => props.actions.onReport()}>
        <Show when={props.sweeping} fallback="Open report">
          Open last report
        </Show>
        <span aria-hidden="true"> ↗</span>
      </button>
    </div>
  );
}

/** The spiral on a canvas, drawn once per state, and again when its size or the display's pixel
 * ratio changes. It never animates: the owner asked for a still picture (2026-11-09). */
function Spiral(props: { scene: Scene }) {
  const [canvas, setCanvas] = createSignal<HTMLCanvasElement>();
  // Its size in CSS pixels, which changes when a banner above it takes room.
  const [box, setBox] = createSignal<Box>({ width: 0, height: 0 });
  // It observes only the canvas, and the browser reports each element once per callback.
  const watch = new ResizeObserver(([entry]) => {
    if (entry !== undefined) {
      setBox({ width: entry.contentRect.width, height: entry.contentRect.height });
    }
  });
  onCleanup(() => watch.disconnect());

  // The ratio changes when the popover moves to a display with another density.
  const [ratio, setRatio] = createSignal(window.devicePixelRatio || 1);
  const moved = () => setRatio(window.devicePixelRatio || 1);
  createEffect(() => {
    const query = window.matchMedia(`(resolution: ${ratio()}dppx)`);
    query.addEventListener("change", moved);
    onCleanup(() => query.removeEventListener("change", moved));
  });

  createEffect(() => {
    const target = canvas();
    // Before layout the box is empty; a gradient of radius 0 throws, and nothing would show.
    if (target !== undefined && box().width > 0 && box().height > 0) {
      paint(fit(target, box(), ratio()), vortex(props.scene, box()), box());
    }
  });
  const mount = (target: HTMLCanvasElement) => {
    watch.observe(target);
    setCanvas(target);
  };
  return <canvas ref={mount} aria-hidden="true" />;
}

/** Sizes the canvas's pixels to its box on this display, and returns its context. */
function fit(canvas: HTMLCanvasElement, box: Box, ratio: number): CanvasRenderingContext2D {
  canvas.width = Math.round(box.width * ratio);
  canvas.height = Math.round(box.height * ratio);
  const g = canvas.getContext("2d");
  if (g === null) {
    throw new Error("the spiral's canvas has no 2D context");
  }
  g.setTransform(ratio, 0, 0, ratio, 0, 0);
  return g;
}

function paint(g: CanvasRenderingContext2D, picture: Vortex, box: Box) {
  g.clearRect(0, 0, box.width, box.height);
  // Overlapping light adds up, as it does in the mockup.
  g.globalCompositeOperation = "lighter";
  g.lineCap = "round";
  for (const streak of [...picture.light, ...picture.findings]) {
    stroke(g, streak);
  }
  g.globalAlpha = 1;
  g.globalCompositeOperation = "source-over";

  // A dark well in the centre so the count reads (78px, the mockup's).
  const { x, y } = picture.centre;
  const well = g.createRadialGradient(x, y, 0, x, y, 78);
  well.addColorStop(0, "rgba(6, 5, 13, 0.92)");
  well.addColorStop(0.6, "rgba(6, 5, 13, 0.75)");
  well.addColorStop(1, "rgba(6, 5, 13, 0)");
  g.fillStyle = well;
  g.fillRect(0, 0, box.width, box.height);

  // Fade the edges into the panel: out toward the reach, and at the top and bottom.
  g.globalCompositeOperation = "destination-in";
  const edge = g.createRadialGradient(x, y, picture.reach * 0.45, x, y, picture.reach * 0.98);
  edge.addColorStop(0, "rgba(0, 0, 0, 1)");
  edge.addColorStop(1, "rgba(0, 0, 0, 0)");
  g.fillStyle = edge;
  g.fillRect(0, 0, box.width, box.height);
  const band = g.createLinearGradient(0, 0, 0, box.height);
  band.addColorStop(0, "rgba(0, 0, 0, 0)");
  band.addColorStop(0.16, "rgba(0, 0, 0, 1)");
  band.addColorStop(0.84, "rgba(0, 0, 0, 1)");
  band.addColorStop(1, "rgba(0, 0, 0, 0)");
  g.fillStyle = band;
  g.fillRect(0, 0, box.width, box.height);
  g.globalCompositeOperation = "source-over";
}

function stroke(g: CanvasRenderingContext2D, streak: Streak) {
  g.strokeStyle = streak.colour;
  for (const layer of streak.layers) {
    g.globalAlpha = streak.alpha * layer.alpha;
    g.lineWidth = layer.width;
    g.beginPath();
    for (const p of streak.points) {
      g.lineTo(p.x, p.y);
    }
    g.stroke();
  }
}
