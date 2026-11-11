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
  readonly onFinding: (id: string) => void;
  readonly onSweep: () => void;
  readonly onCancel: () => void;
  readonly onReport: () => void;
  readonly onSettings: () => void;
  readonly onError: (error: string) => void;
};

/** What the spiral shows for this overview. */
export function sceneOf(overview: Overview): Scene {
  if (overview.status.state === "sweeping") {
    return { mood: "progress", progress: overview.status.percent / 100 };
  }
  if (overview.items.length > 0) {
    return { mood: "findings", lit: overview.items.map(neon) };
  }
  // Nothing open after a sweep is green, also while a reported fix waits for the next sweep:
  // the owner asked that a fixed item show green, not open (2026-11-11).
  return overview.last_swept === null ? { mood: "unswept" } : { mood: "clear" };
}

export function Orbit(props: { overview: Overview; now: Date; actions: OrbitActions }) {
  const sweeping = () =>
    props.overview.status.state === "sweeping" ? props.overview.status : null;
  const clear = () => sweeping() === null && props.overview.all_clear;
  const first = () => (sweeping() === null ? props.overview.items[0] : undefined);
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
          {(f) => <Urgent item={f()} onOpen={() => props.actions.onFinding(f().id)} />}
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
      <Match when={o().items.length === 0}>
        <span class="n word small">{o().headline}</span>
      </Match>
      {/* With nothing urgent, the count is of what is open, as Rust's headline says. */}
      <Match when={o().needs_you === 0}>
        <span class="n">{o().items.length}</span>
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

/** The item Rust ranked first, with where it is; tapping it opens its detail. */
function Urgent(props: { item: Listed; onOpen: () => void }) {
  const f = () => props.item;
  return (
    <button type="button" class="urgent glass" onClick={() => props.onOpen()}>
      <span class="glow" style={{ "--c": neon(f()) }} />
      <span>
        <b>
          {f().name}
          <Show when={f().lead.version}>{(v) => ` ${v()}`}</Show>
        </b>
        <small>
          {f().known_exploited ? "exploited in the wild" : f().severity}
          <Show when={f().advisory_count}>{(n) => ` · ${n()}`}</Show> · {f().target}
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

/** A target's open findings per severity, worst first, as bar segments: only the severities it
 * has. Empty before its first sweep and when it is clear. */
function mix(target: TargetLine): { severity: Severity; count: number }[] {
  if (target.swept === null) {
    return [];
  }
  return SEVERITIES.filter((s) => target.counts[s] > 0).map((s) => ({
    severity: s,
    count: target.counts[s],
  }));
}

/** What a target's counts and bar say, for those who cannot see them. */
function figuresText(target: TargetLine): string {
  if (target.swept === null) {
    return "not swept yet";
  }
  if (target.open === 0) {
    return target.to_confirm ?? "clear";
  }
  const parts = mix(target).map((m) => `${m.count} ${m.severity}`);
  return `${target.open} open: ${parts.join(", ")}`;
}

/** A main-view target row's name for screen readers: its counts, then what was checked. */
function rowStatus(target: TargetLine): string {
  const figures = figuresText(target);
  return target.checked === null ? figures : `${figures}, ${target.checked}`;
}

/** One row per target, every row the same shape: the name, what was checked, a count for each
 * severity in fixed columns, the number above its name so four digits fit at the popover's
 * 360px width (a zero is dimmed, so a severity sits in the same place in every row), and a bar split by severity. The owner asked for standard sizes and positions over tags
 * that wrapped and moved with the counts (2026-11-10). Every bar is the full width, so it shows
 * the mix within its target, not its size beside the others. During a sweep the rows dim: their
 * counts are from the last sweep. Past three rows the card scrolls, so the vortex keeps its
 * room. */
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
          <button
            type="button"
            class="trow"
            aria-label={`${t().label}, ${rowStatus(t())}`}
            onClick={() => props.onOpen()}
          >
            <Icon name={t().kind} />
            <b class="tname">{t().label}</b>
            <span class="go" aria-hidden="true">
              ›
            </span>
            <small class="tsub">
              {t().checked ?? "not swept yet"}
              {/* In place of the clear bar, which would say nothing is left to confirm. */}
              <Show when={t().open === 0 && t().to_confirm}>
                {(text) => (
                  <>
                    {" · "}
                    <span class="confirming">{text()}</span>
                  </>
                )}
              </Show>
            </small>
            <TargetFigures target={t()} colours={NEON} />
          </button>
        )}
      </Index>
    </div>
  );
}

/** A target row's last two lines, here and in the list's Targets tab: a count for each severity
 * in fixed columns, number over word (a zero dimmed, a dash before the first sweep), and the bar
 * split by severity. Screen readers get one sentence instead, in the words of the main view's
 * row names. The colours come from the caller: the main view's neon ones live in orbit.ts,
 * which also paints them on the canvas, so a CSS class per severity would copy them. */
export function TargetFigures(props: {
  target: TargetLine;
  colours: Readonly<Record<Severity, string>>;
}) {
  const t = () => props.target;
  return (
    <>
      <span class="tcounts" aria-hidden="true">
        <Index each={SEVERITIES}>
          {(s) => (
            <span
              class="tcount"
              classList={{ zero: t().swept === null || t().counts[s()] === 0 }}
              style={{ "--c": props.colours[s()] }}
            >
              <b>{t().swept === null ? "–" : t().counts[s()]}</b>
              <small>{s()}</small>
            </span>
          )}
        </Index>
      </span>
      <span
        class="tbar"
        classList={{ ok: t().swept !== null && t().open === 0 && t().to_confirm === null }}
        aria-hidden="true"
      >
        <Index each={mix(t())}>
          {(m) => <i style={{ "flex-grow": m().count, "--c": props.colours[m().severity] }} />}
        </Index>
      </span>
      <span class="sr-only">{figuresText(t())}</span>
    </>
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
