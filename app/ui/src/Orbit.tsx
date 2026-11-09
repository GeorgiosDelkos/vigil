// The main view: Vigil's spiral as a still vortex of light, the count of what needs you in its centre, the most
// urgent finding, the targets and two actions. The full list is a screen behind it.

import { For, Match, Show, Switch, createEffect, createSignal, onCleanup } from "solid-js";

import { Icon } from "./icons.tsx";
import { Menu } from "./Menu.tsx";
import { neon, vortex, type Box, type Scene, type Streak, type Vortex } from "./orbit.ts";
import type { Listed, Overview, Status, TargetLine } from "./overview.ts";
import { since } from "./time.ts";

type Sweeping = Extract<Status, { state: "sweeping" }>;

export type OrbitActions = {
  /** Opens the list behind the main view. */
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

export function Orbit(props: { overview: Overview; now: Date; actions: OrbitActions }) {
  const sweeping = () =>
    props.overview.status.state === "sweeping" ? props.overview.status : null;
  const clear = () => sweeping() === null && props.overview.all_clear;
  const first = () => (sweeping() === null ? props.overview.findings[0] : undefined);
  const scene = (): Scene => {
    const s = sweeping();
    if (s !== null) {
      return { mood: "progress", lit: [], progress: s.percent / 100 };
    }
    if (props.overview.all_clear) {
      return { mood: "clear", lit: [], progress: 1 };
    }
    // Before the first sweep nothing is lit yet.
    return {
      mood: first() ? "findings" : "progress",
      lit: props.overview.findings.map(neon),
      progress: 0,
    };
  };
  const failed = () => (props.overview.status.state === "failed" ? props.overview.status : null);

  return (
    <section class={`orbit ${clear() ? "green" : ""}`}>
      <div class="sky" aria-hidden="true">
        <div class="aurora">
          <i class="a1" />
          <i class="a2" />
          <i class="a3" />
        </div>
      </div>
      <div class="orbit-top">
        <b>Vigil</b>
        <span>
          <Show when={sweeping()} fallback={swept(props.overview, props.now)}>
            {(s) => `sweeping ${s().current ?? ""}`}
          </Show>
        </span>
        <Menu onSettings={props.actions.onSettings} onError={props.actions.onError} />
      </div>
      <Show when={failed()}>{(f) => <p class="banner bad">Last sweep: {f().error}</p>}</Show>
      <div class="stage">
        <Spiral scene={scene()} />
        <button
          type="button"
          class="centre"
          title="Open the list"
          onClick={() => props.actions.onList()}
        >
          <Centre overview={props.overview} sweeping={sweeping()} />
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
            <span class="go">›</span>
          </button>
        </Match>
        <Match when={props.overview.first_sweep_hint}>
          {(hint) => <p class="orbit-hint">{hint()}</p>}
        </Match>
      </Switch>
      <div class="chips">
        <For each={props.overview.targets}>
          {(t) => (
            <button type="button" class="glass" onClick={() => props.actions.onTargets()}>
              <Icon name={t.kind} />
              <b>{t.label}</b>
              <i aria-hidden="true">
                <For each={chipDots(t, props.overview, sweeping() !== null)}>
                  {(colour) => <span style={{ "--c": colour }} />}
                </For>
              </i>
            </button>
          )}
        </For>
      </div>
      <div class="orbit-foot">
        <Show
          when={sweeping()}
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
          {sweeping() ? "Open last report" : "Open report ↗"}
        </button>
      </div>
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
      <span class="go">›</span>
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

/** A target chip's dots: one per open finding in its neon colour, green when it is clear, and
 * one dim dot while a sweep runs or before its first. */
function chipDots(target: TargetLine, overview: Overview, sweeping: boolean): string[] {
  if (sweeping || target.swept === null) {
    return ["var(--n-dim)"];
  }
  const lit = overview.findings.filter((f) => f.target === target.label).map(neon);
  return lit.length > 0 ? lit : ["var(--n-green)"];
}

/** The spiral on a canvas, drawn once per state, and again when its size or the display's pixel
 * ratio changes. It never animates: the owner asked for a still picture (2026-11-09). */
function Spiral(props: { scene: Scene }) {
  const [canvas, setCanvas] = createSignal<HTMLCanvasElement>();
  // Its size in CSS pixels, which changes when a banner above it takes room.
  const [box, setBox] = createSignal<Box>({ width: 0, height: 0 });
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
    if (target !== undefined) {
      watch.observe(target);
      paint(fit(target, box(), ratio()), vortex(props.scene, box()), box());
    }
  });
  return <canvas ref={setCanvas} aria-hidden="true" />;
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
