// The main view: Vigil's spiral drawn live, the count of what needs you in its centre, the most
// urgent finding, the targets and two actions. The full list is a screen behind it.

import { For, Match, Show, Switch, createEffect, createSignal, onCleanup } from "solid-js";

import { Icon } from "./icons.tsx";
import { Menu } from "./Menu.tsx";
import { dots, neon, type Dot, type Scene } from "./orbit.ts";
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
  // The page is hidden while the popover is closed; then nothing moves.
  const [visible, setVisible] = createSignal(document.visibilityState === "visible");
  const seen = () => setVisible(document.visibilityState === "visible");
  document.addEventListener("visibilitychange", seen);
  onCleanup(() => document.removeEventListener("visibilitychange", seen));
  const failed = () => (props.overview.status.state === "failed" ? props.overview.status : null);

  return (
    <section class={`orbit ${clear() ? "green" : ""} ${visible() ? "" : "paused"}`}>
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
        <Spiral
          scene={scene()}
          turning={sweeping() !== null}
          pulsing={first()?.known_exploited === true}
          visible={visible()}
        />
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
      <span class={`glow ${f().known_exploited ? "beat" : ""}`} style={{ "--c": neon(f()) }} />
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

/** Whether the user asked macOS to reduce motion. */
function reducedMotion(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** The spiral on a canvas. It animates only while it turns (a sweep) or its outer dot pulses
 * (an exploited finding), never under reduced motion, and never while the popover is hidden:
 * then it draws one still frame. */
function Spiral(props: { scene: Scene; turning: boolean; pulsing: boolean; visible: boolean }) {
  const [canvas, setCanvas] = createSignal<HTMLCanvasElement>();
  const calm = reducedMotion();

  let frame = 0;
  onCleanup(() => cancelAnimationFrame(frame));
  createEffect(() => {
    cancelAnimationFrame(frame);
    const target = canvas();
    if (target === undefined) {
      return;
    }
    const scene = props.scene;
    const turning = props.turning;
    const moving = !calm && props.visible && (turning || props.pulsing);
    // In milliseconds per radian of turn, and of the pulse's sine; the mockup's values.
    const draw = (time: number) =>
      paint(target, scene, {
        spin: moving && turning ? time / 9000 : 0,
        beat: moving ? 0.75 + 0.25 * Math.sin(time / 300) : 1,
      });
    const loop = (time: number) => {
      draw(time);
      frame = requestAnimationFrame(loop);
    };
    if (moving) {
      frame = requestAnimationFrame(loop);
    } else {
      draw(0);
    }
  });
  return <canvas ref={setCanvas} aria-hidden="true" />;
}

function paint(canvas: HTMLCanvasElement, scene: Scene, motion: { spin: number; beat: number }) {
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (canvas.width !== Math.round(width * ratio)) {
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
  }
  const g = canvas.getContext("2d");
  if (g === null) {
    throw new Error("the spiral's canvas has no 2D context");
  }
  g.setTransform(ratio, 0, 0, ratio, 0, 0);
  g.clearRect(0, 0, width, height);
  for (const dot of dots(scene, { width, height, ...motion })) {
    paintDot(g, dot);
  }
  g.globalAlpha = 1;
  g.shadowBlur = 0;
}

function paintDot(g: CanvasRenderingContext2D, dot: Dot) {
  // A soft halo under each bright dot, so the glow shows where canvas shadows are faint.
  if (dot.glow > 8) {
    const reach = dot.size * 4.5;
    const halo = g.createRadialGradient(dot.x, dot.y, 0, dot.x, dot.y, reach);
    halo.addColorStop(0, dot.colour);
    halo.addColorStop(1, "rgba(0, 0, 0, 0)");
    g.globalAlpha = dot.alpha * 0.22;
    g.fillStyle = halo;
    g.beginPath();
    g.arc(dot.x, dot.y, reach, 0, Math.PI * 2);
    g.fill();
  }
  g.globalAlpha = dot.alpha;
  g.shadowColor = dot.colour;
  g.shadowBlur = dot.glow;
  g.fillStyle = dot.colour;
  g.beginPath();
  g.arc(dot.x, dot.y, dot.size, 0, Math.PI * 2);
  g.fill();
}
