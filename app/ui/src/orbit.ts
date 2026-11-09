// The Orbit main view's spiral: where its dots sit and how each is lit, for one frame. Pure, so
// it is tested without a canvas; Orbit.tsx paints what `dots` returns.

import type { Listed } from "./overview.ts";

/** The neon colours of the Orbit view, one per kind of finding. */
export const NEON = {
  exploited: "#ff2e88",
  critical: "#ff3b3b",
  high: "#ff8a1f",
  medium: "#ffe14a",
  low: "#8fa2ff",
} as const;

/** A dot past a sweep's progress, not lit yet. */
const DARK = "#8fa2ff";

/** The colour a finding lights its dot with: exploited first, then its severity. */
export function neon(finding: Pick<Listed, "severity" | "known_exploited">): string {
  return finding.known_exploited ? NEON.exploited : NEON[finding.severity];
}

/** What the spiral shows: findings at its outer end, a sweep filling it, or all clear. */
export type Mood = "findings" | "progress" | "clear";

export type Scene = {
  readonly mood: Mood;
  /** The colours of the findings' dots, from the arm's outer end inward ("findings"). */
  readonly lit: readonly string[];
  /** How far along the arm the dots are lit, 0 to 1 ("progress"). */
  readonly progress: number;
};

/** A point of the arm, around the drawn shape's centre, before it turns or fits a canvas. */
export type ArmPoint = {
  /** How far along the arm, 0 at the inner end to 1 at the outer end. */
  readonly t: number;
  /** Its angle in radians, from the canvas's x axis, clockwise as the canvas draws. */
  readonly angle: number;
  readonly x: number;
  readonly y: number;
  readonly size: number;
};

export type Dot = {
  readonly x: number;
  readonly y: number;
  readonly size: number;
  readonly colour: string;
  /** The glow's blur radius in canvas pixels; 0 for none. */
  readonly glow: number;
  readonly alpha: number;
};

// Exactly two turns of an Archimedean arm, so it starts and ends at the same angle. START
// matches the tray mark (icons/src/marks.py: 1.55 turns from -90 degrees), whose outer end
// points down and left at 108 degrees. The radii and sizes are the mockup's, in CSS pixels.
const TURNS = 2;
const START = 0.6 * Math.PI;
const INNER = 100;
const OUTER = 150;
/** The gap between neighbouring dots along the arm, in CSS pixels. */
const GAP = 7;

const size = (t: number) => 1.8 + t * 3.6;

/** The arm's dots, at even steps along it rather than at even angles, which crowded the inner
 * turn: each step is a dot's width plus the gap, so dots grow apart as they grow. The steps are
 * then stretched slightly so the last dot lands exactly two turns from the first. */
function buildArm(): readonly ArmPoint[] {
  const span = TURNS * 2 * Math.PI;
  const thetas: number[] = [];
  for (let theta = 0; theta <= span;) {
    thetas.push(theta);
    const t = theta / span;
    theta += (size(t) * 2 + GAP) / (INNER + (OUTER - INNER) * t);
  }
  const stretch = span / (thetas.at(-1) ?? span);
  const raw = thetas.map((theta) => {
    const t = (theta * stretch) / span;
    const r = INNER + (OUTER - INNER) * t;
    const angle = START + theta * stretch;
    return { t, angle, x: Math.cos(angle) * r, y: Math.sin(angle) * r, size: size(t) };
  });

  // Centre the drawn shape, not the arm's origin: an outward spiral is otherwise lopsided.
  const xs = raw.map((p) => p.x);
  const ys = raw.map((p) => p.y);
  const cx = (Math.min(...xs) + Math.max(...xs)) / 2;
  const cy = (Math.min(...ys) + Math.max(...ys)) / 2;
  return raw.map((p) => ({ ...p, x: p.x - cx, y: p.y - cy }));
}

/** The spiral's arm, inner end first. */
export const ARM: readonly ArmPoint[] = buildArm();

type Light = Pick<Dot, "colour" | "glow" | "alpha">;

/** The farthest any dot reaches from the centre, with room for its glow (arbitrary 10px). */
const REACH = Math.max(...ARM.map((p) => Math.hypot(p.x, p.y) + p.size)) + 10;

/** How a dot `t` along the arm and `fromEnd` dots from its outer end is lit, as the mockup
 * lights it. */
function light(scene: Scene, t: number, fromEnd: number, beat: number): Light {
  const lit = scene.lit[fromEnd];
  if (scene.mood === "findings" && lit !== undefined) {
    return { colour: lit, glow: fromEnd === 0 ? 26 * beat : 14, alpha: 1 };
  }
  if (scene.mood === "clear") {
    return {
      colour: `hsl(${150 + t * 40}, 100%, ${62 + t * 10}%)`,
      glow: 6 + t * 10,
      alpha: 0.35 + t * 0.6,
    };
  }
  if (scene.mood === "progress" && t > scene.progress) {
    return { colour: DARK, glow: 0, alpha: 0.12 };
  }
  // Cyan near the centre turning violet outward, like the mark.
  return {
    colour: `hsl(${188 + t * 82}, 100%, ${64 - t * 4}%)`,
    glow: 4 + t * 10,
    alpha: scene.mood === "findings" ? 0.25 + t * 0.45 : 0.45 + t * 0.55,
  };
}

/** Every dot of one frame, in CSS pixels of a `width` by `height` canvas. `spin` turns the
 * spiral about its centre, in radians; `beat` (about 0.5 to 1) scales the outer dot's glow. The
 * spiral shrinks to fit a canvas smaller than it, and never grows. */
export function dots(
  scene: Scene,
  frame: { width: number; height: number; spin: number; beat: number },
): Dot[] {
  const scale = Math.min(1, Math.min(frame.width, frame.height) / 2 / REACH);
  const cos = Math.cos(frame.spin);
  const sin = Math.sin(frame.spin);
  return ARM.map((p, index) => ({
    x: frame.width / 2 + (p.x * cos - p.y * sin) * scale,
    y: frame.height / 2 + (p.x * sin + p.y * cos) * scale,
    size: p.size * scale,
    ...light(scene, p.t, ARM.length - 1 - index, frame.beat),
  }));
}
