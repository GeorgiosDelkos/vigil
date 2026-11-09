// The Orbit main view's spiral, a vortex of light streaks on three logarithmic arms: what to
// draw for one state. Pure, so it is tested without a canvas; Orbit.tsx paints what `vortex`
// returns.
//
// The owner chose this style over a spiral of dots, and a still picture: nothing turns or
// pulses (2026-11-09). A sweep shows its progress by which streaks are lit, not by motion.

import type { Listed } from "./overview.ts";

/** The neon colours of the Orbit view, one per kind of finding. */
export const NEON = {
  exploited: "#ff2e88",
  critical: "#ff3b3b",
  high: "#ff8a1f",
  medium: "#ffe14a",
  low: "#8fa2ff",
} as const;

/** The colour a finding's streak takes: exploited first, then its severity. */
export function neon(finding: Pick<Listed, "severity" | "known_exploited">): string {
  return finding.known_exploited ? NEON.exploited : NEON[finding.severity];
}

/** What the vortex shows: findings on its arms, a sweep lighting it, all clear, or nothing lit
 * before the first sweep. */
export type Scene =
  | {
      readonly mood: "findings";
      /** The colours of the findings' streaks, most urgent first. */
      readonly lit: readonly string[];
    }
  | {
      readonly mood: "progress";
      /** How far out from the centre the streaks are lit, 0 to 1. */
      readonly progress: number;
    }
  | { readonly mood: "clear" }
  | { readonly mood: "unswept" };

type Mood = Scene["mood"];

export type Box = { readonly width: number; readonly height: number };

export type Point = { readonly x: number; readonly y: number };

/** One stroke of a streak: its line width in CSS pixels and its opacity, 0 to 1. */
export type Layer = { readonly width: number; readonly alpha: number };

/** A streak, drawn as the same polyline once per layer, widest first. */
export type Streak = {
  readonly points: readonly Point[];
  readonly colour: string;
  /** Multiplies every layer's opacity. */
  readonly alpha: number;
  readonly layers: readonly Layer[];
};

export type Vortex = {
  readonly centre: Point;
  /** The radius of the outermost streaks; the painter fades the picture out toward it. */
  readonly reach: number;
  /** The background streaks, one per entry of `STREAKS`, in its order. */
  readonly light: readonly Streak[];
  /** The findings' streaks, most urgent first. */
  readonly findings: readonly Streak[];
};

/** The background streaks' shape, before a state colours them; see `streaks`. */
export type Seed = {
  readonly arm: number;
  /** How far out, 0 at the centre to 1 at the edge. */
  readonly u: number;
  /** Its angle off the arm, in radians. */
  readonly jitter: number;
  /** The angle it sweeps, in radians. */
  readonly length: number;
  readonly width: number;
  readonly alpha: number;
  /** Picks its hue from the state's palette, 0 to 1. */
  readonly pick: number;
};

/** The owner asked for three arms and few streaks, kept close to each arm (2026-11-09). */
export const ARMS = 3;
const COUNT = 150;
/** Two findings per arm, so they read as part of the swirl; Rust ranks the rest behind them,
 * and the list shows them all. */
export const SHOWN = 2 * ARMS;
/** The radius the arms start from, in CSS pixels. */
const INNER = 30;
/** How tightly the arms wind: the angle grows by this much per unit of ln(r). */
const WIND = 1.7;

/** A Park-Miller generator (multiplier 16807, modulus 2^31 - 1), so a seed always yields the
 * same streaks and the same state always draws the same picture. */
function seeded(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state * 16_807) % 2_147_483_647;
    return state / 2_147_483_647;
  };
}

/** `count` background streaks from `seed`, as the mockup places them. Their `u` leans outward
 * (a power of 0.75), and the outer ones are longer and wider. */
export function streaks(seed: number, count: number): Seed[] {
  const next = seeded(seed);
  return Array.from({ length: count }, (_, index) => {
    const u = Math.pow(next(), 0.75);
    return {
      arm: index % ARMS,
      u,
      jitter: (next() - 0.5) * 0.28,
      length: 0.22 + next() * 0.5 * (0.4 + u),
      width: 0.5 + u * 2.4 + next() * 0.8,
      alpha: 0.25 + next() * 0.6,
      pick: next(),
    };
  });
}

/** The streaks every state draws; the seed is the mockup's. */
export const STREAKS: readonly Seed[] = streaks(7, COUNT);

type Hsl = readonly [hue: number, saturation: number, lightness: number];

/** A sweep's hues, also before the first sweep, when every streak is dimmed. */
const SWEEP: readonly Hsl[] = [
  [190, 100, 62],
  [222, 100, 64],
  [250, 95, 68],
];

/** Cool hues only behind findings, so pink, orange and yellow mean a finding and nothing else. */
const HUES: Readonly<Record<Mood, readonly Hsl[]>> = {
  findings: [
    [188, 100, 62],
    [205, 100, 64],
    [228, 100, 68],
    [262, 95, 70],
  ],
  progress: SWEEP,
  unswept: SWEEP,
  clear: [
    [150, 100, 58],
    [175, 100, 58],
    [195, 100, 62],
  ],
};

/** The hue `pick` (0 to 1) chooses from `hues`. */
function hue(hues: readonly Hsl[], pick: number): Hsl {
  const chosen = hues[Math.floor(pick * hues.length)];
  if (chosen === undefined) {
    throw new Error(`a streak's pick must be at least 0 and below 1, not ${pick}`);
  }
  return chosen;
}

/** How much a streak past a sweep's progress keeps of its light. */
const DIM = 0.18;

/** A stretch of the log spiral from angle `start` at radius `r`, `steps` segments long: the
 * radius shrinks as the angle grows, so the stretch curls in along its arm. */
function arc(centre: Point, start: number, r: number, length: number, steps: number): Point[] {
  return Array.from({ length: steps + 1 }, (_, k) => {
    const turn = length * (k / steps);
    const radius = r * Math.exp(-turn / WIND);
    return {
      x: centre.x + Math.cos(start + turn) * radius,
      y: centre.y + Math.sin(start + turn) * radius,
    };
  });
}

/** The angle of arm `arm` at radius `r`. */
function armAngle(arm: number, r: number): number {
  return (arm / ARMS) * Math.PI * 2 + Math.log(r / INNER) * WIND;
}

/** Everything to draw for `scene` on a canvas of `box` CSS pixels. */
export function vortex(scene: Scene, box: Box): Vortex {
  const centre = { x: box.width / 2, y: box.height / 2 };
  const reach = Math.hypot(box.width, box.height) / 2;
  const hues = HUES[scene.mood];

  const light = STREAKS.map((s) => {
    const r = INNER + s.u * (reach - INNER);
    const [h, sat, l] = hue(hues, s.pick);
    const dark = scene.mood === "unswept" || (scene.mood === "progress" && s.u > scene.progress);
    return {
      points: arc(centre, armAngle(s.arm, r) + s.jitter, r, s.length, 8),
      colour: `hsl(${h}, ${sat}%, ${l}%)`,
      alpha: s.alpha * (dark ? DIM : 1),
      layers: [
        { width: s.width * 3.2, alpha: 0.18 },
        { width: s.width, alpha: 1 },
      ],
    };
  });

  // The brightest, thickest streaks, two per arm, the second pair further out.
  const lit = scene.mood === "findings" ? scene.lit.slice(0, SHOWN) : [];
  const findings = lit.map((colour, index) => {
    const r = reach * (0.5 + 0.14 * Math.floor(index / ARMS));
    return {
      points: arc(centre, armAngle(index % ARMS, r) + 0.12, r, 0.7, 12),
      colour,
      alpha: 1,
      layers: [
        { width: 16, alpha: 0.16 },
        { width: 7, alpha: 0.35 },
        { width: 3, alpha: 1 },
      ],
    };
  });

  return { centre, reach, light, findings };
}
