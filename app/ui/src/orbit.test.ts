import { describe, expect, it } from "vitest";

import { finding } from "./fixtures.ts";
import { ARM, NEON, dots, neon, type Scene } from "./orbit.ts";

const still = { width: 360, height: 372, spin: 0, beat: 1 };

function first<T>(items: readonly T[]): T {
  const item = items[0];
  if (item === undefined) {
    throw new Error("expected at least one item");
  }
  return item;
}

/** How far a dot is from the centre of a 200 by 160 canvas. */
function radius(d: { x: number; y: number }): number {
  return Math.hypot(d.x - 100, d.y - 80);
}

function last<T>(items: readonly T[]): T {
  return first(items.slice(-1));
}

describe("the arm", () => {
  it("makes exactly two turns, so it ends at the angle it starts", () => {
    expect(first(ARM).angle).toBeCloseTo(0.6 * Math.PI, 10);
    expect(last(ARM).angle - first(ARM).angle).toBeCloseTo(4 * Math.PI, 10);
    expect(Math.cos(last(ARM).angle)).toBeCloseTo(Math.cos(first(ARM).angle), 10);
    expect(Math.sin(last(ARM).angle)).toBeCloseTo(Math.sin(first(ARM).angle), 10);
  });

  it("grows outward, and its dots never touch", () => {
    for (const [index, p] of ARM.entries()) {
      const next = ARM[index + 1];
      if (next !== undefined) {
        expect(next.t).toBeGreaterThan(p.t);
        expect(next.size).toBeGreaterThan(p.size);
        expect(Math.hypot(next.x - p.x, next.y - p.y)).toBeGreaterThan(next.size + p.size);
      }
    }
    expect([first(ARM).t, last(ARM).t]).toEqual([0, 1]);
  });

  it("is centred by its outline, not by where the arm starts", () => {
    const xs = ARM.map((p) => p.x);
    const ys = ARM.map((p) => p.y);
    expect(Math.min(...xs) + Math.max(...xs)).toBeCloseTo(0, 10);
    expect(Math.min(...ys) + Math.max(...ys)).toBeCloseTo(0, 10);
  });
});

describe("a finding's colour", () => {
  it("is pink when exploited, whatever its severity, and its severity's otherwise", () => {
    expect(neon(finding("a", { severity: "low", known_exploited: true }))).toBe(NEON.exploited);
    expect(neon(finding("b", { severity: "critical" }))).toBe(NEON.critical);
    expect(neon(finding("c", { severity: "high" }))).toBe(NEON.high);
    expect(neon(finding("d", { severity: "medium" }))).toBe(NEON.medium);
    expect(neon(finding("e", { severity: "low" }))).toBe(NEON.low);
  });
});

describe("the dots", () => {
  it("light the findings at the outer end, in the order Rust ranked them", () => {
    const findings = [
      finding("a", { known_exploited: true }),
      finding("b"),
      finding("c"),
      finding("d"),
      finding("e", { severity: "medium" }),
      finding("f", { severity: "low" }),
    ];
    const scene: Scene = { mood: "findings", lit: findings.map(neon), progress: 0 };
    const drawn = dots(scene, still);
    expect(drawn).toHaveLength(ARM.length);
    const outerFirst = drawn.slice(-7).toReversed();
    expect(outerFirst.slice(0, 6).map((d) => d.colour)).toEqual([
      NEON.exploited,
      NEON.high,
      NEON.high,
      NEON.high,
      NEON.medium,
      NEON.low,
    ]);
    expect(outerFirst.slice(0, 6).every((d) => d.alpha === 1)).toBe(true);
    expect(last(outerFirst).colour).toMatch(/^hsl\(/);
  });

  it("make the outer dot glow with the beat, and the others steady", () => {
    const scene: Scene = { mood: "findings", lit: [NEON.exploited, NEON.high], progress: 0 };
    const strong = dots(scene, { ...still, beat: 1 });
    const faint = dots(scene, { ...still, beat: 0.5 });
    expect(last(faint).glow).toBe(last(strong).glow / 2);
    expect(faint.at(-2)?.glow).toBe(strong.at(-2)?.glow);
  });

  it("light all of the arm when there are more findings than dots", () => {
    const scene: Scene = { mood: "findings", lit: ARM.map(() => NEON.low), progress: 0 };
    expect(dots(scene, still).every((d) => d.colour === NEON.low)).toBe(true);
  });

  it("stay dark past a sweep's progress", () => {
    const scene: Scene = { mood: "progress", lit: [], progress: 0.42 };
    const drawn = dots(scene, still);
    for (const [index, d] of drawn.entries()) {
      const dark = (ARM[index]?.t ?? 0) > 0.42;
      expect(d.alpha === 0.12).toBe(dark);
    }
  });

  it("are all green when all is clear", () => {
    const drawn = dots({ mood: "clear", lit: [NEON.high], progress: 1 }, still);
    for (const d of drawn) {
      const hue = Number(/^hsl\(([\d.]+),/.exec(d.colour)?.[1]);
      expect(hue).toBeGreaterThanOrEqual(150);
      expect(hue).toBeLessThanOrEqual(190);
    }
  });

  it("turn about the centre, and shrink to fit a small canvas", () => {
    const scene: Scene = { mood: "clear", lit: [], progress: 1 };
    const small = { width: 200, height: 160, spin: 0, beat: 1 };
    const turned = { ...small, spin: 1.3 };
    const a = dots(scene, small);
    const b = dots(scene, turned);
    for (const [index, d] of b.entries()) {
      expect(radius(d)).toBeCloseTo(radius(a[index] ?? d), 8);
      expect(radius(d) + d.size).toBeLessThanOrEqual(80);
    }
    expect(b[0]?.x).not.toBeCloseTo(a[0]?.x ?? 0, 2);
  });
});
