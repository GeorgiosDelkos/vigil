import { describe, expect, it } from "vitest";

import { finding } from "./fixtures.ts";
import { NEON, STREAKS, neon, streaks, vortex, type Scene } from "./orbit.ts";

const box = { width: 360, height: 372 };

/** The hue of an `hsl(...)` colour. */
function hueOf(colour: string): number {
  return Number(/^hsl\(([\d.]+),/.exec(colour)?.[1]);
}

describe("the streaks", () => {
  it("lie on three arms, in turn", () => {
    expect(new Set(STREAKS.map((s) => s.arm))).toEqual(new Set([0, 1, 2]));
    expect(STREAKS.slice(0, 6).map((s) => s.arm)).toEqual([0, 1, 2, 0, 1, 2]);
  });

  it("are the same for the same seed, and differ for another", () => {
    expect(streaks(7, 150)).toEqual(STREAKS);
    expect(streaks(8, 150)).not.toEqual(STREAKS);
    for (const s of STREAKS) {
      expect(s.u).toBeGreaterThan(0);
      expect(s.u).toBeLessThanOrEqual(1);
      expect(s.pick).toBeLessThan(1);
    }
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

describe("the vortex", () => {
  it("draws a streak per finding in Rust's order, two per arm", () => {
    const findings = [
      finding("a", { known_exploited: true }),
      finding("b"),
      finding("c", { severity: "medium" }),
      finding("d", { severity: "low" }),
    ];
    const scene: Scene = { mood: "findings", lit: findings.map(neon) };
    const picture = vortex(scene, box);
    expect(picture.findings.map((s) => s.colour)).toEqual([
      NEON.exploited,
      NEON.high,
      NEON.medium,
      NEON.low,
    ]);
    const radius = (s: (typeof picture.findings)[number]) =>
      Math.hypot((s.points[0]?.x ?? 0) - 180, (s.points[0]?.y ?? 0) - 186);
    const [first, second, third, fourth] = picture.findings.map(radius);
    expect(first).toBeCloseTo(second ?? 0, 8);
    expect(second).toBeCloseTo(third ?? 0, 8);
    expect(fourth).toBeGreaterThan(third ?? 0);
  });

  it("shows at most two findings per arm", () => {
    const scene: Scene = { mood: "findings", lit: Array<string>(10).fill(NEON.high) };
    expect(vortex(scene, box).findings).toHaveLength(6);
  });

  it("keeps the light behind findings cool, so warm colours mean a finding", () => {
    const picture = vortex({ mood: "findings", lit: [NEON.high] }, box);
    expect(picture.light).toHaveLength(STREAKS.length);
    for (const s of picture.light) {
      expect(hueOf(s.colour)).toBeGreaterThanOrEqual(188);
      expect(hueOf(s.colour)).toBeLessThanOrEqual(262);
    }
  });

  it("lights only the streaks within a sweep's progress", () => {
    const picture = vortex({ mood: "progress", progress: 0.42 }, box);
    expect(picture.findings).toHaveLength(0);
    for (const [index, s] of picture.light.entries()) {
      const seed = STREAKS[index];
      const lit = (seed?.u ?? 0) <= 0.42;
      expect(s.alpha).toBeCloseTo((seed?.alpha ?? 0) * (lit ? 1 : 0.18), 10);
    }
    const lit = STREAKS.filter((s) => s.u <= 0.42).length;
    expect(lit).toBeGreaterThan(0);
    expect(lit).toBeLessThan(STREAKS.length);
  });

  it("dims every streak before the first sweep", () => {
    const picture = vortex({ mood: "unswept" }, box);
    expect(picture.findings).toHaveLength(0);
    for (const [index, s] of picture.light.entries()) {
      expect(s.alpha).toBeCloseTo((STREAKS[index]?.alpha ?? 0) * 0.18, 10);
    }
  });

  it("is green and draws no findings when all is clear", () => {
    const picture = vortex({ mood: "clear" }, box);
    expect(picture.findings).toHaveLength(0);
    for (const s of picture.light) {
      expect(hueOf(s.colour)).toBeGreaterThanOrEqual(150);
      expect(hueOf(s.colour)).toBeLessThanOrEqual(195);
      expect(s.alpha).toBe(STREAKS[picture.light.indexOf(s)]?.alpha);
    }
  });

  it("is centred on the canvas and reaches its corners", () => {
    const picture = vortex({ mood: "clear" }, { width: 200, height: 150 });
    expect(picture.centre).toEqual({ x: 100, y: 75 });
    expect(picture.reach).toBe(125);
    for (const s of picture.light) {
      for (const p of s.points) {
        expect(Math.hypot(p.x - 100, p.y - 75)).toBeLessThanOrEqual(125);
      }
    }
  });

  it("curls each streak inward along its arm", () => {
    const picture = vortex({ mood: "clear" }, box);
    for (const s of picture.light) {
      const radii = s.points.map((p) => Math.hypot(p.x - 180, p.y - 186));
      expect(radii.toSorted((a, b) => b - a)).toEqual(radii);
    }
  });
});
