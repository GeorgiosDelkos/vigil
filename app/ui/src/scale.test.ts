// Keeps every size in the app's CSS on the scale at the top of style.css. A pixel value may
// appear only in a token's definition, as a hairline, in a visual effect, or in a structural
// size listed below with its reason; anything else fails, naming the file, rule and value.

import { describe, expect, it } from "vitest";

import orbit from "./orbit.css?raw";
import settings from "./settings.css?raw";
import style from "./style.css?raw";

const FILES: Readonly<Record<string, string>> = {
  "style.css": style,
  "settings.css": settings,
  "orbit.css": orbit,
};

/** Borders, dividers, and the 1 pixel nudges that sit beside them. */
const HAIRLINES = new Set(["0.5px", "1px"]);

/** Properties that draw light, shade or texture, and size or place nothing. */
const EFFECTS = new Set([
  "box-shadow",
  "text-shadow",
  "filter",
  "backdrop-filter",
  "-webkit-backdrop-filter",
  "background",
  "background-size",
  "background-position",
]);

const AURORA = "the light behind the main view, placed by eye and blurred by 80px";
const NUMERAL = "the main view's big number, sized to the vortex, above the type scale";

/** Sizes the scale does not set, as `selector property`, each with why. */
const STRUCTURAL: ReadonlyMap<string, string> = new Map([
  [".pop border-radius", "the window's corner, windowEffects.radius in tauri.conf.json"],
  [".pop > .pane min-height", "about two rows before the popover itself scrolls"],
  [".seal width", "the all-clear seal, larger than any icon"],
  [".seal height", "the all-clear seal, larger than any icon"],
  [".menu min-width", "arbitrary: wide enough that no menu item wraps"],
  [".sum max-width", "a section's summary takes at most half a settings row"],
  [".group.scroll max-height", "about six rows before a settings list scrolls"],
  [".field.num width", "three digits and the stepper"],
  [".tools grid-template-columns", "the narrowest tool chip that fits a tool's name"],
  [".rate grid-template-columns", "the longer rate label, so both meters start together"],
  [".orbit .trows max-height", "three target rows of 100; more scroll"],
  [".orbit .centre max-width", "keeps the centre's words inside the vortex's clear middle"],
  [".orbit .centre .n font", NUMERAL],
  [".orbit .centre .n.percent small font-size", NUMERAL],
  [".orbit .centre .n.word.small font-size", NUMERAL],
  [".orbit .aurora inset", AURORA],
  [".orbit .aurora .a1 width", AURORA],
  [".orbit .aurora .a1 height", AURORA],
  [".orbit .aurora .a1 left", AURORA],
  [".orbit .aurora .a1 top", AURORA],
  [".orbit .aurora .a2 width", AURORA],
  [".orbit .aurora .a2 height", AURORA],
  [".orbit .aurora .a2 right", AURORA],
  [".orbit .aurora .a2 top", AURORA],
  [".orbit .aurora .a3 width", AURORA],
  [".orbit .aurora .a3 height", AURORA],
  [".orbit .aurora .a3 left", AURORA],
  [".orbit .aurora .a3 bottom", AURORA],
]);

type Declaration = { file: string; selector: string; property: string; value: string };

/** Every declaration in `css`, with the selector of the rule it is in. Rules inside an at-rule
 * (`@media`, `@keyframes`) count as their own rules; the at-rule adds no declarations. */
function declarations(file: string, css: string): Declaration[] {
  const found: Declaration[] = [];
  const code = css.replaceAll(/\/\*[\s\S]*?\*\//g, "");
  for (const [, head = "", body = ""] of code.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = head.trim().replaceAll(/\s+/g, " ");
    for (const part of body.split(";")) {
      const colon = part.indexOf(":");
      if (colon !== -1) {
        const property = part.slice(0, colon).trim();
        const value = part.slice(colon + 1).trim();
        found.push({ file, selector, property, value });
      }
    }
  }
  return found;
}

const all = Object.entries(FILES).flatMap(([file, css]) => declarations(file, css));

/** Whether a pixel value in `d` is allowed, as the comment at the top says. */
function allowed(d: Declaration): boolean {
  if (d.property.startsWith("--")) {
    return d.selector === ":root";
  }
  if (EFFECTS.has(d.property) || STRUCTURAL.has(`${d.selector} ${d.property}`)) {
    return true;
  }
  const pixels = d.value.match(/\d*\.?\d+px/g) ?? [];
  return pixels.every((px) => HAIRLINES.has(px));
}

describe("the size scale", () => {
  it("is the only source of pixel sizes", () => {
    const off = all
      .filter((d) => d.value.includes("px") && !allowed(d))
      .map((d) => `${d.file}: ${d.selector} { ${d.property}: ${d.value} }`);
    expect(off).toEqual([]);
  });

  it("defines only tokens that are used", () => {
    const css = Object.values(FILES).join("\n");
    const unused = all
      .filter((d) => d.selector === ":root" && d.value.endsWith("px"))
      .map((d) => d.property)
      .filter((token) => !css.includes(`var(${token})`));
    expect(unused).toEqual([]);
  });

  it("uses only tokens that are defined", () => {
    const css = Object.values(FILES).join("\n");
    const defined = new Set(all.filter((d) => d.property.startsWith("--")).map((d) => d.property));
    // Set from the components' style attributes (Orbit.tsx), not in CSS.
    defined.add("--c");
    const used = [...css.matchAll(/var\((--[\w-]+)/g)].map(([, name = ""]) => name);
    expect([...new Set(used)].filter((name) => !defined.has(name))).toEqual([]);
  });

  it("lists only structural sizes that exist", () => {
    const present = new Set(all.map((d) => `${d.selector} ${d.property}`));
    expect([...STRUCTURAL.keys()].filter((key) => !present.has(key))).toEqual([]);
  });
});
