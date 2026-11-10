// Keeps every size in the app's CSS on the scale at the top of style.css. A length may appear
// only in a pinned token's definition, as a hairline on a border, outline or shadow, as paint
// (a blur, a shadow's offset, a gradient's stops), as em in letter-spacing, or in a listed
// declaration with its exact value and reason. Anything else fails, naming file, rule and value.
// At-rule headers (`@media (...)`) are not scanned, only the rules inside them.

import { describe, expect, it } from "vitest";

const SHEETS = import.meta.glob<string>("./**/*.css", {
  query: "?raw",
  import: "default",
  eager: true,
});

/** The scale. A size token in a `:root` rule must be here with this value. */
const TOKENS: ReadonlyMap<string, string> = new Map([
  ["--space-2", "2px"],
  ["--space-4", "4px"],
  ["--space-8", "8px"],
  ["--space-12", "12px"],
  ["--space-16", "16px"],
  ["--space-24", "24px"],
  ["--space-32", "32px"],
  ["--text-11", "11px"],
  ["--leading-11", "16px"],
  ["--text-12", "12px"],
  ["--leading-12", "16px"],
  ["--text-13", "13px"],
  ["--leading-13", "20px"],
  ["--text-15", "15px"],
  ["--leading-15", "20px"],
  ["--text-20", "20px"],
  ["--leading-20", "24px"],
  ["--radius-6", "6px"],
  ["--radius-10", "10px"],
  ["--radius-full", "999px"],
  ["--control-24", "24px"],
  ["--control-28", "28px"],
  ["--control-32", "32px"],
  ["--stroke-2", "2px"],
]);

/** Properties that only paint: their lengths are blurs and gradient stops. */
const PAINT = new Set([
  "text-shadow",
  "filter",
  "backdrop-filter",
  "-webkit-backdrop-filter",
  "background",
]);

const HAIRLINES = new Set(["0.5px", "1px"]);
const EDGES = /^(border(-(top|right|bottom|left))?(-width)?|outline(-offset)?)$/;

const AURORA = "the light behind the main view, placed by eye and blurred by 80px";
const NUMERAL =
  "the main view's number: the largest that leaves 8 between the centre and the cards when a failed sweep's banner shortens the stage";
const DIVIDER = "a hairline divider starting where the row text does";
const DOT_HALO = "a 3 pixel halo around an 8 pixel status dot";
const STRIPES = "one period of the sweep bar's 12 pixel stripes at 45 degrees, 12 * sqrt(2)";

/** Declarations the scale does not set, as selector, property, exact value and reason. */
const LISTED: readonly (readonly [string, string, string, string])[] = [
  [".pop", "border-radius", "20px", "the window's corner, windowEffects.radius in tauri.conf.json"],
  [".pop > .pane", "min-height", "96px", "about two rows before the popover itself scrolls"],
  [".seal", "width", "48px", "the all-clear seal, larger than any icon"],
  [".seal", "height", "48px", "the all-clear seal, larger than any icon"],
  [".clear p", "max-width", "34ch", "a short measure for the centred all-clear sentence"],
  [".menu", "min-width", "192px", "arbitrary: wide enough that no menu item wraps"],
  [".sum", "max-width", "180px", "a section's summary takes at most half a settings row"],
  [".group.scroll", "max-height", "260px", "about six rows before a settings list scrolls"],
  [".field.num", "width", "56px", "three digits and the stepper"],
  [
    ".tools",
    "grid-template-columns",
    "repeat(auto-fill, minmax(96px, 1fr))",
    "the narrowest tool chip",
  ],
  [
    ".rate",
    "grid-template-columns",
    "88px minmax(0, 1fr) var(--space-24)",
    "the longer rate label",
  ],
  [".row + .row::before", "height", "0.5px", DIVIDER],
  [".trow + .trow::before", "height", "0.5px", DIVIDER],
  [".step + .step::before", "height", "0.5px", DIVIDER],
  [".srow + .srow::before", "height", "0.5px", DIVIDER],
  [".menu hr", "height", "0.5px", "the menu's hairline separator"],
  [".sr-only", "width", "1px", "visually hidden, still read"],
  [".sr-only", "height", "1px", "visually hidden, still read"],
  [".fix .icon, .fixline .icon", "transform", "translateY(1px)", "the wrench's optical baseline"],
  [".sweep-bar-tick", "margin-left", "-1px", "centres the 2 pixel mark on its position"],
  [".sum .dot", "box-shadow", "0 0 0 3px rgba(245, 192, 68, 0.16)", DOT_HALO],
  [".tool i", "box-shadow", "0 0 0 3px rgba(79, 209, 139, 0.14)", DOT_HALO],
  [".sweep-bar-work", "background-size", "17px 100%", STRIPES],
  ["to", "background-position", "17px 0", STRIPES],
  [".orbit .trows", "max-height", "300px", "three target rows of 100; more scroll"],
  [".orbit .centre", "max-width", "190px", "keeps the centre's words inside the vortex's middle"],
  [".orbit .centre .n", "font", "400 48px/0.85 var(--ui)", NUMERAL],
  [".orbit .centre .n.percent small", "font-size", "24px", NUMERAL],
  [".orbit .centre .n.word.small", "font-size", "40px", NUMERAL],
  [".orbit .aurora", "inset", "-60px", AURORA],
  [".orbit .aurora .a1", "width", "260px", AURORA],
  [".orbit .aurora .a1", "height", "260px", AURORA],
  [".orbit .aurora .a1", "left", "-40px", AURORA],
  [".orbit .aurora .a1", "top", "40px", AURORA],
  [".orbit .aurora .a2", "width", "240px", AURORA],
  [".orbit .aurora .a2", "height", "240px", AURORA],
  [".orbit .aurora .a2", "right", "-50px", AURORA],
  [".orbit .aurora .a2", "top", "160px", AURORA],
  [".orbit .aurora .a3", "width", "220px", AURORA],
  [".orbit .aurora .a3", "height", "220px", AURORA],
  [".orbit .aurora .a3", "left", "60px", AURORA],
  [".orbit .aurora .a3", "bottom", "-60px", AURORA],
];

type Declaration = { file: string; selector: string; property: string; value: string };

const key = (selector: string, property: string, value: string) =>
  `${selector} { ${property}: ${value} }`;
const LISTED_KEYS = new Set(LISTED.map(([s, p, v]) => key(s, p, v)));

/** Every declaration in `css`, with the selector of the rule it is in and its value on one
 * line. Rules inside an at-rule count as their own rules. */
function declarations(file: string, css: string): Declaration[] {
  const found: Declaration[] = [];
  const code = css.replaceAll(/\/\*[\s\S]*?\*\//g, "");
  for (const [, head = "", body = ""] of code.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = head.trim().replaceAll(/\s+/g, " ");
    for (const part of body.split(";")) {
      const colon = part.indexOf(":");
      if (colon !== -1) {
        const property = part.slice(0, colon).trim().toLowerCase();
        const value = part
          .slice(colon + 1)
          .trim()
          .replaceAll(/\s+/g, " ");
        found.push({ file, selector, property, value });
      }
    }
  }
  return found;
}

const all = Object.entries(SHEETS).flatMap(([file, css]) => declarations(file, css));

/** The lengths in a value, lower-cased, without their sign. */
function lengths(value: string): string[] {
  return [...value.matchAll(/(\d*\.?\d+)(px|rem|em|ch|vh|vw)\b/gi)].map(([m]) => m.toLowerCase());
}

/** Whether each shadow's spread is a hairline or softened by a blur; offsets and blurs paint. */
function paintedShadows(value: string): boolean {
  return value.split(/,(?![^(]*\))/).every((shadow) => {
    // Offsets, blur and spread in order; a bare 0 counts, a colour's numbers do not.
    const numbers = shadow
      .replaceAll(/\([^)]*\)/g, "")
      .split(" ")
      .filter((word) => /^-?\d*\.?\d+[a-z]*$/i.test(word));
    const [, , blur = "0", spread] = numbers;
    return spread === undefined || parseFloat(blur) !== 0 || HAIRLINES.has(spread.toLowerCase());
  });
}

/** Whether the lengths in `d` are allowed, as the comment at the top says. */
function allowed(d: Declaration): boolean {
  if (d.property.startsWith("--")) {
    return d.selector === ":root";
  }
  if (LISTED_KEYS.has(key(d.selector, d.property, d.value)) || PAINT.has(d.property)) {
    return true;
  }
  if (d.property === "letter-spacing") {
    return lengths(d.value).every((l) => l.endsWith("em") && !l.endsWith("rem"));
  }
  if (d.property === "box-shadow") {
    return paintedShadows(d.value);
  }
  return EDGES.test(d.property) && lengths(d.value).every((l) => HAIRLINES.has(l));
}

describe("the size scale", () => {
  it("is the only source of lengths", () => {
    const off = all
      .filter((d) => lengths(d.value).length > 0 && !allowed(d))
      .map((d) => `${d.file}: ${key(d.selector, d.property, d.value)}`);
    expect(off).toEqual([]);
  });

  it("defines exactly the pinned tokens", () => {
    const defined = all
      .filter((d) => d.selector === ":root" && lengths(d.value).length > 0)
      .map((d): [string, string] => [d.property, d.value]);
    expect(new Map(defined)).toEqual(TOKENS);
    expect(defined.length).toBe(TOKENS.size);
  });

  it("defines only tokens that are used", () => {
    const css = Object.values(SHEETS).join("\n");
    expect([...TOKENS.keys()].filter((token) => !css.includes(`var(${token})`))).toEqual([]);
  });

  it("uses only tokens that are defined", () => {
    const css = Object.values(SHEETS).join("\n");
    const defined = new Set(all.filter((d) => d.property.startsWith("--")).map((d) => d.property));
    // Set from the components' style attributes (Orbit.tsx), not in CSS.
    defined.add("--c");
    const used = [...css.matchAll(/var\((--[\w-]+)/g)].map(([, name = ""]) => name);
    expect([...new Set(used)].filter((name) => !defined.has(name))).toEqual([]);
  });

  it("lists only declarations that exist", () => {
    const present = new Set(all.map((d) => key(d.selector, d.property, d.value)));
    expect([...LISTED_KEYS].filter((listed) => !present.has(listed))).toEqual([]);
  });
});
