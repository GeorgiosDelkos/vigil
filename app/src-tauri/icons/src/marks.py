"""Draw Vigil's tray marks: the main view's vortex in brief, three streaks on each of three arms.

The owner chose the vortex as the logo on 2026-11-09: the app icon is the Findings view's vortex
itself (vortex.html), and the tray keeps only what reads at 22 points (this file).

Writes, next to this file:
  mark.svg          the tray mark, 24 px, in currentColor
  mark-failed.svg   the tray mark with one arm missing, for a failed sweep
  tray-<state>.svg  the coloured tray marks for critical, high, clear and sweeping on a dark
                    menu bar: grey inner streaks, the state's colour on the outer ones, as
                    findings burn at the vortex's edge
  tray-<state>-light.svg  the same on a light menu bar, in deeper colours

Run: uv run --no-project python3 marks.py

The PNGs one level up are rendered with headless Chrome, transparent, then sized with sips:

  tray-<name>.png, 44 px (22 pt at 2x): wrap each SVG in a page that shows it as
    <img style="width:440px;height:440px;display:block"> on a margin-free body, then
    chrome --headless --hide-scrollbars --window-size=440,440 --force-device-scale-factor=1
      --default-background-color=00000000 --screenshot=<out> <page>
    and `sips -z 44 44`. tray-failed comes from mark-failed.svg with currentColor replaced
    by #000: a macOS template image, tinted to the menu bar.
  icon.png, 512 px: the same chrome command on vortex.html with --window-size=1024,1024,
    then `sips -z 512 512`.
"""

import math
import pathlib

HERE = pathlib.Path(__file__).parent

ARMS = 3

# How tightly the arms wind: the angle grows by this much per unit of ln(radius). The same
# value as the main view's vortex (app/ui/src/orbit.ts), so the mark curls the same way.
WIND = 1.7

# The radius, in the 24-unit box, where an arm's angle is zero: the main view's inner radius
# (30 of its 372-point stage, whose outer radius is about 263) scaled to this box's outer
# radius of about 11.7, so the tray mark is turned like the app icon's vortex.
REFERENCE = 30 * 11.7 / 263

# The streaks on each arm, inner to outer: radius, angular length and stroke width, in the
# 24-unit box. Widths are the thinnest that still read at 22 points on a retina display.
LANES = ((4.4, 1.0, 1.6), (7.4, 0.85, 2.0), (10.2, 0.7, 2.4))

# The coloured marks' palettes per menu-bar appearance: the neutral inner streaks, then the
# outer streaks' colour per state (sweeping is all one colour). Neon reads on a dark bar but
# not on a light one (cyan is 1.2:1 against it), so the owner chose two sets switched with the
# appearance (2026-11-09). The light set is each hue at the lightest that keeps 3:1 contrast
# against a light bar (#ececf1, WCAG's minimum for graphics).
#
# Critical, high and clear take the app's severity colours (--critical, --high and --ok in
# app/ui/src/style.css), so the icon reads like the popover. Medium and low have no look: the
# owner decided on 2026-11-11 that only critical and high colour the icon.
PALETTES = {
    "": (
        "#9aa1b4",
        {
            "critical": "#ff5a52",
            "high": "#ff8a3d",
            "clear": "#4fd18b",
            "sweeping": "#3ef0ff",
        },
    ),
    "-light": (
        "#81889c",
        {
            "critical": "#ff3c32",
            "high": "#e75c00",
            "clear": "#289b5d",
            "sweeping": "#0095b2",
        },
    ),
}


def streak(arm: int, radius: float, length: float) -> list[tuple[float, float]]:
    """Return points along arm `arm` from `radius`, curling inward over `length` radians."""
    base = arm / ARMS * 2 * math.pi + math.log(radius / REFERENCE) * WIND
    points = []
    for k in range(11):
        turn = length * k / 10
        r = radius * math.exp(-turn / WIND)
        points.append((12 + math.cos(base + turn) * r, 12 + math.sin(base + turn) * r))
    return points


def offset() -> tuple[float, float]:
    """Return the shift that centres the full three-arm mark's stroked outline in the box."""
    xs, ys = [], []
    for arm in range(ARMS):
        for r, length, width in LANES:
            for x, y in streak(arm, r, length):
                xs += [x - width / 2, x + width / 2]
                ys += [y - width / 2, y + width / 2]
    return 12 - (min(xs) + max(xs)) / 2, 12 - (min(ys) + max(ys)) / 2


def path(points: list[tuple[float, float]], shift: tuple[float, float]) -> str:
    """Return `points` moved by `shift` as SVG path data."""
    return "M" + " L".join(f"{x + shift[0]:.2f},{y + shift[1]:.2f}" for x, y in points)


def mark(inner: str, outer: str, *, arms: int = ARMS) -> str:
    """Return the tray mark as SVG with `arms` arms, inner streaks `inner` and outer `outer`.

    The failed mark drops an arm but keeps the full mark's position, so it does not jump.
    """
    shift = offset()
    paths = "".join(
        f'<path d="{path(streak(arm, r, length), shift)}" '
        f'stroke="{outer if lane == 2 else inner}" stroke-width="{width}"/>'
        for arm in range(arms)
        for lane, (r, length, width) in enumerate(LANES)
    )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        f'stroke-linecap="round">{paths}</svg>\n'
    )


def main() -> None:
    (HERE / "mark.svg").write_text(mark("currentColor", "currentColor"))
    (HERE / "mark-failed.svg").write_text(
        mark("currentColor", "currentColor", arms=ARMS - 1)
    )
    for suffix, (neutral, states) in PALETTES.items():
        for state, colour in states.items():
            inner = colour if state == "sweeping" else neutral
            (HERE / f"tray-{state}{suffix}.svg").write_text(mark(inner, colour))


if __name__ == "__main__":
    main()
