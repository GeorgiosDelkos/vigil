"""Draw Vigil's tray marks: the main view's vortex in brief, three streaks on each of three arms.

The owner chose the vortex as the logo on 2026-11-09: the app icon is the Findings view's vortex
itself (vortex.html), and the tray keeps only what reads at 22 points (this file).

Writes, next to this file:
  mark.svg          the tray mark, 24 px, in currentColor
  mark-failed.svg   the tray mark with one arm missing, for a failed sweep
  tray-<state>.svg  the coloured tray marks for low, medium, high and sweeping: the inner
                    streaks a neutral grey that reads on a light and a dark menu bar, the
                    outer streaks in the state's colour, as findings burn at the vortex's edge

Run: uv run --no-project python3 marks.py

The PNGs one level up are rendered with headless Chrome (--screenshot
--default-background-color=00000000), then `sips -z` to size: tray-*.png at 44 px (22 pt at
2x) from these SVGs, tray-clean.png and tray-failed.png from mark.svg and mark-failed.svg filled
black (macOS template images), and icon.png at 512 px from vortex.html, which draws the app
icon on a canvas at 1024 px.
"""

import math
import pathlib

HERE = pathlib.Path(__file__).parent

ARMS = 3

# How tightly the arms wind: the angle grows by this much per unit of ln(radius). The same
# value as the main view's vortex (app/ui/src/orbit.ts), so the mark curls the same way.
WIND = 1.7

# Where the arms start, in radians: the outer ends point down and left like the main view's.
START = 0.6 * math.pi

# The streaks on each arm, inner to outer: radius, angular length and stroke width, in the
# 24-unit box. Widths are the thinnest that still read at 22 points on a retina display.
LANES = ((4.4, 1.0, 1.6), (7.4, 0.85, 2.0), (10.2, 0.7, 2.4))

# The inner streaks of a coloured mark: readable on a light and on a dark menu bar.
NEUTRAL = "#9aa1b4"

# The outer streaks' colour per tray state; sweeping is all one colour.
STATES = {
    "low": "#8fa2ff",
    "medium": "#ffd23a",
    "high": "#ff2e88",
    "sweeping": "#3ef0ff",
}


def streak(arm: int, radius: float, length: float) -> str:
    """Return an SVG path along arm `arm` from `radius`, curling inward over `length` radians."""
    # 1.2 is the radius where an arm's angle is START: arbitrary, chosen with START so the
    # outer streaks point down and left.
    base = arm / ARMS * 2 * math.pi + math.log(radius / 1.2) * WIND + START
    points = []
    for k in range(11):
        turn = length * k / 10
        r = radius * math.exp(-turn / WIND)
        points.append(
            f"{12 + math.cos(base + turn) * r:.2f},{12 + math.sin(base + turn) * r:.2f}"
        )
    return "M" + " L".join(points)


def mark(inner: str, outer: str, *, arms: int = ARMS) -> str:
    """Return the tray mark as SVG with `arms` arms, inner streaks `inner` and outer `outer`."""
    paths = "".join(
        f'<path d="{streak(arm, r, length)}" stroke="{outer if lane == 2 else inner}" '
        f'stroke-width="{width}"/>'
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
    for state, colour in STATES.items():
        inner = colour if state == "sweeping" else NEUTRAL
        (HERE / f"tray-{state}.svg").write_text(mark(inner, colour))


if __name__ == "__main__":
    main()
