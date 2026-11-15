"""Screenshot rendered approval pages with Playwright's Chromium headless shell.

Usage: screenshot_pages.py <pages-dir> <base-url> <shots-dir> <WxH>...
  Run by scripts/screenshot-pages.sh, which renders the pages into <pages-dir>
  and serves them at <base-url>; run it with scripts/playwright-run.sh, which
  reads the Playwright version from scripts/playwright-pin.env (the one place
  to edit it). Not executable: it is not run directly.
  Launches the browser once, then takes every <pages-dir>/*.html at every size
  in light and dark, as <shots-dir>/<name>-<WxH>-<light|dark>.png at device
  scale 2 and viewport height (what is on screen without scrolling). Each
  screenshot's size is checked against the viewport.
"""

import struct
import sys
from pathlib import Path

from playwright.sync_api import Error, sync_playwright

SCALE = 2
INSTALL_HINT = "scripts/playwright-run.sh install"


def png_size(path):
    header = path.read_bytes()[:24]
    return struct.unpack(">II", header[16:24])


def main():
    if len(sys.argv) < 5:
        print(f"usage: {sys.argv[0]} <pages-dir> <base-url> <shots-dir> <WxH>...", file=sys.stderr)
        return 2
    pages_dir, base_url, shots = Path(sys.argv[1]), sys.argv[2].rstrip("/"), Path(sys.argv[3])
    sizes = [tuple(int(n) for n in size.split("x")) for size in sys.argv[4:]]
    names = sorted(page.stem for page in pages_dir.glob("*.html"))
    if not names:
        print(f"error: no pages in {pages_dir}", file=sys.stderr)
        return 1

    with sync_playwright() as p:
        # No channel and no executable path: only Playwright's own headless shell,
        # never an installed Chrome.
        try:
            browser = p.chromium.launch()
        except Error as e:
            print(f"error: Chromium headless shell failed to start: {e.message.splitlines()[0]}\n"
                  f"hint: {INSTALL_HINT}", file=sys.stderr)
            return 1
        try:
            for width, height in sizes:
                for mode in ("light", "dark"):
                    context = browser.new_context(
                        viewport={"width": width, "height": height},
                        device_scale_factor=SCALE,
                        color_scheme=mode,
                    )
                    for name in names:
                        label = f"{name} at {width}x{height} ({mode})"
                        final = shots / f"{name}-{width}x{height}-{mode}.png"
                        try:
                            page = context.new_page()
                            page.goto(f"{base_url}/{name}.html", wait_until="load")
                            page.evaluate("document.fonts.ready.then(() => true)")
                            page.screenshot(path=str(final))
                            page.close()
                        except Error as e:
                            print(f"error: screenshot of {label} failed: "
                                  f"{e.message.splitlines()[0]}", file=sys.stderr)
                            return 1
                        got = png_size(final)
                        if got != (width * SCALE, height * SCALE):
                            print(f"error: {label}: {final.name} is {got[0]}x{got[1]}, "
                                  f"expected {width * SCALE}x{height * SCALE}", file=sys.stderr)
                            return 1
                    context.close()
        finally:
            browser.close()
    print(f"took {len(names) * len(sizes) * 2} screenshots")
    return 0


if __name__ == "__main__":
    sys.exit(main())
