#!/usr/bin/env bash
# Render every approval UI page with fixture data and screenshot each one at
# phone, tablet and desktop widths in light and dark.
#
# Usage: scripts/screenshot-pages.sh <out-dir>
#   Everything goes under <out-dir>/warden-pages/, the only directory the
#   script ever deletes: the rendered pages (<name>.html, static/warden.css)
#   and the screenshots (shots/<name>-<WxH>-<light|dark>.png). <out-dir> must
#   be outside the repository and is not <HOME> or /.
# Screenshots show the viewport only (what is on screen without scrolling).
# Needs: cargo, python3, Google Chrome (override with CHROME=...), ImageMagick.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <out-dir>" >&2
    exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base="$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1")"
home="$(python3 -c 'import os; print(os.path.realpath(os.path.expanduser("~")))')"
out="$base/warden-pages"
chrome="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
sizes=(320x568 390x844 466x678 678x466 626x890 890x626 1280x800)
shots="$out/shots"

if [[ "$base" == "$root" || "$base" == "$root"/* ]]; then
    echo "error: <out-dir> must be outside the repository" >&2
    exit 2
fi
if [[ "$base" == "/" || "$base" == "$home" ]]; then
    echo "error: <out-dir> must not be / or the home directory" >&2
    exit 2
fi
for tool in cargo python3 magick; do
    command -v "$tool" >/dev/null || { echo "error: $tool not found" >&2; exit 1; }
done
[[ -x "$chrome" ]] || { echo "error: Chrome not found at $chrome (set CHROME)" >&2; exit 1; }

# Start clean so pages from an earlier, failed run cannot leak into the list.
# Only the directory this script owns is ever removed.
rm -rf "$out"
mkdir -p "$shots" "$out/wrap"
WARDEN_RENDER_PAGES_DIR="$out" cargo test --manifest-path "$root/Cargo.toml" \
    -p warden-broker --lib --locked every_page_renders_self_contained

server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$out" >/dev/null 2>&1 &
server_pid=$!

# Wait until the server answers.
for _ in $(seq 1 50); do
    python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$port/static/warden.css')" \
        2>/dev/null && break
    sleep 0.1
done


for page in "$out"/*.html; do
    name="$(basename "$page" .html)"
    for size in "${sizes[@]}"; do
        width="${size%x*}"
        height="${size#*x}"
        # Chrome's headless window has a minimum width, so the page goes in an
        # iframe of the exact size and the screenshot is cropped to it.
        # The inline <style> is for this capture harness only, not an app page.
        wrapper="wrap/$name-$size.html"
        cat >"$out/$wrapper" <<HTML
<!doctype html><meta charset="utf-8"><style>html,body{margin:0;background:#888}iframe{border:0;display:block}</style>
<iframe src="/$name.html" width="$width" height="$height"></iframe>
HTML
        for mode in light dark; do
            # --blink-settings=preferredColorScheme: 0 dark, 1 light. A case,
            # not an associative array, so stock macOS bash 3.2 runs this.
            case "$mode" in
                dark) scheme=0 ;;
                light) scheme=1 ;;
            esac
            raw="$shots/raw-$name-$size-$mode.png"
            final="$shots/$name-$size-$mode.png"
            if ! "$chrome" --headless=new --disable-gpu --hide-scrollbars \
                --force-device-scale-factor=2 \
                --blink-settings="preferredColorScheme=$scheme" \
                --window-size=1400,1100 --virtual-time-budget=2000 \
                --screenshot="$raw" "http://127.0.0.1:$port/$wrapper" >/dev/null 2>&1 \
                || [[ ! -s "$raw" ]]; then
                echo "error: Chrome failed to screenshot page $name at $size ($mode)" >&2
                exit 1
            fi
            magick "$raw" -crop "$((width * 2))x$((height * 2))+0+0" +repage "$final"
            rm -f "$raw"
        done
        rm -f "$out/$wrapper"
    done
done

rm -rf "$out/wrap"

# The two schemes must actually differ, or the dark rendering is not working.
probe="$shots/approve-api-modify-1280x800"
if cmp -s "$probe-light.png" "$probe-dark.png"; then
    echo "error: light and dark screenshots are identical" >&2
    exit 1
fi
echo "wrote $(find "$shots" -name '*.png' | wc -l | tr -d ' ') screenshots to $shots"
