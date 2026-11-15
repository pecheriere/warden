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
# Needs: cargo, python3, uv. Screenshots come from Playwright's Chromium headless
# shell (installed with: scripts/playwright-run.sh install), never from an
# installed Chrome. The Playwright version and dependency date are in
# scripts/playwright-pin.env, the one place to edit them.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <out-dir>" >&2
    exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base="$(python3 -I -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1")"
home="$(python3 -I -c 'import os; print(os.path.realpath(os.path.expanduser("~")))')"
out="$base/warden-pages"
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
for tool in cargo python3 uv; do
    command -v "$tool" >/dev/null || { echo "error: $tool not found" >&2; exit 1; }
done

# Start clean so pages from an earlier, failed run cannot leak into the list.
# Only the directory this script owns is ever removed.
rm -rf "$out"
mkdir -p "$shots"
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

port="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$out" >/dev/null 2>&1 &
server_pid=$!

# Wait until the server answers; fail if it never does.
up=""
for _ in $(seq 1 50); do
    if python3 -I -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$port/static/warden.css')" \
        2>/dev/null; then
        up=1
        break
    fi
    sleep 0.1
done
if [[ -z "$up" ]]; then
    echo "error: the local HTTP server on port $port did not answer within 5 seconds" >&2
    exit 1
fi

"$root/scripts/playwright-run.sh" "$root/scripts/screenshot_pages.py" \
    "$out" "http://127.0.0.1:$port" "$shots" "${sizes[@]}"

# The two schemes must actually differ, or the dark rendering is not working.
probe="$shots/approve-api-modify-1280x800"
if cmp -s "$probe-light.png" "$probe-dark.png"; then
    echo "error: light and dark screenshots are identical" >&2
    exit 1
fi
echo "wrote $(find "$shots" -name '*.png' | wc -l | tr -d ' ') screenshots to $shots"
