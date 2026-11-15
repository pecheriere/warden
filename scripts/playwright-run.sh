#!/usr/bin/env bash
# Run a Playwright script, or install its browser, with the version and the
# dependency date in scripts/playwright-pin.env (the only place to edit them).
#
# Usage: scripts/playwright-run.sh <script.py> [args...]   run it with python3 -I
#        scripts/playwright-run.sh install                 install the Chromium
#                                                          headless shell it needs
# Needs: uv. Set PLAYWRIGHT_BROWSERS_PATH to keep the browser elsewhere.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=playwright-pin.env
source "$here/playwright-pin.env"

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <script.py> [args...] | install" >&2
    exit 2
fi
command -v uv >/dev/null || { echo "error: uv not found" >&2; exit 1; }

uv_run=(uv run --no-project --exclude-newer "$PLAYWRIGHT_EXCLUDE_NEWER"
    --with "playwright==$PLAYWRIGHT_VERSION")
if [[ "$1" == "install" && $# -eq 1 ]]; then
    exec "${uv_run[@]}" playwright install chromium-headless-shell
fi
exec "${uv_run[@]}" python3 -I "$@"
