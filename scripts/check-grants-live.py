#!/usr/bin/env python3
"""Check the grants page's live refresh (warden.js) in headless Chrome.

Usage: scripts/check-grants-live.py <out-dir>
  Renders the page fixtures into <out-dir>/warden-live-check/ (the only
  directory the script ever deletes), serves them on 127.0.0.1 with a mocked
  GET /grants/live, and loads the "grants-live" fixture once per scenario:

  - a 401 or 403 answer stops polling after the first request;
  - a grant missing from the answer loses its card, and polling goes on;
  - a grant with no card makes the page reload exactly once, even when the
    answer keeps listing it (no reload loop).

Chrome runs on virtual time, so 30 s of polling take about a second.
Needs: cargo, Google Chrome (override with CHROME=...).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHROME = os.environ.get(
    "CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)
PAGE = "/grants-live.html"
# Grant ids of the "grants-live" fixture (crates/broker/src/approval/pages.rs).
RELAY, API, CERT = (f"{n:032x}" for n in (5, 4, 2))
NEW = f"{9:032x}"


def live_body(*grant_ids):
    grants = ",".join(
        f'{{"grant_id":"{g}","relay_sessions":[],"proxy_calls":[]}}' for g in grant_ids
    )
    return f'{{"grants":[{grants}]}}'.encode()


class Mock:
    """What GET /grants/live answers, and every path requested."""

    def __init__(self):
        self.lock = threading.Lock()
        self.status, self.body, self.paths = 200, b"", []

    def set(self, status, body):
        with self.lock:
            self.status, self.body, self.paths = status, body, []

    def count(self, path):
        with self.lock:
            return self.paths.count(path)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, mock, **kwargs):
        self.mock = mock
        super().__init__(*args, **kwargs)

    def do_GET(self):
        with self.mock.lock:
            self.mock.paths.append(self.path)
            status, body = self.mock.status, self.mock.body
        if self.path != "/grants/live":
            super().do_GET()
            return
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def load(url, budget_ms):
    """The page's DOM after `budget_ms` of virtual time; empty if Chrome
    does not finish (a page that keeps reloading never does)."""
    with tempfile.TemporaryDirectory() as profile:
        try:
            result = subprocess.run(
                [
                    CHROME,
                    "--headless=new",
                    "--disable-gpu",
                    f"--user-data-dir={profile}",
                    f"--virtual-time-budget={budget_ms}",
                    "--dump-dom",
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
        except subprocess.TimeoutExpired:
            return ""
    return result.stdout


def cards(dom):
    return re.findall(r'class="live-area" data-grant="([0-9a-f]+)"', dom)


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <out-dir>", file=sys.stderr)
        return 2
    base = Path(os.path.realpath(sys.argv[1]))
    if base == ROOT or ROOT in base.parents:
        print("error: <out-dir> must be outside the repository", file=sys.stderr)
        return 2
    if base in (Path("/"), Path(os.path.realpath(Path.home()))):
        print("error: <out-dir> must not be / or the home directory", file=sys.stderr)
        return 2
    if not os.access(CHROME, os.X_OK):
        print(f"error: Chrome not found at {CHROME} (set CHROME)", file=sys.stderr)
        return 1

    out = base / "warden-live-check"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subprocess.run(
        ["cargo", "test", "--manifest-path", str(ROOT / "Cargo.toml"), "-p",
         "warden-broker", "--lib", "--locked", "every_page_renders_self_contained"],
        env={**os.environ, "WARDEN_RENDER_PAGES_DIR": str(out)},
        check=True,
    )
    shutil.copy(ROOT / "crates/broker/src/approval/warden.js", out / "static/warden.js")

    mock = Mock()
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), partial(Handler, mock=mock, directory=str(out))
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}{PAGE}"
    failures = []

    def check(name, ok, detail):
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            failures.append(f"{name}: {detail}")

    try:
        for status in (401, 403):
            mock.set(status, b'{"error":"forbidden"}')
            load(url, 30_000)
            polls = mock.count("/grants/live")
            check(f"a {status} stops polling", polls == 1, f"{polls} requests")

        mock.set(200, live_body(RELAY, CERT))
        dom = load(url, 12_000)
        check("an ended grant loses its card", cards(dom) == [RELAY, CERT], cards(dom))
        polls = mock.count("/grants/live")
        check("polling goes on after a removal", polls >= 2, f"{polls} requests")

        mock.set(200, live_body(RELAY, API, CERT, NEW))
        load(url, 30_000)
        loads = mock.count(PAGE)
        check("a new grant reloads the page once", loads == 2, f"{loads} page loads")

        mock.set(200, live_body(RELAY, API, CERT))
        load(url, 12_000)
        loads = mock.count(PAGE)
        check("matching grants do not reload", loads == 1, f"{loads} page loads")
    finally:
        server.shutdown()

    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
