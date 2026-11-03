#!/usr/bin/env python3
"""Check the live refresh of the grants and pending pages (warden.js) in headless
Chrome.

Usage: scripts/check-grants-live.py <out-dir>
  Renders the page fixtures into <out-dir>/warden-live-check/ (the only
  directory the script ever deletes), serves them on 127.0.0.1 with a mocked
  GET /grants/live, and loads the "grants-live" fixture once per scenario:

  - a 401 or 403 answer stops polling after the first request;
  - a grant missing from the answer loses its card, and polling goes on;
  - when two cards end in one poll, focus on the first one's Revoke button
    moves to the Revoke button of the card that stays;
  - a grant with no card makes the page reload exactly once, even when the
    answer keeps listing it (no reload loop);
  - a relay session's idle time follows the answer, and a certificate grant
    keeps what it says about its certificate;
  - a poll that changes only the idle time updates that text in place.

  And the "pending" and "pending-empty" fixtures, with a mocked GET /pending/live
  and GET /pending:

  - a 401 or 403 answer stops polling after the first request;
  - a request missing from the answer is marked in place, and polling goes on;
  - no live update moves a card: new ones go at the end;
  - a failing or stopped poll shows that the list is not updating;
  - a new request appears without a reload, also from the empty state;
  - the last card going leaves the empty state, which polls on;
  - the time left on a card follows the answer;
  - polling never posts anything;
  - what a denial said stays on screen when the last card goes;
  - the list recovers without a reload after its ended cards went while hidden and a
    refresh had failed, having said it was not updating;
  - the overlaid message takes the tap on it and clears, and a plain one fades;
  - an unchanged note about updating is not written again.

Chrome runs on virtual time, so 30 s of polling take about a second.
Needs: cargo, Google Chrome (override with CHROME=...).
"""

import itertools
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
PENDING_PAGE = "/pending.html"
PENDING_EMPTY_PAGE = "/pending-empty.html"
# Request ids of the "pending" fixture.
PENDING_IDS = [f"{n:032x}" for n in (2, 5, 8, 9)]
NEW_REQUEST = f"{10:032x}"
FOCUS_PAGE = "/focus.html"
DENY_PAGE = "/deny.html"
DENIED_SAYS = "Denied. But the audit log could not be written"
OVERLAY_PAGE = "/overlay.html"
# Test harness only: denies a card, reports what is under the overlaid message and
# whether a tap on it clears it and rests the other buttons, and what later fades.
OVERLAY_HARNESS = """<!doctype html><meta charset="utf-8">
<iframe id="page" src="/pending.html" width="400" height="500"></iframe><pre id="out"></pre>
<script>
const frame = document.getElementById('page');
frame.addEventListener('load', () => {
  const doc = frame.contentDocument;
  doc.querySelector('section.pending button.deny').click();
  setTimeout(() => {
    const box = doc.getElementById('result').getBoundingClientRect();
    const hit = doc.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
    const taken = Boolean(hit && hit.closest('#result'));
    hit.click();
    const cleared = doc.getElementById('result').textContent === '';
    const rested = [...doc.querySelectorAll('section.pending:not(.ended) button.deny')]
      .every((button) => button.disabled);
    document.getElementById('out').textContent =
      `taken:${taken} cleared:${cleared} rested:${rested}`;
  }, 1000);
}, { once: true });
</script>
"""
FADE_PAGE = "/fade.html"
# Test harness only: denies a card and reports the message at 2 s and at 10 s.
FADE_HARNESS = """<!doctype html><meta charset="utf-8">
<iframe id="page" src="/pending.html" width="400" height="900"></iframe><pre id="out"></pre>
<script>
const frame = document.getElementById('page');
frame.addEventListener('load', () => {
  const doc = frame.contentDocument;
  const said = () => doc.getElementById('result').textContent;
  doc.querySelector('section.pending button.deny').click();
  let early = '';
  setTimeout(() => { early = said(); }, 2000);
  setTimeout(() => {
    document.getElementById('out').textContent = `early:[${early}] late:[${said()}]`;
  }, 10000);
}, { once: true });
</script>
"""
NOTE_PAGE = "/note.html"
# Test harness only: counts the changes to the note about updating over some polls.
NOTE_HARNESS = """<!doctype html><meta charset="utf-8">
<iframe id="page" src="/pending.html" width="400" height="900"></iframe><pre id="out"></pre>
<script>
const frame = document.getElementById('page');
frame.addEventListener('load', () => {
  let changes = 0;
  new MutationObserver((list) => { changes += list.length; }).observe(
    frame.contentDocument.getElementById('live-state'), { childList: true, characterData: true });
  setTimeout(() => { document.getElementById('out').textContent = `changes:${changes}`; }, 18000);
}, { once: true });
</script>
"""
RECOVER_PAGE = "/recover.html"
# Test harness only: denies the last card with the refresh failing, hides the page,
# lets the refresh work again, shows the page, and reports the cards and the note.
RECOVER_HARNESS = """<!doctype html><meta charset="utf-8">
<iframe id="page" src="/pending-last.html" width="400" height="900"></iframe><pre id="out"></pre>
<script>
const frame = document.getElementById('page');
frame.addEventListener('load', () => {
  const doc = frame.contentDocument;
  const seen = (state) => {
    Object.defineProperty(doc, 'visibilityState', { configurable: true, get: () => state });
    doc.dispatchEvent(new Event('visibilitychange'));
  };
  doc.querySelector('section.pending button.deny').click();
  setTimeout(() => {
    const failed = doc.getElementById('live-state').textContent;
    seen('hidden');
    fetch('/mock/page-ok').then(() => seen('visible'));
    setTimeout(() => {
      const ids = [...doc.querySelectorAll('section.pending')].map((c) => c.dataset.request);
      document.getElementById('out').textContent =
        `failed:[${failed}] cards:${ids.join(',')} note:[${doc.getElementById('live-state').textContent}]`;
    }, 2000);
  }, 1000);
}, { once: true });
</script>
"""
TAP_PAGE = "/tap.html"
# Test harness only, never served by the broker: frames the fixture, and reports
# where a card's Deny button is at load and 8 s later.
TAP_HARNESS = f"""<!doctype html><meta charset="utf-8">
<iframe id="page" src="{PENDING_PAGE}" width="400" height="3000"></iframe><pre id="out"></pre>
<script>
const frame = document.getElementById('page');
const at = () => frame.contentDocument
  .querySelector('section.pending[data-request="{PENDING_IDS[1]}"] button.deny')
  .getBoundingClientRect().top;
frame.addEventListener('load', () => {{
  const before = at();
  setTimeout(() => {{
    document.getElementById('out').textContent = 'moved:' + (at() - before);
  }}, 8000);
}}, {{ once: true }});
</script>
"""
# Test harness only, never served by the broker: frames a fixture of one card,
# denies it, and reports the status line once the empty state is showing.
DENY_HARNESS = """<!doctype html><meta charset="utf-8">
<iframe id="page" src="/pending-last.html" width="400" height="900"></iframe><pre id="out"></pre>
<script>
const frame = document.getElementById('page');
frame.addEventListener('load', () => {
  frame.contentDocument.querySelector('section.pending button.deny').click();
  setTimeout(() => {
    const doc = frame.contentDocument;
    const main = doc.querySelector('main[data-pending]');
    document.getElementById('out').textContent =
      'state:' + main.dataset.pending + ' said:' + doc.getElementById('result').textContent;
  }, 3000);
}, { once: true });
</script>
"""
# Test harness only, never served by the broker: frames the fixture, focuses
# the first card's Revoke button, and reports what has focus 8 s later.
FOCUS_HARNESS = f"""<!doctype html><meta charset="utf-8">
<iframe id="page" src="{PAGE}" width="400" height="900"></iframe><pre id="out"></pre>
<script>
const frame = document.getElementById('page');
frame.addEventListener('load', () => {{
  const doc = frame.contentDocument;
  doc.querySelector('button.revoke[data-grant="{RELAY}"]').focus();
  setTimeout(() => {{
    const active = doc.activeElement;
    document.getElementById('out').textContent =
      'focused:' + (active.dataset.grant || active.tagName.toLowerCase());
  }}, 8000);
}}, {{ once: true }});
</script>
"""


IDLE_PAGE = "/idle.html"
# Test harness only, never served by the broker: frames the fixture, takes the
# first session's idle time after the first poll rendered it, and reports 12 s
# later whether that same node is still in the page, and what it says.
IDLE_HARNESS = f"""<!doctype html><meta charset="utf-8">
<iframe id="page" src="{PAGE}" width="400" height="900"></iframe><pre id="out"></pre>
<script>
const frame = document.getElementById('page');
frame.addEventListener('load', () => {{
  setTimeout(() => {{
    const node = frame.contentDocument
      .querySelector('.live-area[data-grant="{RELAY}"] .idle');
    const before = node.textContent;
    setTimeout(() => {{
      document.getElementById('out').textContent =
        'kept:' + node.isConnected + ' before:' + before + ' after:' + node.textContent + ';';
    }}, 12000);
  }}, 6000);
}}, {{ once: true }});
</script>
"""


class CheckError(Exception):
    """A step of the check itself failed (not a behaviour under test)."""


def live_body(*grant_ids, idle_secs=None):
    """The answer listing `grant_ids`, with a session under RELAY if `idle_secs` is set."""
    def sessions(grant):
        if idle_secs is None or grant != RELAY:
            return ""
        return (
            '{"started_at":1800000000,"bytes_to_target":1,"bytes_from_target":2,'
            f'"idle_secs":{idle_secs}}}'
        )

    grants = ",".join(
        f'{{"grant_id":"{g}","relay_sessions":[{sessions(g)}],"proxy_calls":[]}}'
        for g in grant_ids
    )
    return f'{{"grants":[{grants}]}}'.encode()


def pending_body(*ids, remaining=300):
    requests = ",".join(f'{{"id":"{i}","remaining":{remaining}}}' for i in ids)
    return f'{{"requests":[{requests}]}}'.encode()


class Mock:
    """What the live routes and GET /pending answer, and every path requested."""

    def __init__(self):
        self.lock = threading.Lock()
        self.status, self.body, self.page, self.paths = 200, b"", b"", []
        self.page_status = 200
        self.denied_says = DENIED_SAYS

    def set(self, status, body, page=b"", page_status=200, denied_says=DENIED_SAYS):
        with self.lock:
            self.status, self.body, self.page, self.paths = status, body, page, []
            self.page_status, self.denied_says = page_status, denied_says

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
        # A callable answers differently on each request.
        if callable(body):
            body = body()
        if self.path == "/mock/page-ok":
            with self.mock.lock:
                self.mock.page_status = 200
            self.send_response(204)
            self.end_headers()
            return
        if self.path == "/pending":
            with self.mock.lock:
                page, page_status = self.mock.page, self.mock.page_status
            self.send_response(page_status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        if self.path not in ("/grants/live", "/pending/live"):
            super().do_GET()
            return
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        with self.mock.lock:
            self.mock.paths.append(f"POST {self.path}")
            says = self.mock.denied_says
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = f'{{"message":"{says}"}}'.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
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
        except subprocess.CalledProcessError as e:
            detail = e.stderr.strip().splitlines()[-1:] or [f"exit status {e.returncode}"]
            raise CheckError(f"Chrome failed on {url}: {detail[0]}") from e
    return result.stdout


def cards(dom):
    return re.findall(r'class="live-area" data-grant="([0-9a-f]+)"', dom)


def pending_cards(dom):
    return re.findall(r'data-request="([0-9a-f]+)"', dom)


def ended_cards(dom):
    return re.findall(r'class="card pending ended" data-request="([0-9a-f]+)"', dom)


def main():
    try:
        return run()
    except CheckError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def run():
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
    rendered = subprocess.run(
        ["cargo", "test", "--manifest-path", str(ROOT / "Cargo.toml"), "-p",
         "warden-broker", "--lib", "--locked", "every_page_renders_self_contained"],
        env={**os.environ, "WARDEN_RENDER_PAGES_DIR": str(out)},
        check=False,
    )
    if rendered.returncode != 0:
        raise CheckError(f"rendering the page fixtures failed (cargo exit {rendered.returncode})")
    shutil.copy(ROOT / "crates/broker/src/approval/warden.js", out / "static/warden.js")
    (out / FOCUS_PAGE.lstrip("/")).write_text(FOCUS_HARNESS)
    (out / IDLE_PAGE.lstrip("/")).write_text(IDLE_HARNESS)
    (out / DENY_PAGE.lstrip("/")).write_text(DENY_HARNESS)
    (out / TAP_PAGE.lstrip("/")).write_text(TAP_HARNESS)
    (out / OVERLAY_PAGE.lstrip("/")).write_text(OVERLAY_HARNESS)
    (out / FADE_PAGE.lstrip("/")).write_text(FADE_HARNESS)
    (out / NOTE_PAGE.lstrip("/")).write_text(NOTE_HARNESS)
    (out / RECOVER_PAGE.lstrip("/")).write_text(RECOVER_HARNESS)
    listed = (out / PENDING_PAGE.lstrip("/")).read_text()
    empty = (out / PENDING_EMPTY_PAGE.lstrip("/")).read_text().encode()
    with_new = listed.replace(PENDING_IDS[3], NEW_REQUEST).encode()
    # One card: the fixture's first, cut out of the page around it.
    first = listed.index("<section class=\"card pending\"")
    second = listed.index("<section class=\"card pending\"", first + 1)
    end = listed.rindex("</section>") + len("</section>")
    (out / "pending-last.html").write_text(listed[:second] + listed[end:])

    mock = Mock()
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), partial(Handler, mock=mock, directory=str(out))
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    url = f"{origin}{PAGE}"
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

        mock.set(200, live_body(CERT))
        dom = load(f"{origin}{FOCUS_PAGE}", 12_000)
        focused = re.search(r"focused:(\w+)", dom)
        focused = focused.group(1) if focused else "nothing reported"
        check("focus skips the cards removed with its own", focused == CERT, focused)

        mock.set(200, live_body(RELAY, API, CERT, NEW))
        load(url, 30_000)
        loads = mock.count(PAGE)
        check("a new grant reloads the page once", loads == 2, f"{loads} page loads")

        mock.set(200, live_body(RELAY, API, CERT))
        load(url, 12_000)
        loads = mock.count(PAGE)
        check("matching grants do not reload", loads == 1, f"{loads} page loads")

        mock.set(200, live_body(RELAY, API, CERT, idle_secs=3660))
        dom = load(url, 12_000)
        check("a session's idle time follows the answer", "Idle 1 h 1 min" in dom, "not shown")
        check("a certificate grant keeps its issue time", "Certificate issued" in dom, "gone")
        check("a certificate grant still says logins are not visible",
              "not visible to warden" in dom, "gone")

        minutes = itertools.count(1)
        mock.set(200, lambda: live_body(RELAY, API, CERT, idle_secs=60 * next(minutes)))
        dom = load(f"{origin}{IDLE_PAGE}", 22_000)
        report = re.search(r"kept:(\w+) before:([^;]*) after:([^;]*);", dom)
        check("an idle time updates without rebuilding the card",
              bool(report) and report.group(1) == "true"
              and report.group(2) != report.group(3) and "Idle" in report.group(3),
              report.group(0) if report else "nothing reported")

        pending_url = f"{origin}{PENDING_PAGE}"
        for status in (401, 403):
            mock.set(status, b'{"error":"forbidden"}')
            load(pending_url, 30_000)
            polls = mock.count("/pending/live")
            dom = load(pending_url, 12_000)
            check(f"pending: a {status} stops polling", polls == 1, f"{polls} requests")
            check(f"pending: a {status} says the list stopped updating",
                  "stopped updating" in dom, "no note")

        mock.set(500, b'{"error":"internal error"}')
        dom = load(pending_url, 12_000)
        check("pending: a failing poll says the list is not updating",
              "not updating" in dom, "no note")

        mock.set(200, pending_body(*PENDING_IDS[:3]), with_new)
        dom = load(pending_url, 12_000)
        shown = pending_cards(dom)
        check("pending: an ended request stays in place", shown == PENDING_IDS, shown)
        check("pending: and is marked as ended", ended_cards(dom) == PENDING_IDS[3:],
              ended_cards(dom))
        polls = mock.count("/pending/live")
        check("pending: polling goes on after a removal", polls >= 2, f"{polls} requests")
        check("pending: a removal fetches no page", mock.count("/pending") == 0,
              f"{mock.count('/pending')} fetches")

        mock.set(200, pending_body(*PENDING_IDS[1:], NEW_REQUEST), with_new)
        dom = load(f"{origin}{TAP_PAGE}", 12_000)
        moved = re.search(r"moved:(-?[\d.]+)", dom)
        moved = moved.group(1) if moved else "nothing reported"
        check("pending: an ended and a new card move nothing", moved == "0", moved)

        mock.set(200, pending_body(*PENDING_IDS, NEW_REQUEST), with_new)
        dom = load(pending_url, 12_000)
        shown = pending_cards(dom)
        check("pending: a new request goes at the end",
              shown == PENDING_IDS + [NEW_REQUEST], shown)
        loads = mock.count(PENDING_PAGE)
        check("pending: a new request does not reload", loads == 1, f"{loads} page loads")
        fetched = mock.count("/pending")
        check("pending: it is fetched once", fetched == 1, f"{fetched} fetches")

        mock.set(200, pending_body(), empty)
        dom = load(pending_url, 22_000)
        check("pending: the last card going leaves the empty state",
              'data-pending="empty"' in dom and not pending_cards(dom), pending_cards(dom))
        polls = mock.count("/pending/live")
        check("pending: the empty state polls on", polls >= 2, f"{polls} requests")

        mock.set(200, pending_body(NEW_REQUEST), with_new)
        dom = load(f"{origin}{PENDING_EMPTY_PAGE}", 12_000)
        check("pending: a request appears from the empty state", NEW_REQUEST in pending_cards(dom),
              pending_cards(dom))

        mock.set(200, pending_body(*PENDING_IDS, remaining=240), listed.encode())
        dom = load(pending_url, 7_000)
        check("pending: the time left follows the answer", "in 4 min" in dom, "no \"in 4 min\"")
        posts = sum(1 for path in mock.paths if path.startswith("POST"))
        check("pending: polling posts nothing", posts == 0, f"{posts} posts")

        mock.set(200, pending_body(), empty)
        dom = load(f"{origin}{DENY_PAGE}", 10_000)
        said = re.search(r"state:(\w+) said:([^<]*)", dom)
        said = said.groups() if said else ("nothing reported", "")
        check("pending: what a denial said stays on the empty state",
              said[0] == "empty" and DENIED_SAYS in said[1], said)

        mock.set(200, pending_body(NEW_REQUEST), with_new, page_status=500)
        dom = load(f"{origin}{RECOVER_PAGE}", 8_000)
        got = re.search(r"failed:\[([^\]]*)\] cards:([0-9a-f,]*) note:\[([^\]]*)\]", dom)
        got = got.groups() if got else ("nothing reported", "", "")
        check("pending: a failed refresh says the list is not updating",
              "not updating" in got[0], got)
        check("pending: a new request appears after cards went while hidden",
              NEW_REQUEST in got[1].split(","), got)
        check("pending: the note clears after that", got[2] == "", got)

        mock.set(200, pending_body(*PENDING_IDS), listed.encode())
        dom = load(f"{origin}{OVERLAY_PAGE}", 6_000)
        check("pending: the overlaid message takes a tap, clears and rests the buttons",
              "taken:true cleared:true rested:true" in dom,
              re.findall(r"taken:\w+ cleared:\w+ rested:\w+", dom))

        mock.set(200, pending_body(*PENDING_IDS), listed.encode(), denied_says="Denied.")
        dom = load(f"{origin}{FADE_PAGE}", 14_000)
        check("pending: a plain denial shows, then fades",
              "early:[Denied.] late:[]" in dom, re.findall(r"early:.*late:\[[^\]]*\]", dom))
        mock.set(200, pending_body(*PENDING_IDS), listed.encode())
        dom = load(f"{origin}{FADE_PAGE}", 14_000)
        check("pending: a warning does not fade", f"late:[{DENIED_SAYS}" in dom,
              re.findall(r"early:.*late:\[[^\]]*\]", dom))

        mock.set(500, b'{"error":"internal error"}')
        dom = load(f"{origin}{NOTE_PAGE}", 24_000)
        changes = re.search(r"changes:(\d+)", dom)
        changes = changes.group(1) if changes else "nothing reported"
        check("pending: an unchanged note is not written again", changes == "1", changes)
    finally:
        server.shutdown()

    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
