// warden approval UI: WebAuthn glue for the enrollment, approval and grants
// pages, and the live refresh of the pending and grants pages. Served as
// /static/warden.js; the pages carry no inline script.
'use strict';

(() => {
  // --- base64url <-> ArrayBuffer -------------------------------------------

  const fromB64u = (text) => {
    const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  };

  const toB64u = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let bin = '';
    for (const byte of bytes) bin += String.fromCharCode(byte);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  // --- requests --------------------------------------------------------------

  const show = (text, ok) => {
    const result = document.getElementById('result');
    if (!result) return;
    result.textContent = text;
    result.classList.toggle('ok', ok);
    result.classList.toggle('err', !ok);
  };

  const post = async (path, body) => {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    let data = {};
    try {
      data = await response.json();
    } catch (_) {
      data = {};
    }
    if (!response.ok) {
      const failure = new Error(data.error || `HTTP ${response.status}`);
      failure.status = response.status;
      throw failure;
    }
    return data;
  };

  // --- WebAuthn ---------------------------------------------------------------

  const createCredential = async (options) => {
    const publicKey = options.publicKey;
    publicKey.challenge = fromB64u(publicKey.challenge);
    publicKey.user.id = fromB64u(publicKey.user.id);
    for (const cred of publicKey.excludeCredentials || []) cred.id = fromB64u(cred.id);
    const cred = await navigator.credentials.create({ publicKey });
    return {
      id: cred.id,
      rawId: toB64u(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: toB64u(cred.response.attestationObject),
        clientDataJSON: toB64u(cred.response.clientDataJSON),
        transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
      },
      extensions: cred.getClientExtensionResults(),
    };
  };

  const getAssertion = async (options) => {
    const publicKey = options.publicKey;
    publicKey.challenge = fromB64u(publicKey.challenge);
    for (const cred of publicKey.allowCredentials || []) cred.id = fromB64u(cred.id);
    const cred = await navigator.credentials.get({ publicKey });
    const response = cred.response;
    return {
      id: cred.id,
      rawId: toB64u(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: toB64u(response.authenticatorData),
        clientDataJSON: toB64u(response.clientDataJSON),
        signature: toB64u(response.signature),
        userHandle: response.userHandle ? toB64u(response.userHandle) : null,
      },
      extensions: cred.getClientExtensionResults(),
    };
  };

  const busy = (buttons, on) => {
    for (const button of buttons) if (button) button.disabled = on;
  };

  // --- approval page ------------------------------------------------------------

  const setupApproval = () => {
    const approve = document.getElementById('approve');
    const deny = document.getElementById('deny');
    const approval = document.getElementById('approval');
    if (!approve || !deny || !approval) return;
    const base = window.location.pathname.replace(/\/+$/, '');

    approve.addEventListener('click', async () => {
      busy([approve, deny], true);
      try {
        const picked = document.querySelector('input[name="window"]:checked');
        if (!picked) throw new Error('Choose how long to grant access for.');
        // The digest of the destination shown on this page: the server refuses
        // to approve if the policy of the target or secret changed since.
        const begun = await post(`${base}/begin`, {
          window: picked.value,
          target: approval.dataset.target,
        });
        show('Confirm with your passkey…', true);
        const credential = await getAssertion(begun.options);
        const done = await post(`${base}/finish`, { ceremony: begun.ceremony, credential });
        show(done.message, true);
      } catch (error) {
        show(error.message, false);
        busy([approve, deny], false);
      }
    });

    deny.addEventListener('click', async () => {
      busy([approve, deny], true);
      try {
        const done = await post(`${base}/deny`, {});
        show(done.message, true);
      } catch (error) {
        show(error.message, false);
        busy([approve, deny], false);
      }
    });

    const countdown = document.getElementById('countdown');
    if (countdown) {
      const deadline = Date.now() + Number(countdown.dataset.remaining) * 1000;
      const tick = () => {
        const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
        const mins = Math.floor(left / 60);
        const secs = String(left % 60).padStart(2, '0');
        countdown.textContent = left > 0 ? `expires in ${mins}:${secs}` : 'expired';
        if (left === 0) busy([approve, deny], true);
        else window.setTimeout(tick, 1000);
      };
      tick();
    }
  };

  // --- grants page --------------------------------------------------------------

  const setupGrants = () => {
    for (const button of document.querySelectorAll('button.revoke')) {
      button.addEventListener('click', async () => {
        button.disabled = true;
        try {
          const done = await post(`/grants/${encodeURIComponent(button.dataset.grant)}/revoke`, {});
          show(done.message, true);
          window.location.reload();
        } catch (error) {
          show(error.message, false);
          button.disabled = false;
        }
      });
    }
  };

  // --- polling ------------------------------------------------------------------

  const LIVE_PERIOD_MS = 5000;

  /** Polls `path` while the page is visible, with one request at a time, and hands
   *  each answer to `apply`. A 401 or 403 stops it, and so does calling the `stop`
   *  it returns. Offline or a bad answer keeps what is shown and tries again.
   *  `report`, if given, hears how each poll went: 'ok', 'failing' or 'stopped'. */
  const pollEvery = (path, apply, report = () => {}) => {
    let timer = null;
    let inFlight = false;
    let stopped = false;

    const schedule = () => {
      window.clearTimeout(timer);
      timer = null;
      if (!stopped && document.visibilityState === 'visible') {
        timer = window.setTimeout(poll, LIVE_PERIOD_MS);
      }
    };

    async function poll() {
      if (inFlight || stopped) return;
      inFlight = true;
      try {
        const response = await fetch(path, {
          credentials: 'same-origin',
          cache: 'no-store',
          headers: { Accept: 'application/json' },
        });
        if (response.status === 401 || response.status === 403) {
          stopped = true;
          report('stopped');
        } else if (response.ok) {
          await apply(await response.json());
          report('ok');
        } else {
          report('failing');
        }
      } catch (_) {
        // Offline or a bad answer: keep what is shown and try again later.
        report('failing');
      } finally {
        inFlight = false;
        schedule();
      }
    }

    document.addEventListener('visibilitychange', () => {
      window.clearTimeout(timer);
      timer = null;
      if (document.visibilityState === 'visible') poll();
    });
    schedule();
    return () => {
      stopped = true;
    };
  };

  // --- pending page -------------------------------------------------------------
  // Polling only reads which requests are waiting; it changes nothing, and no token
  // is replaced except by the owner pressing Approve…. The markup always comes from
  // the server.
  //
  // A refresh must never change what a tap lands on. So a request that ends stays
  // where it is, marked and with its buttons disabled, and goes only while the page
  // is hidden or when no card with live buttons is left. New cards go at the end,
  // and their buttons wake up a moment later, in case a tap was already on its way
  // to that spot. What the page says is overlaid, not in the flow, and takes the taps
  // on it: when it goes, the buttons it may have covered also wake up a moment later.
  // Nothing here moves focus or scrolls.

  const CARD_ARM_MS = 1000;
  const SAID_FADES_MS = 8000;

  const setupPending = () => {
    if (!document.querySelector('main[data-pending]')) return;
    const deadlines = new WeakMap();
    // Requests known to have ended: a stale answer must not bring their cards back.
    const over = new Set();
    const armedUntil = new WeakMap();
    let refreshing = false;
    let fading = null;

    const cards = () => [...document.querySelectorAll('section.pending')];
    const live = (card) => !card.classList.contains('ended');
    const acting = () => Boolean(document.querySelector('section.pending[data-acting]'));
    const buttons = (card) => [card.querySelector('button.approve'), card.querySelector('button.deny')];

    /** Marks `card` as over, in place: nothing about its size changes. */
    const endCard = (card, word) => {
      card.classList.add('ended');
      busy(buttons(card), true);
      const remaining = card.querySelector('.remaining');
      if (remaining) remaining.textContent = `(${word})`;
    };

    const finish = (card, word) => {
      over.add(card.dataset.request);
      delete card.dataset.byClock;
      endCard(card, word);
    };

    const setRemaining = (card, seconds) => {
      deadlines.set(card, Date.now() + seconds * 1000);
    };

    /** Keeps `card`'s buttons from taking a tap for a moment. */
    const arm = (card) => {
      if (!live(card) || card.dataset.acting) return;
      armedUntil.set(card, Date.now() + CARD_ARM_MS);
      busy(buttons(card), true);
      window.setTimeout(() => {
        if (live(card) && !card.dataset.acting && Date.now() >= armedUntil.get(card)) {
          busy(buttons(card), false);
        }
      }, CARD_ARM_MS);
    };

    /** Clears what the page says, if anything. */
    const clearSaid = () => {
      window.clearTimeout(fading);
      const result = document.getElementById('result');
      if (!result || !result.textContent) return;
      result.textContent = '';
      result.classList.remove('ok', 'err');
      cards().forEach(arm);
    };

    /** Says `text`. Only what the owner needs nothing further from fades by itself:
     *  a warning stays until they dismiss it or do something else. */
    const say = (text, ok, fades = false) => {
      window.clearTimeout(fading);
      show(text, ok);
      if (fades) fading = window.setTimeout(clearSaid, SAID_FADES_MS);
    };

    /** Replaces the page's `main` with `fresh`, keeping what the page says. */
    const swapMain = (shown, fresh) => {
      for (const id of ['result', 'live-state']) {
        const said = shown.querySelector(`#${id}`);
        const keep = fresh.querySelector(`#${id}`);
        if (said && keep) {
          keep.textContent = said.textContent;
          keep.className = said.className;
        }
      }
      shown.replaceWith(document.importNode(fresh, true));
      for (const node of document.querySelectorAll('main time[datetime]')) localTime(node);
      for (const card of cards()) wireCard(card, true);
    };

    /** Brings in what only the server can draw. Never under an action in progress,
     *  also if one started during the fetch: the next poll comes back to it. A failure
     *  is the caller's to report. */
    const refresh = async () => {
      if (refreshing || acting()) return;
      refreshing = true;
      try {
        const response = await fetch('/pending', { credentials: 'same-origin', cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const parsed = new DOMParser().parseFromString(await response.text(), 'text/html');
        const fresh = parsed.querySelector('main[data-pending]');
        const shown = document.querySelector('main[data-pending]');
        if (!fresh || !shown) throw new Error('not the pending page');
        if (acting()) return;
        const onPage = new Set(cards().map((card) => card.dataset.request));
        const incoming = [...fresh.querySelectorAll('section.pending')];
        const added = incoming.filter(
          (card) => !onPage.has(card.dataset.request) && !over.has(card.dataset.request));
        if (!incoming.length) {
          // Nothing is waiting on the server. With live buttons here the next poll
          // decides about them first.
          if (shown.dataset.pending === 'list' && !cards().some(live)) swapMain(shown, fresh);
        } else if (!cards().length) {
          // No card here to put them after: the empty state, or a list whose ended
          // cards went while the page was hidden.
          if (!added.length) return;
          for (const card of incoming) if (!added.includes(card)) card.remove();
          swapMain(shown, fresh);
        } else {
          for (const card of added) {
            const node = document.importNode(card, true);
            cards().pop().after(node);
            for (const time of node.querySelectorAll('time[datetime]')) localTime(time);
            wireCard(node, true);
          }
        }
      } finally {
        refreshing = false;
      }
    };

    /** Says when the list may be out of date, only when that changes. A note that
     *  goes may have covered buttons. */
    const reportLive = (state) => {
      const note = document.getElementById('live-state');
      if (!note) return;
      const text = {
        ok: '',
        failing: 'This list is not updating right now. warden keeps trying.',
        stopped: 'This list has stopped updating. Reload the page to see what is waiting.',
      }[state];
      if (note.textContent === text) return;
      note.textContent = text;
      if (!text) cards().forEach(arm);
    };

    /** With no live button left, the server's empty state can take over. */
    const settle = () => {
      if (!cards().some(live)) refresh().catch(() => reportLive('failing'));
    };

    const wireCard = (card, armed) => {
      const remaining = card.querySelector('.remaining');
      if (remaining) setRemaining(card, Number(remaining.dataset.remaining));
      const [approve, deny] = buttons(card);
      if (armed) arm(card);
      const act = (action, done) => async () => {
        card.dataset.acting = 'yes';
        busy([approve, deny], true);
        try {
          done(await post(`/pending/${encodeURIComponent(card.dataset.request)}/${action}`, {}));
        } catch (error) {
          say(error.message, false);
          // 404: decided, expired, cancelled or unknown by now.
          if (error.status === 404) finish(card, 'ended');
          else if (live(card)) busy([approve, deny], false);
        } finally {
          delete card.dataset.acting;
        }
        settle();
      };
      // Opening gives this request a new approval link, and the old one stops
      // working; the decision is made on the page it leads to.
      approve.addEventListener('click', act('open', (opened) => {
        window.location.assign(opened.link);
      }));
      deny.addEventListener('click', act('deny', (denied) => {
        // Anything more than this says something is wrong: it stays.
        say(denied.message, true, denied.message === 'Denied.');
        finish(card, 'denied');
      }));
    };

    /** Keeps "(in N min)" true. A card whose time is up is marked by the clock alone
     *  until the next answer settles it, as this device's clock may be wrong. */
    const tick = () => {
      for (const card of cards().filter(live)) {
        const left = Math.ceil((deadlines.get(card) - Date.now()) / 1000);
        const remaining = card.querySelector('.remaining');
        if (left > 0) {
          if (remaining) remaining.textContent = `(in ${Math.ceil(left / 60)} min)`;
        } else if (!card.dataset.acting) {
          card.dataset.byClock = 'yes';
          endCard(card, 'expired');
        }
      }
    };

    const apply = async (data) => {
      const waiting = new Map((data.requests || []).map((r) => [r.id, r.remaining]));
      for (const card of cards()) {
        const id = card.dataset.request;
        if (!waiting.has(id)) {
          if (!over.has(id)) finish(card, card.dataset.byClock ? 'expired' : 'ended');
        } else if (!over.has(id)) {
          setRemaining(card, waiting.get(id));
          if (card.dataset.byClock) {
            delete card.dataset.byClock;
            card.classList.remove('ended');
            busy(buttons(card), false);
          }
        }
      }
      tick();
      const onPage = new Set(cards().map((card) => card.dataset.request));
      const added = [...waiting.keys()].some((id) => !onPage.has(id) && !over.has(id));
      const shown = document.querySelector('main[data-pending]');
      const bare = shown && shown.dataset.pending === 'list' && !cards().some(live);
      // A failure here reaches the poller, which reports it.
      if (added || bare) await refresh();
    };

    // Back from the approval page must not show this page as it was left: the
    // buttons may still be disabled.
    window.addEventListener('pageshow', (event) => {
      if (event.persisted) window.location.reload();
    });
    // Nothing can be tapped while the page is hidden, so the ended cards can go.
    // Coming back polls at once, which brings in the empty state if it is due.
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') {
        for (const card of cards()) if (!live(card)) card.remove();
      }
    });
    // The overlaid message takes the tap that dismisses it.
    document.addEventListener('click', (event) => {
      if (event.target.closest && event.target.closest('#result')) clearSaid();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') clearSaid();
    });
    for (const node of document.querySelectorAll('main time[datetime]')) localTime(node);
    for (const card of cards()) wireCard(card, false);
    window.setInterval(tick, 1000);
    pollEvery('/pending/live', apply, reportLive);
  };

  // --- live activity on the grants page --------------------------------------------
  // Mirrors `live_area` in pages.rs, which renders the same markup for the
  // first paint and for viewers without script.

  /** `bytes` in pages.rs: powers of 1000, rounded down to a tenth. */
  const bytes = (n) => {
    if (n < 1000) return `${n} B`;
    const [divisor, unit] = n < 1000000 ? [100, 'KB'] : [100000, 'MB'];
    const tenths = Math.floor(n / divisor);
    return `${Math.floor(tenths / 10)}.${tenths % 10} ${unit}`;
  };

  const count = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  const el = (tag, className, ...children) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    for (const child of children) {
      node.append(typeof child === 'string' ? document.createTextNode(child) : child);
    }
    return node;
  };

  /** Shows a <time> in the viewer's local time, from its `datetime`. */
  const localTime = (node) => {
    const date = new Date(node.dateTime);
    if (Number.isNaN(date.getTime())) return;
    node.textContent = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  /** `clock` in pages.rs: a <time> for Unix seconds `ts`, in local time. */
  const clock = (ts) => {
    const node = el('time', '');
    node.dateTime = new Date(ts * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    localTime(node);
    return node;
  };

  const renderLive = (area, live) => {
    const sessions = live.relay_sessions;
    const calls = live.proxy_calls;
    const parts = [];
    if (sessions.length) parts.push(`${count(sessions.length, 'session', 'sessions')} open`);
    if (calls.length) parts.push(`${count(calls.length, 'call', 'calls')} in flight`);
    if (!parts.length) {
      const idle = area.dataset.kind === 'relay' ? 'No sessions open' : 'No calls in flight';
      area.replaceChildren(el('p', 'detail', idle));
      return;
    }
    const list = el('ul', 'live-list');
    list.setAttribute('role', 'list');
    for (const session of sessions) {
      list.append(el('li', '',
        el('span', '', 'Session since ', clock(session.started_at)),
        el('span', '',
          el('span', 'nowrap', `${bytes(session.bytes_to_target)} to target`),
          ' · ',
          el('span', 'nowrap', `${bytes(session.bytes_from_target)} from target`))));
    }
    for (const call of calls) {
      list.append(el('li', '',
        el('code', '', el('bdi', '', `${call.method} ${call.path}`)),
        el('span', '', 'since ', clock(call.started_at))));
    }
    area.replaceChildren(el('p', 'live', parts.join(' · ')), list);
  };

  /** Session storage key: the grants a reload was last made to show. */
  const RELOADED_FOR = 'warden.live.reloadedFor';

  /** Removes the grant cards `cards`. Focus inside one of them moves to
   *  the Revoke button of the nearest card that stays, after it, else
   *  before it, else to the page heading. */
  const removeCards = (cards) => {
    const focused = cards.find((card) => card.contains(document.activeElement));
    let target = null;
    if (focused) {
      const gone = new Set(cards);
      const staying = (step) => {
        let node = focused[step];
        while (node && (!node.matches('section.grant') || gone.has(node))) node = node[step];
        return node;
      };
      const near = staying('nextElementSibling') || staying('previousElementSibling');
      target = near && near.querySelector('button.revoke');
      if (!target) {
        target = document.querySelector('main h1');
        if (target && !target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
      }
    }
    for (const card of cards) card.remove();
    if (target) target.focus();
  };

  /** Whether to reload to show the grants `ids`, which have no card: once
   *  for a given set, so a page that still lacks them cannot loop. Without
   *  session storage there is no such guard, so no reload. */
  const reloadOnceFor = (ids) => {
    const key = [...ids].sort().join(' ');
    try {
      if (window.sessionStorage.getItem(RELOADED_FOR) === key) return false;
      window.sessionStorage.setItem(RELOADED_FOR, key);
      return true;
    } catch (_) {
      return false;
    }
  };

  const setupLive = () => {
    if (!document.querySelector('.live-area[data-grant]')) return;
    for (const node of document.querySelectorAll('main time[datetime]')) localTime(node);

    const shown = new Map();
    let stop = () => {};

    const apply = (data) => {
      const byGrant = new Map((data.grants || []).map((live) => [live.grant_id, live]));
      const ended = [];
      for (const area of document.querySelectorAll('.live-area[data-grant]')) {
        const live = byGrant.get(area.dataset.grant);
        if (!live) {
          // Revoked or expired: never show its last activity as live.
          ended.push(area.closest('section.grant'));
          continue;
        }
        if (area.dataset.kind === 'cert') continue;
        const key = JSON.stringify(live);
        if (shown.get(area.dataset.grant) === key) continue;
        shown.set(area.dataset.grant, key);
        renderLive(area, live);
      }
      removeCards(ended);
      // The last card went: reload for the server's empty state, which
      // has no live area and so no polling.
      if (!document.querySelector('.live-area[data-grant]')) {
        stop();
        window.location.reload();
        return;
      }
      // A grant approved since the page loaded: reload to show its card,
      // but never under a revoke in progress (that one reloads itself).
      const onPage = new Set(
        [...document.querySelectorAll('.live-area[data-grant]')].map((area) => area.dataset.grant));
      const added = [...byGrant.keys()].filter((id) => !onPage.has(id));
      if (added.length && !document.querySelector('button.revoke:disabled') && reloadOnceFor(added)) {
        stop();
        window.location.reload();
      }
    };

    stop = pollEvery('/grants/live', apply);
  };

  // --- enrollment page ------------------------------------------------------------

  const setupEnrollment = () => {
    const enroll = document.getElementById('enroll');
    const code = document.getElementById('code');
    const label = document.getElementById('label');
    if (!enroll || !code || !label) return;
    enroll.addEventListener('click', async () => {
      busy([enroll], true);
      try {
        const begun = await post('/enroll/begin', { code: code.value, label: label.value });
        show('Create the passkey on this device…', true);
        const credential = await createCredential(begun.options);
        const done = await post('/enroll/finish', { ceremony: begun.ceremony, credential });
        show(done.message, true);
      } catch (error) {
        show(error.message, false);
        busy([enroll], false);
      }
    });
  };

  document.addEventListener('DOMContentLoaded', () => {
    setupApproval();
    setupGrants();
    setupPending();
    setupLive();
    setupEnrollment();
  });
})();
