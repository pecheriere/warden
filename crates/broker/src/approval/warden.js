// warden approval UI: WebAuthn glue for the enrollment, approval and grants
// pages, and the live activity of the grants page. Served as
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
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
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

  // --- live activity on the grants page --------------------------------------------
  // Mirrors `live_area` in pages.rs, which renders the same markup for the
  // first paint and for viewers without script.

  const LIVE_PERIOD_MS = 5000;

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

  /** The nearest grant card before or after `card`, by `step`. */
  const siblingCard = (card, step) => {
    let node = card[step];
    while (node && !node.matches('section.grant')) node = node[step];
    return node;
  };

  /** Removes `card`; focus inside it moves to the next card's Revoke
   *  button, else the previous one's, else the page heading. */
  const removeCard = (card) => {
    if (!card.contains(document.activeElement)) {
      card.remove();
      return;
    }
    const near = siblingCard(card, 'nextElementSibling') || siblingCard(card, 'previousElementSibling');
    let target = near && near.querySelector('button.revoke');
    if (!target) {
      target = document.querySelector('main h1');
      if (target && !target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
    }
    card.remove();
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
    let timer = null;
    let inFlight = false;
    let stopped = false;

    const apply = (data) => {
      const byGrant = new Map((data.grants || []).map((live) => [live.grant_id, live]));
      for (const area of document.querySelectorAll('.live-area[data-grant]')) {
        const live = byGrant.get(area.dataset.grant);
        if (!live) {
          // Revoked or expired: never show its last activity as live.
          removeCard(area.closest('section.grant'));
          continue;
        }
        if (area.dataset.kind === 'cert') continue;
        const key = JSON.stringify(live);
        if (shown.get(area.dataset.grant) === key) continue;
        shown.set(area.dataset.grant, key);
        renderLive(area, live);
      }
      // The last card went: reload for the server's empty state, which
      // has no live area and so no polling.
      if (!document.querySelector('.live-area[data-grant]')) {
        stopped = true;
        window.location.reload();
        return;
      }
      // A grant approved since the page loaded: reload to show its card,
      // but never under a revoke in progress (that one reloads itself).
      const onPage = new Set(
        [...document.querySelectorAll('.live-area[data-grant]')].map((area) => area.dataset.grant));
      const added = [...byGrant.keys()].filter((id) => !onPage.has(id));
      if (added.length && !document.querySelector('button.revoke:disabled') && reloadOnceFor(added)) {
        stopped = true;
        window.location.reload();
      }
    };

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
        const response = await fetch('/grants/live', {
          credentials: 'same-origin',
          cache: 'no-store',
          headers: { Accept: 'application/json' },
        });
        if (response.status === 401 || response.status === 403) {
          stopped = true;
        } else if (response.ok) {
          apply(await response.json());
        }
      } catch (_) {
        // Offline or a bad answer: keep what is shown and try again later.
      } finally {
        inFlight = false;
        schedule();
      }
    }

    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        window.clearTimeout(timer);
        timer = null;
        poll();
      } else {
        window.clearTimeout(timer);
        timer = null;
      }
    });
    schedule();
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
    setupLive();
    setupEnrollment();
  });
})();
