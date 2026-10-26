// warden approval UI: WebAuthn glue for the enrollment, approval and grants
// pages. Served as /static/warden.js; the pages carry no inline script.
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
    result.style.color = ok ? 'green' : '#b00';
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
    const select = document.getElementById('window');
    const approval = document.getElementById('approval');
    if (!approve || !deny || !select || !approval) return;
    const base = window.location.pathname.replace(/\/+$/, '');

    approve.addEventListener('click', async () => {
      busy([approve, deny], true);
      try {
        // The digest of the destination shown on this page: the server refuses
        // to approve if the target's host, port or host keys changed since.
        const begun = await post(`${base}/begin`, {
          window: select.value,
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
        countdown.textContent = left > 0 ? `in ${mins}:${secs}` : 'expired';
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
    setupEnrollment();
  });
})();
