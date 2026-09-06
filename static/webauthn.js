/* Passkey helpers.
 *
 * Hand-rolled base64url conversion rather than a library: the WebAuthn JSON
 * shape is small, this file is served from the app itself (no CDN at runtime),
 * and a dependency that touches credentials is a dependency worth avoiding.
 */
(function () {
  function b64urlToBuf(value) {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let raw = '';
    for (let i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function postJSON(url, body) {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await resp.json(); } catch (e) { /* non-JSON error page */ }
    if (!resp.ok) throw new Error(data.error || 'Request failed (' + resp.status + ').');
    return data;
  }

  async function options(url) {
    const resp = await fetch(url, { method: 'POST' });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Could not start the passkey ceremony.');
    return data;
  }

  function friendly(err) {
    // NotAllowedError covers both "user cancelled" and "timed out", and the
    // browser deliberately doesn't say which. Anything more specific would be
    // a guess presented as fact.
    if (err && err.name === 'NotAllowedError') {
      return new Error('No passkey was used. The prompt was dismissed or timed out.');
    }
    if (err && err.name === 'InvalidStateError') {
      return new Error('That device already has a passkey registered for this account.');
    }
    if (err && err.name === 'SecurityError') {
      return new Error('The browser refused: this page must be served over HTTPS on the passkey hostname.');
    }
    return err instanceof Error ? err : new Error(String(err));
  }

  window.passkeySignIn = async function () {
    if (!window.PublicKeyCredential) throw new Error('This browser does not support passkeys.');
    const opts = await options('/webauthn/login/options');
    opts.challenge = b64urlToBuf(opts.challenge);
    (opts.allowCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });

    let assertion;
    try {
      assertion = await navigator.credentials.get({ publicKey: opts });
    } catch (err) {
      throw friendly(err);
    }

    return postJSON('/webauthn/login/verify', {
      credential: {
        id: assertion.id,
        rawId: bufToB64url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
          authenticatorData: bufToB64url(assertion.response.authenticatorData),
          signature: bufToB64url(assertion.response.signature),
          userHandle: assertion.response.userHandle
            ? bufToB64url(assertion.response.userHandle)
            : null,
        },
        clientExtensionResults: assertion.getClientExtensionResults(),
      },
    });
  };

  window.passkeyRegister = async function (name) {
    if (!window.PublicKeyCredential) throw new Error('This browser does not support passkeys.');
    const opts = await options('/webauthn/register/options');
    opts.challenge = b64urlToBuf(opts.challenge);
    opts.user.id = b64urlToBuf(opts.user.id);
    (opts.excludeCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });

    let credential;
    try {
      credential = await navigator.credentials.create({ publicKey: opts });
    } catch (err) {
      throw friendly(err);
    }

    const transports = credential.response.getTransports
      ? credential.response.getTransports()
      : [];

    return postJSON('/webauthn/register/verify', {
      name: name,
      transports: transports,
      credential: {
        id: credential.id,
        rawId: bufToB64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufToB64url(credential.response.clientDataJSON),
          attestationObject: bufToB64url(credential.response.attestationObject),
          transports: transports,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      },
    });
  };
})();
