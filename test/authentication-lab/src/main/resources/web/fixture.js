/* Ordinary application UI behavior. Saved journeys still run through production code. */
(() => {
  const root = document.body.dataset.caseRoot;
  const generation = document.body.dataset.generation;
  const url = (path, origin = location.origin) => {
    const value = new URL(root + path, origin);
    value.searchParams.set('generation', generation);
    return value.href;
  };
  const marker = (id, parent = document.body) => {
    const node = document.createElement('span'); node.id = id; node.textContent = id; parent.append(node);
    const surface = document.querySelector('#surface-stage');
    if (surface) {
      // Ordinary page telemetry, after the DOM marker exists. No private control or credential data.
      post('surface/observe', {surface: surface.dataset.surface, stage: id}).catch(() => {});
    }
  };
  const post = (path, data) => fetch(url(path), {method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
  const token = async (kind, origin = location.origin) => {
    const response = await fetch(url('surface/token?kind=' + kind, origin), {credentials: 'include'});
    if (!response.ok) throw new Error('Token surface request failed');
    return response.json();
  };
  const activated = async (registration) => {
    const worker = registration.active || registration.waiting || registration.installing;
    if (!worker) throw new Error('Worker unavailable');
    if (worker.state !== 'activated') await new Promise((resolve, reject) => worker.addEventListener('statechange', () => {
      if (worker.state === 'activated') resolve();
      if (worker.state === 'redundant') reject(new Error('Worker redundant'));
    }));
    if (!navigator.serviceWorker.controller) await new Promise(resolve => navigator.serviceWorker.addEventListener('controllerchange', resolve, {once: true}));
  };
  const start = async () => {
    if (document.body.dataset.kind === 'complete') {
      const response = await fetch(url('outputs'), {credentials: 'include'});
      if (!response.ok) throw new Error('Completed login outputs unavailable');
      await response.json();
      marker('outputs-received');
    }
    if (document.body.dataset.kind === 'javascript-login') {
      document.querySelector('#login-form').addEventListener('submit', async event => {
        event.preventDefault();
        const response = await post('login/json', {username: document.querySelector('#user').value, password: document.querySelector('#pass').value});
        if (!response.ok) { marker('login-rejected'); return; }
        const value = await response.json();
        const output = document.createElement('script'); output.type = 'application/json'; output.id = 'outputs'; output.textContent = JSON.stringify(value); document.body.append(output);
        marker('login-complete');
      });
    }
    const fresh = document.querySelector('#fresh-observation');
    if (fresh) {
      const kind = fresh.dataset.variant, phase = fresh.dataset.phase, prime = phase === 'PRIME';
      let present;
      if (kind === 'cookies') present = true; // The server checks the actual HttpOnly request cookie.
      else if (kind === 'local-storage' || kind === 'session-storage') {
        const storage = kind === 'local-storage' ? localStorage : sessionStorage;
        if (prime) storage.setItem('authlab.fresh', fresh.dataset.marker);
        present = prime ? storage.getItem('authlab.fresh') === fresh.dataset.marker : storage.getItem('authlab.fresh') !== null;
      } else {
        const scope = new URL(root + 'fresh/service-worker/', location.origin).href;
        if (prime) await activated(await navigator.serviceWorker.register(url('sw.js'), {scope}));
        const registrations = await navigator.serviceWorker.getRegistrations();
        present = registrations.some(value => value.scope === scope) || !!navigator.serviceWorker.controller;
      }
      const response = await post('fresh/' + kind + '/observe', {phase, present});
      if (!response.ok) throw new Error('Fresh-state observation not acknowledged');
      const actual = (await response.json()).present;
      marker(actual ? 'fresh-present' : 'fresh-absent');
      if (prime && !actual) throw new Error('Priming was not observed');
      document.querySelector('#fresh-form').hidden = false;
      marker('fresh-check-complete');
    }
    const surface = document.querySelector('#surface-stage');
    if (!surface) return;
    const kind = surface.dataset.surface;
    if (kind === 'early') {
      await token('early');
      if (!(await post('surface/ready', {})).ok) throw new Error('Ready observation failed');
      marker('ready');
    } else if (kind === 'popup-child' || kind === 'frame-child') {
      await token(kind === 'popup-child' ? 'popup' : 'frame');
      if (kind === 'popup-child' && window.opener) window.opener.postMessage('authlab-complete', location.origin);
      if (kind === 'frame-child') window.parent.postMessage('authlab-complete', location.origin);
    } else if (kind === 'popup-parent' || kind === 'frame-parent') {
      let child;
      window.addEventListener('message', event => {
        if (event.origin === location.origin && event.source === child && event.data === 'authlab-complete') marker('done');
      });
      if (kind === 'popup-parent') document.querySelector('#open-popup').onclick = () => { child = window.open(url('surface/popup-child')); };
      else document.querySelector('#load-frame').onclick = () => {
        const frame = document.createElement('iframe'); frame.id = 'auth-frame'; frame.src = url('surface/frame-child'); document.body.append(frame); child = frame.contentWindow;
      };
      marker('ready');
    } else {
      if (kind === 'worker') {
        await activated(await navigator.serviceWorker.register(url('sw.js'), {scope: root + 'surface/sw/'}));
        marker('worker-controlled');
      }
      document.querySelector('#fetch-token').onclick = async () => {
        if (kind === 'worker') {
          const response = await fetch(url('surface/sw/token'), {credentials: 'include'});
          if (!response.ok) throw new Error('Worker response unavailable');
          await response.json(); marker('done');
        } else if (kind === 'cors') {
          await token('cors', surface.dataset.api); marker('cors-done');
          try { await fetch(url('surface/cors-denied', surface.dataset.api), {credentials: 'include'}); marker('cors-unexpected'); }
          catch { marker('cors-denied'); }
        } else { await token(kind); marker('done'); }
      };
      marker('ready');
    }
  };
  start().catch(() => marker('fixture-stage-failed'));
})();
