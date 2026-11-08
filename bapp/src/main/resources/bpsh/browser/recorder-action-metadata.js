// Password history and source association only. Playwright remains the interaction recorder.
(function (limits) {
  'use strict';
  if (globalThis.__bpshRecorderMetadata) return;
  const fields = new WeakMap(), secrets = new WeakSet(), ordinary = new WeakSet(), unknownHistory = new WeakSet();
  const roots = new Map(), pending = new Set(), sources = new Set();
  const documentId = 'doc_' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  let fieldCount = 0, actionCount = 0, uncertain = false, degraded = false, deliveryFailed = false;
  let enterForm = null;
  // Chromium also emits a zero-count click for Enter's implicit form submission. The native press
  // already replays that effect. Limit deduplication to the same form and the active Enter gesture.
  document.addEventListener('keyup', () => { enterForm = null; }, true);
  const field = element => element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element.isContentEditable;
  const password = element => element instanceof HTMLInputElement && element.type.toLowerCase() === 'password';
  const idFor = element => {
    if (!fields.has(element)) {
      if (fieldCount >= limits.fields) { degraded = true; return ''; }
      fields.set(element, 'field_' + (++fieldCount));
    }
    return fields.get(element);
  };
  const walk = (root, budget, visit) => {
    const stack = [{ node: root, history: true }];
    while (stack.length) {
      if (budget.left-- <= 0) { degraded = true; return; }
      const { node, history } = stack.pop();
      if (node instanceof Element) {
        visit(node, history);
        if (node.shadowRoot) {
          watchRoot(node.shadowRoot);
          if (degraded || stack.length >= budget.left) { degraded = true; return; }
          stack.push({ node: node.shadowRoot, history: false });
        }
      }
      for (let child = node.lastChild; child; child = child.previousSibling) {
        if (stack.length >= budget.left) { degraded = true; return; }
        stack.push({ node: child, history });
      }
    }
  };
  const rememberPassword = element => {
    if (password(element)) { secrets.add(element); idFor(element); }
  };
  const rememberField = (element, knownHistory) => {
    if (!field(element)) return;
    idFor(element); rememberPassword(element);
    if (!knownHistory && !ordinary.has(element) && !secrets.has(element)) unknownHistory.add(element);
    if (knownHistory && !degraded && !uncertain && !unknownHistory.has(element) && !secrets.has(element)) ordinary.add(element);
  };
  const takeAll = initial => {
    const records = [...initial];
    for (const state of roots.values()) {
      const batch = state.observer.takeRecords();
      if (records.length + batch.length > limits.records) { degraded = true; return []; }
      records.push(...batch);
    }
    if (records.length > limits.records) { degraded = true; return []; }
    return records;
  };
  const process = records => {
    if (!records.length || degraded) return;
    const budget = { left: limits.nodes };
    // Establish every password/type history before deciding whether any removal loses that history.
    for (const record of records) {
      if (record.type === 'attributes') {
        if (record.target instanceof HTMLInputElement && String(record.oldValue).toLowerCase() === 'password') {
          secrets.add(record.target); idFor(record.target);
        }
        rememberPassword(record.target);
      } else {
        for (const node of record.addedNodes) walk(node, budget, rememberPassword);
        for (const node of record.removedNodes) walk(node, budget, rememberPassword);
      }
      if (degraded) return;
    }
    for (const record of records) if (record.type === 'childList') {
      for (const node of record.removedNodes) walk(node, budget, element => { if (secrets.has(element)) uncertain = true; });
      if (degraded) return;
    }
    // Only now may newly observed fields acquire ordinary status.
    for (const record of records) {
      if (record.type === 'attributes') rememberField(record.target, true);
      else for (const node of record.addedNodes) walk(node, budget, (element, history) => rememberField(element, history));
      if (degraded) return;
    }
  };
  function watchRoot(root) {
    if (roots.has(root) || degraded) return;
    if (roots.size >= limits.fields) { degraded = true; return; }
    const observer = new MutationObserver(records => { try { process(takeAll(records)); } catch (_) { degraded = true; } });
    observer.observe(root, { subtree: true, childList: true, attributes: true, attributeFilter: ['type'], attributeOldValue: true });
    roots.set(root, { observer });
  }
  function observeRoot(root, completeHistory, budget) {
    if (roots.has(root) || degraded) return;
    watchRoot(root);
    walk(root, budget, (element, history) => rememberField(element, completeHistory && history));
  }
  try { observeRoot(document, true, { left: limits.nodes }); } catch (_) { degraded = true; }

  const track = (result, set) => {
    if (set.size >= limits.pending) { deliveryFailed = true; return; }
    const promise = Promise.resolve(result); set.add(promise);
    promise.then(() => set.delete(promise), () => { deliveryFailed = true; set.delete(promise); });
  };
  const wrap = binding => {
    if (typeof binding !== 'function') return binding;
    return new Proxy(binding, {
      apply(target, receiver, args) {
        const original = args[0];
        if (!original || typeof original.name !== 'string') return Reflect.apply(target, receiver, args);
        const nativeEvent = globalThis.event;
        if (original.name === 'click' && original.clickCount === 0 && enterForm && nativeEvent?.type === 'click'
            && nativeEvent.isTrusted && nativeEvent.target?.form === enterForm) {
          enterForm = null; return Promise.resolve();
        }
        if (original.name === 'press') enterForm = original.key === 'Enter' && nativeEvent?.type === 'keydown'
            && nativeEvent.isTrusted && nativeEvent.target instanceof HTMLInputElement ? nativeEvent.target.form : null;
        else enterForm = null;
        let action = original;
        if (original.name === 'fill') {
          let classification = 'unknown', fieldId = '';
          try {
            process(takeAll([]));
            const event = globalThis.event;
            const element = event && event.type === 'input' ? event.composedPath()[0] : null;
            if (element instanceof Element && field(element)) {
              const root = element.getRootNode();
              if (!roots.has(root)) observeRoot(root, false, { left: limits.nodes });
              rememberPassword(element);
              const value = element.isContentEditable ? element.innerText : element.value;
              if (value === original.text) {
                fieldId = idFor(element);
                classification = secrets.has(element) ? 'secret' : !degraded && ordinary.has(element) ? 'ordinary' : 'unknown';
              }
            }
          } catch (_) { degraded = true; }
          action = { ...original, bpshClassification: classification, bpshFieldId: fieldId, bpshDocumentId: documentId };
        }
        const sourceKey = documentId + '_action_' + (++actionCount);
        action = { ...action, bpshSourceActionId: sourceKey };
        try { track(globalThis.__bpshRecordingSource(sourceKey), sources); } catch (_) { deliveryFailed = true; }
        // Never await source acknowledgement before forwarding the native recorder call.
        let result;
        try { result = Reflect.apply(target, receiver, [action, ...args.slice(1)]); }
        catch (error) { deliveryFailed = true; throw error; }
        track(result, pending); return result;
      }
    });
  };
  const state = Object.freeze({
    async drain(timeout = limits.stop) {
      try { process(takeAll([])); } catch (_) { degraded = true; }
      let timer;
      try { await Promise.race([Promise.allSettled([...pending, ...sources]), new Promise(resolve => { timer = setTimeout(resolve, Math.max(1, Math.min(limits.stop, timeout))); })]); }
      finally { clearTimeout(timer); }
      return { failed: deliveryFailed, pending: pending.size + sources.size, degraded, documentId };
    },
    status() { return { failed: deliveryFailed, pending: pending.size + sources.size, degraded, documentId }; }
  });
  Object.defineProperty(globalThis, '__bpshRecorderMetadata', { value: state, configurable: false });
  try {
    const name = '__pw_recorderRecordAction'; let binding = wrap(globalThis[name]);
    Object.defineProperty(globalThis, name, { configurable: true, get: () => binding, set: value => { binding = wrap(value); } });
  } catch (_) { deliveryFailed = true; }
})(__BPSH_LIMITS__);
